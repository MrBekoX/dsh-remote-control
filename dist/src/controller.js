/**
 * RemoteControlController â€” the single integration point of the Host plugin.
 *
 * Responsibilities:
 *  - lifecycle: initialize stores, enable/disable the phone listener + connection
 *    provider, and the one-shot emergency/security shutdown path;
 *  - device auth: pairing claims, access/refresh cookies, the single-active-device
 *    lease, the shared authentication-failure accounting and revoke flows;
 *  - the phone REST surface (`/rc/api/*`) and the WS upgrade/per-frame auth gate;
 *  - the desktop admin surface (`/api/dsh-remote-control/*`) through AdminApi;
 *  - connection plan/consent/start/stop orchestration for Cloudflare, SSH and LAN;
 *  - audit ring and safe logging.
 *
 * The controller never talks to DSH endpoints directly: session reads/mutations
 * go through `SessionDataPlane`, approvals through `ApprovalHub`. Both are
 * gateway-backed and implemented in their own modules. Provider-specific
 * process work lives in `TunnelManager`; auth primitives live in `device-lease`,
 * `security-monitor`, `token`, `pairing` and `access-jwt`.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveAccessTtlMs } from './config.js';
import { PROTOCOL_VERSION, RC_ACCESS_COOKIE, RC_API_PATH, RC_BASE_PATH, RC_CSRF_HEADER, RC_ERRORS, RC_LIMITS, RC_REFRESH_COOKIE, RC_WS_CLOSE, } from './shared/protocol.js';
import { createAccessVerifier } from './access-jwt.js';
import { createApprovalBridge } from './approval-bridge.js';
import { createAuditRing, sanitizeAuditIp, sanitizeAuditText, toAuditEntryView } from './audit.js';
import { canonicalAuthority, checkOriginFence, clearCookie, createOriginPolicy, isCsrfOk, parseCookies, proxyPolicyForTunnelMode, readJsonBody, resolveClientIp, sendError, sendJson, serializeCookie, } from './auth.js';
import { createDeviceLease } from './device-lease.js';
import { createDeviceStore, toDeviceView } from './device-store.js';
import { createGatewayClient } from './gateway-client.js';
import { createListener } from './listener.js';
import { formatHostForAuthority, isLoopbackHost, isWildcardHost, listLanInterfaces } from './network.js';
import { createPairingManager } from './pairing.js';
import { renderQrSvg } from './qr.js';
import { createSecurityMonitor } from './security-monitor.js';
import { createSessionBridge } from './session-bridge.js';
import { createStateStore } from './state.js';
import { createTokenService } from './token.js';
import { createTunnelManager } from './tunnel.js';
import { createWsBroker } from './ws-broker.js';
const RC_DIR = 'remote-control';
const COOKIE_PATH = RC_BASE_PATH;
const DRAIN_DELAY_MS = 250;
const LAST_SEEN_WRITE_INTERVAL_MS = 60_000;
/** A refresh token retired within this window is a concurrent-rotation race, not reuse. */
const REFRESH_CONCURRENCY_GRACE_MS = 10_000;
const RETIRED_REFRESH_LIMIT = 8;
const PLAN_CACHE_LIMIT = 32;
const ADMIN_AUDIT_LIMIT = 50;
class RcHttpError extends Error {
    status;
    code;
    retryAfterMs;
    constructor(status, code, message, retryAfterMs) {
        super(message);
        this.name = 'RcHttpError';
        this.status = status;
        this.code = code;
        this.retryAfterMs = retryAfterMs;
    }
}
const STATUS_BY_CODE = {
    AUTH_REQUIRED: 401,
    TOKEN_EXPIRED: 401,
    DEVICE_REVOKED: 401,
    DEVICE_LOCKED: 409,
    SECURITY_CLOSED: 503,
    TLS_REQUIRED: 409,
    ACCESS_REQUIRED: 401,
    CONSENT_REQUIRED: 428,
    UNSUPPORTED_PLATFORM: 400,
    CHECKSUM_MISMATCH: 400,
    INSTALL_REQUIRED: 409,
    SSH_MISSING: 409,
    CSRF: 403,
    ORIGIN: 403,
    RATE_LIMITED: 429,
    PAIRING_INVALID: 400,
    PAIRING_EXPIRED: 410,
    PAIRING_DENIED: 403,
    PAIRING_CONSUMED: 403,
    DEVICE_LIMIT: 403,
    NOT_ALLOWED: 403,
    BAD_REQUEST: 400,
    NOT_FOUND: 404,
    GATEWAY: 502,
    INTERNAL: 500,
};
const SECURITY_CLOSED_REASONS = new Set([
    'user-emergency',
    'circuit-breaker',
    'idle-timeout',
    'tunnel-lost',
]);
const isRcCode = (value) => typeof value === 'string' && Object.prototype.hasOwnProperty.call(RC_ERRORS, value);
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const errorMessage = (error) => error instanceof Error ? error.message : String(error);
/** Short, non-sensitive device label sanitizer (pairing manager sanitizes too). */
export function sanitizeLabel(label) {
    return label
        .replace(/[\u0000-\u001f\u007f]/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, 64);
}
function readInt(value, fallback, min, max) {
    if (value === null || value === '')
        return fallback;
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed))
        return fallback;
    return Math.min(max, Math.max(min, parsed));
}
function stripTrailingSlash(value) {
    return value.replace(/\/+$/, '');
}
/** Canonical origin (`scheme://host[:port]`) or null for anything that is not a bare https origin. */
function normalizeHttpsOrigin(value) {
    const trimmed = value.trim();
    if (trimmed === '')
        return null;
    let parsed;
    try {
        parsed = new URL(trimmed);
    }
    catch {
        return null;
    }
    if (parsed.protocol !== 'https:')
        return null;
    if (parsed.username !== '' || parsed.password !== '')
        return null;
    if (parsed.pathname !== '/' && parsed.pathname !== '')
        return null;
    if (parsed.search !== '' || parsed.hash !== '')
        return null;
    return parsed.origin;
}
function isBareHostname(value) {
    const hostname = value.trim().toLowerCase().replace(/\.$/, '');
    if (hostname === '' || hostname.length > 253)
        return false;
    if (hostname.includes('/') || hostname.includes(':') || hostname.includes('@'))
        return false;
    return hostname.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
const AGENT_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
function tunnelModeForMethod(method) {
    switch (method) {
        case 'cloudflare-quick':
            return 'quick';
        case 'cloudflare-named':
            return 'named';
        case 'cloudflare-named-local':
            return 'named-local';
        case 'external':
            return 'external';
        case 'ssh':
            return 'ssh';
        default:
            return 'quick';
    }
}
function needsFixedHostname(method) {
    return method === 'cloudflare-named' || method === 'cloudflare-named-local' || method === 'external';
}
/** True only for the connection methods that execute/download cloudflared. */
function methodUsesCloudflared(method) {
    return (method === 'cloudflare-quick' ||
        method === 'cloudflare-named' ||
        method === 'cloudflare-named-local');
}
export function createController(deps) {
    const { ctx, config, log, pluginVersion } = deps;
    const audit = createAuditRing(RC_LIMITS.auditCapacity);
    const dshHome = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh');
    const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
    const staticRoot = resolve(packageRoot, 'dist/pwa');
    const idleTimeoutMs = deps.idleTimeoutMsOverride !== undefined && Number.isFinite(deps.idleTimeoutMsOverride) && deps.idleTimeoutMsOverride > 0
        ? deps.idleTimeoutMsOverride
        : config.security.idleTimeoutMinutes * 60_000;
    let stateStore = null;
    let deviceStore = null;
    let tokens = null;
    let pairing = null;
    let gateway = null;
    let dataPlane = null;
    let approvals = null;
    let wsBroker = null;
    let listener = null;
    let tunnelManager = null;
    let lease = null;
    let monitor = null;
    let accessVerifier = null;
    let enabled = false;
    let disposed = false;
    let initPromise = null;
    let initError = null;
    let lastState = { v: 2, lastEnabled: false, updatedAt: new Date(0).toISOString() };
    let dshRelease = 'unknown';
    let revocationEpoch = 0;
    let securityClosed = false;
    let securityClosedReason = null;
    let tunnelUrl = null;
    let tunnelWasUp = false;
    let runtimeStopping = false;
    let lastCode = null;
    let runtimeSelection = null;
    let currentListenerTls = false;
    const retiredRefresh = new Map();
    const lastSeenWrite = new Map();
    const refreshLocks = new Map();
    const planCache = new Map();
    let fencePolicy = createOriginPolicy();
    const httpsAuthorities = new Set();
    let transition = Promise.resolve();
    let shutdownPromise = null;
    /** Serializes persisted-state writes so an older snapshot can never win. */
    let stateWriteChain = Promise.resolve();
    let lastPersistedState = null;
    /** Session-level idle clock: armed by enable, renewed only by verified phone activity. */
    let activityTimer = null;
    /** Serialize lifecycle transitions (enable/disable/connection start/stop/shutdown). */
    function serial(task) {
        const next = transition.then(task, task);
        transition = next.then(() => undefined, () => undefined);
        return next;
    }
    function requireStores() {
        if (stateStore === null ||
            deviceStore === null ||
            tokens === null ||
            pairing === null ||
            lease === null ||
            monitor === null ||
            accessVerifier === null) {
            throw new RcHttpError(503, 'INTERNAL', 'remote control is still initializing');
        }
        return { stateStore, deviceStore, tokens, pairing, lease, monitor, accessVerifier };
    }
    function requireDataPlane() {
        if (dataPlane === null) {
            throw new RcHttpError(503, 'GATEWAY', 'DSH gateway is not available');
        }
        return dataPlane;
    }
    /** Public device view plus the single-active-device marker. */
    function toDeviceViewWithActive(device) {
        return { ...toDeviceView(device), active: lease?.activeDeviceId() === device.id };
    }
    /* ----------------------------------------------------------------------- */
    /* Audit helpers                                                           */
    /* ----------------------------------------------------------------------- */
    function auditPush(entry) {
        try {
            audit.push({
                deviceId: entry.deviceId ?? null,
                deviceLabel: entry.deviceLabel ?? null,
                kind: entry.kind,
                operation: entry.operation,
                result: entry.result ?? 'notice',
                ip: entry.ip ?? null,
                userAgent: entry.userAgent ?? null,
                detail: entry.detail ?? entry.operation,
            });
        }
        catch {
            // Audit must never break a request.
        }
        // Host logger mirror (main §8): the same non-sensitive metadata, sanitized
        // again for terminal/log safety. Prompt/tool content, tokens and cookies
        // never enter an audit entry.
        try {
            log.info('remote control audit', {
                kind: entry.kind,
                operation: sanitizeAuditText(entry.operation, 64),
                result: entry.result ?? 'notice',
                deviceId: sanitizeAuditText(entry.deviceId ?? '', 128) || null,
                ip: sanitizeAuditIp(entry.ip ?? null),
                userAgent: sanitizeAuditText(entry.userAgent, 160) || null,
                detail: sanitizeAuditText(entry.detail ?? entry.operation, 200),
            });
        }
        catch {
            // Logging must never break a request.
        }
    }
    const lockAuditAt = new Map();
    const LOCK_AUDIT_INTERVAL_MS = 60_000;
    const MAX_LOCK_AUDIT_KEYS = 128;
    /**
     * Audit + host-log one rejected second-device/session-activation attempt.
     * Repeated attempts from the same rejected device are throttled so the ring
     * and the desktop notification cannot be flooded.
     */
    function auditDeviceLockRejection(operation, detail, meta = {}) {
        const key = meta.key ?? meta.deviceId ?? operation;
        const at = Date.now();
        const previous = lockAuditAt.get(key) ?? 0;
        if (at - previous < LOCK_AUDIT_INTERVAL_MS)
            return;
        if (lockAuditAt.size >= MAX_LOCK_AUDIT_KEYS) {
            const oldest = lockAuditAt.keys().next();
            if (oldest.done !== true)
                lockAuditAt.delete(oldest.value);
        }
        lockAuditAt.set(key, at);
        auditPush({
            kind: 'device-lock',
            operation,
            result: 'rejected',
            deviceId: meta.deviceId ?? null,
            deviceLabel: meta.deviceLabel ?? null,
            ip: meta.ip ?? null,
            userAgent: meta.userAgent ?? null,
            detail,
        });
    }
    /** Trusted-proxy policy is scoped to the provider that terminates the public connection. */
    function trustedProxyPolicy() {
        if (runtimeSelection !== null && runtimeSelection.method !== 'lan' && runtimeSelection.method !== 'loopback') {
            return proxyPolicyForTunnelMode(tunnelModeForMethod(runtimeSelection.method));
        }
        if (!enabled && config.tunnel.enabled)
            return proxyPolicyForTunnelMode(config.tunnel.mode);
        return 'none';
    }
    function requestMeta(request) {
        const resolution = resolveClientIp(request, { trustedProxy: trustedProxyPolicy() });
        const rawAgent = request.headers['user-agent'];
        const userAgent = Array.isArray(rawAgent) ? rawAgent[0] : rawAgent;
        return { ip: resolution.ip, userAgent: typeof userAgent === 'string' ? userAgent : null };
    }
    /**
     * Access enforcement is the union of the config switch and the active run's
     * per-selection requirement: a desktop plan that requires Cloudflare Access
     * must be enforced even when `config.tunnel.access.required` is false. The
     * verifier (and its JWKS cache) is reused; only its switch changes.
     */
    function syncAccessEnforcement() {
        const selectionRequired = runtimeSelection?.accessRequired === true;
        accessVerifier?.setRequired(config.tunnel.access.required || selectionRequired);
    }
    /* ----------------------------------------------------------------------- */
    /* Persisted state                                                         */
    /* ----------------------------------------------------------------------- */
    async function persistState(overrides, options = {}) {
        const store = stateStore;
        if (store === null)
            return;
        const raw = lease?.raw() ?? { deviceId: null, startedAt: null, lastActivityAt: null };
        const next = {
            v: 2,
            lastEnabled: overrides?.lastEnabled ?? enabled,
            updatedAt: new Date().toISOString(),
            revocationEpoch,
            securityClosed,
            securityClosedReason,
            activeDeviceId: raw.deviceId,
            leaseStartedAt: raw.startedAt,
            leaseLastActivityAt: raw.lastActivityAt,
            ...overrides,
        };
        const write = stateWriteChain.then(async () => {
            const previous = lastPersistedState;
            if (previous !== null) {
                const previousEpoch = typeof previous.revocationEpoch === 'number' && Number.isSafeInteger(previous.revocationEpoch)
                    ? previous.revocationEpoch
                    : 0;
                const nextEpoch = typeof next.revocationEpoch === 'number' && Number.isSafeInteger(next.revocationEpoch)
                    ? next.revocationEpoch
                    : 0;
                // Never let a stale in-flight snapshot roll back the persisted epoch.
                if (nextEpoch < previousEpoch)
                    return;
                // Never clear a persisted security closure without an explicit re-enable.
                if (previous.securityClosed === true && next.securityClosed !== true && options.allowReopen !== true) {
                    return;
                }
            }
            try {
                await store.save(next);
                lastPersistedState = next;
                lastState = next;
            }
            catch (error) {
                log.warn('could not persist plugin state', errorMessage(error));
            }
        });
        stateWriteChain = write.then(() => undefined, () => undefined);
        return write;
    }
    function applyPersistedSecurity(state) {
        const epoch = state.revocationEpoch;
        revocationEpoch = typeof epoch === 'number' && Number.isSafeInteger(epoch) && epoch >= 0 ? epoch : 0;
        securityClosed = state.securityClosed === true;
        const reason = typeof state.securityClosedReason === 'string' ? state.securityClosedReason : null;
        securityClosedReason =
            reason !== null && SECURITY_CLOSED_REASONS.has(reason)
                ? reason
                : securityClosed
                    ? 'user-emergency'
                    : null;
    }
    /* ----------------------------------------------------------------------- */
    /* Authority / origin computation (Â§3 single effective runtime state)      */
    /* ----------------------------------------------------------------------- */
    function listenerStatus() {
        if (listener === null) {
            return {
                state: 'off',
                host: null,
                port: null,
                url: null,
                secure: false,
                lan: false,
                access: effectiveAccess(),
                protocol: 'http',
            };
        }
        return listener.status();
    }
    function effectiveAccess() {
        const selection = runtimeSelection;
        if (selection !== null && selection.method === 'lan')
            return 'lan';
        return config.listen.access === 'lan' ? 'lan' : 'loopback';
    }
    function lanAccessActive() {
        const status = listenerStatus();
        return status.access === 'lan' || status.lan === true;
    }
    function publicOrigin() {
        if (!enabled)
            return null;
        const tunnel = tunnelManager?.status() ?? null;
        if (tunnel !== null && tunnel.url !== null)
            return stripTrailingSlash(tunnel.url);
        if (tunnelUrl !== null)
            return stripTrailingSlash(tunnelUrl);
        // External connectors have no child process and no runtime URL; their fixed
        // operator-provided HTTPS origin is only advertised while access is running.
        if (activeSelection().method === 'external') {
            const fixed = normalizeHttpsOrigin(runtimeSelection?.publicUrl ?? config.tunnel.publicUrl);
            if (fixed !== null)
                return fixed;
        }
        return null;
    }
    function lanOrigin() {
        const status = listenerStatus();
        if (status.state !== 'listening' || status.host === null || status.port === null)
            return null;
        if (status.access !== 'lan' && status.lan !== true)
            return null;
        return `${status.secure ? 'https' : 'http'}://${formatHostForAuthority(status.host)}:${status.port}`;
    }
    function activeSelection() {
        if (runtimeSelection !== null)
            return runtimeSelection;
        return selectionFromConfig();
    }
    function currentMethod() {
        return activeSelection().method;
    }
    function rebuildAuthorities() {
        const origins = [];
        const authorities = [];
        httpsAuthorities.clear();
        const status = listenerStatus();
        if (status.state === 'listening' && status.host !== null && status.port !== null) {
            const protocol = status.secure ? 'https' : 'http';
            const port = status.port;
            const hosts = status.host === '127.0.0.1'
                ? ['127.0.0.1', 'localhost', '[::1]']
                : status.host === '::1'
                    ? ['[::1]', '127.0.0.1', 'localhost']
                    : [formatHostForAuthority(status.host)];
            for (const host of hosts) {
                authorities.push(`${host}:${port}`);
                origins.push(`${protocol}://${host}:${port}`);
            }
            if (status.access === 'lan') {
                const lan = lanOrigin();
                if (lan !== null)
                    origins.push(lan);
            }
        }
        const pub = publicOrigin();
        if (pub !== null) {
            origins.push(pub);
            try {
                const authority = canonicalAuthority(new URL(pub).host);
                if (authority !== null)
                    authorities.push(authority);
            }
            catch {
                log.warn('public origin is not a valid URL');
            }
        }
        for (const configured of config.allowedOrigins) {
            origins.push(configured);
            try {
                const authority = canonicalAuthority(new URL(configured.trim()).host);
                if (authority !== null)
                    authorities.push(authority);
            }
            catch {
                log.warn('allowedOrigins entry is not a valid origin');
            }
        }
        fencePolicy = createOriginPolicy({ origins, authorities });
        for (const origin of fencePolicy.allowedOrigins) {
            if (!origin.startsWith('https://'))
                continue;
            try {
                const authority = canonicalAuthority(new URL(origin).host);
                if (authority !== null)
                    httpsAuthorities.add(authority);
            }
            catch {
                // createOriginPolicy already validated the origin; ignore transient parsing.
            }
        }
    }
    function requestIsHttps(request) {
        if (request.socket.encrypted === true)
            return true;
        const rawHost = request.headers.host;
        if (typeof rawHost !== 'string' || rawHost === '')
            return false;
        const authority = canonicalAuthority(rawHost);
        return authority !== null && httpsAuthorities.has(authority);
    }
    function fenceOk(request) {
        return checkOriginFence(request, fencePolicy, { requireOrigin: false }).ok;
    }
    function requireMutationGuard(request) {
        if (!isCsrfOk(request)) {
            throw new RcHttpError(403, 'CSRF', 'missing CSRF header');
        }
        if (!checkOriginFence(request, fencePolicy, { requireOrigin: true }).ok) {
            throw new RcHttpError(403, 'ORIGIN', 'origin not allowed');
        }
    }
    function ensureRemoteOpen() {
        if (securityClosed) {
            throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
        }
        if (!enabled) {
            throw new RcHttpError(503, 'NOT_ALLOWED', 'remote control is disabled');
        }
    }
    function securityClosedMessage() {
        switch (securityClosedReason) {
            case 'circuit-breaker':
                return 'remote access was closed by the authentication circuit breaker; re-enable it from the desktop panel';
            case 'idle-timeout':
                return 'remote access was closed after the idle timeout; re-enable it from the desktop panel';
            case 'tunnel-lost':
                return 'remote access was closed because the public tunnel was lost; re-enable it from the desktop panel';
            default:
                return 'remote access is closed after an emergency stop; re-enable it from the desktop panel';
        }
    }
    /* ----------------------------------------------------------------------- */
    /* Session idle clock (main §7)                                            */
    /* ----------------------------------------------------------------------- */
    function clearIdleTimer() {
        if (activityTimer !== null) {
            clearTimeout(activityTimer);
            activityTimer = null;
        }
    }
    /**
     * (Re)arm the 30-minute idle clock. Only a verified phone request or an
     * authenticated client heartbeat calls this: desktop polling, anonymous
     * traffic, health/static requests and server-side pings never renew it.
     */
    function armIdleTimer() {
        clearIdleTimer();
        if (!enabled || securityClosed || disposed)
            return;
        activityTimer = setTimeout(() => {
            activityTimer = null;
            if (enabled && !securityClosed)
                void requestSecurityShutdown('idle-timeout');
        }, idleTimeoutMs);
        activityTimer.unref();
    }
    function touchRemoteActivity() {
        if (enabled && !securityClosed)
            armIdleTimer();
    }
    /* ----------------------------------------------------------------------- */
    /* Failure accounting (shared by every secret-verification path)           */
    /* ----------------------------------------------------------------------- */
    function ensureNotBlocked(request) {
        const resolution = resolveClientIp(request, { trustedProxy: trustedProxyPolicy() });
        const monitorRef = monitor;
        if (monitorRef === null)
            return { ip: resolution.ip, bucket: resolution.bucket };
        const state = monitorRef.blocked(resolution.bucket);
        if (state.blocked) {
            throw new RcHttpError(429, 'RATE_LIMITED', 'too many authentication failures; try again later', state.retryAfterMs);
        }
        return { ip: resolution.ip, bucket: resolution.bucket };
    }
    function noteAuthFailure(ip, path) {
        monitor?.recordFailure(ip, path);
    }
    function noteAuthSuccess(ip) {
        monitor?.recordSuccess(ip);
    }
    /* ----------------------------------------------------------------------- */
    /* Device auth                                                             */
    /* ----------------------------------------------------------------------- */
    function accessTtlMs() {
        return resolveAccessTtlMs(config.tokens);
    }
    function touchDevice(device) {
        const now = Date.now();
        const previous = lastSeenWrite.get(device.id) ?? 0;
        if (now - previous < LAST_SEEN_WRITE_INTERVAL_MS)
            return;
        lastSeenWrite.set(device.id, now);
        const store = deviceStore;
        if (store === null)
            return;
        // Only the lastSeenAt field is changed: a concurrent refresh rotation keeps
        // its rotated hash instead of being overwritten by this snapshot.
        void store.touch(device.id, now).catch((error) => {
            log.warn('could not persist device lastSeenAt', errorMessage(error));
        });
    }
    /**
     * Authenticate the access cookie, enforce the single-active-device lease and
     * count failures on the shared monitor. Missing credentials are not counted as
     * failures (they are unauthenticated traffic, not a failed attempt).
     */
    async function authenticate(request, options = {}) {
        const { deviceStore: store, tokens: tokenService, lease: leaseRef } = requireStores();
        ensureRemoteOpen();
        const client = ensureNotBlocked(request);
        const cookies = parseCookies(request.headers.cookie);
        const access = cookies[RC_ACCESS_COOKIE];
        if (access === undefined || access === '') {
            throw new RcHttpError(401, 'AUTH_REQUIRED', 'access token required');
        }
        let claims;
        let accessExpired = false;
        try {
            if (typeof tokenService.verifyAccessDetailed === 'function') {
                const detailed = tokenService.verifyAccessDetailed(access, revocationEpoch);
                if (detailed.state === 'invalid') {
                    claims = null;
                }
                else {
                    claims = detailed.claims;
                    accessExpired = detailed.state === 'expired';
                }
            }
            else {
                claims = tokenService.verifyAccess(access, revocationEpoch);
            }
        }
        catch {
            claims = null;
        }
        if (claims === null) {
            noteAuthFailure(client.bucket, options.path ?? 'access');
            throw new RcHttpError(401, 'TOKEN_EXPIRED', 'access token is missing or expired');
        }
        if (accessExpired) {
            // A normally expired access token is not an attack: the phone refreshes
            // with its refresh cookie. No failure accounting, no session counter bump.
            throw new RcHttpError(401, 'TOKEN_EXPIRED', 'access token expired; refresh and retry');
        }
        const device = store.get(claims.deviceId);
        if (device === undefined) {
            noteAuthFailure(client.bucket, options.path ?? 'access');
            throw new RcHttpError(401, 'DEVICE_REVOKED', 'device is not paired');
        }
        if (device.tokenVersion !== claims.tokenVersion) {
            noteAuthFailure(client.bucket, options.path ?? 'access');
            throw new RcHttpError(401, 'DEVICE_REVOKED', 'token version changed');
        }
        const active = leaseRef.activeDeviceId();
        if (active !== null && active !== device.id) {
            const meta = requestMeta(request);
            auditDeviceLockRejection('session.lock', 'another device currently holds the remote-control lock', {
                deviceId: device.id,
                deviceLabel: device.label,
                ...meta,
            });
            throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device currently holds the remote-control lock');
        }
        if (active === null) {
            if (store.count() > 1) {
                const meta = requestMeta(request);
                auditDeviceLockRejection('session.lock', 'active-device selection required in the desktop panel', {
                    key: 'selection',
                    deviceId: device.id,
                    deviceLabel: device.label,
                    ...meta,
                });
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'select the active device from the desktop panel');
            }
            if (!leaseRef.activate(device.id)) {
                const meta = requestMeta(request);
                auditDeviceLockRejection('session.lock', 'another device currently holds the remote-control lock', {
                    deviceId: device.id,
                    deviceLabel: device.label,
                    ...meta,
                });
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device currently holds the remote-control lock');
            }
            await persistState();
        }
        if (options.touch !== false)
            leaseRef.touch(device.id);
        touchDevice(device);
        noteAuthSuccess(client.bucket);
        touchRemoteActivity();
        return { device, expiresAt: claims.expiresAt };
    }
    function setAuthCookies(response, request, device, access, refresh) {
        const secure = requestIsHttps(request);
        const accessMaxAge = Math.max(1, Math.floor((access.expiresAt - Date.now()) / 1000));
        const refreshMaxAge = Math.max(1, Math.floor((refresh.expiresAt - Date.now()) / 1000));
        response.setHeader('Set-Cookie', [
            serializeCookie(RC_ACCESS_COOKIE, access.token, {
                maxAgeSeconds: accessMaxAge,
                path: COOKIE_PATH,
                httpOnly: true,
                secure,
                sameSite: 'Strict',
            }),
            serializeCookie(RC_REFRESH_COOKIE, refresh.token, {
                maxAgeSeconds: refreshMaxAge,
                path: COOKIE_PATH,
                httpOnly: true,
                secure,
                sameSite: 'Strict',
            }),
        ]);
        log.debug('auth cookies issued', { deviceId: device.id, secure });
    }
    function clearAuthCookies(response, request) {
        const secure = requestIsHttps(request);
        response.setHeader('Set-Cookie', [
            clearCookie(RC_ACCESS_COOKIE, { path: COOKIE_PATH, secure }),
            clearCookie(RC_REFRESH_COOKIE, { path: COOKIE_PATH, secure }),
        ]);
    }
    async function createDevice(details) {
        const { deviceStore: store, tokens: tokenService } = requireStores();
        if (store.count() >= config.tokens.maxDevices) {
            throw new RcHttpError(403, 'DEVICE_LIMIT', 'maximum number of paired devices reached');
        }
        const device = {
            id: randomUUID(),
            label: sanitizeLabel(details.deviceName) || 'Phone',
            platform: sanitizeLabel(details.platform) || 'unknown',
            createdAt: Date.now(),
            lastSeenAt: Date.now(),
            refreshExpiresAt: 0,
            tokenVersion: 1,
            tokenKey: randomBytes(32).toString('base64url'),
            refreshHash: '',
        };
        const refresh = tokenService.issueRefresh(device);
        device.refreshHash = refresh.hash;
        device.refreshExpiresAt = refresh.expiresAt;
        await store.add(device);
        const access = tokenService.issueAccess(device, revocationEpoch);
        return { device, access, refresh };
    }
    async function revokeDevice(device, reason) {
        const { deviceStore: store, lease: leaseRef } = requireStores();
        await store.remove(device.id);
        retiredRefresh.delete(device.id);
        lastSeenWrite.delete(device.id);
        if (leaseRef.activeDeviceId() === device.id)
            leaseRef.release('revoke');
        try {
            wsBroker?.closeDevice(device.id, 'device-revoked', RC_WS_CLOSE.deviceLost);
        }
        catch (error) {
            log.warn('could not close device sockets', errorMessage(error));
        }
        auditPush({
            kind: 'revoke',
            operation: 'device.revoke',
            result: 'ok',
            deviceId: device.id,
            deviceLabel: device.label,
            detail: reason,
        });
        await persistState();
    }
    /* ----------------------------------------------------------------------- */
    /* Safe shutdown (Â§7)                                                      */
    /* ----------------------------------------------------------------------- */
    function requestSecurityShutdown(reason) {
        if (shutdownPromise !== null)
            return shutdownPromise;
        // Take effect immediately, even when a long serialized transition (install
        // download, tunnel startup) is still in flight: new requests must already be
        // rejected before the asynchronous teardown gets its turn in the queue.
        if (!securityClosed) {
            securityClosed = true;
            securityClosedReason = reason;
        }
        enabled = false;
        clearIdleTimer();
        lease?.release('emergency');
        monitor?.endSession();
        shutdownPromise = runSecurityShutdown(reason, { persistClosed: true })
            .catch((error) => {
            log.error('security shutdown failed', errorMessage(error));
        })
            .finally(() => {
            shutdownPromise = null;
        });
        return shutdownPromise;
    }
    /**
     * One idempotent, race-safe shutdown used by emergency stop, circuit breaker,
     * idle timeout, unexpected tunnel loss and plugin dispose.
     *
     * Order matters: the closed flag and the bumped revocation epoch are persisted
     * BEFORE the asynchronous teardown so a crash mid-teardown still leaves old
     * tokens invalid after a DSH restart.
     */
    async function runSecurityShutdown(reason, options) {
        return serial(async () => {
            const wasEnabled = options.wasEnabled ?? enabled;
            const wasClosed = securityClosed;
            const previousClosedReason = securityClosedReason;
            securityClosed = true;
            securityClosedReason = reason;
            revocationEpoch = revocationEpoch >= Number.MAX_SAFE_INTEGER - 1 ? 1 : revocationEpoch + 1;
            enabled = false;
            clearIdleTimer();
            lease?.release('emergency');
            monitor?.endSession();
            // A plugin dispose never re-opens access that was already security-closed.
            const effectiveClosed = options.persistClosed || wasClosed;
            try {
                await persistState({
                    securityClosed: effectiveClosed,
                    securityClosedReason: effectiveClosed ? (options.persistClosed ? reason : (previousClosedReason ?? reason)) : null,
                    lastEnabled: options.persistClosed ? false : wasEnabled,
                    activeDeviceId: null,
                    leaseStartedAt: null,
                    leaseLastActivityAt: null,
                }, { allowReopen: true });
            }
            catch (error) {
                log.warn('could not persist security shutdown state', errorMessage(error));
            }
            await revokeAllDevices(`security-shutdown:${reason}`);
            lastCode = null;
            planCache.clear();
            retiredRefresh.clear();
            runtimeSelection = null;
            syncAccessEnforcement();
            try {
                pairing?.dispose();
            }
            catch {
                // ignore
            }
            pairing = null;
            await stopRuntime(true);
            try {
                pairing = createPairingManagerInstance();
            }
            catch (error) {
                log.warn('could not recreate the pairing manager', errorMessage(error));
            }
            if (!effectiveClosed)
                securityClosed = false;
            auditPush({
                kind: 'security',
                operation: 'security.shutdown',
                result: 'ok',
                detail: reason,
            });
            log.warn('remote access security shutdown', { reason, persistClosed: options.persistClosed });
        });
    }
    async function revokeAllDevices(reason) {
        const store = deviceStore;
        if (store === null)
            return;
        for (const device of store.list()) {
            try {
                await store.remove(device.id);
            }
            catch (error) {
                log.warn('could not revoke a device during shutdown', errorMessage(error));
            }
            retiredRefresh.delete(device.id);
            lastSeenWrite.delete(device.id);
            auditPush({ kind: 'revoke', operation: 'device.revoke', result: 'ok', deviceId: device.id, deviceLabel: device.label, detail: reason });
        }
        try {
            wsBroker?.closeAll('security-closed', RC_WS_CLOSE.securityClosed);
        }
        catch {
            // ignore
        }
    }
    /* ----------------------------------------------------------------------- */
    /* HTTP plumbing                                                           */
    /* ----------------------------------------------------------------------- */
    function respondError(response, error) {
        if (error instanceof RcHttpError) {
            sendError(response, error.status, error.code, error.message, error.retryAfterMs);
            return;
        }
        const code = error.code;
        if (isRcCode(code)) {
            const message = error instanceof Error ? error.message : 'request failed';
            sendError(response, STATUS_BY_CODE[code], code, message);
            return;
        }
        log.error('unhandled phone API error', error instanceof Error ? error.name : 'unknown');
        sendError(response, 500, 'INTERNAL', 'unexpected error');
    }
    async function readBody(request, limitBytes = 64 * 1024) {
        const body = await readJsonBody(request, limitBytes);
        if (body === null || typeof body !== 'object' || Array.isArray(body)) {
            throw new RcHttpError(400, 'BAD_REQUEST', 'JSON object body required');
        }
        return body;
    }
    function requireString(value, name, maxLength = 200) {
        if (typeof value !== 'string' || value.trim() === '') {
            throw new RcHttpError(400, 'BAD_REQUEST', `${name} is required`);
        }
        if (value.length > maxLength) {
            throw new RcHttpError(400, 'BAD_REQUEST', `${name} is too long`);
        }
        return value;
    }
    /* ----------------------------------------------------------------------- */
    /* Phone routes                                                            */
    /* ----------------------------------------------------------------------- */
    function health() {
        const store = deviceStore;
        return {
            ok: true,
            protocol: PROTOCOL_VERSION,
            pluginVersion,
            dshRelease,
            secure: currentListenerTls || publicOrigin()?.startsWith('https://') === true,
            pairingAvailable: enabled &&
                !securityClosed &&
                store !== null &&
                store.count() < config.tokens.maxDevices &&
                pairingBaseUrl() !== null,
            securityClosed,
        };
    }
    async function pairClaim(request) {
        const { deviceStore: store, pairing: pairingManager, monitor: monitorRef } = requireStores();
        if (securityClosed)
            throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
        if (!enabled)
            throw new RcHttpError(503, 'NOT_ALLOWED', 'remote control is disabled');
        const client = ensureNotBlocked(request);
        if (lease?.activeDeviceId() !== null && lease?.activeDeviceId() !== undefined) {
            auditDeviceLockRejection('pair.claim', 'another device is currently active', {
                key: 'pair',
                ...requestMeta(request),
            });
            throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device is currently active');
        }
        if (store.count() > 1) {
            auditDeviceLockRejection('pair.claim', 'active-device selection required in the desktop panel', {
                key: 'selection',
                ...requestMeta(request),
            });
            throw new RcHttpError(409, 'DEVICE_LOCKED', 'select the active device from the desktop panel first');
        }
        if (store.count() >= config.tokens.maxDevices) {
            throw new RcHttpError(403, 'DEVICE_LIMIT', 'maximum number of paired devices reached');
        }
        const body = await readBody(request);
        const code = requireString(body.code, 'code', 512);
        const deviceName = sanitizeLabel(requireString(body.deviceName ?? 'Phone', 'deviceName', 128));
        const platform = sanitizeLabel(requireString(body.platform ?? 'unknown', 'platform', 64));
        const result = pairingManager.claim({ code, deviceName, platform });
        if (!result.ok) {
            if (result.code === 'PAIRING_INVALID' ||
                result.code === 'PAIRING_EXPIRED' ||
                result.code === 'PAIRING_CONSUMED') {
                noteAuthFailure(client.bucket, 'pair');
            }
            throw new RcHttpError(STATUS_BY_CODE[result.code], result.code, result.message);
        }
        noteAuthSuccess(client.bucket);
        auditPush({
            kind: 'pair',
            operation: 'pair.claim',
            result: 'ok',
            ip: requestMeta(request).ip,
            userAgent: requestMeta(request).userAgent,
            detail: `claim ${result.claimId.slice(0, 8)}`,
        });
        return {
            ok: true,
            claimId: result.claimId,
            pollToken: result.pollToken,
            status: 'claimed',
            expiresAt: result.expiresAt,
        };
    }
    async function pairStatus(request, response) {
        const { pairing: pairingManager, tokens: tokenService, lease: leaseRef } = requireStores();
        if (securityClosed)
            throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
        if (!enabled)
            throw new RcHttpError(503, 'NOT_ALLOWED', 'remote control is disabled');
        const client = ensureNotBlocked(request);
        const body = await readBody(request);
        const claimId = requireString(body.claimId, 'claimId', 128);
        const pollToken = requireString(body.pollToken, 'pollToken', 512);
        let state = pairingManager.status(claimId, pollToken);
        const expiresAt = Date.now() + config.pairing.ttlSeconds * 1000;
        if (state === 'approved') {
            const details = typeof pairingManager.beginIssue === 'function' ? pairingManager.beginIssue(claimId, pollToken) : null;
            if (details === null) {
                noteAuthFailure(client.bucket, 'poll');
                throw new RcHttpError(410, 'PAIRING_EXPIRED', 'pairing approval has already been consumed');
            }
            if (leaseRef.activeDeviceId() !== null) {
                pairingManager.consume(claimId);
                auditDeviceLockRejection('pair.issue', 'another device is currently active', {
                    key: 'pair',
                    ...requestMeta(request),
                });
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device is currently active');
            }
            let created;
            try {
                created = await createDevice(details);
            }
            catch (error) {
                pairingManager.consume(claimId);
                throw error;
            }
            if (!leaseRef.activate(created.device.id)) {
                await deviceStore?.remove(created.device.id).catch(() => undefined);
                pairingManager.consume(claimId);
                auditDeviceLockRejection('pair.issue', 'another device is currently active', {
                    key: 'pair',
                    ...requestMeta(request),
                });
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device is currently active');
            }
            if (securityClosed || !enabled) {
                await deviceStore?.remove(created.device.id).catch(() => undefined);
                leaseRef.release('security');
                pairingManager.consume(claimId);
                throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
            }
            pairingManager.consume(claimId);
            lastCode = null;
            await persistState();
            noteAuthSuccess(client.bucket);
            touchRemoteActivity();
            setAuthCookies(response, request, created.device, created.access, created.refresh);
            auditPush({
                kind: 'pair',
                operation: 'pair.approved',
                result: 'ok',
                deviceId: created.device.id,
                deviceLabel: created.device.label,
                ...requestMeta(request),
                detail: 'approved',
            });
            return { ok: true, status: 'approved', expiresAt, device: toDeviceViewWithActive(created.device) };
        }
        state = state === 'claimed-timeout' ? 'expired' : state;
        if (state === 'denied')
            throw new RcHttpError(403, 'PAIRING_DENIED', 'pairing was denied');
        if (state === 'expired') {
            noteAuthFailure(client.bucket, 'poll');
            throw new RcHttpError(410, 'PAIRING_EXPIRED', 'pairing code expired');
        }
        if (state === 'claimed' || state === 'pending')
            noteAuthSuccess(client.bucket);
        return { ok: true, status: state, expiresAt };
    }
    async function withDeviceLock(deviceId, task) {
        const previous = refreshLocks.get(deviceId) ?? Promise.resolve();
        const run = previous.then(task, task);
        const chain = run.then(() => undefined, () => undefined);
        refreshLocks.set(deviceId, chain);
        try {
            return await run;
        }
        finally {
            if (refreshLocks.get(deviceId) === chain)
                refreshLocks.delete(deviceId);
        }
    }
    async function refresh(request, response) {
        const { deviceStore: store, tokens: tokenService, lease: leaseRef } = requireStores();
        if (securityClosed)
            throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
        const client = ensureNotBlocked(request);
        const cookies = parseCookies(request.headers.cookie);
        const token = cookies[RC_REFRESH_COOKIE];
        if (token === undefined || token === '') {
            throw new RcHttpError(401, 'AUTH_REQUIRED', 'refresh token required');
        }
        const subject = tokenService.readRefreshSubject(token);
        if (subject === null) {
            noteAuthFailure(client.bucket, 'refresh');
            throw new RcHttpError(401, 'TOKEN_EXPIRED', 'refresh token is invalid');
        }
        const initial = store.get(subject.deviceId);
        if (initial === undefined) {
            noteAuthFailure(client.bucket, 'refresh');
            throw new RcHttpError(401, 'DEVICE_REVOKED', 'device is not paired');
        }
        const activeId = leaseRef.activeDeviceId();
        if (activeId !== null && activeId !== initial.id) {
            throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device currently holds the remote-control lock');
        }
        return withDeviceLock(initial.id, async () => {
            const device = store.get(initial.id);
            if (device === undefined) {
                noteAuthFailure(client.bucket, 'refresh');
                throw new RcHttpError(401, 'DEVICE_REVOKED', 'device is not paired');
            }
            const hash = tokenService.hashRefresh(token);
            if (!tokenService.equalRefresh(hash, device.refreshHash)) {
                const retired = retiredRefresh.get(device.id) ?? [];
                const now = Date.now();
                const raced = retired.some((entry) => now - entry.at <= REFRESH_CONCURRENCY_GRACE_MS && tokenService.equalHex(entry.hash, hash));
                if (!raced) {
                    await revokeDevice(device, 'refresh-reuse');
                    noteAuthFailure(client.bucket, 'refresh');
                    throw new RcHttpError(401, 'DEVICE_REVOKED', 'refresh token reuse detected; device revoked');
                }
                // A concurrent rotation from the same phone already happened; the client
                // must retry with the cookie from the winning response. No second session.
                throw new RcHttpError(401, 'TOKEN_EXPIRED', 'refresh token was already rotated');
            }
            if (device.refreshExpiresAt <= Date.now()) {
                noteAuthFailure(client.bucket, 'refresh');
                throw new RcHttpError(401, 'TOKEN_EXPIRED', 'refresh token expired');
            }
            if (leaseRef.activeDeviceId() === null) {
                if (store.count() > 1) {
                    throw new RcHttpError(409, 'DEVICE_LOCKED', 'select the active device from the desktop panel');
                }
                if (!leaseRef.activate(device.id)) {
                    throw new RcHttpError(409, 'DEVICE_LOCKED', 'another device currently holds the remote-control lock');
                }
            }
            const retired = retiredRefresh.get(device.id) ?? [];
            retired.push({ hash: device.refreshHash, at: Date.now() });
            retiredRefresh.set(device.id, retired.slice(-RETIRED_REFRESH_LIMIT));
            const nextRefresh = tokenService.issueRefresh(device);
            device.refreshHash = nextRefresh.hash;
            device.refreshExpiresAt = nextRefresh.expiresAt;
            device.lastSeenAt = Date.now();
            await store.update(device);
            leaseRef.touch(device.id);
            touchRemoteActivity();
            const access = tokenService.issueAccess(device, revocationEpoch);
            setAuthCookies(response, request, device, access, nextRefresh);
            noteAuthSuccess(client.bucket);
            await persistState();
            return { ok: true, device: toDeviceViewWithActive(device) };
        });
    }
    async function logout(request, response) {
        const { device } = await authenticate(request);
        await revokeDevice(device, 'logout');
        clearAuthCookies(response, request);
        return { ok: true };
    }
    async function state(request) {
        const { device } = await authenticate(request);
        const { lease: leaseRef } = requireStores();
        const deviceCount = deviceStore?.count() ?? 0;
        return {
            ok: true,
            enabled,
            pluginVersion,
            dshRelease,
            device: toDeviceViewWithActive(device),
            deviceCount,
            dshReachable: gateway !== null,
            deviceLock: deviceLockView(),
            secure: requestIsHttps(request),
            idleExpiresAt: leaseRef.idleExpiresAt(),
        };
    }
    async function sessions(request) {
        await authenticate(request);
        const plane = requireDataPlane();
        const items = await plane.list();
        if (typeof plane.workspaces !== 'function')
            return { ok: true, sessions: items };
        const groups = await plane.workspaces();
        return { ok: true, sessions: items, workspaces: groups };
    }
    async function createSession(request) {
        const { device } = await authenticate(request);
        const plane = requireDataPlane();
        if (typeof plane.createSession !== 'function') {
            throw new RcHttpError(501, 'NOT_ALLOWED', 'session creation is not available on this host');
        }
        const body = await readBody(request);
        const createRequest = {};
        if (body.workspaceId !== undefined) {
            if (typeof body.workspaceId !== 'string' || body.workspaceId.length === 0 || body.workspaceId.length > 200) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'workspaceId must be a non-empty short string');
            }
            createRequest.workspaceId = body.workspaceId;
        }
        if (body.cwd !== undefined) {
            if (typeof body.cwd !== 'string' || body.cwd.trim().length === 0 || body.cwd.length > 4096) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'cwd must be a non-empty path');
            }
            createRequest.cwd = body.cwd;
        }
        if (createRequest.workspaceId !== undefined && createRequest.cwd !== undefined) {
            throw new RcHttpError(400, 'BAD_REQUEST', 'workspaceId and cwd are mutually exclusive');
        }
        const result = await plane.createSession(createRequest);
        auditPush({
            kind: 'rpc',
            operation: 'session.create',
            result: 'ok',
            deviceId: device.id,
            deviceLabel: device.label,
            detail: `session ${result.sessionId.slice(0, 12)}`,
        });
        return result;
    }
    async function uploadFile(request, sessionId) {
        const { device } = await authenticate(request);
        const plane = requireDataPlane();
        if (typeof plane.uploadFile !== 'function') {
            throw new RcHttpError(501, 'NOT_ALLOWED', 'file upload is not available on this host');
        }
        const body = await readBody(request, RC_LIMITS.maxPromptBodyBytes);
        const name = typeof body.name === 'string' ? body.name : undefined;
        const data = typeof body.data === 'string' ? body.data : '';
        const result = await plane.uploadFile(sessionId, name === undefined ? { data } : { data, name });
        auditPush({
            kind: 'rpc',
            operation: 'session.file-upload',
            result: 'ok',
            deviceId: device.id,
            deviceLabel: device.label,
            detail: `session ${sessionId.slice(0, 12)}`,
        });
        return result;
    }
    async function readAttachment(request, sessionId, attachmentId) {
        await authenticate(request);
        const plane = requireDataPlane();
        if (typeof plane.readAttachment !== 'function') {
            throw new RcHttpError(501, 'NOT_ALLOWED', 'attachments are not available on this host');
        }
        return plane.readAttachment(sessionId, attachmentId);
    }
    async function projections(request, sessionId) {
        await authenticate(request);
        if (sessionId === '')
            throw new RcHttpError(400, 'BAD_REQUEST', 'sessionId is required');
        return requireDataPlane().projections(sessionId);
    }
    async function page(request, sessionId, query) {
        await authenticate(request);
        if (sessionId === '')
            throw new RcHttpError(400, 'BAD_REQUEST', 'sessionId is required');
        const pageRequest = {};
        const throughSeq = query.get('throughSeq');
        const beforeSeq = query.get('beforeSeq');
        if (throughSeq !== null)
            pageRequest.throughSeq = readInt(throughSeq, 0, 0, Number.MAX_SAFE_INTEGER);
        if (beforeSeq !== null)
            pageRequest.beforeSeq = readInt(beforeSeq, 0, 0, Number.MAX_SAFE_INTEGER);
        pageRequest.maxMessages = readInt(query.get('maxMessages'), RC_LIMITS.pageDefaultMessages, 1, RC_LIMITS.maxMessages);
        return requireDataPlane().page(sessionId, pageRequest);
    }
    async function prompt(request, sessionId, body) {
        const { device } = await authenticate(request);
        if (sessionId === '')
            throw new RcHttpError(400, 'BAD_REQUEST', 'sessionId is required');
        const mode = body.mode === undefined ? 'queue' : body.mode;
        if (mode !== 'queue' && mode !== 'steer') {
            throw new RcHttpError(400, 'BAD_REQUEST', 'mode must be queue or steer');
        }
        const content = normalizePromptContent(body.content);
        const promptRequest = { mode, content };
        if (typeof body.requestId === 'string' && body.requestId !== '') {
            promptRequest.requestId = body.requestId.slice(0, 128);
        }
        if (typeof body.clientTimeZone === 'string' && body.clientTimeZone !== '') {
            promptRequest.clientTimeZone = body.clientTimeZone.slice(0, 64);
        }
        const result = await requireDataPlane().prompt(sessionId, promptRequest);
        auditPush({
            kind: 'rpc',
            operation: mode === 'steer' ? 'session.steer' : 'session.prompt',
            result: 'ok',
            deviceId: device.id,
            deviceLabel: device.label,
            detail: `session ${sessionId.slice(0, 12)}`,
        });
        return result;
    }
    async function cancel(request, sessionId) {
        const { device } = await authenticate(request);
        if (sessionId === '')
            throw new RcHttpError(400, 'BAD_REQUEST', 'sessionId is required');
        const result = await requireDataPlane().cancel(sessionId);
        auditPush({
            kind: 'rpc',
            operation: 'session.cancel',
            result: 'ok',
            deviceId: device.id,
            deviceLabel: device.label,
            detail: `session ${sessionId.slice(0, 12)}`,
        });
        return result;
    }
    function normalizePromptContent(raw) {
        const parts = [];
        let textChars = 0;
        let attachments = 0;
        const pushText = (text) => {
            if (typeof text !== 'string')
                return;
            parts.push({ type: 'text', text });
            textChars += text.length;
        };
        const pushPart = (part) => {
            if (typeof part === 'string') {
                pushText(part);
                return;
            }
            if (part === null || typeof part !== 'object')
                return;
            const record = part;
            if (record.type === 'text') {
                pushText(record.text);
                return;
            }
            if (record.type === 'image' && typeof record.mediaType === 'string' && typeof record.data === 'string') {
                const mediaType = record.mediaType;
                if (mediaType !== 'image/png' &&
                    mediaType !== 'image/jpeg' &&
                    mediaType !== 'image/webp' &&
                    mediaType !== 'image/gif') {
                    throw new RcHttpError(400, 'BAD_REQUEST', 'unsupported image media type');
                }
                const image = { type: 'image', mediaType, data: record.data };
                if (typeof record.name === 'string')
                    image.name = record.name.slice(0, 128);
                parts.push(image);
                attachments += 1;
                return;
            }
            if (record.type === 'file' && typeof record.receiptId === 'string' && record.receiptId.length > 0) {
                parts.push({ type: 'file', receiptId: record.receiptId.slice(0, 256) });
                attachments += 1;
            }
        };
        if (typeof raw === 'string' || (raw !== null && typeof raw === 'object' && !Array.isArray(raw))) {
            pushPart(raw);
        }
        else if (Array.isArray(raw)) {
            for (const part of raw)
                pushPart(part);
        }
        if (parts.length === 0) {
            throw new RcHttpError(400, 'BAD_REQUEST', 'prompt content must not be empty');
        }
        if (textChars > RC_LIMITS.maxPromptChars) {
            throw new RcHttpError(400, 'BAD_REQUEST', 'prompt is too long');
        }
        if (attachments === 0 && parts.every((part) => part.type !== 'text' || part.text.trim() === '')) {
            throw new RcHttpError(400, 'BAD_REQUEST', 'prompt content must include non-whitespace text');
        }
        return parts;
    }
    async function verifyAccessLayer(request) {
        const verifier = accessVerifier;
        if (verifier === null || !verifier.enabled())
            return;
        let result;
        try {
            result = await verifier.verify(request);
        }
        catch {
            result = { ok: false, code: 'ACCESS_REQUIRED', message: 'cloudflare access verification failed' };
        }
        if (!result.ok) {
            throw new RcHttpError(401, 'ACCESS_REQUIRED', result.message ?? 'cloudflare access verification failed');
        }
    }
    async function dispatchApi(request, response) {
        const method = (request.method ?? 'GET').toUpperCase();
        const rawUrl = request.url ?? '/';
        if (!rawUrl.startsWith(RC_API_PATH)) {
            sendError(response, 404, 'NOT_FOUND', 'unknown route');
            return;
        }
        const url = new URL(rawUrl, 'http://remote-control.invalid');
        const path = url.pathname;
        if (!fenceOk(request)) {
            sendError(response, 403, 'ORIGIN', 'host or origin not allowed');
            return;
        }
        response.setHeader('Cache-Control', 'no-store');
        response.setHeader('X-Content-Type-Options', 'nosniff');
        await verifyAccessLayer(request);
        if (path === `${RC_API_PATH}/health`) {
            if (method !== 'GET')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            sendJson(response, 200, health());
            return;
        }
        if (path === `${RC_API_PATH}/pair/claim`) {
            if (method !== 'POST')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            requireMutationGuard(request);
            sendJson(response, 200, await pairClaim(request));
            return;
        }
        if (path === `${RC_API_PATH}/pair/status`) {
            if (method !== 'POST')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            requireMutationGuard(request);
            sendJson(response, 200, await pairStatus(request, response));
            return;
        }
        if (path === `${RC_API_PATH}/session/refresh`) {
            if (method !== 'POST')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            requireMutationGuard(request);
            sendJson(response, 200, await refresh(request, response));
            return;
        }
        if (path === `${RC_API_PATH}/session/logout`) {
            if (method !== 'POST')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            requireMutationGuard(request);
            sendJson(response, 200, await logout(request, response));
            return;
        }
        if (path === `${RC_API_PATH}/state`) {
            if (method !== 'GET')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            sendJson(response, 200, await state(request));
            return;
        }
        if (path === `${RC_API_PATH}/sessions`) {
            if (method === 'GET') {
                sendJson(response, 200, await sessions(request));
                return;
            }
            if (method === 'POST') {
                requireMutationGuard(request);
                sendJson(response, 200, await createSession(request));
                return;
            }
            return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
        }
        const fileRoute = /^\/rc\/api\/sessions\/([^/]+)\/files$/.exec(path);
        if (fileRoute !== null) {
            if (method !== 'POST')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            requireMutationGuard(request);
            const sessionId = decodeURIComponent(fileRoute[1] ?? '');
            sendJson(response, 200, await uploadFile(request, sessionId));
            return;
        }
        const attachmentRoute = /^\/rc\/api\/sessions\/([^/]+)\/attachments\/([^/]+)$/.exec(path);
        if (attachmentRoute !== null) {
            if (method !== 'GET')
                return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
            const sessionId = decodeURIComponent(attachmentRoute[1] ?? '');
            const attachmentId = decodeURIComponent(attachmentRoute[2] ?? '');
            sendJson(response, 200, await readAttachment(request, sessionId, attachmentId));
            return;
        }
        const sessionRoute = /^\/rc\/api\/sessions\/([^/]+)\/(projections|page|prompt|cancel)$/.exec(path);
        if (sessionRoute !== null) {
            const sessionId = decodeURIComponent(sessionRoute[1] ?? '');
            const action = sessionRoute[2];
            if (action === 'projections') {
                if (method !== 'GET')
                    return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
                sendJson(response, 200, await projections(request, sessionId));
                return;
            }
            if (action === 'page') {
                if (method !== 'GET')
                    return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
                sendJson(response, 200, await page(request, sessionId, url.searchParams));
                return;
            }
            if (action === 'prompt') {
                if (method !== 'POST')
                    return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
                requireMutationGuard(request);
                sendJson(response, 200, await prompt(request, sessionId, await readBody(request, RC_LIMITS.maxPromptBodyBytes)));
                return;
            }
            if (action === 'cancel') {
                if (method !== 'POST')
                    return sendError(response, 405, 'BAD_REQUEST', 'method not allowed');
                requireMutationGuard(request);
                sendJson(response, 200, await cancel(request, sessionId));
                return;
            }
        }
        sendError(response, 404, 'NOT_FOUND', 'unknown route');
    }
    function handleApi(request, response) {
        void dispatchApi(request, response).catch((error) => {
            try {
                respondError(response, error);
            }
            catch {
                try {
                    response.destroy();
                }
                catch {
                    // ignore
                }
            }
        });
    }
    function rejectUpgrade(socket, status, code) {
        const phrase = status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Service Unavailable';
        try {
            socket.write(`HTTP/1.1 ${status} ${phrase}\r\n` +
                'Connection: close\r\n' +
                'Content-Length: 0\r\n' +
                `X-RC-Error: ${code}\r\n\r\n`);
        }
        catch {
            // ignore
        }
        finally {
            try {
                socket.destroy();
            }
            catch {
                // ignore
            }
        }
    }
    function handleUpgrade(request, socket, head) {
        void (async () => {
            if (disposed) {
                rejectUpgrade(socket, 403, 'NOT_ALLOWED');
                return;
            }
            if (securityClosed) {
                rejectUpgrade(socket, 503, 'SECURITY_CLOSED');
                return;
            }
            if (!enabled || wsBroker === null) {
                rejectUpgrade(socket, 403, 'NOT_ALLOWED');
                return;
            }
            if (!checkOriginFence(request, fencePolicy, { requireOrigin: true }).ok) {
                rejectUpgrade(socket, 403, 'ORIGIN');
                return;
            }
            await verifyAccessLayer(request);
            let authed;
            try {
                authed = await authenticate(request, { path: 'ws', touch: true });
            }
            catch (error) {
                if (error instanceof RcHttpError) {
                    rejectUpgrade(socket, error.status === 429 ? 429 : 401, error.code);
                    return;
                }
                rejectUpgrade(socket, 401, 'AUTH_REQUIRED');
                return;
            }
            // The expiry is bound to this exact socket by the broker, not to the device:
            // a second connection of the same device can never extend this session.
            wsBroker.handleUpgrade(request, socket, head, authed.device, authed.expiresAt);
        })().catch((error) => {
            log.warn('ws upgrade failed', errorMessage(error));
            rejectUpgrade(socket, 500, 'INTERNAL');
        });
    }
    /* ----------------------------------------------------------------------- */
    /* Connection selection / plan (Â§2, Â§3)                                    */
    /* ----------------------------------------------------------------------- */
    function selectionFromConfig() {
        const listeningOnLan = config.listen.access === 'lan' ||
            (config.listen.allowLan === true && !isLoopbackHost(config.listen.host || '127.0.0.1'));
        if (listeningOnLan) {
            const lanAddress = config.listen.lanAddress.trim() !== ''
                ? config.listen.lanAddress.trim()
                : isWildcardHost(config.listen.host) || config.listen.host.trim() === ''
                    ? ''
                    : config.listen.host.trim();
            return { method: 'lan', lanAddress, loopbackPort: config.listen.port };
        }
        if (!config.tunnel.enabled) {
            return { method: 'loopback', loopbackPort: config.listen.port };
        }
        const tunnel = config.tunnel;
        const common = {
            cloudflaredPath: tunnel.cloudflaredPath,
            transport: tunnel.transport,
        };
        switch (tunnel.mode) {
            case 'quick':
                return { method: 'cloudflare-quick', ...common };
            case 'named':
                return {
                    method: 'cloudflare-named',
                    ...common,
                    hostname: tunnel.hostname,
                    tokenEnv: tunnel.tokenEnv,
                    tokenFile: tunnel.tokenFile,
                    loopbackPort: config.listen.port,
                };
            case 'named-local':
                return {
                    method: 'cloudflare-named-local',
                    ...common,
                    hostname: tunnel.hostname,
                    tunnelId: tunnel.tunnelId,
                    credentialsFile: tunnel.credentialsFile,
                    loopbackPort: config.listen.port,
                };
            case 'external':
                return {
                    method: 'external',
                    publicUrl: tunnel.publicUrl,
                    loopbackPort: config.listen.port,
                };
            case 'ssh':
                return {
                    method: 'ssh',
                    sshPath: tunnel.sshPath,
                    sshUser: tunnel.sshUser,
                    sshHost: tunnel.sshHost,
                    sshRemotePort: tunnel.sshRemotePort,
                };
            default:
                return { method: 'loopback', loopbackPort: config.listen.port };
        }
    }
    function normalizeSelection(raw) {
        if (raw === null || typeof raw !== 'object') {
            throw new RcHttpError(400, 'BAD_REQUEST', 'connection selection is required');
        }
        const allowed = new Set([
            'loopback',
            'lan',
            'cloudflare-quick',
            'cloudflare-named',
            'cloudflare-named-local',
            'external',
            'ssh',
        ]);
        if (typeof raw.method !== 'string' || !allowed.has(raw.method)) {
            throw new RcHttpError(400, 'BAD_REQUEST', 'unknown connection method');
        }
        const selection = { method: raw.method };
        const copyString = (key, max = 512) => {
            const value = raw[key];
            if (value === undefined)
                return;
            if (typeof value !== 'string' || value.length > max) {
                throw new RcHttpError(400, 'BAD_REQUEST', `invalid ${String(key)}`);
            }
            ;
            selection[key] = value.trim();
        };
        for (const key of [
            'lanAddress',
            'cloudflaredPath',
            'hostname',
            'tokenEnv',
            'tokenFile',
            'tunnelId',
            'credentialsFile',
            'publicUrl',
            'sshPath',
            'sshUser',
            'sshHost',
        ]) {
            copyString(key);
        }
        if (raw.transport !== undefined) {
            if (raw.transport !== 'auto' && raw.transport !== 'quic' && raw.transport !== 'http2') {
                throw new RcHttpError(400, 'BAD_REQUEST', 'invalid transport');
            }
            selection.transport = raw.transport;
        }
        if (raw.loopbackPort !== undefined) {
            if (!Number.isInteger(raw.loopbackPort) || raw.loopbackPort < 0 || raw.loopbackPort > 65_535) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'invalid loopbackPort');
            }
            selection.loopbackPort = raw.loopbackPort;
        }
        if (raw.sshRemotePort !== undefined) {
            if (!Number.isInteger(raw.sshRemotePort) || raw.sshRemotePort < 1 || raw.sshRemotePort > 65_535) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'invalid sshRemotePort');
            }
            selection.sshRemotePort = raw.sshRemotePort;
        }
        if (raw.accessRequired !== undefined) {
            if (typeof raw.accessRequired !== 'boolean') {
                throw new RcHttpError(400, 'BAD_REQUEST', 'invalid accessRequired');
            }
            selection.accessRequired = raw.accessRequired;
        }
        return selection;
    }
    function resolveListener(selection) {
        const accessRequired = config.tunnel.access.required || selection.accessRequired === true;
        if (accessRequired) {
            if (!needsFixedHostname(selection.method)) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'cloudflare access requires a fixed hostname connection method (named, named-local or external)');
            }
            if (config.tunnel.access.teamDomain.trim() === '' || config.tunnel.access.audience.trim() === '') {
                throw new RcHttpError(400, 'BAD_REQUEST', 'cloudflare access teamDomain/audience are not configured');
            }
        }
        if (selection.method === 'lan') {
            const interfaces = listLanInterfaces();
            const address = (selection.lanAddress ?? config.listen.lanAddress ?? '').trim();
            if (address === '') {
                throw new RcHttpError(400, 'BAD_REQUEST', 'choose a LAN interface address first');
            }
            const candidate = interfaces.find((entry) => entry.address === address);
            if (candidate === undefined) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'the selected LAN address is not a concrete local interface');
            }
            const certFile = config.listen.tls.certFile.trim();
            const keyFile = config.listen.tls.keyFile.trim();
            if (certFile === '' || keyFile === '') {
                throw new RcHttpError(409, 'TLS_REQUIRED', 'LAN access requires a trusted TLS certificate/key pair for the listener; pairing is not started without HTTPS');
            }
            // An explicit panel selection of a concrete interface (plus the disclosed
            // plan the user confirms) is the required explicit LAN opt-in; the
            // config-level allowLan/access switch only governs config-driven starts.
            return {
                selection: { ...selection, lanAddress: address },
                listener: {
                    access: 'lan',
                    host: address,
                    port: config.listen.port,
                    protocol: 'https',
                    secure: true,
                },
                tls: { certFile, keyFile },
            };
        }
        const loopbackHost = '127.0.0.1';
        const dynamicPort = 0;
        if (selection.method === 'cloudflare-quick' || selection.method === 'cloudflare-named-local' || selection.method === 'ssh') {
            return {
                selection,
                listener: { access: 'loopback', host: loopbackHost, port: dynamicPort, protocol: 'http', secure: false },
                tls: null,
            };
        }
        if (selection.method === 'cloudflare-named' || selection.method === 'external') {
            const port = selection.loopbackPort !== undefined ? selection.loopbackPort : config.listen.port;
            if (!Number.isInteger(port) || port < 0 || port > 65_535) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'invalid fixed loopback port');
            }
            return {
                selection,
                listener: { access: 'loopback', host: loopbackHost, port, protocol: 'http', secure: false },
                tls: null,
            };
        }
        // Plain loopback listener: local-only remote control, no public exposure.
        const port = selection.loopbackPort !== undefined ? selection.loopbackPort : config.listen.port;
        const certFile = config.listen.tls.certFile.trim();
        const keyFile = config.listen.tls.keyFile.trim();
        const tls = certFile !== '' && keyFile !== '' ? { certFile, keyFile } : null;
        return {
            selection: { ...selection, method: 'loopback' },
            listener: {
                access: 'loopback',
                host: loopbackHost,
                port,
                protocol: tls === null ? 'http' : 'https',
                secure: tls !== null,
            },
            tls,
        };
    }
    function selectionToConfigView(selection) {
        const tunnel = { ...config.tunnel, enabled: true };
        switch (selection.method) {
            case 'cloudflare-quick':
                tunnel.mode = 'quick';
                break;
            case 'cloudflare-named':
                tunnel.mode = 'named';
                break;
            case 'cloudflare-named-local':
                tunnel.mode = 'named-local';
                break;
            case 'external':
                tunnel.mode = 'external';
                break;
            case 'ssh':
                tunnel.mode = 'ssh';
                break;
            default:
                tunnel.mode = 'quick';
                break;
        }
        return { ...config, tunnel };
    }
    function tunnelStatusOff() {
        const method = currentMethod();
        const mode = tunnelModeForMethod(method);
        return {
            enabled: false,
            mode,
            state: 'off',
            url: null,
            temporary: method === 'cloudflare-quick' || method === 'ssh',
            ownership: method === 'external' ? 'external' : 'none',
            transport: selectionFromConfig().transport ?? config.tunnel.transport,
            serviceUrl: null,
            verified: { http: false, ws: false },
            error: null,
            detail: null,
        };
    }
    function viewDeviceLock() {
        const store = deviceStore;
        const registered = store?.list() ?? [];
        const raw = lease?.raw() ?? { deviceId: null, startedAt: null, lastActivityAt: null };
        const active = raw.deviceId !== null ? registered.find((device) => device.id === raw.deviceId) : undefined;
        const activeDeviceId = active?.id ?? null;
        const registeredDevices = registered.length;
        let state;
        if (activeDeviceId !== null)
            state = 'active';
        else if (registeredDevices === 0)
            state = 'none';
        else if (registeredDevices > 1)
            state = 'selection-required';
        else
            state = 'released';
        return {
            state,
            activeDeviceId,
            activeDeviceLabel: active?.label ?? null,
            activeSince: raw.startedAt,
            lastActivityAt: raw.lastActivityAt,
            idleExpiresAt: lease?.idleExpiresAt() ?? null,
            idleTimeoutMinutes: config.security.idleTimeoutMinutes,
            needsSelection: registeredDevices > 1 && activeDeviceId === null,
            registeredDevices,
        };
    }
    function deviceLockView() {
        return viewDeviceLock();
    }
    function securityView() {
        const blocked = monitor?.blockedCount() ?? 0;
        return {
            closed: securityClosed,
            closedReason: securityClosedReason,
            circuitBreaker: monitor?.isCircuitBreakerOpen() === true ? 'open' : 'closed',
            failureCount: monitor?.failureCount() ?? 0,
            blockedClients: blocked,
            failureWindowSeconds: config.security.failureWindowSeconds,
            temporaryBanMinutes: config.security.temporaryBanMinutes,
            maxFailuresBeforeCircuitBreaker: config.security.circuitBreakerFailures,
            revocationEpoch,
            idleTimeoutMinutes: config.security.idleTimeoutMinutes,
        };
    }
    function connectionView() {
        const status = listenerStatus();
        const tunnel = tunnelManager?.status() ?? tunnelStatusOff();
        const pub = publicOrigin();
        const qrBase = pairingBaseUrl();
        return {
            method: currentMethod(),
            listener: status,
            publicOrigin: pub,
            qrOrigin: qrBase,
            hostAuthorities: [...fencePolicy.allowedOrigins].sort(),
            secureCookies: status.secure || pub?.startsWith('https://') === true,
            accessRequired: accessVerifier?.enabled() === true,
            tunnel,
        };
    }
    function pairingBaseUrl() {
        const pub = publicOrigin();
        if (pub !== null)
            return pub;
        const lan = lanOrigin();
        if (lan !== null)
            return lan;
        const status = listenerStatus();
        if (status.state === 'listening' && status.url !== null)
            return status.url;
        return null;
    }
    async function buildPlan(selectionRaw) {
        const manager = tunnelManager;
        if (manager === null)
            throw new RcHttpError(503, 'INTERNAL', 'tunnel manager is not initialized');
        const selection = normalizeSelection(selectionRaw);
        const resolved = resolveListener(selection);
        const localUrl = `${resolved.listener.protocol}://${formatHostForAuthority(resolved.listener.host)}:${resolved.listener.port}`;
        const providerPlan = await manager.describe(resolved.selection, {
            localUrl,
            listener: {
                access: resolved.listener.access,
                host: resolved.listener.host,
                port: resolved.listener.port,
                protocol: resolved.listener.protocol,
                secure: resolved.listener.secure,
            },
        });
        const steps = [];
        steps.push({
            kind: 'listener',
            text: resolved.listener.access === 'lan'
                ? `Bind the phone listener to LAN address ${resolved.listener.host}:${resolved.listener.port || '(automatic port)'} over HTTPS.`
                : `Bind the phone listener to loopback ${resolved.listener.host}:${resolved.listener.port || '(automatic port)'}.`,
            params: {
                host: resolved.listener.host,
                port: resolved.listener.port,
                protocol: resolved.listener.protocol,
                access: resolved.listener.access,
            },
        });
        if (resolved.listener.access === 'lan') {
            steps.push({
                kind: 'tls',
                text: `Use the configured TLS certificate/key (${config.listen.tls.certFile}) so the phone can trust HTTPS.`,
                params: { certFile: config.listen.tls.certFile },
            });
        }
        steps.push(...providerPlan.steps);
        if (providerPlan.download !== null) {
            steps.push({
                kind: 'download',
                text: `The pinned official cloudflared ${providerPlan.download.version} asset ${providerPlan.download.asset} (${providerPlan.download.sizeBytes} bytes) must be downloaded and verified against official SHA-256 ${providerPlan.download.sha256}. Nothing is downloaded until you confirm.`,
                params: {
                    version: providerPlan.download.version,
                    asset: providerPlan.download.asset,
                    sizeBytes: providerPlan.download.sizeBytes,
                    sha256: providerPlan.download.sha256,
                },
            });
        }
        if (providerPlan.accessRequired || config.tunnel.access.required || resolved.selection.accessRequired === true) {
            steps.push({
                kind: 'access',
                text: `Cloudflare Access is enforced in addition to the plugin authentication for ${config.tunnel.access.teamDomain}.`,
                params: { teamDomain: config.tunnel.access.teamDomain, audience: config.tunnel.access.audience },
            });
        }
        const publicOriginHint = providerPlan.publicOrigin;
        if (publicOriginHint !== null) {
            steps.push({
                kind: 'origin',
                text: `The public HTTPS origin will be ${publicOriginHint}; the pairing QR code is bound to it and old origins/probations are removed when the provider changes.`,
                params: { publicOrigin: publicOriginHint },
            });
        }
        steps.push({
            kind: 'warning',
            text: 'Starting remote access lets a paired phone read this local DSH session and, when enabled in settings, send prompts/steer/cancel and answer approvals. Only one device can be active at a time.',
        });
        steps.push({
            kind: 'security',
            text: 'Emergency stop permanently invalidates all access/refresh tokens, cancels pairings, closes WebSockets and terminates the plugin-owned tunnel process. Old tokens stay invalid after a DSH restart.',
        });
        if (providerPlan.fixedLoopbackPort && resolved.listener.port === 0) {
            steps.push({
                kind: 'warning',
                text: 'A dynamic loopback port is used while the remote connector expects a fixed service URL; the public route is verified with bounded probes and reported separately.',
                params: { port: 0 },
            });
        }
        for (const warning of providerPlan.warnings) {
            steps.push({ kind: 'warning', text: warning });
        }
        const now = Date.now();
        const plan = {
            planId: randomBytes(16).toString('base64url'),
            selection: resolved.selection,
            steps,
            listener: resolved.listener,
            publicOrigin: publicOriginHint,
            qrOrigin: publicOriginHint,
            secureCookies: resolved.listener.secure || publicOriginHint?.startsWith('https://') === true,
            accessRequired: providerPlan.accessRequired ||
                config.tunnel.access.required ||
                resolved.selection.accessRequired === true,
            download: providerPlan.download,
            expiresAt: now + RC_LIMITS.planTtlMs,
        };
        return { resolved, plan, providerPlan };
    }
    function prunePlanCache() {
        const now = Date.now();
        for (const [planId, entry] of planCache) {
            if (entry.expiresAt <= now)
                planCache.delete(planId);
        }
        while (planCache.size > PLAN_CACHE_LIMIT) {
            const oldest = planCache.keys().next();
            if (oldest.done)
                break;
            planCache.delete(oldest.value);
        }
    }
    /* ----------------------------------------------------------------------- */
    /* Runtime lifecycle                                                       */
    /* ----------------------------------------------------------------------- */
    function tunnelLocalUrl() {
        const current = listener?.status();
        if (current === null || current === undefined || current.port === null) {
            throw new Error('listener is not ready');
        }
        const rawHost = current.host !== null && current.host !== '0.0.0.0' && current.host !== '::' ? current.host : '127.0.0.1';
        const host = formatHostForAuthority(rawHost);
        return `${current.secure ? 'https' : 'http'}://${host}:${current.port}`;
    }
    function ensureDataPlane() {
        if (gateway !== null)
            return;
        gateway = createGatewayClient(ctx, log);
        dataPlane = createSessionBridge({ gateway, config, log, audit });
        approvals = createApprovalBridge({ gateway, config, log, audit });
    }
    function createWsBrokerInstance() {
        return createWsBroker({
            dataPlane: dataPlane,
            approvals: approvals,
            pluginVersion,
            log,
            authorize: (deviceId) => {
                if (disposed)
                    return { ok: false, code: 'NOT_ALLOWED', message: 'shutting down' };
                if (securityClosed) {
                    return { ok: false, code: 'SECURITY_CLOSED', message: securityClosedMessage() };
                }
                if (!enabled)
                    return { ok: false, code: 'NOT_ALLOWED', message: 'remote control is disabled' };
                const store = deviceStore;
                const device = store?.get(deviceId);
                if (device === undefined) {
                    return { ok: false, code: 'DEVICE_REVOKED', message: 'device is not paired' };
                }
                const leaseRef = lease;
                if (leaseRef === null || !leaseRef.isActive(deviceId)) {
                    return { ok: false, code: 'DEVICE_LOCKED', message: 'this device does not hold the remote-control lock' };
                }
                return { ok: true };
            },
            touchActivity: (deviceId) => {
                const leaseRef = lease;
                if (leaseRef === null || !leaseRef.isActive(deviceId))
                    return false;
                leaseRef.touch(deviceId);
                // An authenticated client heartbeat/frame is verified phone activity: it
                // renews the session idle clock exactly like an authenticated HTTP request.
                touchRemoteActivity();
                return true;
            },
        });
    }
    async function startListener(resolved) {
        const handle = createListener({
            bind: () => ({
                host: resolved.listener.host,
                port: resolved.listener.port,
                allowLan: resolved.listener.access === 'lan',
                tls: resolved.tls,
            }),
            staticRoot,
            api: handleApi,
            upgrade: handleUpgrade,
            log,
        });
        listener = handle;
        const status = await handle.start();
        currentListenerTls = status.secure;
    }
    async function stopRuntime(securityShutdown = false) {
        clearIdleTimer();
        runtimeStopping = true;
        try {
            if (wsBroker !== null) {
                try {
                    wsBroker.broadcastDrain(DRAIN_DELAY_MS);
                }
                catch {
                    // ignore
                }
                await sleep(DRAIN_DELAY_MS).catch(() => undefined);
                try {
                    wsBroker.closeAll(securityShutdown ? 'security-shutdown' : 'disabled', securityShutdown ? RC_WS_CLOSE.securityClosed : RC_WS_CLOSE.policyViolation);
                }
                catch (error) {
                    log.warn('could not close sockets', errorMessage(error));
                }
            }
            if (listener !== null) {
                const current = listener;
                listener = null;
                await current.stop().catch((error) => {
                    log.warn('could not stop listener', errorMessage(error));
                });
            }
            if (tunnelManager !== null) {
                await tunnelManager.stop().catch((error) => {
                    log.warn('could not stop tunnel', errorMessage(error));
                });
            }
            tunnelUrl = null;
            tunnelWasUp = false;
            await approvals?.dispose().catch((error) => {
                log.warn('could not dispose approvals', errorMessage(error));
            });
            approvals = null;
            await gateway?.dispose().catch((error) => {
                log.warn('could not dispose gateway', errorMessage(error));
            });
            gateway = null;
            dataPlane = null;
            await wsBroker?.dispose().catch((error) => {
                log.warn('could not dispose ws broker', errorMessage(error));
            });
            wsBroker = null;
            currentListenerTls = false;
            rebuildAuthorities();
        }
        finally {
            runtimeStopping = false;
        }
    }
    function handleTunnelStatus(status) {
        const previousUrl = tunnelUrl;
        if (status.url !== null) {
            tunnelUrl = status.url;
            if (status.state === 'ready' || status.state === 'connected-unverified')
                tunnelWasUp = true;
        }
        else {
            // No public URL (stopped/starting/reconnecting/down): the old origin and
            // its QR must not survive even if the provider is still restarting.
            tunnelUrl = null;
        }
        if (previousUrl !== tunnelUrl) {
            lastCode = null;
            rebuildAuthorities();
            auditPush({
                kind: 'tunnel',
                operation: 'tunnel.origin',
                result: tunnelUrl === null ? 'notice' : 'ok',
                detail: tunnelUrl === null ? 'origin cleared' : `origin ${tunnelUrl}`,
            });
        }
        if (status.state === 'down' || status.state === 'mismatch') {
            const shouldShutdown = enabled && !securityClosed && tunnelWasUp && !runtimeStopping;
            if (shouldShutdown) {
                tunnelWasUp = false;
                auditPush({
                    kind: 'tunnel',
                    operation: 'tunnel.state',
                    result: 'failed',
                    detail: `${status.state}: ${status.error ?? 'tunnel lost'}`,
                });
                void requestSecurityShutdown('tunnel-lost');
            }
        }
    }
    function createManager() {
        const managerDeps = {
            config,
            log,
            managedDir: () => join(dshHome, RC_DIR, 'bin'),
            runtimeDir: () => join(dshHome, RC_DIR, 'tunnel'),
        };
        const manager = deps.tunnelFactory !== undefined
            ? deps.tunnelFactory(managerDeps)
            : createTunnelManager(managerDeps);
        manager.setStatusListener?.(handleTunnelStatus);
        return manager;
    }
    async function applySelection(selection, options) {
        if (disposed)
            throw new RcHttpError(503, 'INTERNAL', 'plugin is shutting down');
        await initialize();
        if (enabled)
            return;
        const { deviceStore: store } = requireStores();
        const wasClosedBeforeStart = securityClosed;
        const closedReasonBeforeStart = securityClosedReason;
        if (securityClosed) {
            if (!options.explicit) {
                throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
            }
            securityClosed = false;
            securityClosedReason = null;
            auditPush({ kind: 'security', operation: 'security.reopen', result: 'ok', detail: 'explicit user re-enable' });
        }
        try {
            if (store.count() > 1 && lease?.activeDeviceId() === null) {
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'more than one device is registered: select an active device or revoke the extra devices from the desktop panel first');
            }
            const { resolved, providerPlan } = await buildPlan(selection);
            // Missing provider binary: fail closed and require the explicit install flow.
            if (providerPlan.download !== null) {
                throw new RcHttpError(409, 'INSTALL_REQUIRED', `cloudflared ${providerPlan.download.version} is not installed; run the explicit install flow from the panel first`);
            }
            if (providerPlan.publicOrigin === null && needsFixedHostname(resolved.selection.method)) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'the selected provider requires a fixed public hostname/origin');
            }
            runtimeSelection = resolved.selection;
            enabled = true;
            syncAccessEnforcement();
            monitor?.beginSession();
            await startListener(resolved);
            // The loopback/LAN authority is valid as soon as the listener is bound; the
            // panel must be able to poll state while a tunnel connector is still starting.
            rebuildAuthorities();
            const localUrl = tunnelLocalUrl();
            const status = await tunnelManager.start(resolved.selection, {
                localUrl,
                listener: {
                    access: resolved.listener.access,
                    host: resolved.listener.host,
                    port: resolved.listener.port,
                    protocol: resolved.listener.protocol,
                    secure: resolved.listener.secure,
                },
            });
            // A security shutdown requested while the tunnel was starting always wins:
            // never persist an open state over a closure.
            if (securityClosed || disposed) {
                throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
            }
            handleTunnelStatus(status);
            rebuildAuthorities();
            ensureDataPlane();
            wsBroker = createWsBrokerInstance();
            await persistState({ lastEnabled: true, securityClosed: false, securityClosedReason: null }, { allowReopen: true });
            armIdleTimer();
            auditPush({
                kind: 'enable',
                operation: 'connection.start',
                result: 'ok',
                detail: serviceDescription(resolved.selection),
            });
            log.info('remote control enabled', {
                method: resolved.selection.method,
                host: listener?.status().host,
                port: listener?.status().port,
                secure: listener?.status().secure,
            });
        }
        catch (error) {
            enabled = false;
            monitor?.endSession();
            runtimeSelection = null;
            syncAccessEnforcement();
            clearIdleTimer();
            await stopRuntime();
            if (wasClosedBeforeStart && !securityClosed) {
                // A failed explicit re-enable must not silently keep access open-able:
                // restore the previous closure in memory and on disk.
                securityClosed = true;
                securityClosedReason = closedReasonBeforeStart;
            }
            await persistState({ lastEnabled: false });
            throw error;
        }
    }
    function serviceDescription(selection) {
        switch (selection.method) {
            case 'cloudflare-quick':
                return 'cloudflare quick tunnel';
            case 'cloudflare-named':
                return `cloudflare named tunnel ${selection.hostname ?? ''}`.trim();
            case 'cloudflare-named-local':
                return `cloudflare locally-managed tunnel ${selection.tunnelId ?? ''}`.trim();
            case 'external':
                return `external origin ${selection.publicUrl ?? ''}`.trim();
            case 'ssh':
                return `ssh ${selection.sshUser ?? 'nokey'}@${selection.sshHost ?? 'localhost.run'}`;
            case 'lan':
                return `lan ${selection.lanAddress ?? ''}`.trim();
            default:
                return 'loopback';
        }
    }
    async function disableInternal() {
        if (!enabled) {
            await stopRuntime();
            return;
        }
        enabled = false;
        clearIdleTimer();
        monitor?.endSession();
        auditPush({ kind: 'disable', operation: 'control.disable', result: 'ok', detail: 'user' });
        await stopRuntime();
        runtimeSelection = null;
        syncAccessEnforcement();
        lastCode = null;
        planCache.clear();
        rebuildAuthorities();
        await persistState({ lastEnabled: false, activeDeviceId: lease?.raw().deviceId ?? null });
        log.info('remote control disabled');
    }
    async function enableInternal() {
        const selection = selectionFromConfig();
        await applySelection(selection, { explicit: true });
    }
    /* ----------------------------------------------------------------------- */
    /* Initialization                                                          */
    /* ----------------------------------------------------------------------- */
    function createPairingManagerInstance() {
        const store = deviceStore;
        return createPairingManager({
            ttlMs: config.pairing.ttlSeconds * 1000,
            maxPendingCodes: config.pairing.maxPendingCodes,
            log,
            deviceCount: () => store?.count() ?? 0,
            maxDevices: config.tokens.maxDevices,
        });
    }
    function detectDshRelease() {
        for (const key of ['releaseInfo', 'hostInfo', 'runtimeInfo', 'appReady']) {
            const value = ctx.get(key);
            if (value !== null && typeof value === 'object' && value !== undefined) {
                const release = value.release ??
                    value.version;
                if (typeof release === 'string' && release !== '')
                    return release;
            }
        }
        const fromEnv = process.env.DSH_RELEASE?.trim() ?? process.env.DSH_VERSION?.trim();
        return fromEnv !== undefined && fromEnv !== '' ? fromEnv : 'unknown';
    }
    async function initialize() {
        if (initPromise !== null)
            return initPromise;
        initPromise = (async () => {
            dshRelease = detectDshRelease();
            stateStore =
                deps.stateStoreFactory !== undefined ? deps.stateStoreFactory(dshHome, log) : createStateStore(dshHome, log);
            lastState = await stateStore.load();
            lastPersistedState = lastState;
            applyPersistedSecurity(lastState);
            const deviceStorePath = config.tokens.deviceStorePath.trim() !== ''
                ? config.tokens.deviceStorePath.trim()
                : join(dshHome, RC_DIR, 'devices.json');
            deviceStore = await createDeviceStore({
                filePath: deviceStorePath,
                maxDevices: config.tokens.maxDevices,
                log,
            });
            await deviceStore.load();
            tokens = createTokenService({
                accessTtlMs: accessTtlMs(),
                refreshTtlMs: config.tokens.refreshTtlDays * 86_400_000,
                getDevice: (id) => deviceStore?.get(id),
            });
            lease = createDeviceLease({ idleTimeoutMs: config.security.idleTimeoutMinutes * 60_000, log });
            lease.setIdleHandler(() => {
                void requestSecurityShutdown('idle-timeout');
            });
            const wantsAutoEnable = config.enabled === true || (config.autoStart === true && lastState.lastEnabled === true);
            if (wantsAutoEnable && !securityClosed) {
                // A lease that idled out while DSH was down fires the one-shot handler
                // here and keeps remote access closed until an explicit user re-enable.
                lease.restore(lastState);
            }
            monitor = createSecurityMonitor({
                failureWindowMs: config.security.failureWindowSeconds * 1000,
                failuresBeforeBan: config.security.failuresBeforeBan,
                temporaryBanMs: config.security.temporaryBanMinutes * 60_000,
                circuitBreakerFailures: config.security.circuitBreakerFailures,
                log,
            });
            monitor.setCircuitBreakerHandler(() => {
                void requestSecurityShutdown('circuit-breaker');
            });
            accessVerifier = createAccessVerifier({
                required: config.tunnel.access.required,
                teamDomain: config.tunnel.access.teamDomain,
                audience: config.tunnel.access.audience,
                log,
            });
            syncAccessEnforcement();
            pairing = createPairingManagerInstance();
            tunnelManager = createManager();
        })();
        try {
            await initPromise;
            initError = null;
        }
        catch (error) {
            initError = errorMessage(error);
            initPromise = null;
            log.error('remote control failed to initialize', initError);
            throw error;
        }
        return initPromise;
    }
    async function ensureInitializedSafe() {
        if (initPromise === null && initError !== null) {
            throw new RcHttpError(503, 'INTERNAL', initError);
        }
        try {
            await initialize();
        }
        catch (error) {
            throw new RcHttpError(503, 'INTERNAL', errorMessage(error));
        }
    }
    /* ----------------------------------------------------------------------- */
    /* Admin API                                                               */
    /* ----------------------------------------------------------------------- */
    async function adminStatus() {
        await ensureInitializedSafe();
        const pub = publicOrigin();
        const qrBase = pairingBaseUrl();
        const devices = (deviceStore?.list() ?? []).map((device) => toDeviceViewWithActive(device));
        let cloudflared = null;
        let networkInterfaces = [];
        try {
            cloudflared = tunnelManager !== null ? await tunnelManager.installInfo() : null;
        }
        catch (error) {
            log.warn('cloudflared install info is unavailable', errorMessage(error));
            cloudflared = null;
        }
        try {
            networkInterfaces = listLanInterfaces();
        }
        catch {
            networkInterfaces = [];
        }
        const status = {
            enabled,
            pluginVersion,
            dshRelease,
            devices,
            pairings: pairing?.list() ?? [],
            listener: listenerStatus(),
            tunnel: tunnelManager?.status() ?? tunnelStatusOff(),
            publicUrl: pub,
            pairingUrlBase: qrBase,
            loopbackOnly: pub === null && !lanAccessActive(),
            connection: connectionView(),
            deviceLock: deviceLockView(),
            security: securityView(),
            cloudflared,
            networkInterfaces,
            audit: audit.snapshot().slice(-ADMIN_AUDIT_LIMIT).map(toAuditEntryView),
            qrSvg: null,
            pairing: null,
            initializationError: initError,
        };
        if (lastCode !== null && lastCode.expiresAt > Date.now() && qrBase !== null) {
            status.pairing = { ...lastCode, url: `${qrBase}${RC_BASE_PATH}/#/pair?c=${encodeURIComponent(lastCode.code)}` };
            try {
                status.qrSvg = await renderQrSvg(status.pairing.url);
            }
            catch (error) {
                log.warn('could not render pairing QR', errorMessage(error));
            }
        }
        return status;
    }
    async function adminControl(action) {
        return serial(async () => {
            await ensureInitializedSafe();
            if (action === 'enable')
                await enableInternal();
            else
                await disableInternal();
            return { enabled, listener: listenerStatus(), tunnel: tunnelManager?.status() ?? tunnelStatusOff() };
        });
    }
    async function adminPairCreate() {
        return serial(async () => {
            await ensureInitializedSafe();
            if (securityClosed)
                throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
            if (!enabled)
                throw new RcHttpError(409, 'NOT_ALLOWED', 'enable Remote Control first');
            if (lease?.activeDeviceId() !== null && lease?.activeDeviceId() !== undefined) {
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'a device is currently active; release it or revoke it first');
            }
            const { pairing: pairingManager } = requireStores();
            const base = pairingBaseUrl();
            if (base === null)
                throw new RcHttpError(503, 'INTERNAL', 'listener is not ready');
            const created = pairingManager.create();
            if (created === null) {
                throw new RcHttpError(429, 'RATE_LIMITED', 'too many pending pairing codes', 60_000);
            }
            lastCode = {
                code: created.code,
                url: `${base}${RC_BASE_PATH}/#/pair?c=${encodeURIComponent(created.code)}`,
                expiresAt: created.expiresAt,
            };
            auditPush({ kind: 'pair', operation: 'pair.code', result: 'ok', detail: 'code-created' });
            return { code: lastCode.code, url: lastCode.url, expiresAt: lastCode.expiresAt };
        });
    }
    async function adminPairApprove(claimId) {
        return serial(async () => {
            await ensureInitializedSafe();
            if (securityClosed)
                throw new RcHttpError(503, 'SECURITY_CLOSED', securityClosedMessage());
            if (!enabled)
                throw new RcHttpError(409, 'NOT_ALLOWED', 'enable Remote Control first');
            if (lease?.activeDeviceId() !== null && lease?.activeDeviceId() !== undefined) {
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'a device is currently active; release it before approving another device');
            }
            const { pairing: pairingManager } = requireStores();
            const approved = pairingManager.approve(claimId);
            if (approved === null)
                throw new RcHttpError(404, 'NOT_FOUND', 'pairing claim not found');
            auditPush({
                kind: 'approve',
                operation: 'pair.approve',
                result: 'ok',
                deviceLabel: approved.deviceName,
                detail: claimId.slice(0, 8),
            });
            return { ok: true };
        });
    }
    async function adminPairDeny(claimId) {
        return serial(async () => {
            await ensureInitializedSafe();
            const { pairing: pairingManager } = requireStores();
            if (!pairingManager.deny(claimId)) {
                throw new RcHttpError(404, 'NOT_FOUND', 'pairing claim not found');
            }
            auditPush({ kind: 'deny', operation: 'pair.deny', result: 'ok', detail: claimId.slice(0, 8) });
            return { ok: true };
        });
    }
    async function adminRevoke(deviceId) {
        return serial(async () => {
            await ensureInitializedSafe();
            const { deviceStore: store } = requireStores();
            const device = store.get(deviceId);
            if (device === undefined)
                throw new RcHttpError(404, 'NOT_FOUND', 'device not found');
            await revokeDevice(device, 'revoked');
            return { ok: true };
        });
    }
    async function adminRevokeAll() {
        return serial(async () => {
            await ensureInitializedSafe();
            const { deviceStore: store, lease: leaseRef } = requireStores();
            leaseRef.release('revoke');
            for (const device of store.list())
                await revokeDevice(device, 'revoked-all');
            await persistState({ activeDeviceId: null, leaseStartedAt: null, leaseLastActivityAt: null });
            return { ok: true };
        });
    }
    async function adminActivateDevice(deviceId) {
        return serial(async () => {
            await ensureInitializedSafe();
            const { deviceStore: store, lease: leaseRef } = requireStores();
            const device = store.get(deviceId);
            if (device === undefined)
                throw new RcHttpError(404, 'NOT_FOUND', 'device not found');
            const previous = leaseRef.activeDeviceId();
            if (previous !== null && previous !== deviceId)
                leaseRef.release('manual');
            if (!leaseRef.activate(device.id)) {
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'could not take the single-active-device lock');
            }
            if (previous !== null && previous !== device.id) {
                try {
                    wsBroker?.closeDevice(previous, 'lease-lost', RC_WS_CLOSE.leaseLost);
                }
                catch {
                    // ignore
                }
            }
            await persistState();
            auditPush({
                kind: 'device-lock',
                operation: 'device.activate',
                result: 'ok',
                deviceId: device.id,
                deviceLabel: device.label,
                detail: previous === null ? 'activated' : 'taken-over',
            });
            return { ok: true };
        });
    }
    async function adminReleaseDevice(deviceId) {
        return serial(async () => {
            await ensureInitializedSafe();
            const { deviceStore: store, lease: leaseRef } = requireStores();
            const device = store.get(deviceId);
            if (device === undefined)
                throw new RcHttpError(404, 'NOT_FOUND', 'device not found');
            if (leaseRef.activeDeviceId() !== deviceId) {
                throw new RcHttpError(409, 'DEVICE_LOCKED', 'this device does not hold the active lock');
            }
            leaseRef.release('manual');
            try {
                wsBroker?.closeDevice(deviceId, 'lease-released', RC_WS_CLOSE.leaseLost);
            }
            catch {
                // ignore
            }
            await persistState();
            auditPush({
                kind: 'device-lock',
                operation: 'device.release',
                result: 'ok',
                deviceId: device.id,
                deviceLabel: device.label,
                detail: 'released',
            });
            return { ok: true };
        });
    }
    async function adminPending() {
        await ensureInitializedSafe();
        return { pairings: pairing?.pendingApprovals() ?? [] };
    }
    async function adminAuditLog() {
        await ensureInitializedSafe();
        return { entries: audit.snapshot().map(toAuditEntryView) };
    }
    async function adminConnectionPlan(selection) {
        return serial(async () => {
            await ensureInitializedSafe();
            prunePlanCache();
            const { plan } = await buildPlan(selection);
            planCache.set(plan.planId, { selection: plan.selection, plan, expiresAt: plan.expiresAt });
            return { ok: true, plan };
        });
    }
    async function adminConnectionStart(request) {
        return serial(async () => {
            await ensureInitializedSafe();
            const entry = planCache.get(request.planId);
            if (entry === undefined || entry.expiresAt <= Date.now()) {
                planCache.delete(request.planId);
                throw new RcHttpError(428, 'CONSENT_REQUIRED', 'connection plan is missing or expired; review the plan again');
            }
            planCache.delete(request.planId);
            if (request.confirm !== true) {
                throw new RcHttpError(428, 'CONSENT_REQUIRED', 'explicit confirmation is required');
            }
            if (enabled) {
                enabled = false;
                monitor?.endSession();
                await stopRuntime();
            }
            // The closure is cleared only by applySelection's explicit re-enable path,
            // which restores it again when the start fails.
            await applySelection(entry.selection, { explicit: true });
            return { ok: true, connection: connectionView() };
        });
    }
    async function adminConnectionStop() {
        return serial(async () => {
            await ensureInitializedSafe();
            planCache.clear();
            lastCode = null;
            const stoppedMethod = activeSelection().method;
            if (tunnelManager !== null) {
                await tunnelManager.stop().catch((error) => {
                    log.warn('could not stop tunnel', errorMessage(error));
                });
            }
            tunnelUrl = null;
            tunnelWasUp = false;
            const wasLan = lanAccessActive();
            if (wasLan && listener !== null) {
                const current = listener;
                listener = null;
                await current.stop().catch((error) => {
                    log.warn('could not stop LAN listener', errorMessage(error));
                });
                try {
                    wsBroker?.closeAll('lane-removed', RC_WS_CLOSE.policyViolation);
                }
                catch {
                    // ignore
                }
                await wsBroker?.dispose().catch(() => undefined);
                wsBroker = null;
                runtimeSelection = stateSelectionLoopback();
                syncAccessEnforcement();
                const resolved = resolveListener(runtimeSelection);
                await startListener(resolved);
                wsBroker = createWsBrokerInstance();
            }
            else if (stoppedMethod === 'external') {
                // The external route belongs to an operator-owned connector, so stopping
                // the runtime tunnel cannot cut it. Tearing down the listener leaves the
                // connector nothing to forward to, closes every WS/follow/approval stream,
                // and clearing the runtime selection removes the public origin from the
                // Host/Origin fence and QR state.
                await stopRuntime();
                runtimeSelection = stateSelectionLoopback();
                syncAccessEnforcement();
                wsBroker = null;
            }
            rebuildAuthorities();
            await persistState();
            auditPush({
                kind: 'tunnel',
                operation: 'connection.stop',
                result: 'ok',
                detail: stoppedMethod === 'external'
                    ? 'external origin revoked; listener stopped'
                    : 'public exposure stopped',
            });
            return { ok: true, connection: connectionView() };
        });
    }
    function stateSelectionLoopback() {
        return {
            method: 'loopback',
            loopbackPort: config.listen.port,
        };
    }
    async function adminEmergencyStop() {
        await requestSecurityShutdown('user-emergency');
        return { ok: true, security: securityView(), connection: connectionView() };
    }
    async function adminInstallInfo() {
        await ensureInitializedSafe();
        if (tunnelManager === null)
            throw new RcHttpError(503, 'INTERNAL', 'tunnel manager is not initialized');
        return tunnelManager.installInfo();
    }
    async function adminInstall(planId) {
        return serial(async () => {
            await ensureInitializedSafe();
            const entry = planCache.get(planId);
            if (entry === undefined || entry.expiresAt <= Date.now()) {
                planCache.delete(planId);
                throw new RcHttpError(428, 'CONSENT_REQUIRED', 'install plan is missing or expired; review the plan again');
            }
            if (tunnelManager === null)
                throw new RcHttpError(503, 'INTERNAL', 'tunnel manager is not initialized');
            if (!methodUsesCloudflared(entry.selection.method)) {
                throw new RcHttpError(400, 'BAD_REQUEST', 'this connection method does not use cloudflared');
            }
            const info = await tunnelManager.install();
            // One-shot consent: the same disclosed plan cannot authorize a second install.
            planCache.delete(planId);
            auditPush({ kind: 'tunnel', operation: 'cloudflared.install', result: 'ok', detail: `cloudflared ${info.version}` });
            return { ok: true, cloudflared: info };
        });
    }
    /** Legacy explicit action: start the configured tunnel at runtime. */
    async function startTunnel() {
        return serial(async () => {
            await ensureInitializedSafe();
            if (!enabled)
                throw new RcHttpError(409, 'NOT_ALLOWED', 'enable Remote Control first');
            if (tunnelManager === null)
                throw new RcHttpError(503, 'INTERNAL', 'tunnel manager is not initialized');
            const current = tunnelManager.status();
            if (current.enabled)
                return current;
            const selection = runtimeSelection ?? selectionFromConfig();
            if (selection.method === 'loopback' || selection.method === 'lan') {
                throw new RcHttpError(400, 'BAD_REQUEST', 'the selected connection method does not start a tunnel process');
            }
            const status = await tunnelManager.start(selection, {
                localUrl: tunnelLocalUrl(),
                listener: {
                    access: 'loopback',
                    host: '127.0.0.1',
                    port: listener?.status().port ?? 0,
                    protocol: 'http',
                    secure: false,
                },
            });
            handleTunnelStatus(status);
            rebuildAuthorities();
            await persistState();
            return status;
        });
    }
    /** Legacy explicit action: stop the runtime tunnel without disabling the listener. */
    async function stopTunnel() {
        return serial(async () => {
            const current = tunnelManager;
            tunnelUrl = null;
            tunnelWasUp = false;
            if (current !== null) {
                await current.stop().catch((error) => {
                    log.warn('could not stop tunnel', errorMessage(error));
                });
            }
            lastCode = null;
            rebuildAuthorities();
            return current?.status() ?? tunnelStatusOff();
        });
    }
    /* ----------------------------------------------------------------------- */
    /* Plugin lifecycle                                                        */
    /* ----------------------------------------------------------------------- */
    async function start() {
        try {
            await initialize();
        }
        catch {
            return;
        }
        if (securityClosed) {
            log.warn('remote access stays security-closed until the user re-enables it');
            return;
        }
        if (initError !== null)
            return;
        const wantsEnable = config.enabled === true || (config.autoStart && lastState.lastEnabled);
        if (!wantsEnable || disposed)
            return;
        try {
            await serial(async () => {
                if (!enabled)
                    await enableInternal();
            });
        }
        catch (error) {
            log.error('remote control could not auto-enable', errorMessage(error));
        }
    }
    async function dispose() {
        if (disposed)
            return;
        disposed = true;
        // Reject new work immediately; the asynchronous teardown follows in the
        // serialized transition queue (a slow in-flight transition cannot hold this
        // open). `wasEnabled` is captured so autoStart semantics are preserved.
        const wasEnabled = enabled;
        enabled = false;
        clearIdleTimer();
        monitor?.endSession();
        try {
            monitor?.setCircuitBreakerHandler(() => undefined);
            lease?.setIdleHandler(() => undefined);
            await runSecurityShutdown('dispose', { persistClosed: false, wasEnabled });
        }
        catch (error) {
            log.warn('shutdown error', errorMessage(error));
        }
        try {
            pairing?.dispose();
        }
        catch {
            // ignore
        }
        deviceStore?.dispose();
        audit.dispose();
        accessVerifier?.dispose();
        monitor?.dispose();
        lease?.dispose();
        try {
            await tunnelManager?.dispose();
        }
        catch {
            // ignore
        }
        tunnelManager = null;
    }
    return {
        start,
        dispose,
        handleApi,
        handleUpgrade,
        status: adminStatus,
        control: adminControl,
        pairCreate: adminPairCreate,
        pairApprove: adminPairApprove,
        pairDeny: adminPairDeny,
        revoke: adminRevoke,
        revokeAll: adminRevokeAll,
        pending: adminPending,
        startTunnel,
        stopTunnel,
        connectionPlan: adminConnectionPlan,
        connectionStart: adminConnectionStart,
        connectionStop: adminConnectionStop,
        emergencyStop: adminEmergencyStop,
        installInfo: adminInstallInfo,
        install: adminInstall,
        activateDevice: adminActivateDevice,
        releaseDevice: adminReleaseDevice,
        auditLog: adminAuditLog,
    };
}
