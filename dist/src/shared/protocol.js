/**
 * Host ↔ PWA / desktop-client wire contract.
 *
 * This module is the single source of truth for the remote-control protocol.
 * It is intentionally dependency-free (types + literal constants only) so that
 * it can be imported by the Host (NodeNext), the PWA bundle and the client
 * plugin bundle without pulling any runtime code.
 *
 * See PROTOCOL.md for the human-readable description and PROTOCOL_VERSION for
 * the compatibility gate.
 */
/** Version of the remote-control wire protocol. Bump on breaking frame changes. */
export const PROTOCOL_VERSION = 2;
/** Base path of the plugin's own HTTP listener (the PWA origin). */
export const RC_BASE_PATH = '/rc';
/** REST surface below the base path, e.g. `/rc/api/health`. */
export const RC_API_PATH = `${RC_BASE_PATH}/api`;
/** The single WebSocket multiplexer path on the plugin listener. */
export const RC_WS_PATH = `${RC_BASE_PATH}/ws`;
/** Cookies minted for a paired device. Both are HttpOnly + SameSite=Strict + Path=/rc. */
export const RC_ACCESS_COOKIE = 'rc_access';
export const RC_REFRESH_COOKIE = 'rc_refresh';
/** Header that must accompany every authenticated mutation (CSRF defense). */
export const RC_CSRF_HEADER = 'x-rc-csrf';
/** Desktop admin surface served through the DSH webServer (same origin as the GUI). */
export const RC_ADMIN_PATH = '/api/dsh-remote-control';
/** Logical stream kinds accepted by `/rc/ws`. */
export const RC_STREAM_FOLLOW = 'follow';
/** Canonical error codes. Every error envelope uses one of these. */
export const RC_ERRORS = {
    AUTH_REQUIRED: 'AUTH_REQUIRED',
    TOKEN_EXPIRED: 'TOKEN_EXPIRED',
    DEVICE_REVOKED: 'DEVICE_REVOKED',
    /** Another device currently holds the single-active-device lease. */
    DEVICE_LOCKED: 'DEVICE_LOCKED',
    /** Remote access is closed after an emergency shutdown / circuit breaker / idle timeout. */
    SECURITY_CLOSED: 'SECURITY_CLOSED',
    /** The selected LAN access strategy requires a usable TLS certificate. */
    TLS_REQUIRED: 'TLS_REQUIRED',
    /** Cloudflare Access JWT verification failed / is required. */
    ACCESS_REQUIRED: 'ACCESS_REQUIRED',
    /** A disclosed plan id is missing, expired or does not match the request. */
    CONSENT_REQUIRED: 'CONSENT_REQUIRED',
    /** No pinned official cloudflared asset exists for this platform/architecture. */
    UNSUPPORTED_PLATFORM: 'UNSUPPORTED_PLATFORM',
    /** The downloaded artifact did not match the pinned official SHA-256. */
    CHECKSUM_MISMATCH: 'CHECKSUM_MISMATCH',
    /** The provider executable must be installed/downloaded by the user first. */
    INSTALL_REQUIRED: 'INSTALL_REQUIRED',
    /** The OpenSSH client executable was not found (never downloaded). */
    SSH_MISSING: 'SSH_MISSING',
    CSRF: 'CSRF',
    ORIGIN: 'ORIGIN',
    RATE_LIMITED: 'RATE_LIMITED',
    PAIRING_INVALID: 'PAIRING_INVALID',
    PAIRING_EXPIRED: 'PAIRING_EXPIRED',
    PAIRING_DENIED: 'PAIRING_DENIED',
    /** The one-time pairing code was already claimed once; a replay must be 403. */
    PAIRING_CONSUMED: 'PAIRING_CONSUMED',
    DEVICE_LIMIT: 'DEVICE_LIMIT',
    NOT_ALLOWED: 'NOT_ALLOWED',
    BAD_REQUEST: 'BAD_REQUEST',
    NOT_FOUND: 'NOT_FOUND',
    GATEWAY: 'GATEWAY',
    INTERNAL: 'INTERNAL',
};
/** Endpoints intentionally never exposed to remote clients (documentation of the boundary). */
export const FORBIDDEN_NAMESPACES = [
    'terminal',
    'workspace',
    'credentials',
    'settings',
    'pluginManager',
    'job',
    'attachment',
];
/** Heartbeat and flow-control constants shared by host and PWA. */
export const RC_HEARTBEAT = {
    /** Server sends a ping every 15 s. */
    pingIntervalMs: 15_000,
    /** Connection is closed when no pong arrived for 30 s. */
    pongTimeoutMs: 30_000,
    /** Per-socket buffered-bytes budget; assistant-stream frames may be dropped above it. */
    maxBufferedBytes: 512 * 1024,
};
/** Pagination bounds accepted from clients. */
export const RC_LIMITS = {
    maxMessages: 200,
    defaultMessages: 80,
    pageDefaultMessages: 40,
    maxPromptChars: 32_000,
    /** Decoded bytes per image/file attachment accepted from the phone. */
    maxAttachmentBytes: 8 * 1024 * 1024,
    /** Attachments allowed on one prompt. */
    maxAttachmentsPerMessage: 6,
    /** Decoded bytes across all attachments of one prompt. */
    maxAttachmentMessageBytes: 16 * 1024 * 1024,
    /** JSON body ceiling for prompts carrying base64 attachments. */
    maxPromptBodyBytes: 32 * 1024 * 1024,
    /** How long a disclosed connection plan stays confirmable. */
    planTtlMs: 120_000,
    /** Cache/backlog bound for the in-memory audit ring. */
    auditCapacity: 200,
};
/** Effective default security limits (config may override within its bounds). */
export const RC_SECURITY_DEFAULTS = {
    idleTimeoutMs: 30 * 60_000,
    failureWindowMs: 60_000,
    /** Failures allowed before the next one triggers the temporary ban. */
    failuresBeforeBan: 5,
    temporaryBanMs: 5 * 60_000,
    /** Total failures in one manual session that close remote access. */
    circuitBreakerFailures: 10,
    accessTtlMs: 15 * 60_000,
};
/**
 * WebSocket close codes used by the plugin (RFC 6455 private range).
 * `policyViolation` is the standard policy close; the 400x codes are ours.
 */
export const RC_WS_CLOSE = {
    policyViolation: 1008,
    /** Device was revoked, expired or otherwise no longer authenticated. */
    deviceLost: 4001,
    /** Remote access was closed by the security shutdown path. */
    securityClosed: 4002,
    /** The lease idle clock expired. */
    idleTimeout: 4003,
    /** Another device now holds the single-active-device lease. */
    leaseLost: 4004,
};
/** Cloudflare Access is enforced in addition to the plugin's own auth layers. */
export const RC_ACCESS_JWT_HEADER = 'cf-access-jwt-assertion';
/** Cookie Cloudflare Access sets on the browser (used only as a fallback hint). */
export const RC_CF_ACCESS_COOKIE = 'CF_Authorization';
