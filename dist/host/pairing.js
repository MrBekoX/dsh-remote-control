/**
 * In-memory pairing state machine (design §5.1).
 *
 * Only one-time codes are hashed in memory (`sha256`); a claim keeps the poll
 * token so the desktop approval hook can hand it back to the controller, but it
 * never leaves the process and is compared in constant time.
 *
 * Lifecycle:
 *   code minted  → claim (code consumed atomically) → desktop approve/deny
 *   → controller issues device tokens → consume(claimId)
 *
 * Codes and claims are swept on TTL. A claim that is approved/denied stays
 * visible until `consume()` or its retention window ends, so the phone can
 * observe the terminal state on its next poll.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
const CODE_BYTES = 32;
const CLAIM_ID_BYTES = 16;
const POLL_TOKEN_BYTES = 32;
const MAX_DEVICE_NAME = 64;
const MAX_PENDING_CLAIMS = 256;
/** Bounded memory of already-claimed code hashes so a replay reports 403, not 400. */
const MAX_CONSUMED_CODES = 512;
const TERMINAL_STATES = new Set(['denied', 'expired', 'claimed-timeout']);
function sha256Hex(value) {
    return createHash('sha256').update(value, 'utf8').digest('hex');
}
function constantTimeEqualHex(a, b) {
    const left = Buffer.from(a, 'utf8');
    const right = Buffer.from(b, 'utf8');
    if (left.length !== right.length)
        return false;
    return timingSafeEqual(left, right);
}
/**
 * Normalize a device name for display: strip control/bidi characters, collapse
 * whitespace, cap at 64 chars. Falls back to "Unknown device" when empty.
 */
export function sanitizeDeviceName(value) {
    const cleaned = String(value ?? '')
        .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
    if (cleaned === '')
        return 'Unknown device';
    return cleaned.slice(0, MAX_DEVICE_NAME).trim();
}
/** Normalize the platform tag to a short opaque lowercase token. */
export function sanitizePlatform(value) {
    const normalized = String(value ?? '').trim().toLowerCase();
    if (/^[a-z0-9._-]{1,32}$/.test(normalized))
        return normalized;
    return 'web';
}
export function createPairingManager(options) {
    const now = options.now ?? Date.now;
    const random = options.randomBytes ?? randomBytes;
    const ttlMs = Number.isSafeInteger(options.ttlMs) && options.ttlMs > 0 ? options.ttlMs : 120_000;
    const maxPendingCodes = Number.isSafeInteger(options.maxPendingCodes) && options.maxPendingCodes > 0
        ? options.maxPendingCodes
        : 3;
    const maxDevices = options.maxDevices !== undefined && Number.isSafeInteger(options.maxDevices) && options.maxDevices > 0
        ? options.maxDevices
        : undefined;
    const log = options.log;
    /** codeHash(hex) → code entry. Raw codes are never retained. */
    const codes = new Map();
    /** codeHash(hex) → claim time. Only used to answer replays with PAIRING_CONSUMED. */
    const consumedCodes = new Map();
    /** claimId → claim. */
    const claims = new Map();
    const failure = (code, message) => ({ ok: false, code, message });
    function toView(entry) {
        return {
            claimId: entry.claimId,
            deviceName: entry.deviceName,
            platform: entry.platform,
            createdAt: entry.createdAt,
            expiresAt: entry.expiresAt,
            state: entry.state,
        };
    }
    function codeView(entry) {
        return {
            claimId: null,
            // The code hash is not user display data; the panel renders "waiting for phone".
            deviceName: '',
            platform: '',
            createdAt: entry.createdAt,
            expiresAt: entry.expiresAt,
            state: 'pending',
        };
    }
    function sweep(at = now()) {
        for (const [hash, entry] of codes) {
            if (entry.expiresAt <= at)
                codes.delete(hash);
        }
        // Consumed-code markers only exist to turn a replay into 403; they may be
        // dropped after the original code would have expired anyway.
        for (const [hash, consumedAt] of consumedCodes) {
            if (consumedAt + ttlMs * 2 <= at)
                consumedCodes.delete(hash);
        }
        while (consumedCodes.size > MAX_CONSUMED_CODES) {
            const oldest = consumedCodes.keys().next();
            if (oldest.done === true)
                break;
            consumedCodes.delete(oldest.value);
        }
        for (const [claimId, entry] of claims) {
            if ((entry.state === 'claimed' || entry.state === 'approved') && entry.expiresAt <= at) {
                entry.state = entry.state === 'approved' ? 'expired' : 'claimed-timeout';
                entry.removeAt = at + ttlMs;
                log.debug('pairing claim expired', { claimId, state: entry.state });
            }
            if (entry.removeAt <= at)
                claims.delete(claimId);
        }
        if (claims.size > MAX_PENDING_CLAIMS) {
            const excess = claims.size - MAX_PENDING_CLAIMS;
            let removed = 0;
            for (const [claimId, entry] of claims) {
                if (removed >= excess)
                    break;
                if (TERMINAL_STATES.has(entry.state)) {
                    claims.delete(claimId);
                    removed += 1;
                }
            }
        }
    }
    function create() {
        sweep();
        if (codes.size >= maxPendingCodes) {
            log.debug('pairing code limit reached', { maxPendingCodes });
            return null;
        }
        const code = random(CODE_BYTES).toString('base64url');
        const createdAt = now();
        const expiresAt = createdAt + ttlMs;
        codes.set(sha256Hex(code), { createdAt, expiresAt });
        log.info('pairing code created');
        return { code, expiresAt };
    }
    function claim(input) {
        const at = now();
        const rawCode = typeof input?.code === 'string' ? input.code.trim() : '';
        if (rawCode === '')
            return failure('PAIRING_INVALID', 'Pairing code is invalid or already used');
        const codeHash = sha256Hex(rawCode);
        // Look the code up before sweeping so an expired (but not yet pruned) code
        // can report PAIRING_EXPIRED instead of a generic invalid-code error.
        const entry = codes.get(codeHash);
        if (entry !== undefined)
            codes.delete(codeHash);
        sweep(at);
        if (entry === undefined) {
            // A code that was already claimed once must report a replay distinctly:
            // the phone reuses a code exactly once, while an attacker replays it.
            if (consumedCodes.has(codeHash)) {
                return failure('PAIRING_CONSUMED', 'Pairing code has already been used');
            }
            return failure('PAIRING_INVALID', 'Pairing code is invalid or already used');
        }
        // Single use: the code is gone before any other check or race can reuse it.
        if (entry.expiresAt <= at) {
            return failure('PAIRING_EXPIRED', 'Pairing code has expired');
        }
        const used = options.deviceCount?.();
        if (used !== undefined && maxDevices !== undefined && used >= maxDevices) {
            log.warn('pairing rejected: device limit reached', { maxDevices });
            return failure('DEVICE_LIMIT', 'Maximum number of paired devices reached');
        }
        const claimId = random(CLAIM_ID_BYTES).toString('base64url');
        const pollToken = random(POLL_TOKEN_BYTES).toString('base64url');
        const deviceName = sanitizeDeviceName(input.deviceName);
        const platform = sanitizePlatform(input.platform);
        const expiresAt = at + ttlMs;
        claims.set(claimId, {
            claimId,
            pollHash: sha256Hex(pollToken),
            pollToken,
            deviceName,
            platform,
            createdAt: at,
            expiresAt,
            state: 'claimed',
            removeAt: expiresAt + ttlMs,
            reserved: false,
        });
        log.info('pairing claim created', { claimId, platform });
        // The code is spent: remember its hash (never the code) so a second claim
        // is rejected as a replay instead of a generic invalid code.
        consumedCodes.set(codeHash, at);
        return { ok: true, claimId, pollToken, expiresAt };
    }
    function status(claimId, pollToken) {
        sweep();
        const entry = typeof claimId === 'string' ? claims.get(claimId) : undefined;
        if (entry === undefined)
            return 'expired';
        const presentedHash = sha256Hex(typeof pollToken === 'string' ? pollToken : '');
        if (!constantTimeEqualHex(presentedHash, entry.pollHash)) {
            // Do not reveal whether the claim id exists: fail closed as expired.
            log.warn('pairing status poll with an invalid poll token', { claimId });
            return 'expired';
        }
        return entry.state;
    }
    function approve(claimId) {
        sweep();
        const entry = typeof claimId === 'string' ? claims.get(claimId) : undefined;
        if (entry === undefined)
            return null;
        // Once a poll reserved the claim for token issuance, nothing may re-read or
        // re-approve it: the desktop decision is already spent.
        if (entry.reserved)
            return null;
        if (entry.state === 'approved') {
            // Idempotent: the controller may re-read the details while issuing tokens.
            return { deviceName: entry.deviceName, platform: entry.platform, pollToken: entry.pollToken };
        }
        if (entry.state !== 'claimed')
            return null;
        entry.state = 'approved';
        // Keep the freshly approved claim observable long enough for the phone's
        // next poll: the controller creates the device and consumes the claim on
        // that poll, so the original code TTL must not expire in between.
        entry.expiresAt = now() + ttlMs;
        entry.removeAt = entry.expiresAt + ttlMs;
        log.info('pairing claim approved', { claimId });
        return { deviceName: entry.deviceName, platform: entry.platform, pollToken: entry.pollToken };
    }
    /**
     * Atomically reserve an approved claim exactly once, BEFORE the controller's
     * first async device-creation step. This is the single-winner gate: a
     * concurrent/replayed status poll gets `null` (fail closed) and can never
     * mint a second device. The poll secret is compared in constant time and the
     * raw secret is dropped from memory once the claim is reserved.
     */
    function beginIssue(claimId, pollToken) {
        sweep();
        if (typeof claimId !== 'string' || typeof pollToken !== 'string')
            return null;
        if (claimId === '' || pollToken === '')
            return null;
        const entry = claims.get(claimId);
        if (entry === undefined)
            return null;
        if (entry.reserved)
            return null;
        const presentedHash = sha256Hex(pollToken);
        if (!constantTimeEqualHex(presentedHash, entry.pollHash)) {
            // Do not reveal whether the claim id exists: fail closed.
            log.warn('pairing issue attempted with an invalid poll token', { claimId });
            return null;
        }
        if (entry.state !== 'approved')
            return null;
        if (entry.expiresAt <= now()) {
            entry.state = 'expired';
            entry.removeAt = now() + ttlMs;
            return null;
        }
        entry.reserved = true;
        entry.pollToken = '';
        log.info('pairing claim reserved for device issuance', { claimId });
        return { deviceName: entry.deviceName, platform: entry.platform };
    }
    function deny(claimId) {
        sweep();
        const entry = typeof claimId === 'string' ? claims.get(claimId) : undefined;
        if (entry === undefined || entry.state !== 'claimed' || entry.reserved)
            return false;
        entry.state = 'denied';
        entry.removeAt = now() + ttlMs;
        log.info('pairing claim denied', { claimId });
        return true;
    }
    function consume(claimId) {
        if (typeof claimId !== 'string')
            return;
        claims.delete(claimId);
    }
    function list() {
        sweep();
        const views = [];
        for (const entry of codes.values())
            views.push(codeView(entry));
        for (const entry of claims.values())
            views.push(toView(entry));
        return views.sort((a, b) => a.createdAt - b.createdAt);
    }
    function pendingApprovals() {
        sweep();
        return [...claims.values()]
            .filter((entry) => entry.state === 'claimed')
            .map(toView)
            .sort((a, b) => a.createdAt - b.createdAt);
    }
    const sweepTimer = setInterval(() => {
        try {
            sweep();
        }
        catch {
            // Sweeping must never take the plugin down.
        }
    }, Math.max(1_000, Math.min(5_000, Math.floor(ttlMs / 4))));
    sweepTimer.unref();
    function dispose() {
        clearInterval(sweepTimer);
        codes.clear();
        consumedCodes.clear();
        claims.clear();
    }
    return {
        create,
        claim,
        status,
        beginIssue,
        approve,
        deny,
        consume,
        list,
        pendingApprovals,
        sweep,
        dispose,
    };
}
