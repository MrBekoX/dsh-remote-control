/**
 * Session data plane: the narrow, default-deny projection of the DSH Session
 * Remote API that the phone REST surface and the `/rc/ws` multiplexer share.
 *
 * Nothing outside {@link ALLOWED_GATEWAY_METHODS} ever reaches the gateway, and
 * every public method returns the RC wire shapes from `shared/protocol.ts`
 * instead of raw DSH values. That keeps DSH's generated wire descriptors an
 * implementation detail of this module.
 *
 * Wire-shape evidence (`scratch/CONTRACT.md` §2.1): every Session endpoint takes
 * exactly one named request object, wrapped by {@link GatewayClient} as
 * `{ request: … }` (and `{ _request: … }` for list). This module therefore
 * passes **logical** arguments only. `session/page` requires `throughSeq` (the
 * follow snapshot cursor) and is rejected here without it.
 */
import { randomUUID } from 'node:crypto';
import { RC_LIMITS, } from './shared/protocol.js';
/** Read-only endpoints exposed to remote clients. `prompt`/`cancel` gate on config. */
const ALLOWED_GATEWAY_METHODS = new Set(['list', 'page', 'projections', 'prompt', 'cancel', 'follow', 'create', 'attachment']);
/** File-upload Remote is namespace-scoped, not a Session namespace method. */
const FILE_UPLOAD_METHOD = 'fileUploads/upload';
/* ------------------------------------------------------------------------- */
/* Small runtime validators                                                  */
/* ------------------------------------------------------------------------- */
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function isFiniteNumber(value) {
    return typeof value === 'number' && Number.isFinite(value);
}
/** Public error carrying one of the RC error codes. */
function rcError(code, message) {
    return Object.assign(new Error(message), { code });
}
function errorMessage(error) {
    if (error instanceof Error && error.message.length > 0)
        return error.message.slice(0, 300);
    if (typeof error === 'string' && error.length > 0)
        return error.slice(0, 300);
    return 'gateway request failed';
}
function errorCode(error) {
    if (!isRecord(error))
        return undefined;
    return typeof error.code === 'string' && error.code.length > 0 ? error.code : undefined;
}
/**
 * Map a gateway failure onto the public RC error vocabulary.
 *
 * A DSH message never contains phone token material; it may contain file paths
 * or argument field names, which are bounded here and never logged verbatim.
 */
function mapGatewayError(error) {
    const message = errorMessage(error);
    const code = errorCode(error);
    if (code !== undefined) {
        if (code === 'gateway/input-invalid' || code === 'gateway/arguments-invalid') {
            return rcError('BAD_REQUEST', message);
        }
        if (code === 'remote-access/denied' || code === 'gateway/interactions-forbidden') {
            return rcError('NOT_ALLOWED', message);
        }
        if (code.startsWith('session/') && code.includes('not-found')) {
            return rcError('NOT_FOUND', message);
        }
        if (code === 'gateway/cancelled') {
            return rcError('GATEWAY', 'gateway invocation was cancelled');
        }
    }
    return rcError('GATEWAY', message);
}
function clampInteger(value, min, max) {
    if (!isFiniteNumber(value))
        return undefined;
    if (!Number.isInteger(value))
        return undefined;
    return Math.min(max, Math.max(min, value));
}
/* ------------------------------------------------------------------------- */
/* DSH → RC normalization                                                    */
/* ------------------------------------------------------------------------- */
/**
 * DSH follow/page records are `{ type: 'event', event }` wrappers. Accept both
 * the wrapper and a bare event; anything without the durable envelope fields
 * is dropped (never fabricated).
 */
function normalizeEvent(value) {
    if (!isRecord(value))
        return null;
    if (typeof value.type !== 'string' || value.type.length === 0)
        return null;
    if (!isFiniteNumber(value.seq) || !isFiniteNumber(value.time))
        return null;
    const record = { type: value.type, seq: value.seq, time: value.time };
    if (Object.hasOwn(value, 'data'))
        record.data = value.data;
    if (value.ignorable === true)
        record.ignorable = true;
    if (Object.hasOwn(value, 'surfaceOp'))
        record.surfaceOp = value.surfaceOp;
    if (Array.isArray(value.sourceEventSeqs) && value.sourceEventSeqs.every(isFiniteNumber)) {
        record.sourceEventSeqs = [...value.sourceEventSeqs];
    }
    return record;
}
function normalizeRecords(value) {
    if (!Array.isArray(value))
        return [];
    const records = [];
    for (const entry of value) {
        const event = isRecord(entry) && entry.type === 'event' && isRecord(entry.event) ? entry.event : entry;
        const record = normalizeEvent(event);
        if (record !== null)
            records.push(record);
    }
    return records;
}
function normalizeProjectionBlock(value) {
    if (!isRecord(value))
        return null;
    const asOfSeq = isFiniteNumber(value.asOfSeq) ? value.asOfSeq : 0;
    const values = isRecord(value.values) ? value.values : {};
    return { asOfSeq, values };
}
/** Normalize one `session/list` item; unknown/missing DSH fields get safe defaults. */
function normalizeSessionSummary(item) {
    if (!isRecord(item) || typeof item.sessionId !== 'string' || item.sessionId.length === 0)
        return null;
    const projections = isRecord(item.projections) ? item.projections : undefined;
    const values = projections !== undefined && isRecord(projections.values) ? projections.values : undefined;
    const title = values !== undefined && typeof values.title === 'string' && values.title.length > 0 ? values.title : null;
    const cwd = typeof item.cwd === 'string' && item.cwd.length > 0 ? item.cwd : null;
    const parentSessionId = typeof item.parentSessionId === 'string' && item.parentSessionId.length > 0 ? item.parentSessionId : null;
    const formatStatus = typeof item.formatStatus === 'string' ? item.formatStatus : null;
    const running = item.running === true;
    const agentAvailable = item.agentAvailable === true;
    return {
        sessionId: item.sessionId,
        updatedAt: isFiniteNumber(item.updatedAt) ? item.updatedAt : 0,
        running,
        agentAvailable,
        blank: item.blank === true,
        cwd,
        title,
        parentSessionId,
        // `formatStatus` is the best host-provided hint; otherwise fall back to the
        // live activity the phone list already renders.
        status: formatStatus ?? (running ? 'running' : 'idle'),
    };
}
function normalizeFollowFrame(value) {
    if (!isRecord(value) || typeof value.type !== 'string')
        return null;
    switch (value.type) {
        case 'snapshot':
            return {
                type: 'snapshot',
                cursor: isFiniteNumber(value.cursor) ? value.cursor : 0,
                header: Object.hasOwn(value, 'header') ? value.header : null,
                records: normalizeRecords(value.records),
                hasMore: value.hasMore === true,
                projections: normalizeProjectionBlock(value.projections),
            };
        case 'event': {
            const event = normalizeEvent(value.event);
            return event === null ? null : { type: 'event', event };
        }
        case 'assistant-stream':
            return Object.hasOwn(value, 'frame') ? { type: 'assistant-stream', frame: value.frame } : null;
        default:
            return null;
    }
}
/** Media types the DSH prompt endpoint accepts for inline images. */
const IMAGE_MEDIA_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);
/** Exact decoded byte length of a canonical base64 payload, or null when invalid. */
function base64Bytes(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0)
        return null;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value))
        return null;
    try {
        const decoded = Buffer.from(value, 'base64');
        // DSH rejects non-canonical base64; enforce the same round-trip rule here.
        if (decoded.toString('base64') !== value)
            return null;
        return decoded.length;
    }
    catch {
        return null;
    }
}
function attachmentName(value) {
    if (value === undefined)
        return undefined;
    if (typeof value !== 'string')
        throw rcError('BAD_REQUEST', 'attachment name must be a string');
    const name = value.trim();
    if (name.length === 0)
        return undefined;
    if (name.length > 128)
        throw rcError('BAD_REQUEST', 'attachment name is too long');
    return name;
}
/** Convert phone prompt content into the exact DSH prompt vocabulary (text/image/file). */
function normalizePromptContent(value) {
    if (typeof value === 'string')
        return [{ type: 'text', text: value }];
    if (!Array.isArray(value))
        throw rcError('BAD_REQUEST', 'prompt content must be a string or an array of parts');
    const parts = [];
    let textChars = 0;
    let attachments = 0;
    let attachmentBytes = 0;
    let hasText = false;
    for (const entry of value) {
        if (typeof entry === 'string') {
            parts.push({ type: 'text', text: entry });
            textChars += entry.length;
            if (entry.trim().length > 0)
                hasText = true;
            continue;
        }
        if (!isRecord(entry))
            throw rcError('BAD_REQUEST', 'prompt content part is malformed');
        if (entry.type === 'text') {
            if (typeof entry.text !== 'string')
                throw rcError('BAD_REQUEST', 'text part must carry text');
            parts.push({ type: 'text', text: entry.text });
            textChars += entry.text.length;
            if (entry.text.trim().length > 0)
                hasText = true;
            continue;
        }
        if (entry.type === 'image') {
            const mediaType = entry.mediaType;
            if (typeof mediaType !== 'string' || !IMAGE_MEDIA_TYPES.has(mediaType)) {
                throw rcError('BAD_REQUEST', 'unsupported image media type');
            }
            const data = entry.data;
            if (typeof data !== 'string')
                throw rcError('BAD_REQUEST', 'image data must be a base64 string');
            const bytes = base64Bytes(data);
            if (bytes === null)
                throw rcError('BAD_REQUEST', 'image data must be canonical base64');
            if (bytes > RC_LIMITS.maxAttachmentBytes)
                throw rcError('BAD_REQUEST', 'image is too large');
            attachments += 1;
            attachmentBytes += bytes;
            const name = attachmentName(entry.name);
            const imageType = mediaType;
            parts.push(name === undefined ? { type: 'image', mediaType: imageType, data } : { type: 'image', mediaType: imageType, data, name });
            continue;
        }
        if (entry.type === 'file') {
            if (typeof entry.receiptId !== 'string' || entry.receiptId.length === 0 || entry.receiptId.length > 256) {
                throw rcError('BAD_REQUEST', 'file part must carry a valid receiptId');
            }
            attachments += 1;
            parts.push({ type: 'file', receiptId: entry.receiptId });
            continue;
        }
        throw rcError('BAD_REQUEST', 'unsupported prompt content part type');
    }
    if (parts.length === 0)
        throw rcError('BAD_REQUEST', 'prompt content must not be empty');
    if (textChars > RC_LIMITS.maxPromptChars)
        throw rcError('BAD_REQUEST', 'prompt content is too long');
    if (attachments > RC_LIMITS.maxAttachmentsPerMessage) {
        throw rcError('BAD_REQUEST', 'too many attachments in one prompt');
    }
    if (attachmentBytes > RC_LIMITS.maxAttachmentMessageBytes) {
        throw rcError('BAD_REQUEST', 'attachments in one prompt are too large');
    }
    if (!hasText && attachments === 0) {
        throw rcError('BAD_REQUEST', 'prompt content must include non-whitespace text or an attachment');
    }
    return parts;
}
function normalizePromptRequest(value) {
    if (!isRecord(value))
        throw rcError('BAD_REQUEST', 'prompt body is required');
    const mode = value.mode === undefined ? 'queue' : value.mode;
    if (mode !== 'queue' && mode !== 'steer')
        throw rcError('BAD_REQUEST', 'mode must be "queue" or "steer"');
    let requestId;
    if (value.requestId === undefined) {
        requestId = randomUUID();
    }
    else if (typeof value.requestId === 'string' && value.requestId.length > 0 && value.requestId.length <= 200) {
        requestId = value.requestId;
    }
    else {
        throw rcError('BAD_REQUEST', 'requestId must be a non-empty string of at most 200 characters');
    }
    const content = normalizePromptContent(value.content);
    let clientTimeZone;
    if (value.clientTimeZone !== undefined) {
        if (typeof value.clientTimeZone !== 'string' || value.clientTimeZone.length === 0 || value.clientTimeZone.length > 64) {
            throw rcError('BAD_REQUEST', 'clientTimeZone must be a short IANA time-zone name');
        }
        clientTimeZone = value.clientTimeZone;
    }
    return clientTimeZone === undefined ? { requestId, mode, content } : { requestId, mode, content, clientTimeZone };
}
/* ------------------------------------------------------------------------- */
/* Factory                                                                   */
/* ------------------------------------------------------------------------- */
/**
 * Create the allowlisted data plane for one plugin lifetime.
 *
 * @param deps.gateway - DSH gateway client (shared owner peer).
 * @param deps.config - plugin config; `remoteMutations=false` keeps phones read-only.
 * @param deps.log - plugin logger; never receives prompt text or tokens.
 * @param deps.audit - audit ring; only short non-sensitive metadata is pushed.
 */
export function createSessionBridge(deps) {
    const { gateway, config, log, audit } = deps;
    let disposed = false;
    function assertActive() {
        if (disposed)
            throw rcError('INTERNAL', 'remote control: session bridge is disposed');
    }
    function assertSessionId(value) {
        if (typeof value !== 'string' || value.trim().length === 0 || value.length > 200) {
            throw rcError('BAD_REQUEST', 'sessionId is required');
        }
        return value;
    }
    function assertMutations() {
        if (!config.remoteMutations)
            throw rcError('NOT_ALLOWED', 'remote mutations are disabled');
    }
    function auditMeta(detail, kind = 'rpc') {
        try {
            audit.push({ deviceId: null, kind, detail });
        }
        catch {
            /* the audit ring must never fail a gateway call */
        }
    }
    function assertAllowed(method) {
        if (!ALLOWED_GATEWAY_METHODS.has(method)) {
            throw rcError('NOT_ALLOWED', `endpoint session/${method} is not exposed to remote clients`);
        }
        return method;
    }
    async function call(method, args, signal) {
        assertAllowed(method);
        try {
            return await gateway.invoke(method, args, signal);
        }
        catch (error) {
            throw mapGatewayError(error);
        }
    }
    /**
     * Cached desktop-parity visibility scope. The workspace baseline changes only
     * on workspace/session archive mutations, so a short TTL keeps list calls
     * cheap without letting the phone drift for long.
     */
    const WORKSPACE_SCOPE_TTL_MS = 10_000;
    let workspaceScopeCache = null;
    /** Last list() result, reused by the cwd-grouping fallback (avoids a double gateway read). */
    let lastSessionsCache = null;
    async function readWorkspaceScope(signal) {
        const now = Date.now();
        if (workspaceScopeCache !== null && now - workspaceScopeCache.readAt < WORKSPACE_SCOPE_TTL_MS) {
            return workspaceScopeCache.scope;
        }
        if (typeof gateway.workspaceSessionScope !== 'function')
            return null;
        try {
            const scope = await gateway.workspaceSessionScope(signal);
            workspaceScopeCache = { readAt: Date.now(), scope };
            return scope;
        }
        catch (error) {
            log.debug('session bridge: workspace visibility scope unavailable', errorMessage(error));
            return null;
        }
    }
    async function list(signal) {
        assertActive();
        // Logical (unwrapped) arguments: gateway-client adds the descriptor's
        // `_request` wire wrapper for `session/list`.
        const value = await call('list', {}, signal);
        if (!isRecord(value) || !Array.isArray(value.items)) {
            throw rcError('GATEWAY', 'unexpected session list response');
        }
        const sessions = [];
        for (const item of value.items) {
            const summary = normalizeSessionSummary(item);
            if (summary !== null)
                sessions.push(summary);
        }
        // Desktop parity: the Workspace registry accounts only top-level sessions,
        // so subagent/teammate sessions and archived sessions disappear here while
        // the desktop sidebar shows the same set. A registry failure must never
        // break the list; the unfiltered gateway list is a safe fallback.
        const scope = await readWorkspaceScope(signal);
        if (scope !== null) {
            const archived = new Set(scope.archivedSessionIds);
            const order = new Map();
            scope.orderedSessionIds.forEach((id, index) => order.set(id, index));
            const filtered = sessions.filter((session) => !archived.has(session.sessionId) && order.has(session.sessionId));
            filtered.sort((left, right) => {
                const leftOrder = order.get(left.sessionId) ?? Number.MAX_SAFE_INTEGER;
                const rightOrder = order.get(right.sessionId) ?? Number.MAX_SAFE_INTEGER;
                if (leftOrder !== rightOrder)
                    return leftOrder - rightOrder;
                return right.updatedAt - left.updatedAt;
            });
            lastSessionsCache = filtered;
            return filtered;
        }
        lastSessionsCache = sessions;
        return sessions;
    }
    async function projections(sessionId, signal) {
        assertActive();
        const id = assertSessionId(sessionId);
        const value = await call('projections', { sessionId: id }, signal);
        if (value === null || value === undefined) {
            return { ok: true, sessionId: id, kind: 'none', asOfSeq: null, values: {} };
        }
        if (!isRecord(value))
            throw rcError('GATEWAY', 'unexpected session projections response');
        const values = isRecord(value.values) ? value.values : {};
        if (value.kind === 'migration-required') {
            return { ok: true, sessionId: id, kind: 'migration-required', asOfSeq: null, values };
        }
        const asOfSeq = isFiniteNumber(value.asOfSeq) ? value.asOfSeq : null;
        if (value.kind !== 'sequenced' && asOfSeq === null) {
            return { ok: true, sessionId: id, kind: 'none', asOfSeq: null, values: {} };
        }
        return { ok: true, sessionId: id, kind: 'sequenced', asOfSeq, values };
    }
    async function page(sessionId, request, signal) {
        assertActive();
        const id = assertSessionId(sessionId);
        if (!isRecord(request))
            throw rcError('BAD_REQUEST', 'page request is required');
        // DSH requires `throughSeq` (the follow snapshot `cursor`); a page without
        // it cannot be expressed on the wire, so reject it before the gateway does.
        if (!isFiniteNumber(request.throughSeq)) {
            throw rcError('BAD_REQUEST', 'throughSeq is required and must be the latest follow snapshot cursor');
        }
        const wire = {
            address: { kind: 'session', sessionId: id },
            throughSeq: request.throughSeq,
            maxMessages: clampInteger(request.maxMessages, 1, RC_LIMITS.maxMessages) ?? RC_LIMITS.pageDefaultMessages,
        };
        if (isFiniteNumber(request.beforeSeq))
            wire.beforeSeq = request.beforeSeq;
        const value = await call('page', wire, signal);
        if (!isRecord(value))
            throw rcError('GATEWAY', 'unexpected session page response');
        return {
            ok: true,
            sessionId: id,
            records: normalizeRecords(value.records),
            hasMore: value.hasMore === true,
        };
    }
    async function prompt(sessionId, request, signal) {
        assertActive();
        assertMutations();
        const id = assertSessionId(sessionId);
        const normalized = normalizePromptRequest(request);
        const wire = {
            requestId: normalized.requestId,
            sessionId: id,
            mode: normalized.mode,
            content: normalized.content,
        };
        if (normalized.clientTimeZone !== undefined)
            wire.clientTimeZone = normalized.clientTimeZone;
        auditMeta(`session/prompt:${normalized.mode}`);
        const value = await call('prompt', wire, signal);
        return { ok: true, accepted: isRecord(value) ? value.accepted === true : false };
    }
    async function cancel(sessionId, signal) {
        assertActive();
        assertMutations();
        const id = assertSessionId(sessionId);
        auditMeta('session/cancel');
        const value = await call('cancel', { sessionId: id }, signal);
        return { ok: true, accepted: isRecord(value) ? value.accepted === true : false };
    }
    function follow(sessionId, options) {
        const signal = options.signal;
        const requested = options.maxMessages;
        return (async function* () {
            assertActive();
            const id = assertSessionId(sessionId);
            if (signal.aborted)
                return;
            const maxMessages = clampInteger(requested, 1, RC_LIMITS.maxMessages) ?? RC_LIMITS.defaultMessages;
            let source;
            try {
                source = await gateway.stream('follow', {
                    address: { kind: 'session', sessionId: id },
                    assistantStream: true,
                    maxMessages,
                    // `turnWindow.minMessages` must not exceed `maxMessages`.
                    turnWindow: { minMessages: Math.min(50, maxMessages), minTurns: 2 },
                }, signal);
            }
            catch (error) {
                if (signal.aborted)
                    return;
                throw mapGatewayError(error);
            }
            try {
                for await (const raw of source) {
                    if (signal.aborted)
                        return;
                    const frame = normalizeFollowFrame(raw);
                    if (frame === null) {
                        log.debug('session bridge: dropped an unrecognized follow frame');
                        continue;
                    }
                    yield frame;
                }
            }
            catch (error) {
                // An abort is the normal unsubscribe path; do not surface it as an error.
                if (signal.aborted)
                    return;
                throw mapGatewayError(error);
            }
        })();
    }
    function desktopConnected() {
        return gateway.hasLiveClient();
    }
    async function dispose() {
        disposed = true;
        log.debug('session bridge: disposed');
    }
    /* --------------------------------------------------------------------- */
    /* Workspace grouping / new sessions / attachments (desktop-parity extras) */
    /* --------------------------------------------------------------------- */
    const WORKSPACE_GROUPS_TTL_MS = 10_000;
    let workspaceGroupsCache = null;
    function cwdLabel(cwd) {
        if (cwd === null || cwd.trim().length === 0)
            return 'Default workspace';
        const parts = cwd.split(/[\\/]+/).filter((part) => part.length > 0);
        return parts.length > 0 ? parts[parts.length - 1] : cwd;
    }
    /** Fallback grouping used when the Workspace registry is unavailable. */
    function groupsFromSessions(sessions) {
        const groups = new Map();
        for (const session of sessions) {
            const cwd = session.cwd ?? '';
            const key = cwd.length === 0 ? 'cwd:default' : `cwd:${cwd}`;
            let group = groups.get(key);
            if (group === undefined) {
                group = {
                    workspaceId: key,
                    title: cwdLabel(session.cwd),
                    path: cwd,
                    sessionIds: [],
                };
                groups.set(key, group);
            }
            group.sessionIds.push(session.sessionId);
        }
        return [...groups.values()];
    }
    async function workspaces(signal) {
        assertActive();
        const now = Date.now();
        if (workspaceGroupsCache !== null && now - workspaceGroupsCache.readAt < WORKSPACE_GROUPS_TTL_MS) {
            return workspaceGroupsCache.groups;
        }
        if (typeof gateway.workspaceGroups === 'function') {
            try {
                const groups = await gateway.workspaceGroups(signal);
                if (Array.isArray(groups) && groups.length > 0) {
                    workspaceGroupsCache = { readAt: Date.now(), groups };
                    return groups;
                }
            }
            catch (error) {
                log.debug('session bridge: workspace groups unavailable', errorMessage(error));
            }
        }
        const fallback = groupsFromSessions(lastSessionsCache ?? (await list(signal)));
        workspaceGroupsCache = { readAt: Date.now(), groups: fallback };
        return fallback;
    }
    async function createSession(request, signal) {
        assertActive();
        assertMutations();
        if (!isRecord(request))
            throw rcError('BAD_REQUEST', 'create-session request is required');
        const wire = {};
        if (request.workspaceId !== undefined) {
            if (typeof request.workspaceId !== 'string' || request.workspaceId.length === 0 || request.workspaceId.length > 200) {
                throw rcError('BAD_REQUEST', 'workspaceId must be a non-empty short string');
            }
            wire.workspaceId = request.workspaceId;
        }
        if (request.cwd !== undefined) {
            if (typeof request.cwd !== 'string' || request.cwd.trim().length === 0 || request.cwd.length > 4096) {
                throw rcError('BAD_REQUEST', 'cwd must be a non-empty path');
            }
            wire.cwd = request.cwd;
        }
        if (wire.workspaceId !== undefined && wire.cwd !== undefined) {
            throw rcError('BAD_REQUEST', 'workspaceId and cwd are mutually exclusive');
        }
        const value = await call('create', wire, signal);
        if (!isRecord(value) || typeof value.sessionId !== 'string' || value.sessionId.length === 0) {
            throw rcError('GATEWAY', 'unexpected session create response');
        }
        auditMeta('session.create');
        return { ok: true, sessionId: value.sessionId };
    }
    async function uploadFile(sessionId, request, signal) {
        assertActive();
        assertMutations();
        const id = assertSessionId(sessionId);
        if (!isRecord(request))
            throw rcError('BAD_REQUEST', 'file upload request is required');
        const bytes = base64Bytes(request.data);
        if (bytes === null)
            throw rcError('BAD_REQUEST', 'file data must be canonical base64');
        if (bytes > RC_LIMITS.maxAttachmentBytes)
            throw rcError('BAD_REQUEST', 'file is too large');
        const name = attachmentName(request.name);
        const uploadRequest = { data: request.data };
        if (name !== undefined)
            uploadRequest.name = name;
        let value;
        try {
            value = await gateway.invoke(FILE_UPLOAD_METHOD, { agentId: id, request: uploadRequest }, signal);
        }
        catch (error) {
            throw mapGatewayError(error);
        }
        if (!isRecord(value) ||
            typeof value.receiptId !== 'string' ||
            value.receiptId.length === 0 ||
            !isRecord(value.file) ||
            typeof value.file.attachmentId !== 'string' ||
            typeof value.file.name !== 'string' ||
            !isFiniteNumber(value.file.bytes)) {
            throw rcError('GATEWAY', 'unexpected file upload response');
        }
        auditMeta('session.file-upload');
        return {
            ok: true,
            receiptId: value.receiptId,
            file: {
                attachmentId: value.file.attachmentId,
                name: value.file.name,
                bytes: value.file.bytes,
            },
        };
    }
    async function readAttachment(sessionId, attachmentId, signal) {
        assertActive();
        const id = assertSessionId(sessionId);
        if (typeof attachmentId !== 'string' || attachmentId.length === 0 || attachmentId.length > 256) {
            throw rcError('BAD_REQUEST', 'attachmentId is required');
        }
        const value = await call('attachment', { sessionId: id, attachmentId }, signal);
        if (!isRecord(value) || !isRecord(value.attachment) || typeof value.data !== 'string') {
            throw rcError('GATEWAY', 'unexpected attachment response');
        }
        const attachment = value.attachment;
        if (typeof attachment.attachmentId !== 'string' ||
            typeof attachment.mediaType !== 'string' ||
            !IMAGE_MEDIA_TYPES.has(attachment.mediaType) ||
            !isFiniteNumber(attachment.bytes) ||
            !isFiniteNumber(attachment.width) ||
            !isFiniteNumber(attachment.height)) {
            throw rcError('GATEWAY', 'unexpected attachment metadata');
        }
        const bytes = base64Bytes(value.data);
        if (bytes === null || bytes > RC_LIMITS.maxAttachmentMessageBytes) {
            throw rcError('GATEWAY', 'attachment bytes are invalid or too large');
        }
        return {
            ok: true,
            attachment: {
                attachmentId: attachment.attachmentId,
                mediaType: attachment.mediaType,
                bytes: attachment.bytes,
                width: attachment.width,
                height: attachment.height,
                ...(typeof attachment.name === 'string' ? { name: attachment.name } : {}),
            },
            data: value.data,
        };
    }
    return {
        list,
        projections,
        page,
        prompt,
        cancel,
        follow,
        desktopConnected,
        workspaces,
        createSession,
        uploadFile,
        readAttachment,
        dispose,
    };
}
