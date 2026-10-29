/**
 * `/rc/ws` broker: one WebSocket multiplexer per phone socket.
 *
 * The listener owns cookie authentication and the Host/Origin fence; this
 * module receives only already-authenticated upgrades. It still requires an
 * `Origin` header on the upgrade itself (defense in depth) and completes the
 * RFC6455 handshake itself, because `ctx.webServer.registerUpgrade` hands the
 * raw socket to the plugin.
 *
 * Frame contract: `shared/protocol.ts` (`ClientFrame` / `ServerFrame`). Client
 * frames are validated defensively — every socket is remote input. The
 * allowlist for `rpc` is the same default-deny projection the REST surface
 * uses (`session/list|projections|page|prompt|cancel`).
 *
 * Flow control: `assistant-stream` frames are droppable above
 * `RC_HEARTBEAT.maxBufferedBytes` and are reported with a `degraded` frame;
 * durable `event` frames and snapshots are never dropped.
 */
import WebSocket, { WebSocketServer } from 'ws';
import { PROTOCOL_VERSION, RC_ERRORS, RC_HEARTBEAT, RC_LIMITS, RC_STREAM_FOLLOW, RC_WS_CLOSE, } from './shared/protocol.js';
/** RPC methods a paired phone may invoke over the mux. Default-deny. */
const WS_ALLOWED_RPC = new Set([
    'session/list',
    'session/projections',
    'session/page',
    'session/prompt',
    'session/cancel',
]);
const MAX_STREAM_ID_LENGTH = 64;
const MAX_CLOSE_REASON_BYTES = 120;
/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function isFiniteNumber(value) {
    return typeof value === 'number' && Number.isFinite(value);
}
function errorMessage(error) {
    if (error instanceof Error && error.message.length > 0)
        return error.message.slice(0, 300);
    if (typeof error === 'string' && error.length > 0)
        return error.slice(0, 300);
    return 'request failed';
}
function rcError(code, message) {
    return Object.assign(new Error(message), { code });
}
/** Normalize any thrown value into the RC error envelope pair. */
function errorInfo(error) {
    const candidate = isRecord(error) && typeof error.code === 'string' ? error.code : undefined;
    const known = candidate !== undefined && Object.values(RC_ERRORS).includes(candidate);
    return { code: known ? candidate : 'GATEWAY', message: errorMessage(error) };
}
function clampMaxMessages(value) {
    if (!isFiniteNumber(value) || !Number.isInteger(value))
        return RC_LIMITS.defaultMessages;
    return Math.min(RC_LIMITS.maxMessages, Math.max(1, value));
}
function rawDataToText(data) {
    if (Buffer.isBuffer(data))
        return data.toString('utf8');
    if (data instanceof ArrayBuffer)
        return Buffer.from(data).toString('utf8');
    return Buffer.concat(data).toString('utf8');
}
/** WebSocket close reasons are limited to 123 UTF-8 bytes. */
function truncateCloseReason(reason) {
    let text = reason.length > 0 ? reason : 'closed';
    while (Buffer.byteLength(text, 'utf8') > MAX_CLOSE_REASON_BYTES)
        text = text.slice(0, -1);
    return text;
}
/**
 * Close codes a server may legally send (RFC 6455 §7.4): the standard
 * 1000-1014 range except the reserved 1004/1005/1006, plus the private
 * 4000-4999 range used by `RC_WS_CLOSE`.
 */
function isValidCloseCode(code) {
    if (!Number.isInteger(code))
        return false;
    if (code >= 4000 && code <= 4999)
        return true;
    if (code < 1000 || code > 1014)
        return false;
    return code !== 1004 && code !== 1005 && code !== 1006;
}
function closeCodeOr(code, fallback) {
    if (code === undefined)
        return fallback;
    return isValidCloseCode(code) ? code : fallback;
}
function toDeviceView(device) {
    return {
        id: device.id,
        label: device.label,
        platform: device.platform,
        createdAt: device.createdAt,
        lastSeenAt: device.lastSeenAt,
        refreshExpiresAt: device.refreshExpiresAt,
    };
}
/**
 * Create the WebSocket broker for one plugin lifetime.
 *
 * @param deps.dataPlane - session data plane shared with the REST surface.
 * @param deps.approvals - approval hub; one sink is registered per socket.
 * @param deps.pluginVersion - advertised in the `ready` frame.
 * @param deps.log - plugin logger; never receives prompt text or tokens.
 */
export function createWsBroker(deps) {
    const { dataPlane, approvals, pluginVersion, log } = deps;
    const now = deps.now ?? Date.now;
    const heartbeat = deps.heartbeat ?? {
        pingIntervalMs: RC_HEARTBEAT.pingIntervalMs,
        pongTimeoutMs: RC_HEARTBEAT.pongTimeoutMs,
    };
    const maxConnectionsPerDevice = deps.maxConnectionsPerDevice ?? 4;
    const drainGraceMs = deps.drainGraceMs ?? 1_500;
    const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
    const sockets = new Set();
    const byDevice = new Map();
    let drainTimer;
    let disposed = false;
    /* ----------------------------------------------------------------------- */
    /* Per-frame authorization / idle activity                                  */
    /* ----------------------------------------------------------------------- */
    /**
     * Run `deps.authorize(deviceId)` (the controller's current device/revocation/
     * lease check). Returns null when allowed; any failure — including a thrown
     * hook or a malformed result — is fail-closed with an RC error pair.
     */
    function authorizationFailure(conn) {
        // Per-connection session deadline: an access token verified at upgrade/hello
        // is only valid for THIS socket's own expiry. A newer connection of the same
        // device must never extend an older socket's session.
        if (typeof conn.sessionExpiresAt !== 'number' ||
            !Number.isFinite(conn.sessionExpiresAt) ||
            conn.sessionExpiresAt <= now()) {
            log.warn('ws broker: per-frame authorization refused: session expired');
            return { code: 'TOKEN_EXPIRED', message: 'access token expired; refresh and reconnect' };
        }
        const authorize = deps.authorize;
        if (authorize === undefined)
            return null;
        let result;
        try {
            result = authorize(conn.device.id);
        }
        catch (error) {
            log.warn('ws broker: per-frame authorization threw', errorMessage(error));
            return { code: 'INTERNAL', message: 'authorization check failed' };
        }
        if (isRecord(result) && result.ok === true)
            return null;
        if (isRecord(result) && result.ok === false) {
            const knownCodes = Object.values(RC_ERRORS);
            const code = typeof result.code === 'string' && knownCodes.includes(result.code)
                ? result.code
                : 'DEVICE_REVOKED';
            const message = typeof result.message === 'string' && result.message.length > 0
                ? result.message.slice(0, 300)
                : 'device is no longer authorized';
            return { code, message };
        }
        // A hook that does not return the documented shape must not grant access.
        log.warn('ws broker: per-frame authorization returned an unexpected result');
        return { code: 'DEVICE_REVOKED', message: 'device is no longer authorized' };
    }
    /**
     * Renew the idle clock for a verified client frame. Returns null when the
     * device still holds the active lease; otherwise a lease-lost error pair.
     * Only authenticated client frames call this — server pings and automatic
     * pongs never renew the idle clock.
     */
    function activityFailure(conn) {
        const touch = deps.touchActivity;
        if (touch === undefined)
            return null;
        let active = false;
        try {
            active = touch(conn.device.id) !== false;
        }
        catch (error) {
            log.warn('ws broker: activity touch threw', errorMessage(error));
            active = false;
        }
        if (active)
            return null;
        return { code: 'DEVICE_LOCKED', message: 'device no longer holds the active lease' };
    }
    /** Close one socket with an explicit policy code after disposing its resources. */
    function closePolicy(conn, code, reason) {
        disposeConnection(conn, reason);
        closeConnection(conn, code, reason);
    }
    /** Touch the idle clock; close with `leaseLost` when the lease is gone. */
    function renewActivity(conn) {
        const inactive = activityFailure(conn);
        if (inactive === null)
            return true;
        log.warn('ws broker: activity check refused', inactive.code);
        closePolicy(conn, RC_WS_CLOSE.leaseLost, inactive.message);
        return false;
    }
    /* ----------------------------------------------------------------------- */
    /* Frame senders                                                           */
    /* ----------------------------------------------------------------------- */
    function safeSend(conn, frame) {
        if (conn.disposed)
            return false;
        if (conn.ws.readyState !== conn.ws.OPEN)
            return false;
        try {
            conn.ws.send(JSON.stringify(frame));
            return true;
        }
        catch (error) {
            log.debug('ws broker: send failed', errorMessage(error));
            return false;
        }
    }
    /**
     * Send a frame; `droppableStreamId` marks the temporary assistant-stream
     * frames that may be dropped under backpressure. Durable frames never pass
     * a stream id here.
     */
    function sendFrame(conn, frame, droppableStreamId) {
        if (droppableStreamId === undefined)
            return safeSend(conn, frame);
        if (conn.ws.bufferedAmount > RC_HEARTBEAT.maxBufferedBytes) {
            const dropped = (conn.droppedFrames.get(droppableStreamId) ?? 0) + 1;
            conn.droppedFrames.set(droppableStreamId, dropped);
            if (!conn.degradedNotified.has(droppableStreamId)) {
                conn.degradedNotified.add(droppableStreamId);
                // The small degraded frame is still delivered so the client knows the
                // live token stream is incomplete; durable state arrives via events.
                safeSend(conn, { type: 'degraded', streamId: droppableStreamId, droppedAssistantStreamFrames: dropped });
            }
            return false;
        }
        const sent = safeSend(conn, frame);
        if (sent && conn.degradedNotified.has(droppableStreamId)) {
            const dropped = conn.droppedFrames.get(droppableStreamId) ?? 0;
            conn.degradedNotified.delete(droppableStreamId);
            conn.droppedFrames.delete(droppableStreamId);
            if (dropped > 0) {
                safeSend(conn, { type: 'degraded', streamId: droppableStreamId, droppedAssistantStreamFrames: dropped });
            }
        }
        return sent;
    }
    /* ----------------------------------------------------------------------- */
    /* Heartbeat                                                               */
    /* ----------------------------------------------------------------------- */
    function markAlive(conn) {
        conn.awaitingPong = false;
        if (conn.pongTimer !== undefined) {
            clearTimeout(conn.pongTimer);
            conn.pongTimer = undefined;
        }
    }
    function startHeartbeat(conn) {
        conn.heartbeatTimer = setInterval(() => {
            if (conn.disposed)
                return;
            safeSend(conn, { type: 'ping', t: now() });
            // Keep a degrading client informed about the frames it is missing.
            for (const streamId of conn.degradedNotified) {
                safeSend(conn, {
                    type: 'degraded',
                    streamId,
                    droppedAssistantStreamFrames: conn.droppedFrames.get(streamId) ?? 0,
                });
            }
            if (conn.pongTimer !== undefined)
                return;
            conn.awaitingPong = true;
            conn.pongTimer = setTimeout(() => {
                conn.pongTimer = undefined;
                if (conn.disposed)
                    return;
                if (conn.awaitingPong)
                    terminateConnection(conn, 'heartbeat timeout');
            }, heartbeat.pongTimeoutMs);
        }, heartbeat.pingIntervalMs);
    }
    /* ----------------------------------------------------------------------- */
    /* Socket lifecycle                                                        */
    /* ----------------------------------------------------------------------- */
    function abortStream(state) {
        try {
            state.controller.abort(new Error('stream closed'));
        }
        catch {
            /* AbortController.abort with a plain reason does not throw */
        }
    }
    function disposeConnection(conn, reason) {
        if (conn.disposed)
            return;
        conn.disposed = true;
        for (const state of [...conn.streams.values()])
            abortStream(state);
        conn.streams.clear();
        if (conn.heartbeatTimer !== undefined) {
            clearInterval(conn.heartbeatTimer);
            conn.heartbeatTimer = undefined;
        }
        if (conn.pongTimer !== undefined) {
            clearTimeout(conn.pongTimer);
            conn.pongTimer = undefined;
        }
        const disposer = conn.approvalDisposer;
        conn.approvalDisposer = undefined;
        if (disposer !== undefined) {
            try {
                disposer();
            }
            catch (error) {
                log.debug('ws broker: approval detach failed', errorMessage(error));
            }
        }
        sockets.delete(conn);
        const deviceSockets = byDevice.get(conn.device.id);
        if (deviceSockets !== undefined) {
            deviceSockets.delete(conn);
            if (deviceSockets.size === 0)
                byDevice.delete(conn.device.id);
        }
        log.debug('ws broker: connection closed', reason);
    }
    function closeConnection(conn, code, reason) {
        try {
            conn.ws.close(code, truncateCloseReason(reason));
        }
        catch {
            try {
                conn.ws.terminate();
            }
            catch {
                /* socket already gone */
            }
        }
    }
    function terminateConnection(conn, reason) {
        disposeConnection(conn, reason);
        try {
            conn.ws.terminate();
        }
        catch {
            /* socket already gone */
        }
    }
    function rejectUpgrade(socket, status, message) {
        const code = status === 403 ? 'ORIGIN' : status === 429 ? 'RATE_LIMITED' : 'INTERNAL';
        const reason = status === 403 ? 'Forbidden' : status === 429 ? 'Too Many Requests' : 'Service Unavailable';
        try {
            const body = JSON.stringify({ ok: false, error: { code, message } });
            socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
        }
        catch {
            /* the peer may already be gone */
        }
        try {
            socket.destroy();
        }
        catch {
            /* ignore */
        }
    }
    function attachApprovals(conn) {
        const sink = {
            onApproval(view) {
                if (conn.disposed)
                    return;
                safeSend(conn, {
                    type: 'approval',
                    eventId: view.eventId,
                    kind: view.kind,
                    request: view.request,
                    agentId: view.agentId,
                    answerable: view.answerable,
                    expiresInMs: view.expiresInMs,
                });
            },
            onCancel(eventId, reason) {
                if (conn.disposed)
                    return;
                const frame = { type: 'approval-cancel', eventId, reason };
                safeSend(conn, frame);
            },
            onHostEvent(event, args) {
                if (conn.disposed)
                    return;
                const frame = { type: 'event', event, args };
                safeSend(conn, frame);
            },
        };
        void approvals
            .registerDevice(conn.device.id, sink)
            .then((disposer) => {
            if (conn.disposed) {
                try {
                    disposer();
                }
                catch (error) {
                    log.debug('ws broker: late approval detach failed', errorMessage(error));
                }
                return;
            }
            conn.approvalDisposer = disposer;
        })
            .catch((error) => {
            log.warn('ws broker: approval relay attach failed', errorMessage(error));
        });
    }
    function onConnection(ws, device, sessionExpiresAt) {
        if (disposed) {
            ws.on('error', () => {
                /* swallow, the socket is being rejected */
            });
            try {
                ws.close(1001, 'server shutting down');
            }
            catch {
                /* ignore */
            }
            return;
        }
        const deviceSockets = byDevice.get(device.id);
        if (deviceSockets !== undefined && deviceSockets.size >= maxConnectionsPerDevice) {
            // The handshake completed, so the client gets a real WebSocket close code.
            ws.on('error', () => {
                /* swallow, the socket is being rejected */
            });
            try {
                ws.close(1013, 'too many connections for this device');
            }
            catch {
                /* ignore */
            }
            log.warn('ws broker: device connection limit reached');
            return;
        }
        const conn = {
            ws,
            device,
            sessionExpiresAt,
            streams: new Map(),
            heartbeatTimer: undefined,
            pongTimer: undefined,
            awaitingPong: false,
            helloDone: false,
            disposed: false,
            approvalDisposer: undefined,
            droppedFrames: new Map(),
            degradedNotified: new Set(),
        };
        sockets.add(conn);
        const targetSet = deviceSockets ?? new Set();
        targetSet.add(conn);
        byDevice.set(device.id, targetSet);
        ws.on('message', (data, isBinary) => {
            onMessage(conn, data, isBinary);
        });
        ws.on('close', () => {
            disposeConnection(conn, 'socket closed');
        });
        ws.on('error', (error) => {
            log.debug('ws broker: socket error', errorMessage(error));
        });
    }
    /* ----------------------------------------------------------------------- */
    /* Client frames                                                           */
    /* ----------------------------------------------------------------------- */
    function onMessage(conn, data, isBinary) {
        if (conn.disposed)
            return;
        if (isBinary) {
            closeConnection(conn, 1003, 'text frames only');
            return;
        }
        let parsed;
        try {
            parsed = JSON.parse(rawDataToText(data));
        }
        catch {
            closeConnection(conn, 1002, 'invalid JSON frame');
            return;
        }
        if (!isRecord(parsed) || typeof parsed.type !== 'string') {
            closeConnection(conn, 1002, 'invalid frame');
            return;
        }
        markAlive(conn);
        if (!conn.helloDone) {
            handleHello(conn, parsed);
            return;
        }
        void handleClientFrame(conn, parsed).catch((error) => {
            log.warn('ws broker: frame handling failed', errorMessage(error));
        });
    }
    function handleHello(conn, frame) {
        if (frame.type !== 'hello') {
            closeConnection(conn, 1002, 'first frame must be hello');
            return;
        }
        if (frame.protocol !== PROTOCOL_VERSION) {
            closeConnection(conn, 1002, 'unsupported protocol version');
            return;
        }
        // Authentication is not upgrade-only: re-check the device at hello (it may
        // have been revoked/expired between the HTTP upgrade and this frame).
        const denied = authorizationFailure(conn);
        if (denied !== null) {
            log.warn('ws broker: hello authorization refused', denied.code);
            closePolicy(conn, RC_WS_CLOSE.deviceLost, denied.message);
            return;
        }
        if (!renewActivity(conn))
            return;
        conn.helloDone = true;
        const ready = {
            type: 'ready',
            protocol: PROTOCOL_VERSION,
            pluginVersion,
            device: toDeviceView(conn.device),
        };
        safeSend(conn, ready);
        startHeartbeat(conn);
        attachApprovals(conn);
    }
    /**
     * Authorization for the non-mutation frames (ping/pong/sub/unsub/unknown).
     * Mutation frames (rpc/answer) keep their dedicated checks, which also answer
     * with an explicit error frame. An expired, revoked or lease-lost socket must
     * not keep opening follow streams or heartbeating after the upgrade.
     */
    function authorizeFrame(conn, kind) {
        const denied = authorizationFailure(conn);
        if (denied === null)
            return true;
        log.warn('ws broker: frame authorization refused', { kind, code: denied.code });
        closePolicy(conn, RC_WS_CLOSE.deviceLost, denied.message);
        return false;
    }
    async function handleClientFrame(conn, frame) {
        // Mutations and approval answers re-check authorization themselves because
        // their rejection path also sends an error frame to the caller.
        if (frame.type === 'rpc') {
            await handleRpc(conn, frame);
            return;
        }
        if (frame.type === 'answer') {
            await handleAnswer(conn, frame);
            return;
        }
        if (!authorizeFrame(conn, String(frame.type)))
            return;
        switch (frame.type) {
            case 'ping':
                // Client-initiated application ping = verified phone activity.
                if (!renewActivity(conn))
                    return;
                safeSend(conn, { type: 'pong', t: isFiniteNumber(frame.t) ? frame.t : now() });
                return;
            case 'pong':
                // Automatic reply to a server heartbeat ping: never renews the idle clock.
                return;
            case 'sub':
                if (!renewActivity(conn))
                    return;
                startFollow(conn, frame);
                return;
            case 'unsub':
                if (!renewActivity(conn))
                    return;
                stopStream(conn, frame.streamId);
                return;
            case 'hello':
                log.debug('ws broker: duplicate hello ignored');
                return;
            default:
                // Forward compatibility: an unknown frame type is ignored, not fatal.
                log.debug('ws broker: ignored an unknown frame type');
        }
    }
    /* ----------------------------------------------------------------------- */
    /* Follow streams                                                          */
    /* ----------------------------------------------------------------------- */
    function stopStream(conn, streamId) {
        if (typeof streamId !== 'string')
            return;
        const state = conn.streams.get(streamId);
        if (state === undefined)
            return;
        conn.streams.delete(streamId);
        abortStream(state);
    }
    function startFollow(conn, frame) {
        const streamId = typeof frame.streamId === 'string' ? frame.streamId : '';
        if (streamId.length === 0 || streamId.length > MAX_STREAM_ID_LENGTH) {
            log.debug('ws broker: ignored a sub frame without a valid streamId');
            return;
        }
        if (frame.kind !== RC_STREAM_FOLLOW) {
            const streamError = {
                type: 'stream-error',
                streamId,
                error: { code: 'NOT_ALLOWED', message: 'unsupported stream kind' },
            };
            safeSend(conn, streamError);
            return;
        }
        const sessionId = typeof frame.sessionId === 'string' ? frame.sessionId.trim() : '';
        if (sessionId.length === 0) {
            const streamError = {
                type: 'stream-error',
                streamId,
                error: { code: 'BAD_REQUEST', message: 'sessionId is required' },
            };
            safeSend(conn, streamError);
            return;
        }
        stopStream(conn, streamId);
        const controller = new AbortController();
        const state = { controller, pump: Promise.resolve() };
        conn.streams.set(streamId, state);
        const maxMessages = clampMaxMessages(frame.maxMessages);
        state.pump = (async () => {
            try {
                for await (const follow of dataPlane.follow(sessionId, { maxMessages, signal: controller.signal })) {
                    if (conn.disposed || controller.signal.aborted)
                        return;
                    switch (follow.type) {
                        case 'snapshot': {
                            const snapshot = {
                                type: 'snapshot',
                                streamId,
                                sessionId,
                                cursor: follow.cursor,
                                header: follow.header,
                                records: follow.records,
                                hasMore: follow.hasMore,
                                projections: follow.projections,
                            };
                            sendFrame(conn, snapshot);
                            break;
                        }
                        case 'event': {
                            const eventFrame = { type: 'frame', streamId, kind: 'event', event: follow.event };
                            sendFrame(conn, eventFrame);
                            break;
                        }
                        case 'assistant-stream': {
                            const assistantFrame = {
                                type: 'frame',
                                streamId,
                                kind: 'assistant-stream',
                                frame: follow.frame,
                            };
                            // Live tokens are droppable; durable events above are not.
                            sendFrame(conn, assistantFrame, streamId);
                            break;
                        }
                        default:
                            break;
                    }
                }
            }
            catch (error) {
                if (!controller.signal.aborted && !conn.disposed) {
                    const streamError = { type: 'stream-error', streamId, error: errorInfo(error) };
                    safeSend(conn, streamError);
                }
            }
            finally {
                if (conn.streams.get(streamId) === state)
                    conn.streams.delete(streamId);
            }
        })();
    }
    /* ----------------------------------------------------------------------- */
    /* RPC / answer                                                            */
    /* ----------------------------------------------------------------------- */
    function requireSessionId(args) {
        const value = args.sessionId;
        if (typeof value !== 'string' || value.length === 0)
            throw rcError('BAD_REQUEST', 'sessionId is required');
        return value;
    }
    async function dispatchRpc(method, args) {
        switch (method) {
            case 'session/list':
                return { sessions: await dataPlane.list() };
            case 'session/projections':
                return await dataPlane.projections(requireSessionId(args));
            case 'session/page': {
                const sessionId = requireSessionId(args);
                const request = {};
                if (isFiniteNumber(args.throughSeq))
                    request.throughSeq = args.throughSeq;
                if (isFiniteNumber(args.beforeSeq))
                    request.beforeSeq = args.beforeSeq;
                if (isFiniteNumber(args.maxMessages))
                    request.maxMessages = args.maxMessages;
                return await dataPlane.page(sessionId, request);
            }
            case 'session/prompt': {
                const sessionId = requireSessionId(args);
                // The bridge validates content/mode/requestId; pass the logical prompt
                // body through, allowing either a raw string or text-part content.
                const request = { content: args.content };
                if (typeof args.requestId === 'string')
                    request.requestId = args.requestId;
                if (args.mode === 'queue' || args.mode === 'steer')
                    request.mode = args.mode;
                if (typeof args.clientTimeZone === 'string')
                    request.clientTimeZone = args.clientTimeZone;
                return await dataPlane.prompt(sessionId, request);
            }
            case 'session/cancel':
                return await dataPlane.cancel(requireSessionId(args));
            default:
                throw rcError('NOT_ALLOWED', 'endpoint is not exposed to remote clients');
        }
    }
    async function handleRpc(conn, frame) {
        const id = typeof frame.id === 'string' ? frame.id : '';
        if (id.length === 0) {
            log.debug('ws broker: ignored an rpc frame without an id');
            return;
        }
        // Per-frame authorization: a socket that was valid at upgrade/hello may be
        // revoked, expired or lease-lost by the time a mutation arrives.
        const denied = authorizationFailure(conn);
        if (denied !== null) {
            log.warn('ws broker: rpc authorization refused', denied.code);
            const rejected = { type: 'rpc-result', id, ok: false, error: denied };
            safeSend(conn, rejected);
            closePolicy(conn, RC_WS_CLOSE.deviceLost, denied.message);
            return;
        }
        const inactive = activityFailure(conn);
        if (inactive !== null) {
            log.warn('ws broker: rpc activity check refused', inactive.code);
            const rejected = { type: 'rpc-result', id, ok: false, error: inactive };
            safeSend(conn, rejected);
            closePolicy(conn, RC_WS_CLOSE.leaseLost, inactive.message);
            return;
        }
        const method = typeof frame.method === 'string' ? frame.method : '';
        if (!WS_ALLOWED_RPC.has(method)) {
            const result = {
                type: 'rpc-result',
                id,
                ok: false,
                error: { code: 'NOT_ALLOWED', message: 'endpoint is not exposed to remote clients' },
            };
            safeSend(conn, result);
            return;
        }
        const args = isRecord(frame.args) ? frame.args : {};
        try {
            const value = await dispatchRpc(method, args);
            const result = { type: 'rpc-result', id, ok: true, value };
            safeSend(conn, result);
        }
        catch (error) {
            const result = { type: 'rpc-result', id, ok: false, error: errorInfo(error) };
            safeSend(conn, result);
        }
    }
    async function handleAnswer(conn, frame) {
        // Per-frame authorization before an approval decision can ever be relayed.
        const denied = authorizationFailure(conn);
        if (denied !== null) {
            log.warn('ws broker: answer authorization refused', denied.code);
            closePolicy(conn, RC_WS_CLOSE.deviceLost, denied.message);
            return;
        }
        const inactive = activityFailure(conn);
        if (inactive !== null) {
            log.warn('ws broker: answer activity check refused', inactive.code);
            closePolicy(conn, RC_WS_CLOSE.leaseLost, inactive.message);
            return;
        }
        const eventId = typeof frame.eventId === 'string' ? frame.eventId : '';
        if (eventId.length === 0) {
            log.debug('ws broker: ignored an answer frame without an eventId');
            return;
        }
        const outcome = frame.outcome;
        let result;
        try {
            result = await approvals.answer(conn.device.id, eventId, outcome);
        }
        catch (error) {
            result = { ok: false, error: { code: 'GATEWAY', message: errorMessage(error) } };
        }
        if (result.ok) {
            // DSH settles the waterfall and pushes `cancel` to the other deliveries.
            safeSend(conn, { type: 'answer-result', eventId, ok: true });
            return;
        }
        // The phone needs an explicit negative acknowledgement: without one the card
        // would look answered while the relay rejected the decision (settled,
        // expired, revoked or a gateway failure).
        log.warn('ws broker: approval answer was not accepted', result.error?.code ?? 'GATEWAY');
        const ack = {
            type: 'answer-result',
            eventId,
            ok: false,
            error: result.error ?? { code: 'GATEWAY', message: 'approval answer was not accepted' },
        };
        safeSend(conn, ack);
    }
    /* ----------------------------------------------------------------------- */
    /* Upgrade / broadcast / shutdown                                          */
    /* ----------------------------------------------------------------------- */
    function handleUpgrade(request, socket, head, device, sessionExpiresAt) {
        if (disposed) {
            rejectUpgrade(socket, 503, 'broker is shutting down');
            return;
        }
        const header = request.headers.origin;
        const origin = Array.isArray(header) ? undefined : header;
        if (typeof origin !== 'string' || origin.trim().length === 0) {
            // The listener fence already validated the origin value; the broker only
            // refuses to upgrade a browser socket that omits it entirely.
            rejectUpgrade(socket, 403, 'origin header is required');
            return;
        }
        try {
            wss.handleUpgrade(request, socket, head, (ws) => {
                try {
                    onConnection(ws, device, sessionExpiresAt);
                }
                catch (error) {
                    log.warn('ws broker: connection setup failed', errorMessage(error));
                    try {
                        ws.terminate();
                    }
                    catch {
                        /* already gone */
                    }
                }
            });
        }
        catch (error) {
            log.warn('ws broker: handshake failed', errorMessage(error));
            try {
                socket.destroy();
            }
            catch {
                /* ignore */
            }
        }
    }
    function broadcastDrain(retryAfterMs) {
        if (disposed)
            return;
        const delay = isFiniteNumber(retryAfterMs) ? Math.max(0, Math.trunc(retryAfterMs)) : 0;
        const frame = { type: 'server-drain', retryAfterMs: delay };
        for (const conn of sockets)
            safeSend(conn, frame);
        if (drainTimer !== undefined)
            clearTimeout(drainTimer);
        drainTimer = setTimeout(() => {
            drainTimer = undefined;
            if (!disposed)
                closeAll('server draining');
        }, drainGraceMs);
    }
    function closeAll(reason, code) {
        if (drainTimer !== undefined) {
            clearTimeout(drainTimer);
            drainTimer = undefined;
        }
        const closeCode = closeCodeOr(code, 1001);
        for (const conn of [...sockets]) {
            disposeConnection(conn, reason);
            closeConnection(conn, closeCode, reason);
        }
    }
    function closeDevice(deviceId, reason, code) {
        if (typeof deviceId !== 'string' || deviceId.length === 0)
            return;
        const deviceSockets = byDevice.get(deviceId);
        if (deviceSockets === undefined)
            return;
        const detail = reason.length > 0 ? reason : 'device revoked';
        // 1008 policy violation is the legacy default; callers may pass an explicit
        // RC_WS_CLOSE code (e.g. leaseLost/idleTimeout) instead.
        const closeCode = closeCodeOr(code, RC_WS_CLOSE.policyViolation);
        for (const conn of [...deviceSockets]) {
            disposeConnection(conn, detail);
            closeConnection(conn, closeCode, detail);
        }
        byDevice.delete(deviceId);
    }
    /** Close every socket with an explicit policy code (security/idle shutdown). */
    function closeWithCode(code, reason) {
        closeAll(reason, code);
    }
    async function dispose() {
        if (disposed)
            return;
        disposed = true;
        if (drainTimer !== undefined) {
            clearTimeout(drainTimer);
            drainTimer = undefined;
        }
        const closing = [...sockets];
        for (const conn of closing) {
            disposeConnection(conn, 'broker disposed');
            closeConnection(conn, 1001, 'server shutting down');
        }
        await new Promise((resolve) => {
            let settled = false;
            const finish = () => {
                if (settled)
                    return;
                settled = true;
                resolve();
            };
            try {
                wss.close(() => finish());
            }
            catch {
                finish();
            }
            const guard = setTimeout(finish, 1_000);
            guard.unref();
        });
        for (const conn of closing) {
            try {
                conn.ws.terminate();
            }
            catch {
                /* already gone */
            }
        }
        sockets.clear();
        byDevice.clear();
    }
    return {
        handleUpgrade,
        broadcastDrain,
        closeAll,
        closeDevice,
        closeWithCode,
        get connections() {
            return sockets.size;
        },
        dispose,
    };
}
