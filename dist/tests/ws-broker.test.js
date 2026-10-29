/**
 * `/rc/ws` broker contract (M2/M3/M4 wire):
 * handshake + Origin gate, hello/ready, follow snapshot/frame ordering,
 * default-deny RPC allowlist, approval fan-out, heartbeat, connection limits,
 * drain/close semantics and assistant-stream backpressure degradation.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import WebSocket from 'ws';
import { createWsBroker } from '../src/ws-broker.js';
import { PROTOCOL_VERSION, RC_WS_CLOSE, } from '../src/shared/protocol.js';
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
const DEVICE = {
    id: 'dev-1',
    label: 'Pixel',
    platform: 'android',
    createdAt: 1,
    lastSeenAt: 2,
    refreshExpiresAt: 3,
    tokenVersion: 1,
    tokenKey: 'a'.repeat(43),
    refreshHash: 'b'.repeat(64),
};
const PLUGIN_VERSION = '9.9.9';
async function flush() {
    for (let index = 0; index < 2; index += 1)
        await new Promise((resolve) => setImmediate(resolve));
}
function makeChannel(signal) {
    const buffer = [];
    const waiters = [];
    let ended = false;
    const stop = () => {
        ended = true;
        for (const waiter of waiters.splice(0))
            waiter({ value: undefined, done: true });
    };
    signal?.addEventListener('abort', stop, { once: true });
    return {
        signal,
        iterable: {
            [Symbol.asyncIterator]() {
                return {
                    next() {
                        const next = buffer.shift();
                        if (next !== undefined)
                            return Promise.resolve({ value: next, done: false });
                        if (ended)
                            return Promise.resolve({ value: undefined, done: true });
                        return new Promise((resolve) => {
                            waiters.push(resolve);
                        });
                    },
                    return() {
                        stop();
                        return Promise.resolve({ value: undefined, done: true });
                    },
                };
            },
        },
        push(frame) {
            if (ended)
                return;
            const waiter = waiters.shift();
            if (waiter !== undefined)
                waiter({ value: frame, done: false });
            else
                buffer.push(frame);
        },
        end: stop,
        aborted: () => signal?.aborted ?? false,
    };
}
function makeDataPlane() {
    const calls = [];
    const channels = [];
    const plane = {
        calls,
        channels,
        listResult: [{ sessionId: 's1' }],
        projectionsResult: { ok: true, sessionId: 's1', kind: 'none', asOfSeq: null, values: {} },
        pageResult: { ok: true, sessionId: 's1', records: [], hasMore: false },
        promptResult: { ok: true, accepted: true },
        cancelResult: { ok: true, accepted: true },
        async list() {
            calls.push({ method: 'list' });
            if (plane.listError !== undefined)
                throw Object.assign(new Error('list failed'), plane.listError);
            return plane.listResult;
        },
        async projections(sessionId) {
            calls.push({ method: 'projections', args: sessionId });
            return plane.projectionsResult;
        },
        async page(sessionId, request) {
            calls.push({ method: 'page', args: { sessionId, request } });
            return plane.pageResult;
        },
        async prompt(sessionId, request) {
            calls.push({ method: 'prompt', args: { sessionId, request } });
            return plane.promptResult;
        },
        async cancel(sessionId) {
            calls.push({ method: 'cancel', args: sessionId });
            return plane.cancelResult;
        },
        follow(_sessionId, options) {
            const channel = makeChannel(options.signal);
            channels.push(channel);
            return channel.iterable;
        },
        desktopConnected: () => true,
        async dispose() { },
    };
    return plane;
}
function makeApprovals() {
    const sinks = [];
    const registrations = [];
    const answers = [];
    const approvals = {
        sinks,
        registrations,
        answers,
        answerResult: { ok: true },
        detached: 0,
        async registerDevice(deviceId, sink) {
            registrations.push(deviceId);
            sinks.push(sink);
            return () => {
                approvals.detached += 1;
            };
        },
        async answer(deviceId, eventId, outcome) {
            answers.push({ deviceId, eventId, outcome });
            return approvals.answerResult;
        },
        pending: () => [],
        async dispose() { },
    };
    return approvals;
}
function makeClient(ws) {
    const queue = [];
    const waiters = [];
    let closeInfo = null;
    const closePromise = new Promise((resolve) => {
        ws.on('close', (code, reason) => {
            closeInfo = { code, reason: reason.toString() };
            resolve(closeInfo);
        });
    });
    ws.on('message', (data) => {
        let frame;
        try {
            frame = JSON.parse(data.toString());
        }
        catch {
            return;
        }
        const waiter = waiters.shift();
        if (waiter !== undefined) {
            clearTimeout(waiter.timer);
            waiter.resolve(frame);
        }
        else {
            queue.push(frame);
        }
    });
    return {
        ws,
        send(frame) {
            ws.send(JSON.stringify(frame));
        },
        next(timeoutMs = 2_000) {
            const immediate = queue.shift();
            if (immediate !== undefined)
                return Promise.resolve(immediate);
            return new Promise((resolve, reject) => {
                const waiter = {
                    resolve,
                    timer: setTimeout(() => {
                        const index = waiters.indexOf(waiter);
                        if (index >= 0)
                            waiters.splice(index, 1);
                        reject(new Error(`timed out waiting for a ws frame (${timeoutMs}ms)`));
                    }, timeoutMs),
                };
                waiters.push(waiter);
            });
        },
        async expectNone(waitMs = 80) {
            await new Promise((resolve) => setTimeout(resolve, waitMs));
            const stray = queue.shift();
            assert.equal(stray, undefined, `unexpected frame: ${JSON.stringify(stray)}`);
        },
        close() {
            try {
                ws.close();
            }
            catch {
                /* ignore */
            }
        },
        get closeInfo() {
            return closePromise;
        },
    };
}
async function createHarness(options = {}) {
    const dataPlane = options.dataPlane ?? makeDataPlane();
    const approvals = options.approvals ?? makeApprovals();
    const server = createServer();
    const clock = options.now ?? Date.now;
    // Per-connection session deadline handed to the broker for the next upgrade;
    // tests set it through connect({ sessionExpiresAt }) and it resets afterwards.
    let nextSessionExpiry;
    const broker = createWsBroker({
        dataPlane,
        approvals,
        pluginVersion: PLUGIN_VERSION,
        log: silentLogger(),
        now: options.now,
        heartbeat: options.heartbeat,
        maxConnectionsPerDevice: options.maxConnectionsPerDevice,
        drainGraceMs: options.drainGraceMs,
        authorize: options.authorize,
        touchActivity: options.touchActivity,
    });
    server.on('upgrade', (request, socket, head) => {
        const expiry = nextSessionExpiry ?? clock() + 3_600_000;
        nextSessionExpiry = undefined;
        broker.handleUpgrade(request, socket, head, DEVICE, expiry);
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const origin = `http://127.0.0.1:${port}`;
    const url = `ws://127.0.0.1:${port}/rc/ws`;
    return {
        broker,
        dataPlane,
        approvals,
        url,
        origin,
        async connect(connectOptions = {}) {
            const headers = {};
            if (connectOptions.origin !== null)
                headers.Origin = connectOptions.origin ?? origin;
            if (connectOptions.sessionExpiresAt !== undefined)
                nextSessionExpiry = connectOptions.sessionExpiresAt;
            const ws = new WebSocket(url, { headers });
            const client = makeClient(ws);
            await new Promise((resolve, reject) => {
                ws.once('open', () => resolve());
                ws.once('error', reject);
            });
            client.send({ type: 'hello', protocol: connectOptions.protocol ?? PROTOCOL_VERSION });
            const ready = await client.next();
            assert.equal(ready.type, 'ready');
            return client;
        },
        async rawHandshake(headers = {}) {
            return new Promise((resolve, reject) => {
                const ws = new WebSocket(url, { headers });
                ws.once('unexpected-response', (_request, response) => {
                    let body = '';
                    response.on('data', (chunk) => {
                        body += chunk.toString();
                    });
                    response.on('end', () => {
                        resolve({ statusCode: response.statusCode ?? 0, body });
                        try {
                            ws.terminate();
                        }
                        catch {
                            /* already closed */
                        }
                    });
                });
                ws.once('error', () => {
                    /* rejected handshakes also emit error */
                });
                setTimeout(() => reject(new Error('handshake did not settle')), 2_000).unref();
            });
        },
        async stop() {
            await broker.dispose();
            await new Promise((resolve) => {
                server.closeAllConnections?.();
                server.close(() => resolve());
            });
        },
    };
}
function withHarness(t) {
    let harness;
    t.after(async () => {
        await harness?.stop();
    });
    return {
        get current() {
            assert.ok(harness, 'harness not created');
            return harness;
        },
        async create(options = {}) {
            harness = await createHarness(options);
            return harness;
        },
    };
}
/* ------------------------------------------------------------------------- */
/* Handshake / hello                                                         */
/* ------------------------------------------------------------------------- */
test('ws-broker: hello returns a ready frame with the protocol and public device view', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    // `connect()` consumed hello itself and waited for ready; send a ping to prove liveness.
    client.send({ type: 'ping', t: 7 });
    const pong = await client.next();
    assert.deepEqual(pong, { type: 'pong', t: 7 });
    client.close();
});
test('ws-broker: an upgrade without an Origin header is rejected with 403', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const response = await harness.rawHandshake({});
    assert.equal(response.statusCode, 403);
    assert.equal(response.body.includes('ORIGIN'), true);
});
test('ws-broker: the first client frame must be hello', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const ws = new WebSocket(harness.url, { headers: { Origin: harness.origin } });
    const client = makeClient(ws);
    await new Promise((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', reject);
    });
    client.send({ type: 'rpc', id: 'x', method: 'session/list', args: {} });
    const close = await client.closeInfo;
    assert.equal(close.code, 1002);
});
test('ws-broker: unsupported protocol version closes the socket', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const ws = new WebSocket(harness.url, { headers: { Origin: harness.origin } });
    const client = makeClient(ws);
    await new Promise((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', reject);
    });
    client.send({ type: 'hello', protocol: 999 });
    const close = await client.closeInfo;
    assert.equal(close.code, 1002);
});
test('ws-broker: malformed JSON and binary frames are refused', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const ws = new WebSocket(harness.url, { headers: { Origin: harness.origin } });
    const client = makeClient(ws);
    await new Promise((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', reject);
    });
    ws.send('{not json');
    assert.equal((await client.closeInfo).code, 1002);
    const binaryWs = new WebSocket(harness.url, { headers: { Origin: harness.origin } });
    const binaryClient = makeClient(binaryWs);
    await new Promise((resolve, reject) => {
        binaryWs.once('open', () => resolve());
        binaryWs.once('error', reject);
    });
    binaryWs.send(Buffer.from([1, 2, 3]));
    assert.equal((await binaryClient.closeInfo).code, 1003);
});
/* ------------------------------------------------------------------------- */
/* Follow streams                                                            */
/* ------------------------------------------------------------------------- */
test('ws-broker: sub delivers snapshot then event/assistant frames in order', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    client.send({ type: 'sub', streamId: 'stream-1', kind: 'follow', sessionId: 's1', maxMessages: 5 });
    await flush();
    assert.equal(harness.dataPlane.channels.length, 1);
    const channel = harness.dataPlane.channels[0];
    assert.notEqual(channel, undefined);
    channel?.push({
        type: 'snapshot',
        cursor: 10,
        header: { title: 'x' },
        records: [{ type: 'user/message', seq: 10, time: 1 }],
        hasMore: false,
        projections: null,
    });
    const snapshot = await client.next();
    assert.equal(snapshot.type, 'snapshot');
    assert.equal(snapshot.streamId, 'stream-1');
    assert.equal(snapshot.sessionId, 's1');
    assert.equal(snapshot.cursor, 10);
    assert.deepEqual(snapshot.records, [{ type: 'user/message', seq: 10, time: 1 }]);
    channel?.push({ type: 'event', event: { type: 'assistant/message', seq: 11, time: 2 } });
    const eventFrame = await client.next();
    assert.deepEqual(eventFrame, {
        type: 'frame',
        streamId: 'stream-1',
        kind: 'event',
        event: { type: 'assistant/message', seq: 11, time: 2 },
    });
    channel?.push({ type: 'assistant-stream', frame: { delta: 'tok' } });
    const assistantFrame = await client.next();
    assert.deepEqual(assistantFrame, {
        type: 'frame',
        streamId: 'stream-1',
        kind: 'assistant-stream',
        frame: { delta: 'tok' },
    });
    client.close();
});
test('ws-broker: sub errors are reported as stream-error frames', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    client.send({ type: 'sub', streamId: 'stream-1', kind: 'not-a-kind', sessionId: 's1' });
    const unsupported = await client.next();
    assert.equal(unsupported.type, 'stream-error');
    assert.equal(unsupported.error.code, 'NOT_ALLOWED');
    client.send({ type: 'sub', streamId: 'stream-2', kind: 'follow', sessionId: '' });
    const missing = await client.next();
    assert.equal(missing.type, 'stream-error');
    assert.equal(missing.error.code, 'BAD_REQUEST');
    client.close();
});
test('ws-broker: unsub aborts the follow stream', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    client.send({ type: 'sub', streamId: 'stream-1', kind: 'follow', sessionId: 's1' });
    await flush();
    const channel = harness.dataPlane.channels[0];
    client.send({ type: 'unsub', streamId: 'stream-1' });
    await flush();
    assert.equal(channel?.aborted(), true);
    channel?.push({ type: 'event', event: { type: 'x/y', seq: 1, time: 1 } });
    await client.expectNone();
    client.close();
});
/* ------------------------------------------------------------------------- */
/* RPC allowlist                                                             */
/* ------------------------------------------------------------------------- */
test('ws-broker: allowlisted rpc methods are dispatched to the data plane', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    client.send({ type: 'rpc', id: 'r1', method: 'session/list', args: {} });
    const listResult = await client.next();
    assert.equal(listResult.type, 'rpc-result');
    assert.equal(listResult.id, 'r1');
    assert.equal(listResult.ok, true);
    assert.deepEqual(listResult.value, { sessions: [{ sessionId: 's1' }] });
    client.send({ type: 'rpc', id: 'r2', method: 'session/page', args: { sessionId: 's1', throughSeq: 5 } });
    const pageResult = await client.next();
    assert.equal(pageResult.ok, true);
    assert.deepEqual(harness.dataPlane.calls.at(-1), {
        method: 'page',
        args: { sessionId: 's1', request: { throughSeq: 5 } },
    });
    client.send({ type: 'rpc', id: 'r3', method: 'session/cancel', args: { sessionId: 's1' } });
    assert.equal((await client.next()).ok, true);
    client.close();
});
test('ws-broker: non-allowlisted rpc methods are rejected without touching the data plane', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    const callsBefore = harness.dataPlane.calls.length;
    for (const method of ['terminal/exec', 'workspace/read', 'settings/read', 'pluginManager/install', 'session/create']) {
        client.send({ type: 'rpc', id: `id-${method}`, method, args: {} });
        const result = await client.next();
        assert.equal(result.type, 'rpc-result');
        assert.equal(result.ok, false);
        assert.equal(result.error.code, 'NOT_ALLOWED');
    }
    assert.equal(harness.dataPlane.calls.length, callsBefore);
    client.close();
});
test('ws-broker: data-plane failures map into an rpc-result error', async (t) => {
    const scope = withHarness(t);
    const dataPlane = makeDataPlane();
    dataPlane.listError = { code: 'NOT_ALLOWED' };
    const harness = await scope.create({ dataPlane });
    const client = await harness.connect();
    client.send({ type: 'rpc', id: 'r1', method: 'session/list', args: {} });
    const result = await client.next();
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'NOT_ALLOWED');
    client.close();
});
/* ------------------------------------------------------------------------- */
/* Approvals                                                                 */
/* ------------------------------------------------------------------------- */
test('ws-broker: approval sink frames are forwarded and answers are acknowledged', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    await flush();
    assert.deepEqual(harness.approvals.registrations, [DEVICE.id]);
    const sink = harness.approvals.sinks[0];
    assert.notEqual(sink, undefined);
    const view = {
        eventId: 'evt-1',
        kind: 'approval',
        request: { toolName: 'bash', reason: null, displayReason: null, callId: null },
        agentId: 'agent-1',
        answerable: true,
        expiresInMs: 300_000,
    };
    sink?.onApproval(view);
    assert.deepEqual(await client.next(), {
        type: 'approval',
        eventId: 'evt-1',
        kind: 'approval',
        request: view.request,
        agentId: 'agent-1',
        answerable: true,
        expiresInMs: 300_000,
    });
    // The relay accepted the decision: the phone gets a positive acknowledgement.
    harness.approvals.answerResult = { ok: true };
    client.send({ type: 'answer', eventId: 'evt-1', outcome: { kind: 'result', value: 'allowed-once' } });
    assert.deepEqual(await client.next(), { type: 'answer-result', eventId: 'evt-1', ok: true });
    assert.deepEqual(harness.approvals.answers, [
        { deviceId: DEVICE.id, eventId: 'evt-1', outcome: { kind: 'result', value: 'allowed-once' } },
    ]);
    // A rejected answer must never look successful: the phone receives a negative
    // acknowledgement carrying the relay error, so it can reopen the card.
    harness.approvals.answerResult = { ok: false, error: { code: 'GATEWAY', message: 'settled' } };
    client.send({ type: 'answer', eventId: 'evt-2', outcome: { kind: 'result', value: 'rejected' } });
    assert.deepEqual(await client.next(), {
        type: 'answer-result',
        eventId: 'evt-2',
        ok: false,
        error: { code: 'GATEWAY', message: 'settled' },
    });
    sink?.onCancel('evt-3', 'answered-elsewhere');
    assert.deepEqual(await client.next(), { type: 'approval-cancel', eventId: 'evt-3', reason: 'answered-elsewhere' });
    client.close();
});
/* ------------------------------------------------------------------------- */
/* Heartbeat / limits / shutdown                                             */
/* ------------------------------------------------------------------------- */
test('ws-broker: a missing pong terminates the connection after the timeout', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({ heartbeat: { pingIntervalMs: 20, pongTimeoutMs: 30 } });
    const client = await harness.connect();
    const ping = await client.next();
    assert.equal(ping.type, 'ping');
    // Deliberately do not answer the application-level ping.
    const close = await client.closeInfo;
    assert.equal(close.code, 1006);
    await flush();
    assert.equal(harness.broker.connections, 0);
});
test('ws-broker: answering ping keeps the connection alive', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({ heartbeat: { pingIntervalMs: 20, pongTimeoutMs: 30 } });
    const client = await harness.connect();
    for (let index = 0; index < 3; index += 1) {
        const frame = await client.next();
        assert.equal(frame.type, 'ping');
        client.send({ type: 'pong' });
        await new Promise((resolve) => setTimeout(resolve, 12));
    }
    client.send({ type: 'ping', t: 3 });
    await waitForPong(client, 3);
    client.close();
});
async function waitForPong(client, t) {
    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline) {
        const frame = await client.next(deadline - Date.now());
        if (frame.type === 'ping') {
            client.send({ type: 'pong' });
            continue;
        }
        assert.equal(frame.type, 'pong');
        if (frame.t === t)
            return;
    }
    assert.fail('pong was not received before the deadline');
}
test('ws-broker: per-device connection limit closes extra sockets with 1013', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({ maxConnectionsPerDevice: 1 });
    await harness.connect();
    assert.equal(harness.broker.connections, 1);
    const second = new WebSocket(harness.url, { headers: { Origin: harness.origin } });
    const client = makeClient(second);
    await new Promise((resolve, reject) => {
        second.once('open', () => resolve());
        second.once('error', reject);
    });
    assert.equal((await client.closeInfo).code, 1013);
    assert.equal(harness.broker.connections, 1);
});
test('ws-broker: broadcastDrain sends server-drain then closes sockets', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({ drainGraceMs: 30 });
    const client = await harness.connect();
    harness.broker.broadcastDrain(1_000);
    const drain = await client.next();
    assert.deepEqual(drain, { type: 'server-drain', retryAfterMs: 1_000 });
    assert.equal((await client.closeInfo).code, 1001);
});
test('ws-broker: closeDevice closes only that device with policy code 1008', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    harness.broker.closeDevice(DEVICE.id, 'revoked');
    assert.equal((await client.closeInfo).code, 1008);
    await flush();
    assert.equal(harness.broker.connections, 0);
});
test('ws-broker: dispose closes sockets and refuses new upgrades', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    await harness.broker.dispose();
    assert.equal((await client.closeInfo).code, 1001);
    assert.equal(harness.broker.connections, 0);
    const response = await harness.rawHandshake({ Origin: harness.origin });
    assert.equal(response.statusCode, 503);
});
/* ------------------------------------------------------------------------- */
/* Backpressure                                                              */
/* ------------------------------------------------------------------------- */
test('ws-broker: assistant-stream frames are dropped and reported as degraded under backpressure', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    client.send({ type: 'sub', streamId: 'stream-bp', kind: 'follow', sessionId: 's1' });
    await flush();
    const channel = harness.dataPlane.channels[0];
    assert.notEqual(channel, undefined);
    channel?.push({ type: 'snapshot', cursor: 0, header: null, records: [], hasMore: false, projections: null });
    await client.next();
    // Stop reading on the client so the server's send buffer grows, and stream
    // enough assistant tokens to cross the 512 KiB droppable budget.
    const rawSocket = client.ws._socket;
    rawSocket.pause();
    const chunk = 'x'.repeat(64 * 1024);
    for (let index = 0; index < 80; index += 1) {
        channel?.push({ type: 'assistant-stream', frame: { index, chunk } });
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
    // Durable events must survive the pressure.
    channel?.push({ type: 'event', event: { type: 'durable/event', seq: 1, time: 1 } });
    await new Promise((resolve) => setTimeout(resolve, 100));
    rawSocket.resume();
    const frames = [];
    try {
        for (;;) {
            frames.push(await client.next(500));
        }
    }
    catch {
        /* timeout = drained */
    }
    const degraded = frames.filter((frame) => frame.type === 'degraded');
    const durable = frames.filter((frame) => frame.type === 'frame' && frame.kind === 'event');
    const assistant = frames.filter((frame) => frame.type === 'frame' && frame.kind === 'assistant-stream');
    assert.ok(degraded.length > 0, 'a degraded frame must be sent when assistant-stream frames are dropped');
    assert.ok(degraded[0]?.droppedAssistantStreamFrames > 0, 'degraded frame must report the dropped frame count');
    assert.equal(durable.length, 1, 'durable events must never be dropped');
    assert.ok(assistant.length < 80, 'some assistant-stream frames must have been dropped');
    client.close();
});
/* ------------------------------------------------------------------------- */
/* Post-upgrade authorization & activity (per-frame aut / close codes)       */
/* ------------------------------------------------------------------------- */
/** Open a socket without completing hello (used for hello-failure tests). */
async function openSocket(harness) {
    const ws = new WebSocket(harness.url, { headers: { Origin: harness.origin } });
    const client = makeClient(ws);
    await new Promise((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', reject);
    });
    return client;
}
/** Read the next non-heartbeat frame, answering server pings so the socket stays alive. */
async function nextServerFrame(client) {
    for (;;) {
        const frame = await client.next(2_000);
        if (frame.type === 'ping') {
            client.send({ type: 'pong' });
            continue;
        }
        return frame;
    }
}
test('ws-broker: authorize runs at hello and before every rpc and answer frame', async (t) => {
    const scope = withHarness(t);
    const calls = [];
    const harness = await scope.create({
        authorize: (deviceId) => {
            calls.push(deviceId);
            return { ok: true };
        },
    });
    const client = await harness.connect();
    assert.deepEqual(calls, [DEVICE.id], 'hello must be authorized');
    client.send({ type: 'rpc', id: 'r1', method: 'session/list', args: {} });
    const result = await nextServerFrame(client);
    assert.equal(result.type, 'rpc-result');
    assert.equal(result.ok, true);
    assert.deepEqual(calls, [DEVICE.id, DEVICE.id], 'every rpc frame must be authorized again');
    client.send({ type: 'answer', eventId: 'evt-1', outcome: { kind: 'result', value: 'allowed-once' } });
    await flush();
    assert.deepEqual(calls, [DEVICE.id, DEVICE.id, DEVICE.id], 'every answer frame must be authorized again');
    assert.equal(harness.approvals.answers.length, 1);
    client.close();
});
test('ws-broker: a failed authorize at hello closes with deviceLost and never sends ready', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({
        authorize: () => ({ ok: false, code: 'DEVICE_REVOKED', message: 'device was revoked' }),
    });
    const client = await openSocket(harness);
    client.send({ type: 'hello', protocol: PROTOCOL_VERSION });
    const close = await client.closeInfo;
    assert.equal(close.code, RC_WS_CLOSE.deviceLost);
    assert.equal(close.reason, 'device was revoked');
    await client.expectNone(50);
    assert.deepEqual(harness.approvals.registrations, [], 'approval relay must not attach for a rejected socket');
    assert.equal(harness.broker.connections, 0);
});
test('ws-broker: a failed per-frame authorize blocks rpc dispatch and closes with deviceLost', async (t) => {
    const scope = withHarness(t);
    let authorized = true;
    const harness = await scope.create({
        authorize: () => authorized
            ? { ok: true }
            : { ok: false, code: 'DEVICE_REVOKED', message: 'device was revoked' },
    });
    const client = await harness.connect();
    const callsBefore = harness.dataPlane.calls.length;
    authorized = false;
    client.send({ type: 'rpc', id: 'r-blocked', method: 'session/list', args: {} });
    const result = await client.next();
    assert.equal(result.type, 'rpc-result');
    assert.equal(result.id, 'r-blocked');
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'DEVICE_REVOKED');
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.deviceLost);
    assert.equal(harness.dataPlane.calls.length, callsBefore, 'unauthorized rpc must never be dispatched');
});
test('ws-broker: a failed per-frame authorize blocks approval answers and closes with deviceLost', async (t) => {
    const scope = withHarness(t);
    let authorized = true;
    const harness = await scope.create({
        authorize: () => authorized ? { ok: true } : { ok: false, code: 'DEVICE_REVOKED', message: 'revoked' },
    });
    const client = await harness.connect();
    authorized = false;
    client.send({ type: 'answer', eventId: 'evt-blocked', outcome: { kind: 'next' } });
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.deviceLost);
    assert.deepEqual(harness.approvals.answers, [], 'unauthorized answer must never be forwarded');
});
test('ws-broker: a failed per-frame authorize blocks follow subscriptions and heartbeats', async (t) => {
    const scope = withHarness(t);
    let authorized = true;
    const harness = await scope.create({
        authorize: () => authorized
            ? { ok: true }
            : { ok: false, code: 'TOKEN_EXPIRED', message: 'access token expired' },
    });
    const client = await harness.connect();
    const callsBefore = harness.dataPlane.calls.length;
    authorized = false;
    client.send({ type: 'sub', streamId: 'stream-blocked', kind: 'follow', sessionId: 's1' });
    const close = await client.closeInfo;
    assert.equal(close.code, RC_WS_CLOSE.deviceLost);
    assert.equal(close.reason, 'access token expired');
    assert.equal(harness.dataPlane.calls.length, callsBefore, 'an unauthorized subscription must never reach the data plane');
    assert.deepEqual(harness.dataPlane.channels, [], 'no follow channel may be opened for an expired session');
});
test('ws-broker: a newer connection cannot extend an older socket session deadline', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({});
    // Same device, same valid access token: the first socket only has a short
    // deadline, the second one has a long one. The second connection must not
    // extend the first socket's session.
    const shortLived = await harness.connect({ sessionExpiresAt: Date.now() + 120 });
    const longLived = await harness.connect({ sessionExpiresAt: Date.now() + 60_000 });
    await new Promise((resolve) => setTimeout(resolve, 200));
    shortLived.send({ type: 'ping', t: 1 });
    const close = await shortLived.closeInfo;
    assert.equal(close.code, RC_WS_CLOSE.deviceLost);
    assert.match(close.reason, /expired/i, 'the expired socket is closed with the token-expired reason');
    // The newer socket keeps working with its own later deadline.
    longLived.send({ type: 'ping', t: 2 });
    const pong = await longLived.next();
    assert.equal(pong.type, 'pong');
    assert.equal(harness.broker.connections, 1, 'only the recorded-expired socket was closed');
    longLived.close();
});
test('ws-broker: an authorize exception fails closed with deviceLost', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create({
        authorize: () => {
            throw new Error('authorize exploded');
        },
    });
    const client = await openSocket(harness);
    client.send({ type: 'hello', protocol: PROTOCOL_VERSION });
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.deviceLost);
});
test('ws-broker: touchActivity renews authenticated client frames, never server pings', async (t) => {
    const scope = withHarness(t);
    const touches = [];
    const harness = await scope.create({
        heartbeat: { pingIntervalMs: 25, pongTimeoutMs: 250 },
        touchActivity: (deviceId) => {
            touches.push(deviceId);
            return true;
        },
    });
    const client = await harness.connect();
    assert.deepEqual(touches, [DEVICE.id], 'hello is one authenticated client frame');
    // A server ping and the client pong are transport heartbeat only: no renewal.
    const serverPing = await client.next();
    assert.equal(serverPing.type, 'ping');
    client.send({ type: 'pong' });
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.deepEqual(touches, [DEVICE.id], 'server ping/pong must not renew the idle clock');
    // The application-level ping IS verified client activity.
    client.send({ type: 'ping', t: 11 });
    const pong = await nextServerFrame(client);
    assert.deepEqual(pong, { type: 'pong', t: 11 });
    assert.deepEqual(touches, [DEVICE.id, DEVICE.id]);
    client.send({ type: 'sub', streamId: 'stream-touch', kind: 'follow', sessionId: 's1' });
    await flush();
    assert.equal(touches.length, 3, 'sub renews activity');
    client.send({ type: 'unsub', streamId: 'stream-touch' });
    await flush();
    assert.equal(touches.length, 4, 'unsub renews activity');
    client.send({ type: 'rpc', id: 'r-touch', method: 'session/list', args: {} });
    assert.equal((await nextServerFrame(client)).type, 'rpc-result');
    assert.equal(touches.length, 5, 'rpc renews activity');
    client.send({ type: 'answer', eventId: 'evt-touch', outcome: { kind: 'next' } });
    await flush();
    assert.equal(touches.length, 6, 'answer renews activity');
    client.close();
});
test('ws-broker: touchActivity returning false closes with leaseLost and blocks the frame', async (t) => {
    const scope = withHarness(t);
    let active = true;
    const harness = await scope.create({
        touchActivity: () => active,
    });
    const client = await harness.connect();
    active = false;
    client.send({ type: 'ping', t: 5 });
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.leaseLost);
    await client.expectNone(50);
    await flush();
    assert.equal(harness.broker.connections, 0);
});
test('ws-broker: lease loss during an rpc is reported then closed with leaseLost', async (t) => {
    const scope = withHarness(t);
    let active = true;
    const harness = await scope.create({
        touchActivity: () => active,
    });
    const client = await harness.connect();
    const callsBefore = harness.dataPlane.calls.length;
    active = false;
    client.send({ type: 'rpc', id: 'r-lease', method: 'session/list', args: {} });
    const result = await client.next();
    assert.equal(result.type, 'rpc-result');
    assert.equal(result.ok, false);
    assert.equal(result.error.code, 'DEVICE_LOCKED');
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.leaseLost);
    assert.equal(harness.dataPlane.calls.length, callsBefore);
});
test('ws-broker: closeAll accepts an explicit security close code', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    harness.broker.closeAll('remote access is security-closed', RC_WS_CLOSE.securityClosed);
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.securityClosed);
});
test('ws-broker: closeDevice accepts an explicit idle-timeout close code', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    harness.broker.closeDevice(DEVICE.id, 'lease idle timeout', RC_WS_CLOSE.idleTimeout);
    assert.equal((await client.closeInfo).code, RC_WS_CLOSE.idleTimeout);
});
test('ws-broker: closeWithCode closes every socket with the requested code', async (t) => {
    const scope = withHarness(t);
    const harness = await scope.create();
    const client = await harness.connect();
    harness.broker.closeWithCode(RC_WS_CLOSE.securityClosed, 'security shutdown');
    const close = await client.closeInfo;
    assert.equal(close.code, RC_WS_CLOSE.securityClosed);
    await flush();
    assert.equal(harness.broker.connections, 0);
});
