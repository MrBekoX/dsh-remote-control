/**
 * Session data plane (M2 read path + M3 mutations):
 * default-deny allowlist, DSH â†’ RC normalization for list/page/projections,
 * prompt/cancel gating on `remoteMutations`, and follow-stream normalization.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { Config } from '../src/config.js';
import { createSessionBridge } from '../src/session-bridge.js';
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
function makeConfig(overrides = {}) {
    return Config(overrides);
}
function makeAudit() {
    const entries = [];
    return {
        entries,
        push: (entry) => {
            entries.push(entry);
        },
        snapshot: () => entries.map((entry) => ({ ...entry, time: 0 })),
        get size() {
            return entries.length;
        },
        dispose: () => undefined,
    };
}
function makeGateway(options = {}) {
    const invocations = [];
    const gateway = {
        invocations,
        async invoke(method, args) {
            invocations.push({ method, args });
            if (options.invoke === undefined)
                throw new Error(`unexpected invoke ${method}`);
            return (await options.invoke(method, args));
        },
        async stream(method, args) {
            invocations.push({ method, args });
            if (options.stream === undefined)
                throw new Error(`unexpected stream ${method}`);
            return (await options.stream(method, args));
        },
        async openApprovalEvents() {
            throw new Error('approval events are not used by the session bridge');
        },
        hasLiveClient: () => options.liveClient === true,
        dispose: async () => undefined,
    };
    return gateway;
}
async function collect(iterable) {
    const items = [];
    for await (const item of iterable)
        items.push(item);
    return items;
}
/* ------------------------------------------------------------------------- */
/* Public surface                                                            */
/* ------------------------------------------------------------------------- */
test('session-bridge: exports exactly the allowlisted data-plane surface', () => {
    const bridge = createSessionBridge({
        gateway: makeGateway(),
        config: makeConfig(),
        log: silentLogger(),
        audit: makeAudit(),
    });
    assert.deepEqual(Object.keys(bridge).sort(), [
        'cancel',
        'createSession',
        'desktopConnected',
        'dispose',
        'follow',
        'list',
        'page',
        'projections',
        'prompt',
        'readAttachment',
        'uploadFile',
        'workspaces',
    ]);
    assert.equal('invoke' in bridge, false, 'no generic gateway escape hatch may be exposed');
});
test('session-bridge: desktopConnected delegates to gateway.hasLiveClient', () => {
    const connected = createSessionBridge({
        gateway: makeGateway({ liveClient: true }),
        config: makeConfig(),
        log: silentLogger(),
        audit: makeAudit(),
    });
    const offline = createSessionBridge({
        gateway: makeGateway({ liveClient: false }),
        config: makeConfig(),
        log: silentLogger(),
        audit: makeAudit(),
    });
    assert.equal(connected.desktopConnected(), true);
    assert.equal(offline.desktopConnected(), false);
});
/* ------------------------------------------------------------------------- */
/* session/list                                                              */
/* ------------------------------------------------------------------------- */
test('session-bridge: list() normalizes DSH summaries and drops malformed rows', async () => {
    const gateway = makeGateway({
        invoke: () => ({
            items: [
                {
                    sessionId: 's1',
                    updatedAt: 1234,
                    running: true,
                    agentAvailable: true,
                    blank: false,
                    cwd: '/work',
                    projections: { values: { title: 'Fix the parser' } },
                    formatStatus: 'waiting',
                },
                { sessionId: 's2' },
                { sessionId: '', running: true },
                { notASession: true },
                'garbage',
            ],
        }),
    });
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    const sessions = await bridge.list();
    assert.equal(sessions.length, 2);
    assert.deepEqual(sessions[0], {
        sessionId: 's1',
        updatedAt: 1234,
        running: true,
        agentAvailable: true,
        blank: false,
        cwd: '/work',
        title: 'Fix the parser',
        parentSessionId: null,
        status: 'waiting',
    });
    assert.deepEqual(sessions[1], {
        sessionId: 's2',
        updatedAt: 0,
        running: false,
        agentAvailable: false,
        blank: false,
        cwd: null,
        title: null,
        parentSessionId: null,
        status: 'idle',
    });
    assert.deepEqual(gateway.invocations, [{ method: 'list', args: {} }]);
});
test('session-bridge: list() rejects an unexpected gateway shape', async () => {
    const bridge = createSessionBridge({
        gateway: makeGateway({ invoke: () => ({ nope: true }) }),
        config: makeConfig(),
        log: silentLogger(),
        audit: makeAudit(),
    });
    await assert.rejects(bridge.list(), (error) => error.code === 'GATEWAY');
});
test('session-bridge: gateway failures map onto RC error codes', async () => {
    const cases = [
        ['gateway/input-invalid', 'BAD_REQUEST'],
        ['gateway/arguments-invalid', 'BAD_REQUEST'],
        ['remote-access/denied', 'NOT_ALLOWED'],
        ['gateway/interactions-forbidden', 'NOT_ALLOWED'],
        ['session/foo-not-found', 'NOT_FOUND'],
        ['gateway/cancelled', 'GATEWAY'],
        ['gateway/unknown', 'GATEWAY'],
    ];
    for (const [gatewayCode, expected] of cases) {
        const bridge = createSessionBridge({
            gateway: makeGateway({
                invoke: () => {
                    throw Object.assign(new Error('gateway failure'), { code: gatewayCode });
                },
            }),
            config: makeConfig(),
            log: silentLogger(),
            audit: makeAudit(),
        });
        await assert.rejects(bridge.list(), (error) => error.code === expected, `code ${gatewayCode} must map to ${expected}`);
    }
});
/* ------------------------------------------------------------------------- */
/* projections & page                                                        */
/* ------------------------------------------------------------------------- */
test('session-bridge: projections() normalizes sequenced/migration/none', async () => {
    const responses = [
        { kind: 'sequenced', asOfSeq: 42, values: { title: 'x' } },
        { kind: 'migration-required', values: { title: 'y' } },
        null,
        { values: { title: 'z' } },
    ];
    const bridge = createSessionBridge({
        gateway: makeGateway({ invoke: () => responses.shift() }),
        config: makeConfig(),
        log: silentLogger(),
        audit: makeAudit(),
    });
    assert.deepEqual(await bridge.projections('s1'), {
        ok: true,
        sessionId: 's1',
        kind: 'sequenced',
        asOfSeq: 42,
        values: { title: 'x' },
    });
    assert.deepEqual(await bridge.projections('s1'), {
        ok: true,
        sessionId: 's1',
        kind: 'migration-required',
        asOfSeq: null,
        values: { title: 'y' },
    });
    assert.deepEqual(await bridge.projections('s1'), {
        ok: true,
        sessionId: 's1',
        kind: 'none',
        asOfSeq: null,
        values: {},
    });
    assert.deepEqual(await bridge.projections('s1'), {
        ok: true,
        sessionId: 's1',
        kind: 'none',
        asOfSeq: null,
        values: {},
    });
});
test('session-bridge: page() requires throughSeq and normalizes records', async () => {
    const gateway = makeGateway({
        invoke: () => ({
            records: [
                { type: 'event', event: { type: 'user/message', seq: 1, time: 10, data: { text: 'hi' } } },
                { type: 'assistant/message', seq: 2, time: 11, ignorable: true, sourceEventSeqs: [1] },
                { type: 'incomplete' },
                { nope: true },
            ],
            hasMore: true,
        }),
    });
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    await assert.rejects(bridge.page('s1', { maxMessages: 10 }), (error) => error.code === 'BAD_REQUEST', 'page without throughSeq must be rejected before the gateway');
    assert.equal(gateway.invocations.length, 0);
    const page = await bridge.page('s1', { throughSeq: 99, beforeSeq: 50, maxMessages: 999 });
    assert.equal(page.ok, true);
    assert.equal(page.sessionId, 's1');
    assert.equal(page.hasMore, true);
    assert.deepEqual(page.records, [
        { type: 'user/message', seq: 1, time: 10, data: { text: 'hi' } },
        { type: 'assistant/message', seq: 2, time: 11, ignorable: true, sourceEventSeqs: [1] },
    ]);
    assert.deepEqual(gateway.invocations[0], {
        method: 'page',
        args: {
            address: { kind: 'session', sessionId: 's1' },
            throughSeq: 99,
            maxMessages: 200,
            beforeSeq: 50,
        },
    });
});
test('session-bridge: page() applies the default maxMessages', async () => {
    const gateway = makeGateway({ invoke: () => ({ records: [], hasMore: false }) });
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    await bridge.page('s1', { throughSeq: 5 });
    assert.equal((gateway.invocations[0]?.args).maxMessages, 40);
});
/* ------------------------------------------------------------------------- */
/* prompt / cancel gating                                                    */
/* ------------------------------------------------------------------------- */
test('session-bridge: remoteMutations=false makes prompt/cancel NOT_ALLOWED', async () => {
    const gateway = makeGateway();
    const bridge = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: false }), log: silentLogger(), audit: makeAudit() });
    await assert.rejects(bridge.prompt('s1', { content: [{ type: 'text', text: 'hello' }] }), (error) => error.code === 'NOT_ALLOWED');
    await assert.rejects(bridge.cancel('s1'), (error) => error.code === 'NOT_ALLOWED');
    assert.equal(gateway.invocations.length, 0, 'read-only mode must never reach the gateway for mutations');
});
test('session-bridge: prompt() normalizes content/mode/requestId and audits sanely', async () => {
    const gateway = makeGateway({ invoke: () => ({ accepted: true }) });
    const audit = makeAudit();
    const bridge = createSessionBridge({
        gateway,
        config: makeConfig({ remoteMutations: true }),
        log: silentLogger(),
        audit,
    });
    const result = await bridge.prompt('s1', {
        requestId: 'req-1',
        mode: 'steer',
        clientTimeZone: 'Europe/Istanbul',
        content: [{ type: 'text', text: 'hello' }],
    });
    assert.deepEqual(result, { ok: true, accepted: true });
    const invocation = gateway.invocations[0];
    assert.equal(invocation?.method, 'prompt');
    const args = invocation?.args;
    assert.equal(args.requestId, 'req-1');
    assert.equal(args.sessionId, 's1');
    assert.equal(args.mode, 'steer');
    assert.equal(args.clientTimeZone, 'Europe/Istanbul');
    assert.deepEqual(args.content, [{ type: 'text', text: 'hello' }]);
    assert.equal(audit.entries.length, 1);
    assert.match(audit.entries[0]?.detail ?? '', /^session\/prompt:steer$/);
});
test('session-bridge: prompt() defaults mode=queue and mints a requestId when absent', async () => {
    const gateway = makeGateway({ invoke: () => ({ accepted: true }) });
    const bridge = createSessionBridge({
        gateway,
        config: makeConfig({ remoteMutations: true }),
        log: silentLogger(),
        audit: makeAudit(),
    });
    await bridge.prompt('s1', { content: [{ type: 'text', text: 'plain text prompt' }] });
    const args = gateway.invocations[0]?.args;
    assert.equal(args.mode, 'queue');
    assert.match(String(args.requestId), /^[0-9a-f-]{36}$/);
    assert.deepEqual(args.content, [{ type: 'text', text: 'plain text prompt' }]);
});
test('session-bridge: prompt() rejects empty, non-text and oversized content', async () => {
    const gateway = makeGateway({ invoke: () => ({ accepted: true }) });
    const bridge = createSessionBridge({
        gateway,
        config: makeConfig({ remoteMutations: true }),
        log: silentLogger(),
        audit: makeAudit(),
    });
    const badInputs = [
        { content: [] },
        { content: [{ type: 'text', text: '   ' }] },
        { content: [{ type: 'image', data: 'x' }] },
        { content: [{ type: 'text', text: 'x'.repeat(32_001) }] },
        { content: 'ok', mode: 'bogus' },
        { content: 'ok', clientTimeZone: 'x'.repeat(65) },
        {},
    ];
    for (const input of badInputs) {
        await assert.rejects(bridge.prompt('s1', input), (error) => error.code === 'BAD_REQUEST', `must reject ${JSON.stringify(input).slice(0, 80)}`);
    }
    assert.equal(gateway.invocations.length, 0);
});
test('session-bridge: cancel() normalizes the gateway acknowledgement', async () => {
    const gateway = makeGateway({ invoke: () => ({ accepted: true }) });
    const audit = makeAudit();
    const bridge = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: true }), log: silentLogger(), audit });
    assert.deepEqual(await bridge.cancel('s1'), { ok: true, accepted: true });
    assert.deepEqual(gateway.invocations[0], { method: 'cancel', args: { sessionId: 's1' } });
    assert.equal(audit.entries[0]?.detail, 'session/cancel');
});
test('session-bridge: invalid session ids are rejected before the gateway', async () => {
    const gateway = makeGateway();
    const bridge = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: true }), log: silentLogger(), audit: makeAudit() });
    for (const sessionId of ['', '   ', 'x'.repeat(201)]) {
        await assert.rejects(bridge.cancel(sessionId), (error) => error.code === 'BAD_REQUEST');
    }
    assert.equal(gateway.invocations.length, 0);
});
/* ------------------------------------------------------------------------- */
/* follow stream                                                             */
/* ------------------------------------------------------------------------- */
test('session-bridge: follow() normalizes snapshot/event/assistant-stream frames', async () => {
    const rawFrames = [
        {
            type: 'snapshot',
            cursor: 12,
            header: { title: 'x' },
            records: [
                { type: 'event', event: { type: 'user/message', seq: 11, time: 1 } },
                { type: 'assistant/message', seq: 12, time: 2, data: { text: 'hi' } },
                { bogus: true },
            ],
            hasMore: true,
            projections: { asOfSeq: 12, values: { title: 'x' } },
        },
        { type: 'event', event: { type: 'assistant/message', seq: 13, time: 3 } },
        { type: 'assistant-stream', frame: { delta: 'partial' } },
        { type: 'unknown-frame' },
        null,
    ];
    const gateway = makeGateway({
        stream: () => ({
            async *[Symbol.asyncIterator]() {
                for (const frame of rawFrames)
                    yield frame;
            },
        }),
    });
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    const controller = new AbortController();
    const frames = await collect(bridge.follow('s1', { maxMessages: 999, signal: controller.signal }));
    assert.deepEqual(frames.map((frame) => frame.type), ['snapshot', 'event', 'assistant-stream']);
    assert.deepEqual(frames[0], {
        type: 'snapshot',
        cursor: 12,
        header: { title: 'x' },
        records: [
            { type: 'user/message', seq: 11, time: 1 },
            { type: 'assistant/message', seq: 12, time: 2, data: { text: 'hi' } },
        ],
        hasMore: true,
        projections: { asOfSeq: 12, values: { title: 'x' } },
    });
    const args = gateway.invocations[0]?.args;
    assert.equal(gateway.invocations[0]?.method, 'follow');
    assert.deepEqual(args.address, { kind: 'session', sessionId: 's1' });
    assert.equal(args.assistantStream, true);
    assert.equal(args.maxMessages, 200);
    const turnWindow = args.turnWindow;
    assert.ok(turnWindow.minMessages <= 200, 'turnWindow.minMessages must not exceed maxMessages');
});
test('session-bridge: follow() defaults the message window and honours abort', async () => {
    let streamCalls = 0;
    const gateway = makeGateway({
        stream: () => {
            streamCalls += 1;
            return {
                async *[Symbol.asyncIterator]() {
                    yield { type: 'event', event: { type: 'x/y', seq: 1, time: 1 } };
                },
            };
        },
    });
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    const controller = new AbortController();
    const frames = await collect(bridge.follow('s1', { signal: controller.signal }));
    assert.equal(frames.length, 1);
    assert.equal((gateway.invocations[0]?.args).maxMessages, 80);
    const aborted = new AbortController();
    aborted.abort();
    const none = await collect(bridge.follow('s1', { signal: aborted.signal }));
    assert.deepEqual(none, []);
    assert.equal(streamCalls, 1, 'an already-aborted follow must not open a gateway stream');
});
test('session-bridge: follow() maps gateway stream failures', async () => {
    const bridge = createSessionBridge({
        gateway: makeGateway({
            stream: () => {
                throw Object.assign(new Error('denied'), { code: 'remote-access/denied' });
            },
        }),
        config: makeConfig(),
        log: silentLogger(),
        audit: makeAudit(),
    });
    await assert.rejects(collect(bridge.follow('s1', { signal: new AbortController().signal })), (error) => error.code === 'NOT_ALLOWED');
});
/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */
test('session-bridge: dispose() disables every method', async () => {
    const gateway = makeGateway({ invoke: () => ({ accepted: true }), liveClient: true });
    const bridge = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: true }), log: silentLogger(), audit: makeAudit() });
    await bridge.dispose();
    await assert.rejects(bridge.list(), (error) => error.code === 'INTERNAL');
    await assert.rejects(bridge.cancel('s1'), (error) => error.code === 'INTERNAL');
});
/* ------------------------------------------------------------------------- */
/* Workspaces / new session / attachments (round-6 features)                 */
/* ------------------------------------------------------------------------- */
test('session-bridge: prompt() forwards image and file parts unchanged', async () => {
    const image = Buffer.from('PNG-bytes').toString('base64');
    const gateway = makeGateway({ invoke: () => ({ accepted: true }) });
    const audit = makeAudit();
    const bridge = createSessionBridge({
        gateway,
        config: makeConfig({ remoteMutations: true }),
        log: silentLogger(),
        audit,
    });
    const result = await bridge.prompt('s1', {
        content: [
            { type: 'text', text: 'look at this' },
            { type: 'image', mediaType: 'image/png', data: image, name: 'screen.png' },
            { type: 'file', receiptId: 'receipt-1' },
        ],
    });
    assert.deepEqual(result, { ok: true, accepted: true });
    const args = gateway.invocations[0]?.args;
    assert.deepEqual(args.content, [
        { type: 'text', text: 'look at this' },
        { type: 'image', mediaType: 'image/png', data: image, name: 'screen.png' },
        { type: 'file', receiptId: 'receipt-1' },
    ]);
});
test('session-bridge: prompt() accepts an image-only prompt and rejects malformed attachments', async () => {
    const gateway = makeGateway({ invoke: () => ({ accepted: true }) });
    const bridge = createSessionBridge({
        gateway,
        config: makeConfig({ remoteMutations: true }),
        log: silentLogger(),
        audit: makeAudit(),
    });
    const image = Buffer.from('img').toString('base64');
    await bridge.prompt('s1', { content: [{ type: 'image', mediaType: 'image/jpeg', data: image }] });
    assert.equal(gateway.invocations.length, 1);
    const badInputs = [
        { content: [{ type: 'image', mediaType: 'text/plain', data: image }] },
        { content: [{ type: 'image', mediaType: 'image/png', data: 'not base64!' }] },
        { content: [{ type: 'image', mediaType: 'image/png', data: 'aGVsbG8===' }] },
        { content: [{ type: 'file', receiptId: '' }] },
        { content: [{ type: 'file' }] },
        { content: [{ type: 'image', mediaType: 'image/png', data: image }, ...Array.from({ length: 6 }, () => ({ type: 'image', mediaType: 'image/png', data: image }))] },
    ];
    for (const input of badInputs) {
        await assert.rejects(bridge.prompt('s1', input), (error) => error.code === 'BAD_REQUEST', `must reject ${JSON.stringify(input).slice(0, 80)}`);
    }
});
test('session-bridge: workspaces() maps the registry baseline and falls back to cwd groups', async () => {
    const groups = [
        { workspaceId: 'w1', title: 'dsh-remote-control', path: 'D:/dsh-remote-control', sessionIds: ['s1', 's2'] },
        { workspaceId: 'w2', title: 'other', path: 'D:/other', sessionIds: ['s3'] },
    ];
    const gateway = makeGateway({ invoke: () => ({ items: [] }) });
    gateway.workspaceGroups = async () => groups;
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    assert.deepEqual(await bridge.workspaces(), groups);
    const fallbackGateway = makeGateway({
        invoke: () => ({
            items: [
                { sessionId: 'a', updatedAt: 1, running: false, agentAvailable: true, blank: false, cwd: 'D:/work/proj' },
                { sessionId: 'b', updatedAt: 2, running: false, agentAvailable: true, blank: false, cwd: 'D:/work/proj' },
                { sessionId: 'c', updatedAt: 3, running: false, agentAvailable: true, blank: false, cwd: null },
            ],
        }),
    });
    const fallback = createSessionBridge({ gateway: fallbackGateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    const byCwd = await fallback.workspaces();
    assert.deepEqual(byCwd.map((group) => group.title), ['proj', 'Default workspace']);
    assert.deepEqual(byCwd[0]?.sessionIds, ['a', 'b']);
    assert.deepEqual(byCwd[1]?.sessionIds, ['c']);
});
test('session-bridge: createSession() gates mutations and maps workspace/cwd requests', async () => {
    const gateway = makeGateway({ invoke: (method) => (method === 'create' ? { sessionId: 'new-session' } : null) });
    const readOnly = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: false }), log: silentLogger(), audit: makeAudit() });
    await assert.rejects(readOnly.createSession({ workspaceId: 'w1' }), (error) => error.code === 'NOT_ALLOWED');
    const bridge = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: true }), log: silentLogger(), audit: makeAudit() });
    assert.deepEqual(await bridge.createSession({ workspaceId: 'w1' }), { ok: true, sessionId: 'new-session' });
    assert.deepEqual(gateway.invocations[0], { method: 'create', args: { workspaceId: 'w1' } });
    await assert.rejects(bridge.createSession({ workspaceId: 'w1', cwd: 'D:/x' }), (error) => error.code === 'BAD_REQUEST');
});
test('session-bridge: uploadFile() uses the agent scope and validates canonical base64', async () => {
    const uploaded = { receiptId: 'receipt-9', file: { attachmentId: 'sha256:abc', name: 'notes.txt', bytes: 5 } };
    const gateway = makeGateway({ invoke: (method) => (method === 'fileUploads/upload' ? uploaded : null) });
    const bridge = createSessionBridge({ gateway, config: makeConfig({ remoteMutations: true }), log: silentLogger(), audit: makeAudit() });
    const data = Buffer.from('hello').toString('base64');
    assert.deepEqual(await bridge.uploadFile('s1', { data, name: 'notes.txt' }), { ok: true, ...uploaded });
    assert.deepEqual(gateway.invocations[0], {
        method: 'fileUploads/upload',
        args: { agentId: 's1', request: { data, name: 'notes.txt' } },
    });
    await assert.rejects(bridge.uploadFile('s1', { data: 'aGVsbG8===' }), (error) => error.code === 'BAD_REQUEST');
});
test('session-bridge: readAttachment() maps image metadata and canonical bytes', async () => {
    const data = Buffer.from('img-bytes').toString('base64');
    const gateway = makeGateway({
        invoke: () => ({
            attachment: { attachmentId: 'sha256:abc', mediaType: 'image/png', bytes: 9, width: 4, height: 4, name: 'a.png' },
            data,
        }),
    });
    const bridge = createSessionBridge({ gateway, config: makeConfig(), log: silentLogger(), audit: makeAudit() });
    const result = await bridge.readAttachment('s1', 'sha256:abc');
    assert.equal(result.data, data);
    assert.equal(result.attachment.mediaType, 'image/png');
    assert.deepEqual(gateway.invocations[0], {
        method: 'attachment',
        args: { sessionId: 's1', attachmentId: 'sha256:abc' },
    });
});
