/**
 * Approval relay (M4): DSH `$events` waterfall frames become phone cards,
 * answers go back through `$events/result`, the first answer wins and the
 * remaining deliveries are cancelled.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { Config } from '../src/config.js'
import { createApprovalBridge } from '../src/approval-bridge.js'
import type { RemoteControlConfig } from '../src/config.js'
import type {
  ApprovalEventStream,
  AuditEntry,
  AuditRing,
  GatewayClient,
  Logger,
} from '../src/shared/internal.js'
import type { ApprovalView, AnswerOutcome } from '../src/shared/protocol.js'
import type { DshEventsFrame } from '../src/types/dsh.js'

function silentLogger(): Logger {
  return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined }
}

function makeConfig(overrides: Record<string, unknown> = {}): RemoteControlConfig {
  return Config(overrides) as RemoteControlConfig
}

function makeAudit(): AuditRing & { entries: Omit<AuditEntry, 'time'>[] } {
  const entries: Omit<AuditEntry, 'time'>[] = []
  return {
    entries,
    push: (entry) => {
      entries.push(entry)
    },
    snapshot: () => entries.map((entry) => ({ ...entry, time: 0 })),
    get size() {
      return entries.length
    },
    dispose: () => undefined,
  }
}

interface FakeStream extends ApprovalEventStream {
  push(frame: DshEventsFrame): void
  end(): void
  readonly disposed_: boolean
  readonly answers: Array<{ eventId: string; outcome: AnswerOutcome }>
}

/** Controllable async iterable of `$events` frames. */
function makeStream(): FakeStream {
  const buffer: DshEventsFrame[] = []
  const waiters: Array<(result: IteratorResult<DshEventsFrame>) => void> = []
  let ended = false
  let disposed = false
  const answers: Array<{ eventId: string; outcome: AnswerOutcome }> = []

  const frames: AsyncIterable<DshEventsFrame> = {
    [Symbol.asyncIterator](): AsyncIterator<DshEventsFrame> {
      return {
        next(): Promise<IteratorResult<DshEventsFrame>> {
          const next = buffer.shift()
          if (next !== undefined) return Promise.resolve({ value: next, done: false })
          if (ended) return Promise.resolve({ value: undefined, done: true })
          return new Promise((resolve) => {
            waiters.push(resolve)
          })
        },
        return(): Promise<IteratorResult<DshEventsFrame>> {
          ended = true
          flush()
          return Promise.resolve({ value: undefined, done: true })
        },
      }
    },
  }

  function flush(): void {
    for (const waiter of waiters.splice(0)) waiter({ value: undefined, done: true })
  }

  return {
    frames,
    push(frame) {
      const waiter = waiters.shift()
      if (waiter !== undefined) waiter({ value: frame, done: false })
      else buffer.push(frame)
    },
    end() {
      ended = true
      flush()
    },
    get disposed_() {
      return disposed
    },
    answers,
    async answer(eventId: string, outcome: AnswerOutcome): Promise<unknown> {
      answers.push({ eventId, outcome })
      return undefined
    },
    async dispose(): Promise<void> {
      disposed = true
      ended = true
      flush()
    },
  }
}

interface FakeGateway extends GatewayClient {
  readonly streams: Map<string, FakeStream>
  readonly opened: string[]
  failOpen?: Error
  failAnswer?: Error
}

function makeGateway(): FakeGateway {
  const streams = new Map<string, FakeStream>()
  const opened: string[] = []
  const gateway: FakeGateway = {
    streams,
    opened,
    async invoke(): Promise<never> {
      throw new Error('the approval bridge must not invoke unary methods')
    },
    async stream(): Promise<never> {
      throw new Error('the approval bridge must not open data-plane streams')
    },
    async openApprovalEvents(deviceId: string): Promise<ApprovalEventStream> {
      opened.push(deviceId)
      if (gateway.failOpen !== undefined) throw gateway.failOpen
      const stream = makeStream()
      streams.set(deviceId, stream)
      return stream
    },
    hasLiveClient: () => true,
    async dispose(): Promise<void> {},
  }
  return gateway
}

function makeSink(): {
  views: ApprovalView[]
  cancels: Array<{ eventId: string; reason: string }>
  sink: { onApproval(view: ApprovalView): void; onCancel(eventId: string, reason: 'answered-elsewhere' | 'cancelled' | 'expired'): void }
} {
  const views: ApprovalView[] = []
  const cancels: Array<{ eventId: string; reason: string }> = []
  return {
    views,
    cancels,
    sink: {
      onApproval: (view) => {
        views.push(view)
      },
      onCancel: (eventId, reason) => {
        cancels.push({ eventId, reason })
      },
    },
  }
}

async function flush(): Promise<void> {
  for (let index = 0; index < 3; index += 1) await new Promise((resolve) => setImmediate(resolve))
}

function waterfall(request: unknown, event = 'approval/request', eventId = 'evt-1'): DshEventsFrame {
  return { type: 'waterfall', event, eventId, agentId: 'agent-1', request }
}

/* ------------------------------------------------------------------------- */
/* Registration & projection                                                 */
/* ------------------------------------------------------------------------- */

test('approval-bridge: relay disabled by config opens no answering stream', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: false }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const handle = makeSink()
  const detach = await bridge.registerDevice('dev-1', handle.sink)

  assert.deepEqual(gateway.opened, [])
  assert.deepEqual(handle.views, [])
  detach()
  await bridge.dispose()
})

test('approval-bridge: an approval waterfall becomes a card without tool arguments', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true, approvalReminderSeconds: 60 }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const handle = makeSink()
  const detach = await bridge.registerDevice('dev-1', handle.sink)
  assert.deepEqual(gateway.opened, ['dev-1'])

  gateway.streams.get('dev-1')?.push(
    waterfall({
      toolName: 'bash',
      reason: 'Run the test suite',
      displayReason: { en: 'Run the test suite' },
      args: { command: 'rm -rf /' },
      callId: 'call-1',
    }),
  )
  await flush()

  assert.equal(handle.views.length, 1)
  const view = handle.views[0]
  assert.equal(view?.eventId, 'evt-1')
  assert.equal(view?.kind, 'approval')
  assert.equal(view?.agentId, 'agent-1')
  assert.equal(view?.answerable, true)
  assert.equal(view?.expiresInMs, 60_000)
  assert.deepEqual(view?.request, {
    toolName: 'bash',
    reason: 'Run the test suite',
    displayReason: { en: 'Run the test suite' },
    callId: 'call-1',
  })
  assert.equal(JSON.stringify(view).includes('rm -rf'), false, 'tool arguments must never be forwarded')

  detach()
  await bridge.dispose()
})

test('approval-bridge: user-question waterfalls are gated by userQuestions', async () => {
  const off = createApprovalBridge({
    gateway: makeGateway(),
    config: makeConfig({ approvalRelay: true, userQuestions: false }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const offSink = makeSink()
  await off.registerDevice('dev-1', offSink.sink)
  const offGateway = makeGateway()
  void offGateway
  await flush()
  // Re-use a fresh bridge/gateway pair to push a question frame.
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true, userQuestions: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  gateway.streams.get('dev-1')?.push(waterfall({ questions: [{ id: 'q1', text: 'Pick' }] }, 'user-questions/request', 'q-1'))
  await flush()

  assert.equal(sink.views.length, 1)
  assert.equal(sink.views[0]?.kind, 'question')
  assert.deepEqual(sink.views[0]?.request, { questions: [{ id: 'q1', text: 'Pick' }] })

  await off.dispose()
  await bridge.dispose()
})

test('approval-bridge: malformed/irrelevant frames are ignored', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  const stream = gateway.streams.get('dev-1')

  stream?.push({ type: 'ready', clientId: 'c1', host: { home: '/tmp' } })
  stream?.push({ type: 'emit', event: 'api-session/added', args: [] })
  stream?.push({ type: 'waterfall', event: 'approval/request', eventId: '', agentId: null, request: { toolName: 'x' } })
  stream?.push(waterfall({ reason: 'no tool name' }))
  stream?.push(waterfall({ toolName: 'x' }, 'some/other-event'))
  await flush()

  assert.deepEqual(sink.views, [])
  assert.deepEqual(bridge.pending(), [])
  await bridge.dispose()
})

test('approval-bridge: pending() reports live cards only', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  gateway.streams.get('dev-1')?.push(waterfall({ toolName: 'read' }, 'approval/request', 'evt-9'))
  await flush()

  assert.deepEqual(bridge.pending().map((view) => view.eventId), ['evt-9'])
  await bridge.dispose()
  assert.deepEqual(bridge.pending(), [])
})

/* ------------------------------------------------------------------------- */
/* Answering                                                                 */
/* ------------------------------------------------------------------------- */

test('approval-bridge: answer() sends the outcome once and rejects duplicates', async () => {
  const gateway = makeGateway()
  const audit = makeAudit()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit,
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  gateway.streams.get('dev-1')?.push(waterfall({ toolName: 'bash' }))
  await flush()

  const result = await bridge.answer('dev-1', 'evt-1', { kind: 'result', value: 'allowed-once' })
  assert.deepEqual(result, { ok: true })
  assert.deepEqual(gateway.streams.get('dev-1')?.answers, [
    { eventId: 'evt-1', outcome: { kind: 'result', value: 'allowed-once' } },
  ])
  assert.match(audit.entries[0]?.detail ?? '', /approval:allowed-once/)

  const duplicate = await bridge.answer('dev-1', 'evt-1', { kind: 'result', value: 'rejected' })
  assert.equal(duplicate.ok, false)
  assert.equal(duplicate.error?.code, 'GATEWAY')
  await bridge.dispose()
})

test('approval-bridge: invalid or stale answers fail closed', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  gateway.streams.get('dev-1')?.push(waterfall({ toolName: 'bash' }))
  await flush()

  for (const [eventId, outcome] of [
    ['evt-unknown', { kind: 'result', value: 'allowed-once' }],
    ['evt-1', { kind: 'result', value: 'maybe' }],
    ['evt-1', { kind: 'bogus' }],
    ['', { kind: 'next' }],
  ] as const) {
    const result = await bridge.answer('dev-1', eventId, outcome as AnswerOutcome)
    assert.equal(result.ok, false, `answer ${eventId} ${JSON.stringify(outcome)} must fail`)
  }
  const wrongDevice = await bridge.answer('dev-other', 'evt-1', { kind: 'next' })
  assert.equal(wrongDevice.ok, false)
  await bridge.dispose()
})

test('approval-bridge: next outcome and channel errors are handled', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  gateway.streams.get('dev-1')?.push(waterfall({ toolName: 'bash' }))
  await flush()

  const next = await bridge.answer('dev-1', 'evt-1', { kind: 'next' })
  assert.deepEqual(next, { ok: true })
  assert.deepEqual(gateway.streams.get('dev-1')?.answers[0]?.outcome, { kind: 'next' })

  const failingStream = makeStream()
  failingStream.answer = async () => {
    throw Object.assign(new Error('settled'), { code: 'gateway/invocation-unavailable' })
  }
  const failingGateway = makeGateway()
  failingGateway.openApprovalEvents = async (deviceId: string) => {
    failingGateway.opened.push(deviceId)
    return failingStream
  }
  const failingBridge = createApprovalBridge({
    gateway: failingGateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const secondSink = makeSink()
  await failingBridge.registerDevice('dev-2', secondSink.sink)
  failingStream.push(waterfall({ toolName: 'bash' }, 'approval/request', 'evt-2'))
  await flush()
  const failed = await failingBridge.answer('dev-2', 'evt-2', { kind: 'result', value: 'rejected' })
  assert.equal(failed.ok, false)
  assert.equal(failed.error?.code, 'GATEWAY')

  await bridge.dispose()
  await failingBridge.dispose()
})

/* ------------------------------------------------------------------------- */
/* Cancellation & device fan-out                                             */
/* ------------------------------------------------------------------------- */

test('approval-bridge: DSH cancel frames become onCancel for every attached tab', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const first = makeSink()
  const second = makeSink()
  await bridge.registerDevice('dev-1', first.sink)
  await bridge.registerDevice('dev-1', second.sink)
  assert.equal(gateway.opened.length, 1, 'one answering stream per device, not per socket/tab')

  gateway.streams.get('dev-1')?.push(waterfall({ toolName: 'bash' }))
  await flush()
  assert.equal(first.views.length, 1)
  assert.equal(second.views.length, 1)

  gateway.streams.get('dev-1')?.push({ type: 'cancel', eventId: 'evt-1', reason: 'answered' })
  await flush()
  assert.deepEqual(first.cancels, [{ eventId: 'evt-1', reason: 'answered-elsewhere' }])
  assert.deepEqual(second.cancels, [{ eventId: 'evt-1', reason: 'answered-elsewhere' }])
  assert.deepEqual(bridge.pending(), [])
  await bridge.dispose()
})

test('approval-bridge: a second device cannot answer another device\'s event', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sinkA = makeSink()
  const sinkB = makeSink()
  await bridge.registerDevice('dev-a', sinkA.sink)
  await bridge.registerDevice('dev-b', sinkB.sink)

  gateway.streams.get('dev-a')?.push(waterfall({ toolName: 'bash' }, 'approval/request', 'evt-a'))
  await flush()
  assert.equal(sinkA.views.length, 1)
  assert.equal(sinkB.views.length, 0)

  const crossAnswer = await bridge.answer('dev-b', 'evt-a', { kind: 'result', value: 'allowed-once' })
  assert.equal(crossAnswer.ok, false)
  const ownAnswer = await bridge.answer('dev-a', 'evt-a', { kind: 'result', value: 'allowed-once' })
  assert.deepEqual(ownAnswer, { ok: true })
  await bridge.dispose()
})

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

test('approval-bridge: detaching the last tab retires and disposes the stream', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  const detach = await bridge.registerDevice('dev-1', sink.sink)
  const stream = gateway.streams.get('dev-1')
  assert.notEqual(stream, undefined)
  detach()
  await flush()

  assert.equal(stream?.disposed_, true)
  assert.deepEqual(bridge.pending(), [])
  // A new registration opens a new answering stream after the device detached.
  const again = await bridge.registerDevice('dev-1', sink.sink)
  assert.equal(gateway.opened.length, 2)
  again()
  await bridge.dispose()
})

test('approval-bridge: a closed $events stream cancels pending cards and can be reopened', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  gateway.streams.get('dev-1')?.push(waterfall({ toolName: 'bash' }))
  await flush()
  gateway.streams.get('dev-1')?.end()
  await flush()

  assert.deepEqual(sink.cancels, [{ eventId: 'evt-1', reason: 'cancelled' }])
  assert.deepEqual(bridge.pending(), [])
  const answer = await bridge.answer('dev-1', 'evt-1', { kind: 'next' })
  assert.equal(answer.ok, false)
  await bridge.dispose()
})

test('approval-bridge: dispose() detaches streams and refuses new registrations', async () => {
  const gateway = makeGateway()
  const bridge = createApprovalBridge({
    gateway,
    config: makeConfig({ approvalRelay: true }),
    log: silentLogger(),
    audit: makeAudit(),
  })
  const sink = makeSink()
  await bridge.registerDevice('dev-1', sink.sink)
  const stream = gateway.streams.get('dev-1')
  await bridge.dispose()

  assert.equal(stream?.disposed_, true)
  await assert.rejects(bridge.registerDevice('dev-1', sink.sink))
  assert.equal((await bridge.answer('dev-1', 'evt-1', { kind: 'next' })).ok, false)
})
