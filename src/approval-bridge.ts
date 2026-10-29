/**
 * Approval relay: turns DSH forwarded waterfalls (`$events`) into phone
 * approval cards and routes the phone's answer back as a `$events/result` RPC.
 *
 * One owner + `interactions: 'answer'` Peer is opened per **device**, not per
 * socket: a paired device may hold up to four `/rc/ws` sockets (tabs), and all
 * of them share that answering stream. The hub keeps a fan-out pending map so
 * that:
 *
 * - every socket's {@link ApprovalSink} sees its own delivery of the card;
 * - when one delivery answers, DSH settles the waterfall and the gateway sends
 *   a `cancel` frame to the remaining deliveries, which is forwarded as
 *   `onCancel(eventId, 'answered-elsewhere')` to every other socket.
 *
 * Notes from the installed 0.2.1-rc.3 gateway (`dsh-api-gateway.index.js`):
 * the `$events` opening frame carries the `clientId` used by `$events/result`,
 * `waterfall` frames always carry `eventId`, and a request that was already
 * settled is a silent no-op at the gateway. This module therefore rejects an
 * answer for an event it no longer considers pending instead of pretending it
 * was accepted.
 */

import type { RemoteControlConfig } from './config.js'
import type {
  AnswerResult,
  ApprovalEventStream,
  ApprovalHub,
  ApprovalSink,
  AuditRing,
  GatewayClient,
  Logger,
} from './shared/internal.js'
import type {
  ApprovalKind,
  ApprovalRequestView,
  ApprovalView,
  AnswerOutcome,
  QuestionRequestView,
  RcErrorCode,
} from './shared/protocol.js'
import type { DshEventsFrame } from './types/dsh.js'

/** Default visual countdown when the config is somehow unusable. */
const DEFAULT_REMINDER_MS = 300_000

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) return error.message.slice(0, 300)
  if (typeof error === 'string' && error.length > 0) return error.slice(0, 300)
  return 'approval relay failure'
}

function failure(code: RcErrorCode, message: string): AnswerResult {
  return { ok: false, error: { code, message } }
}

/** Validate/normalize the untrusted answer outcome into the DSH wire vocabulary. */
function normalizeOutcome(value: unknown): AnswerOutcome | null {
  if (!isRecord(value)) return null
  if (value.kind === 'next') return { kind: 'next' }
  if (value.kind === 'result' && (value.value === 'allowed-once' || value.value === 'rejected')) {
    return { kind: 'result', value: value.value }
  }
  return null
}

function outcomeLabel(outcome: AnswerOutcome): string {
  return outcome.kind === 'next' ? 'next' : outcome.value
}

/**
 * Project an approval waterfall request. Tool arguments are deliberately not
 * part of this projection: the DSH request does not carry them, and a phone
 * card only ever shows the tool name plus the human-readable reason.
 */
function projectApprovalRequest(value: unknown): ApprovalRequestView {
  const request = isRecord(value) ? value : {}
  return {
    toolName: typeof request.toolName === 'string' ? request.toolName : '',
    reason: typeof request.reason === 'string' ? request.reason : null,
    displayReason: Object.hasOwn(request, 'displayReason') ? request.displayReason : null,
    callId: typeof request.callId === 'string' ? request.callId : null,
  }
}

/** Project a user-question waterfall request; the questions payload travels as-is. */
function projectQuestionRequest(value: unknown): QuestionRequestView {
  if (isRecord(value) && Object.hasOwn(value, 'questions')) return { questions: value.questions }
  return { questions: value ?? null }
}

interface DeviceRelay {
  readonly deviceId: string
  readonly stream: ApprovalEventStream
  readonly controller: AbortController
  readonly sinks: Set<ApprovalSink>
  /** Event ids this device's stream may still answer. */
  readonly pending: Set<string>
  closed: boolean
}

interface PendingApproval {
  readonly view: ApprovalView
  /** Devices that still hold an unanswered delivery for this event. */
  readonly devices: Set<string>
}

/**
 * Create the approval hub for one plugin lifetime.
 *
 * @param deps.gateway - gateway client (per-device answering streams).
 * @param deps.config - `approvalRelay` gates the whole relay; `userQuestions`
 *   gates question waterfalls; `approvalReminderSeconds` is the visual countdown.
 * @param deps.log - plugin logger; never receives prompt text or tokens.
 * @param deps.audit - audit ring; only `deviceId` + event kind/decision meta.
 */
export function createApprovalBridge(deps: {
  gateway: GatewayClient
  config: RemoteControlConfig
  log: Logger
  audit: AuditRing
}): ApprovalHub {
  const { gateway, config, log, audit } = deps
  const relays = new Map<string, DeviceRelay>()
  const opening = new Map<string, Promise<DeviceRelay>>()
  const pending = new Map<string, PendingApproval>()
  let disposed = false

  const reminderMs = Number.isFinite(config.approvalReminderSeconds)
    ? Math.max(1_000, Math.trunc(config.approvalReminderSeconds * 1_000))
    : DEFAULT_REMINDER_MS

  function auditMeta(deviceId: string, detail: string): void {
    try {
      audit.push({ deviceId, kind: 'answer', detail })
    } catch {
      /* the audit ring must never fail an answer */
    }
  }

  function notifyCancel(relay: DeviceRelay, eventId: string, reason: 'answered-elsewhere' | 'cancelled' | 'expired'): void {
    for (const sink of relay.sinks) {
      try {
        sink.onCancel(eventId, reason)
      } catch (error) {
        log.warn('approval bridge: sink cancel handler failed', errorMessage(error))
      }
    }
  }

  function notifyApproval(relay: DeviceRelay, view: ApprovalView): void {
    for (const sink of relay.sinks) {
      try {
        sink.onApproval(view)
      } catch (error) {
        log.warn('approval bridge: sink approval handler failed', errorMessage(error))
      }
    }
  }

  function removePendingDevice(deviceId: string, eventId: string): void {
    const entry = pending.get(eventId)
    if (entry === undefined) return
    entry.devices.delete(deviceId)
    if (entry.devices.size === 0) pending.delete(eventId)
  }

  function handleFrame(relay: DeviceRelay, frame: DshEventsFrame): void {
    switch (frame.type) {
      case 'ready':
        log.debug('approval bridge: device event stream ready')
        return
      case 'waterfall': {
        const kind = waterfallKind(frame.event)
        if (kind === undefined) {
          log.debug('approval bridge: ignored a waterfall that is not relayed')
          return
        }
        // The Lead contract is explicit: only the frame's own `eventId` is a
        // correlation id. Never fall back to request fields, never invent one.
        if (typeof frame.eventId !== 'string' || frame.eventId.length === 0) {
          log.warn('approval bridge: ignored a waterfall frame without an eventId')
          return
        }
        const view = buildView(kind, frame)
        if (view === null) {
          log.warn('approval bridge: ignored a malformed waterfall request')
          return
        }
        const entry = pending.get(view.eventId)
        if (entry === undefined) {
          pending.set(view.eventId, { view, devices: new Set([relay.deviceId]) })
        } else {
          entry.devices.add(relay.deviceId)
        }
        if (relay.pending.has(view.eventId)) return
        relay.pending.add(view.eventId)
        notifyApproval(relay, view)
        return
      }
      case 'cancel': {
        if (typeof frame.eventId !== 'string' || frame.eventId.length === 0) {
          log.warn('approval bridge: ignored a cancel frame without an eventId')
          return
        }
        relay.pending.delete(frame.eventId)
        removePendingDevice(relay.deviceId, frame.eventId)
        notifyCancel(relay, frame.eventId, 'answered-elsewhere')
        return
      }
      case 'emit': {
        if (typeof frame.event !== 'string' || frame.event.length === 0) {
          log.debug('approval bridge: ignored an emit frame without an event name')
          return
        }
        const args = Array.isArray(frame.args) ? frame.args : []
        for (const sink of relay.sinks) {
          try {
            sink.onHostEvent?.(frame.event, args)
          } catch (error) {
            log.debug('approval bridge: a host-event sink threw', errorMessage(error))
          }
        }
        return
      }
      default:
        log.debug('approval bridge: ignored an unknown $events frame')
    }
  }

  function waterfallKind(event: string): ApprovalKind | undefined {
    if (event === 'approval/request') return 'approval'
    if (event === 'user-questions/request') return config.userQuestions ? 'question' : undefined
    return undefined
  }

  function buildView(kind: ApprovalKind, frame: Extract<DshEventsFrame, { type: 'waterfall' }>): ApprovalView | null {
    if (kind === 'question') {
      return {
        eventId: frame.eventId,
        kind,
        request: projectQuestionRequest(frame.request),
        agentId: frame.agentId,
        answerable: true,
        expiresInMs: reminderMs,
      }
    }
    if (!isRecord(frame.request) || !Object.hasOwn(frame.request, 'toolName')) {
      // An approval without a tool name cannot be rendered as an approval card.
      return null
    }
    return {
      eventId: frame.eventId,
      kind,
      request: projectApprovalRequest(frame.request),
      agentId: frame.agentId,
      answerable: true,
      expiresInMs: reminderMs,
    }
  }

  async function retireRelay(
    relay: DeviceRelay,
    why: 'stream-ended' | 'detached' | 'disposed',
  ): Promise<void> {
    if (relay.closed) return
    relay.closed = true
    if (relays.get(relay.deviceId) === relay) relays.delete(relay.deviceId)
    const eventIds = [...relay.pending]
    relay.pending.clear()
    for (const eventId of eventIds) {
      removePendingDevice(relay.deviceId, eventId)
      if (why === 'stream-ended') notifyCancel(relay, eventId, 'cancelled')
    }
    try {
      relay.controller.abort(new Error(`approval relay ${why}`))
    } catch {
      /* AbortController.abort never throws for a plain reason */
    }
    try {
      await relay.stream.dispose()
    } catch (error) {
      log.debug('approval bridge: answering stream disposal failed', errorMessage(error))
    }
  }

  async function pumpRelay(relay: DeviceRelay): Promise<void> {
    try {
      for await (const frame of relay.stream.frames) {
        if (relay.closed || disposed) return
        handleFrame(relay, frame)
      }
    } catch (error) {
      if (!relay.closed && !disposed) {
        log.warn('approval bridge: device event stream failed', errorMessage(error))
      }
    } finally {
      if (!relay.closed) void retireRelay(relay, 'stream-ended')
    }
  }

  function startRelay(deviceId: string, stream: ApprovalEventStream, controller: AbortController): DeviceRelay {
    const relay: DeviceRelay = {
      deviceId,
      stream,
      controller,
      sinks: new Set(),
      pending: new Set(),
      closed: false,
    }
    relays.set(deviceId, relay)
    void pumpRelay(relay)
    return relay
  }

  async function ensureRelay(deviceId: string): Promise<DeviceRelay> {
    const existing = relays.get(deviceId)
    if (existing !== undefined) return existing
    const inFlight = opening.get(deviceId)
    if (inFlight !== undefined) return inFlight
    const controller = new AbortController()
    const promise = (async (): Promise<DeviceRelay> => {
      const stream = await gateway.openApprovalEvents(deviceId, controller.signal)
      if (disposed) {
        try {
          await stream.dispose()
        } catch {
          /* best effort */
        }
        throw Object.assign(new Error('remote control: approval bridge is disposed'), { code: 'GATEWAY' })
      }
      return startRelay(deviceId, stream, controller)
    })()
    opening.set(deviceId, promise)
    try {
      return await promise
    } finally {
      if (opening.get(deviceId) === promise) opening.delete(deviceId)
    }
  }

  async function registerDevice(deviceId: string, sink: ApprovalSink): Promise<() => void> {
    if (disposed) throw Object.assign(new Error('remote control: approval bridge is disposed'), { code: 'GATEWAY' })
    if (typeof deviceId !== 'string' || deviceId.length === 0) {
      throw Object.assign(new Error('deviceId is required'), { code: 'BAD_REQUEST' })
    }
    if (typeof sink !== 'object' || sink === null) {
      throw Object.assign(new Error('approval sink is required'), { code: 'INTERNAL' })
    }
    if (!config.approvalRelay) {
      // Fail closed: without the explicit opt-in no answering client is opened.
      log.debug('approval bridge: relay disabled by config; device gets no approvals')
      return () => {}
    }
    const relay = await ensureRelay(deviceId)
    relay.sinks.add(sink)
    let released = false
    return (): void => {
      if (released) return
      released = true
      relay.sinks.delete(sink)
      if (relay.sinks.size === 0) void retireRelay(relay, 'detached')
    }
  }

  async function answer(deviceId: string, eventId: string, outcome: AnswerOutcome): Promise<AnswerResult> {
    if (disposed) return failure('GATEWAY', 'approval relay is disposed')
    if (typeof deviceId !== 'string' || deviceId.length === 0) return failure('BAD_REQUEST', 'deviceId is required')
    if (typeof eventId !== 'string' || eventId.length === 0) return failure('BAD_REQUEST', 'eventId is required')
    const normalized = normalizeOutcome(outcome)
    if (normalized === null) return failure('BAD_REQUEST', 'invalid approval outcome')
    const relay = relays.get(deviceId)
    if (relay === undefined || relay.closed) return failure('GATEWAY', 'approval channel is not attached')
    const entry = pending.get(eventId)
    if (entry === undefined || !entry.devices.has(deviceId) || !relay.pending.has(eventId)) {
      return failure('GATEWAY', 'approval request is no longer pending')
    }
    auditMeta(deviceId, `${entry.view.kind}:${outcomeLabel(normalized)}`)
    try {
      await relay.stream.answer(eventId, normalized)
    } catch (error) {
      return failure('GATEWAY', errorMessage(error))
    }
    // DSH settles the waterfall; every other delivery gets a `cancel` frame.
    // The answering delivery is finished locally so a duplicate tap is rejected.
    relay.pending.delete(eventId)
    removePendingDevice(deviceId, eventId)
    return { ok: true }
  }

  function pendingViews(): ApprovalView[] {
    const views: ApprovalView[] = []
    for (const entry of pending.values()) {
      if (entry.devices.size > 0) views.push(entry.view)
    }
    return views
  }

  async function dispose(): Promise<void> {
    if (disposed) return
    disposed = true
    const closing = [...relays.values()]
    relays.clear()
    pending.clear()
    opening.clear()
    await Promise.all(closing.map((relay) => retireRelay(relay, 'disposed')))
  }

  return { registerDevice, answer, pending: pendingViews, dispose }
}
