/**
 * Gateway client: the single host-side entry point into the DSH Typert Remote
 * data plane (`ctx.typertGateway`).
 *
 * Two lifetime models are kept deliberately separate:
 *
 * - **Data plane** (session list/page/projections/prompt/cancel/follow): one
 *   long-lived owner Peer with `interactions: 'none'`. All phones share it, so
 *   a phone socket closing never disturbs another phone's data reads.
 * - **Answering plane** (`$events`): one owner Peer per paired device with
 *   `interactions: 'answer'`, each with its own `$events` wire stream. DSH
 *   fans a forwarded waterfall out to every answering client and the first
 *   answer wins; the per-device peer is what makes that delivery-bound.
 *
 * Runtime assumptions verified against the extracted 0.2.1-rc.3 gateway
 * (`scratch/evidence/dsh-api-gateway.index.js`):
 *
 * - `$events` opens with `{ type: 'ready', clientId, host }` and only then
 *   yields `waterfall` / `cancel` / `emit` frames. `clientId` is the
 *   correlation id every `$events/result` call must carry.
 * - `wireStream.open()` is declared as an `AsyncIterable` in `dsh.d.ts` but the
 *   installed runtime wraps it in a Promise; awaiting the value works for both
 *   shapes.
 * - `dispatchRpc('$events/result', …)` never throws: it resolves to
 *   `{ ok: true, value }` or `{ ok: false, error }`. This module turns the
 *   failure envelope into a coded Error so callers have one failure style.
 */

import type {
  ApprovalEventStream,
  GatewayClient,
  Logger,
  PluginContext,
} from './shared/internal.js'
import type { AnswerOutcome } from './shared/protocol.js'
import type { WorkspaceGroupView } from './shared/protocol.js'
import type { ConnectionPeer, DshEventsFrame } from './types/dsh.js'

/** Remote methods exposed through this client live in the Session namespace. */
const SESSION_NAMESPACE = 'session'
/** Gateway-internal logical stream carrying forwarded waterfalls. */
const APPROVAL_EVENTS_ENDPOINT = '$events'
/** Gateway-internal unary endpoint that settles one forwarded waterfall. */
const APPROVAL_RESULT_ENDPOINT = '$events/result'

/** Uplink for `$events`: the gateway releases (and ignores) it for this endpoint. */
async function* emptyUplink(): AsyncGenerator<never, void, unknown> {
  /* never yields */
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) return error.message
  if (typeof error === 'string' && error.length > 0) return error
  return 'gateway request failed'
}

/**
 * Re-shape an arbitrary gateway failure into an Error carrying `code`.
 * Codes are never dropped: session-bridge maps them onto the public RC error
 * vocabulary, and unknown failures become `GATEWAY`.
 */
function normalizeGatewayFailure(error: unknown): Error {
  const code = isRecord(error) && typeof error.code === 'string' && error.code.length > 0 ? error.code : 'GATEWAY'
  return Object.assign(new Error(errorMessage(error)), { code })
}

interface Endpoint {
  namespace: string
  method: string
}

/**
 * Accept both `'list'` (implicit `session` namespace, the shape session-bridge
 * uses) and an explicit `'session/list'` endpoint.
 */
function splitEndpoint(method: string): Endpoint {
  const separator = method.indexOf('/')
  if (separator < 0) return { namespace: SESSION_NAMESPACE, method }
  return { namespace: method.slice(0, separator), method: method.slice(separator + 1) }
}

/**
 * Wrap logical arguments into the exact wire shape of a descriptor.
 *
 * CONTRACT §2.1: session descriptors name the single request parameter
 * `request`, except `session/list`, whose reserved parameter is `_request`.
 * `assertExactArguments` compares the key set exactly, so this wrapper is the
 * difference between a working call and `gateway/arguments-invalid`.
 *
 * The only non-session endpoint this client uses is `workspace/follow`, which
 * declares no parameters at all; its wire argument object must be empty.
 */
function wrapWireArgs(endpoint: Endpoint, args: Record<string, unknown> | undefined): Record<string, unknown> {
  if (endpoint.namespace !== SESSION_NAMESPACE) return args ?? {}
  const logical = args ?? {}
  return endpoint.method === 'list' ? { _request: logical } : { request: logical }
}

/**
 * Validate one raw `$events` frame. Unknown or malformed frames are dropped
 * instead of being cast imperatively into the answering bridge.
 */
function toEventsFrame(raw: unknown): DshEventsFrame | null {
  if (!isRecord(raw) || typeof raw.type !== 'string') return null
  switch (raw.type) {
    case 'ready': {
      if (typeof raw.clientId !== 'string' || raw.clientId.length === 0) return null
      const host = isRecord(raw.host) && typeof raw.host.home === 'string' ? { home: raw.host.home } : { home: '' }
      return { type: 'ready', clientId: raw.clientId, host }
    }
    case 'emit': {
      if (typeof raw.event !== 'string' || !Array.isArray(raw.args)) return null
      return { type: 'emit', event: raw.event, args: raw.args }
    }
    case 'waterfall': {
      if (typeof raw.event !== 'string' || raw.event.length === 0) return null
      if (typeof raw.eventId !== 'string' || raw.eventId.length === 0) return null
      const agentId = typeof raw.agentId === 'string' && raw.agentId.length > 0 ? raw.agentId : null
      return { type: 'waterfall', event: raw.event, eventId: raw.eventId, agentId, request: raw.request }
    }
    case 'cancel': {
      if (typeof raw.eventId !== 'string' || raw.eventId.length === 0) return null
      const reason = typeof raw.reason === 'string' ? raw.reason : undefined
      return reason === undefined ? { type: 'cancel', eventId: raw.eventId } : { type: 'cancel', eventId: raw.eventId, reason }
    }
    default:
      return null
  }
}

/**
 * Build the gateway client for one plugin lifetime.
 *
 * @param ctx - plugin context carrying `connection` and `typertGateway`.
 * @param log - plugin logger; never receives tokens, prompt text or tool args.
 */
export function createGatewayClient(ctx: PluginContext, log: Logger): GatewayClient {
  let dataPeer: ConnectionPeer | undefined
  let disposed = false
  const approvalStreams = new Set<ApprovalEventStream>()

  function ensureDataPeer(): ConnectionPeer {
    if (disposed) {
      throw Object.assign(new Error('remote control: gateway client is disposed'), { code: 'GATEWAY' })
    }
    dataPeer ??= ctx.connection.createPeer({ principal: { kind: 'owner' }, interactions: 'none' })
    return dataPeer
  }

  async function invoke<T = unknown>(
    method: string,
    args?: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<T> {
    const peer = ensureDataPeer()
    const endpoint = splitEndpoint(method)
    try {
      return await ctx.typertGateway.invoke<T>({
        namespace: endpoint.namespace,
        method: endpoint.method,
        args: wrapWireArgs(endpoint, args),
        peer,
        ...(signal === undefined ? {} : { signal }),
      })
    } catch (error) {
      throw normalizeGatewayFailure(error)
    }
  }

  async function stream<T = unknown>(
    method: string,
    args?: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<AsyncIterable<T>> {
    const peer = ensureDataPeer()
    const endpoint = splitEndpoint(method)
    try {
      return await ctx.typertGateway.stream<T>({
        namespace: endpoint.namespace,
        method: endpoint.method,
        args: wrapWireArgs(endpoint, args),
        peer,
        ...(signal === undefined ? {} : { signal }),
      })
    } catch (error) {
      throw normalizeGatewayFailure(error)
    }
  }

  async function openApprovalEvents(deviceId: string, signal: AbortSignal): Promise<ApprovalEventStream> {
    if (disposed) {
      throw Object.assign(new Error('remote control: gateway client is disposed'), { code: 'GATEWAY' })
    }
    const peer = ctx.connection.createPeer({ principal: { kind: 'owner' }, interactions: 'answer' })
    const lifetime = new AbortController()
    const combined = AbortSignal.any([lifetime.signal, signal])

    let source: AsyncIterable<unknown>
    try {
      const opened = ctx.typertGateway.wireStream.open(
        APPROVAL_EVENTS_ENDPOINT,
        { args: {} },
        emptyUplink(),
        peer,
        combined,
      )
      // `$events` resolution is promise-shaped at runtime (see module header).
      source = await opened
    } catch (error) {
      lifetime.abort(new Error('approval event stream failed to open'))
      try {
        await peer.dispose()
      } catch {
        /* peer disposal is best effort */
      }
      throw normalizeGatewayFailure(error)
    }

    let streamDisposed = false
    const state: { clientId: string | undefined } = { clientId: undefined }

    const frames: AsyncIterable<DshEventsFrame> = (async function* (): AsyncGenerator<DshEventsFrame> {
      for await (const raw of source) {
        if (streamDisposed) return
        const frame = toEventsFrame(raw)
        if (frame === null) {
          log.debug('gateway client: dropped an unrecognized $events frame')
          continue
        }
        if (frame.type === 'ready' && state.clientId === undefined) state.clientId = frame.clientId
        yield frame
      }
    })()

    const approvalStream: ApprovalEventStream = {
      frames,
      async answer(eventId: string, outcome: AnswerOutcome, answerSignal?: AbortSignal): Promise<unknown> {
        if (streamDisposed || disposed) {
          throw Object.assign(new Error('approval event stream is closed'), { code: 'gateway/invocation-unavailable' })
        }
        const clientId = state.clientId
        if (clientId === undefined) {
          throw Object.assign(new Error('approval event stream is not ready'), { code: 'gateway/invocation-unavailable' })
        }
        let result: unknown
        try {
          result = await ctx.typertGateway.dispatchRpc(
            APPROVAL_RESULT_ENDPOINT,
            { args: { clientId, eventId, outcome } },
            answerSignal,
            peer,
          )
        } catch (error) {
          throw normalizeGatewayFailure(error)
        }
        if (isRecord(result) && result.ok === false) {
          const failure = isRecord(result.error) ? result.error : {}
          const code = typeof failure.code === 'string' && failure.code.length > 0 ? failure.code : 'gateway/internal'
          const message =
            typeof failure.message === 'string' && failure.message.length > 0
              ? failure.message
              : 'approval answer was rejected'
          throw Object.assign(new Error(message), { code })
        }
        return result
      },
      async dispose(): Promise<void> {
        if (streamDisposed) return
        streamDisposed = true
        approvalStreams.delete(approvalStream)
        lifetime.abort(new Error('approval event stream disposed'))
        try {
          await peer.dispose()
        } catch (error) {
          log.debug('gateway client: answering peer disposal failed', errorMessage(error))
        }
      },
    }

    approvalStreams.add(approvalStream)
    return approvalStream
  }

  /**
   * Read the desktop Workspace registry from the first `workspace/follow`
   * baseline: full groups (titles, paths, manually ordered session ids) plus the
   * archived id set. A registry failure must not break the phone list.
   */
  async function readWorkspaceBaseline(
    signal?: AbortSignal,
  ): Promise<{ workspaces: WorkspaceGroupView[]; orderedSessionIds: string[]; archivedSessionIds: string[] }> {
    if (disposed) {
      throw Object.assign(new Error('remote control: gateway client is disposed'), { code: 'GATEWAY' })
    }
    const lifetime = new AbortController()
    const combined = signal === undefined ? lifetime.signal : AbortSignal.any([lifetime.signal, signal])
    try {
      const frames = await stream<unknown>('workspace/follow', {}, combined)
      const iterator = frames[Symbol.asyncIterator]()
      try {
        const first = await iterator.next()
        if (first.done === true) {
          throw Object.assign(new Error('workspace baseline stream ended'), { code: 'GATEWAY' })
        }
        const frame = first.value
        if (!isRecord(frame) || frame.type !== 'baseline' || !isRecord(frame.value)) {
          throw Object.assign(new Error('unexpected workspace baseline frame'), { code: 'GATEWAY' })
        }
        const value = frame.value
        const workspaces: WorkspaceGroupView[] = []
        const orderedSessionIds: string[] = []
        const seen = new Set<string>()
        if (Array.isArray(value.items)) {
          for (const item of value.items) {
            if (!isRecord(item) || typeof item.workspaceId !== 'string' || item.workspaceId.length === 0) continue
            const sessionIds = Array.isArray(item.sessionIds)
              ? item.sessionIds.filter((id): id is string => typeof id === 'string' && id.length > 0)
              : []
            workspaces.push({
              workspaceId: item.workspaceId,
              title: typeof item.title === 'string' && item.title.length > 0 ? item.title : 'Workspace',
              path: typeof item.path === 'string' ? item.path : '',
              sessionIds,
            })
            for (const id of sessionIds) {
              if (!seen.has(id)) {
                seen.add(id)
                orderedSessionIds.push(id)
              }
            }
          }
        }
        const archivedSessionIds = Array.isArray(value.archivedSessionIds)
          ? value.archivedSessionIds.filter((id): id is string => typeof id === 'string' && id.length > 0)
          : []
        return { workspaces, orderedSessionIds, archivedSessionIds }
      } finally {
        try {
          await iterator.return?.()
        } catch {
          /* the stream is already cancelled by the lifetime abort */
        }
      }
    } catch (error) {
      throw normalizeGatewayFailure(error)
    } finally {
      lifetime.abort(new Error('workspace baseline scope closed'))
    }
  }

  /**
   * Read the desktop session visibility scope from the Workspace registry:
   * the first `workspace/follow` baseline carries every accounted session id
   * (in manual workspace order) plus the archived id set. The phone list is
   * filtered with this so it matches what the desktop sidebar shows; subagent
   * sessions are never accounted to a workspace and therefore drop out.
   */
  async function workspaceSessionScope(
    signal?: AbortSignal,
  ): Promise<{ orderedSessionIds: string[]; archivedSessionIds: string[] }> {
    const baseline = await readWorkspaceBaseline(signal)
    return {
      orderedSessionIds: baseline.orderedSessionIds,
      archivedSessionIds: baseline.archivedSessionIds,
    }
  }

  async function workspaceGroups(signal?: AbortSignal): Promise<WorkspaceGroupView[]> {
    return (await readWorkspaceBaseline(signal)).workspaces
  }

  function hasLiveClient(): boolean {
    // The installed DSH probe counts *every* owner answering `$events` client,
    // including the ones this plugin opens per device, so it can never answer
    // "is a desktop browser attached?". The RC protocol no longer exposes a
    // desktopConnected flag; the contract keeps the method but never lies.
    return false
  }

  async function dispose(): Promise<void> {
    if (disposed) return
    disposed = true
    for (const approvalStream of [...approvalStreams]) {
      try {
        await approvalStream.dispose()
      } catch (error) {
        log.debug('gateway client: approval stream disposal failed', errorMessage(error))
      }
    }
    approvalStreams.clear()
    const peer = dataPeer
    dataPeer = undefined
    if (peer !== undefined) {
      try {
        await peer.dispose()
      } catch (error) {
        log.debug('gateway client: data peer disposal failed', errorMessage(error))
      }
    }
  }

  return { invoke, stream, workspaceSessionScope, workspaceGroups, openApprovalEvents, hasLiveClient, dispose }
}
