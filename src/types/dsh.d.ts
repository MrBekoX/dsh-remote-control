/**
 * Contract subset of the DSH host services used by dsh-remote-control.
 *
 * The installed DSH runtime (0.2.1-rc.3) ships JavaScript without public `.d.ts`
 * files for its services, so this file is a locally maintained contract instead
 * of a compile-time dependency on DSH packages. `scripts/contract-check.mjs`
 * verifies the runtime descriptors that this contract encodes.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'

/** A Cordis disposer. */
export type Disposer = () => void

export interface HostLogger {
  error(...args: unknown[]): void
  warn(...args: unknown[]): void
  info(...args: unknown[]): void
  debug(...args: unknown[]): void
}

/** Minimal Cordis context surface used by this plugin. */
export interface HostContext {
  /** Register an effect; the returned disposer tears it down on unload. */
  effect(callback: () => void | Disposer, label?: string): Disposer
  /** Listen to a host event; returns a disposer. */
  on(event: string, listener: (...args: any[]) => void): Disposer
  /** Read a service from the store without the inject requirement. */
  get<T = unknown>(name: string): T | undefined
  /** Wait for services and run the callback once they are available. */
  inject(names: readonly string[], callback: (ctx: HostContext) => void): Disposer | void
  logger?: HostLogger
}

/* ------------------------------------------------------------------------- */
/* webServer                                                                 */
/* ------------------------------------------------------------------------- */

export interface ExactRoute {
  kind: 'exact'
  path: string
  handler: (request: IncomingMessage, response: ServerResponse) => void
}

export interface PrefixRoute {
  kind: 'prefix'
  path: string
  handler: (request: IncomingMessage, response: ServerResponse) => void
}

export interface UpgradeRoute {
  path: string
  handler: (request: IncomingMessage, socket: Duplex, head: Buffer) => void
}

/**
 * DSH's authenticated web server. Routes registered here are served on the DSH
 * origin but carry **no** authentication by themselves: the plugin must run
 * `connection.requestRejection()` in every handler.
 */
export interface WebServerService {
  readonly host: string
  readonly port: number
  readonly protocol: 'http:' | 'https:'
  register(route: ExactRoute | PrefixRoute): Disposer
  registerUpgrade(route: UpgradeRoute): Disposer
  getOrigin(): string
}

/* ------------------------------------------------------------------------- */
/* connection                                                                */
/* ------------------------------------------------------------------------- */

export interface ConnectionPeer {
  readonly id: string
  readonly principal: { kind: string }
  readonly interactions: 'answer' | 'none'
  readonly ctx: unknown
  readonly signal: AbortSignal
  dispose(): Promise<void>
}

export interface CreatePeerOptions {
  principal: { kind: 'owner' | 'user' | string; [key: string]: unknown }
  interactions?: 'answer' | 'none'
}

export interface ConnectionService {
  requestRejection(request: IncomingMessage): 401 | 403 | undefined
  admit(request: IncomingMessage): { peer: ConnectionPeer } | { rejection: 401 | 403 }
  createPeer(options: CreatePeerOptions): ConnectionPeer
  /** URL with the process launch token, usable for a browser handshake. */
  authenticatedUrl(baseUrl: string): string
}

/* ------------------------------------------------------------------------- */
/* typertGateway                                                             */
/* ------------------------------------------------------------------------- */

export interface GatewayRequest {
  namespace: string
  method: string
  args?: Record<string, unknown>
  peer: ConnectionPeer
  signal?: AbortSignal
}

export interface GatewayStreamRequest extends GatewayRequest {}

export interface WireStreamApi {
  /**
   * Open a wire stream (e.g. `'$events'`). The installed runtime returns a
   * Promise of an async iterable, so callers must `await` this call.
   */
  open(
    endpoint: string,
    payload: { args?: Record<string, unknown> },
    uplink: AsyncIterable<unknown>,
    peer: ConnectionPeer,
    signal?: AbortSignal,
  ): Promise<AsyncIterable<unknown>>
}

/**
 * In-process typert gateway. This is the documented wire contract used by the
 * desktop GUI itself: descriptors validate named arguments, a real invocation
 * context (peer/principal/signal) is attached, and access control hooks fire.
 */
export interface TypertGatewayService {
  invoke<T = unknown>(request: GatewayRequest): Promise<T>
  stream<T = unknown>(request: GatewayStreamRequest): Promise<AsyncIterable<T>>
  readonly wireStream: WireStreamApi
  dispatchRpc(
    endpoint: string,
    payload: { args: Record<string, unknown> },
    signal: AbortSignal | undefined,
    peer: ConnectionPeer,
  ): Promise<unknown>
  hasLiveClient?(): boolean
}

/* ------------------------------------------------------------------------- */
/* Optional services                                                         */
/* ------------------------------------------------------------------------- */

/** Present in the Electron desktop composition; absent under `dsh web`. */
export interface AppReadyService {
  onReady(callback: () => void): Disposer
}

/* ------------------------------------------------------------------------- */
/* DSH gateway wire frames (subset consumed by the plugin)                   */
/* ------------------------------------------------------------------------- */

/** `$events` wire frames emitted by `ctx.typertGateway.wireStream.open('$events', …)`. */
export type DshEventsFrame =
  | { type: 'ready'; clientId: string; host: { home: string } }
  | { type: 'emit'; event: string; args: unknown[] }
  | { type: 'waterfall'; event: string; eventId: string; agentId: string | null; request: unknown }
  | { type: 'cancel'; eventId: string; reason?: string }

/** `session/follow` stream frames. */
export type DshFollowFrame =
  | {
      type: 'snapshot'
      cursor: number
      header?: unknown
      records?: Array<{ type: 'event'; event: DshSessionEvent }>
      hasMore?: boolean
      projections?: { asOfSeq: number; values: Record<string, unknown> } | null
    }
  | { type: 'event'; event: DshSessionEvent }
  | { type: 'assistant-stream'; frame: unknown }

export interface DshSessionEvent {
  type: string
  seq: number
  time: number
  data?: unknown
  ignorable?: true
  surfaceOp?: unknown
  sourceEventSeqs?: number[]
}
