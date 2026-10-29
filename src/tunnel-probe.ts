/**
 * Bounded public-origin probes.
 *
 * Connector readiness ("Registered tunnel connection") says nothing about
 * whether the public route actually reaches this plugin listener. The manager
 * therefore reports HTTP and WebSocket verification separately and never shows
 * `ready` without both probes succeeding:
 * - HTTP: `GET <origin>/rc/api/health` must return the plugin health JSON
 *   (`ok: true`); a redirect to Cloudflare Access is reported as
 *   `access-required`; any other answer is a `mismatch` signal.
 * - WS: a WSS handshake to `<origin>/rc/ws` must reach the plugin listener. An
 *   unauthenticated handshake is expected to be rejected by the plugin with an
 *   HTTP 400/401/403/426 answer, which still proves the route exists; 3xx to
 *   Cloudflare Access maps to `access-required`.
 */

import { WebSocket as NodeWebSocket } from 'ws'

import { RC_API_PATH, RC_WS_PATH } from './shared/protocol.js'
import type { FetchLike, SpawnFn } from './tunnel-process.js'

export interface ProbeResult {
  ok: boolean
  /** HTTP status observed (null on network/timeout failure). */
  status: number | null
  /** True when the public origin redirected to a Cloudflare Access login. */
  accessRequired: boolean
  /** Short non-sensitive diagnostic. */
  detail: string | null
}

export interface TunnelProbe {
  http(origin: string, timeoutMs?: number): Promise<ProbeResult>
  ws(origin: string, timeoutMs?: number): Promise<ProbeResult>
}

export interface WsLike {
  on(event: string, listener: (...args: unknown[]) => void): void
  close?(): void
  terminate?(): void
}

export interface TunnelProbeDeps {
  fetch?: FetchLike
  webSocketFactory?: (url: string, options: { handshakeTimeout: number; followRedirects: boolean }) => WsLike
  timeoutMs?: number
}

const DEFAULT_TIMEOUT_MS = 5_000
const ACCESS_HINT = /cloudflareaccess\.com|cdn-cgi\/access/i
const ROUTE_REACHABLE_WS_STATUSES = new Set([101, 400, 401, 403, 426])

function originOf(origin: string): string {
  return origin.replace(/\/+$/, '')
}

function wsUrlFor(origin: string): string {
  const url = new URL(originOf(origin))
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  url.pathname = RC_WS_PATH
  url.search = ''
  url.hash = ''
  return url.origin.replace(/^http/, 'ws') + RC_WS_PATH
}

function networkFailure(error: unknown): ProbeResult {
  const name = error instanceof Error ? error.name : 'Error'
  return { ok: false, status: null, accessRequired: false, detail: `network error (${name})` }
}

/** Real public-origin probe. Unit tests inject a fake `TunnelProbe` into the manager. */
export function createTunnelProbe(deps: TunnelProbeDeps = {}): TunnelProbe {
  const fetchImpl: FetchLike = deps.fetch ?? fetch
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const webSocketFactory =
    deps.webSocketFactory ??
    ((url: string, options: { handshakeTimeout: number; followRedirects: boolean }): WsLike =>
      new NodeWebSocket(url, {
        handshakeTimeout: options.handshakeTimeout,
        followRedirects: options.followRedirects,
        headers: { 'user-agent': 'dsh-remote-control-readiness' },
      }) as unknown as WsLike)

  const http = async (origin: string, overrideTimeoutMs?: number): Promise<ProbeResult> => {
    const budget = overrideTimeoutMs ?? timeoutMs
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), budget)
    timer.unref()
    try {
      const response = await fetchImpl(`${originOf(origin)}${RC_API_PATH}/health`, {
        method: 'GET',
        redirect: 'manual',
        cache: 'no-store',
        signal: controller.signal,
        headers: { accept: 'application/json' },
      })
      const location = response.headers.get('location') ?? ''
      if (response.status >= 300 && response.status < 400) {
        if (ACCESS_HINT.test(location)) {
          return { ok: false, status: response.status, accessRequired: true, detail: 'Access login redirect' }
        }
        return { ok: false, status: response.status, accessRequired: false, detail: 'unexpected redirect' }
      }
      if (response.status !== 200) {
        return { ok: false, status: response.status, accessRequired: false, detail: `HTTP ${response.status}` }
      }
      const text = await response.text()
      let body: unknown
      try {
        body = JSON.parse(text)
      } catch {
        return { ok: false, status: 200, accessRequired: false, detail: 'health response is not JSON' }
      }
      const ok = typeof body === 'object' && body !== null && (body as { ok?: unknown }).ok === true
      return ok
        ? { ok: true, status: 200, accessRequired: false, detail: null }
        : { ok: false, status: 200, accessRequired: false, detail: 'health response is not from this plugin' }
    } catch (error) {
      return networkFailure(error)
    } finally {
      clearTimeout(timer)
    }
  }

  const ws = (origin: string, overrideTimeoutMs?: number): Promise<ProbeResult> => {
    const budget = overrideTimeoutMs ?? timeoutMs
    return new Promise<ProbeResult>((resolve) => {
      let settled = false
      const finish = (result: ProbeResult): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        try {
          socket?.terminate?.()
        } catch {
          // Already closed.
        }
        resolve(result)
      }
      let socket: WsLike | null = null
      const timer = setTimeout(() => finish({ ok: false, status: null, accessRequired: false, detail: 'timeout' }), budget)
      timer.unref()
      try {
        socket = webSocketFactory(wsUrlFor(origin), { handshakeTimeout: budget, followRedirects: false })
      } catch (error) {
        finish(networkFailure(error))
        return
      }
      socket.on('open', () => finish({ ok: true, status: 101, accessRequired: false, detail: null }))
      socket.on('unexpected-response', (_request: unknown, response: unknown) => {
        const status = typeof (response as { statusCode?: unknown }).statusCode === 'number'
          ? ((response as { statusCode: number }).statusCode)
          : null
        const headers = (response as { headers?: Record<string, unknown> }).headers ?? {}
        const rawLocation = headers['location'] ?? headers['Location']
        const location = Array.isArray(rawLocation) ? rawLocation.join(',') : typeof rawLocation === 'string' ? rawLocation : ''
        if (status !== null && status >= 300 && status < 400 && ACCESS_HINT.test(location)) {
          finish({ ok: false, status, accessRequired: true, detail: 'Access login redirect' })
          return
        }
        if (status !== null && ROUTE_REACHABLE_WS_STATUSES.has(status)) {
          finish({ ok: true, status, accessRequired: false, detail: null })
          return
        }
        finish({ ok: false, status, accessRequired: false, detail: status === null ? 'no HTTP response' : `HTTP ${status}` })
      })
      socket.on('error', (error: unknown) => {
        // An unexpected-response rejection may surface as an error as well; the
        // first settled result wins.
        finish(networkFailure(error))
      })
    })
  }

  return { http, ws }
}

/** Test seam helper: a provider-free fake probe factory. */
export function staticProbe(http: ProbeResult, ws: ProbeResult): TunnelProbe {
  return {
    http: async () => ({ ...http }),
    ws: async () => ({ ...ws }),
  }
}

export type { FetchLike, SpawnFn }
