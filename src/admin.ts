/**
 * Desktop admin API served through DSH's own authenticated web server at
 * `/api/dsh-remote-control/*` (design D-04).
 *
 * `webServer.register` routes carry **no** authentication by themselves, so every
 * handler:
 * 1. rejects via `ctx.connection.requestRejection()` (DSH browser auth + fence),
 * 2. adds an explicit local/same-origin gate (loopback peer or the exact DSH
 *    origin, `Sec-Fetch-Site: cross-site` always rejected),
 * 3. enforces the HTTP method and, for mutations, `application/json` + POST,
 * 4. returns `Cache-Control: no-store` + `X-Content-Type-Options: nosniff`, and
 *    maps failures to a generic 400/503 envelope (never leaks internals).
 *
 * Routes (see PROTOCOL.md): `status`, `pending`, `audit` (GET); `control`,
 * `pair/create`, `pair/approve`, `pair/deny`, `device/revoke`,
 * `device/revoke-all`, `device/activate`, `device/release`, `connection/plan`,
 * `connection/start`, `connection/stop`, `emergency-stop`, `install/info`
 * (GET), `install`, plus the legacy `tunnel/start` / `tunnel/stop`.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'

import { HttpError, methodNotAllowed, readJsonBody, sendError, sendJson } from './auth.js'
import type { AdminApi, Logger, PluginContext } from './shared/internal.js'
import type { ConnectionSelection, RcErrorCode } from './shared/protocol.js'
import { RC_ADMIN_PATH, RC_ERRORS } from './shared/protocol.js'

const ADMIN_BODY_LIMIT = 16 * 1024
const ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/
const JSON_CONTENT_TYPE = /^application\/json\b/i
const RC_CODE_SET: ReadonlySet<string> = new Set<string>(Object.values(RC_ERRORS))

type AdminMethod = 'GET' | 'POST'
type BodyKind = 'none' | 'object'

interface AdminRoute {
  suffix: string
  method: AdminMethod
  body: BodyKind
  handle(request: IncomingMessage, response: ServerResponse, body: Record<string, unknown> | null): Promise<void>
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function header(request: IncomingMessage, name: string): string | undefined {
  const raw = request.headers[name]
  if (raw === undefined) return undefined
  const value = Array.isArray(raw) ? raw[0] : raw
  return typeof value === 'string' ? value : undefined
}

function normalizeRemote(value: string | undefined): string | null {
  if (typeof value !== 'string' || value === '') return null
  const trimmed = value.trim()
  return trimmed.toLowerCase().startsWith('::ffff:') ? trimmed.slice(7) : trimmed
}

function isLoopbackPeer(value: string | null): boolean {
  if (value === null) return false
  if (value === '::1' || value === '0:0:0:0:0:0:0:1') return true
  return /^127\./.test(value)
}

function dshOrigin(ctx: PluginContext): { protocol: string; authority: string } | null {
  try {
    const parsed = new URL(ctx.webServer.getOrigin())
    return { protocol: parsed.protocol, authority: parsed.host.toLowerCase() }
  } catch {
    const host = typeof ctx.webServer.host === 'string' ? ctx.webServer.host : ''
    const port = typeof ctx.webServer.port === 'number' ? ctx.webServer.port : 0
    if (host === '' || port <= 0) return null
    const protocol = ctx.webServer.protocol === 'https:' ? 'https:' : 'http:'
    const formatted = host.includes(':') ? `[${host}]` : host
    return { protocol, authority: `${formatted}:${port}`.toLowerCase() }
  }
}

/**
 * Extra local/same-origin gate on top of `requestRejection`: the admin API is
 * only for the local desktop client (loopback socket or the exact DSH origin).
 * Cross-site browser requests are always refused.
 */
function isTrustedAdminRequest(request: IncomingMessage, ctx: PluginContext): boolean {
  const site = header(request, 'sec-fetch-site')
  if (site !== undefined && site.trim().toLowerCase() === 'cross-site') return false

  const expected = dshOrigin(ctx)
  const host = header(request, 'host')
  const origin = header(request, 'origin')
  const loopback = isLoopbackPeer(normalizeRemote(request.socket?.remoteAddress))

  if (origin !== undefined && origin.trim() !== '') {
    let parsed: URL
    try {
      parsed = new URL(origin)
    } catch {
      return false
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
    const authority = parsed.host.toLowerCase()
    if (expected !== null) {
      return parsed.protocol === expected.protocol && authority === expected.authority
    }
    return host !== undefined && authority === host.trim().toLowerCase()
  }

  // Without an Origin header (curl, navigation) only a loopback peer is
  // trusted: the Host header alone is attacker-controlled and must never turn
  // a remote request into an admin request.
  return loopback
}

function setAdminHeaders(response: ServerResponse): void {
  if (response.headersSent) return
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('Referrer-Policy', 'no-referrer')
}

function readId(body: Record<string, unknown> | null, key: string): string {
  const value = body?.[key]
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new HttpError(400, 'BAD_REQUEST', `Invalid ${key}`)
  }
  return value
}

function readAction(body: Record<string, unknown> | null): 'enable' | 'disable' {
  const value = body?.action
  if (value !== 'enable' && value !== 'disable') {
    throw new HttpError(400, 'BAD_REQUEST', 'Invalid action')
  }
  return value
}

/** The two destructive routes must be explicitly confirmed by the user. */
function readConfirm(body: Record<string, unknown> | null): true {
  if (body?.confirm !== true) {
    throw new HttpError(428, 'CONSENT_REQUIRED', 'explicit confirmation is required')
  }
  return true
}

function readPlanId(body: Record<string, unknown> | null): string {
  const value = body?.planId
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new HttpError(400, 'BAD_REQUEST', 'Invalid planId')
  }
  return value
}

/** Body fields are validated again by the controller; reject non-objects only. */
function readSelection(body: Record<string, unknown> | null): ConnectionSelection {
  if (body === null) throw new HttpError(400, 'BAD_REQUEST', 'Connection selection is required')
  return body as unknown as ConnectionSelection
}

/** Fail with a safe 503 when the controller does not expose an optional route. */
function requireHandler<T>(handler: T | undefined, label: string): T {
  if (typeof handler !== 'function') {
    throw new HttpError(503, 'INTERNAL', `${label} is not available`)
  }
  return handler
}

export function registerAdminRoutes(ctx: PluginContext, api: AdminApi, log: Logger): void {
  const routes: AdminRoute[] = [
    {
      suffix: 'status',
      method: 'GET',
      body: 'none',
      handle: async (_request, response) => {
        sendJson(response, 200, await api.status())
      },
    },
    {
      suffix: 'pending',
      method: 'GET',
      body: 'none',
      handle: async (_request, response) => {
        sendJson(response, 200, await api.pending())
      },
    },
    {
      suffix: 'audit',
      method: 'GET',
      body: 'none',
      handle: async (_request, response) => {
        const handler = requireHandler(api.auditLog, 'audit').bind(api)
        sendJson(response, 200, await handler())
      },
    },
    {
      suffix: 'control',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        sendJson(response, 200, await api.control(readAction(body)))
      },
    },
    {
      suffix: 'pair/create',
      method: 'POST',
      body: 'none',
      handle: async (_request, response) => {
        sendJson(response, 200, await api.pairCreate())
      },
    },
    {
      suffix: 'pair/approve',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        sendJson(response, 200, await api.pairApprove(readId(body, 'claimId')))
      },
    },
    {
      suffix: 'pair/deny',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        sendJson(response, 200, await api.pairDeny(readId(body, 'claimId')))
      },
    },
    {
      suffix: 'device/revoke',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        sendJson(response, 200, await api.revoke(readId(body, 'deviceId')))
      },
    },
    {
      suffix: 'device/revoke-all',
      method: 'POST',
      body: 'none',
      handle: async (_request, response) => {
        sendJson(response, 200, await api.revokeAll())
      },
    },
    {
      suffix: 'device/activate',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        const handler = requireHandler(api.activateDevice, 'device/activate').bind(api)
        sendJson(response, 200, await handler(readId(body, 'deviceId')))
      },
    },
    {
      suffix: 'device/release',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        const handler = requireHandler(api.releaseDevice, 'device/release').bind(api)
        sendJson(response, 200, await handler(readId(body, 'deviceId')))
      },
    },
    {
      suffix: 'connection/plan',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        const handler = requireHandler(api.connectionPlan, 'connection/plan').bind(api)
        sendJson(response, 200, await handler(readSelection(body)))
      },
    },
    {
      suffix: 'connection/start',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        const handler = requireHandler(api.connectionStart, 'connection/start').bind(api)
        readConfirm(body)
        sendJson(response, 200, await handler({ planId: readPlanId(body), confirm: true }))
      },
    },
    {
      suffix: 'connection/stop',
      method: 'POST',
      body: 'none',
      handle: async (_request, response) => {
        const handler = requireHandler(api.connectionStop, 'connection/stop').bind(api)
        sendJson(response, 200, await handler())
      },
    },
    {
      suffix: 'emergency-stop',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        const handler = requireHandler(api.emergencyStop, 'emergency-stop').bind(api)
        readConfirm(body)
        sendJson(response, 200, await handler())
      },
    },
    {
      suffix: 'install/info',
      method: 'GET',
      body: 'none',
      handle: async (_request, response) => {
        const handler = requireHandler(api.installInfo, 'install/info').bind(api)
        sendJson(response, 200, await handler())
      },
    },
    {
      suffix: 'install',
      method: 'POST',
      body: 'object',
      handle: async (_request, response, body) => {
        const handler = requireHandler(api.install, 'install').bind(api)
        readConfirm(body)
        sendJson(response, 200, await handler(readPlanId(body)))
      },
    },
    {
      suffix: 'tunnel/start',
      method: 'POST',
      body: 'none',
      handle: async (_request, response) => {
        sendJson(response, 200, await api.startTunnel())
      },
    },
    {
      suffix: 'tunnel/stop',
      method: 'POST',
      body: 'none',
      handle: async (_request, response) => {
        sendJson(response, 200, await api.stopTunnel())
      },
    },
  ]

  const handleFailure = (response: ServerResponse, error: unknown, suffix: string): void => {
    if (response.headersSent || response.destroyed) {
      response.destroy()
      return
    }
    if (error instanceof HttpError) {
      sendError(response, error.status, error.code, error.message)
      return
    }
    // The controller's AdminApi throws its own status/code errors (intentional
    // 4xx like "pairing claim not found"); honour those without leaking
    // internals, and collapse everything unexpected into a generic 503.
    const candidateStatus = (error as { status?: unknown }).status
    const candidateCode = (error as { code?: unknown }).code
    if (
      typeof candidateStatus === 'number' &&
      candidateStatus >= 400 &&
      candidateStatus <= 599 &&
      typeof candidateCode === 'string' &&
      RC_CODE_SET.has(candidateCode)
    ) {
      if (candidateStatus >= 500) {
        log.error('admin route failed', { route: suffix, message: errorMessage(error) })
        sendError(response, 503, 'INTERNAL', 'Remote Control is temporarily unavailable')
        return
      }
      const message = error instanceof Error && error.message.length <= 200 ? error.message : 'Request failed'
      sendError(response, candidateStatus, candidateCode as RcErrorCode, message)
      return
    }
    log.error('admin route failed', { route: suffix, message: errorMessage(error) })
    sendError(response, 503, 'INTERNAL', 'Remote Control is temporarily unavailable')
  }

  const runRoute = async (
    route: AdminRoute,
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> => {
    setAdminHeaders(response)
    try {
      const rejection = ctx.connection.requestRejection(request)
      if (rejection === 401) {
        sendError(response, 401, 'AUTH_REQUIRED', 'Authentication required')
        return
      }
      if (rejection === 403) {
        sendError(response, 403, 'ORIGIN', 'Request rejected')
        return
      }
      if (!isTrustedAdminRequest(request, ctx)) {
        sendError(response, 403, 'ORIGIN', 'Remote Control admin API is local-only')
        return
      }
      if (request.method !== route.method) {
        methodNotAllowed(response, [route.method])
        return
      }

      let body: Record<string, unknown> | null = null
      if (route.body === 'object') {
        const contentType = header(request, 'content-type') ?? ''
        if (!JSON_CONTENT_TYPE.test(contentType)) {
          sendError(response, 400, 'BAD_REQUEST', 'JSON content-type required')
          return
        }
        const parsed = await readJsonBody(request, ADMIN_BODY_LIMIT)
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          sendError(response, 400, 'BAD_REQUEST', 'JSON object body required')
          return
        }
        body = parsed as Record<string, unknown>
      } else {
        // Drain an unexpected body so keep-alive connections stay usable.
        request.resume()
      }

      await route.handle(request, response, body)
      if (!response.headersSent && !response.writableEnded) {
        sendJson(response, 200, { ok: true })
      }
    } catch (error) {
      handleFailure(response, error, route.suffix)
    }
  }

  for (const route of routes) {
    const path = `${RC_ADMIN_PATH}/${route.suffix}`
    ctx.effect(
      () =>
        ctx.webServer.register({
          kind: 'exact',
          path,
          handler: (request: IncomingMessage, response: ServerResponse): void => {
            void runRoute(route, request, response)
          },
        }),
      `remote-control: ${path}`,
    )
  }
}
