/**
 * End-to-end integration through the real controller (fake DSH host services and
 * a fake tunnel manager): enable → pair create → phone claim → desktop approve →
 * auth cookies → authenticated REST → fence/CSRF → revoke → disable, plus the
 * connection plan/consent flow, single-active-device lock, security shutdown,
 * refresh races and brute-force accounting.
 *
 * Child processes and network providers are faked; the listener, the WebSocket
 * upgrade gate and the HTTP surface are real.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import WebSocket from 'ws'

import { Config, type RemoteControlConfig } from '../src/config.js'
import { createController, type RemoteControlController } from '../src/controller.js'
import { listLanInterfaces } from '../src/network.js'
import type { PersistedState, PluginContext, StateStore } from '../src/shared/internal.js'
import {
  RC_WS_CLOSE,
  type CloudflaredDownloadInfo,
  type ConnectionSelection,
  type TunnelStatus,
} from '../src/shared/protocol.js'
import type { ConnectionPeer } from '../src/types/dsh.js'

interface FakePeer extends ConnectionPeer {
  readonly interactionsUsed: string
}

interface FakeGatewayCall {
  namespace: string
  method: string
  args: Record<string, unknown> | undefined
}

const SESSION_ITEMS = [
  {
    sessionId: 'sess-1',
    updatedAt: 1700,
    running: true,
    agentAvailable: true,
    blank: false,
    cwd: '/work',
    projections: { values: { title: 'Integration session' } },
    formatStatus: 'idle',
  },
]

function silentLogger() {
  return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined }
}

function makeContext(): { ctx: PluginContext; calls: FakeGatewayCall[]; peerInteractions: string[] } {
  const calls: FakeGatewayCall[] = []
  const peerInteractions: string[] = []
  let peerId = 0

  const connection = {
    requestRejection: () => undefined,
    admit: () => ({ rejection: 401 as const }),
    createPeer: (options: { interactions?: 'answer' | 'none' }): ConnectionPeer => {
      peerId += 1
      peerInteractions.push(options.interactions ?? 'none')
      return {
        id: `peer-${peerId}`,
        principal: { kind: 'owner' },
        interactions: options.interactions ?? 'none',
        ctx: {},
        signal: new AbortController().signal,
        dispose: async () => undefined,
      }
    },
    authenticatedUrl: (base: string) => base,
  }

  const typertGateway = {
    async invoke<T>(request: { namespace: string; method: string; args?: Record<string, unknown> }): Promise<T> {
      calls.push({ namespace: request.namespace, method: request.method, args: request.args })
      if (request.namespace === 'session' && request.method === 'list') {
        return { items: SESSION_ITEMS } as T
      }
      if (request.namespace === 'session' && (request.method === 'prompt' || request.method === 'cancel')) {
        return { ok: true } as T
      }
      if (request.namespace === 'session' && request.method === 'create') {
        return { sessionId: 'created-session' } as T
      }
      if (request.namespace === 'fileUploads' && request.method === 'upload') {
        const upload = (request.args?.['request'] ?? {}) as { data?: string; name?: string }
        return {
          receiptId: 'receipt-1',
          file: {
            attachmentId: 'sha256:file-1',
            name: typeof upload.name === 'string' ? upload.name : 'upload.txt',
            bytes: typeof upload.data === 'string' ? Buffer.from(upload.data, 'base64').length : 0,
          },
        } as T
      }
      if (request.namespace === 'session' && request.method === 'attachment') {
        return {
          attachment: {
            attachmentId: 'sha256:abc',
            mediaType: 'image/png',
            bytes: 3,
            width: 1,
            height: 1,
            name: 'a.png',
          },
          data: Buffer.from('img').toString('base64'),
        } as T
      }
      throw Object.assign(new Error(`unexpected invoke ${request.namespace}/${request.method}`), {
        code: 'gateway/arguments-invalid',
      })
    },
    async stream<T>(): Promise<AsyncIterable<T>> {
      throw new Error('integration test does not open streams')
    },
    wireStream: {
      open: () => {
        throw new Error('integration test does not open $events')
      },
    },
    dispatchRpc: async () => ({ ok: true }),
    hasLiveClient: () => false,
  }

  const webServer = {
    host: '127.0.0.1',
    port: 1,
    protocol: 'http:' as const,
    register: () => () => undefined,
    registerUpgrade: () => () => undefined,
    getOrigin: () => 'http://127.0.0.1:1',
  }

  const ctx = {
    effect: (callback: () => void | (() => void)) => {
      const disposer = callback()
      return typeof disposer === 'function' ? disposer : () => undefined
    },
    on: () => () => undefined,
    get: (name: string) => (name === 'releaseInfo' ? { release: '0.2.1-rc.3' } : undefined),
    inject: () => undefined,
    logger: silentLogger(),
    webServer,
    connection,
    typertGateway,
  } as unknown as PluginContext

  return { ctx, calls, peerInteractions }
}

/** Minimal fake provider manager: no child process, configurable tunnel status. */
function makeFakeTunnelManager() {
  let current: ConnectionSelection | null = null
  let listener: ((status: TunnelStatus) => void) | null = null
  let status: TunnelStatus = {
    enabled: false,
    mode: 'quick',
    state: 'off',
    url: null,
    temporary: false,
    ownership: 'none',
    transport: 'auto',
    serviceUrl: null,
    verified: { http: false, ws: false },
    error: null,
    detail: null,
  }
  let calls = 0

  const info: CloudflaredDownloadInfo = {
    version: '2026.10.5',
    asset: 'cloudflared-windows-amd64.exe',
    sizeBytes: 55_343_328,
    sha256: 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9',
    releaseUrl: 'https://github.com/cloudflare/cloudflared/releases/tag/2026.10.5',
    cacheDirectory: '/cache',
    installed: { path: 'cloudflared', source: 'path', version: '2026.10.5', verified: true },
    supported: true,
  }

  const manager = {
    calls: () => calls,
    async describe(selection: ConnectionSelection) {
      calls += 1
      const publicOrigin =
        selection.method === 'external' && typeof selection.publicUrl === 'string'
          ? new URL(selection.publicUrl).origin
          : selection.method === 'cloudflare-named' || selection.method === 'cloudflare-named-local'
            ? selection.hostname !== undefined && selection.hostname !== ''
              ? `https://${selection.hostname}`
              : null
            : null
      return {
        steps: [{ kind: 'tunnel' as const, text: `fake provider ${selection.method}` }],
        publicOrigin,
        accessRequired: false,
        download: null,
        warnings: [],
        fixedLoopbackPort: selection.method === 'external' || selection.method === 'cloudflare-named',
        temporary: selection.method === 'cloudflare-quick' || selection.method === 'ssh',
      }
    },
    async start(selection: ConnectionSelection) {
      current = selection
      const publicOrigin =
        selection.method === 'external' && typeof selection.publicUrl === 'string'
          ? new URL(selection.publicUrl).origin
          : selection.method === 'cloudflare-quick'
            ? 'https://fake-quick.trycloudflare.com'
            : selection.method === 'cloudflare-named' || selection.method === 'cloudflare-named-local'
              ? `https://${selection.hostname}`
              : selection.method === 'ssh'
                ? 'https://fake.lhr.life'
                : null
      status = {
        enabled: publicOrigin !== null,
        mode:
          selection.method === 'cloudflare-quick'
            ? 'quick'
            : selection.method === 'cloudflare-named'
              ? 'named'
              : selection.method === 'cloudflare-named-local'
                ? 'named-local'
                : selection.method === 'external'
                  ? 'external'
                  : selection.method === 'ssh'
                    ? 'ssh'
                    : 'quick',
        state: publicOrigin === null ? 'off' : 'ready',
        url: publicOrigin,
        temporary: selection.method === 'cloudflare-quick' || selection.method === 'ssh',
        ownership: publicOrigin === null ? 'none' : 'plugin',
        transport: 'auto',
        serviceUrl: null,
        verified: { http: publicOrigin !== null, ws: publicOrigin !== null },
        error: null,
        detail: null,
      }
      listener?.(status)
      return status
    },
    async stop() {
      status = { ...status, enabled: false, state: 'off', url: null }
      listener?.(status)
    },
    status: () => status,
    async installInfo() {
      return info
    },
    async install() {
      return info
    },
    currentSelection: () => current,
    setStatusListener(fn: (next: TunnelStatus) => void) {
      listener = fn
    },
    async dispose() {
      status = { ...status, enabled: false, state: 'off', url: null }
    },
  }
  return manager
}

function makeConfig(deviceStorePath: string, overrides: Record<string, unknown> = {}): RemoteControlConfig {
  return Config({
    enabled: true,
    listen: { host: '127.0.0.1', port: 0, allowLan: false },
    remoteMutations: true,
    approvalRelay: false,
    tokens: { deviceStorePath },
    ...overrides,
  }) as RemoteControlConfig
}

interface HttpResponse {
  status: number
  headers: http.IncomingHttpHeaders
  body: string
  json: () => Record<string, unknown>
  setCookie: string[]
}

async function request(
  base: string,
  requestPath: string,
  options: {
    method?: string
    headers?: Record<string, string>
    body?: unknown
    cookies?: string[]
  } = {},
): Promise<HttpResponse> {
  const url = new URL(requestPath, base)
  const headers: Record<string, string> = { ...(options.headers ?? {}) }
  let payload: string | undefined
  if (options.body !== undefined) {
    payload = JSON.stringify(options.body)
    headers['content-type'] = 'application/json'
    headers['content-length'] = String(Buffer.byteLength(payload))
  }
  if (options.cookies !== undefined && options.cookies.length > 0) {
    headers.cookie = options.cookies.join('; ')
  }
  return new Promise<HttpResponse>((resolve, reject) => {
    const req = http.request(
      {
        host: url.hostname,
        port: Number(url.port),
        path: `${url.pathname}${url.search}`,
        method: options.method ?? 'GET',
        headers,
      },
      (res) => {
        const chunks: Buffer[] = []
        res.on('data', (chunk: Buffer) => chunks.push(chunk))
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8')
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body,
            setCookie: res.headers['set-cookie'] ?? [],
            json: () => JSON.parse(body) as Record<string, unknown>,
          })
        })
      },
    )
    req.on('error', reject)
    if (payload !== undefined) req.write(payload)
    req.end()
  })
}

function cookiePairs(setCookie: string[]): string[] {
  return setCookie.map((value) => value.split(';')[0] ?? '').filter((pair) => pair.includes('='))
}

function errorCode(response: HttpResponse): string {
  const body = response.json()
  const error = body.error as { code?: string } | undefined
  return error?.code ?? ''
}

async function makeTempHome(t: { after: (fn: () => void | Promise<void>) => void }): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rc-integration-'))
  t.after(async () => {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => undefined)
  })
  return dir
}

type TestController = RemoteControlController & {
  emergencyStop: NonNullable<RemoteControlController['emergencyStop']>
  connectionPlan: NonNullable<RemoteControlController['connectionPlan']>
  connectionStart: NonNullable<RemoteControlController['connectionStart']>
  connectionStop: NonNullable<RemoteControlController['connectionStop']>
  activateDevice: NonNullable<RemoteControlController['activateDevice']>
  releaseDevice: NonNullable<RemoteControlController['releaseDevice']>
  installInfo: NonNullable<RemoteControlController['installInfo']>
  install: NonNullable<RemoteControlController['install']>
  auditLog: NonNullable<RemoteControlController['auditLog']>
}

interface CaptureLogger {
  error(message: string, detail?: unknown): void
  warn(message: string, detail?: unknown): void
  info(message: string, detail?: unknown): void
  debug(message: string, detail?: unknown): void
}

interface ControllerSeams {
  idleTimeoutMsOverride?: number
  stateStoreFactory?: (home: string, log: unknown) => StateStore
  /** Replace the fake tunnel manager (e.g. slow/failing start). */
  tunnelFactory?: () => unknown
  /** Capture host-logger entries instead of discarding them. */
  log?: CaptureLogger
}

function makeHarness(
  t: { after: (fn: () => void | Promise<void>) => void },
  home: string,
  overrides?: Record<string, unknown>,
  seams: ControllerSeams = {},
) {
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const { ctx, calls, peerInteractions } = makeContext()
  const config = makeConfig(path.join(home, 'remote-control', 'devices.json'), overrides)
  const tunnel = makeFakeTunnelManager()
  const controller = createController({
    ctx,
    config,
    log: seams.log ?? silentLogger(),
    pluginVersion: '0.2.0-test',
    tunnelFactory: (seams.tunnelFactory ?? (() => tunnel as never)) as never,
    idleTimeoutMsOverride: seams.idleTimeoutMsOverride,
    stateStoreFactory: seams.stateStoreFactory as never,
  }) as TestController
  t.after(async () => {
    await controller.dispose().catch(() => undefined)
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
  })
  return { controller, tunnel, calls, peerInteractions }
}

/** Pair one phone through claim → desktop approval and return its cookies + device. */
async function pairDevice(
  controller: RemoteControlController,
  origin: string,
  name: string,
): Promise<{ cookies: string[]; deviceId: string }> {
  const created = await controller.pairCreate()
  const claim = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { code: created.code, deviceName: name, platform: 'android' },
  })
  assert.equal(claim.status, 200, claim.body)
  const claimBody = claim.json()
  const claimId = String(claimBody.claimId)
  const pollToken = String(claimBody.pollToken)
  assert.deepEqual(await controller.pairApprove(claimId), { ok: true })
  const approved = await request(origin, '/rc/api/pair/status', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { claimId, pollToken },
  })
  assert.equal(approved.status, 200, approved.body)
  assert.equal(approved.json().status, 'approved')
  const device = approved.json().device as { id: string }
  return { cookies: cookiePairs(approved.setCookie), deviceId: device.id }
}

test('integration: enable → pair → approve → cookies → sessions 200 → revoke 401 → disable', async (t) => {
  const home = await makeTempHome(t)
  const { controller, calls, peerInteractions } = makeHarness(t, home)

  await controller.start()
  const status = await controller.status()
  assert.equal(status.enabled, true)
  assert.equal(status.listener.state, 'listening')
  assert.notEqual(status.listener.port, null)
  assert.notEqual(status.listener.url, null)
  assert.equal(status.connection?.method, 'loopback')
  const origin = status.listener.url as string

  // --- health is public ---------------------------------------------------
  const health = await request(origin, '/rc/api/health')
  assert.equal(health.status, 200)
  assert.equal(health.json().ok, true)
  assert.equal(health.json().protocol, 2)
  assert.equal(health.json().securityClosed, false)

  // --- pairing: create code, claim from the phone, approve from desktop ---
  const created = await controller.pairCreate()
  assert.ok(created.code.length > 20)
  assert.equal(created.url.startsWith(origin), true)

  const claim = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { code: created.code, deviceName: 'Test Phone', platform: 'android' },
  })
  assert.equal(claim.status, 200, claim.body)
  const claimBody = claim.json()
  const claimId = String(claimBody.claimId)
  const pollToken = String(claimBody.pollToken)
  assert.equal(claimBody.status, 'claimed')

  const pending = await request(origin, '/rc/api/pair/status', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { claimId, pollToken },
  })
  assert.equal(pending.status, 200)
  assert.equal(pending.json().status, 'claimed')

  const wrongToken = await request(origin, '/rc/api/pair/status', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { claimId, pollToken: 'wrong' },
  })
  assert.equal(wrongToken.status, 410)
  assert.equal(errorCode(wrongToken), 'PAIRING_EXPIRED')

  assert.deepEqual(await controller.pairApprove(claimId), { ok: true })

  const approved = await request(origin, '/rc/api/pair/status', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { claimId, pollToken },
  })
  assert.equal(approved.status, 200)
  const approvedBody = approved.json()
  assert.equal(approvedBody.status, 'approved')
  const device = approvedBody.device as { id: string; active?: boolean }
  assert.ok(device.id.length > 0)
  assert.equal(device.active, true)

  const cookies = cookiePairs(approved.setCookie)
  assert.equal(cookies.some((pair) => pair.startsWith('rc_access=')), true, 'access cookie must be issued')
  assert.equal(cookies.some((pair) => pair.startsWith('rc_refresh=')), true, 'refresh cookie must be issued')
  for (const setCookie of approved.setCookie) {
    assert.match(setCookie, /HttpOnly/i)
    assert.match(setCookie, /SameSite=Strict/i)
    assert.match(setCookie, /Path=\/rc/i)
  }

  // The claim is single-use: a second approval fails.
  await assert.rejects(controller.pairApprove(claimId))

  // --- authenticated REST ------------------------------------------------
  const state = await request(origin, '/rc/api/state', { cookies })
  assert.equal(state.status, 200, state.body)
  assert.equal((state.json().device as { id: string }).id, device.id)
  assert.equal((state.json().deviceLock as { state: string }).state, 'active')

  const sessions = await request(origin, '/rc/api/sessions', { cookies })
  assert.equal(sessions.status, 200, sessions.body)
  const sessionRows = sessions.json().sessions as Array<{ sessionId: string; title: string }>
  assert.equal(sessionRows.length, 1)
  assert.equal(sessionRows[0]?.sessionId, 'sess-1')
  assert.equal(sessionRows[0]?.title, 'Integration session')

  assert.equal(calls.length, 1)
  assert.equal(calls[0]?.namespace, 'session')
  assert.equal(calls[0]?.method, 'list')
  assert.deepEqual(calls[0]?.args, { _request: {} })
  assert.deepEqual(peerInteractions, ['none'], 'the data plane uses a single interactions:none peer')

  // --- auth failures ------------------------------------------------------
  const noCookie = await request(origin, '/rc/api/state')
  assert.equal(noCookie.status, 401)
  assert.equal(errorCode(noCookie), 'AUTH_REQUIRED')

  const noCookieSessions = await request(origin, '/rc/api/sessions')
  assert.equal(noCookieSessions.status, 401)

  const tampered = await request(origin, '/rc/api/state', {
    cookies: cookies.map((pair) => (pair.startsWith('rc_access=') ? `${pair.slice(0, -2)}AA` : pair)),
  })
  assert.equal(tampered.status, 401)

  // --- Host/Origin fence --------------------------------------------------
  const crossOrigin = await request(origin, '/rc/api/state', {
    cookies,
    headers: { origin: 'https://evil.example' },
  })
  assert.equal(crossOrigin.status, 403)
  assert.equal(errorCode(crossOrigin), 'ORIGIN')

  const crossSite = await request(origin, '/rc/api/state', {
    cookies,
    headers: { origin, 'sec-fetch-site': 'cross-site' },
  })
  assert.equal(crossSite.status, 403)
  assert.equal(errorCode(crossSite), 'ORIGIN')

  const nullOrigin = await request(origin, '/rc/api/state', {
    cookies,
    headers: { origin: 'null' },
  })
  assert.equal(nullOrigin.status, 403)
  assert.equal(errorCode(nullOrigin), 'ORIGIN')

  // --- CSRF guard on mutations -------------------------------------------
  const logoutNoCsrf = await request(origin, '/rc/api/session/logout', {
    method: 'POST',
    cookies,
    headers: { origin },
    body: {},
  })
  assert.equal(logoutNoCsrf.status, 403)
  assert.equal(errorCode(logoutNoCsrf), 'CSRF')

  const logoutBadOrigin = await request(origin, '/rc/api/session/logout', {
    method: 'POST',
    cookies,
    headers: { origin: 'https://evil.example', 'x-rc-csrf': '1' },
    body: {},
  })
  assert.equal(logoutBadOrigin.status, 403)
  assert.equal(errorCode(logoutBadOrigin), 'ORIGIN')

  const refreshNoCsrf = await request(origin, '/rc/api/session/refresh', {
    method: 'POST',
    cookies,
    headers: { origin },
    body: {},
  })
  assert.equal(refreshNoCsrf.status, 403)
  assert.equal(errorCode(refreshNoCsrf), 'CSRF')

  // --- revoke -------------------------------------------------------------
  assert.deepEqual(await controller.revoke(device.id), { ok: true })
  const afterRevoke = await request(origin, '/rc/api/sessions', { cookies })
  assert.equal(afterRevoke.status, 401)
  assert.equal(errorCode(afterRevoke), 'DEVICE_REVOKED')

  // --- persisted state ----------------------------------------------------
  const stateFile = path.join(home, 'remote-control', 'state.json')
  const persisted = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as { v: number; lastEnabled: boolean }
  assert.equal(persisted.v, 2)
  assert.equal(persisted.lastEnabled, true, 'enable must persist lastEnabled for autoStart')

  // --- disable closes the listener ----------------------------------------
  const disabled = await controller.control('disable')
  assert.equal(disabled.enabled, false)
  assert.equal(disabled.listener.state, 'off')
  await assert.rejects(request(origin, '/rc/api/health'), /ECONNREFUSED|ECONNRESET|connect/i)
  const disabledState = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as { lastEnabled: boolean }
  assert.equal(disabledState.lastEnabled, false)
})

test('integration: disable before enable leaves no listener and pair creation is refused', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, { enabled: false })
  await controller.start()
  const status = await controller.status()
  assert.equal(status.enabled, false)
  assert.equal(status.listener.state, 'off')
  await assert.rejects(controller.pairCreate(), /enable Remote Control first/)
})

test('integration: sixth bad pairing claim bans the client and later attempts are 429', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home)
  await controller.start()
  const origin = (await controller.status()).listener.url as string

  const statuses: number[] = []
  for (let index = 0; index < 7; index += 1) {
    const response = await request(origin, '/rc/api/pair/claim', {
      method: 'POST',
      headers: { origin, 'x-rc-csrf': '1' },
      body: { code: 'not-a-real-code', deviceName: 'Phone', platform: 'android' },
    })
    statuses.push(response.status)
  }
  assert.deepEqual(statuses.slice(0, 6), [400, 400, 400, 400, 400, 400])
  assert.equal(statuses[6], 429, `expected the 7th attempt to be blocked: ${statuses.join(',')}`)
})

test('integration: emergency stop invalidates tokens, persists closed state and requires explicit re-enable', async (t) => {
  const home = await makeTempHome(t)
  const { controller, tunnel } = makeHarness(t, home)
  await controller.start()
  const origin = (await controller.status()).listener.url as string
  const { cookies, deviceId } = await pairDevice(controller, origin, 'Phone')

  const stopped = await controller.emergencyStop()
  assert.equal(stopped.ok, true)
  assert.equal(stopped.security.closed, true)
  assert.equal(stopped.security.closedReason, 'user-emergency')
  assert.equal(tunnel.status().enabled, false)

  const stateFile = path.join(home, 'remote-control', 'state.json')
  const persisted = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as {
    securityClosed: boolean
    securityClosedReason: string
  }
  assert.equal(persisted.securityClosed, true)
  assert.equal(persisted.securityClosedReason, 'user-emergency')

  // The listener is closed; old cookies are gone with it. Re-enabling is the
  // only path and it must need an explicit user action.
  const reEnabled = await controller.control('enable')
  assert.equal(reEnabled.enabled, true)
  const newOrigin = (await controller.status()).listener.url as string
  const oldCookie = await request(newOrigin, '/rc/api/state', { cookies })
  assert.equal(oldCookie.status, 401)
  // The revoked device is gone from the store, so its old access token can no
  // longer verify (epoch bump + missing device key). Either way it must not
  // authenticate again.
  assert.equal(
    ['TOKEN_EXPIRED', 'DEVICE_REVOKED'].includes(errorCode(oldCookie)),
    true,
    oldCookie.body,
  )

  // The device record was revoked by the security shutdown.
  const status = await controller.status()
  assert.equal(status.devices.some((entry) => entry.id === deviceId), false)
})

test('integration: only one active device and an explicit multi-device selection is required', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home)
  await controller.start()
  const origin = (await controller.status()).listener.url as string

  const first = await pairDevice(controller, origin, 'First Phone')

  // While the first device is active, another pairing is refused.
  await assert.rejects(controller.pairCreate(), /another device is currently active|currently active/i)
  const claimAttempt = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { code: 'x'.repeat(43), deviceName: 'Second', platform: 'ios' },
  })
  assert.equal(claimAttempt.status, 409)
  assert.equal(errorCode(claimAttempt), 'DEVICE_LOCKED')

  // Release the lock, pair a second device, then release it again: two devices
  // are registered with no active one, so enabling requires an explicit choice.
  assert.deepEqual(await controller.releaseDevice(first.deviceId), { ok: true })
  const second = await pairDevice(controller, origin, 'Second Phone')
  assert.notEqual(second.deviceId, first.deviceId)
  assert.deepEqual(await controller.releaseDevice(second.deviceId), { ok: true })

  const lock = (await controller.status()).deviceLock
  assert.equal(lock?.state, 'selection-required')
  assert.equal(lock?.needsSelection, true)

  await controller.control('disable')
  await assert.rejects(controller.control('enable'), /select an active device or revoke/i)

  assert.deepEqual(await controller.activateDevice(first.deviceId), { ok: true })
  const reEnabled = await controller.control('enable')
  assert.equal(reEnabled.enabled, true)
  const lockAfter = (await controller.status()).deviceLock
  assert.equal(lockAfter?.state, 'active')
  assert.equal(lockAfter?.activeDeviceId, first.deviceId)
})

test('integration: connection plan → confirm → start computes origin, QR and cookie decisions', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, { enabled: false })

  const plan = await controller.connectionPlan({
    method: 'external',
    publicUrl: 'https://rc.example.com',
    loopbackPort: 0,
  })
  assert.equal(plan.ok, true)
  assert.notEqual(plan.plan.planId, '')
  assert.equal(plan.plan.publicOrigin, 'https://rc.example.com')
  assert.equal(plan.plan.listener.access, 'loopback')
  assert.equal(plan.plan.listener.host, '127.0.0.1')
  assert.ok(plan.plan.steps.some((step) => step.kind === 'listener'))
  assert.ok(plan.plan.steps.some((step) => step.kind === 'origin'))
  assert.ok(plan.plan.steps.some((step) => step.kind === 'security'))

  // A start without the disclosed plan id is refused.
  await assert.rejects(
    controller.connectionStart({ planId: 'unknown-plan', confirm: true }),
    /plan is missing or expired/i,
  )

  const started = await controller.connectionStart({ planId: plan.plan.planId, confirm: true })
  assert.equal(started.ok, true)
  assert.equal(started.connection.publicOrigin, 'https://rc.example.com')
  assert.equal(started.connection.qrOrigin, 'https://rc.example.com')
  assert.equal(started.connection.secureCookies, true)
  assert.equal(started.connection.tunnel.ownership, 'plugin')
  assert.equal((await controller.status()).enabled, true)

  const created = await controller.pairCreate()
  assert.equal(created.url.startsWith('https://rc.example.com/rc/#/pair?c='), true)

  // Switching provider clears the old origin and QR code.
  const secondPlan = await controller.connectionPlan({ method: 'cloudflare-quick' })
  const switched = await controller.connectionStart({ planId: secondPlan.plan.planId, confirm: true })
  assert.equal(switched.connection.publicOrigin, 'https://fake-quick.trycloudflare.com')
  const statusAfterSwitch = await controller.status()
  assert.equal(statusAfterSwitch.publicUrl, 'https://fake-quick.trycloudflare.com')
  assert.equal(statusAfterSwitch.pairing, null, 'the old QR code must not survive a provider change')
})

test('integration: concurrent refresh requests cannot create two sessions', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home)
  await controller.start()
  const origin = (await controller.status()).listener.url as string
  const { cookies } = await pairDevice(controller, origin, 'Phone')

  const [first, second] = await Promise.all([
    request(origin, '/rc/api/session/refresh', {
      method: 'POST',
      headers: { origin, 'x-rc-csrf': '1' },
      cookies,
      body: {},
    }),
    request(origin, '/rc/api/session/refresh', {
      method: 'POST',
      headers: { origin, 'x-rc-csrf': '1' },
      cookies,
      body: {},
    }),
  ])
  const statuses = [first.status, second.status].sort()
  assert.deepEqual(statuses, [200, 401])
  const loser = first.status === 200 ? second : first
  assert.equal(errorCode(loser), 'TOKEN_EXPIRED')

  // The device is not revoked by a concurrent rotation race.
  const winner = first.status === 200 ? first : second
  const nextCookies = cookiePairs(winner.setCookie)
  const ok = await request(origin, '/rc/api/state', { cookies: nextCookies })
  assert.equal(ok.status, 200, ok.body)
})

const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms))

test('integration: the public tunnel Host/Origin is accepted by the canonical fence', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, { enabled: false })
  const plan = await controller.connectionPlan({
    method: 'external',
    publicUrl: 'https://rc.example.com',
  })
  await controller.connectionStart({ planId: plan.plan.planId, confirm: true })
  const loopback = (await controller.status()).listener.url as string
  const publicHeaders = { host: 'rc.example.com', origin: 'https://rc.example.com' }

  // Real cloudflared/SSH/external requests carry Host=<public hostname>; the
  // canonical fence must accept that authority and report the connection secure.
  const health = await request(loopback, '/rc/api/health', { headers: publicHeaders })
  assert.equal(health.status, 200, health.body)
  assert.equal(health.json().secure, true)

  // An unauthenticated read over the public origin passes the fence (401, not 403).
  const unauth = await request(loopback, '/rc/api/state', { headers: publicHeaders })
  assert.equal(unauth.status, 401, unauth.body)
  assert.equal(errorCode(unauth), 'AUTH_REQUIRED')

  // A wrong Origin is still rejected even with the public Host.
  const wrongOrigin = await request(loopback, '/rc/api/state', {
    headers: { host: 'rc.example.com', origin: 'https://evil.example' },
  })
  assert.equal(wrongOrigin.status, 403)
  assert.equal(errorCode(wrongOrigin), 'ORIGIN')

  // Full pairing over the public origin issues Secure cookies.
  const created = await controller.pairCreate()
  assert.equal(created.url.startsWith('https://rc.example.com/rc/#/pair?c='), true)
  const claim = await request(loopback, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { ...publicHeaders, 'x-rc-csrf': '1' },
    body: { code: created.code, deviceName: 'Public Phone', platform: 'android' },
  })
  assert.equal(claim.status, 200, claim.body)
  const claimBody = claim.json()
  assert.deepEqual(await controller.pairApprove(String(claimBody.claimId)), { ok: true })
  const approved = await request(loopback, '/rc/api/pair/status', {
    method: 'POST',
    headers: { ...publicHeaders, 'x-rc-csrf': '1' },
    body: { claimId: String(claimBody.claimId), pollToken: String(claimBody.pollToken) },
  })
  assert.equal(approved.status, 200, approved.body)
  assert.equal(approved.setCookie.length >= 2, true)
  for (const cookie of approved.setCookie) assert.match(cookie, /;\s*Secure/i)

  const cookies = cookiePairs(approved.setCookie)
  const authed = await request(loopback, '/rc/api/state', { cookies, headers: publicHeaders })
  assert.equal(authed.status, 200, authed.body)
})

test('integration: the session idle clock closes never-touched remote access and ignores anonymous traffic', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, {}, { idleTimeoutMsOverride: 250 })
  await controller.start()
  const origin = (await controller.status()).listener.url as string

  // Anonymous health/static traffic must not renew the idle window.
  for (let index = 0; index < 3; index += 1) {
    await sleep(100)
    await request(origin, '/rc/api/health').catch(() => undefined)
  }
  await sleep(400)

  const status = await controller.status()
  assert.equal(status.enabled, false)
  assert.equal(status.security?.closed, true)
  assert.equal(status.security?.closedReason, 'idle-timeout')
  const persisted = JSON.parse(fs.readFileSync(path.join(home, 'remote-control', 'state.json'), 'utf8')) as {
    securityClosed: boolean
    securityClosedReason: string
  }
  assert.equal(persisted.securityClosed, true)
  assert.equal(persisted.securityClosedReason, 'idle-timeout')
})

test('integration: a stale in-flight state save cannot roll back the security shutdown state', async (t) => {
  const home = await makeTempHome(t)
  const completed: PersistedState[] = []
  let delayNext = false
  const releaseRef: { fn: (() => void) | null } = { fn: null }
  const fakeStore: StateStore = {
    path: 'fake-state',
    async load() {
      return {
        v: 2,
        lastEnabled: false,
        updatedAt: new Date(0).toISOString(),
        revocationEpoch: 0,
        securityClosed: false,
        securityClosedReason: null,
        activeDeviceId: null,
        leaseStartedAt: null,
        leaseLastActivityAt: null,
      }
    },
    async save(state: PersistedState) {
      if (delayNext) {
        delayNext = false
        await new Promise<void>((resolve) => {
          releaseRef.fn = resolve
        })
      }
      completed.push({ ...state })
    },
  }
  const { controller } = makeHarness(t, home, {}, { stateStoreFactory: () => fakeStore })
  await controller.start()
  const origin = (await controller.status()).listener.url as string

  // Pair up to the approved-but-not-yet-issued claim, then delay the next save
  // (the one written while issuing the device) and let an emergency shutdown
  // race against it.
  const created = await controller.pairCreate()
  const claim = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { code: created.code, deviceName: 'Race Phone', platform: 'android' },
  })
  const claimBody = claim.json()
  assert.deepEqual(await controller.pairApprove(String(claimBody.claimId)), { ok: true })
  delayNext = true
  const issuing = request(origin, '/rc/api/pair/status', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { claimId: String(claimBody.claimId), pollToken: String(claimBody.pollToken) },
  }).catch(() => undefined)
  await sleep(100)
  const shutdown = controller.emergencyStop().catch(() => undefined)
  await sleep(100)
  assert.notEqual(releaseRef.fn, null, 'the delayed save should be in flight')
  releaseRef.fn?.()
  await issuing
  await shutdown

  const final = completed[completed.length - 1]
  assert.ok(final !== undefined, 'at least one state save completed')
  assert.equal(final.securityClosed, true, 'shutdown closure must be the last persisted state')
  assert.equal(final.revocationEpoch, 1)
  assert.equal(final.lastEnabled, false)
})

test('integration: an explicit re-enable after a security closure clears it only after a successful start', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home)
  await controller.start()
  await controller.emergencyStop()
  assert.equal((await controller.status()).security?.closed, true)

  // A failing start must not clear the persisted closure.
  await assert.rejects(controller.connectionStart({ planId: 'missing-plan', confirm: true }))
  const stillClosed = await controller.status()
  assert.equal(stillClosed.security?.closed, true)
  assert.equal(stillClosed.enabled, false)

  const plan = await controller.connectionPlan({ method: 'loopback' })
  const started = await controller.connectionStart({ planId: plan.plan.planId, confirm: true })
  assert.equal(started.ok, true)
  assert.equal((await controller.status()).security?.closed, false)
})

test('integration: a per-plan Cloudflare Access requirement is enforced by the host', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, {
    enabled: false,
    tunnel: { access: { required: false, teamDomain: 'access.invalid', audience: 'aud-tag' } },
  })
  const plan = await controller.connectionPlan({
    method: 'cloudflare-named',
    hostname: 'rc.example.com',
    tokenEnv: 'CF_TUNNEL_TOKEN',
    accessRequired: true,
  })
  assert.equal(plan.plan.accessRequired, true, 'the plan must disclose the per-selection Access requirement')
  const started = await controller.connectionStart({ planId: plan.plan.planId, confirm: true })
  assert.equal(
    started.connection.accessRequired,
    true,
    'the plan requirement must be reflected in the live connection state',
  )
  const origin = (await controller.status()).listener.url as string
  // A missing Cf-Access-Jwt-Assertion fails closed before any plugin auth runs.
  const health = await request(origin, '/rc/api/health')
  assert.equal(health.status, 401)
  assert.equal(errorCode(health), 'ACCESS_REQUIRED')

  await controller.control('disable')
  assert.equal((await controller.status()).connection?.accessRequired, false)
})

test('integration: emergency stop is immediate while a tunnel start is in flight', async (t) => {
  const home = await makeTempHome(t)
  const base = makeFakeTunnelManager()
  let entered = false
  const gate: { release: (() => void) | null } = { release: null }
  const gatePromise = new Promise<void>((resolve) => {
    gate.release = resolve
  })
  const slow = {
    ...base,
    async start(selection: ConnectionSelection) {
      entered = true
      await gatePromise
      return base.start(selection)
    },
  }
  const { controller } = makeHarness(t, home, { enabled: false }, { tunnelFactory: () => slow as never })
  const plan = await controller.connectionPlan({ method: 'external', publicUrl: 'https://rc.example.com' })
  const starting = controller
    .connectionStart({ planId: plan.plan.planId, confirm: true })
    .catch((error: unknown) => error)
  try {
    for (let index = 0; index < 400 && !entered; index += 1) await sleep(10)
    assert.equal(entered, true, 'the fake tunnel start should be in flight')

    const origin = (await controller.status()).listener.url as string
    assert.notEqual(origin, null)
    const stopping = controller.emergencyStop()

    // The closure is applied synchronously, before the queued teardown runs.
    assert.equal((await controller.status()).security?.closed, true)
    assert.equal((await controller.status()).enabled, false)

    // Even while the serialized start transition is still in flight, new remote
    // requests are already rejected by the security closure.
    const blocked = await request(origin, '/rc/api/pair/claim', {
      method: 'POST',
      headers: { origin, 'x-rc-csrf': '1' },
      body: { code: 'x'.repeat(43), deviceName: 'Phone', platform: 'android' },
    })
    assert.equal(blocked.status, 503, blocked.body)
    assert.equal(errorCode(blocked), 'SECURITY_CLOSED')

    gate.release?.()
    await starting
    await stopping
  } finally {
    gate.release?.()
  }

  const status = await controller.status()
  assert.equal(status.enabled, false)
  assert.equal(status.security?.closed, true)
  const persisted = JSON.parse(
    fs.readFileSync(path.join(home, 'remote-control', 'state.json'), 'utf8'),
  ) as { securityClosed: boolean; lastEnabled: boolean }
  assert.equal(persisted.securityClosed, true)
  assert.equal(persisted.lastEnabled, false)
})

test('integration: a failed explicit re-enable keeps the persisted security closure', async (t) => {
  const home = await makeTempHome(t)
  const failing = {
    ...makeFakeTunnelManager(),
    async start() {
      throw new Error('tunnel start failed')
    },
  }
  const { controller } = makeHarness(t, home, {}, { tunnelFactory: () => failing as never })
  await controller.start()
  await controller.emergencyStop()
  assert.equal((await controller.status()).security?.closed, true)

  const plan = await controller.connectionPlan({ method: 'external', publicUrl: 'https://rc.example.com' })
  await assert.rejects(controller.connectionStart({ planId: plan.plan.planId, confirm: true }))
  const status = await controller.status()
  assert.equal(status.enabled, false)
  assert.equal(status.security?.closed, true, 'a failed start must restore the closure')
  assert.equal(status.security?.closedReason, 'user-emergency')
  const persisted = JSON.parse(
    fs.readFileSync(path.join(home, 'remote-control', 'state.json'), 'utf8'),
  ) as { securityClosed: boolean; securityClosedReason: string | null }
  assert.equal(persisted.securityClosed, true)
  assert.equal(persisted.securityClosedReason, 'user-emergency')
})

test('integration: a rejected second-device attempt is audited for the desktop panel', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home)
  await controller.start()
  const origin = (await controller.status()).listener.url as string
  const first = await pairDevice(controller, origin, 'First Phone')
  assert.notEqual(first.deviceId, '')

  const claim = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { code: 'y'.repeat(43), deviceName: 'Second Phone', platform: 'ios' },
  })
  assert.equal(claim.status, 409)
  assert.equal(errorCode(claim), 'DEVICE_LOCKED')

  const audit = await controller.auditLog()
  const rejection = audit.entries.find((entry) => entry.kind === 'device-lock' && entry.result === 'rejected')
  assert.notEqual(rejection, undefined, 'the rejected second-device attempt must be audited')
  assert.equal(rejection?.operation, 'pair.claim')
  assert.ok((rejection?.detail.length ?? 0) > 0)
  assert.equal(typeof rejection?.time, 'number')
})

test('integration: prompt audit carries the device id and reaches the host logger', async (t) => {
  const home = await makeTempHome(t)
  const logEntries: Array<{ message: string; detail?: unknown }> = []
  const capture: CaptureLogger = {
    error: (message: string, detail?: unknown) => {
      logEntries.push({ message, detail })
    },
    warn: (message: string, detail?: unknown) => {
      logEntries.push({ message, detail })
    },
    info: (message: string, detail?: unknown) => {
      logEntries.push({ message, detail })
    },
    debug: (message: string, detail?: unknown) => {
      logEntries.push({ message, detail })
    },
  }
  const { controller } = makeHarness(t, home, {}, { log: capture })
  await controller.start()
  const origin = (await controller.status()).listener.url as string
  const { cookies, deviceId } = await pairDevice(controller, origin, 'Phone')

  const canary = 'PROMPT-CONTENT-CANARY-12345'
  const prompt = await request(origin, '/rc/api/sessions/sess-1/prompt', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    cookies,
    body: { content: canary, mode: 'queue' },
  })
  assert.equal(prompt.status, 200, prompt.body)

  const audit = await controller.auditLog()
  const entry = audit.entries.find((item) => item.kind === 'rpc' && item.operation === 'session.prompt')
  assert.notEqual(entry, undefined)
  assert.equal(entry?.deviceId, deviceId, 'prompt audit must carry the authenticated device id')

  const mirrored = logEntries
    .filter((item) => item.message === 'remote control audit')
    .map((item) => item.detail as Record<string, unknown>)
  const promptLog = mirrored.find((detail) => detail.operation === 'session.prompt')
  assert.notEqual(promptLog, undefined, 'the audit entry must also reach the host logger')
  assert.equal(promptLog?.deviceId, deviceId)
  assert.equal(JSON.stringify(logEntries).includes(canary), false, 'prompt content must never be logged')
})

test('integration: a replayed one-time pairing code is rejected with 403', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home)
  await controller.start()
  const origin = (await controller.status()).listener.url as string
  const created = await controller.pairCreate()

  const body = { code: created.code, deviceName: 'Phone', platform: 'android' }
  const first = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body,
  })
  assert.equal(first.status, 200, first.body)

  const replay = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body,
  })
  assert.equal(replay.status, 403, replay.body)
  assert.equal(errorCode(replay), 'PAIRING_CONSUMED')

  const unknown = await request(origin, '/rc/api/pair/claim', {
    method: 'POST',
    headers: { origin, 'x-rc-csrf': '1' },
    body: { code: 'not-a-real-code', deviceName: 'Phone', platform: 'android' },
  })
  assert.equal(unknown.status, 400)
  assert.equal(errorCode(unknown), 'PAIRING_INVALID')
})

test('integration: an explicit panel LAN selection plans HTTPS without the config LAN opt-in', async (t) => {
  const interfaces = listLanInterfaces()
  const candidate =
    interfaces.find((entry) => entry.recommended) ??
    interfaces.find((entry) => entry.family === 'IPv4' && !entry.address.startsWith('127.'))
  if (candidate === undefined) {
    t.skip('no concrete LAN interface is available on this host')
    return
  }

  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, {
    enabled: false,
    listen: {
      allowLan: false,
      access: 'loopback',
      tls: { certFile: '/tmp/rc-test-cert.pem', keyFile: '/tmp/rc-test-key.pem' },
    },
  })
  const plan = await controller.connectionPlan({ method: 'lan', lanAddress: candidate.address })
  assert.equal(plan.ok, true)
  assert.equal(plan.plan.listener.access, 'lan')
  assert.equal(plan.plan.listener.host, candidate.address)
  assert.equal(plan.plan.listener.secure, true)
  assert.equal(plan.plan.listener.protocol, 'https')

  // Without TLS material pairing is refused instead of downgrading to plain HTTP.
  const bareHome = await makeTempHome(t)
  const { controller: withoutTls } = makeHarness(t, bareHome, { enabled: false })
  await assert.rejects(
    withoutTls.connectionPlan({ method: 'lan', lanAddress: candidate.address }),
    (error: unknown) => (error as { code?: string }).code === 'TLS_REQUIRED',
  )
})

test('integration: phone creates sessions, uploads files and reads image attachments', async (t) => {
  const home = await makeTempHome(t)
  const { controller, calls } = makeHarness(t, home, { enabled: false })
  const plan = await controller.connectionPlan({ method: 'loopback' })
  await controller.connectionStart({ planId: plan.plan.planId, confirm: true })
  const origin = (await controller.status()).listener.url as string
  const { cookies } = await pairDevice(controller, origin, 'Phone')
  const headers = { origin, 'x-rc-csrf': '1' }

  // Grouped list: the Workspace registry is unavailable in this harness, so the
  // bridge falls back to cwd groups derived from the session list.
  const listed = await request(origin, '/rc/api/sessions', { cookies })
  assert.equal(listed.status, 200, listed.body)
  const listBody = listed.json() as { sessions: unknown[]; workspaces?: Array<{ title: string; sessionIds: string[] }> }
  assert.equal(listBody.sessions.length, 1)
  assert.deepEqual(listBody.workspaces, [{ workspaceId: 'cwd:/work', title: 'work', path: '/work', sessionIds: ['sess-1'] }])

  // New session (workspace-scoped).
  const created = await request(origin, '/rc/api/sessions', {
    method: 'POST',
    headers,
    cookies,
    body: { workspaceId: 'workspace-1' },
  })
  assert.equal(created.status, 200, created.body)
  assert.equal(created.json().sessionId, 'created-session')
  const createCall = calls.find((call) => call.namespace === 'session' && call.method === 'create')
  assert.deepEqual(createCall?.args, { request: { workspaceId: 'workspace-1' } })

  // File upload (base64) through the agent-scoped DSH upload Remote.
  const data = Buffer.from('hello').toString('base64')
  const uploaded = await request(origin, '/rc/api/sessions/sess-1/files', {
    method: 'POST',
    headers,
    cookies,
    body: { name: 'notes.txt', data },
  })
  assert.equal(uploaded.status, 200, uploaded.body)
  const uploadBody = uploaded.json() as { receiptId: string; file: { name: string } }
  assert.equal(uploadBody.receiptId, 'receipt-1')
  assert.equal(uploadBody.file.name, 'notes.txt')
  const uploadCall = calls.find((call) => call.namespace === 'fileUploads' && call.method === 'upload')
  assert.deepEqual(uploadCall?.args, { agentId: 'sess-1', request: { data, name: 'notes.txt' } })

  // Image attachment read for transcript rendering.
  const attachment = await request(origin, '/rc/api/sessions/sess-1/attachments/sha256%3Aabc', { cookies })
  assert.equal(attachment.status, 200, attachment.body)
  const attachmentBody = attachment.json() as { attachment: { mediaType: string }; data: string }
  assert.equal(attachmentBody.attachment.mediaType, 'image/png')
  assert.equal(attachmentBody.data, Buffer.from('img').toString('base64'))

  // Image-only prompt is accepted by the controller and forwarded to DSH.
  const image = Buffer.from('img').toString('base64')
  const prompted = await request(origin, '/rc/api/sessions/sess-1/prompt', {
    method: 'POST',
    headers,
    cookies,
    body: { content: [{ type: 'image', mediaType: 'image/png', data: image }] },
  })
  assert.equal(prompted.status, 200, prompted.body)
  const promptCall = calls.find((call) => call.namespace === 'session' && call.method === 'prompt')
  const promptRequest = promptCall?.args?.['request'] as {
    sessionId: string
    mode: string
    content: unknown
    requestId: string
  }
  assert.equal(promptRequest.sessionId, 'sess-1')
  assert.equal(promptRequest.mode, 'queue')
  assert.match(promptRequest.requestId, /^[0-9a-f-]{36}$/)
  assert.deepEqual(promptRequest.content, [{ type: 'image', mediaType: 'image/png', data: image }])
})

test('integration: stopping an external connection revokes the origin, closes WS and stops the listener', async (t) => {
  const home = await makeTempHome(t)
  const { controller } = makeHarness(t, home, { enabled: false })
  const plan = await controller.connectionPlan({
    method: 'external',
    publicUrl: 'https://rc.example.com',
    loopbackPort: 0,
  })
  await controller.connectionStart({ planId: plan.plan.planId, confirm: true })
  const loopback = (await controller.status()).listener.url as string
  assert.notEqual(loopback, null)
  const publicHeaders = { host: 'rc.example.com', origin: 'https://rc.example.com' }

  // Pair over the loopback authority and prove the public origin is usable.
  const { cookies, deviceId } = await pairDevice(controller, loopback, 'Phone')
  assert.notEqual(deviceId, '')
  const before = await request(loopback, '/rc/api/sessions', { cookies, headers: publicHeaders })
  assert.equal(before.status, 200, before.body)

  // An open WebSocket on the connection that must be cut by Stop.
  const ws = new WebSocket(`${loopback.replace(/^http/, 'ws')}/rc/ws`, {
    headers: { Origin: loopback, Cookie: cookies.join('; ') },
  })
  const frames: Record<string, unknown>[] = []
  const waiters: Array<(frame: Record<string, unknown>) => void> = []
  ws.on('message', (data) => {
    const frame = JSON.parse(data.toString()) as Record<string, unknown>
    const waiter = waiters.shift()
    if (waiter !== undefined) waiter(frame)
    else frames.push(frame)
  })
  const closed = new Promise<{ code: number; reason: string }>((resolve) => {
    ws.once('close', (code, reason) => resolve({ code, reason: reason.toString() }))
  })
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve())
    ws.once('error', reject)
  })
  const nextFrame = (): Promise<Record<string, unknown>> => {
    const queued = frames.shift()
    if (queued !== undefined) return Promise.resolve(queued)
    return new Promise((resolve) => waiters.push(resolve))
  }
  ws.send(JSON.stringify({ type: 'hello', protocol: 2 }))
  assert.equal((await nextFrame()).type, 'ready')

  const stopped = await controller.connectionStop()
  assert.equal(stopped.ok, true)
  assert.equal(stopped.connection.publicOrigin, null, 'the public origin must be revoked')
  assert.equal(stopped.connection.qrOrigin, null)
  assert.equal(stopped.connection.listener.state, 'off', 'the listener must be stopped for external Stop')
  assert.equal(
    stopped.connection.hostAuthorities.includes('https://rc.example.com'),
    false,
    'the public origin must be removed from the Host/Origin fence',
  )

  const wsClose = await Promise.race([
    closed,
    new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error('ws did not close')), 3_000)),
  ])
  assert.equal(wsClose.code, RC_WS_CLOSE.policyViolation, 'open WS connections are closed by Stop')

  // The listener socket is gone: neither public nor loopback requests can authenticate.
  await assert.rejects(
    request(loopback, '/rc/api/sessions', { cookies, headers: publicHeaders }),
    /ECONNREFUSED|ECONNRESET|connect|socket hang up/i,
  )

  const status = await controller.status()
  assert.equal(status.publicUrl, null)
  assert.equal(status.pairing, null)

  // The logical session stays enabled and a new plan can start cleanly afterwards.
  assert.equal(status.enabled, true)
  const nextPlan = await controller.connectionPlan({ method: 'loopback' })
  const restarted = await controller.connectionStart({ planId: nextPlan.plan.planId, confirm: true })
  assert.equal(restarted.ok, true)
  const healthOrigin = (await controller.status()).listener.url as string
  const health = await request(healthOrigin, '/rc/api/health')
  assert.equal(health.status, 200)
})
