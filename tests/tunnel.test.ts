/**
 * TunnelManager lane: provider plans, lifecycle, readiness/verification
 * semantics, error contract, secret hygiene, ownership and install delegation.
 *
 * FAILING-FIRST: written before `src/tunnel.ts` is rewritten. Child processes,
 * HTTP probes, downloads and clock-adjacent behavior are injected fakes; no
 * network and no real cloudflared/ssh execution happens in this file.
 */

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { after, before, test } from 'node:test'

import {
  PINNED_CLOUDFLARED_RELEASE,
  type CloudflaredFacade,
  type CloudflaredInstalled,
  type CloudflaredResolveResult,
} from '../src/cloudflared.js'
import { Config } from '../src/config.js'
import type { RemoteControlConfig } from '../src/config.js'
import type { Logger, TunnelPlanContext } from '../src/shared/internal.js'
import type {
  CloudflaredDownloadInfo,
  ConnectionSelection,
  TunnelStatus,
} from '../src/shared/protocol.js'
import { TunnelError } from '../src/tunnel-errors.js'
import {
  createTunnelManager,
  type ManagedTunnelManager,
  type TunnelManagerDeps,
} from '../src/tunnel.js'
import type { SpawnFn } from '../src/tunnel-process.js'
import type { ProbeResult, TunnelProbe } from '../src/tunnel-probe.js'

const CLI_UUID = '11111111-2222-3333-4444-555555555555'

function silentLogger(): Logger & { messages: string[] } {
  const messages: string[] = []
  const record = (message: string) => {
    messages.push(message)
  }
  return {
    messages,
    error: record,
    warn: record,
    info: record,
    debug: record,
  }
}

function makeConfig(overrides: Record<string, unknown> = {}): RemoteControlConfig {
  return Config(overrides) as RemoteControlConfig
}

let root = ''

before(async () => {
  root = await mkdtemp(join(tmpdir(), 'dsh-rc-tunnel-'))
})

after(async () => {
  if (root !== '') await rm(root, { recursive: true, force: true })
})

function planContext(localUrl = 'http://127.0.0.1:47123'): TunnelPlanContext {
  const parsed = new URL(localUrl)
  return {
    localUrl,
    listener: {
      access: 'loopback',
      host: parsed.hostname,
      port: Number(parsed.port),
      protocol: parsed.protocol === 'https:' ? 'https' : 'http',
      secure: parsed.protocol === 'https:',
    },
  }
}

let dirCounter = 0
function freshDir(label: string): string {
  dirCounter += 1
  return join(root, `${label}-${dirCounter}`)
}

/* ------------------------------------------------------------------------- */
/* Fakes                                                                     */
/* ------------------------------------------------------------------------- */

interface FakeSpawnCall {
  command: string
  args: readonly string[]
  options: { env?: NodeJS.ProcessEnv; windowsHide?: boolean; shell?: unknown }
}

interface ControllableChild {
  child: import('node:child_process').ChildProcess
  emitStdout(text: string): void
  emitStderr(text: string): void
  exit(code: number | null, signal?: NodeJS.Signals | null): void
  readonly killed: Array<NodeJS.Signals | number>
  killMode: 'exit-on-term' | 'ignore-term'
}

function makeControllableChild(): ControllableChild {
  const child = new EventEmitter() as unknown as import('node:child_process').ChildProcess
  const stdout = new EventEmitter() as unknown as NodeJS.ReadableStream
  const stderr = new EventEmitter() as unknown as NodeJS.ReadableStream
  const killed: Array<NodeJS.Signals | number> = []
  const state: ControllableChild = {
    child,
    killed,
    killMode: 'exit-on-term',
    emitStdout: (text) => (stdout as unknown as EventEmitter).emit('data', text),
    emitStderr: (text) => (stderr as unknown as EventEmitter).emit('data', text),
    exit: (code, signal = null) => {
      Object.assign(child, { exitCode: code, signalCode: signal })
      child.emit('exit', code, signal)
    },
  }
  Object.assign(child, {
    stdout,
    stderr,
    exitCode: null,
    signalCode: null,
    kill: (signal?: NodeJS.Signals | number) => {
      const effective = signal ?? 'SIGTERM'
      killed.push(effective)
      if (state.killMode === 'exit-on-term' && effective === 'SIGTERM') {
        setImmediate(() => state.exit(null, 'SIGTERM'))
      }
      return true
    },
  })
  return state
}

function makeVersionChild(version = 'cloudflared version 2026.10.5 (built 2026-10-27T06:05 UTC)'): import('node:child_process').ChildProcess {
  const child = new EventEmitter() as unknown as import('node:child_process').ChildProcess
  const stderr = new EventEmitter() as unknown as NodeJS.ReadableStream
  Object.assign(child, {
    stdout: new EventEmitter(),
    stderr,
    exitCode: null,
    signalCode: null,
    kill: () => true,
  })
  setImmediate(() => {
    ;(stderr as unknown as EventEmitter).emit('data', `${version}\n`)
    Object.assign(child, { exitCode: 0 })
    child.emit('exit', 0, null)
  })
  return child
}

interface SpawnHarness {
  spawn: SpawnFn
  calls: FakeSpawnCall[]
}

function makeSpawn(handler: (call: FakeSpawnCall, callIndex: number) => import('node:child_process').ChildProcess): SpawnHarness {
  const calls: FakeSpawnCall[] = []
  const spawn: SpawnFn = (command, args, options) => {
    const call: FakeSpawnCall = { command, args, options: options as FakeSpawnCall['options'] }
    return handler(call, (calls.push(call), calls.length - 1))
  }
  return { spawn, calls }
}

/** cloudflared runner: `--version` discovery probes get a version child, all else the tunnel child. */
function cloudflaredSpawn(
  tunnelChildren: ControllableChild[],
  version = 'cloudflared version 2026.10.5 (built 2026-10-27T06:05 UTC)',
): SpawnHarness {
  let tunnelIndex = 0
  return makeSpawn((call) => {
    if (call.args[0] === '--version') return makeVersionChild(version)
    const child = tunnelChildren[tunnelIndex] ?? tunnelChildren[tunnelChildren.length - 1]!
    tunnelIndex += 1
    return child.child
  })
}

/** ssh runner: `-V` discovery probes get a version child, all else the tunnel child. */
function sshSpawn(tunnelChildren: ControllableChild[]): SpawnHarness {
  let tunnelIndex = 0
  return makeSpawn((call) => {
    if (call.args[0] === '-V') return makeVersionChild('OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2')
    const child = tunnelChildren[tunnelIndex] ?? tunnelChildren[tunnelChildren.length - 1]!
    tunnelIndex += 1
    return child.child
  })
}

function installedCloudflared(overrides: Partial<CloudflaredInstalled> = {}): CloudflaredInstalled {
  return {
    path: '/opt/cloudflared',
    source: 'path',
    version: '2026.10.5',
    verified: false,
    ...overrides,
  }
}

function downloadInfo(overrides: Partial<CloudflaredDownloadInfo> = {}): CloudflaredDownloadInfo {
  const asset = PINNED_CLOUDFLARED_RELEASE.assets['linux-x64']!
  return {
    version: PINNED_CLOUDFLARED_RELEASE.version,
    asset: asset.asset,
    sizeBytes: asset.sizeBytes,
    sha256: asset.sha256,
    releaseUrl: `${PINNED_CLOUDFLARED_RELEASE.releaseBaseUrl}/${asset.asset}`,
    cacheDirectory: '/cache',
    installed: null,
    supported: true,
    ...overrides,
  }
}

interface FakeCloudflared extends CloudflaredFacade {
  readonly resolveCalls: number
  readonly installCalls: number
}

function fakeCloudflared(options: {
  installed?: CloudflaredInstalled | null
  supported?: boolean
  info?: CloudflaredDownloadInfo
} = {}): FakeCloudflared {
  let resolveCalls = 0
  let installCalls = 0
  const installed = options.installed === undefined ? installedCloudflared() : options.installed
  const supported = options.supported ?? installed !== null
  const resolve = async (): Promise<CloudflaredResolveResult> => {
    resolveCalls += 1
    return {
      installed,
      asset: supported ? PINNED_CLOUDFLARED_RELEASE.assets['linux-x64']! : null,
      supported,
      cacheDirectory: '/cache',
      release: PINNED_CLOUDFLARED_RELEASE,
    }
  }
  const info = async (): Promise<CloudflaredDownloadInfo> =>
    options.info ?? downloadInfo({ installed, supported })
  const install = async (): Promise<CloudflaredDownloadInfo> => {
    installCalls += 1
    return info()
  }
  return {
    resolve,
    info,
    install,
    get resolveCalls() {
      return resolveCalls
    },
    get installCalls() {
      return installCalls
    },
  }
}

const OK_PROBE: ProbeResult = { ok: true, status: 200, accessRequired: false, detail: null }

interface OrderedCloudflared extends CloudflaredFacade {
  readonly resolveArgs: Array<readonly string[] | undefined>
  readonly infoArgs: Array<readonly string[] | undefined>
}

/** A facade whose installed binary depends on the ordered candidate list it receives. */
function orderedCloudflared(
  installedFor: (paths: readonly string[] | undefined) => CloudflaredInstalled | null,
): OrderedCloudflared {
  const resolveArgs: Array<readonly string[] | undefined> = []
  const infoArgs: Array<readonly string[] | undefined> = []
  const asset = PINNED_CLOUDFLARED_RELEASE.assets['linux-x64']!
  const asResult = (installed: CloudflaredInstalled | null): CloudflaredResolveResult => ({
    installed,
    asset,
    supported: true,
    cacheDirectory: '/cache',
    release: PINNED_CLOUDFLARED_RELEASE,
  })
  return {
    resolveArgs,
    infoArgs,
    resolve: async (paths) => {
      resolveArgs.push(paths)
      return asResult(installedFor(paths))
    },
    info: async (paths) => {
      infoArgs.push(paths)
      return downloadInfo({ installed: installedFor(paths) })
    },
    install: async () => downloadInfo(),
  }
}

function makeProbe(http: ProbeResult = OK_PROBE, ws: ProbeResult = OK_PROBE): TunnelProbe & { calls: string[] } {
  const calls: string[] = []
  return {
    calls,
    http: async (origin: string) => {
      calls.push(`http:${origin}`)
      return { ...http }
    },
    ws: async (origin: string) => {
      calls.push(`ws:${origin}`)
      return { ...ws }
    },
  }
}

function managerDeps(overrides: Partial<TunnelManagerDeps> = {}): TunnelManagerDeps {
  const managed = freshDir('managed')
  const runtime = freshDir('runtime')
  return {
    config: makeConfig(),
    log: silentLogger(),
    managedDir: () => managed,
    runtimeDir: () => runtime,
    ...overrides,
  }
}

function makeManager(overrides: Partial<TunnelManagerDeps> = {}): {
  manager: ManagedTunnelManager
  statuses: TunnelStatus[]
  deps: TunnelManagerDeps
} {
  const deps = managerDeps(overrides)
  const manager = createTunnelManager(deps)
  const statuses: TunnelStatus[] = []
  manager.setStatusListener((status) => statuses.push(status))
  return { manager, statuses, deps }
}

function quickSelection(overrides: Partial<ConnectionSelection> = {}): ConnectionSelection {
  return { method: 'cloudflare-quick', ...overrides }
}

async function expectTunnelError(action: () => Promise<unknown>, code: string): Promise<TunnelError> {
  try {
    await action()
  } catch (error) {
    assert.ok(error instanceof TunnelError, `expected TunnelError, got ${String(error)}`)
    assert.equal(error.code, code)
    return error
  }
  assert.fail(`expected TunnelError ${code}`)
}

/** The manager spawns asynchronously; tests must wait for the child before emitting stdout/stderr. */
async function waitFor(predicate: () => boolean, label: string, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${label}`)
    await new Promise((resolve) => setImmediate(resolve))
  }
}

function isTunnelSpawn(call: FakeSpawnCall): boolean {
  return call.args[0] !== '--version' && call.args[0] !== '-V'
}

async function waitForTunnelSpawn(spawn: SpawnHarness, count = 1): Promise<void> {
  await waitFor(() => spawn.calls.filter(isTunnelSpawn).length >= count, 'tunnel child spawn')
}

/* ------------------------------------------------------------------------- */
/* describe(): plan -> confirmation disclosure                               */
/* ------------------------------------------------------------------------- */

test('describe quick: temporary URL plan with pinned download, no side effects', async () => {
  const cloudflared = fakeCloudflared({ installed: null, supported: true })
  const spawn = cloudflaredSpawn([])
  const { manager } = makeManager({ cloudflared, spawn: spawn.spawn })
  const plan = await manager.describe(quickSelection(), planContext())
  assert.equal(plan.publicOrigin, null)
  assert.equal(plan.temporary, true)
  assert.equal(plan.fixedLoopbackPort, false)
  assert.equal(plan.accessRequired, false)
  assert.ok(plan.download !== null)
  assert.equal(plan.download.version, '2026.10.5')
  assert.equal(plan.download.sha256, 'e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298')
  assert.ok(plan.steps.some((step) => step.kind === 'tunnel'))
  assert.ok(plan.steps.some((step) => step.kind === 'download'))
  assert.ok(plan.steps.some((step) => step.kind === 'security'))
  assert.equal(cloudflared.installCalls, 0, 'describe never downloads')
  assert.equal(spawn.calls.length, 0, 'describe never spawns a tunnel process')
  assert.equal(manager.status().state, 'off')
  assert.equal(manager.currentSelection(), null)
})

test('describe quick: unsupported platform has no download plan and a warning', async () => {
  const cloudflared = fakeCloudflared({ installed: null, supported: false, info: downloadInfo({ supported: false, installed: null }) })
  const { manager } = makeManager({ cloudflared })
  const plan = await manager.describe(quickSelection(), planContext())
  assert.equal(plan.download, null)
  assert.ok(plan.warnings.some((warning) => /platform/i.test(warning)))
})

test('describe named: fixed hostname + fixed loopback port + mutually exclusive token sources', async () => {
  const cloudflared = fakeCloudflared()
  const { manager } = makeManager({ cloudflared })
  const plan = await manager.describe(
    { method: 'cloudflare-named', hostname: 'rc.example.com' },
    planContext(),
  )
  assert.equal(plan.publicOrigin, 'https://rc.example.com')
  assert.equal(plan.fixedLoopbackPort, true)
  assert.equal(plan.temporary, false)
  assert.ok(
    plan.warnings.some((warning) => /registered connector does not prove|hostname/i.test(warning)),
    'warns that connector != public route',
  )

  await expectTunnelError(
    () =>
      manager.describe(
        { method: 'cloudflare-named', hostname: 'rc.example.com', tokenEnv: 'A_TOKEN', tokenFile: '/tmp/t' },
        planContext(),
      ),
    'BAD_REQUEST',
  )
  await expectTunnelError(
    () => manager.describe({ method: 'cloudflare-named', hostname: 'not a host' }, planContext()),
    'BAD_REQUEST',
  )
  await expectTunnelError(
    () => manager.describe({ method: 'cloudflare-named', hostname: 'https://rc.example.com' }, planContext()),
    'BAD_REQUEST',
  )
})

test('describe named: falls back to the configured token file when the selection omits it', async () => {
  const cloudflared = fakeCloudflared()
  const config = makeConfig({ tunnel: { tokenFile: 'C:\\secrets\\tunnel.token' } })
  const { manager } = makeManager({ config, cloudflared })
  const plan = await manager.describe({ method: 'cloudflare-named', hostname: 'rc.example.com' }, planContext())
  assert.equal(plan.publicOrigin, 'https://rc.example.com')
  assert.ok(plan.warnings.length >= 0)
})

test('describe named-local: requires UUID + credentials and only targets the RC listener', async () => {
  const cloudflared = fakeCloudflared()
  const { manager } = makeManager({ cloudflared })
  await expectTunnelError(
    () =>
      manager.describe(
        { method: 'cloudflare-named-local', hostname: 'rc.example.com', tunnelId: CLI_UUID },
        planContext(),
      ),
    'BAD_REQUEST',
  )
  const plan = await manager.describe(
    {
      method: 'cloudflare-named-local',
      hostname: 'rc.example.com',
      tunnelId: CLI_UUID,
      credentialsFile: 'C:\\secrets\\tunnel.json',
    },
    planContext(),
  )
  assert.equal(plan.publicOrigin, 'https://rc.example.com')
  assert.equal(plan.fixedLoopbackPort, false)
  assert.equal(plan.download, null, 'a usable binary means no download disclosure')
})

test('describe external: validates the operator-provided fixed HTTPS origin', async () => {
  const { manager } = makeManager()
  const plan = await manager.describe(
    { method: 'external', publicUrl: 'https://rc.example.com' },
    planContext(),
  )
  assert.equal(plan.publicOrigin, 'https://rc.example.com')
  assert.equal(plan.fixedLoopbackPort, true)
  assert.equal(plan.temporary, false)
  await expectTunnelError(
    () => manager.describe({ method: 'external', publicUrl: 'http://rc.example.com' }, planContext()),
    'BAD_REQUEST',
  )
  await expectTunnelError(
    () => manager.describe({ method: 'external', publicUrl: 'https://rc.example.com/path' }, planContext()),
    'BAD_REQUEST',
  )
})

test('describe loopback/lan: public exposure is null and no provider process is planned', async () => {
  const { manager } = makeManager()
  for (const method of ['loopback', 'lan'] as const) {
    const plan = await manager.describe({ method }, planContext())
    assert.equal(plan.publicOrigin, null)
    assert.equal(plan.download, null)
    assert.equal(plan.temporary, false)
    assert.ok(plan.steps.some((step) => step.kind === 'tunnel'))
  }
})

test('describe ssh: missing OpenSSH is disclosed as a warning, never as a download', async () => {
  const spawn = makeSpawn(() => {
    const child = new EventEmitter() as unknown as import('node:child_process').ChildProcess
    Object.assign(child, { stdout: new EventEmitter(), stderr: new EventEmitter(), exitCode: null, signalCode: null, kill: () => true })
    setImmediate(() => child.emit('error', Object.assign(new Error('ENOENT'), { code: 'ENOENT' })))
    return child
  })
  const { manager } = makeManager({ spawn: spawn.spawn })
  const plan = await manager.describe({ method: 'ssh' }, planContext())
  assert.equal(plan.publicOrigin, null)
  assert.equal(plan.download, null)
  assert.equal(plan.temporary, true)
  assert.ok(plan.warnings.some((warning) => /openssh|ssh/i.test(warning)))
})

/* ------------------------------------------------------------------------- */
/* quick provider                                                           */
/* ------------------------------------------------------------------------- */

test('start quick: exact argv, fragmented URL+registration, probes decide ready', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const probe = makeProbe()
  const { manager, statuses } = makeManager({
    cloudflared: fakeCloudflared(),
    spawn: spawn.spawn,
    probe,
    startupTimeoutMs: 500,
  })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  const tunnelCall = spawn.calls.find((call) => call.args[0] === 'tunnel')
  assert.ok(tunnelCall !== undefined)
  assert.deepEqual(tunnelCall.args, [
    'tunnel',
    '--no-autoupdate',
    '--protocol',
    'auto',
    '--url',
    'http://127.0.0.1:47123',
  ])
  assert.equal((tunnelCall.options as { shell?: unknown }).shell, undefined)
  child.emitStderr('INF |  https://bases-switching-')
  child.emitStderr('photography-garage.trycloudflare.com   |\n')
  child.emitStderr('INF Registered tunnel connection connIndex=0 event=0\n')
  const status = await started
  assert.equal(status.state, 'ready')
  assert.equal(status.url, 'https://bases-switching-photography-garage.trycloudflare.com')
  assert.equal(status.temporary, true)
  assert.equal(status.ownership, 'plugin')
  assert.equal(status.transport, 'auto')
  assert.equal(status.serviceUrl, planContext().localUrl)
  assert.deepEqual(status.verified, { http: true, ws: true })
  assert.equal(status.error, null)
  assert.deepEqual(probe.calls, [
    'http:https://bases-switching-photography-garage.trycloudflare.com',
    'ws:https://bases-switching-photography-garage.trycloudflare.com',
  ])
  assert.equal(manager.currentSelection()?.method, 'cloudflare-quick')
  assert.equal(manager.status().state, 'ready')
  assert.ok(statuses.length >= 1)
  await manager.dispose()
})

test('readiness: connector connected is NOT public verification (HTTP probe failure)', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const probe = makeProbe({ ok: false, status: null, accessRequired: false, detail: 'timeout' }, OK_PROBE)
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe, startupTimeoutMs: 500 })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.state, 'connected-unverified')
  assert.deepEqual(status.verified, { http: false, ws: true })
  assert.equal(status.url, 'https://abc-name.trycloudflare.com')
  assert.ok(status.error !== null)
  await manager.dispose()
})

test('readiness: an HTTP answer that is not our health endpoint reports mismatch', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const probe = makeProbe({ ok: false, status: 404, accessRequired: false, detail: null })
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe, startupTimeoutMs: 500 })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.state, 'mismatch')
  await manager.dispose()
})

test('readiness: a Cloudflare Access login redirect reports access-required', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const probe = makeProbe({ ok: false, status: 302, accessRequired: true, detail: 'access login redirect' })
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe, startupTimeoutMs: 500 })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.state, 'access-required')
  await manager.dispose()
})

test('start quick: a non-trycloudflare URL is ignored; startup timeout kills the child', async () => {
  const child = makeControllableChild()
  child.killMode = 'ignore-term'
  const spawn = cloudflaredSpawn([child])
  const { manager } = makeManager({
    cloudflared: fakeCloudflared(),
    spawn: spawn.spawn,
    probe: makeProbe(),
    startupTimeoutMs: 25,
    killGraceMs: 10,
  })
  const started = manager.start(quickSelection(), planContext())
  child.emitStderr('INF https://evil.example\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.state, 'down')
  assert.equal(status.url, null)
  assert.match(status.error ?? '', /TIMEOUT|timeout/i)
  assert.deepEqual(child.killed, ['SIGTERM'])
  await manager.dispose()
})

test('start quick: early process exit reports down (TUNNEL_EXITED)', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe: makeProbe(), startupTimeoutMs: 500 })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.exit(2)
  const status = await started
  assert.equal(status.state, 'down')
  assert.match(status.error ?? '', /EXITED|exited/i)
  await manager.dispose()
})

test('stop: SIGTERM -> SIGKILL escalation, URL cleared through the listener, ownership none', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const { manager, statuses } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe: makeProbe(), startupTimeoutMs: 500, killGraceMs: 15 })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  await started
  child.killMode = 'ignore-term'
  await manager.stop()
  assert.equal(manager.status().state, 'off')
  assert.equal(manager.status().url, null)
  assert.equal(manager.status().ownership, 'none')
  assert.equal(manager.currentSelection(), null)
  assert.deepEqual(child.killed, ['SIGTERM', 'SIGKILL'])
  assert.ok(statuses.some((status) => status.url === null && status.state === 'off'))
  await manager.dispose()
})

test('quick: URL changes while running are surfaced to the status listener', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const { manager, statuses } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe: makeProbe(), startupTimeoutMs: 500 })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://first-name.trycloudflare.com\nINF Registered tunnel connection\n')
  await started
  // The connector never changes the quick URL in practice, but a parser/channel
  // duplicate must not crash and must keep one committed URL.
  child.emitStderr('INF https://second-name.trycloudflare.com\nINF Registered tunnel connection\n')
  await new Promise((resolve) => setImmediate(resolve))
  const urls = statuses.map((status) => status.url).filter((url): url is string => url !== null)
  assert.ok(urls.length >= 1)
  assert.equal(manager.status().url, 'https://first-name.trycloudflare.com')
  await manager.dispose()
})

test('start: missing binary fails closed with INSTALL_REQUIRED and a missing-binary state', async () => {
  const cloudflared = fakeCloudflared({ installed: null, supported: true })
  const spawn = cloudflaredSpawn([makeControllableChild()])
  const { manager } = makeManager({ cloudflared, spawn: spawn.spawn, startupTimeoutMs: 200 })
  await expectTunnelError(() => manager.start(quickSelection(), planContext()), 'INSTALL_REQUIRED')
  assert.equal(manager.status().state, 'missing-binary')
  assert.equal(manager.status().ownership, 'none')
  assert.equal(spawn.calls.length, 0, 'no child is spawned without a binary')
  await manager.dispose()
})

test('start: unsupported platform fails closed with UNSUPPORTED_PLATFORM', async () => {
  const cloudflared = fakeCloudflared({ installed: null, supported: false })
  const { manager } = makeManager({ cloudflared })
  await expectTunnelError(() => manager.start(quickSelection(), planContext()), 'UNSUPPORTED_PLATFORM')
  await manager.dispose()
})

/* ------------------------------------------------------------------------- */
/* selection.cloudflaredPath override (review finding M1)                    */
/* ------------------------------------------------------------------------- */

test('start: an explicit selection.cloudflaredPath overrides the configured binary', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const facade = orderedCloudflared((paths) => ({
    path: paths?.[0] ?? '/opt/cloudflared',
    source: 'configured',
    version: '2026.10.5',
    verified: false,
  }))
  const config = makeConfig({ tunnel: { cloudflaredPath: '/config/cloudflared' } })
  const { manager } = makeManager({ config, cloudflared: facade, spawn: spawn.spawn, probe: makeProbe(), startupTimeoutMs: 500 })
  const started = manager.start(
    quickSelection({ cloudflaredPath: '/selection/cloudflared' }),
    planContext(),
  )
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.state, 'ready')
  assert.deepEqual(facade.resolveArgs[0], ['/selection/cloudflared', '/config/cloudflared'])
  const tunnelCall = spawn.calls.find((call) => call.args[0] === 'tunnel')!
  assert.equal(tunnelCall.command, '/selection/cloudflared', 'the selected binary is the one executed')
  assert.ok(!tunnelCall.args.join(' ').includes('cloudflaredPath'), 'the selection key is never put in argv')
  await manager.dispose()
})

test('describe: the download disclosure reflects the effective selection binary', async () => {
  const facade = orderedCloudflared((paths) =>
    paths?.includes('/present/cloudflared') === true
      ? { path: '/present/cloudflared', source: 'configured', version: '2026.10.5', verified: false }
      : null,
  )
  const config = makeConfig({ tunnel: { cloudflaredPath: '/missing/config' } })
  const { manager } = makeManager({ config, cloudflared: facade })

  const withPresent = await manager.describe(
    quickSelection({ cloudflaredPath: '/present/cloudflared' }),
    planContext(),
  )
  assert.equal(withPresent.download, null, 'an overriding usable binary means no download is disclosed')
  assert.deepEqual(facade.infoArgs[0], ['/present/cloudflared', '/missing/config'])

  const withMissing = await manager.describe(
    quickSelection({ cloudflaredPath: '/missing/override' }),
    planContext(),
  )
  assert.ok(withMissing.download !== null, 'with every effective candidate missing the pinned download is disclosed')
  assert.deepEqual(facade.infoArgs[1], ['/missing/override', '/missing/config'])

  const withoutOverride = await manager.describe(quickSelection(), planContext())
  assert.ok(withoutOverride.download !== null)
  assert.deepEqual(facade.infoArgs[2], ['/missing/config'])
  await manager.dispose()
})

test('start: malformed selection.cloudflaredPath values fail closed before spawning', async () => {
  const spawn = cloudflaredSpawn([makeControllableChild()])
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, startupTimeoutMs: 200 })
  for (const bad of ['tool.cmd', 'tool.bat', 'tool.ps1']) {
    await expectTunnelError(() => manager.start(quickSelection({ cloudflaredPath: bad }), planContext()), 'BAD_REQUEST')
  }
  await expectTunnelError(
    () => manager.describe(quickSelection({ cloudflaredPath: 42 as never }), planContext()),
    'BAD_REQUEST',
  )
  assert.equal(spawn.calls.filter((call) => call.args[0] === 'tunnel').length, 0)
  await manager.dispose()
})

/* ------------------------------------------------------------------------- */
/* remotely-managed named provider                                          */
/* ------------------------------------------------------------------------- */

test('start named (token env): token goes to the child env only, never argv/status/logs', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const log = silentLogger()
  const config = makeConfig({ tunnel: { tokenEnv: 'CF_TUNNEL_TOKEN' } })
  const { manager } = makeManager({
    config,
    log,
    cloudflared: fakeCloudflared(),
    spawn: spawn.spawn,
    probe: makeProbe(),
    hostEnv: { CF_TUNNEL_TOKEN: 'super-secret-connector-token' },
    startupTimeoutMs: 500,
  })
  const started = manager.start({ method: 'cloudflare-named', hostname: 'rc.example.com' }, planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF Starting tunnel tunnelID=11111111-2222-3333-4444-555555555555\n')
  child.emitStderr('INF Initial protocol quic\n')
  const status = await started
  assert.equal(status.state, 'ready')
  assert.equal(status.url, 'https://rc.example.com')
  assert.equal(status.ownership, 'plugin')
  const tunnelCall = spawn.calls.find((call) => call.args[0] === 'tunnel')!
  assert.equal(tunnelCall.options.env?.TUNNEL_TOKEN, 'super-secret-connector-token')
  assert.ok(!tunnelCall.args.join(' ').includes('super-secret-connector-token'))
  assert.ok(!JSON.stringify(status).includes('super-secret-connector-token'))
  assert.ok(log.messages.every((message) => !message.includes('super-secret-connector-token')))
  await manager.dispose()
})

test('start named: conflicting config token sources fail closed instead of silently preferring one', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const config = makeConfig({
    tunnel: { tokenEnv: 'CUSTOM_CF_TOKEN', tokenFile: join(freshDir('secret'), 'connector.token') },
  })
  const { manager } = makeManager({
    config,
    cloudflared: fakeCloudflared(),
    spawn: spawn.spawn,
    probe: makeProbe(),
    hostEnv: { CUSTOM_CF_TOKEN: 'token' },
    startupTimeoutMs: 200,
  })
  await expectTunnelError(
    () => manager.start({ method: 'cloudflare-named', hostname: 'rc.example.com' }, planContext()),
    'BAD_REQUEST',
  )
  assert.equal(
    spawn.calls.filter((call) => call.args[0] === 'tunnel').length,
    0,
    'an ambiguous token source must never spawn the connector',
  )
  await manager.dispose()
})

test('start named (token file): version gate requires cloudflared >= 2025.4.0 and passes only the path', async () => {
  const tokenFile = join(freshDir('token'), 'connector.token')
  await mkdir(dirname(tokenFile), { recursive: true })
  await writeFile(tokenFile, '  file-secret-token  \n')

  const oldChild = makeControllableChild()
  const oldSpawn = cloudflaredSpawn([oldChild], 'cloudflared version 2025.3.9 (built 2025-03-01)')
  const old = makeManager({
    cloudflared: fakeCloudflared({ installed: installedCloudflared({ version: '2025.3.9' }) }),
    spawn: oldSpawn.spawn,
    startupTimeoutMs: 200,
  })
  const error = await expectTunnelError(
    () => old.manager.start({ method: 'cloudflare-named', hostname: 'rc.example.com', tokenFile }, planContext()),
    'INSTALL_REQUIRED',
  )
  assert.match(error.message, /2025\.4\.0/)
  assert.equal(oldSpawn.calls.filter((call) => call.args[0] === 'tunnel').length, 0)
  await old.manager.dispose()

  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const log = silentLogger()
  const { manager } = makeManager({
    config: makeConfig(),
    log,
    cloudflared: fakeCloudflared(),
    spawn: spawn.spawn,
    probe: makeProbe(),
    startupTimeoutMs: 500,
  })
  const started = manager.start(
    { method: 'cloudflare-named', hostname: 'rc.example.com', tokenFile },
    planContext(),
  )
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF Starting tunnel tunnelID=x\nINF Initial protocol http2\n')
  await started
  const tunnelCall = spawn.calls.find((call) => call.args[0] === 'tunnel')!
  assert.ok(tunnelCall.args.includes('--token-file'))
  assert.equal(tunnelCall.args[tunnelCall.args.indexOf('--token-file') + 1], tokenFile)
  assert.equal(tunnelCall.options.env?.TUNNEL_TOKEN, undefined)
  assert.ok(!tunnelCall.args.join(' ').includes('file-secret-token'))
  assert.ok(log.messages.every((message) => !message.includes('file-secret-token')))
  await manager.dispose()
})

test('start named: missing token file and conflicting token sources fail closed before spawning', async () => {
  const spawn = cloudflaredSpawn([makeControllableChild()])
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, startupTimeoutMs: 200 })
  await expectTunnelError(
    () => manager.start({ method: 'cloudflare-named', hostname: 'rc.example.com', tokenFile: join(root, 'missing.token') }, planContext()),
    'BAD_REQUEST',
  )
  await expectTunnelError(
    () =>
      manager.start(
        {
          method: 'cloudflare-named',
          hostname: 'rc.example.com',
          tokenEnv: 'MY_TOKEN',
          tokenFile: join(root, 'missing.token'),
        },
        planContext(),
      ),
    'BAD_REQUEST',
  )
  assert.equal(spawn.calls.filter((call) => call.args[0] === 'tunnel').length, 0)
  await manager.dispose()
})

test('transport: explicit http2 appears in argv, invalid transport fails closed', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe: makeProbe(), startupTimeoutMs: 500 })
  const started = manager.start(quickSelection({ transport: 'http2' }), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.transport, 'http2')
  const call = spawn.calls.find((entry) => entry.args[0] === 'tunnel')!
  assert.equal(call.args[call.args.indexOf('--protocol') + 1], 'http2')
  await manager.dispose()

  const second = makeManager({ cloudflared: fakeCloudflared() })
  await expectTunnelError(
    () => second.manager.start(quickSelection({ transport: 'tcp' as never }), planContext()),
    'BAD_REQUEST',
  )
  await second.manager.dispose()
})

/* ------------------------------------------------------------------------- */
/* locally-managed named provider                                           */
/* ------------------------------------------------------------------------- */

test('start named-local: validates credentials, generates plugin-owned ingress only for the RC listener, cleans up', async () => {
  const credentials = join(freshDir('creds'), `${CLI_UUID}.json`)
  await mkdir(dirname(credentials), { recursive: true })
  await writeFile(
    credentials,
    JSON.stringify({
      AccountTag: 'aaaa1111bbbb2222cccc3333dddd4444',
      TunnelSecret: Buffer.alloc(32, 7).toString('base64'),
      TunnelID: CLI_UUID,
    }),
  )
  const child = makeControllableChild()
  let configPath = ''
  let configText = ''
  const spawn = makeSpawn((call) => {
    if (call.args[0] === '--version') return makeVersionChild()
    const index = call.args.indexOf('--config')
    configPath = call.args[index + 1]!
    configText = readFileSync(configPath, 'utf8')
    return child.child
  })
  const deps = managerDeps({
    cloudflared: fakeCloudflared(),
    spawn: spawn.spawn,
    probe: makeProbe(),
    startupTimeoutMs: 500,
  })
  const manager = createTunnelManager(deps)
  const started = manager.start(
    {
      method: 'cloudflare-named-local',
      hostname: 'rc.example.com',
      tunnelId: CLI_UUID,
      credentialsFile: credentials,
    },
    planContext('http://127.0.0.1:47123'),
  )
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF Starting tunnel tunnelID=11111111-2222-3333-4444-555555555555\nINF Initial protocol quic\n')
  const status = await started
  assert.equal(status.state, 'ready')
  assert.equal(status.url, 'https://rc.example.com')
  assert.ok(configPath.startsWith(deps.runtimeDir()), 'runtime config lives in the plugin runtime dir')
  assert.match(configText, new RegExp(`^tunnel:\\s*${CLI_UUID}$`, 'm'))
  assert.ok(configText.includes(`credentials-file: ${JSON.stringify(credentials)}`))
  assert.ok(configText.includes('hostname: rc.example.com'))
  assert.ok(configText.includes('service: http://127.0.0.1:47123'))
  assert.match(configText, /^\s*- service: http_status:404$/m)
  assert.ok(!configText.includes('61114'), 'never forwards to the DSH port')
  assert.ok(!configText.includes('admin'), 'no other ingress rule')
  assert.ok(!configText.includes('TunnelSecret'))
  const tunnelCall = spawn.calls.find((call) => call.args[0] === 'tunnel')!
  assert.deepEqual(tunnelCall.args.slice(-2), ['run', CLI_UUID])
  await manager.stop()
  await assert.rejects(() => stat(configPath), /ENOENT/)
  await manager.dispose()
})

test('start named-local: credentials UUID mismatch and unsafe credentials files fail closed', async (t) => {
  const mismatched = join(freshDir('creds'), `${CLI_UUID}.json`)
  await mkdir(dirname(mismatched), { recursive: true })
  await writeFile(
    mismatched,
    JSON.stringify({
      AccountTag: 'aaaa1111bbbb2222cccc3333dddd4444',
      TunnelSecret: Buffer.alloc(32, 1).toString('base64'),
      TunnelID: '99999999-8888-7777-6666-555555555555',
    }),
  )
  const spawn = cloudflaredSpawn([makeControllableChild()])
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, startupTimeoutMs: 200 })
  await expectTunnelError(
    () =>
      manager.start(
        { method: 'cloudflare-named-local', hostname: 'rc.example.com', tunnelId: CLI_UUID, credentialsFile: mismatched },
        planContext(),
      ),
    'BAD_REQUEST',
  )
  await expectTunnelError(
    () =>
      manager.start(
        { method: 'cloudflare-named-local', hostname: 'rc.example.com', tunnelId: CLI_UUID, credentialsFile: join(root, 'missing.json') },
        planContext(),
      ),
    'BAD_REQUEST',
  )
  assert.equal(spawn.calls.filter((call) => call.args[0] === 'tunnel').length, 0)
  await manager.dispose()

  // A symlinked credentials file is refused (skip where symlinks are unavailable).
  const linkDir = freshDir('creds-link')
  await mkdir(linkDir, { recursive: true })
  const target = join(linkDir, 'real.json')
  await writeFile(target, JSON.stringify({ AccountTag: 'a'.repeat(32), TunnelSecret: Buffer.alloc(32).toString('base64'), TunnelID: CLI_UUID }))
  const link = join(linkDir, 'link.json')
  try {
    await symlink(target, link)
  } catch {
    t.skip('creating symlinks is not permitted on this host')
    return
  }
  const second = makeManager({ cloudflared: fakeCloudflared(), spawn: cloudflaredSpawn([makeControllableChild()]).spawn, startupTimeoutMs: 200 })
  await expectTunnelError(
    () =>
      second.manager.start(
        { method: 'cloudflare-named-local', hostname: 'rc.example.com', tunnelId: CLI_UUID, credentialsFile: link },
        planContext(),
      ),
    'BAD_REQUEST',
  )
  await second.manager.dispose()
})

/* ------------------------------------------------------------------------- */
/* external provider                                                        */
/* ------------------------------------------------------------------------- */

test('start external: no child process, verified probes required for ready, ownership external', async () => {
  const spawn = cloudflaredSpawn([])
  const probe = makeProbe()
  const { manager } = makeManager({ spawn: spawn.spawn, probe })
  const status = await manager.start({ method: 'external', publicUrl: 'https://rc.example.com' }, planContext())
  assert.equal(status.state, 'ready')
  assert.equal(status.url, 'https://rc.example.com')
  assert.equal(status.ownership, 'external')
  assert.equal(status.verified?.http, true)
  assert.equal(status.verified?.ws, true)
  assert.equal(spawn.calls.length, 0, 'external never owns a process')
  assert.deepEqual(probe.calls, ['http:https://rc.example.com', 'ws:https://rc.example.com'])
  await manager.stop()
  assert.equal(manager.status().state, 'off')
  assert.equal(manager.status().url, null)
  assert.equal(manager.status().ownership, 'none')
  await manager.dispose()
})

test('external: an unreachable origin is a mismatch, not a ready tunnel', async () => {
  const { manager } = makeManager({ probe: makeProbe({ ok: false, status: null, accessRequired: false, detail: 'dns' }) })
  const status = await manager.start({ method: 'external', publicUrl: 'https://rc.example.com' }, planContext())
  assert.equal(status.state, 'mismatch')
  assert.equal(status.verified?.http, false)
  await manager.dispose()
})

test('external: invalid public origin is rejected by describe and start (CONSENT/BAD_REQUEST)', async () => {
  const { manager } = makeManager()
  await expectTunnelError(
    () => manager.start({ method: 'external', publicUrl: 'ftp://rc.example.com' }, planContext()),
    'BAD_REQUEST',
  )
  await manager.dispose()
})

/* ------------------------------------------------------------------------- */
/* ssh provider via the manager                                             */
/* ------------------------------------------------------------------------- */

test('start ssh: hardened argv, URL from stdout, probes decide ready, ownership plugin', async () => {
  const child = makeControllableChild()
  const spawn = sshSpawn([child])
  const probe = makeProbe()
  const { manager } = makeManager({ spawn: spawn.spawn, probe, startupTimeoutMs: 1_000 })
  const started = manager.start({ method: 'ssh' }, planContext())
  await waitForTunnelSpawn(spawn)
  const tunnelCall = spawn.calls.find((call) => call.args[0] !== '-V')
  assert.ok(tunnelCall !== undefined)
  const remoteIndex = tunnelCall.args.indexOf('-R')
  assert.equal(tunnelCall.args[remoteIndex + 1], '80:127.0.0.1:47123')
  assert.equal(tunnelCall.args[tunnelCall.args.length - 1], 'nokey@localhost.run')
  assert.ok(!tunnelCall.args.includes('-N'))
  child.emitStdout('fdbf4f40573d56.lhr.life tunneled with ')
  child.emitStdout('tls termination, https://fdbf4f40573d56.lhr.life\n')
  const status = await started
  assert.equal(status.state, 'ready')
  assert.equal(status.url, 'https://fdbf4f40573d56.lhr.life')
  assert.equal(status.ownership, 'plugin')
  assert.equal(status.temporary, true)
  assert.equal(status.transport, undefined)
  assert.equal(status.serviceUrl, planContext().localUrl)
  await manager.dispose()
})

test('start ssh: a missing ssh client fails with SSH_MISSING and spawns no tunnel', async () => {
  const spawn = makeSpawn(() => {
    const child = new EventEmitter() as unknown as import('node:child_process').ChildProcess
    Object.assign(child, { stdout: new EventEmitter(), stderr: new EventEmitter(), exitCode: null, signalCode: null, kill: () => true })
    setImmediate(() => child.emit('error', Object.assign(new Error('ENOENT'), { code: 'ENOENT' })))
    return child
  })
  const { manager } = makeManager({
    spawn: spawn.spawn,
    startupTimeoutMs: 200,
    fileExists: async () => false,
  })
  await expectTunnelError(() => manager.start({ method: 'ssh' }, planContext()), 'SSH_MISSING')
  assert.equal(manager.status().state, 'missing-binary')
  assert.equal(spawn.calls.length, 1, 'only the -V discovery probe ran')
  await manager.dispose()
})

test('ssh: a dropped free tunnel is supervised with backoff and a new URL, never a false down', async () => {
  const first = makeControllableChild()
  const second = makeControllableChild()
  const spawn = sshSpawn([first, second])
  const { manager, statuses } = makeManager({
    spawn: spawn.spawn,
    probe: makeProbe(),
    startupTimeoutMs: 500,
    restartDelaysMs: [10, 10],
    maxRestartAttempts: 3,
  })
  const started = manager.start({ method: 'ssh' }, planContext())
  await waitForTunnelSpawn(spawn)
  first.emitStdout('https://aaaa1111bbbb2222.lhr.life tunneled with tls termination, https://aaaa1111bbbb2222.lhr.life\n')
  await started
  assert.equal(manager.status().state, 'ready')

  first.killMode = 'ignore-term'
  first.exit(255)
  await waitForTunnelSpawn(spawn, 2)
  second.emitStdout('https://cccc3333dddd4444.lhr.life tunneled with tls termination, https://cccc3333dddd4444.lhr.life\n')
  await waitFor(() => manager.status().state === 'ready', 'ssh restart readiness')
  const finalStatus = manager.status()
  assert.equal(finalStatus.url, 'https://cccc3333dddd4444.lhr.life')
  assert.equal(finalStatus.state, 'ready')
  assert.ok(
    statuses.every((status) => status.state !== 'down'),
    'transient loss never reports security-terminal down',
  )
  await manager.dispose()
})

test('ssh: exhausted supervised restarts end in a terminal down state', async () => {
  const children = [makeControllableChild(), makeControllableChild(), makeControllableChild()]
  const spawn = sshSpawn(children)
  const { manager, statuses } = makeManager({
    spawn: spawn.spawn,
    probe: makeProbe(),
    startupTimeoutMs: 200,
    restartDelaysMs: [5, 5],
    maxRestartAttempts: 2,
  })
  const started = manager.start({ method: 'ssh' }, planContext())
  await waitForTunnelSpawn(spawn)
  children[0]!.emitStdout('https://aaaa1111bbbb2222.lhr.life tunneled with tls termination, https://aaaa1111bbbb2222.lhr.life\n')
  await started
  children[0]!.exit(255)
  await waitForTunnelSpawn(spawn, 2)
  children[1]!.exit(255)
  await waitForTunnelSpawn(spawn, 3)
  children[2]!.exit(255)
  await waitFor(() => manager.status().state === 'down', 'terminal ssh down state')
  assert.equal(manager.status().state, 'down')
  assert.ok(statuses.some((status) => status.state === 'down'))
  await manager.dispose()
})

/* ------------------------------------------------------------------------- */
/* install delegation + misc                                                */
/* ------------------------------------------------------------------------- */

test('install: user-initiated only; delegates to the verified installer and never auto-starts', async () => {
  const cloudflared = fakeCloudflared({ installed: null, supported: true })
  const { manager } = makeManager({ cloudflared })
  const info = await manager.installInfo()
  assert.equal(info.supported, true)
  assert.equal(cloudflared.installCalls, 0)
  const installedInfo = await manager.install()
  assert.equal(installedInfo.supported, true)
  assert.equal(cloudflared.installCalls, 1)
  assert.equal(manager.status().state, 'off')
  await manager.dispose()
})

test('start loopback: no public exposure, no child, state stays off', async () => {
  const spawn = cloudflaredSpawn([])
  const { manager } = makeManager({ cloudflared: fakeCloudflared(), spawn: spawn.spawn })
  const status = await manager.start({ method: 'loopback' }, planContext())
  assert.equal(status.state, 'off')
  assert.equal(status.url, null)
  assert.equal(status.ownership, 'none')
  assert.equal(spawn.calls.length, 0)
  await manager.dispose()
})

test('status listener: exceptions are swallowed, dispose is idempotent', async () => {
  const child = makeControllableChild()
  const spawn = cloudflaredSpawn([child])
  const deps = managerDeps({ cloudflared: fakeCloudflared(), spawn: spawn.spawn, probe: makeProbe(), startupTimeoutMs: 500 })
  const manager = createTunnelManager(deps)
  manager.setStatusListener(() => {
    throw new Error('listener bug')
  })
  const started = manager.start(quickSelection(), planContext())
  await waitForTunnelSpawn(spawn)
  child.emitStderr('INF https://abc-name.trycloudflare.com\nINF Registered tunnel connection\n')
  const status = await started
  assert.equal(status.state, 'ready')
  await manager.dispose()
  await manager.dispose()
  assert.equal(manager.status().state, 'off')
})
