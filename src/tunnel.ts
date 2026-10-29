/**
 * TunnelManager: owns every provider-specific public-reachability detail for the
 * plugin. The controller owns the listener lifecycle, origin fencing, QR/cookie
 * computation and the safe shutdown; this module never talks to DSH.
 *
 * Providers (`ConnectionSelection.method`):
 * - `cloudflare-quick`: token-free managed `cloudflared` quick tunnel; temporary
 *   `https://*.trycloudflare.com` origin; connector ready != public verified.
 * - `cloudflare-named`: remotely-managed Cloudflare tunnel via a connector token
 *   from an env var (child env `TUNNEL_TOKEN` only) or a token file
 *   (`--token-file`, cloudflared >= 2025.4.0). The public hostname is configured
 *   in Cloudflare; the local service must be reachable at the fixed loopback
 *   port chosen by the plan.
 * - `cloudflare-named-local`: locally-managed tunnel (UUID + credentials JSON);
 *   the plugin generates its own runtime config with one ingress rule
 *   `hostname -> http://127.0.0.1:<port>` and the mandatory final
 *   `http_status: 404`; runs `cloudflared tunnel --config <cfg> run <UUID>`.
 * - `external`: operator-managed connector/service; no child process owned.
 * - `ssh`: managed OpenSSH reverse tunnel via localhost.run (nokey@localhost.run,
 *   `-R 80:127.0.0.1:<port>`), with a plugin-private known_hosts (TOFU) and
 *   supervised restarts with capped backoff (free tunnels drop).
 *
 * Managed Cloudflare/SSH providers always forward to the actual listener passed
 * in `TunnelPlanContext.localUrl`; only remotely-managed named and external use a
 * fixed loopback port. Readiness: a connector "registered" line is reported as
 * `connected-unverified`; only bounded HTTP + WS probes against the configured
 * public origin may produce `ready`, and they are reported separately in
 * `verified{http,ws}`.
 */

import { spawn as nodeSpawn, type ChildProcess } from 'node:child_process'
import { randomBytes as defaultRandomBytes } from 'node:crypto'

import type {
  Logger,
  TunnelManager,
  TunnelPlanContext,
  TunnelProviderPlan,
} from './shared/internal.js'
import type {
  CloudflaredDownloadInfo,
  ConnectionPlanStep,
  ConnectionSelection,
  TunnelMode,
  TunnelState,
  TunnelStatus,
  TunnelTransport,
} from './shared/protocol.js'
import {
  PINNED_CLOUDFLARED_RELEASE,
  buildCloudflaredArgs,
  createCloudflaredInstaller,
  createCloudflaredOutputParser,
  versionAtLeast,
  type CloudflaredFacade,
  type CloudflaredOutputParser,
} from './cloudflared.js'
import type { RemoteControlConfig } from './config.js'
import { DEFAULT_TUNNEL_TOKEN_ENV } from './config.js'
import {
  buildCloudflaredConfig,
  cleanRuntimeDirectory,
  normalizeHostname,
  normalizeHttpsOrigin,
  normalizeUuid,
  readCredentialsFile,
  readTokenFile,
  removeFileQuietly,
  validateCredentialsObject,
  writePrivateRuntimeFile,
} from './tunnel-config.js'
import { TunnelError, errorMessage, isTunnelError } from './tunnel-errors.js'
import {
  assertExecutableNotShim,
  buildChildEnv,
  terminateChild,
  type FetchLike,
  type SpawnFn,
} from './tunnel-process.js'
import { createTunnelProbe, type ProbeResult, type TunnelProbe } from './tunnel-probe.js'
import {
  createSshTunnel,
  discoverSsh,
  ensureKnownHosts,
  normalizeSshHost,
  normalizeSshUser,
  validateSshRemotePort,
  type SshTunnelHandle,
} from './ssh.js'

/* ------------------------------------------------------------------------- */
/* Public factory contract                                                   */
/* ------------------------------------------------------------------------- */

export interface TunnelManagerDeps {
  config: RemoteControlConfig
  log: Logger
  /** Plugin-private directory for the verified cloudflared binary cache. */
  managedDir(): string
  /** Plugin-private directory for generated configs and the SSH known_hosts. */
  runtimeDir(): string
  /* Optional seams (tests, feature toggles); production omits them. */
  spawn?: SpawnFn
  fetch?: FetchLike
  now?: () => number
  randomBytes?: (size: number) => Buffer
  platform?: NodeJS.Platform | string
  arch?: string
  hostEnv?: NodeJS.ProcessEnv
  probe?: TunnelProbe
  cloudflared?: CloudflaredFacade
  startupTimeoutMs?: number
  killGraceMs?: number
  probeTimeoutMs?: number
  /** Set false to never mark a tunnel `ready` (e.g. offline diagnostics). */
  verify?: boolean
  restartDelaysMs?: number[]
  maxRestartAttempts?: number
  fileExists?: (path: string) => Promise<boolean>
}

export interface ManagedTunnelManager extends TunnelManager {
  /** Observe every committed status change (URL change, loss, reconnect). */
  setStatusListener(listener: (status: TunnelStatus) => void): void
}

/* ------------------------------------------------------------------------- */
/* Internal provider resolution                                              */
/* ------------------------------------------------------------------------- */

type ProviderKind = 'loopback' | 'lan' | 'quick' | 'named' | 'named-local' | 'external' | 'ssh'

interface ResolvedProvider {
  method: ConnectionSelection['method']
  kind: ProviderKind
  mode: TunnelMode
  selection: ConnectionSelection
  temporary: boolean
  fixedLoopbackPort: boolean
  accessRequired: boolean
  hostname: string | null
  publicOrigin: string | null
  transport: TunnelTransport | undefined
  tokenSource: { kind: 'env'; envName: string } | { kind: 'file'; path: string } | null
  tokenEnvValue: string | null
  configFile: string | null
  tunnelId: string | null
  credentialsFile: string | null
  sshPath: string
  sshHost: string
  sshUser: string
  sshRemotePort: number
}

const METHODS = new Set<ConnectionSelection['method']>([
  'loopback',
  'lan',
  'cloudflare-quick',
  'cloudflare-named',
  'cloudflare-named-local',
  'external',
  'ssh',
])
const TRANSPORTS: ReadonlySet<string> = new Set(['auto', 'quic', 'http2'])
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/
const CLOUDFLARED_TOKEN_FILE_MIN_VERSION = '2025.4.0'
const DEFAULT_KILL_GRACE_MS = 2_000
const DEFAULT_PROBE_TIMEOUT_MS = 5_000
const DEFAULT_RESTART_DELAYS = [1_000, 2_000, 4_000, 8_000, 15_000]
const DEFAULT_MAX_RESTART_ATTEMPTS = 5

function modeForMethod(method: ConnectionSelection['method'], fallback: TunnelMode): TunnelMode {
  switch (method) {
    case 'loopback':
    case 'lan':
      return fallback
    case 'cloudflare-quick':
      return 'quick'
    case 'cloudflare-named':
      return 'named'
    case 'cloudflare-named-local':
      return 'named-local'
    case 'external':
      return 'external'
    case 'ssh':
      return 'ssh'
  }
}

function offStatus(mode: TunnelMode): TunnelStatus {
  return {
    enabled: false,
    mode,
    state: 'off',
    url: null,
    temporary: mode === 'quick' || mode === 'ssh',
    ownership: 'none',
    transport: undefined,
    serviceUrl: null,
    verified: { http: false, ws: false },
    error: null,
    detail: null,
  }
}

function cloneStatus(status: TunnelStatus): TunnelStatus {
  return { ...status, verified: { ...status.verified! } }
}

function isFixedHostnameMethod(method: ConnectionSelection['method']): boolean {
  return method === 'cloudflare-named' || method === 'cloudflare-named-local' || method === 'external'
}

interface VerificationOutcome {
  state: TunnelState
  verified: { http: boolean; ws: boolean }
  error: string | null
  detail: string | null
}

/* ------------------------------------------------------------------------- */
/* Factory                                                                   */
/* ------------------------------------------------------------------------- */

export function createTunnelManager(deps: TunnelManagerDeps): ManagedTunnelManager {
  const log = deps.log
  const config = deps.config
  const now = deps.now ?? Date.now
  const randomBytes = deps.randomBytes ?? defaultRandomBytes
  const platform = String(deps.platform ?? process.platform)
  const arch = String(deps.arch ?? process.arch)
  const hostEnv = deps.hostEnv ?? process.env
  const spawn: SpawnFn = deps.spawn ?? (nodeSpawn as unknown as SpawnFn)
  const startupTimeoutMs =
    deps.startupTimeoutMs ?? Math.max(1, config.tunnel.startupTimeoutSeconds) * 1_000
  const killGraceMs = deps.killGraceMs ?? DEFAULT_KILL_GRACE_MS
  const probeTimeoutMs = deps.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS
  const verifyEnabled = deps.verify ?? true
  const restartDelays = deps.restartDelaysMs ?? DEFAULT_RESTART_DELAYS
  const maxRestartAttempts = deps.maxRestartAttempts ?? DEFAULT_MAX_RESTART_ATTEMPTS
  const cacheDirectory = deps.managedDir()
  const runtimeDirectory = deps.runtimeDir()
  const cloudflared: CloudflaredFacade =
    deps.cloudflared ??
    createCloudflaredInstaller({
      configuredPath: config.tunnel.cloudflaredPath,
      cacheDir: cacheDirectory,
      platform,
      arch,
      log,
      env: hostEnv,
      spawn,
      fetch: deps.fetch,
      randomBytes,
      now,
      fileExists: deps.fileExists,
    })
  const probe: TunnelProbe =
    deps.probe ?? createTunnelProbe({ fetch: deps.fetch, timeoutMs: probeTimeoutMs })

  let status: TunnelStatus = offStatus(config.tunnel.mode)
  let selection: ConnectionSelection | null = null
  let context: TunnelPlanContext | null = null
  let resolved: ResolvedProvider | null = null
  let started = false
  let stopped = false
  let disposed = false
  let statusListener: ((value: TunnelStatus) => void) | null = null

  let child: ChildProcess | null = null
  let outputParser: CloudflaredOutputParser | null = null
  let sshTunnel: SshTunnelHandle | null = null
  let runtimeConfigPath: string | null = null

  let startupTimer: NodeJS.Timeout | null = null
  let startSettled = true
  let settleConnector: (() => void) | null = null
  let startPromise: Promise<TunnelStatus> | null = null

  let restartAttempt = 0
  let restartTimer: NodeJS.Timeout | null = null
  let settleRestart: (() => void) | null = null


  /* ----------------------------------------------------------------------- */
  /* Status plumbing                                                         */
  /* ----------------------------------------------------------------------- */

  const notify = (): void => {
    const listener = statusListener
    if (listener === null) return
    try {
      listener(cloneStatus(status))
    } catch {
      log.warn('tunnel status listener threw; ignoring')
    }
  }

  const commit = (next: TunnelStatus): TunnelStatus => {
    status = next
    notify()
    return cloneStatus(status)
  }

  const snapshot = (): TunnelStatus => cloneStatus(status)

  const clearStartupTimer = (): void => {
    if (startupTimer !== null) {
      clearTimeout(startupTimer)
      startupTimer = null
    }
  }

  const clearRestartTimer = (): void => {
    if (restartTimer !== null) {
      clearTimeout(restartTimer)
      restartTimer = null
    }
    const settle = settleRestart
    settleRestart = null
    settle?.()
  }

  const waitForRestart = (delayMs: number): Promise<void> =>
    new Promise<void>((resolve) => {
      settleRestart = resolve
      restartTimer = setTimeout(() => {
        restartTimer = null
        settleRestart = null
        resolve()
      }, Math.max(0, delayMs))
      restartTimer.unref()
    })

  const baseStatus = (mode: TunnelMode): TunnelStatus => ({
    ...offStatus(mode),
    temporary: mode === 'quick' || mode === 'ssh',
  })

  /* ----------------------------------------------------------------------- */
  /* Selection + plan resolution                                             */
  /* ----------------------------------------------------------------------- */

  const resolveTransport = (input: ConnectionSelection): TunnelTransport => {
    const transport = input.transport ?? config.tunnel.transport
    if (!TRANSPORTS.has(transport)) {
      throw new TunnelError('BAD_REQUEST', 'unsupported connector transport (auto|quic|http2 only)')
    }
    return transport
  }

  const resolveProvider = (input: ConnectionSelection): ResolvedProvider => {
    if (input === null || typeof input !== 'object') {
      throw new TunnelError('BAD_REQUEST', 'a connection selection is required')
    }
    const method = input.method
    if (typeof method !== 'string' || !METHODS.has(method)) {
      throw new TunnelError('BAD_REQUEST', 'unknown connection method')
    }
    const mode = modeForMethod(method, config.tunnel.mode)
    const accessRequired = input.accessRequired ?? config.tunnel.access.required
    const base: ResolvedProvider = {
      method,
      kind: 'loopback',
      mode,
      selection: { ...input, method },
      temporary: mode === 'quick' || mode === 'ssh',
      fixedLoopbackPort: false,
      accessRequired,
      hostname: null,
      publicOrigin: null,
      transport: undefined,
      tokenSource: null,
      tokenEnvValue: null,
      configFile: null,
      tunnelId: null,
      credentialsFile: null,
      sshPath: config.tunnel.sshPath,
      sshHost: config.tunnel.sshHost,
      sshUser: config.tunnel.sshUser,
      sshRemotePort: config.tunnel.sshRemotePort,
    }
    switch (method) {
      case 'loopback':
      case 'lan':
        base.kind = method
        base.temporary = false
        if (accessRequired) {
          throw new TunnelError('BAD_REQUEST', 'Cloudflare Access applies only to fixed-hostname tunnel providers')
        }
        return base
      case 'cloudflare-quick': {
        base.kind = 'quick'
        base.transport = resolveTransport(input)
        if (accessRequired) {
          throw new TunnelError('BAD_REQUEST', 'Cloudflare Access cannot protect a temporary quick-tunnel hostname')
        }
        return base
      }
      case 'cloudflare-named': {
        base.kind = 'named'
        base.fixedLoopbackPort = true
        base.transport = resolveTransport(input)
        const hostname = normalizeHostname(input.hostname ?? config.tunnel.hostname)
        if (hostname === null) throw new TunnelError('BAD_REQUEST', 'a bare fixed public hostname is required')
        base.hostname = hostname
        base.publicOrigin = `https://${hostname}`
        const selectionEnv = (input.tokenEnv ?? '').trim()
        const selectionFile = (input.tokenFile ?? '').trim()
        if (selectionEnv !== '' && selectionFile !== '') {
          throw new TunnelError('BAD_REQUEST', 'connector token sources are mutually exclusive (tokenEnv XOR tokenFile)')
        }
        const configEnv = config.tunnel.tokenEnv.trim()
        const configFile = config.tunnel.tokenFile.trim()
        if (
          selectionFile === '' &&
          selectionEnv === '' &&
          configFile !== '' &&
          configEnv !== '' &&
          configEnv !== DEFAULT_TUNNEL_TOKEN_ENV
        ) {
          // The config-level sources are used for this run; setting both an
          // explicit token variable and a token file is ambiguous, so fail closed
          // instead of silently preferring one.
          throw new TunnelError(
            'BAD_REQUEST',
            'config connector token sources are mutually exclusive (set either tokenEnv or tokenFile)',
          )
        }
        if (selectionFile !== '') {
          base.tokenSource = { kind: 'file', path: selectionFile }
        } else if (configFile !== '' && selectionEnv === '') {
          base.tokenSource = { kind: 'file', path: configFile }
        } else {
          const envName = (selectionEnv || configEnv || 'TUNNEL_TOKEN').trim()
          if (!ENV_NAME.test(envName)) {
            throw new TunnelError('BAD_REQUEST', 'the connector token environment variable name is invalid')
          }
          base.tokenSource = { kind: 'env', envName }
        }
        return base
      }
      case 'cloudflare-named-local': {
        base.kind = 'named-local'
        base.transport = resolveTransport(input)
        const hostname = normalizeHostname(input.hostname ?? config.tunnel.hostname)
        if (hostname === null) throw new TunnelError('BAD_REQUEST', 'a bare fixed public hostname is required')
        const tunnelId = normalizeUuid(input.tunnelId ?? config.tunnel.tunnelId)
        if (tunnelId === null) throw new TunnelError('BAD_REQUEST', 'a concrete tunnel UUID is required')
        const credentialsFile = (input.credentialsFile ?? config.tunnel.credentialsFile).trim()
        if (credentialsFile === '') throw new TunnelError('BAD_REQUEST', 'the tunnel credentials file is required')
        base.hostname = hostname
        base.publicOrigin = `https://${hostname}`
        base.tunnelId = tunnelId
        base.credentialsFile = credentialsFile
        return base
      }
      case 'external': {
        base.kind = 'external'
        base.fixedLoopbackPort = true
        const origin = normalizeHttpsOrigin(input.publicUrl ?? config.tunnel.publicUrl)
        if (origin === null) {
          throw new TunnelError('BAD_REQUEST', 'a fixed https public origin without path/query is required')
        }
        base.publicOrigin = origin
        return base
      }
      case 'ssh': {
        base.kind = 'ssh'
        base.sshPath = (input.sshPath ?? config.tunnel.sshPath).trim() || 'ssh'
        const sshHost = normalizeSshHost(input.sshHost ?? config.tunnel.sshHost)
        if (sshHost === null) throw new TunnelError('BAD_REQUEST', 'the SSH host must be an allowed localhost.run host')
        const sshUser = normalizeSshUser(input.sshUser ?? config.tunnel.sshUser)
        if (sshUser === null) throw new TunnelError('BAD_REQUEST', 'the SSH user must be "nokey" for localhost.run')
        const sshRemotePort = validateSshRemotePort(input.sshRemotePort ?? config.tunnel.sshRemotePort)
        if (sshRemotePort === null) throw new TunnelError('BAD_REQUEST', 'the SSH remote port must be 80 or 443')
        base.sshPath = base.sshPath
        base.sshHost = sshHost
        base.sshUser = sshUser
        base.sshRemotePort = sshRemotePort
        if (accessRequired) {
          throw new TunnelError('BAD_REQUEST', 'Cloudflare Access cannot protect a localhost.run SSH origin')
        }
        return base
      }
    }
  }

  const sessionDescription = (provider: ResolvedProvider, ctx: TunnelPlanContext): string => {
    switch (provider.kind) {
      case 'quick':
        return `Run cloudflared quick tunnel forwarding only to the plugin listener at ${ctx.localUrl}.`
      case 'named':
        return `Run the Cloudflare connector with the token from ${provider.tokenSource?.kind === 'file' ? 'the configured token file' : `environment variable ${provider.tokenSource?.envName ?? ''}`}; Cloudflare ingress must point ${provider.hostname} at the fixed loopback port.`
      case 'named-local':
        return `Run cloudflared for tunnel ${provider.tunnelId} with a plugin-owned config that publishes only ${provider.hostname} -> ${ctx.localUrl}.`
      case 'external':
        return `Advertise the operator-managed public origin ${provider.publicOrigin}; the plugin does not own that connector process.`
      case 'ssh':
        return `Run OpenSSH (${provider.sshUser}@${provider.sshHost}) reverse-forwarding port ${provider.sshRemotePort} to the plugin listener at ${ctx.localUrl}.`
      default:
        return `No public tunnel is started; the plugin listener stays on the selected ${provider.kind} access.`
    }
  }

  const providerWarnings = (provider: ResolvedProvider, ctx: TunnelPlanContext): string[] => {
    const warnings: string[] = []
    switch (provider.kind) {
      case 'quick':
        warnings.push(
          'Quick tunnels are temporary: the hostname changes on every start and Cloudflare gives no uptime guarantee; do not use it for durable remote access.',
        )
        break
      case 'named':
        warnings.push(
          'A registered connector does not prove that the public hostname points at this listener; only the bounded probes report that separately.',
        )
        if (ctx.listener.port === 0) {
          warnings.push(
            'The Cloudflare ingress configured for this tunnel must target the fixed loopback port; a dynamic port cannot be assumed to match.',
          )
        }
        break
      case 'named-local':
        warnings.push(
          'The plugin generates its own cloudflared config and never reads or modifies your global ~/.cloudflared config.',
        )
        break
      case 'external':
        warnings.push(
          'The external connector/service is not owned by the plugin: emergency stop only closes the local listener and never kills that process.',
        )
        break
      case 'ssh':
        warnings.push(
          'The localhost.run host key is trusted on first use (TOFU) in a plugin-owned known_hosts file; it is not pre-verified.',
        )
        warnings.push(
          'Free localhost.run tunnels are best-effort and periodically drop; the manager supervises restarts with backoff.',
        )
        break
      default:
        break
    }
    if (provider.accessRequired) {
      warnings.push(
        'Cloudflare Access login is enforced in addition to the plugin authentication; only the Cf-Access-Jwt-Assertion header can be trusted at the origin.',
      )
    }
    return warnings
  }

  /**
   * Ordered cloudflared binary candidates: the desktop panel's explicit
   * selection first, then the configured path. A malformed selection fails
   * closed before anything is spawned (no shell is ever used, so Windows
   * `.cmd/.bat/.ps1` shims are refused). The cloudflared argv never carries
   * this value; it only selects the executable.
   */
  const cloudflaredCandidates = (input: ConnectionSelection): string[] => {
    const candidates: string[] = []
    const selected = input.cloudflaredPath
    if (selected !== undefined) {
      if (typeof selected !== 'string') {
        throw new TunnelError('BAD_REQUEST', 'the cloudflared path selection must be a string')
      }
      const trimmed = selected.trim()
      if (trimmed !== '') {
        assertExecutableNotShim(trimmed)
        candidates.push(trimmed)
      }
    }
    const configured = config.tunnel.cloudflaredPath.trim()
    if (configured !== '' && !candidates.includes(configured)) candidates.push(configured)
    return candidates
  }

  const buildPlanSteps = (provider: ResolvedProvider, ctx: TunnelPlanContext): ConnectionPlanStep[] => {
    const steps: ConnectionPlanStep[] = [
      {
        kind: 'tunnel',
        text: sessionDescription(provider, ctx),
        params: { method: provider.method, serviceUrl: ctx.localUrl },
      },
    ]
    steps.push({
      kind: 'security',
      text: 'Provider child processes are launched as executable+argv only (no shell), with a minimal environment; connector tokens are never placed in argv, the config, the QR code or logs.',
    })
    if (provider.kind === 'named-local') {
      steps.push({
        kind: 'origin',
        text: `Generate a plugin-owned cloudflared runtime config with ingress ${provider.hostname} -> ${ctx.localUrl} and a final http_status:404 catch-all.`,
        params: { hostname: provider.hostname, serviceUrl: ctx.localUrl },
      })
    }
    if (provider.publicOrigin !== null) {
      steps.push({
        kind: 'origin',
        text: `The public HTTPS origin is ${provider.publicOrigin}; the pairing QR code and Host/Origin fences bind to it.`,
        params: { publicOrigin: provider.publicOrigin },
      })
    }
    return steps
  }

  /* ----------------------------------------------------------------------- */
  /* Readiness verification                                                  */
  /* ----------------------------------------------------------------------- */

  const verifyOrigin = async (
    origin: string,
    connectivity: 'connector' | 'external',
  ): Promise<VerificationOutcome> => {
    const httpPromise = probe.http(origin, probeTimeoutMs).catch(
      (error: unknown): ProbeResult => ({ ok: false, status: null, accessRequired: false, detail: errorMessage(error) }),
    )
    const wsPromise = probe.ws(origin, probeTimeoutMs).catch(
      (error: unknown): ProbeResult => ({ ok: false, status: null, accessRequired: false, detail: errorMessage(error) }),
    )
    const [http, ws] = await Promise.all([httpPromise, wsPromise])
    const verified = { http: http.ok, ws: ws.ok }
    if (http.accessRequired || ws.accessRequired) {
      return {
        state: 'access-required',
        verified,
        error: 'Cloudflare Access login is required before this origin is reachable',
        detail: 'Access login redirect detected',
      }
    }
    if (http.ok && ws.ok) return { state: 'ready', verified, error: null, detail: null }
    if (connectivity === 'external') {
      return {
        state: 'mismatch',
        verified,
        error: 'the operator-provided public origin did not reach this plugin listener',
        detail: `HTTP ${http.ok ? 'ok' : (http.status ?? 'failed')}; WebSocket ${ws.ok ? 'ok' : (ws.status ?? 'failed')}`,
      }
    }
    const answered = http.status !== null && !http.ok
    if (answered) {
      return {
        state: 'mismatch',
        verified,
        error: 'the public origin answered, but not with this plugin listener; DNS/ingress/port may point elsewhere',
        detail: `HTTP ${http.status}; WebSocket ${ws.status ?? 'failed'}`,
      }
    }
    return {
      state: 'connected-unverified',
      verified,
      error: 'the connector is connected but the public route could not be verified yet',
      detail: `HTTP ${http.detail ?? 'failed'}; WebSocket ${ws.detail ?? 'failed'}`,
    }
  }

  const commitVerification = (origin: string | null, outcome: VerificationOutcome): TunnelStatus =>
    commit({
      ...status,
      enabled: true,
      state: outcome.state,
      url: origin,
      serviceUrl: context?.localUrl ?? status.serviceUrl ?? null,
      ownership: resolved?.kind === 'external' ? 'external' : 'plugin',
      verified: outcome.verified,
      error: outcome.error,
      detail: outcome.detail,
    })

  const verifyAndCommit = async (origin: string, connectivity: 'connector' | 'external'): Promise<void> => {
    commit({
      ...status,
      enabled: true,
      state: 'connected-unverified',
      url: origin,
      verified: { http: false, ws: false },
      error: null,
      detail: 'connector connected; verifying the public route with bounded probes',
    })
    if (!verifyEnabled) {
      commit({ ...status, detail: 'public route verification is disabled in this configuration' })
      return
    }
    const outcome = await verifyOrigin(origin, connectivity)
    commitVerification(origin, outcome)
  }

  /* ----------------------------------------------------------------------- */
  /* cloudflared providers                                                   */
  /* ----------------------------------------------------------------------- */

  const failMissingBinary = (message: string): never => {
    commit({
      ...status,
      enabled: false,
      state: 'missing-binary',
      url: null,
      ownership: 'none',
      verified: { http: false, ws: false },
      error: message,
      detail: null,
    })
    throw new TunnelError('INSTALL_REQUIRED', message)
  }

  const prepareNamedLocalConfig = async (provider: ResolvedProvider, ctx: TunnelPlanContext): Promise<string> => {
    const credentialsFile = provider.credentialsFile
    const tunnelId = provider.tunnelId
    if (credentialsFile === null || tunnelId === null) {
      throw new TunnelError('BAD_REQUEST', 'the locally-managed tunnel needs credentials and a UUID')
    }
    const content = await readCredentialsFile(credentialsFile)
    let parsed: unknown
    try {
      parsed = JSON.parse(content)
    } catch {
      throw new TunnelError('BAD_REQUEST', 'the tunnel credentials JSON is not valid JSON')
    }
    const validation = validateCredentialsObject(parsed, tunnelId)
    if (!validation.ok) throw new TunnelError('BAD_REQUEST', validation.reason ?? 'the tunnel credentials are invalid')
    const configText = buildCloudflaredConfig({
      tunnelId,
      credentialsFile,
      hostname: provider.hostname ?? '',
      serviceUrl: ctx.localUrl,
    })
    await cleanRuntimeDirectory(runtimeDirectory)
    return writePrivateRuntimeFile(runtimeDirectory, 'cloudflared', configText, randomBytes)
  }

  const connectorReady = (): void => {
    if (startSettled) return
    const parser = outputParser
    if (parser === null || !parser.connected()) return
    startSettled = true
    clearStartupTimer()
    settleConnector?.()
    settleConnector = null
  }

  const handleCloudflaredExit = (code: number | null, signal: NodeJS.Signals | null): void => {
    child = null
    outputParser = null
    clearStartupTimer()
    if (!startSettled) {
      startSettled = true
      const detail = `cloudflared exited before readiness (code=${code ?? 'null'}, signal=${signal ?? 'none'})`
      settleConnector?.()
      settleConnector = null
      commit({
        ...status,
        enabled: false,
        state: 'down',
        url: null,
        ownership: 'none',
        verified: { http: false, ws: false },
        error: `TUNNEL_EXITED: ${detail}`,
        detail,
      })
      return
    }
    if (stopped || disposed) return
    commit({
      ...status,
      enabled: false,
      state: 'down',
      url: null,
      ownership: 'none',
      verified: { http: false, ws: false },
      error: `TUNNEL_EXITED: cloudflared exited (code=${code ?? 'null'}, signal=${signal ?? 'none'})`,
      detail: null,
    })
  }

  const startCloudflaredProvider = async (provider: ResolvedProvider, ctx: TunnelPlanContext): Promise<void> => {
    const candidates = cloudflaredCandidates(provider.selection)
    const resolvedBinary = await cloudflared.resolve(candidates)
    const installed = resolvedBinary.installed
    if (installed === null) {
      if (!resolvedBinary.supported) {
        commit({
          ...status,
          enabled: false,
          state: 'missing-binary',
          url: null,
          ownership: 'none',
          error: `no pinned official cloudflared asset exists for ${platform}/${arch}`,
        })
        throw new TunnelError(
          'UNSUPPORTED_PLATFORM',
          `no pinned official cloudflared asset exists for ${platform}/${arch}`,
        )
      }
      failMissingBinary(
        `cloudflared ${PINNED_CLOUDFLARED_RELEASE.version} is not installed; an explicit verified download is required from the desktop panel`,
      )
    }
    assertExecutableNotShim(installed!.path)

    let tokenValue: string | null = null
    if (provider.kind === 'named') {
      const source = provider.tokenSource
      if (source === null) throw new TunnelError('BAD_REQUEST', 'a connector token source is required')
      if (source.kind === 'file') {
        const version = installed!.version
        if (version === null || version === 'unknown' || !versionAtLeast(version, CLOUDFLARED_TOKEN_FILE_MIN_VERSION)) {
          commit({
            ...status,
            enabled: false,
            state: 'missing-binary',
            error: `cloudflared ${version ?? 'unknown'} does not support --token-file; version ${CLOUDFLARED_TOKEN_FILE_MIN_VERSION} or newer is required`,
          })
          throw new TunnelError(
            'INSTALL_REQUIRED',
            `cloudflared ${version ?? 'unknown'} does not support --token-file; version ${CLOUDFLARED_TOKEN_FILE_MIN_VERSION} or newer is required`,
          )
        }
        // Validate readability/content shape now; the path (not the secret) goes to argv.
        await readTokenFile(source.path)
      } else {
        tokenValue = hostEnv[source.envName]?.trim() ?? null
        if (tokenValue === null || tokenValue === '') {
          commit({
            ...status,
            enabled: false,
            state: 'missing-config',
            error: `the connector token environment variable ${source.envName} is not set`,
          })
          throw new TunnelError(
            'BAD_REQUEST',
            `the connector token environment variable ${source.envName} is not set in the host environment`,
          )
        }
      }
    }

    let configFile: string | null = null
    if (provider.kind === 'named-local') {
      configFile = await prepareNamedLocalConfig(provider, ctx)
      runtimeConfigPath = configFile
    }

    const args = buildCloudflaredArgs({
      mode: provider.kind === 'quick' ? 'quick' : provider.kind === 'named' ? 'named' : 'named-local',
      transport: provider.transport ?? 'auto',
      localUrl: ctx.localUrl,
      configFile: configFile ?? undefined,
      tunnelId: provider.tunnelId ?? undefined,
      tokenSource:
        provider.tokenSource === null
          ? undefined
          : provider.tokenSource.kind === 'env'
            ? { kind: 'env', envName: provider.tokenSource.envName }
            : { kind: 'file', path: provider.tokenSource.path },
    })
    const additions: Record<string, string> = tokenValue === null ? {} : { TUNNEL_TOKEN: tokenValue }
    const env = buildChildEnv(config.tunnel.env ?? {}, additions, log, hostEnv)

    outputParser = createCloudflaredOutputParser({
      mode: provider.kind === 'quick' ? 'quick' : provider.kind === 'named' ? 'named' : 'named-local',
    })
    startSettled = false
    const ready = new Promise<void>((resolve) => {
      settleConnector = resolve
    })

    let proc: ChildProcess
    try {
      proc = spawn(installed!.path, args, {
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      })
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      outputParser = null
      if (code === 'ENOENT') failMissingBinary('the cloudflared executable could not be started (not found)')
      commit({
        ...status,
        enabled: false,
        state: 'down',
        ownership: 'none',
        error: `TUNNEL_SPAWN_FAILED: ${errorMessage(error)}`,
      })
      throw new TunnelError('INSTALL_REQUIRED', 'the cloudflared executable could not be started')
    }
    child = proc
    const parser = outputParser
    const onOutput = (chunk: Buffer | string): void => {
      parser?.push(chunk)
      connectorReady()
    }
    proc.stdout?.on('data', onOutput)
    proc.stderr?.on('data', onOutput)
    proc.once('exit', handleCloudflaredExit)
    proc.once('error', (error: NodeJS.ErrnoException) => {
      if (child === proc) child = null
      outputParser = null
      if (!startSettled) {
        startSettled = true
        clearStartupTimer()
        settleConnector?.()
        settleConnector = null
        commit({
          ...status,
          enabled: false,
          state: 'down',
          url: null,
          ownership: 'none',
          error: `TUNNEL_SPAWN_FAILED: ${error.code ?? 'unknown error'}`,
        })
      }
    })
    startupTimer = setTimeout(() => {
      startupTimer = null
      if (startSettled) return
      startSettled = true
      settleConnector?.()
      settleConnector = null
      commit({
        ...status,
        enabled: false,
        state: 'down',
        url: null,
        ownership: 'none',
        verified: { http: false, ws: false },
        error: `TUNNEL_TIMEOUT: cloudflared did not become ready within ${Math.round(startupTimeoutMs / 1_000)}s`,
      })
      void terminateChild(proc, killGraceMs)
    }, startupTimeoutMs)
    startupTimer.unref()

    log.info('cloudflared starting', { mode: provider.mode, platform, temporary: provider.temporary })
    await ready
    if (stopped || disposed || status.state !== 'starting') return

    const parserUrl = parser?.url() ?? null
    const origin = provider.kind === 'quick' ? parserUrl : provider.publicOrigin
    if (origin === null) {
      commit({
        ...status,
        enabled: false,
        state: 'down',
        url: null,
        ownership: 'none',
        error: 'TUNNEL_URL_MISSING: the connector reported readiness without a valid public origin',
      })
      void terminateChild(proc, killGraceMs)
      return
    }
    await verifyAndCommit(origin, 'connector')
  }

  /* ----------------------------------------------------------------------- */
  /* SSH provider                                                            */
  /* ----------------------------------------------------------------------- */

  const launchSshChild = async (
    provider: ResolvedProvider,
    ctx: TunnelPlanContext,
  ): Promise<SshTunnelHandle> => {
    const installation = await discoverSsh({
      configuredPath: provider.sshPath,
      platform,
      spawn,
      log,
      env: hostEnv,
      fileExists: deps.fileExists,
      probeTimeoutMs,
    })
    const knownHosts = await ensureKnownHosts(runtimeDirectory)
    const handle = createSshTunnel({
      executable: installation.path,
      sshHost: provider.sshHost,
      sshUser: provider.sshUser,
      sshRemotePort: provider.sshRemotePort,
      localPort: ctx.listener.port,
      knownHostsFile: knownHosts.knownHostsFile,
      spawn,
      log,
      env: hostEnv,
      startupTimeoutMs,
      killGraceMs,
    })
    handle.setExitHandler((detail) => {
      if (stopped || disposed) return
      sshTunnel = null
      void superviseSshRestart(detail)
    })
    sshTunnel = handle
    const { url } = await handle.start()
    return handle
  }

  const commitSshDown = (message: string, state: TunnelState = 'down'): void => {
    commit({
      ...status,
      enabled: false,
      state,
      url: null,
      ownership: 'none',
      verified: { http: false, ws: false },
      error: message,
      detail: null,
    })
  }

  const superviseSshRestart = async (detail: string): Promise<void> => {
    const provider = resolved
    const planContext = context
    if (provider === null || planContext === null || stopped || disposed) return
    if (restartAttempt >= maxRestartAttempts) {
      commitSshDown(`TUNNEL_LOST: ${detail}; restart attempts exhausted`)
      return
    }
    restartAttempt += 1
    const attempt = restartAttempt
    const delayMs = restartDelays[Math.min(attempt - 1, restartDelays.length - 1)] ?? 1_000
    commit({
      ...status,
      enabled: true,
      state: 'starting',
      url: null,
      ownership: 'plugin',
      verified: { http: false, ws: false },
      error: null,
      detail: `ssh tunnel lost; reconnecting (attempt ${attempt}/${maxRestartAttempts})`,
    })
    await waitForRestart(delayMs)
    if (stopped || disposed) return
    try {
      const handle = await launchSshChild(provider, planContext)
      const url = handle.url
      if (url === null) throw new TunnelError('INTERNAL', 'ssh reconnect produced no provider URL')
      restartAttempt = 0
      await verifyAndCommit(url, 'connector')
    } catch (error) {
      if (stopped || disposed) return
      sshTunnel = null
      if (isTunnelError(error) && error.code === 'SSH_MISSING') {
        commitSshDown(error.message, 'missing-binary')
        return
      }
      log.warn('ssh supervised restart failed', { message: errorMessage(error) })
      await superviseSshRestart(errorMessage(error))
    }
  }

  const startSshProvider = async (provider: ResolvedProvider, ctx: TunnelPlanContext): Promise<void> => {
    let handle: SshTunnelHandle
    try {
      handle = await launchSshChild(provider, ctx)
    } catch (error) {
      sshTunnel = null
      if (isTunnelError(error) && error.code === 'SSH_MISSING') {
        commitSshDown(error.message, 'missing-binary')
        throw error
      }
      commitSshDown(errorMessage(error))
      return
    }
    const url = handle.url
    if (url === null) {
      commitSshDown('the SSH provider announced no public URL')
      return
    }
    restartAttempt = 0
    await verifyAndCommit(url, 'connector')
  }

  /* ----------------------------------------------------------------------- */
  /* Public TunnelManager API                                                */
  /* ----------------------------------------------------------------------- */

  const describe = async (
    input: ConnectionSelection,
    planContext: TunnelPlanContext,
  ): Promise<TunnelProviderPlan> => {
    const provider = resolveProvider(input)
    const steps = buildPlanSteps(provider, planContext)
    const warnings = providerWarnings(provider, planContext)
    if (provider.kind === 'ssh') {
      try {
        await discoverSsh({
          configuredPath: provider.sshPath,
          platform,
          spawn,
          log,
          env: hostEnv,
          fileExists: deps.fileExists,
          probeTimeoutMs,
        })
      } catch (error) {
        warnings.push(
          'OpenSSH is not installed; the plugin never downloads an SSH binary. Install the OS OpenSSH client first.',
        )
        void error
      }
    }
    const cloudflaredInfo =
      provider.kind === 'quick' || provider.kind === 'named' || provider.kind === 'named-local'
        ? await cloudflared.info(cloudflaredCandidates(provider.selection))
        : null
    // The effective selection (desktop override first, then the configured
    // path) decides whether a verified download has to be disclosed.
    const download =
      cloudflaredInfo !== null && cloudflaredInfo.installed === null && cloudflaredInfo.supported
        ? cloudflaredInfo
        : null
    if (download !== null) {
      steps.push({
        kind: 'download',
        text: `A pinned official cloudflared ${download.version} asset (${download.asset}, ${download.sizeBytes} bytes) must be downloaded and verified against the official SHA-256 ${download.sha256}; nothing is downloaded until you confirm.`,
        params: { version: download.version, asset: download.asset, sizeBytes: download.sizeBytes, sha256: download.sha256 },
      })
    } else if (cloudflaredInfo !== null && !cloudflaredInfo.supported) {
      warnings.push('No pinned official cloudflared asset exists for this platform/architecture; fail closed.')
    }
    return {
      steps,
      publicOrigin: provider.publicOrigin,
      accessRequired: provider.accessRequired,
      download,
      warnings,
      fixedLoopbackPort: provider.fixedLoopbackPort,
      temporary: provider.temporary,
    }
  }

  const startInternal = async (
    input: ConnectionSelection,
    planContext: TunnelPlanContext,
  ): Promise<TunnelStatus> => {
    await stopInternal()
    stopped = false
    const provider = resolveProvider(input)
    resolved = provider
    selection = provider.selection
    context = planContext
    restartAttempt = 0
    const base = { ...baseStatus(provider.mode), temporary: provider.temporary }
    commit({
      ...base,
      enabled: true,
      state: 'starting',
      serviceUrl: planContext.localUrl,
      ownership: provider.kind === 'external' ? 'external' : provider.kind === 'loopback' || provider.kind === 'lan' ? 'none' : 'plugin',
      transport: provider.transport,
    })
    if (provider.kind === 'loopback' || provider.kind === 'lan') {
      started = false
      commit({ ...base, serviceUrl: planContext.localUrl, detail: 'loopback/LAN access has no tunnel provider' })
      return snapshot()
    }
    started = true
    try {
      if (provider.kind === 'external') {
        const origin = provider.publicOrigin
        if (origin === null) throw new TunnelError('BAD_REQUEST', 'the external origin is missing')
        await verifyAndCommit(origin, 'external')
      } else if (provider.kind === 'ssh') {
        await startSshProvider(provider, planContext)
      } else {
        await startCloudflaredProvider(provider, planContext)
      }
    } catch (error) {
      if (isTunnelError(error)) {
        const terminalCodes = new Set([
          'BAD_REQUEST',
          'INSTALL_REQUIRED',
          'UNSUPPORTED_PLATFORM',
          'SSH_MISSING',
          'CHECKSUM_MISMATCH',
          'ACCESS_REQUIRED',
        ])
        if (terminalCodes.has(error.code)) {
          started = false
          if (status.state === 'starting') {
            const missingBinary =
              error.code === 'INSTALL_REQUIRED' ||
              error.code === 'UNSUPPORTED_PLATFORM' ||
              error.code === 'SSH_MISSING'
            commit({
              ...status,
              enabled: false,
              state: missingBinary ? 'missing-binary' : 'missing-config',
              url: null,
              ownership: 'none',
              verified: { http: false, ws: false },
              error: error.message,
              detail: null,
            })
          }
          throw error
        }
      }
      started = false
      if (status.state === 'off' || status.state === 'down' || status.state === 'missing-binary' || status.state === 'missing-config') {
        throw error
      }
      commit({
        ...status,
        enabled: false,
        state: 'down',
        url: null,
        ownership: 'none',
        verified: { http: false, ws: false },
        error: errorMessage(error),
      })
      return snapshot()
    }
    return snapshot()
  }

  const start = (input: ConnectionSelection, planContext: TunnelPlanContext): Promise<TunnelStatus> => {
    if (disposed) {
      return Promise.reject(new TunnelError('INTERNAL', 'the tunnel manager is shutting down'))
    }
    if (startPromise !== null) return startPromise
    if (started && status.state !== 'off' && status.state !== 'down') return Promise.resolve(snapshot())
    startPromise = startInternal(input, planContext).finally(() => {
      startPromise = null
    })
    return startPromise
  }

  async function stopInternal(): Promise<void> {
    stopped = true
    clearStartupTimer()
    clearRestartTimer()
    startSettled = true
    settleConnector?.()
    settleConnector = null
    const proc = child
    child = null
    outputParser = null
    const ssh = sshTunnel
    sshTunnel = null
    if (ssh !== null) {
      await ssh.stop().catch(() => undefined)
    }
    if (proc !== null) {
      await terminateChild(proc, killGraceMs)
    }
    await removeFileQuietly(runtimeConfigPath)
    runtimeConfigPath = null
    const previous = status
    const mode = previous.mode
    started = false
    selection = null
    context = null
    resolved = null
    restartAttempt = 0
    const next = offStatus(mode)
    if (previous.state !== 'off' || previous.url !== null) {
      commit(next)
    } else {
      status = next
    }
  }

  const stop = async (): Promise<void> => {
    await stopInternal()
    if (disposed) return
    stopped = false
  }

  const installInfo = async (): Promise<CloudflaredDownloadInfo> => cloudflared.info()

  const install = async (): Promise<CloudflaredDownloadInfo> => {
    const info = await cloudflared.install()
    log.info('cloudflared install flow finished', { supported: info.supported })
    return info
  }

  const statusOf = (): TunnelStatus => snapshot()

  const currentSelection = (): ConnectionSelection | null =>
    selection === null ? null : { ...selection }

  const setStatusListener = (listener: (value: TunnelStatus) => void): void => {
    statusListener = listener
  }

  const dispose = async (): Promise<void> => {
    if (disposed) return
    disposed = true
    await stopInternal()
    await cleanRuntimeDirectory(runtimeDirectory)
    statusListener = null
  }

  return {
    describe,
    start,
    stop,
    status: statusOf,
    installInfo,
    install,
    currentSelection,
    setStatusListener,
    dispose,
  }
}
