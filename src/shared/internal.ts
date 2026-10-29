/**
 * Internal collaborator contracts.
 *
 * The Host plugin is split into small modules (listener, pairing, device store,
 * gateway, broker, tunnel). Each module implements one of the interfaces below
 * so that modules can be unit-tested in isolation with fakes and so that the
 * Lead-owned orchestrator (`controller.ts`) is the only integration point.
 */

import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'

import type { RemoteControlConfig } from '../config.js'
import type {
  AdminConnectionPlanResponse,
  AdminConnectionStartRequest,
  AdminConnectionStartResponse,
  AdminConnectionStopResponse,
  AdminControlResponse,
  AdminEmergencyStopResponse,
  AdminInstallResponse,
  AdminOkResponse,
  AdminPairCreateResponse,
  AdminStatusEnvelope,
  ApprovalView,
  AnswerOutcome,
  AuditEntryView,
  CancelResponse,
  CloudflaredDownloadInfo,
  ConnectionPlanStep,
  ConnectionSelection,
  ConnectionStateView,
  CreateSessionRequest,
  CreateSessionResponse,
  DeviceLockView,
  DeviceView,
  HealthResponse,
  ListenerStatus,
  LogoutResponse,
  PageRequest,
  PairClaimResponse,
  PairStatusResponse,
  PairingState,
  PairingView,
  PromptRequest,
  PromptResponse,
  RcErrorCode,
  RefreshResponse,
  SecurityStateView,
  SessionEventRecord,
  SessionPageResponse,
  SessionProjectionsResponse,
  SessionSummary,
  SessionsResponse,
  SessionAttachmentResponse,
  StateResponse,
  TunnelStatus,
  UploadFileRequest,
  UploadFileResponse,
  WorkspaceGroupView,
} from './protocol.js'
import type {
  ConnectionService,
  DshEventsFrame,
  HostContext,
  HostLogger,
  WebServerService,
} from '../types/dsh.js'

/* ------------------------------------------------------------------------- */
/* Logging & audit                                                           */
/* ------------------------------------------------------------------------- */

export interface Logger {
  error(message: string, detail?: unknown): void
  warn(message: string, detail?: unknown): void
  info(message: string, detail?: unknown): void
  debug(message: string, detail?: unknown): void
}

export type AuditKind =
  | 'enable'
  | 'disable'
  | 'pair'
  | 'approve'
  | 'deny'
  | 'revoke'
  | 'rpc'
  | 'answer'
  | 'tunnel'
  | 'security'
  | 'device-lock'

export type AuditResult = 'ok' | 'rejected' | 'failed' | 'notice'

/**
 * One audit record. Only non-sensitive metadata is stored: no prompt text, tool
 * arguments, tool output, token, cookie, pairing code or poll secret ever enters
 * this record. `ip`/`userAgent` are only filled when they can be established
 * reliably, and the user agent is sanitized (bounded length, no control/ANSI
 * characters, no line breaks).
 */
export interface AuditEntry {
  /** Monotonic record id within this process, assigned by the ring. */
  id?: number
  /** Epoch milliseconds. */
  time: number
  deviceId: string | null
  /** Display label of the device, when known and already sanitized. */
  deviceLabel?: string | null
  kind: AuditKind
  /** Short operation name, e.g. `pair.claim`, `session.prompt`, `tunnel.start`. */
  operation?: string
  /** Outcome classification; omitted entries are treated as `notice`. */
  result?: AuditResult
  /** Client IP when reliably attributable to the request (never a spoofable header). */
  ip?: string | null
  /** Sanitized User-Agent, truncated. */
  userAgent?: string | null
  /** Short, non-sensitive detail (endpoint name, tool name, outcome). */
  detail: string
}

export interface AuditRing {
  push(entry: Omit<AuditEntry, 'time'>): void
  snapshot(): AuditEntry[]
  readonly size: number
  dispose(): void
}

/* ------------------------------------------------------------------------- */
/* Persisted state                                                           */
/* ------------------------------------------------------------------------- */

export interface PersistedState {
  /** `1` is the legacy shape (still accepted and migrated); `2` adds the security fields. */
  v: 1 | 2
  lastEnabled: boolean
  updatedAt: string
  /**
   * Monotonic token-revocation epoch (v2+). Access tokens carry the epoch they
   * were minted with; a bump permanently invalidates every previously issued
   * access/refresh token, including across a DSH restart. Persist the bump before
   * claiming the invalidation succeeded.
   */
  revocationEpoch?: number
  /** True when a one-shot emergency shutdown left remote access closed. */
  securityClosed?: boolean
  securityClosedReason?: string | null
  /** Explicitly selected device that holds the single-active-device lease. */
  activeDeviceId?: string | null
  leaseStartedAt?: number | null
  leaseLastActivityAt?: number | null
}

export interface StateStore {
  readonly path: string
  load(): Promise<PersistedState>
  save(state: PersistedState): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* Devices                                                                   */
/* ------------------------------------------------------------------------- */

/** Persisted device record. Never leaves the host: `tokenKey`/`refreshHash` stay on disk. */
export interface StoredDevice {
  id: string
  label: string
  platform: string
  createdAt: number
  lastSeenAt: number
  refreshExpiresAt: number
  tokenVersion: number
  /** base64url-encoded 32-byte HMAC key. */
  tokenKey: string
  /** sha256 hex of the current refresh token. */
  refreshHash: string
}

export interface DeviceStore {
  readonly path: string
  load(): Promise<void>
  list(): StoredDevice[]
  get(id: string): StoredDevice | undefined
  count(): number
  add(device: StoredDevice): Promise<void>
  update(device: StoredDevice): Promise<void>
  /**
   * Update only the `lastSeenAt` field of one device under the store's write
   * serialization, so a concurrent token rotation cannot be clobbered by a
   * stale whole-record snapshot. Unknown ids and non-increasing timestamps are
   * ignored.
   */
  touch(id: string, lastSeenAt: number): Promise<void>
  remove(id: string): Promise<void>
  dispose(): void
}

/* ------------------------------------------------------------------------- */
/* Tokens & pairing                                                          */
/* ------------------------------------------------------------------------- */

export interface AccessClaims {
  deviceId: string
  tokenVersion: number
  expiresAt: number
  /**
   * Token revocation epoch the access token was minted with (v2). The
   * controller compares it with the persisted epoch; a mismatch means the token
   * was invalidated by an emergency shutdown (including across a restart).
   * Optional so legacy five-part tokens/fakes still verify (treated as epoch 0).
   */
  epoch?: number
}

/**
 * Detailed access-token verification result. `expired` is returned when the
 * token is structurally valid and correctly signed but past its expiry: the
 * controller answers TOKEN_EXPIRED without counting an authentication failure,
 * because a normal expired-access → refresh flow is not an attack.
 */
export type AccessVerificationState =
  | { state: 'valid'; claims: AccessClaims }
  | { state: 'expired'; claims: AccessClaims }
  | { state: 'invalid' }

export interface TokenService {
  /** Mint an access token bound to the given revocation epoch (default 0 for legacy fakes). */
  issueAccess(device: StoredDevice, epoch?: number): { token: string; expiresAt: number }
  /** Returns null for malformed, expired or tampered tokens. */
  verifyAccess(token: string, expectedEpoch?: number): AccessClaims | null
  /**
   * Like `verifyAccess`, but distinguishes a normally expired token from an
   * invalid/tampered/revoked one. Optional for lightweight test fakes; the
   * controller falls back to `verifyAccess` + the invalid path when absent.
   */
  verifyAccessDetailed?(token: string, expectedEpoch?: number): AccessVerificationState
  issueRefresh(device: StoredDevice): { token: string; hash: string; expiresAt: number }
  /** Extract the device id from a refresh token without validating its secret. */
  readRefreshSubject(token: string): { deviceId: string } | null
  hashRefresh(token: string): string
  equalRefresh(a: string, b: string): boolean
  /** sha256 hex helper used for pairing codes and refresh lookups. */
  hashSecret(secret: string): string
  /** Constant-time comparison of two hex strings. */
  equalHex(a: string, b: string): boolean
}

export interface PairingClaimResult {
  ok: true
  claimId: string
  pollToken: string
  expiresAt: number
}

export interface PairingFailure {
  ok: false
  code: 'PAIRING_INVALID' | 'PAIRING_EXPIRED' | 'PAIRING_CONSUMED' | 'DEVICE_LIMIT' | 'DEVICE_LOCKED'
  message: string
}

/** Details needed to mint a device after the desktop approved a claim. */
export interface PairingApprovalDetails {
  deviceName: string
  platform: string
}

export interface PairingManager {
  /** Mint a new one-time code. Returns null when too many codes are outstanding. */
  create(): { code: string; expiresAt: number } | null
  claim(input: { code: string; deviceName: string; platform: string }): PairingClaimResult | PairingFailure
  status(claimId: string, pollToken: string): PairingState
  /**
   * Atomically reserve an approved claim exactly once, BEFORE the controller's
   * first async device-creation step. Returns null when the claim is unknown,
   * already consumed, or the poll token does not match (fail closed).
   */
  beginIssue?(claimId: string, pollToken: string): PairingApprovalDetails | null
  /** Desktop approval hook. Returns the approved claim description. */
  approve(claimId: string): { deviceName: string; platform: string; pollToken: string } | null
  deny(claimId: string): boolean
  /** Remove the claim from the desk once tokens were issued. */
  consume(claimId: string): void
  list(): PairingView[]
  /** Claims waiting for desktop approval (drives the overlay modal). */
  pendingApprovals(): PairingView[]
  sweep(now?: number): void
  dispose(): void
}

/* ------------------------------------------------------------------------- */
/* Listener                                                                  */
/* ------------------------------------------------------------------------- */

export type HttpHandler = (request: IncomingMessage, response: ServerResponse) => void
export type UpgradeHandler = (request: IncomingMessage, socket: Duplex, head: Buffer) => void

export interface ListenerBindConfig {
  host: string
  port: number
  allowLan: boolean
  tls: { certFile: string; keyFile: string } | null
}

export interface ListenerDeps {
  bind(): ListenerBindConfig
  /** Absolute directory that holds the built PWA (`dist/pwa`). */
  staticRoot: string
  /** Phone REST API under `/rc/api/*`. */
  api: HttpHandler
  /** `/rc/ws` upgrade entry. */
  upgrade: UpgradeHandler
  log: Logger
}

export interface ListenerHandle {
  start(): Promise<ListenerStatus>
  stop(): Promise<void>
  status(): ListenerStatus
  /** `http://host:port` once started, otherwise null. */
  origin(): string | null
}

/* ------------------------------------------------------------------------- */
/* Data plane (gateway-backed)                                               */
/* ------------------------------------------------------------------------- */

export interface FollowOptions {
  maxMessages?: number
  signal: AbortSignal
}

export type FollowFrame =
  | {
      type: 'snapshot'
      cursor: number
      header: unknown
      records: SessionEventRecord[]
      hasMore: boolean
      projections: { asOfSeq: number; values: Record<string, unknown> } | null
    }
  | { type: 'event'; event: SessionEventRecord }
  | { type: 'assistant-stream'; frame: unknown }

/**
 * Narrow, allowlisted projection of the DSH session API. This is the only way
 * phone-facing code reaches DSH state; it never exposes an arbitrary endpoint.
 */
export interface SessionDataPlane {
  list(signal?: AbortSignal): Promise<SessionSummary[]>
  projections(sessionId: string, signal?: AbortSignal): Promise<SessionProjectionsResponse>
  page(sessionId: string, request: PageRequest, signal?: AbortSignal): Promise<SessionPageResponse>
  prompt(sessionId: string, request: PromptRequest, signal?: AbortSignal): Promise<PromptResponse>
  cancel(sessionId: string, signal?: AbortSignal): Promise<CancelResponse>
  follow(sessionId: string, options: FollowOptions): AsyncIterable<FollowFrame>
  desktopConnected(): boolean
  /**
   * Optional feature extensions. They stay optional so existing fakes/tests keep
   * working; the controller answers 501 NOT_ALLOWED when a provider is absent.
   */
  workspaces?(signal?: AbortSignal): Promise<WorkspaceGroupView[]>
  createSession?(request: CreateSessionRequest, signal?: AbortSignal): Promise<CreateSessionResponse>
  uploadFile?(
    sessionId: string,
    request: UploadFileRequest,
    signal?: AbortSignal,
  ): Promise<UploadFileResponse>
  readAttachment?(
    sessionId: string,
    attachmentId: string,
    signal?: AbortSignal,
  ): Promise<SessionAttachmentResponse>
  dispose(): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* Gateway client                                                            */
/* ------------------------------------------------------------------------- */

/** Per-device answering stream used for approval / user-question waterfalls. */
export interface ApprovalEventStream {
  readonly frames: AsyncIterable<DshEventsFrame>
  answer(eventId: string, outcome: AnswerOutcome, signal?: AbortSignal): Promise<unknown>
  dispose(): Promise<void>
}

/**
 * Thin wrapper over `ctx.typertGateway` with a long-lived owner Peer for the
 * data plane and per-device answering peers for `$events`.
 */
export interface GatewayClient {
  invoke<T = unknown>(method: string, args?: Record<string, unknown>, signal?: AbortSignal): Promise<T>
  stream<T = unknown>(
    method: string,
    args?: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<AsyncIterable<T>>
  openApprovalEvents(deviceId: string, signal: AbortSignal): Promise<ApprovalEventStream>
  /**
   * Desktop-parity session visibility: session ids accounted to a Workspace
   * (manual order) and the archived ids, read from the first
   * `workspace/follow` baseline. Optional so lightweight test fakes can omit it;
   * the session bridge then falls back to the unfiltered gateway list.
   */
  workspaceSessionScope?(signal?: AbortSignal): Promise<{
    orderedSessionIds: string[]
    archivedSessionIds: string[]
  }>
  /**
   * Full desktop Workspace groups (titles, paths, manually ordered session ids)
   * from the first `workspace/follow` baseline. Optional for lightweight fakes;
   * the session bridge then falls back to grouping by `cwd`.
   */
  workspaceGroups?(signal?: AbortSignal): Promise<WorkspaceGroupView[]>
  hasLiveClient(): boolean
  dispose(): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* Approval hub                                                              */
/* ------------------------------------------------------------------------- */

export interface ApprovalSink {
  onApproval(view: ApprovalView): void
  onCancel(eventId: string, reason: 'answered-elsewhere' | 'cancelled' | 'expired'): void
  /** Forwarded non-waterfall `$events` notifications (e.g. `api-session/status`). */
  onHostEvent?(event: string, args: unknown[]): void
}

export interface AnswerResult {
  ok: boolean
  error?: { code: RcErrorCode; message: string }
}

export interface ApprovalHub {
  /** Open the per-device `$events` stream and forward waterfalls to `sink`. */
  registerDevice(deviceId: string, sink: ApprovalSink): Promise<() => void>
  answer(deviceId: string, eventId: string, outcome: AnswerOutcome): Promise<AnswerResult>
  pending(): ApprovalView[]
  dispose(): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* WebSocket broker                                                          */
/* ------------------------------------------------------------------------- */

export interface WsBrokerDeps {
  dataPlane: SessionDataPlane
  approvals: ApprovalHub
  pluginVersion: string
  log: Logger
  /**
   * Per-frame authorization (not upgrade-only). Called once at `hello` and again
   * before every `rpc` / `answer` frame; when it returns `ok:false` the broker
   * sends the error and closes the socket with the device-lost policy code.
   */
  authorize?(deviceId: string): { ok: true } | { ok: false; code: RcErrorCode; message: string }
  /**
   * Record verified phone activity (authenticated frame/heartbeat). Returns
   * false when the device no longer holds the active lease. Renews the idle
   * clock; server-initiated pings never renew it.
   */
  touchActivity?(deviceId: string): boolean
}

export interface WsBroker {
  /**
   * Complete the WebSocket handshake for an already-authenticated device.
   *
   * `sessionExpiresAt` is the verified access-token expiry of THIS connection. It
   * is stored per socket (never per device), so a newer connection of the same
   * device can never extend the lifetime of an older one.
   */
  handleUpgrade(
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
    device: StoredDevice,
    sessionExpiresAt: number,
  ): void
  broadcastDrain(retryAfterMs: number): void
  /** Close every socket of one device (used by revoke / lease loss). */
  closeDevice(deviceId: string, reason: string, closeCode?: number): void
  closeAll(reason: string, closeCode?: number): void
  readonly connections: number
  dispose(): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* Phone REST API used by the listener                                       */
/* ------------------------------------------------------------------------- */

export interface PhoneApi {
  health(): HealthResponse
  pairClaim(body: unknown): Promise<PairClaimResponse>
  pairStatus(query: URLSearchParams): Promise<PairStatusResponse>
  refresh(request: IncomingMessage): Promise<RefreshResponse>
  logout(request: IncomingMessage): Promise<LogoutResponse>
  state(request: IncomingMessage): Promise<StateResponse>
  sessions(request: IncomingMessage): Promise<SessionsResponse>
  projections(request: IncomingMessage, sessionId: string): Promise<SessionProjectionsResponse>
  page(request: IncomingMessage, sessionId: string, query: URLSearchParams): Promise<SessionPageResponse>
  prompt(request: IncomingMessage, sessionId: string, body: unknown): Promise<PromptResponse>
  cancel(request: IncomingMessage, sessionId: string): Promise<CancelResponse>
}

/* ------------------------------------------------------------------------- */
/* Security policy (failure accounting, circuit breaker)                     */
/* ------------------------------------------------------------------------- */

export interface FailureRecordResult {
  /** This failure triggered a temporary per-IP block. */
  banned: boolean
  /** Milliseconds until the block expires (0 when not blocked). */
  retryAfterMs: number
  /** This failure crossed the circuit-breaker threshold (one-shot). */
  circuitBreakerOpen: boolean
  /** Failures counted in the current manually started remote-access period. */
  totalFailures: number
}

export interface SecurityMonitor {
  /**
   * True when the client is currently under a temporary block. A blocked
   * request is rejected once and is NOT counted as a new failure, and it never
   * extends the block (documented behavior).
   */
  blocked(ip: string): { blocked: boolean; retryAfterMs: number }
  /**
   * Count one failed authentication exactly once for a request. Shared by the
   * pairing secret, polling secret, access, refresh and WS verification paths.
   * Returns whether this failure banned the IP and/or opened the circuit
   * breaker. After the breaker opens, `onCircuitBreaker` fires exactly once.
   */
  recordFailure(ip: string, path: string): FailureRecordResult
  /** Record a successful verified authentication (kept for accounting symmetry). */
  recordSuccess(ip: string): void
  /** Reset per-session accounting when the user manually starts remote access. */
  beginSession(): void
  /** Stop per-session accounting when remote access stops. */
  endSession(): void
  isCircuitBreakerOpen(): boolean
  failureCount(): number
  blockedCount(): number
  /** Wire the one-shot circuit-breaker action (safe emergency shutdown). */
  setCircuitBreakerHandler(handler: () => void | Promise<void>): void
  dispose(): void
}

/* ------------------------------------------------------------------------- */
/* Single-active-device lease                                                */
/* ------------------------------------------------------------------------- */

export type LeaseReleaseReason =
  | 'manual'
  | 'revoke'
  | 'idle'
  | 'emergency'
  | 'restart'
  | 'security'

export interface LeaseRawState {
  deviceId: string | null
  startedAt: number | null
  lastActivityAt: number | null
}

export interface DeviceLease {
  /** Raw lease fields for persistence/status composition. */
  raw(): LeaseRawState
  /** Restore from persisted plugin state (v1 state has no lease). */
  restore(persisted: PersistedState): void
  activeDeviceId(): string | null
  isActive(deviceId: string): boolean
  /**
   * Take the single active-device lease for `deviceId`. Fails when another
   * device holds it; re-activating the current device is a no-op refresh.
   */
  activate(deviceId: string): boolean
  /**
   * Verified phone activity for the active device; renews the idle clock.
   * Returns false when the device is not the active device.
   */
  touch(deviceId: string): boolean
  /** Release the lease (idempotent). */
  release(reason: LeaseReleaseReason): void
  idleExpiresAt(): number | null
  /** Wire the one-shot idle-timeout action (safe emergency shutdown). */
  setIdleHandler(handler: () => void | Promise<void>): void
  dispose(): void
}

/* ------------------------------------------------------------------------- */
/* Cloudflare Access verification                                            */
/* ------------------------------------------------------------------------- */

export interface AccessVerification {
  ok: boolean
  code?: RcErrorCode
  message?: string
}

export interface AccessVerifier {
  /** True when Access enforcement is configured and currently required. */
  enabled(): boolean
  /**
   * Update the enforcement switch at runtime: a desktop plan/selection may
   * require Cloudflare Access for one run even when the config default is off.
   */
  setRequired(required: boolean): void
  /** Validate the `Cf-Access-Jwt-Assertion` header (fail closed when required). */
  verify(request: IncomingMessage): Promise<AccessVerification>
  dispose(): void
}

/* ------------------------------------------------------------------------- */
/* Connection providers (TunnelManager)                                      */
/* ------------------------------------------------------------------------- */

/** Listener decision the controller computed from the selection + config. */
export interface TunnelPlanContext {
  localUrl: string
  listener: {
    access: 'loopback' | 'lan'
    host: string
    port: number
    protocol: 'http' | 'https'
    secure: boolean
  }
}

export interface TunnelProviderPlan {
  steps: ConnectionPlanStep[]
  publicOrigin: string | null
  accessRequired: boolean
  /** Non-null only when a pinned official download would be required/shown. */
  download: CloudflaredDownloadInfo | null
  warnings: string[]
  /** True when this provider requires a fixed loopback port (named/external). */
  fixedLoopbackPort: boolean
  temporary: boolean
}

/**
 * Owns every provider-specific public-reachability detail. The controller owns
 * the listener lifecycle, origin fencing, QR/cookie computation and the safe
 * shutdown; the manager never talks to DSH.
 */
export interface TunnelManager {
  /** Pre-start disclosure for the panel; does not start anything. */
  describe(selection: ConnectionSelection, context: TunnelPlanContext): Promise<TunnelProviderPlan>
  /** Start the selected provider; the listener must already be running at context.localUrl. */
  start(selection: ConnectionSelection, context: TunnelPlanContext): Promise<TunnelStatus>
  stop(): Promise<void>
  status(): TunnelStatus
  /** Metadata for the pinned official cloudflared download (or found binary). */
  installInfo(): Promise<CloudflaredDownloadInfo>
  /** Explicit user-requested download; verifies SHA-256 before use. */
  install(): Promise<CloudflaredDownloadInfo>
  currentSelection(): ConnectionSelection | null
  /**
   * Observe provider lifecycle changes (URL change, unexpected loss, probe
   * completion). Optional so lightweight fakes can omit it.
   */
  setStatusListener?(listener: (status: TunnelStatus) => void): void
  dispose(): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* Tunnel                                                                    */
/* ------------------------------------------------------------------------- */

export interface TunnelDeps {
  config: RemoteControlConfig
  /** Local host/port the tunnel must forward to; never the DSH port. */
  localUrl(): string
  log: Logger
  onUrlChanged(url: string | null): void
  /**
   * Directory that stores the managed cloudflared binary (e.g.
   * `<DSH_HOME>/remote-control/bin`). Optional so tests can omit it.
   */
  managedDir?(): string
}

export interface TunnelController {
  start(): Promise<TunnelStatus>
  stop(): Promise<void>
  status(): TunnelStatus
  dispose(): Promise<void>
}

/* ------------------------------------------------------------------------- */
/* Admin API used by `admin.ts`                                              */
/* ------------------------------------------------------------------------- */

export interface AdminApi {
  status(): Promise<AdminStatusEnvelope>
  control(action: 'enable' | 'disable'): Promise<AdminControlResponse>
  pairCreate(): Promise<AdminPairCreateResponse>
  pairApprove(claimId: string): Promise<AdminOkResponse>
  pairDeny(claimId: string): Promise<AdminOkResponse>
  revoke(deviceId: string): Promise<AdminOkResponse>
  revokeAll(): Promise<AdminOkResponse>
  /** Claims waiting for the desktop pairing modal (overlay polls this). */
  pending(): Promise<{ pairings: PairingView[] }>
  /** Legacy explicit action: start the configured tunnel at runtime. */
  startTunnel(): Promise<TunnelStatus>
  /** Legacy explicit action: stop the runtime tunnel. */
  stopTunnel(): Promise<TunnelStatus>

  /* New connection workflow (panel plan → confirm → start; §2/§3). */
  /** Pre-start disclosure for the desktop panel. Never starts anything. */
  connectionPlan?(selection: ConnectionSelection): Promise<AdminConnectionPlanResponse>
  /** Apply a previously disclosed and explicitly confirmed plan. */
  connectionStart?(request: AdminConnectionStartRequest): Promise<AdminConnectionStartResponse>
  /** Stop public exposure / revert to loopback without closing remote control. */
  connectionStop?(): Promise<AdminConnectionStopResponse>
  /** One-shot emergency shutdown (user action, circuit breaker, idle timeout). */
  emergencyStop?(): Promise<AdminEmergencyStopResponse>
  /** Metadata for the pinned official cloudflared download. */
  installInfo?(): Promise<CloudflaredDownloadInfo>
  /** Explicit user-requested download + SHA-256 verification + cache. */
  install?(planId: string): Promise<AdminInstallResponse>
  /** Explicitly select the device that holds the single-active-device lease. */
  activateDevice?(deviceId: string): Promise<AdminOkResponse>
  /** Release the active-device lease without revoking the pairing. */
  releaseDevice?(deviceId: string): Promise<AdminOkResponse>
  /** Recent audit entries for the desktop panel. */
  auditLog?(): Promise<{ entries: AuditEntryView[] }>
}

/* ------------------------------------------------------------------------- */
/* Host context used across the plugin                                       */
/* ------------------------------------------------------------------------- */

export interface PluginContext extends HostContext {
  webServer: WebServerService
  connection: ConnectionService
  typertGateway: import('../types/dsh.js').TypertGatewayService
  logger?: HostLogger
}
