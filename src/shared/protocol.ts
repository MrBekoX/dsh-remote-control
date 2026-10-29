/**
 * Host ↔ PWA / desktop-client wire contract.
 *
 * This module is the single source of truth for the remote-control protocol.
 * It is intentionally dependency-free (types + literal constants only) so that
 * it can be imported by the Host (NodeNext), the PWA bundle and the client
 * plugin bundle without pulling any runtime code.
 *
 * See PROTOCOL.md for the human-readable description and PROTOCOL_VERSION for
 * the compatibility gate.
 */

/** Version of the remote-control wire protocol. Bump on breaking frame changes. */
export const PROTOCOL_VERSION = 2

/** Base path of the plugin's own HTTP listener (the PWA origin). */
export const RC_BASE_PATH = '/rc'
/** REST surface below the base path, e.g. `/rc/api/health`. */
export const RC_API_PATH = `${RC_BASE_PATH}/api`
/** The single WebSocket multiplexer path on the plugin listener. */
export const RC_WS_PATH = `${RC_BASE_PATH}/ws`

/** Cookies minted for a paired device. Both are HttpOnly + SameSite=Strict + Path=/rc. */
export const RC_ACCESS_COOKIE = 'rc_access'
export const RC_REFRESH_COOKIE = 'rc_refresh'

/** Header that must accompany every authenticated mutation (CSRF defense). */
export const RC_CSRF_HEADER = 'x-rc-csrf'

/** Desktop admin surface served through the DSH webServer (same origin as the GUI). */
export const RC_ADMIN_PATH = '/api/dsh-remote-control'

/** Logical stream kinds accepted by `/rc/ws`. */
export const RC_STREAM_FOLLOW = 'follow' as const

/** Canonical error codes. Every error envelope uses one of these. */
export const RC_ERRORS = {
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  DEVICE_REVOKED: 'DEVICE_REVOKED',
  /** Another device currently holds the single-active-device lease. */
  DEVICE_LOCKED: 'DEVICE_LOCKED',
  /** Remote access is closed after an emergency shutdown / circuit breaker / idle timeout. */
  SECURITY_CLOSED: 'SECURITY_CLOSED',
  /** The selected LAN access strategy requires a usable TLS certificate. */
  TLS_REQUIRED: 'TLS_REQUIRED',
  /** Cloudflare Access JWT verification failed / is required. */
  ACCESS_REQUIRED: 'ACCESS_REQUIRED',
  /** A disclosed plan id is missing, expired or does not match the request. */
  CONSENT_REQUIRED: 'CONSENT_REQUIRED',
  /** No pinned official cloudflared asset exists for this platform/architecture. */
  UNSUPPORTED_PLATFORM: 'UNSUPPORTED_PLATFORM',
  /** The downloaded artifact did not match the pinned official SHA-256. */
  CHECKSUM_MISMATCH: 'CHECKSUM_MISMATCH',
  /** The provider executable must be installed/downloaded by the user first. */
  INSTALL_REQUIRED: 'INSTALL_REQUIRED',
  /** The OpenSSH client executable was not found (never downloaded). */
  SSH_MISSING: 'SSH_MISSING',
  CSRF: 'CSRF',
  ORIGIN: 'ORIGIN',
  RATE_LIMITED: 'RATE_LIMITED',
  PAIRING_INVALID: 'PAIRING_INVALID',
  PAIRING_EXPIRED: 'PAIRING_EXPIRED',
  PAIRING_DENIED: 'PAIRING_DENIED',
  /** The one-time pairing code was already claimed once; a replay must be 403. */
  PAIRING_CONSUMED: 'PAIRING_CONSUMED',
  DEVICE_LIMIT: 'DEVICE_LIMIT',
  NOT_ALLOWED: 'NOT_ALLOWED',
  BAD_REQUEST: 'BAD_REQUEST',
  NOT_FOUND: 'NOT_FOUND',
  GATEWAY: 'GATEWAY',
  INTERNAL: 'INTERNAL',
} as const

export type RcErrorCode = (typeof RC_ERRORS)[keyof typeof RC_ERRORS]

/** The one and only REST error envelope shape. */
export interface RcErrorEnvelope {
  ok: false
  error: {
    code: RcErrorCode
    message: string
    retryAfterMs?: number
  }
}

/**
 * Tunnel modes. Backward compatible with the original `quick` / `external` /
 * `named` values:
 * - `quick`: token-free managed cloudflared quick tunnel with a temporary URL;
 * - `named`: remotely-managed Cloudflare named tunnel (connector token/token file);
 * - `named-local`: locally-managed Cloudflare named tunnel (UUID + credentials JSON);
 * - `external`: operator-provided/harness-external fixed HTTPS origin, no child process;
 * - `ssh`: managed OpenSSH reverse tunnel (localhost.run); the only other child-process mode.
 * LAN is a listener access strategy, never a tunnel mode.
 */
export type TunnelMode = 'quick' | 'external' | 'named' | 'named-local' | 'ssh'

/**
 * Lifecycle of the public reachability layer, as shown in the panel.
 * - `missing-config`: required provider input/credentials are missing or invalid;
 * - `missing-binary`: the provider executable is not installed (SSH is never downloaded);
 * - `starting`: child process/listener is starting or the operator origin is being validated;
 * - `connected-unverified`: connector reports connected, public route not proven yet;
 * - `access-required`: Cloudflare Access login/JWT is required before the PWA is reachable;
 * - `ready`: bounded HTTP and WebSocket checks against the configured origin succeeded;
 * - `mismatch`: hostname/DNS/ingress/port does not match the actual listener;
 * - `security-closed`: reserved wire value; the security closure is reported via
 *   `SecurityStateView.closed`/`closedReason` and the tunnel ends up `off`/`down`;
 * - `down` / `off`: failed/stopped.
 */
export type TunnelState =
  | 'off'
  | 'starting'
  | 'connected-unverified'
  | 'access-required'
  | 'ready'
  /** @deprecated legacy alias of `ready`; accepted in stored/test fixtures only. */
  | 'up'
  | 'down'
  | 'missing-config'
  | 'missing-binary'
  | 'mismatch'
  | 'security-closed'

/** Which process actually owns the public exposure. */
export type ProcessOwnership = 'plugin' | 'external' | 'none'

/** Connector transport; `auto` is the default and never a separate method. */
export type TunnelTransport = 'auto' | 'quic' | 'http2'

export interface TunnelStatus {
  enabled: boolean
  mode: TunnelMode
  state: TunnelState
  /** Public HTTPS origin currently serving the PWA, if any. */
  url: string | null
  /** True when the URL is ephemeral and will change on every start (`quick`). */
  temporary: boolean
  /** Who owns the local/public process behind this origin (for the panel). */
  ownership?: ProcessOwnership
  /** Selected connector transport (connector modes only). */
  transport?: TunnelTransport
  /** Local service URL the tunnel forwards to (never the DSH port). */
  serviceUrl?: string | null
  /** Bounded verification results; never inferred from "connector connected". */
  verified?: { http: boolean; ws: boolean }
  /** Human-readable explanation when state is not `ready`/`off`. */
  error: string | null
  /** Additional non-sensitive diagnostic detail (e.g. hostname/port mismatch). */
  detail?: string | null
}

export interface ListenerStatus {
  state: 'off' | 'listening'
  host: string | null
  port: number | null
  /** Origin a phone on the same machine could use (loopback). */
  url: string | null
  secure: boolean
  lan: boolean
  /** Effective listener access strategy. */
  access?: 'loopback' | 'lan'
  protocol?: 'http' | 'https'
}

/** Public device view. Never carries token material or hashes. */
export interface DeviceView {
  id: string
  label: string
  platform: string
  createdAt: number
  lastSeenAt: number
  refreshExpiresAt: number
  /** True for the device that currently holds the single-active-device lease. */
  active?: boolean
}

/** A pairing code currently waiting for a device claim or a desktop decision. */
export interface PairingView {
  claimId: string | null
  deviceName: string
  platform: string
  createdAt: number
  expiresAt: number
  state: PairingState
}

export type PairingState = 'pending' | 'claimed' | 'approved' | 'denied' | 'expired' | 'claimed-timeout'

/* ------------------------------------------------------------------------- */
/* Connection selection / plan (desktop panel)                               */
/* ------------------------------------------------------------------------- */

/** Panel-level connection choices; LAN is modeled as an access strategy. */
export type ConnectionMethod =
  | 'loopback'
  | 'lan'
  | 'cloudflare-quick'
  | 'cloudflare-named'
  | 'cloudflare-named-local'
  | 'external'
  | 'ssh'

/** Explicit user selection sent to plan/start. No free-form command arguments. */
export interface ConnectionSelection {
  method: ConnectionMethod
  /** LAN: explicitly selected interface address (never guessed). */
  lanAddress?: string
  /** Fixed loopback port for remotely-managed named / external; 0/absent = dynamic. */
  loopbackPort?: number
  cloudflaredPath?: string
  transport?: TunnelTransport
  /** Fixed public hostname (named / named-local; validated in the panel). */
  hostname?: string
  /** Remotely-managed named: env var that holds the connector token. */
  tokenEnv?: string
  /** Remotely-managed named: token file path (mutually exclusive with tokenEnv). */
  tokenFile?: string
  /** Locally-managed named: tunnel UUID + its credentials JSON path. */
  tunnelId?: string
  credentialsFile?: string
  /** External: operator-provided fixed HTTPS origin. */
  publicUrl?: string
  /** SSH: explicit executable path (defaults to the platform ssh). */
  sshPath?: string
  sshUser?: string
  sshHost?: string
  sshRemotePort?: number
  /** Fixed-hostname Cloudflare Access enforcement. */
  accessRequired?: boolean
}

/** One human-readable step of the pre-start disclosure ("explain before start"). */
export interface ConnectionPlanStep {
  kind:
    | 'listener'
    | 'tunnel'
    | 'download'
    | 'tls'
    | 'access'
    | 'origin'
    | 'warning'
    | 'security'
  /** Localized-free English text; the panel localizes the step kind + params. */
  text: string
  /** Non-sensitive structured params for the panel (e.g. address, port, size). */
  params?: Record<string, string | number | boolean | null>
}

/** Disclosed download plan for the pinned official cloudflared release. */
export interface CloudflaredDownloadInfo {
  /** Pinmed official release tag, e.g. `2026.10.0`. */
  version: string
  /** Official asset name for this OS/architecture. */
  asset: string
  sizeBytes: number
  /** Official SHA-256 for exactly this release asset. */
  sha256: string
  /** Official release URL used for the download + hash provenance. */
  releaseUrl: string
  cacheDirectory: string
  /** Currently usable binary, if one was already found. */
  installed: {
    path: string
    source: 'configured' | 'path' | 'cache'
    version: string | null
    /** True only for a binary whose digest matched the pinned official hash. */
    verified: boolean
  } | null
  /** False when the platform/architecture has no pinned official asset (fail closed). */
  supported: boolean
}

/**
 * The pre-start plan the desktop user must confirm. `planId` binds the later
 * start call to exactly the disclosed plan; it expires quickly and is one-shot.
 */
export interface ConnectionPlan {
  planId: string
  selection: ConnectionSelection
  steps: ConnectionPlanStep[]
  /** Listener bind decision the plan would apply. */
  listener: {
    access: 'loopback' | 'lan'
    host: string
    port: number
    protocol: 'http' | 'https'
    secure: boolean
  }
  publicOrigin: string | null
  qrOrigin: string | null
  secureCookies: boolean
  accessRequired: boolean
  download: CloudflaredDownloadInfo | null
  expiresAt: number
}

/** Single computed runtime state used by the whole panel (§3). */
export interface ConnectionStateView {
  method: ConnectionMethod
  listener: ListenerStatus
  publicOrigin: string | null
  qrOrigin: string | null
  hostAuthorities: string[]
  secureCookies: boolean
  accessRequired: boolean
  /** Provider-side public exposure status. */
  tunnel: TunnelStatus
}

/** Single active-device lease state. */
export interface DeviceLockView {
  state: 'none' | 'active' | 'selection-required' | 'released'
  activeDeviceId: string | null
  activeDeviceLabel: string | null
  activeSince: number | null
  lastActivityAt: number | null
  idleExpiresAt: number | null
  idleTimeoutMinutes: number
  /** Registered devices exist but the desktop must pick/revoke before enabling. */
  needsSelection: boolean
  registeredDevices: number
}

export type SecurityClosedReason =
  | 'user-emergency'
  | 'circuit-breaker'
  | 'idle-timeout'
  | 'tunnel-lost'
  | 'dispose'
  | null

/** Security/attack-surface runtime state shown in the panel. */
export interface SecurityStateView {
  /** Remote access is closed and will not reopen until the user re-enables it. */
  closed: boolean
  closedReason: SecurityClosedReason
  /** One-shot circuit breaker state (`open` = remote access was closed). */
  circuitBreaker: 'closed' | 'open'
  /** Failures counted in the current manually started remote-access period. */
  failureCount: number
  /** Number of clients currently under a temporary block. */
  blockedClients: number
  /** Current failure window / threshold values for display. */
  failureWindowSeconds: number
  temporaryBanMinutes: number
  maxFailuresBeforeCircuitBreaker: number
  /** Persisted token revocation epoch; bumps permanently invalidate old tokens. */
  revocationEpoch: number
  idleTimeoutMinutes: number
}

/** Audit entry as exposed to the desktop panel (never over the phone surface). */
export interface AuditEntryView {
  id: number
  time: number
  kind: string
  operation: string
  result: 'ok' | 'rejected' | 'failed' | 'notice'
  deviceId: string | null
  deviceLabel: string | null
  ip: string | null
  userAgent: string | null
  detail: string
}

/* ------------------------------------------------------------------------- */
/* Desktop admin API (`RC_ADMIN_PATH`, same origin as the DSH GUI)           */
/* ------------------------------------------------------------------------- */

export interface AdminStatusResponse {
  enabled: boolean
  pluginVersion: string
  dshRelease: string
  devices: DeviceView[]
  pairings: PairingView[]
  listener: ListenerStatus
  tunnel: TunnelStatus
  /** Public URL advertised in the QR when a tunnel/external origin is active. */
  publicUrl: string | null
  /** The URL the QR code currently encodes (origin + /rc/#/pair?c=…). */
  pairingUrlBase: string | null
  /** True when only loopback is reachable: the phone cannot pair. */
  loopbackOnly: boolean
  /** Single computed runtime connection state (§3). */
  connection?: ConnectionStateView
  /** Single-active-device lease state. */
  deviceLock?: DeviceLockView
  /** Security/attack-surface state. */
  security?: SecurityStateView
  /** Current OS/architecture download plan (null when a binary is usable or unsupported). */
  cloudflared?: CloudflaredDownloadInfo | null
  /** Concrete LAN interfaces the user can explicitly select. */
  networkInterfaces?: LanInterfaceView[]
  /** Latest audit records (newest last), bounded. */
  audit?: AuditEntryView[]
}

/** One concrete LAN interface candidate for the panel. */
export interface LanInterfaceView {
  name: string
  address: string
  family: 'IPv4' | 'IPv6'
  scope: 'private' | 'tailscale' | 'link-local' | 'other'
  /** True for plausible phone-reachable private/Tailscale addresses. */
  recommended: boolean
}

export interface AdminStatusEnvelope extends AdminStatusResponse {
  qrSvg: string | null
  /** The pairing code currently shown in the panel (null when none/expired). */
  pairing: AdminPairCreateResponse | null
  /** Non-null when the plugin could not initialize (e.g. corrupt device store). */
  initializationError: string | null
}

export interface AdminControlRequest {
  action: 'enable' | 'disable'
}

export interface AdminControlResponse {
  enabled: boolean
  listener: ListenerStatus
  tunnel: TunnelStatus
}

export interface AdminPairCreateResponse {
  code: string
  url: string
  expiresAt: number
}

export interface AdminPairDecisionRequest {
  claimId: string
}

export interface AdminRevokeRequest {
  deviceId: string
}

export interface AdminOkResponse {
  ok: true
}

/* ------------------------------------------------------------------------- */
/* Desktop admin: connection planning, emergency stop, install, devices      */
/* ------------------------------------------------------------------------- */

export interface AdminConnectionPlanRequest extends ConnectionSelection {}

export interface AdminConnectionPlanResponse {
  ok: true
  plan: ConnectionPlan
}

export interface AdminConnectionStartRequest {
  planId: string
  /** Must be exactly true: the user saw and confirmed the disclosed plan. */
  confirm: true
}

export interface AdminConnectionStartResponse {
  ok: true
  connection: ConnectionStateView
}

export interface AdminConnectionStopResponse {
  ok: true
  connection: ConnectionStateView
}

export interface AdminEmergencyStopRequest {
  /** Must be exactly true: this is a destructive security action. */
  confirm: true
}

export interface AdminEmergencyStopResponse {
  ok: true
  security: SecurityStateView
  connection: ConnectionStateView
}

/** Explicitly select the single active device (required when >1 registered). */
export interface AdminDeviceActivateRequest {
  deviceId: string
}

/** Release the single-active-device lease without revoking the device pairing. */
export interface AdminDeviceReleaseRequest {
  deviceId: string
}

export interface AdminInstallRequest {
  /** Plan id from `connection/plan` (or an install-only plan); one-shot. */
  planId: string
  confirm: true
}

export interface AdminInstallResponse {
  ok: true
  cloudflared: CloudflaredDownloadInfo
}

/* ------------------------------------------------------------------------- */
/* Phone REST surface (`RC_API_PATH`)                                        */
/* ------------------------------------------------------------------------- */

export interface HealthResponse {
  ok: true
  protocol: number
  pluginVersion: string
  dshRelease: string
  secure: boolean
  pairingAvailable: boolean
  /** True while remote access is closed after an emergency shutdown. */
  securityClosed?: boolean
}

export interface PairClaimRequest {
  code: string
  deviceName: string
  platform: string
}

export interface PairClaimResponse {
  ok: true
  claimId: string
  pollToken: string
  status: 'claimed'
  expiresAt: number
}

/**
 * Pairing status poll. The polling secret is a request BODY field (never a GET
 * query value) so it cannot leak into proxy/server access logs. Sent as a CSRF
 * protected POST with an allowed Origin.
 */
export interface PairStatusRequest {
  claimId: string
  pollToken: string
}

export interface PairStatusResponse {
  ok: true
  status: PairingState
  expiresAt: number
  /** Present only once the desktop approved the claim. */
  device?: DeviceView
}

export interface RefreshResponse {
  ok: true
  device: DeviceView
}

export interface LogoutResponse {
  ok: true
}

export interface StateResponse {
  ok: true
  enabled: boolean
  pluginVersion: string
  dshRelease: string
  device: DeviceView
  /** Other paired devices (labels only) so the UI can say "another device is connected". */
  deviceCount: number
  /** True when the in-process DSH gateway is currently reachable. */
  dshReachable: boolean
  /** Single-active-device lease view (the caller is not necessarily the active device). */
  deviceLock?: DeviceLockView
  /** True once the authentication for this request was accepted on a secure origin. */
  secure?: boolean
  /** Epoch ms after which the lease idle clock closes remote access (null when no lease). */
  idleExpiresAt?: number | null
}

/** Normalized session list row. */
export interface SessionSummary {
  sessionId: string
  updatedAt: number
  running: boolean
  agentAvailable: boolean
  blank: boolean
  cwd: string | null
  title: string | null
  parentSessionId: string | null
  /** Best-effort one-line status for the list, e.g. "idle". */
  status: string | null
}

export interface SessionsResponse {
  ok: true
  sessions: SessionSummary[]
  /**
   * Desktop-parity workspace groups (with their session ids in manual order).
   * Optional: an older host or a registry failure falls back to `cwd` grouping.
   */
  workspaces?: WorkspaceGroupView[]
}

/** One DSH Workspace as shown in the desktop sidebar. */
export interface WorkspaceGroupView {
  workspaceId: string
  title: string
  path: string
  sessionIds: string[]
}

export interface CreateSessionRequest {
  /** Workspace the new session joins (exclusive with `cwd`). */
  workspaceId?: string
  /** Directory the session owns when no workspace is named. */
  cwd?: string
}

export interface CreateSessionResponse {
  ok: true
  sessionId: string
}

export interface UploadFileRequest {
  /** Optional display name; the host sanitizes it into the stored leaf name. */
  name?: string
  /** Canonical base64 encoding of the exact file bytes. */
  data: string
}

export interface UploadedFileView {
  attachmentId: string
  name: string
  bytes: number
}

export interface UploadFileResponse {
  ok: true
  /** Per-upload authority accepted only inside the receiving session scope. */
  receiptId: string
  file: UploadedFileView
}

/** One durable image reference returned for transcript rendering. */
export interface SessionAttachmentResponse {
  ok: true
  attachment: {
    attachmentId: string
    mediaType: string
    bytes: number
    width: number
    height: number
    name?: string
  }
  /** Canonical base64 encoding of the exact image bytes. */
  data: string
}

export interface SessionProjectionsResponse {
  ok: true
  sessionId: string
  kind: 'sequenced' | 'migration-required' | 'none'
  asOfSeq: number | null
  values: Record<string, unknown>
}

/** A durable transcript record. Mirrors the DSH session event envelope. */
export interface SessionEventRecord {
  type: string
  seq: number
  time: number
  data?: unknown
  ignorable?: true
  surfaceOp?: unknown
  sourceEventSeqs?: number[]
}

export interface SessionPageResponse {
  ok: true
  sessionId: string
  records: SessionEventRecord[]
  hasMore: boolean
}

/** Backward pagination request for the durable transcript. */
export interface PageRequest {
  /** Return records up to and including this seq (defaults to the newest). */
  throughSeq?: number
  /** Return records strictly before this seq. */
  beforeSeq?: number
  maxMessages?: number
}

/** One prompt content block the phone may send. Mirrors the DSH wire vocabulary. */
export type PromptContentPart =
  | { type: 'text'; text: string }
  | {
      type: 'image'
      mediaType: 'image/png' | 'image/jpeg' | 'image/webp' | 'image/gif'
      /** Canonical base64 encoding of the exact image bytes. */
      data: string
      name?: string
    }
  | { type: 'file'; receiptId: string }

export interface PromptRequest {
  /** Stable client-minted id; a repeated requestId is accepted idempotently by DSH. */
  requestId?: string
  mode?: 'queue' | 'steer'
  content: PromptContentPart[]
  clientTimeZone?: string
}

export interface PromptResponse {
  ok: true
  accepted: boolean
}

export interface CancelResponse {
  ok: true
  accepted: boolean
}

/* ------------------------------------------------------------------------- */
/* Approval / user-question relay                                            */
/* ------------------------------------------------------------------------- */

export type ApprovalDecision = 'allowed-once' | 'rejected'

export type ApprovalKind = 'approval' | 'question'

export interface ApprovalRequestView {
  /** Tool name (safe to display; tool arguments are never forwarded). */
  toolName: string
  reason: string | null
  /** Optional pre-localized display text (string or locale map). */
  displayReason: unknown
  /** Opaque call identifier. */
  callId: string | null
}

export interface QuestionRequestView {
  questions: unknown
}

export interface ApprovalView {
  eventId: string
  kind: ApprovalKind
  request: ApprovalRequestView | QuestionRequestView
  agentId: string | null
  answerable: boolean
  expiresInMs: number
}

/** Answer outcome sent back to DSH through `$events/result`. */
export type AnswerOutcome =
  | { kind: 'result'; value: ApprovalDecision }
  /** Leave the decision to the desktop ("bir sonraki client'a bırak"). */
  | { kind: 'next' }

/* ------------------------------------------------------------------------- */
/* WebSocket `/rc/ws` frames                                                 */
/* ------------------------------------------------------------------------- */

export interface HelloFrame {
  type: 'hello'
  protocol: number
  clientTimeZone?: string
}

export interface SubFrame {
  type: 'sub'
  streamId: string
  kind: typeof RC_STREAM_FOLLOW
  sessionId: string
  maxMessages?: number
}

export interface UnsubFrame {
  type: 'unsub'
  streamId: string
}

export interface RpcFrame {
  type: 'rpc'
  id: string
  method: RemoteRpcMethod
  args: Record<string, unknown>
}

export interface AnswerFrame {
  type: 'answer'
  eventId: string
  outcome: AnswerOutcome
}

export interface PingFrame {
  type: 'ping'
  t: number
}

export interface PongFrame {
  type: 'pong'
  t: number
}

export type ClientFrame =
  | HelloFrame
  | SubFrame
  | UnsubFrame
  | RpcFrame
  | AnswerFrame
  | PingFrame
  | PongFrame

export interface ReadyFrame {
  type: 'ready'
  protocol: number
  pluginVersion: string
  device: DeviceView
}

export interface SnapshotFrame {
  type: 'snapshot'
  streamId: string
  sessionId: string
  cursor: number
  header: unknown
  records: SessionEventRecord[]
  hasMore: boolean
  projections: { asOfSeq: number; values: Record<string, unknown> } | null
}

export interface EventFrame {
  type: 'frame'
  streamId: string
  kind: 'event'
  event: SessionEventRecord
}

export interface AssistantStreamFrame {
  type: 'frame'
  streamId: string
  kind: 'assistant-stream'
  frame: unknown
}

export interface HostEventFrame {
  type: 'event'
  event: string
  args: unknown[]
}

export interface ApprovalFrame {
  type: 'approval'
  eventId: string
  kind: ApprovalKind
  request: ApprovalRequestView | QuestionRequestView
  agentId: string | null
  answerable: boolean
  expiresInMs: number
}

export interface ApprovalCancelFrame {
  type: 'approval-cancel'
  eventId: string
  reason: 'answered-elsewhere' | 'cancelled' | 'expired'
}

/**
 * Explicit acknowledgement for a phone `answer` frame. Without it the phone can
 * only close the card optimistically and never learns that the relay rejected
 * the decision (settled/expired/unauthorised).
 */
export interface AnswerResultFrame {
  type: 'answer-result'
  eventId: string
  ok: boolean
  error?: { code: RcErrorCode; message: string }
}

export interface RpcResultFrame {
  type: 'rpc-result'
  id: string
  ok: boolean
  value?: unknown
  error?: { code: RcErrorCode; message: string }
}

export interface StreamErrorFrame {
  type: 'stream-error'
  streamId: string
  error: { code: RcErrorCode; message: string }
}

export interface DegradedFrame {
  type: 'degraded'
  streamId: string
  droppedAssistantStreamFrames: number
}

export interface ServerDrainFrame {
  type: 'server-drain'
  retryAfterMs: number
}

export type ServerFrame =
  | ReadyFrame
  | SnapshotFrame
  | EventFrame
  | AssistantStreamFrame
  | HostEventFrame
  | ApprovalFrame
  | ApprovalCancelFrame
  | AnswerResultFrame
  | RpcResultFrame
  | StreamErrorFrame
  | DegradedFrame
  | ServerDrainFrame
  | PingFrame
  | PongFrame

/** Endpoints a paired phone may reach over the WS `rpc` frame. Default-deny. */
export type RemoteRpcMethod =
  | 'session/list'
  | 'session/projections'
  | 'session/page'
  | 'session/prompt'
  | 'session/cancel'

/** Endpoints intentionally never exposed to remote clients (documentation of the boundary). */
export const FORBIDDEN_NAMESPACES = [
  'terminal',
  'workspace',
  'credentials',
  'settings',
  'pluginManager',
  'job',
  'attachment',
] as const

/** Heartbeat and flow-control constants shared by host and PWA. */
export const RC_HEARTBEAT = {
  /** Server sends a ping every 15 s. */
  pingIntervalMs: 15_000,
  /** Connection is closed when no pong arrived for 30 s. */
  pongTimeoutMs: 30_000,
  /** Per-socket buffered-bytes budget; assistant-stream frames may be dropped above it. */
  maxBufferedBytes: 512 * 1024,
} as const

/** Pagination bounds accepted from clients. */
export const RC_LIMITS = {
  maxMessages: 200,
  defaultMessages: 80,
  pageDefaultMessages: 40,
  maxPromptChars: 32_000,
  /** Decoded bytes per image/file attachment accepted from the phone. */
  maxAttachmentBytes: 8 * 1024 * 1024,
  /** Attachments allowed on one prompt. */
  maxAttachmentsPerMessage: 6,
  /** Decoded bytes across all attachments of one prompt. */
  maxAttachmentMessageBytes: 16 * 1024 * 1024,
  /** JSON body ceiling for prompts carrying base64 attachments. */
  maxPromptBodyBytes: 32 * 1024 * 1024,
  /** How long a disclosed connection plan stays confirmable. */
  planTtlMs: 120_000,
  /** Cache/backlog bound for the in-memory audit ring. */
  auditCapacity: 200,
} as const

/** Effective default security limits (config may override within its bounds). */
export const RC_SECURITY_DEFAULTS = {
  idleTimeoutMs: 30 * 60_000,
  failureWindowMs: 60_000,
  /** Failures allowed before the next one triggers the temporary ban. */
  failuresBeforeBan: 5,
  temporaryBanMs: 5 * 60_000,
  /** Total failures in one manual session that close remote access. */
  circuitBreakerFailures: 10,
  accessTtlMs: 15 * 60_000,
} as const

/**
 * WebSocket close codes used by the plugin (RFC 6455 private range).
 * `policyViolation` is the standard policy close; the 400x codes are ours.
 */
export const RC_WS_CLOSE = {
  policyViolation: 1008,
  /** Device was revoked, expired or otherwise no longer authenticated. */
  deviceLost: 4001,
  /** Remote access was closed by the security shutdown path. */
  securityClosed: 4002,
  /** The lease idle clock expired. */
  idleTimeout: 4003,
  /** Another device now holds the single-active-device lease. */
  leaseLost: 4004,
} as const

/** Cloudflare Access is enforced in addition to the plugin's own auth layers. */
export const RC_ACCESS_JWT_HEADER = 'cf-access-jwt-assertion'
/** Cookie Cloudflare Access sets on the browser (used only as a fallback hint). */
export const RC_CF_ACCESS_COOKIE = 'CF_Authorization'
