# Remote Control wire protocol (v2)

This document is the human-readable form of `src/shared/protocol.ts`, the single
source of truth for constants, error codes, frames and view shapes.
**`PROTOCOL_VERSION = 2`** in 0.2.0 (v1 was 0.1.x).

## Versioning and compatibility

- Every value below is part of the plugin's own wire contract, not DSH's.
- `GET /rc/api/health` reports the protocol number. `POST /rc/ws` requires the
  first frame to be `hello` with `protocol: 2`; a mismatch closes the socket with
  `1002 "unsupported protocol version"`. **v1 phone clients are rejected.**
- Breaking changes from v1:
  - `POST /rc/api/pair/status` replaces `GET ...?claimId&pollToken` (the polling
    secret is no longer in a query string);
  - new error codes (`DEVICE_LOCKED`, `SECURITY_CLOSED`, `TLS_REQUIRED`,
    `ACCESS_REQUIRED`, `CONSENT_REQUIRED`, `UNSUPPORTED_PLATFORM`,
    `CHECKSUM_MISMATCH`, `INSTALL_REQUIRED`, `SSH_MISSING`);
  - access-token default lifetime is 15 minutes, tokens are bound to a
    revocation epoch, and one active device holds a lease;
  - WS close codes `4001`–`4004` and per-frame authorization;
  - new optional fields on `health`/`state`/`status` views and new admin routes;
  - `quick`/`external`/`named` config compatibility is preserved, but a config
    update does not change the wire version.
- New **optional** response fields may be added within v2; clients must ignore
  unknown JSON fields and unknown non-fatal WS frame types (the broker already
  ignores unknown client frame types, and unknown server fields are additive).

## Origins and paths

The phone talks to the **plugin's own listener**, never to the DSH server:

| Path | Purpose |
|---|---|
| `/rc/` | PWA shell (static, no plugin auth; may be behind Cloudflare Access at the edge) |
| `/rc/app.js`, `/rc/app.css`, `/rc/sw.js`, `/rc/manifest.webmanifest`, `/rc/icon.svg` | Static assets (no plugin auth) |
| `/rc/api/*` | REST API (auth rules below) |
| `/rc/ws` | Single WebSocket multiplexer (cookie + Origin + Access when enabled) |

The desktop talks to the DSH origin through the plugin's admin routes at
`/api/dsh-remote-control/*` (DSH browser session + `ctx.connection.requestRejection`,
plus an explicit local/same-origin gate).

## Error envelope

Every non-2xx JSON response uses one shape:

```json
{ "ok": false, "error": { "code": "AUTH_REQUIRED", "message": "...", "retryAfterMs": 60000 } }
```

`retryAfterMs` is present only when a retry delay is known (e.g. `RATE_LIMITED`);
the same response carries a `Retry-After` header. Messages are short,
non-sensitive and may change; clients must branch on `code`, never on message
text. Body limits: phone API 64 KiB, admin API 16 KiB (oversize → 413
`BAD_REQUEST`).

### Error codes

| Code | Meaning |
|---|---|
| `AUTH_REQUIRED` | No access cookie / not authenticated |
| `TOKEN_EXPIRED` | Access token expired or malformed; refresh and retry |
| `DEVICE_REVOKED` | Device is no longer paired, or the token version changed |
| `DEVICE_LOCKED` | Another device holds the single-active-device lease, or a multi-device store needs an explicit selection |
| `SECURITY_CLOSED` | Remote access was closed by emergency stop / circuit breaker / idle timeout / tunnel loss |
| `TLS_REQUIRED` | LAN access selected without a usable TLS certificate/key |
| `ACCESS_REQUIRED` | Cloudflare Access JWT is missing/invalid, or its login redirect was detected |
| `CONSENT_REQUIRED` | A disclosed plan id is missing/expired/mismatched, or `confirm:true` is absent |
| `UNSUPPORTED_PLATFORM` | No pinned official cloudflared asset exists for this OS/architecture |
| `CHECKSUM_MISMATCH` | Downloaded/cached artifact did not match the pinned official SHA-256/size |
| `INSTALL_REQUIRED` | A provider executable must be installed/downloaded by the user first (or the installed cloudflared is too old for `--token-file`) |
| `SSH_MISSING` | The system OpenSSH client was not found (never downloaded) |
| `CSRF` | Missing/invalid `X-RC-CSRF: 1` on a mutation |
| `ORIGIN` | Host/Origin fence rejection (missing, `null`, malformed, disallowed, mismatch, cross-site) |
| `RATE_LIMITED` | Temporary per-client ban; see `retryAfterMs` |
| `PAIRING_INVALID` | Pairing code is unknown/invalid |
| `PAIRING_EXPIRED` | Pairing code/claim expired, or an approved claim was already consumed |
| `PAIRING_DENIED` | The desktop denied the pairing |
| `PAIRING_CONSUMED` | The one-time pairing code was already claimed once (replay → `403`) |
| `DEVICE_LIMIT` | Maximum number of paired devices reached |
| `NOT_ALLOWED` | Action not permitted in the current state (e.g. remote control disabled) |
| `BAD_REQUEST` | Malformed body/query/path or unsupported method |
| `NOT_FOUND` | Unknown route or unknown pairing/device/plan id |
| `GATEWAY` | The in-process DSH gateway is unavailable (phone REST only) |
| `INTERNAL` | Unexpected server-side failure (details are logged, never returned) |

Phone REST status mapping (`controller.ts` `STATUS_BY_CODE`; a route may raise a
more specific status explicitly):
`401` AUTH_REQUIRED/TOKEN_EXPIRED/DEVICE_REVOKED/ACCESS_REQUIRED;
`409` DEVICE_LOCKED/TLS_REQUIRED/INSTALL_REQUIRED/SSH_MISSING;
`503` SECURITY_CLOSED; `428` CONSENT_REQUIRED; `400`
UNSUPPORTED_PLATFORM/CHECKSUM_MISMATCH/BAD_REQUEST/PAIRING_INVALID; `403`
CSRF/ORIGIN/PAIRING_DENIED/PAIRING_CONSUMED/DEVICE_LIMIT/NOT_ALLOWED; `410` PAIRING_EXPIRED;
`429` RATE_LIMITED; `404` NOT_FOUND; `502` GATEWAY; `500` INTERNAL.
Notable overrides: remote control disabled is `503 NOT_ALLOWED`; “enable Remote
Control first” style admin checks are `409 NOT_ALLOWED`; `remoteMutations`
disabled is `NOT_ALLOWED` (403). `405` method rejections use `BAD_REQUEST` on the
phone surface and `NOT_ALLOWED` on the admin surface (with `Allow`).

## Phone authentication model

- `GET /rc/api/health` and `POST /rc/api/pair/claim` are unauthenticated (the
  Host/Origin fence still applies; the Cloudflare Access check applies when
  enabled).
- Every other REST call requires the `rc_access` cookie, except
  `POST /rc/api/session/refresh`, which requires the `rc_refresh` cookie and
  rotates it.
- Every mutation (`POST`) additionally requires `X-RC-CSRF: 1` **and** a present,
  exact allowed `Origin` that matches the request `Host` authority.
- `POST /rc/api/session/refresh` uses `rc_refresh`, rotates it on every call and is
  serialized per device. Reuse outside the concurrent-rotation grace window
  revokes the device.
- Cookies: `rc_access` / `rc_refresh`, `HttpOnly`, `SameSite=Strict`, `Path=/rc`;
  `Secure` when the listener is TLS or the request's `Host` is a known public
  HTTPS authority. Lifetimes: access = resolved access TTL (default 15 min),
  refresh = refresh TTL (default 10 days); `Max-Age` matches.
- When Cloudflare Access is required, `/rc/api/*` requests and the `/rc/ws` upgrade
  must carry a valid `Cf-Access-Jwt-Assertion` header (verified at the Host).
- When remote access is security-closed, every phone route fails with
  `503 SECURITY_CLOSED` (except `health`, which reports `securityClosed: true`).

## Pairing flow (v2)

```
desktop: POST /api/dsh-remote-control/pair/create
         -> { code, url, expiresAt }              # url = https://<origin>/rc/#/pair?c=<code>
phone:   POST /rc/api/pair/claim { code, deviceName, platform }   (+ CSRF + Origin)
         -> { ok, claimId, pollToken, status: "claimed", expiresAt }
desktop: POST /api/dsh-remote-control/pair/approve { claimId }    # or pair/deny
phone:   POST /rc/api/pair/status { claimId, pollToken }          (+ CSRF + Origin)
         -> 200 { ok, status: "claimed" | "approved", expiresAt, device? }
            approved also sets rc_access + rc_refresh cookies
         -> 403 PAIRING_DENIED | 410 PAIRING_EXPIRED | 409 DEVICE_LOCKED
```

State machine (`PairingState`): `pending` (a code exists, not claimed) →
`claimed` → `approved` | `denied` → terminal; `expired` and `claimed-timeout` are
timeout terminals. The desktop `PairingView` carries `claimId` (null for an
unclaimed code), device name/platform, timestamps and state.

Rules:

- The code is single-use: `claim` consumes it **before** any other check. A replay
  of the same code fails with `403 PAIRING_CONSUMED`; an unknown code is
  `400 PAIRING_INVALID`. Opening the QR alone grants nothing.
- The number of outstanding codes is capped (`pairing.maxPendingCodes`, default 3;
  exceeding it → `429 RATE_LIMITED`).
- `pollToken` is returned once to the claiming browser and is required for
  `pair/status`; a wrong token is reported exactly like an expired claim (fail
  closed, no claim-id oracle).
- Approval reserves the claim once (`beginIssue`, constant-time poll-secret check)
  **before** device creation; a concurrent/replayed status poll cannot mint a
  second device; the approved claim is consumed after cookies are issued.
- The phone's post-approval status response includes `device` (with `active: true`
  for the lease holder) and the cookies; the claim is then gone.
- A second device while a lease is active fails at claim with `409 DEVICE_LOCKED`;
  a store with >1 devices and no selection also blocks claiming and enabling.

## Phone REST surface (`/rc/api/*`)

All responses are JSON and include `ok` except error envelopes. `SessionId`
path segments are URL-decoded. `GET` reads do not require `Origin` from
non-browser clients but do require an allowed `Host`.

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| GET | `/rc/api/health` | none | - | `HealthResponse` |
| POST | `/rc/api/pair/claim` | code | `{ code, deviceName, platform }` | `{ ok, claimId, pollToken, status: "claimed", expiresAt }` |
| POST | `/rc/api/pair/status` | poll token | `{ claimId, pollToken }` | `{ ok, status, expiresAt, device? }` |
| POST | `/rc/api/session/refresh` | refresh cookie | `{}` (body optional) | `{ ok, device }` + rotated cookies |
| POST | `/rc/api/session/logout` | access + CSRF | `{}` | `{ ok: true }` (revokes this device, clears cookies) |
| GET | `/rc/api/state` | access | - | `{ ok, enabled, pluginVersion, dshRelease, device, deviceCount, dshReachable, deviceLock?, secure?, idleExpiresAt? }` |
| GET | `/rc/api/sessions` | access | - | `{ ok, sessions: [SessionSummary], workspaces?: [WorkspaceGroupView] }` |
| POST | `/rc/api/sessions` | access + CSRF | `{ workspaceId? }` or `{ cwd? }` | `{ ok, sessionId }` |
| POST | `/rc/api/sessions/:id/files` | access + CSRF | `{ name?, data }` (canonical base64) | `{ ok, receiptId, file: { attachmentId, name, bytes } }` |
| GET | `/rc/api/sessions/:id/attachments/:attachmentId` | access | - | `{ ok, attachment: { attachmentId, mediaType, bytes, width, height, name? }, data }` |
| GET | `/rc/api/sessions/:id/projections` | access | - | `{ ok, sessionId, kind, asOfSeq, values }` |
| GET | `/rc/api/sessions/:id/page` | access | `?throughSeq&beforeSeq&maxMessages` | `{ ok, sessionId, records, hasMore }` |
| POST | `/rc/api/sessions/:id/prompt` | access + CSRF | `{ requestId?, mode?: "queue"\|"steer", content, clientTimeZone? }` | `{ ok, accepted }` |
| POST | `/rc/api/sessions/:id/cancel` | access + CSRF | `{}` | `{ ok, accepted }` |

`WorkspaceGroupView` = `{ workspaceId, title, path, sessionIds }`. It mirrors the
desktop sidebar: `sessionIds` is the workspace's manual order; sessions in no
workspace remain reachable under their `cwd`. The host reads the groups from the
DSH `workspace/follow` baseline and falls back to `cwd` grouping when the
registry is unavailable.

Prompt `content` mirrors the DSH vocabulary exactly:

```jsonc
{ "type": "text",  "text": "..." }
{ "type": "image", "mediaType": "image/png", "data": "<canonical base64>", "name": "screen.png" }
{ "type": "file",  "receiptId": "<from POST /files>" }
```

Limits (`RC_LIMITS`): 32 000 text characters, 8 MiB decoded per attachment,
6 attachments and 16 MiB decoded attachments per prompt, 32 MiB JSON request
body. Files must be uploaded first; the returned `receiptId` is valid only for
the same session/Agent and is consumed by the prompt.

Field notes:

- `HealthResponse`: `ok, protocol, pluginVersion, dshRelease, secure,
  pairingAvailable, securityClosed?`. `pairingAvailable` is false when remote
  control is disabled/security-closed, the listener has no pairing origin, or the
  device limit is reached.
- `StateResponse.deviceLock` is the lease view (see below); `idleExpiresAt` is the
  epoch-ms lease idle deadline (null when no lease); `secure` reflects HTTPS for
  this request.
- `SessionSummary`: `{ sessionId, updatedAt, running, agentAvailable, blank, cwd,
  title, parentSessionId, status }` (`cwd`/`title`/`status` may be null).
- `session/page` uses `throughSeq` (inclusive) or `beforeSeq` (exclusive);
  `maxMessages` defaults to 40, max 200.
- `SessionEventRecord`: `{ type, seq, time, data?, ignorable?, surfaceOp?,
  sourceEventSeqs? }`.
- Prompt content is `[{ type: "text", text }]`; a plain string is accepted and
  normalized. Empty/whitespace-only prompts are rejected (`BAD_REQUEST`);
  combined text is limited to 32,000 chars; `mode` defaults to `queue`.
  `requestId` is passed to DSH for idempotency.
- Mutations require `remoteMutations: true`; otherwise they fail with
  `NOT_ALLOWED`.
- `GET /rc/api/health` and all mutating paths enforce the method exactly; other
  methods return `405` with `BAD_REQUEST`.

## WebSocket `/rc/ws`

One socket carries many logical streams. Handshake: valid `rc_access` cookie,
the canonical Origin/Host fence with a **required** `Origin` header, the active
device lease, and (when enabled) Cloudflare Access. Otherwise the upgrade is
rejected with `401`/`403`/`429`/`503` (response header `X-RC-Error: <code>`) and
the socket is destroyed. The first frame must be `hello` with
`protocol: 2`; the device is re-authorized at hello and the server replies
`ready`, then starts heartbeats and approval delivery.

### Client → server frames

```jsonc
{ "type":"hello", "protocol":2, "clientTimeZone":"Europe/Istanbul" }
{ "type":"sub", "streamId":"s1", "kind":"follow", "sessionId":"session-...", "maxMessages":80 }
{ "type":"unsub", "streamId":"s1" }
{ "type":"rpc", "id":"r7", "method":"session/list", "args":{} }
{ "type":"answer", "eventId":"...", "outcome":{ "kind":"result", "value":"allowed-once" } }
{ "type":"answer", "eventId":"...", "outcome":{ "kind":"next" } }      // leave it to the desktop
{ "type":"ping", "t":1730000000000 }
{ "type":"pong", "t":1730000000000 }
```

`rpc.method` is allowlisted: `session/list`, `session/projections`,
`session/page`, `session/prompt`, `session/cancel`. Anything else is answered with
an `rpc-result` error `NOT_ALLOWED` and is never dispatched.

### Server → client frames

```jsonc
{ "type":"ready", "protocol":2, "pluginVersion":"0.2.0", "device":{ ... } }

{ "type":"snapshot", "streamId":"s1", "sessionId":"...", "cursor":1234,
  "header":{...}, "records":[{ "type":"event", "event":{ "type":"assistant/message", "seq":1235, "time":123, "data":{} } }],
  "hasMore":true, "projections":{ "asOfSeq":1234, "values":{} } }

{ "type":"frame", "streamId":"s1", "kind":"event", "event":{ ... } }
{ "type":"frame", "streamId":"s1", "kind":"assistant-stream", "frame":{ "type":"chunk", ... } }
{ "type":"stream-error", "streamId":"s1", "error":{ "code":"GATEWAY", "message":"..." } }

{ "type":"event", "event":"api-session/status", "args":["session-...", true] }

{ "type":"approval", "eventId":"...", "kind":"approval",
  "request":{ "toolName":"bash", "reason":"...", "displayReason":{}, "callId":"..." },
  "agentId":"...", "answerable":true, "expiresInMs":300000 }
{ "type":"approval", "eventId":"...", "kind":"question", "request":{ "questions":[ ... ] } }
{ "type":"approval-cancel", "eventId":"...", "reason":"answered-elsewhere" }
{ "type":"answer-result", "eventId":"...", "ok":true }
{ "type":"answer-result", "eventId":"...", "ok":false,
  "error":{ "code":"GATEWAY", "message":"approval request is no longer pending" } }

{ "type":"rpc-result", "id":"r7", "ok":true, "value":{ ... } }
{ "type":"rpc-result", "id":"r7", "ok":false, "error":{ "code":"BAD_REQUEST", "message":"..." } }

{ "type":"degraded", "streamId":"s1", "droppedAssistantStreamFrames":12 }
{ "type":"server-drain", "retryAfterMs":1500 }
{ "type":"ping", "t":1730000000000 }
{ "type":"pong", "t":1730000000000 }
```

Every `answer` receives exactly one `answer-result` for the same `eventId`.
`ok:true` means the relay accepted the decision and DSH settled the waterfall;
the phone removes the card. `ok:false` (or no acknowledgement within the client's
8 s budget) reopens the card with an error so the decision can be retried — the
phone never closes a card optimistically. `approval-cancel` still reports a
settled/cancelled request to the remaining deliveries.

`assistant-stream` chunks can be `text-delta` or `reasoning-delta`; both are
display-only. The PWA renders reasoning as a collapsed disclosure and shows the
live reasoning stream expanded while a turn is running. The phone stores no
preferences: the TR/EN switch travels in the hash query
(`#/sessions?lang=tr`) and is re-applied on reload.

### Close codes

| Code | Name | Meaning |
|---|---|---|
| `1000` | normal | normal close |
| `1001` | going away | server shutdown/drain |
| `1002` | protocol error | first frame not `hello`, `protocol !== 2`, invalid JSON, binary frame |
| `1003` | unsupported data | binary frames are rejected |
| `1008` | policy violation | generic policy close (e.g. disabled) |
| `1013` | try again later | per-device connection limit exceeded (default 4) |
| `4001` | device lost | device revoked/expired or failed per-frame authorization |
| `4002` | security closed | emergency shutdown / circuit breaker / idle timeout closed access |
| `4003` | idle timeout | the lease idle clock expired (reserved close reason; the idle handler normally triggers the security shutdown first) |
| `4004` | lease lost | another device holds/obtained the active lease, or the device released it |

### Semantics

- **Authorize at hello and per frame.** Authentication is not upgrade-only: the
  device must exist, its access token must not be expired, security must not be
  closed, the plugin must be enabled, and the device must still hold the lease.
  The access-token expiry is bound to the individual socket at upgrade time (the
  broker stores it per connection, never per device), so a newer connection of the
  same device cannot extend an older socket's session: the older socket starts
  refusing frames as soon as its own deadline passes.
  Every `rpc`/`answer` frame is re-checked before dispatch; a denied `rpc` first
  receives `rpc-result {ok:false, error:{code,message}}`, then the socket closes
  with `4001`/`4004`. The denied frame is never executed. The same full check also
  runs before `sub`/`unsub`/`ping`/`pong`/unknown frames; a denied non-mutation
  frame is dropped and the socket closes with `4001` (no follow channel is opened).
- **Idle touch.** Verified phone activity renews the lease idle clock **and** the
  30-minute session idle clock: `hello`, `sub`, `unsub`, `rpc`, `answer`, and client
  `ping` — never server pings or automatic `pong` replies. If `touch` reports the
  device no longer holds the lease, the socket closes with `4004`.
- **Snapshot on every (re)connect.** `session/follow` takes no `sinceSeq`; a
  reconnect opens a new follow stream and receives a fresh snapshot. Use
  `session/page` (`throughSeq`/`beforeSeq`) for older messages.
- **No replay.** Prompts, cancels and approval answers are never replayed.
  `requestId` makes prompts idempotent on the DSH side. Pending approvals are
  re-delivered by DSH to a fresh answering client; settled ones never are.
- **Approvals.** The plugin opens one answering `$events` client per paired
  device, so DSH forwards the same waterfall to the desktop and every phone (when
  `approvalRelay` is enabled). The first answer settles the event; other clients
  receive `approval-cancel` (`answered-elsewhere`). The plugin never fabricates
  `allowed-once`/`rejected`; it reports a failed answer instead.
- **Heartbeat.** Server ping every 15 s; no pong within 30 s closes the socket.
- **Backpressure.** 512 KiB per socket; assistant-stream frames may be dropped
  (reported with `degraded`), durable transcript `event` frames are not.
- **Disconnect ≠ agent stopped.** Connection state and agent state are separate.
- **Drain.** Disable/restart/emergency sends `server-drain` (or closes directly for
  a security shutdown) and then closes sockets; see the close-code table.

## View types shared by phone and desktop

```ts
DeviceView   = { id, label, platform, createdAt, lastSeenAt, refreshExpiresAt, active? }
PairingView  = { claimId, deviceName, platform, createdAt, expiresAt, state }
PairingState = 'pending' | 'claimed' | 'approved' | 'denied' | 'expired' | 'claimed-timeout'

ListenerStatus = {
  state: 'off' | 'listening', host, port, url, secure, lan,
  access?: 'loopback' | 'lan', protocol?: 'http' | 'https'
}

TunnelStatus = {
  enabled, mode: 'quick'|'external'|'named'|'named-local'|'ssh',
  state: 'off'|'starting'|'connected-unverified'|'access-required'|'ready'|'up'|'down'
        |'missing-config'|'missing-binary'|'mismatch'|'security-closed',
  url, temporary, ownership?: 'plugin'|'external'|'none',
  transport?: 'auto'|'quic'|'http2', serviceUrl?,
  verified?: { http: boolean; ws: boolean }, error, detail?
}

DeviceLockView = {
  state: 'none'|'active'|'selection-required'|'released',
  activeDeviceId, activeDeviceLabel, activeSince, lastActivityAt,
  idleExpiresAt, idleTimeoutMinutes, needsSelection, registeredDevices
}

SecurityStateView = {
  closed, closedReason: 'user-emergency'|'circuit-breaker'|'idle-timeout'|'tunnel-lost'|'dispose'|null,
  circuitBreaker: 'closed'|'open', failureCount, blockedClients,
  failureWindowSeconds, temporaryBanMinutes, maxFailuresBeforeCircuitBreaker,
  revocationEpoch, idleTimeoutMinutes
}

AuditEntryView = {
  id, time, kind, operation, result: 'ok'|'rejected'|'failed'|'notice',
  deviceId, deviceLabel, ip, userAgent, detail
}

CloudflaredDownloadInfo = {
  version, asset, sizeBytes, sha256, releaseUrl, cacheDirectory,
  installed: { path, source: 'configured'|'path'|'cache', version, verified } | null,
  supported: boolean
}

LanInterfaceView = { name, address, family: 'IPv4'|'IPv6',
  scope: 'private'|'tailscale'|'link-local'|'other', recommended }
```

`TunnelState.up` is a deprecated legacy alias of `ready`; clients should treat it
as `ready` and new servers never emit it.

## Desktop admin API (`/api/dsh-remote-control/*`)

Same origin as the DSH GUI. Every route, in order:

1. `ctx.connection.requestRejection(request)` — `401` → `AUTH_REQUIRED`,
   `403` → `ORIGIN`;
2. explicit local/same-origin gate: `Sec-Fetch-Site: cross-site` refused, an
   `Origin` must match the exact DSH origin, and without an `Origin` only a
   loopback peer is accepted (a bare `Host` header never grants admin access);
3. exact HTTP method;
4. for `object` routes: `Content-Type: application/json` and a JSON object body
   (≤ 16 KiB).

Responses set `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`. Failures use the same error envelope; unknown
internal failures collapse to `503 INTERNAL`.

### Admin routes

| Method | Path | Request body | Response |
|---|---|---|---|
| GET | `/api/dsh-remote-control/status` | - | `AdminStatusEnvelope` |
| GET | `/api/dsh-remote-control/pending` | - | `{ pairings: [PairingView] }` |
| GET | `/api/dsh-remote-control/audit` | - | `{ entries: [AuditEntryView] }` (full ring) |
| POST | `/api/dsh-remote-control/control` | `{ action: "enable" \| "disable" }` | `{ enabled, listener, tunnel }` |
| POST | `/api/dsh-remote-control/pair/create` | - | `{ code, url, expiresAt }` |
| POST | `/api/dsh-remote-control/pair/approve` | `{ claimId }` | `{ ok: true }` |
| POST | `/api/dsh-remote-control/pair/deny` | `{ claimId }` | `{ ok: true }` |
| POST | `/api/dsh-remote-control/device/revoke` | `{ deviceId }` | `{ ok: true }` |
| POST | `/api/dsh-remote-control/device/revoke-all` | - | `{ ok: true }` |
| POST | `/api/dsh-remote-control/device/activate` | `{ deviceId }` | `{ ok: true }` |
| POST | `/api/dsh-remote-control/device/release` | `{ deviceId }` | `{ ok: true }` |
| POST | `/api/dsh-remote-control/connection/plan` | `ConnectionSelection` | `{ ok: true, plan: ConnectionPlan }` |
| POST | `/api/dsh-remote-control/connection/start` | `{ planId, confirm: true }` | `{ ok: true, connection: ConnectionStateView }` |
| POST | `/api/dsh-remote-control/connection/stop` | - | `{ ok: true, connection: ConnectionStateView }` |
| POST | `/api/dsh-remote-control/emergency-stop` | `{ confirm: true }` | `{ ok: true, security: SecurityStateView, connection: ConnectionStateView }` |
| GET | `/api/dsh-remote-control/install/info` | - | `CloudflaredDownloadInfo` |
| POST | `/api/dsh-remote-control/install` | `{ planId, confirm: true }` | `{ ok: true, cloudflared: CloudflaredDownloadInfo }` |
| POST | `/api/dsh-remote-control/tunnel/start` | - | `TunnelStatus` (legacy explicit action) |
| POST | `/api/dsh-remote-control/tunnel/stop` | - | `TunnelStatus` (legacy explicit action) |

`dsh-remote-control` routes with a JSON body require the object form; extra
unknown fields are ignored. `confirm` must be exactly `true` on
`connection/start`, `install` and `emergency-stop` (otherwise `428
CONSENT_REQUIRED`). `status` does not start anything; it reports the current
state and includes `qrSvg` + `pairing` when a pairing code is shown.

`AdminStatusEnvelope` = `AdminStatusResponse` plus `qrSvg`, `pairing`,
`initializationError`:

```ts
AdminStatusResponse = {
  enabled, pluginVersion, dshRelease,
  devices: DeviceView[], pairings: PairingView[],
  listener: ListenerStatus, tunnel: TunnelStatus,
  publicUrl, pairingUrlBase, loopbackOnly,
  connection?: ConnectionStateView, deviceLock?: DeviceLockView,
  security?: SecurityStateView, cloudflared?: CloudflaredDownloadInfo | null,
  networkInterfaces?: LanInterfaceView[],
  audit?: AuditEntryView[]
}
```

### Connection selection (plan input)

```ts
ConnectionSelection = {
  method: 'loopback' | 'lan' | 'cloudflare-quick' |
          'cloudflare-named' | 'cloudflare-named-local' | 'external' | 'ssh',
  lanAddress?, loopbackPort?, cloudflaredPath?, transport?: 'auto'|'quic'|'http2',
  hostname?, tokenEnv?, tokenFile?, tunnelId?, credentialsFile?, publicUrl?,
  sshPath?, sshUser?, sshHost?, sshRemotePort?, accessRequired?
}
```

Validation: unknown methods/fields with the wrong type are `400 BAD_REQUEST`;
`transport` must be `auto|quic|http2`; connector token sources are mutually
exclusive (selection-level and, for a config-driven run, config-level: an explicit
`tokenEnv` **and** a `tokenFile` is rejected rather than silently preferring one);
`named` requires a bare hostname; `named-local` requires a bare hostname + UUID +
credentials path; `external` requires a canonical HTTPS origin (no path/query);
`loopbackPort` is the explicitly selected fixed loopback port for `cloudflare-named`
and `external`; `ssh` host/user/remote-port are allowlisted; LAN requires a concrete
interface address present on this machine and a configured TLS cert/key
(`TLS_REQUIRED` otherwise) — the panel selection of that concrete address is the
explicit LAN opt-in; `accessRequired` is only valid for fixed-hostname methods and,
when true, **is enforced** by the Host for that run even if
`tunnel.access.required` is false. Malformed `cloudflaredPath` selections (non-string,
empty/control characters, `.cmd`/`.bat`/`.ps1` shims) fail with `BAD_REQUEST` before
any process is spawned; a selection overrides the configured binary (ordered
candidates: selection, then configured path, then `PATH`, then the verified cache).

### Connection plan / consent semantics

`POST connection/plan` returns a **disclosed plan** and starts nothing:

```ts
ConnectionPlan = {
  planId, selection: ConnectionSelection,
  steps: [{ kind: 'listener'|'tunnel'|'download'|'tls'|'access'|'origin'|'warning'|'security',
            text, params? }],
  listener: { access: 'loopback'|'lan', host, port, protocol: 'http'|'https', secure },
  publicOrigin, qrOrigin, secureCookies, accessRequired,
  download: CloudflaredDownloadInfo | null,
  expiresAt
}
```

- `planId` is random and **one-shot**; it expires after **120 seconds**
  (`RC_LIMITS.planTtlMs`), and the host keeps a bounded cache (32 plans).
- `connection/start` requires the `planId` of a still-valid plan and
  `confirm: true`; the attempt consumes the plan (a call with the id removes it
  even if `confirm` was omitted, so a missed confirmation needs a new plan). A
  missing, expired or replayed plan fails with `428 CONSENT_REQUIRED`. Starting
  from a plan is the only way to apply a new connection selection from the panel.
- `install` requires a valid, unexpired plan id from `connection/plan` and
  `confirm: true`; the panel only offers the download when that plan's `download`
  is non-null. On success it **consumes the plan** (the panel re-plans after
  installing before it can start); a failed install keeps the plan usable until it
  expires. Installing does not start anything.
- The plan discloses the listener decision, `publicOrigin`/`qrOrigin`,
  `secureCookies`, Cloudflare Access enforcement, the pinned download
  (version/asset/size/SHA-256/release URL/cache dir), TLS usage for LAN, provider
  warnings, the “one active device” rule and the emergency-stop contract. The
  panel renders these steps; the user confirms with the same `planId`.
- `connection/stop` stops the public exposure/provider child, closes every open
  WebSocket/follow/approval stream (policy close `1008`), revokes the runtime
  public origin from `hostAuthorities`/QR state, and keeps remote control enabled;
  it does not revoke tokens or devices. It is different from `emergency-stop`. For
  LAN it reverts the listener to loopback. For an `external` method there is no
  plugin-owned child to stop: Stop additionally stops the plugin listener, so the
  operator-owned connector/service keeps existing but has nothing left to forward
  to (the plugin cannot terminate that external service). `connection.listener`
  then reports `state: "off"` and `publicOrigin`/`qrOrigin` are `null`; the logical
  `enabled` flag stays true so a new plan can be started without re-pairing.
- `emergency-stop` is the one-shot destructive action described in
  `SECURITY.md` (revocation epoch bump, device revocation, teardown, persisted
  closure, no auto-reopen). It requires `confirm: true`.
- Legacy `tunnel/start`/`tunnel/stop` act on the configured tunnel at runtime
  without changing the listener configuration; `tunnel/start` fails with
  `NOT_ALLOWED` when remote control is disabled. New panels should prefer the
  plan/start/stop workflow.

### State views returned by plan/start/stop

```ts
ConnectionStateView = {
  method: ConnectionSelection['method'],
  listener: ListenerStatus, publicOrigin, qrOrigin,
  hostAuthorities: string[], secureCookies, accessRequired,
  tunnel: TunnelStatus
}
```

`publicOrigin`/`qrOrigin` follow the single computed runtime state: a managed
tunnel's origin is cleared when the provider changes, the connection stops or a
security shutdown runs. A fixed `external` public origin comes from configuration
and remains the advertised origin while the plugin is running; the plugin cannot
make an operator-owned connector unreachable. `secureCookies` is true when the
listener is TLS or the public origin is HTTPS (for temporary providers the public
origin is unknown at plan time, so the plan may show `false` while runtime cookies
become `Secure` once the HTTPS origin is known). `accessRequired` reflects the
**effective** Cloudflare Access requirement for the live run: the config switch or
the active plan's `accessRequired`.

### Tunnel status state `security-closed` (reserved)

The `TunnelState` union keeps `security-closed` for wire compatibility, but the
tunnel manager never emits it: the plugin's security closure is reported through
`SecurityStateView.closed`/`closedReason` and the tunnel reports `off`/`down` after
the listener and owned child are terminated.

## Trusted-proxy and origin expectations per method

| Method | Peer seen by the listener | Client-IP policy |
|---|---|---|
| `loopback` | loopback / local browser | socket address |
| `lan` | direct LAN peer | socket address; forwarding headers ignored |
| `cloudflare-quick` / `cloudflare-named` / `cloudflare-named-local` | loopback (plugin's own connector) | `CF-Connecting-IP` honoured only from the loopback peer; missing/invalid ⇒ unknown |
| `external` | loopback (operator connector) | no trusted client-identity header ⇒ unknown shared bucket |
| `ssh` (localhost.run) | loopback (SSH client) | no trustworthy client IP ⇒ unknown shared bucket |

`X-Forwarded-For`/`Forwarded` are never trusted. The public origin must be HTTPS
for tunnel/external methods; the canonical fence compares exact
scheme + host + effective port and requires `Origin`/`Host` agreement on WS and
mutations.

## Security-closed behavior

While `securityClosed` is true:

- phone REST: `503 SECURITY_CLOSED` (the `health` route still answers and reports
  `securityClosed: true`);
- WS upgrade: rejected `503` with `X-RC-Error: SECURITY_CLOSED`;
- existing sockets are closed with `4002` during the shutdown;
- pairing creation/claim/approval are refused;
- the panel shows the reason (`user-emergency`, `circuit-breaker`,
  `idle-timeout`, `tunnel-lost`) and a re-enable action.

Re-enabling is explicit (`control {action:"enable"}` or starting a new confirmed
plan); nothing reopens automatically, including after a restart.

## Data-plane mapping (Host side)

| Phone call | DSH gateway call |
|---|---|
| `session/list` | `session/list` |
| `session/projections` | `session/projections` |
| `session/page` | `session/page` |
| `session/prompt` | `session/prompt` (`mode: queue\|steer`) |
| `session/cancel` | `session/cancel` |
| `sub kind=follow` | `session/follow` stream (`assistantStream:true`, snapshot + event frames) |
| `approval` / `approval-cancel` | per-device `$events` wire stream |
| `answer` | `$events/result` (`dispatchRpc`) |

The phone never receives an arbitrary DSH endpoint: the only reachable DSH
functions are the allowlisted ones above.

## DSH wire argument wrapping

The installed typert gateway validates exact argument keys: the key is
`parameter.wire ?? parameter.name`. The gateway client therefore wraps logical
arguments as follows:

- `session/list` → `{ _request: { ... } }`
- `session/follow`, `session/page`, `session/prompt`, `session/cancel`,
  `session/projections` → `{ request: { ... } }`
- endpoints without parameters → `{}`

`session/follow` accepts `assistantStream` only as `true` (or omitted);
`session/page` requires `throughSeq`.
