# Security Policy — DSH Remote Control

This plugin gives a paired phone **owner-level control** of a local DeepSeek
Harness session. Treat it like an SSH key for your agent, not like a read-only
dashboard. It is a personal-scale remote-control plugin, not an audited or
certified product; nothing here is a claim of “100 % security” or
“production-ready”.

## Supported versions

| DSH Remote Control | DSH Host | Status |
|---|---|---|
| 0.2.x | `>=0.2.1-rc.3 <0.3.0` | supported |
| 0.1.x | `>=0.2.1-rc.3 <0.3.0` | superseded (wire protocol v1; old clients rejected by the v2 hello gate) |

## Reporting a vulnerability

Please do not open a public issue for security problems. Report privately to the
repository owner (GitHub security advisory or the contact in the repository
profile) with: affected version, reproduction steps, impact and any suggested
fix. We will acknowledge as soon as possible and coordinate disclosure.

## Threat model

| Assumption | Consequence |
|---|---|
| The DSH Host, the desktop user and the phone owner are the same person | The phone is an owner operator; there is no viewer/RBAC role in this DSH build |
| The phone is a trusted device | Losing it means losing Host control — revoke from Settings immediately |
| The desktop click is the trust anchor | Every new device requires a human approval on the desktop; there is no config switch to disable it |
| A tunnel terminates TLS at the provider edge | Quick/named Cloudflare and localhost.run traffic is visible to that provider at the edge; it is not end-to-end encrypted between phone and Host |
| Loopback is the safe default; LAN is explicit | The listener binds `127.0.0.1` unless the user explicitly selects LAN **and** configures TLS |
| The operator configures Cloudflare/DNS/Access/TLS | The plugin validates shape and fails closed, but cannot prove that an operator's Cloudflare route or Access policy is “correct” |
| TLS to the pinned release host is authentic | The SHA-256 pin defends against corrupt/mirrored downloads, not against a compromised upstream account |

**Assets protected**: the ability to read the local DSH transcript and to
prompt/steer/cancel/answer approvals; the device token material; the tunnel
connector secrets; the integrity of the Host process and of the user's files.
**Trust boundaries**: phone/browser → public origin → provider/connector →
plugin listener → controller → DSH gateway. The desktop admin API is a separate
boundary on the DSH origin behind DSH's own browser auth.

**Non-goals**: protecting against a malicious phone owner (they are an owner
operator), against a malicious local user with access to the Host account, against
provider compromise, against a compromised OS/Node runtime, or against a user who
approves a pairing they did not initiate.

## Safe defaults

| Setting | Default | Notes |
|---|---|---|
| `enabled` | `false` | No listener, no socket, no tunnel until the user enables it |
| `autoStart` | `false` | A previously enabled listener is not re-opened automatically unless opted in |
| `tunnel.enabled` | `false` | No public exposure by default |
| `listen.access` | `loopback` | Wildcard binds (`0.0.0.0`, `::`) are always refused |
| `remoteMutations` / `approvalRelay` | `false` (config) | The shipped bundle row sets both to `true` so a paired phone is a full operator once the user enables the plugin; a read-only phone is safer — turn them off |
| Desktop approval | always required | Not configurable |
| `tokens.accessTtlMinutes` | 15 min effective | Legacy `accessTtlHours` accepted; minimum effective 10 min |
| `tokens.refreshTtlDays` | 10 days | Rotated on every use with reuse detection |
| `tokens.maxDevices` | 4 | Hard schema ceiling 4; only one device is active |
| `security.idleTimeoutMinutes` | 30 | 5–240 |
| `security.failuresBeforeBan` | 5 | The 6th failure in the window bans |
| `security.circuitBreakerFailures` | 10 | One-shot shutdown for the period |
| cloudflared download | user-initiated only | Never at load/background; pinned version + SHA-256 |
| `userQuestions` | `false` | Wire shape unconfirmed for this DSH build |

## Enforced by code vs. depends on the operator/network/CI

| Enforced by this repository's code | Depends on the operator / network / CI |
|---|---|
| Loopback listener + wildcard-bind refusal; LAN requires explicit address **and** TLS | That the operator's TLS certificate is issued by a CA the phone trusts |
| Canonical scheme+host+effective-port Origin/Host fence, `Sec-Fetch-Site`, CSRF header | Browser behavior and any reverse proxy that must preserve Host/Origin headers |
| Single-use pairing codes, atomic reservation, mandatory desktop approval | That the human actually checks the pairing prompt |
| Single-active-device lease at every layer | That the operator resolves legacy multi-device stores via select/revoke |
| HttpOnly/SameSite=Strict/`Secure`-when-HTTPS cookies, 15-min access token, refresh rotation + reuse detection | The operator's browser/OS not being compromised |
| Persisted revocation epoch + device revocation on emergency stop | That the state file on the Host disk is not tampered with by a local admin |
| Shared failure accounting, temporary bans, one-shot breaker, idle timeout | Distribution/volume of real attack traffic; in-memory counters reset on restart |
| Provider-scoped client-IP policy (no `X-Forwarded-For` trust) | Whether the provider actually forwards the documented header |
| Pinned cloudflared version/asset/size/SHA-256, HTTPS-only bounded download, atomic cache, re-verify | TLS to GitHub and the upstream account not being compromised |
| OpenSSH executable+argv hardening, plugin-owned `known_hosts`, TOFU | That `localhost.run` is the real provider you intend to use |
| Cloudflare Access JWT verification (RS256/JWKS/aud/iss/exp) when enabled | That the operator's Access application/team/audience are correct |
| No shell, allowlisted child env, `.cmd/.bat` refusal, owned-child-only termination | OS-level process/file permissions of the Host user account |
| Audit sanitization and bounded ring | That the operator looks at the panel/logs |
| No `process.exit()`; `ctx.effect` cleanup | No guarantee under `SIGKILL`, forced termination or power loss |
| **No claim**: real Cloudflare/localhost.run/phone/LAN/TLS end-to-end is **not** exercised by CI | Manual acceptance testing must be run by the operator for real providers |

## Pairing and session security

- 256-bit pairing code (CSPRNG), default 120 s TTL (30–600 configurable), max 3
  outstanding codes. The raw code is never stored: only its SHA-256 is kept in
  memory.
- The code travels in the URL **fragment** and is removed from the address bar and
  history immediately; it is not sent to the server, proxies or Referer headers.
- A claim atomically consumes the code before any other check. A **replayed** claim
  of an already-consumed code is answered with `403 PAIRING_CONSUMED` (distinct from
  an unknown code, which is `400 PAIRING_INVALID`) and counts once as a failed
  authentication attempt. The polling secret is a POST body field with a CSRF header
  and an allowed Origin — never a GET query value.
- Desktop approval is mandatory. Approval reserves the claim exactly once
  (`beginIssue`, constant-time poll-secret check) **before** the first async
  device-creation step; a concurrent or replayed poll cannot mint a second device,
  and a persistence failure leaves a safe state.
- Tokens: stateless HMAC access token
  (`rc1.<deviceId>.<exp>.<tokenVersion>.<epoch>.<nonce>.<sig>`) bound to the device,
  its `tokenVersion` and the persisted revocation epoch; random 32-byte refresh
  token stored only as SHA-256. All secret comparisons use `crypto.timingSafeEqual`
  (or fixed-length digests); malformed secrets never throw.
- Refresh rotation: every refresh rotates the token. Reuse of a rotated-out token
  (outside the short concurrent-rotation grace window) revokes the device. One
  refresh token can never produce two independent valid sessions; concurrent
  refresh requests are serialized per device.
- Cookies: `HttpOnly`, `SameSite=Strict`, `Path=/rc`, and `Secure` whenever the
  listener is TLS or the request arrives through a known public HTTPS authority.
  Cookies are cleared on logout/revoke. Tokens, cookies, pairing codes and polling
  secrets are never logged.
- The mobile PWA never receives a DSH cookie or an Access service secret.

## Single-active-device lock

- Exactly one logical device holds the lease; the lease (device id + start/last
  activity) is persisted in the plugin state file and restored after a restart.
- Enforcement points: pairing claim, desktop approval, REST authentication,
  refresh, WebSocket upgrade, and every WebSocket `rpc`/`answer` frame. A losing
  device gets `DEVICE_LOCKED` (REST 409 / WS close 4004).
- Same device: multiple tabs and reconnects keep the lease (re-activation is a
  no-op refresh); a short disconnect never transfers it. There is no
  disconnect-transfer API.
- The lease ends only by explicit desktop release, device revoke, emergency
  shutdown, idle timeout, or an idled-out restoration.
- An idled-out lease restored at startup fails closed; remote access stays closed
  until the user re-enables.
- A store with more than one registered device and no active selection blocks
  enabling/pairing until the desktop performs an explicit select/revoke. The
  plugin never picks randomly and never silently deletes a device.
- IP address and User-Agent are **never** device identity evidence (they are only
  audit metadata when reliably attributable).

## Rate limiting and the circuit breaker

All failed-authentication paths (pairing secret, polling secret, access token,
refresh token, WS verification) share one accounting; a request is counted at most
once.

- **Temporary per-client ban**: a sliding window (default 60 s) counts failures.
  With `failuresBeforeBan = 5`, the **6th** failure inside the window blocks that
  client for `temporaryBanMinutes` (default 5). A blocked client is rejected once
  with `RATE_LIMITED` + `Retry-After`; **blocked repeats are not counted and never
  extend the ban**.
- **One-shot circuit breaker**: with `circuitBreakerFailures = 10`, the 10th
  failure counted inside one manually started remote-access period opens the
  breaker, which runs the safe shutdown once. It never reopens automatically; an
  explicit user re-enable starts a fresh period (`beginSession`).
- A successful verified authentication clears that client's sliding window. A
  **normally expired access token is not counted as an attack**: the client gets
  `401 TOKEN_EXPIRED`, refreshes, and normal expiry/refresh use never accumulates
  toward the circuit breaker. Only structurally/signature/epoch-invalid tokens
  count as failures. Successful pairing polls and health/static access are not
  failures.
- Memory is bounded: at most 1,024 client keys are tracked (oldest evicted under
  pressure); per-client failure lists are truncated to the threshold. Counters are
  in-memory only — a DSH restart clears bans/session failure counts, while the
  persisted security closure and revocation epoch remain.
- Clients whose real address cannot be established share one conservative bucket
  (`shared:unknown-client`) instead of bypassing limits.

**Deliberate DoS trade-off (documented, not a bug)**: an attacker who can cause 10
authentication failures in one remote-access period can force remote access
closed until the desktop user re-enables it. This is preferred over an unbounded
retry surface. The plugin **never kills the DSH Host process**, never touches your
sessions/tools/files, never auto-reopens, and recovery needs no DSH restart —
only an explicit desktop re-enable. Do not remove or silently raise the threshold
to “fix” an outage; raise it deliberately via config if you accept the larger
retry surface.

## Trusted-proxy and client-IP policy

The plugin never trusts an arbitrary forwarding header. The policy is scoped to
the provider that terminates the public connection:

| Situation | Client identity used |
|---|---|
| Direct non-loopback peer (LAN, loopback-only local browser) | The socket address; `CF-Connecting-IP`/`X-Forwarded-For`/`Forwarded` are ignored |
| Loopback peer + Cloudflare connector (quick/named/named-local) | A well-formed `CF-Connecting-IP` is honoured — the peer is the plugin's own connector. Missing/malformed ⇒ explicit “unknown” |
| Loopback peer + SSH/localhost.run | No trustworthy client IP exists ⇒ explicit “unknown” shared bucket (the peer is tunnel infrastructure) |
| Loopback peer + external connector | No client-identity header scheme is trusted ⇒ “unknown” shared bucket |
| Loopback peer + no tunnel | The loopback peer is the real local client |

`X-Forwarded-For` and the `Forwarded` header are **never** trusted. When the real
client cannot be established, the panel/audit show the unknown state explicitly
and a safe shared limit applies. Audit `ip` fields keep only real IP literals and
are `null` when unknown.

## Origin / Host fence

- `Host` must be an exact allowlisted authority. `Origin`, when present, must be an
  exact canonical `scheme://host:effective-port` origin in the allowlist **and** its
  authority must equal `Host`; scheme and effective port are part of the
  comparison. Missing `Host`, missing `Origin` on WS/mutations, literal `null`,
  malformed/duplicate headers, credentials in the URL, non-http(s) schemes,
  `Origin != Host` and `Sec-Fetch-Site: cross-site` are rejected with `ORIGIN`.
- WebSocket upgrades and browser mutations require `Origin`; HTTP reads from
  non-browser clients (no `Origin`) are allowed only with a valid allowlisted
  `Host`.
- Every authenticated mutation additionally requires `X-RC-CSRF: 1`.
- Additional origins are configurable (`allowedOrigins`) for a reverse proxy you
  control; each entry is validated and must be an exact origin. This is an
  advanced escape hatch — do not add origins you do not control.
- JSON-only bodies, bounded body sizes (16 KiB admin, 64 KiB phone; prompt bodies
  may carry base64 attachments up to 32 MiB) and the strict route allowlist are
  enforced.

### Phone attachments and new sessions

- Attachments are accepted only on the authenticated phone REST routes and only
  while `remoteMutations` is enabled (upload/new-session/prompt all pass the same
  mutation gate). Bodies are canonical-base64 checked, limited to 8 MiB decoded per
  item and 6 items / 16 MiB per prompt; anything else is rejected before the
  gateway.
- Images travel inline in the DSH prompt (`{type:"image", mediaType, data}`); other
  files are uploaded first through the session-scoped `fileUploads/upload` Remote,
  which returns a receipt valid only for that same session/Agent. The phone never
  receives a filesystem path, and it cannot ask the plugin to read arbitrary files.
- Transcript images are fetched back through
  `GET /rc/api/sessions/:id/attachments/:attachmentId`, which the host resolves via
  DSH's `session/attachment` (the DSH session itself proves reachability). The
  response is base64 image data only; no workspace file endpoint is exposed.
- Workspace grouping is read-only: the host reads the first `workspace/follow`
  baseline and returns workspace titles/paths/session ids; `workspace/*` mutation
  Remotes are never exposed to the phone.
- New sessions are created through DSH `session/create` with an optional
  workspace id from that baseline (or a cwd); the phone cannot name arbitrary
  endpoints or presets.

## WebSocket authentication

Authentication is not upgrade-only:

- The upgrade requires the access cookie, the Origin fence and (when enabled) the
  Cloudflare Access assertion. Missing/expired/revoked/locked devices are rejected
  before the socket is created.
- At `hello`, the device is re-checked (revoked/expired/lease lost between upgrade
  and hello) and the protocol version must match `2` exactly; otherwise the socket
  closes.
- Before every `rpc` and `answer` frame, the Host re-checks: device exists, **the
  access-token expiry of this exact socket** (stored per connection, so a newer
  socket of the same device can never extend an older one), security not closed,
  plugin enabled, and this device still holds the single-active-device lease. A
  denied frame is not dispatched; the socket closes with `4001` (device lost) or
  `4004` (lease lost).
- The same full re-check runs before `sub`/`unsub`/`ping`/`pong`/unknown frames, so
  an expired or revoked socket cannot keep opening follow streams (or heartbeat)
  after its access token expires; only `hello`, `rpc` and `answer` keep their
  dedicated error-frame paths.
- Only verified phone frames renew the idle clocks (`hello`, `sub`, `unsub`, `rpc`,
  `answer`, client `ping`): the device-lease idle clock **and** the 30-minute
  session idle clock that closes remote access. Server heartbeats and `pong`
  replies do not.
- Close codes: `4001` device lost, `4002` security closed, `4003` idle timeout
  (reserved: the idle handler normally triggers the `4002` security shutdown
  first), `4004` lease lost, `1008` policy violation, plus `1001`/`1002`/`1013`
  for shutdown/protocol/connection-limit cases.
- Per-device connection limit (default 4), per-socket backpressure budget (512
  KiB), heartbeat (ping 15 s, pong timeout 30 s) and a `server-drain` notice before
  a controlled close.

## Cookie rules

`rc_access` (access token) and `rc_refresh` (refresh token): `HttpOnly`,
`SameSite=Strict`, `Path=/rc`, bounded `Max-Age` matching their expiry. `Secure` is
set whenever the listener is TLS **or** the request's `Host` is a known public
HTTPS authority (so the cookie is never sent over plain HTTP to a public origin).
The plugin does not add a `Domain` attribute, does not drop `Secure` to enable
plain HTTP, and does not keep cookies on logout/revoke. There is no
`document.cookie` access from the PWA.

## Emergency shutdown invariants

One idempotent, serialized safe-shutdown path is used by: user emergency stop, the
circuit breaker, the idle timeout, unexpected tunnel loss (after a tunnel was up),
and plugin dispose. The closed flag and the disabled state are applied
**synchronously** when the shutdown is requested (so new requests are rejected even
while a long serialized transition — an install download or a 45 s tunnel start —
is still finishing); the same path then:

1. stops accepting new requests (security-closed state);
2. cancels pending/active pairings and clears the pairing manager;
3. **bumps and persists the token-revocation epoch before the async teardown**
   (so a crash mid-teardown still leaves old tokens invalid after a DSH restart)
   and invalidates every access/refresh token issued before the bump;
4. revokes every paired device (token keys/hashes removed);
5. closes WebSockets, follow and approval streams (`closeAll` with 4002);
6. terminates the plugin-owned listener and provider child processes
   (`SIGTERM` → bounded grace → `SIGKILL`);
7. clears the current pairing code/QR state and stops listening (a fixed
   `external` origin remains a configuration value, but nothing listens for it),
   and stays closed until an explicit user re-enable.

Dispose (DSH shutdown/crash path) runs the same path but does **not** persist the
closure: it persists `securityClosed: false` and `lastEnabled: wasEnabled`, while
still bumping the epoch and revoking paired devices. Consequence: after a normal
DSH restart with `autoStart`, the listener can come back but the phone must
pair again.

Normal **Stop tunnel/connection** is different: it stops the public exposure
(reverting LAN to loopback), closes every open WebSocket/follow/approval stream,
and keeps the plugin enabled, pairings and tokens. For an **external** connector,
Stop additionally revokes the public origin from the Host/Origin fence and stops
the plugin listener, so the operator-owned route has nothing left to forward to;
**external/operator-owned connector processes are never killed** — only the
plugin's own listener and children are terminated. Stopping one plugin-owned
connector does not
globally close a shared public hostname that other connectors/replicas serve.
**Disable** closes the runtime but keeps pairings/tokens (no epoch bump).

## Idle timeout

30 minutes by default (5–240). Only verified activity of the active phone renews
the clock: authenticated REST requests from that device and authenticated WS
frames (`hello`, `sub`, `unsub`, `rpc`, `answer`, client `ping`). Desktop polling,
anonymous traffic (health/static), server pings and automatic pongs do not. When
the window elapses the one-shot idle handler runs the safe shutdown with reason
`idle-timeout`, and the closure is persisted. A lease that idled out while DSH was
down is restored as expired and fails closed.

## External inputs and audit sanitization

- Audit records contain only non-sensitive metadata: time, kind, operation,
  result, device id/label, and IP/User-Agent only when reliably established.
- Every audit record is mirrored to the DSH Host logger with the same non-sensitive
  fields (sanitized again for log safety), so the required security events —
  pairing, rejected second-device attempts, revoke, prompt/steer/cancel, approval
  answers, tunnel state changes and security closures — are visible in the Host
  logs as well as the desktop panel. Rejected second-device/session attempts also
  produce a `device-lock`/`rejected` entry that the panel surfaces as a security
  notice; repeats are throttled per device so the ring cannot be flooded.
- User-Agent/labels/details/operation names are sanitized before storage and again
  before display: ANSI/OSC escapes and C0/C1/bidi/zero-width controls removed,
  newlines collapsed, length bounded — so hostile metadata cannot inject log lines
  or terminal escapes. Objects/arrays are not coerced to text.
- Prompt content, tool arguments, tool output, tokens, cookies, pairing codes, poll
  secrets and full request objects are never stored in the audit ring or logs.
- The audit ring is bounded (200 entries) and in-memory; the desktop shows the
  latest entries (50 in the status payload, full ring via the audit route).

## cloudflared download trust model

- Only the official `cloudflare/cloudflared` release **2026.10.5** is eligible, and
  only per-OS/architecture assets with a pinned **size** and **official SHA-256**
  that were taken from two official channels (the GitHub release API asset
  `digest` and the release-body SHA-256 block). For the macOS `.tgz` assets the
  archive bytes and the extracted binary are pinned separately and never mixed.
- The download is **user-initiated only** (from a disclosed plan, with explicit
  confirmation); never in the background, never at plugin load, never as part of
  matching a missing binary. Unsupported platform/arch/malformed pin fails closed
  before any network access.
- HTTPS only; manual redirect handling (≤ 5) staying on HTTPS and official GitHub
  download hosts; credentials in redirect URLs rejected; declared size must match
  the pin; streamed bytes capped at the pin; 120 s timeout.
- Temp file inside the private cache (`0600`) → size + SHA-256 verified while
  writing → atomic rename into the user-private cache (`0700`) → **re-verify**
  before use. A mismatch deletes the temp file and never executes or caches it.
  Later uses re-hash the cache; a symlinked/tampered/size-mismatched cache entry is
  removed.
- Archives are verified before extraction; extraction is bounded and strict
  (regular files only, no symlinks/hardlinks, no absolute/`..` paths, entry/size
  caps), only the expected executable is read, and the extracted binary is
  verified against its pinned hash before caching.
- `--no-autoupdate` is always passed; the plugin never auto-updates. No
  administrator rights, system service or system-wide install is used.
- **Trust boundary**: this is hash pinning, not signing. No signature/attestation
  asset is published that the plugin verifies (the Windows Authenticode signature
  is not checked by the plugin). It defends against corrupt/mirrored downloads,
  not a compromised upstream account. Operator-installed binaries (`PATH`/
  `tunnel.cloudflaredPath`) are trusted like any local executable and are reported
  as `verified: false`, distinct from a cryptographically verified download.

## SSH / localhost.run hardening

- OpenSSH is used as executable + argv (`shell: false`), never a shell command.
- The user's `~/.ssh/config` is bypassed (`-F none`); the plugin pins the host key
  into its **own** known_hosts (`UserKnownHostsFile=<pluginDir>/known_hosts`,
  `GlobalKnownHostsFile=none`) with `StrictHostKeyChecking=accept-new`. This is
  TOFU on the first connection, not pre-verification; a changed host key is
  refused.
- `BatchMode=yes` (no password/host-key prompts), no agent forwarding
  (`ForwardAgent=no`), no X11 (`ForwardX11=no`), no local command
  (`PermitLocalCommand=no`), no `-N` (required to receive the URL),
  `ExitOnForwardFailure=yes`, `ServerAliveInterval=30`/`ServerAliveCountMax=3`,
  `ConnectTimeout=15`, `-R <80|443>:127.0.0.1:<port>`.
- Host/user/remote-port are allowlisted (`localhost.run` family, `nokey`, port
  80/443); only provider-owned `*.lhr.life` / `*.lhr.rocks` / `*.localhost.run`
  HTTPS origins printed by the provider are accepted from its output.
- A missing SSH client fails with `SSH_MISSING`; the plugin **never downloads** an
  SSH binary. Free tunnels are supervised with capped backoff; a dead free tunnel
  is normal, not a security event.
- Caveat: free localhost.run domains change and drop; the host key is TOFU. Treat
  the public URL as ephemeral and provider-visible.

## LAN TLS requirement and no plain-HTTP downgrade

LAN access is opt-in and requires **both** a concrete, explicitly selected local
interface address and a TLS certificate/key pair readable by the plugin. Selecting
the concrete interface in the desktop panel and confirming the disclosed plan is
the explicit opt-in; the config-level `listen.access`/`listen.allowLan` switches
only govern a config-driven start/`autoStart`. Without TLS material, plan/start
fails with `TLS_REQUIRED` and pairing is not started. The plugin
never downgrades to plain HTTP, never drops the `Secure` cookie, and never treats
a LAN address as “safe” because it is private: the listener binds that address
explicitly and only HTTPS protects the bearer cookies on the network.

The certificate must be trusted by the phone (a public CA or a private CA whose
root is installed and trusted on the device). A self-signed leaf with no trusted
CA is not usable for a phone PWA; that is an operator setup requirement, not
something the plugin can bypass. Host-side certificate files must be PEM and are
read fail-closed (both or neither).

## Cloudflare Access as an additional layer

Access is optional, configurable only for fixed-hostname methods (named,
named-local, external) and is **not** a tunnel method. It is required either by the
config switch (`tunnel.access.required`) **or** by the active connection plan
(`accessRequired: true` in the panel selection); the Host switches the verifier on
for that run only, so a plan that advertises Access enforcement can never serve
requests without a valid assertion, and the live `connection.accessRequired` state
reflects the effective requirement. When required, the Host
verifies `Cf-Access-Jwt-Assertion` on `/rc/api/*` and the `/rc/ws` upgrade:
RS256 only, JWKS fetched from `https://<teamDomain>/cdn-cgi/access/certs` (HTTPS,
redirects refused, bounded timeout/size/cache; cache clamped 60 s–1 h; `no-store`
disables; unknown `kid` triggers at most one rate-limited refresh), `iss` equals
the team domain, `aud` contains the configured tag, `exp` in the future, `nbf`
(when present) not in the future. Any failure ⇒ `ACCESS_REQUIRED`, fail closed. A
required-but-misconfigured verifier never falls open.
Access adds a layer on top of pairing/desktop approval/cookies/origin/device-lock;
it does not replace them. No Access service secret is exposed to the PWA, and the
plugin cannot verify that your Access application/AUD/policy is the one you
intended — that is operator configuration. The static shell is protected at the
edge by your Access application; the plugin-side assertion check guards the API
and WebSocket surfaces.

## Child-process policy

- Every provider child is spawned with executable + argv and `shell: false`.
- `.cmd`/`.bat`/`.ps1` shims are refused (launching them would require a shell);
  the panel/plan explain the safe error instead.
- The child environment is an allowlist of OS variables only. `DSH_*`,
  `TUNNEL_*`/`CF_TUNNEL_*` (except the explicitly added `TUNNEL_TOKEN`), proxy
  variables, `SSH_AUTH_SOCK` and credential-looking names (`*TOKEN*`, `*SECRET*`,
  `*CREDENTIAL*`, `*PASSWORD*`, `*PRIVATE_KEY*`, `*API_KEY*`, `*ACCESS_KEY*`) are
  not inherited. Extra env entries that look like credentials are ignored with a
  warning.
- `windowsHide: true` avoids console windows; stdout/stderr are bounded rolling
  tails, never rendered raw to a terminal.
- Termination is owned-process-only: `SIGTERM`, then bounded grace, then
  `SIGKILL`; only processes the plugin started are signalled. External/operator
  processes are never killed.
- The plugin only ever forwards a tunnel to its **own** listener (`127.0.0.1`,
  dynamic port for managed methods), never to the DSH port.

## Host/plugin lifecycle

- The plugin never installs a global exception handler and never calls
  `process.exit()`; `apply` must not throw and a failed plugin stays inert.
- Teardown is driven by `ctx.effect` cleanup, which runs on normal close,
  SIGTERM/SIGINT and Electron shutdown/IPC paths. It is **not** guaranteed on
  `SIGKILL`, forced termination, crash or power loss — event handlers cannot
  guarantee anything there. Stronger process supervision is not implemented.
- State and device files are written atomically (temp + fsync + rename) with
  restrictive permissions (`0700` directory, `0600` files); symlinked or
  oversized/corrupt files fail closed. Malformed security fields force
  `securityClosed: true` and disable auto-enable; a malformed lease is discarded.
- The state file is not a secret store: device token keys and refresh hashes live
  in the device store file, never in config, QR, logs or the PWA.

## Residual risks and unknowns

- **Circuit-breaker DoS lever**: 10 failures can close remote access until the
  desktop user re-enables it. Deliberate trade-off; never auto-reopens; the plugin
  never kills the DSH process.
- **In-memory enforcement**: temporary bans, failure counts and the pairing
  reservation are in-memory and reset on restart (the persisted closure/epoch are
  durable). A crash between pairing reservation and device creation spends that
  claim; the phone must re-pair.
- **Cloudflare Access config trust**: the verifier trusts the operator-provided
  team domain/audience; a wrong (but well-formed) configuration fails closed for
  clients but cannot detect that it is the wrong application.
- **Download trust**: hash pinning only; no signature verification; trust in TLS to
  GitHub. Pinned version must be updated deliberately (no auto-update).
- **Provider visibility**: cloudflared/Cloudflare and localhost.run terminate TLS
  at their edge; they see traffic in cleartext at the edge. The phone↔edge leg is
  TLS; edge↔connector is the provider's transport.
- **localhost.run TOFU + free tier**: host key accepted on first use; free domains
  change and may throttle; the provider is a third-party dependency.
- **LAN depends on operator TLS**: an untrusted/expired certificate breaks pairing;
  the plugin cannot make a phone trust it. Plain HTTP on LAN is not offered.
- **Shared hostname caveat**: stopping the plugin-owned connector does not
  necessarily close a public hostname served by other connectors/replicas; the
  plugin will not claim otherwise and never deletes DNS/tunnel configuration.
- **Multi-user/compromised Host**: a local user with access to the Host account can
  read/alter plugin state and binaries; OS-level protections are out of scope.
- **No live E2E in CI**: CI/unit tests are fake-driven (spawn/fetch/clock seams).
  Real Cloudflare, localhost.run, phone, LAN TLS and live DSH desktop acceptance is
  manual. Signal/exit cleanup and some file-permission tests are POSIX-only
  (skipped on Windows) and cannot be guaranteed under `SIGKILL`/power loss.
- **`refreshAheadSeconds`** is reserved and currently unenforced: refresh-token
  rotation happens on every refresh use, not proactively. Documented as such; do
  not rely on it as a security control.
- **`userQuestions` relay** is off by default because the wire shape is not
  confirmed for this DSH build.
- The approval relay opens answering clients for paired devices on the same
  waterfall as the desktop: “first answer wins” with no viewer/RBAC distinction —
  an owner phone and the desktop share authority by design.

## Operator checklist

1. Keep `remoteMutations`/`approvalRelay` off when you only need monitoring; the
   bundle row enables them — turn them off if you want a read-only phone.
2. Prefer loopback; use LAN only with a certificate the phone trusts; prefer a
   fixed-hostname Cloudflare/external setup with Cloudflare Access over an ephemeral
   quick tunnel for durable access.
3. Never approve a pairing you did not initiate. Verify the device name in the
   desktop prompt.
4. Keep `autoStart` off unless you accept the listener reopening; remember that
   dispose revokes pairings, so a restarted Host still needs re-pairing.
5. Revoke devices you no longer use; emergency-stop (or disable) when idle.
6. Do not add `allowedOrigins` entries you do not control; do not bypass
   `CHECKSUM_MISMATCH` or `UNSUPPORTED_PLATFORM` by placing unverifiable binaries
   where the plugin looks.
7. Remember that **Enable** is not a security boundary by itself: the tokens are
   the boundary. Emergency stop is the revocation action.
8. Treat green CI as code-quality evidence only; run the real-provider acceptance
   manually before relying on a tunnel/phone setup.
