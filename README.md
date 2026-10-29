# DSH Remote Control

A second client for a local **DeepSeek Harness (DSH)** session: pair a phone or
browser (PWA) with the Host running on your computer and use it to watch the live
transcript, send prompts, cancel a run and answer tool approvals — while the
agent loop, tools, files and credentials stay on the Host.

- Package / plugin id: `dsh-remote-control`
- Version: **0.2.0** (wire protocol v2)
- Display name: **DSH Remote Control** (Settings tab: “Remote Control”)
- Out-of-tree Cordis bundle, installed into a DSH profile; the DSH installation
  and its source checkout are never modified.
- Host + desktop panel + PWA are written in TypeScript. Built artifacts live in
  `dist/` and are committed so that a local `link:` install works without a build.

This is **not** a cloud agent: the Host must be running for the phone to see
anything. It is also not an audited, certified or “production-ready” security
product — it is a personal-scale remote-control plugin with a deliberately small
attack surface. No claim of “100 % secure” is made anywhere in this repository;
`SECURITY.md` separates controls enforced by code from assumptions that depend on
the operator, the network, the tunnel provider or CI.

## What 0.2.0 adds

- **Connection methods beyond loopback**: Cloudflare quick tunnel, remotely-managed
  named tunnel (token env var or `--token-file`), locally-managed named tunnel
  (UUID + credentials JSON with a plugin-generated ingress), an externally-managed
  connector/origin, managed OpenSSH → localhost.run, and **LAN** as an explicit
  listener access strategy.
- **Plan → confirm → start consent flow**: the desktop panel discloses a plan
  (listener, public origin, TLS, binary download, Access, warnings) and only starts
  when the user confirms the exact disclosed plan.
- **User-initiated, SHA-256-verified cloudflared download** from a pinned official
  release (explicit policy change; the plugin no longer says “never downloads
  executables”).
- **Persisted security state**: single-active-device lease, 15-minute access
  tokens, one-shot emergency shutdown with a persisted token-revocation epoch,
  30-minute idle timeout, shared brute-force accounting and a one-shot circuit
  breaker, an expanded audit log, and optional Cloudflare Access assertion
  verification.

## Features

| Area | What works |
|---|---|
| Pairing | One-time 256-bit code, QR on the desktop, 120 s default TTL, **desktop approval always required**, max 3 pending codes, max 4 paired devices; polling secret moved to a CSRF-protected POST body (never a GET query) |
| Auth | Per-device HMAC access token (default **15 min**) + rotating refresh token (default 10 days, reuse detection) in HttpOnly cookies; token-revocation epoch; per-device revoke |
| Single device | Exactly one **active logical device** (lease); same device tabs/reconnects are fine; another device is refused at claim/approve/REST/refresh/WS-upgrade/per-frame |
| Sessions | Session list with running state, live transcript, backward pagination, projections (title/todos/inbox); **desktop-parity workspace groups** and a “new session” action on the phone |
| Mutations | Prompt (queue), steer, cancel, new session and attachment upload — gated behind `remoteMutations`; `requestId` idempotency |
| Attachments | Phone can attach **images** (inline base64, PNG/JPEG/WebP/GIF, ≤8 MiB each) and **files** (uploaded first, session-scoped receipt); 6 attachments / 16 MiB per prompt; transcript images are fetched through an authenticated, session-scoped endpoint |
| Approvals | Tool-approval waterfalls forwarded to paired phones as answering clients; **first answer wins**, the plugin never fabricates a decision; every answer is acknowledged (`answer-result`) |
| Transport | REST `/rc/api/*` + one WebSocket mux `/rc/ws`; heartbeat, 512 KiB backpressure, explicit close codes 4001–4004, replay-free reconnect |
| Reachability | Loopback only by default; LAN (explicit address + TLS); Cloudflare quick / named / named-local; external connector; SSH/localhost.run |
| Consent | Plan → confirm → start (one-shot plan id, 120 s TTL); explicit emergency stop; no silent mode switches |
| Desktop | Settings section (status, QR, pairing, devices/lease, connection plan, security state, audit) and a pairing-approval overlay |
| Security | Canonical Host/Origin fence, CSRF header, provider-scoped client-IP policy, brute-force policy, idle shutdown, emergency shutdown with persisted revocation epoch, CSP, text-only rendering, bounded audit ring |

## Architecture

```
Phone / browser PWA  (/rc/)          Desktop DSH GUI
   REST /rc/api/*  +  WS /rc/ws       Settings → Remote Control
            │                              │ fetch /api/dsh-remote-control/*
            ▼                              ▼
┌──────────────────────────────────────────────────────────────┐
│ Host plugin (this repository, runs inside the DSH Host)       │
│  listener  auth  pairing  token  device-store  state          │
│  device-lease  security-monitor  access-jwt  network          │
│  session-bridge ── owner Peer ──► ctx.typertGateway           │
│  approval-bridge ── per-device owner+answer Peer ──► $events  │
│  ws-broker  admin  audit  qr  controller                      │
│  tunnel manager: cloudflared installer / quick / named /      │
│                  named-local / external / ssh (owned child)   │
└──────────────────────────────────────────────────────────────┘
            │ in-process only
            ▼
   DSH core: session/list|follow|page|prompt|cancel, $events waterfall
```

### Interface and visual design

The desktop panel is rendered inside the DSH Settings page and follows the DSH
design system rather than carrying its own palette: it consumes the host's
`--dsw-*` tokens (`--dsw-alias-*`, `--dsw-radius-*`, `--dsw-font-family`,
elevation/focus tokens) so it automatically matches the user's light/dark theme and
DSH's deepseek-blue accent. Layout follows the same visual language: hairline
borders, 16 px cards, 8–28 px radii, a compact status hero with tinted chips, a
card-based method picker, numbered/colour-coded plan steps, quiet tables and pill
buttons (near-black primary buttons, blue info/accent actions, red destructive
actions). Only tokens that DSH does not ship fall back to calibrated values, so the
panel still renders in a preview/test harness.

The phone PWA is a standalone surface and therefore ships its own matching palette:
light-first surfaces (`#f9fafb` canvas, white cards, hairline borders) with a
`prefers-color-scheme: dark` variant, the same deepseek-blue accent, system font and
soft radii. The session view uses DeepSeek-style chat bubbles (right-aligned tinted
user bubbles, plain assistant messages), a pill composer with segmented
Queue/Steer controls and a bottom-sheet approval card; `theme-color` follows the
active colour scheme. Both surfaces keep the strict CSP (no inline styles/scripts),
text-only rendering and the documented security boundaries unchanged.

The phone also renders the model's **reasoning** content: finalized assistant
messages expose a collapsed “Reasoning” disclosure with a one-line preview (the
full text expands in place), and the live assistant stream shows
`reasoning-delta` chunks expanded while the turn is running, followed by the answer
text. Approval decisions are **acknowledged** by the host (`answer-result`): the
card is removed only after the relay accepts it, and a rejection/timeout reopens
the card with an error so the decision can be retried. A persistent **TR/EN**
switch lives on every screen; the choice is carried in the hash (`?lang=tr`) so it
survives reloads without any storage API. The sessions screen's refresh button now
shows an explicit “Refreshing…” state and reports the result; the shell service
worker cache is versioned so a new phone bundle is picked up instead of serving a
stale cached `app.js`.

The phone surface follows the DeepSeek mobile app: a `deepseek` wordmark home
header with a greeting and a menu button that opens a **slide-in history drawer**
(workspace groups from the desktop sidebar, localized “Default workspace”, an
“Other sessions” bucket, and a new-chat action), plus a one-tap **new chat**
button in the header. The session screen uses a back/title/new-chat header and a
rounded composer with an attach button. Assistant answers are rendered as
**Markdown** (headings, lists, fenced/inline code, links with an http/https/mailto
allowlist, tables, quotes) by a dependency-free, DOM-building renderer — no
`innerHTML`, no raw HTML interpretation. User uploads support **images**
(PNG/JPEG/WebP/GIF, sent inline) and **files** (uploaded first to a session-scoped
DSH receipt); both appear in the transcript, images are fetched back through an
authenticated session endpoint, and DSH-injected context messages
(“Time sampled…”, runtime/skill context) are hidden like the desktop chat does.
Attachments are capped per message (6 items / 16 MiB) and the composer reports
oversized files.

The phone never receives a DSH cookie and never talks to the DSH `/api` surface.
It only sees the allowlisted remote-control API. The phone-facing DSH data plane
is limited to `session/{list,follow,page,prompt,cancel,projections,create,attachment}`,
the read-only `workspace/follow` baseline used for sidebar-parity groups, and the
session-scoped `fileUploads/upload` Remote. `terminal/*`, `workspace/*` mutations,
`credentials/*`, `settings/*`, `pluginManager/*`, jobs and arbitrary attachment or
workspace access are **never** exposed.

Every provider child process is owned by the plugin and launched as
executable + argv (no shell). The tunnel always forwards to the plugin's `/rc`
listener, never to the DSH port.

## Requirements

- DSH Desktop **0.2.1-rc.3** (`dsh >=0.2.1-rc.3 <0.3.0`)
- Node.js **>= 22.19** (the bundled DSH runtime is fine; system Node for building)
- `pnpm` 10 for development/build
- One of:
  - `cloudflared` — either installed by the operator (`tunnel.cloudflaredPath` or
    `PATH`) or downloaded by the plugin through the explicit, SHA-256-verified
    flow described below (Cloudflare methods only);
  - a system OpenSSH client (`ssh`) for the SSH/localhost.run method — the plugin
    never downloads an SSH binary;
  - a TLS certificate/key pair that the **phone trusts** for LAN access;
  - nothing for loopback-only use.

## Install

### Plugin Manager (desktop profile — recommended)

Install the bundle with the DSH Plugin Manager (`install_bundle`), then open
**Settings → Plugins** and enable “DSH Remote Control” if the bundle row is
disabled. The desktop profile is managed by the Electron app; do not add it
through the CLI. Two targets are supported:

- **From GitHub** (no local checkout required):

  ```
  github:MrBekoX/dsh-remote-control
  ```

  `MrBekoX/dsh-remote-control` is the public release repository: a clean,
  single-commit snapshot of the project (the full development history is kept in a
  private mirror, `MrBekoX/dsh-remote-control-private`). Install the current
  `main`. If you need reproducibility, pin the commit SHA that GitHub shows for the
  release you reviewed:
  `github:MrBekoX/dsh-remote-control#<commit-sha>`. The repository is public, so no
  credentials are needed. `dist/` is committed, so the git install needs no build.
- **From a local checkout:** point the install at the absolute package directory
  (e.g. `D:\dsh-remote-control`). This is a `link:` install and uses that
  checkout's own dependencies.

The bundle insert row keeps the master switch **off**. A DSH restart is required
for the Host half to load (client plugins hot-reload; Host plugins need a
restart). A git install can be updated later by installing the same spec with a
newer commit; pinning keeps the running version stable.

### CLI (non-desktop profiles)

```bash
dsh plugin --profile <profile> add /absolute/path/to/dsh-remote-control
# or straight from GitHub:
dsh plugin --profile <profile> add github:MrBekoX/dsh-remote-control
```

`dist/` is committed, so a `link:` or git install needs no build step. A DSH
restart is required for the Host half to load.

### First run (desktop)

1. Open **Settings → Remote Control**.
2. Pick a **connection method** (Loopback is the safe default) and press
   **Review plan**.
3. Read the disclosed plan (listener address, public exposure, TLS, download,
   access layer, warnings) and press **Start**. If the plan requires the pinned
   `cloudflared` binary, press **Download and verify** first; nothing is
   downloaded before that click.
4. Press **Pair device**, then scan the QR with the phone (or open the URL).
5. Approve the device in the desktop pairing overlay. The phone receives cookies,
   becomes the single active device, and can now list sessions.
6. **Emergency stop** is always available in the panel; **Stop** ends only the
   public connection, **Disable** turns the listener off but keeps pairings.

## Connection methods

`Settings → Remote Control` shows these as a connection choice. LAN is modeled as
a **listener access strategy**, not a tunnel method; loopback means “no public
exposure”.

| Method | What you provide | Public origin | Process ownership | Listener bind |
|---|---|---|---|---|
| `loopback` | nothing | none (same machine only) | none | `127.0.0.1:<port|0>` |
| `lan` | explicitly selected interface address **and** a TLS cert/key the phone trusts | `https://<lan-address>:<port>` | plugin listener only | selected LAN address:port, HTTPS |
| `cloudflare-quick` | cloudflared binary (operator install or verified download); no Cloudflare account | temporary `https://*.trycloudflare.com` | plugin (owned child) | `127.0.0.1:0` |
| `cloudflare-named` | fixed public hostname + connector token from an env var, or a token file (cloudflared ≥ 2025.4.0); the ingress/DNS side is configured by you in Cloudflare | `https://<hostname>` | plugin (owned child) | `127.0.0.1:<fixed port matching your ingress>`, or `0` with a disclosed warning |
| `cloudflare-named-local` | tunnel UUID + its credentials JSON + fixed hostname | `https://<hostname>` | plugin (owned child) | `127.0.0.1:0` |
| `external` | fixed HTTPS origin of a connector/service you already run, plus the fixed loopback port your connector targets | your origin | **external** (never killed by the plugin) | `127.0.0.1:<fixed port you configured>` |
| `ssh` | system OpenSSH client; no key needed for free localhost.run tunnels | provider-assigned `https://<id>.lhr.life` (or the provider's `lhr.rocks` / `localhost.run` families) | plugin (owned child) | `127.0.0.1:0` |

Detail per method:

- **Loopback** — the listener binds `127.0.0.1`. The phone must be on the same
  machine (emulator, USB port-forward, local browser). The panel reports
  `loopbackOnly`; a phone cannot pair over the internet in this mode.
- **LAN** — the panel lists concrete interfaces, classifies RFC1918 private and
  Tailscale `100.64.0.0/10` addresses as *recommended*, shows link-local and other
  concrete addresses but does not recommend them, and never guesses an address.
  The user must select one explicitly. Selecting a concrete interface in the
  panel and confirming the disclosed plan **is** the explicit LAN opt-in; the
  config-level `listen.access`/`listen.allowLan` switches only govern a
  config-driven start/`autoStart` (they are not required for a panel-started LAN
  session). **TLS is mandatory for LAN pairing**: if
  `listen.tls.certFile`/`keyFile` are not both configured, the plan/start fails
  with `TLS_REQUIRED` and pairing is not started. The plugin never downgrades to
  plain HTTP and never drops the `Secure` cookie to make plain HTTP work. A
  self-signed leaf that no CA vouches for will fail on a phone; issue the
  certificate from a private CA and install that root CA on the phone once (e.g.
  `mkcert`; the plugin does not run or bundle it).
- **Cloudflare quick** — managed `cloudflared tunnel --no-autoupdate --protocol
  <auto|quic|http2> --url http://127.0.0.1:<port>`; the temporary URL is parsed
  from the streamed output (everything including the URL is on stderr) and only a
  canonical `https://<label>.trycloudflare.com` origin is accepted. Quick tunnels
  are temporary, change hostname on every start, have no uptime guarantee and are
  rate/feature limited by Cloudflare; the plan discloses that. A “Registered
  tunnel connection” line proves only that the connector reached the edge — it is
  reported as `connected-unverified` until bounded HTTP **and** WS probes against
  the public origin succeed.
- **Remotely-managed named** — you pre-create the tunnel and its public hostname
  route in the Cloudflare dashboard; the plugin only runs the connector. Provide
  the hostname and **one** token source:
  - an environment variable name read from the Host environment and passed to the
    child as `TUNNEL_TOKEN` (never in argv/config/QR/logs), or
  - a token file passed as `--token-file <path>` (cloudflared **≥ 2025.4.0** is
    required and checked); the secret is never read into config or argv.
  The plugin cannot change Cloudflare-side ingress with the token; the connector
  being registered does **not** prove that the hostname points at this listener.
  Use a fixed loopback port that matches your Cloudflare ingress service URL; the
  panel exposes an explicit **fixed loopback port** input for this method. If the
  plan uses a dynamic port it warns, and the bounded probes will most likely
  report `mismatch`.
- **Locally-managed named** — you provide the tunnel UUID and its credentials JSON
  (`AccountTag`, `TunnelSecret`, `TunnelID`). The plugin validates the JSON shape
  and that `TunnelID` matches the selected UUID, refuses symlinked/replaced files,
  reads it with a bounded size, and generates its **own** runtime config (never
  your global `~/.cloudflared` config) with exactly one ingress rule
  `hostname → http://127.0.0.1:<actual port>` plus the mandatory final
  `http_status: 404`, then runs `cloudflared tunnel --config <generated> run
  <UUID>`. It never requires or stores an account-wide `cert.pem`; the tunnel
  credentials only grant the right to run that one tunnel.
- **External connector** — for a connector/service you already operate (Cloudflare
  dashboard-managed, Tailscale Serve/Funnel, a reverse proxy, a container, …).
  The plugin validates the fixed HTTPS origin (no path/query/credentials), manages
  only its own listener, probes the origin, and reports `ownership: external`.
  The plugin never installs, reconfigures or terminates that service. **Stop**
  additionally revokes the external origin from the Host/Origin fence, closes every
  open WebSocket/follow/approval stream and stops the plugin listener, so the
  operator-owned connector has nothing left to forward to; the plugin does not
  claim to terminate the connector process itself.
- **SSH / localhost.run** — uses the system OpenSSH client with executable + argv
  (never a shell) and an explicitly hardened invocation: no user `~/.ssh/config`
  (`-F none`), non-interactive (`BatchMode=yes`), a **plugin-owned** `known_hosts`
  in `<DSH_HOME>/remote-control/tunnel/ssh/` with `StrictHostKeyChecking=accept-new`
  and `GlobalKnownHostsFile=none` (TOFU on first use — it is not claimed to be
  pre-verified), `ExitOnForwardFailure=yes`, `ServerAliveInterval=30`,
  `ServerAliveCountMax=3`, no agent/X11 forwarding, `PermitLocalCommand=no`,
  `ConnectTimeout=15`, `-R <80|443>:127.0.0.1:<port>`, `nokey@localhost.run`.
  There is deliberately **no `-N`** (localhost.run prints the URL from the remote
  session; `-N` suppresses it). The provider URL is accepted only from the
  provider's own `*.lhr.life` / `*.lhr.rocks` / `*.localhost.run` HTTPS domains and
  is read from **stdout** (cloudflared, by contrast, prints everything including
  the URL on stderr). Free tunnels today are assigned
  `<16 lowercase hex chars>.lhr.life`; the plugin validates the provider-owned
  domain family rather than a hard-coded sample URL, so a provider-side domain
  change within those families is handled, while an arbitrary URL is not accepted.
  Free localhost.run domains change regularly and are speed/connection limited; the
  manager supervises reconnects with capped backoff (1 s, 2 s, 4 s, 8 s, 15 s;
  max 5 attempts before a terminal `down`). A missing `ssh` executable fails with
  `SSH_MISSING`; the plugin never downloads an SSH binary.

Common behavior: mode changes are controlled stop → start (no silent switching).
If a port is busy the start fails; the plugin never silently picks a different
port. Changing the provider or stopping a **managed** tunnel clears the old
runtime origin, QR base and HTTPS trust. A statically configured `external` origin
is advertised only while that runtime connection is started: **Stop** removes the
origin authority, closes existing connections and stops the plugin listener (the
plugin cannot kill the operator-owned connector, so the connector keeps running
but has nothing to forward to).

### Listener and port rules

- Managed Cloudflare methods (quick, named-local) and SSH always bind
  `127.0.0.1` with port `0`; the OS-assigned port is fed to the connector
  (quick URL / generated ingress / `-R` forwarding).
- Remotely-managed named and external may (and in practice must) use an
  explicitly selected fixed loopback port that matches the Cloudflare ingress /
  connector configuration. A dynamic port there triggers a disclosed plan warning,
  and the bounded probes will most likely report `mismatch`.
- Plain `loopback` uses the configured/selected loopback port; it is not public.
- LAN is the **only** non-loopback bind and requires an explicit address
  selection plus TLS. Wildcard binds (`0.0.0.0`, `::`) are always refused.
- The tunnel/connector always targets the plugin's own listener; it never targets
  the DSH port. The plugin refuses to start rather than silently changing ports.

### Connection status you may see

| State | Meaning |
|---|---|
| `off` / `down` | not running / failed or stopped |
| `starting` | listener or provider child is starting |
| `missing-config` | required provider input/credentials are missing (e.g. token env var not set) |
| `missing-binary` | the provider executable is not installed (cloudflared, or OpenSSH for SSH); SSH is never downloaded |
| `connected-unverified` | connector reports connected; the public route is **not** proven yet |
| `access-required` | the public origin redirects to Cloudflare Access; sign in required |
| `ready` | bounded HTTP **and** WS probes against the configured public origin both succeeded |
| `mismatch` | the public origin answered, but not with this listener (DNS/ingress/port mismatch) |
| `security-closed` | reserved wire value: closures are reported via `security.closed`/`security.closedReason`, and the tunnel reports `off`/`down` after the listener and owned child stop |

HTTP and WS verification are reported separately (`verified.http`/`verified.ws`);
`ready` requires both.

## Plan → confirm → start

Nothing is started by choosing a method. The Host computes a **disclosed plan**
(`POST connection/plan`), the panel renders it, and only the explicit
confirmation applies it:

- The plan includes the listener decision (host/port/protocol/access), public
  origin, QR origin, Secure-cookie decision, Cloudflare Access requirement, every
  provider step/warning, TLS usage for LAN, the security contract, and — when the
  binary is missing — the pinned `cloudflared` download disclosure
  (version, asset, size, SHA-256, release URL, cache directory).
- The plan id is **one-shot** and expires after **120 seconds**. `Start` must send
  the same `planId` with `confirm: true`; a missing, expired or replayed plan is
  rejected with `CONSENT_REQUIRED` and the plan must be reviewed again.
- The download (`install`) uses the same rule: a valid plan id + `confirm: true`.
  A successful install **consumes** that plan (the panel discloses a fresh plan
  before starting); a failed install keeps the plan usable until it expires.
  Installing never starts a tunnel by itself.
- Changing the provider, stopping the connection, an emergency stop or a failed
  start clears the old runtime public origin/QR state and HTTPS trust; mode changes
  are always controlled stop → start and never silently switch ports. Stopping an
  `external` connection also stops the plugin listener (the operator connector is
  never killed, but it can no longer reach an authenticated surface).
- When `tunnel.enabled` is false but the user starts a connection from the panel,
  the runtime selection still feeds the listener address, public origin, QR,
  Host/Origin allowlist and Secure-cookie decision (one computed runtime state).

## cloudflared download policy (pinned, verified, user-initiated)

This is an explicit policy change from 0.1.x. The plugin may now download a
cloudflared binary **only** when the desktop user explicitly starts the download
from the disclosed connection plan. It never downloads in the background, at
plugin load, or as part of “Enable”.

- **Resolution order**: configured `tunnel.cloudflaredPath` (absolute/path-like
  value) → `cloudflared` on `PATH` → digest-verified plugin cache. Only a cache
  entry that matches the pinned official SHA-256 is reported `verified: true`; a
  user/operator-installed binary is usable but reported as *unverified* (trusted
  the way any local executable is trusted).
- **Pinned official release**: `cloudflare/cloudflared` **2026.10.5**. The version,
  exact asset name, exact byte size and official SHA-256 are compiled into the
  plugin, one row per OS/architecture. There is no “latest” lookup and the
  `.../releases/latest/download/...` alias is never used.

| Platform | Official asset | Bytes | Official SHA-256 |
|---|---|---|---|
| win32 x64 | `cloudflared-windows-amd64.exe` | 55,343,328 | `db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9` |
| win32 ia32 | `cloudflared-windows-386.exe` | 38,078,600 | `66cba8003e4f87a8e6b772f331b8c04c7d41ac4f2dc30dd2c13ae09de3b6007e` |
| linux x64 | `cloudflared-linux-amd64` | 40,263,303 | `e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298` |
| linux arm64 | `cloudflared-linux-arm64` | 37,662,975 | `72e0d05a67e09da87cf495e409a28c3cc5994dd23fc66a982eebea6a55923b7d` |
| linux arm | `cloudflared-linux-arm` | 37,132,381 | `a018911e1bbfd739937f3011f589e9e73245baeee14742f8b3413472bb007adc` |
| linux ia32 | `cloudflared-linux-386` | 37,680,533 | `f2de713829081837130b38e27f3c95aa9d7fc1a4f48b833362d21234dd8780d8` |
| darwin arm64 | `cloudflared-darwin-arm64.tgz` | 19,840,425 | archive: `184c7d4f5f977348243a6d7ca8f6cf6073b9b2746cfe8c1fe15aa59e9a522bf0` · inner binary: `2b23964528ddcd641c1449275df8b5b51e3c7193b5257919846331bc5bc13b0f` (39,485,536 B) |
| darwin x64 | `cloudflared-darwin-amd64.tgz` | 21,798,374 | archive: `6699392fed92367808c248c2d90bed66e49bbf66e1b4ee3e4141230f3f7391b3` · inner binary: `cb09afb9b4d0a4730de477ac710aebb6107568930a8345775629bf264f70c284` |

The pinned values come from two official channels: the **GitHub release API**
asset `digest` (machine-readable `sha256:<hex>`) and the **release body** SHA-256
block (human-readable, fetched from the official release page). For bare binaries
the two agree. **macOS nuance**: the API `digest` covers the downloaded `.tgz`
bytes while the release-body checksum covers the *extracted* `cloudflared`
binary. The plugin pins and verifies both separately and never mixes them
(comparing `.tgz` bytes against the body value would always fail on macOS).
Official `.pkg`/`.msi` assets are deliberately not used: no admin rights, no
system service, no system-wide install.

- **Fail-closed conditions** — no download when:
  - the OS/architecture has no pinned row (e.g. win32 arm64, freebsd, unsupported
    arch) → `UNSUPPORTED_PLATFORM`;
  - the pinned row itself is malformed (bad hex, non-positive size, archive
    without an inner-binary digest) → fail closed (`UNSUPPORTED_PLATFORM`; never a
    silent fallback to an unverified URL);
  - the URL/redirect/response fails validation.
- **Network limits**: HTTPS only; redirects are followed manually at most 5 times
  and must stay on HTTPS and on official GitHub download hosts
  (`github.com`, `objects.githubusercontent.com`,
  `release-assets.githubusercontent.com`); credentials in redirect URLs are
  rejected; the declared `Content-Length` (when present) must equal the pinned
  size; streamed bytes may not exceed it; the whole download has a 120 s timeout.
- **Verification and cache placement**: the download is written to a temporary
  file inside the plugin cache directory (mode `0600`) while the SHA-256 is
  computed; a size or digest mismatch throws `CHECKSUM_MISMATCH` and the temp file
  is deleted without being executed or cached. The verified file is then renamed
  atomically into `<DSH_HOME>/remote-control/bin/` (directory mode `0700`;
  filename `cloudflared-<version>-<platform>-<arch>[.exe]`) and **re-verified**
  before being reported usable. Later uses re-hash the cache entry; a symlinked,
  size-mismatched or tampered entry is removed and a new explicit download is
  required.
- **Archives (macOS `.tgz`)**: the archive is verified first, then extracted with
  a bounded, strict tar reader (max 4,096 entries, 256 MiB extracted cap, regular
  files only — no symlinks/hardlinks/directories, no absolute/`..` paths, no
  duplicate executable), only the expected `cloudflared` member is accepted, and
  the extracted binary is verified against the pinned inner-binary SHA-256 before
  being cached. (A bounded safe zip path also exists; the current pinned table has
  no zip assets.)
- **No auto-update**: every managed cloudflared invocation passes
  `--no-autoupdate`; the plugin itself never checks for or installs newer versions
  in the background.
- **No privileges**: the download and cache are user-private; no administrator
  rights, system service, PATH install or system-wide change is performed. The
  binary is executed from the plugin cache/operator path only.
- **Trust caveat**: this is a hash pin, not a signature. There is no signature or
  attestation asset published with these releases that the plugin verifies (the
  Windows binary's Authenticode signature is *not* checked by the plugin). Hash
  verification defends against corrupt, truncated or mirrored downloads; it is
  only as trustworthy as TLS to the pinned release host. The plugin does not
  claim to defend against a compromised upstream account.

## Pairing and QR

- Desktop: **Pair device** creates a one-time code (default 120 s TTL, config
  `pairing.ttlSeconds` 30–600; max 3 outstanding codes) and shows
  `https://<public-origin>/rc/#/pair?c=<one-time-code>` plus a QR code.
- The pairing code lives in the **URL fragment**, so it is not sent to the server,
  proxy logs or Referer headers. The PWA reads it into memory and immediately
  removes it from the address bar/history (`history.replaceState`).
- Opening the QR alone grants nothing. The phone claims the code
  (`POST /rc/api/pair/claim`), which atomically consumes it; replaying the same
  code is rejected with `403 PAIRING_CONSUMED` (an unknown code is `400
  PAIRING_INVALID`). The desktop must then **approve** the claim — there is no
  config switch to skip approval.
- The phone polls pairing status with a **POST body** (`claimId` + `pollToken`,
  CSRF header + allowed Origin). The polling secret is never placed in a GET
  query string, so it cannot leak into access logs.
- On approval the Host mints the device, sets `rc_access`/`rc_refresh` cookies,
  activates the single-active-device lease, and the claim is consumed once (a
  concurrent or replayed poll cannot mint a second device).
- Denied/expired/consumed claims fail with `PAIRING_DENIED` / `PAIRING_EXPIRED` /
  `PAIRING_CONSUMED` (403 for a replayed code); a second device while one holds the
  lease fails with `DEVICE_LOCKED`.

## Tokens, cookies and lifetimes

| Item | Default | Config |
|---|---|---|
| Access token | 15 minutes | `tokens.accessTtlMinutes` (0 = default); legacy `tokens.accessTtlHours` (`0` = unused); effective minimum 10 minutes |
| Refresh token | 10 days, rotated on use | `tokens.refreshTtlDays` (1–90) |
| Proactive refresh lead | reserved, currently unenforced | `tokens.refreshAheadSeconds` is a reserved knob: rotation happens on every refresh **use**, not proactively. Do not rely on it as a security control. |
| Pairing code | 120 s | `pairing.ttlSeconds` (30–600) |
| Idle timeout | 30 minutes | `security.idleTimeoutMinutes` (5–240) |

Access tokens are stateless HMAC tokens
(`rc1.<deviceId>.<exp>.<tokenVersion>.<epoch>.<nonce>.<sig>`) bound to the device
store entry, its `tokenVersion` and the persisted token-revocation epoch. Refresh
tokens are random 32-byte secrets; only their SHA-256 is stored. Refresh rotation
has reuse detection: presenting a rotated-out refresh token (outside the short
concurrent-rotation grace window) revokes the device. Concurrent refreshes from
the same device are serialized per device; one refresh token can never yield two
independent valid sessions.

Cookies: `HttpOnly`, `SameSite=Strict`, `Path=/rc`; `Secure` whenever the
listener is TLS or the request arrives through a known public HTTPS authority.
Logout and revoke remove the device and clear the cookies. Tokens, cookies,
pairing codes and polling secrets are never logged or rendered.

Changing the access-token lifetime: set `tokens.accessTtlMinutes`. Existing
configs that set the old `tokens.accessTtlHours` still work (used only while
`accessTtlMinutes` is `0`); `accessTtlMinutes` wins.

## Single active-device lease

At most **one logical device** is active at a time. The lease is persisted in the
plugin state file and enforced at every layer:

- Claim, desktop approval, REST authentication, refresh, WebSocket upgrade and
  each WebSocket `rpc`/`answer` frame are checked; a non-active device gets
  `DEVICE_LOCKED` (REST 409; WS closes with 4004).
- The **same device** may use several tabs and reconnect freely: re-activation is
  a no-op refresh of the same lease, and a short disconnect never transfers the
  lease to another device. There is no “disconnect transfer” API at all.
- The lease ends only by an explicit desktop **release**, device **revoke**,
  **emergency stop**, **idle timeout**, or (at restart) by restoration rules.
- A lease that already idled out while DSH was down is restored as expired and
  fails closed: remote access stays closed until the user explicitly re-enables.
- IP addresses and User-Agents are **never** used as device identity evidence.
- **Legacy multi-device stores**: if the device store already contains more than
  one device and no active device is selected, remote access cannot be enabled
  and pairing is refused until the desktop completes an explicit
  select/revoke flow (`device/activate` / `device/revoke`). The plugin never
  randomly picks a device and never silently deletes one. `tokens.maxDevices`
  (1–4, default 4) is a hard cap on registered devices.

## Idle timeout

Remote access closes after **30 minutes** without verified phone activity
(config `security.idleTimeoutMinutes`, 5–240). Only activity that is
authenticated as the active phone renews the clock: authenticated REST requests
by that device and authenticated WS frames (`hello`, `sub`, `unsub`, `rpc`,
`answer`, client `ping`). Desktop panel polling, anonymous traffic
(health/static), server-side heartbeats and automatic `pong` replies never renew
it. On expiry the one-shot security shutdown runs with reason `idle-timeout`:
remote access closes, the closure is persisted, and it stays closed until an
explicit re-enable. A long-running agent does not keep the phone session alive by
itself.

## Emergency stop vs. Stop tunnel vs. Disable

| Action | What it does |
|---|---|
| **Stop** (connection stop) | Stops the public exposure/provider child and closes every open WebSocket/follow/approval stream. For LAN it reverts the listener to loopback; for an `external` connector it also stops the plugin listener and revokes the public origin from the Host/Origin fence (the operator's connector process is never killed, it just has nothing left to forward to). Remote control stays enabled; pairings/tokens stay valid. A legacy `tunnel/stop` action does the same for the tunnel only. |
| **Disable** (master switch) | Closes the listener, WebSockets and the tunnel; keeps pairings and tokens (no revocation-epoch bump). Re-enabling restores the previously enabled listener. |
| **Emergency stop** | One-shot destructive security action: stops new requests, cancels pending/active pairings, **permanently invalidates all access/refresh tokens** (persisted revocation epoch, so old tokens stay invalid across a DSH restart), revokes every paired device, closes WebSockets/approval streams, terminates the plugin-owned child processes and listener, clears the current pairing code/QR state and stops listening, and stays closed until the user explicitly re-enables. External/unowned connector processes are never killed (a statically configured external origin remains a config value, but nothing listens for it). |
| **Plugin dispose** (DSH shutdown/crash path) | Runs the same safe-shutdown path: it bumps the revocation epoch, revokes every paired device and tears everything down, then persists `securityClosed: false` and `lastEnabled: wasEnabled`. Therefore, after a normal DSH restart with `autoStart`, the listener can come back but **the phone must pair again**. |

The same safe shutdown is triggered by the circuit breaker, the idle timeout and
an unexpected tunnel loss (when a tunnel had been up). It is idempotent and
serialized.

## Brute-force and circuit-breaker policy

All failed-authentication paths (pairing secret, polling secret, access token,
refresh token, WS verification) share one failure account keyed by the
provider-scoped client address:

- **Per-IP temporary ban**: failures are counted in a sliding window
  (default 60 s; `security.failureWindowSeconds` 10–600). With the default
  `security.failuresBeforeBan = 5`, the **6th** failure from one client inside
  the window blocks that client for 5 minutes
  (`security.temporaryBanMinutes` 1–60). A blocked client is rejected once with
  `RATE_LIMITED` + `Retry-After`; blocked repeats are **not** counted and never
  extend the ban.
- **One-shot circuit breaker**: with the default
  `security.circuitBreakerFailures = 10`, the 10th failure counted inside one
  manually started remote-access period opens the breaker, which runs the
  emergency shutdown once. It never reopens automatically; an explicit user
  re-enable starts a fresh accounting period.
- **Not attacks**: successful pairing polls, health/static access, and a normally
  expired access token are not counted as failures — the client receives
  `401 TOKEN_EXPIRED`, refreshes successfully, and normal expiry/refresh use never
  accumulates toward the circuit breaker. Only structurally/signature/epoch-invalid
  access tokens count, and a successful verified authentication clears that
  client's per-IP window.
- **DoS trade-off, on purpose**: anyone who can cause 10 authentication failures
  can force remote access closed. This is a deliberate availability/security
  trade-off (bounded retry surface vs. a determined attacker); the threshold is a
  config value, not silently removed. Closing remote access never kills the DSH
  Host process, never touches your files/sessions/tools, and never requires a DSH
  restart to recover — the desktop user re-enables when appropriate.
- Failure/ban counters are in-memory and reset on DSH restart; the persisted
  security closure and revocation epoch are the durable parts.

## Cloudflare Access (optional extra layer)

Cloudflare Access can be enforced **in addition to** the plugin's own auth when a
fixed hostname is protected by an Access application. It is not a tunnel method.

- Config: `tunnel.access.required` + `teamDomain` (bare host, e.g.
  `myteam.cloudflareaccess.com`) + `audience` (the Access application AUD tag).
  Requiring Access with a method that has no fixed hostname (loopback, LAN,
  quick, SSH) is rejected.
- A connection plan may also require Access for **one run** (`accessRequired: true`
  in the panel selection) even when `tunnel.access.required` is false. The Host
  switches its verifier on for that active run, the disclosed plan and the live
  `connection.accessRequired` state both reflect it, and disabling/stopping the
  run returns to the config default. The requirement is enforced by the Host — a
  checked plan can never advertise Access while serving requests without a JWT.
- The Host verifies the `Cf-Access-Jwt-Assertion` request header on `/rc/api/*`
  and on the `/rc/ws` upgrade: RS256 signature against the team domain's JWKS
  (`https://<teamDomain>/cdn-cgi/access/certs`, HTTPS, redirects refused, bounded
  timeout/size/cache), plus `iss`, `aud`, `exp` and (when present) `nbf`. Failure
  is `ACCESS_REQUIRED` (HTTP 401; WS upgrade rejected). A required-but-misconfigured
  verifier never falls open.
- The browser performs the Access login/re-auth at the edge; the PWA treats an
  Access HTML/redirect response as an actionable “sign in again” state and
  rebuilds the WebSocket afterwards. No Access service secret ever reaches the
  PWA. The static PWA shell itself relies on the Access application at the edge;
  the plugin-side JWT check guards the API and WebSocket surfaces.
- Access does not replace the plugin's pairing, desktop approval, device lease,
  CSRF/Origin or cookie controls, and the plugin does not claim to validate that
  your Access policy is “correct” — that remains your Cloudflare configuration.

## What the phone can and cannot do

Allowed (all via the allowlisted remote-control API):

- read the session list, projections and durable transcript (paged);
- prompt (queue) and steer a session, cancel a run — only when
  `remoteMutations` is enabled;
- answer tool approval/user-question waterfalls — only when `approvalRelay`
  (and, for non-tool questions, `userQuestions`) is enabled; the first answer
  wins, the desktop stays authoritative, and the plugin never fabricates an
  answer on timeout.

Never exposed: terminal, workspace/file APIs, credentials, settings, plugin
manager, jobs, attachments, arbitrary DSH endpoints, tunnel/pairing management,
or any “enable/disable remote access” control. The phone cannot approve its own
pairing, cannot change its own permissions, and cannot start/stop tunnels.

## Audit log

A bounded in-memory ring (200 entries) records non-sensitive metadata for
enable/disable, pairing (code created, claim, approve, deny, rejected second
device), revoke, device-lock changes, prompt/steer/cancel, approval answers,
tunnel state changes and security shutdowns. Each entry has time, kind,
operation, result, device id/label, and IP/User-Agent only when reliably known.
User-Agent and other external text is stripped of ANSI/control characters,
newlines and length-overflow before storage. Prompt content, tool arguments,
tool output, tokens, cookies, pairing codes and polling secrets are never stored.
The desktop panel shows the latest entries and the current security state.

Every audit record is also mirrored to the DSH Host logger with the same
non-sensitive fields (sanitized again for log safety), so pairing, rejected
second-device attempts, revoke, prompt/steer/cancel, approval answers, tunnel
state changes and security closures are visible in the Host logs as well. A
rejected second-device/session attempt produces a `device-lock`/`rejected` entry
that the panel surfaces as a security notice; repeated rejections from the same
device are throttled (at most one audit entry per minute) so the ring cannot be
flooded.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `INSTALL_REQUIRED` / `missing-binary` for Cloudflare methods | No usable cloudflared. Review the plan and use **Download and verify** (pinned release), or install cloudflared yourself (`winget`/`brew`/official release) or set `tunnel.cloudflaredPath`. |
| `UNSUPPORTED_PLATFORM` | No pinned official asset for this OS/architecture (e.g. Windows on ARM, freebsd). Install cloudflared yourself and point `tunnel.cloudflaredPath` at it, or use another method. |
| `CHECKSUM_MISMATCH` | The download/cache did not match the pinned official SHA-256. Nothing was executed or cached; retry the explicit download. If it persists, your network/mirror is tampering or the pinned release changed — do not bypass the check. |
| `SSH_MISSING` | The system OpenSSH client was not found. Install the OS OpenSSH client; the plugin never downloads an SSH binary. |
| `TLS_REQUIRED` on LAN | Configure both `listen.tls.certFile` and `listen.tls.keyFile` with a certificate the phone trusts (private CA root installed on the phone). There is no plain-HTTP LAN option. |
| `DEVICE_LOCKED` | Another device holds the single-active-device lease, or the store has multiple devices without an explicit selection. Release/revoke the other device or use `device/activate` from the panel. |
| `SECURITY_CLOSED` / `security-closed` | Emergency stop, circuit breaker, idle timeout or tunnel loss closed remote access. Re-enable explicitly from the panel; nothing auto-reopens. |
| Connector says connected but the panel is `connected-unverified`/`mismatch` | Connector registration is not route verification. Check your Cloudflare hostname/ingress/DNS target and the fixed loopback port; view `verified.http`/`verified.ws`. |
| Cloudflare Access redirects forever | Sign in at the team domain in the same browser; verify `teamDomain`/`audience`; the Access application must front the exact public hostname. |
| QR does not open / phone cannot reach | The panel's `loopbackOnly` is true (no public exposure), or the QR origin does not match the listener. Re-plan with LAN or a tunnel. |
| `PWA build missing` (503) | `dist/pwa` was not built/packaged. Rebuild (`pnpm run build`) or reinstall the bundle. |
| Port already in use | The plugin never switches ports silently. Choose a different fixed loopback port (named/external) or free the port. |
| Token file rejected on named tunnel | `--token-file` requires cloudflared **≥ 2025.4.0**; the plugin checks the version and fails closed. Upgrade cloudflared or use the env-var token source. |
| State looks “closed” after a crash/restart | Corrupt/partial security state fails closed. Inspect the panel and explicitly re-enable if you trust the state. |

## Security posture (short version)

Code-enforced: loopback-by-default listener and wildcard-bind refusal; canonical
scheme+host+effective-port Origin/Host fence; CSRF header; HttpOnly/SameSite=Strict
cookies; 256-bit single-use pairing codes with mandatory desktop approval;
atomic claim→approve→issue; single-active-device lease; hashed refresh tokens with
rotation/reuse detection; revocation epoch surviving restarts; shared brute-force
accounting with a one-shot breaker; emergency shutdown; idle timeout; no shell for
child processes; pinned-SHA-256 cloudflared download; plugin-owned SSH known_hosts;
audit sanitization; strict phone endpoint allowlist; no `process.exit()`.

Depends on the operator/network/CI: the phone's own security, your TLS
certificate/CA choices for LAN, your Cloudflare tunnel/DNS/Access configuration,
the tunnel providers' behavior and availability, TLS to the pinned release host,
and manual acceptance testing against real providers (CI does not run real
Cloudflare/SSH/phone E2E). See `SECURITY.md` for the full threat model and
residual risks.

## Development

```bash
pnpm install
pnpm run verify        # typecheck + build + tests + pack-check
pnpm run typecheck     # all five tsconfig projects
pnpm run build         # dist/host + dist/client.js + dist/pwa + dist/tests
pnpm test              # node --test dist/tests
pnpm run contract      # verifies the installed DSH runtime contract
pnpm run pack-check    # npm pack content + artifact sanity
git status --porcelain dist   # must be empty after a build (no dist/src drift)
```

`dist/` is committed build output — rebuild it with `pnpm run build`, never edit
it by hand. `scripts/contract-check.mjs` inspects the locally installed DSH
`app.asar` and verifies the gateway/descriptor surface this plugin depends on;
when no DSH installation is present it prints `SKIP` and exits 0 (exit code alone
is not a compatibility proof — read `PASS`/`SKIP`). CI runs typecheck, build,
tests, pack-check and the contract check on Ubuntu/Node 22; it does **not** run a
real phone, cloudflared, Cloudflare, localhost.run or a live DSH desktop.

## Known limitations

- **No automated end-to-end test with real providers.** Unit/integration suites
  inject fake spawn/fetch/clock seams; real Cloudflare, localhost.run, phone PWA,
  LAN TLS and live DSH desktop acceptance is a manual, explicitly started test.
  Do not treat a green CI run as proof that a real tunnel or phone works.
- The **10-failure circuit breaker is a DoS lever** by design: an attacker who can
  cause failures can force remote access closed until the desktop user re-enables
  it. The plugin never kills the DSH process and never auto-reopens.
- Normal **Stop tunnel/connection** and **Disable** are not security revocations;
  only emergency stop (and plugin dispose) invalidate tokens/epoch.
- Cloudflare **quick tunnel** URLs are temporary and Cloudflare terminates TLS at
  the edge (traffic is not end-to-end encrypted beyond the edge). Quick tunnels
  have Cloudflare-side limits and no uptime guarantee.
- localhost.run free tunnels **change domains and drop**; the plugin supervises
  restarts with backoff, but the public URL is inherently ephemeral, and the host
  key is trusted on first use (TOFU), not pre-verified.
- **LAN** security depends on your certificate/CA setup and on the phone trusting
  it; the plugin cannot make a phone trust a self-signed certificate.
- **Cloudflare Access** verification trusts the operator-supplied team domain and
  audience; a misconfiguration fails closed but cannot prove the deployed Access
  policy is the one you intended. WebSocket re-auth behavior is handled by
  reconnecting, not by a documented provider guarantee.
- Brute-force/ban counters are in-memory and reset on DSH restart; pairing claim
  reservation is in-memory (a crash between reservation and device creation
  spends the claim; the phone must re-pair).
- TLS listener/cleanup and some file-permission tests are POSIX-only and are
  skipped on Windows; signal/exit handling cannot be guaranteed for `SIGKILL`,
  forced termination or power loss (only normal close/signals are covered).
- `userQuestions` relay is behind an off-by-default flag because its wire shape is
  not confirmed for this DSH build.
- Backpressure may drop assistant-stream chunks (never durable transcript
  events); the PWA falls back to the durable transcript after a gap.

## Repository layout

```
src/            Host plugin (TypeScript, tsc -> dist/host)
  shared/       frozen wire/internal contracts (protocol v2)
client/src/     Desktop client plugin bundle (esbuild -> dist/client.js)
pwa/            Phone PWA (esbuild -> dist/pwa)
tests/          node:test suites (tsc -> dist/tests)
scripts/        build/contract/pack dev scripts
dist/           committed build artifacts (link: installs need no build)
locale/         plugin metadata (en/tr)
cordis.patch.yml  bundle insert row (master switch off)
```

## License

MIT
