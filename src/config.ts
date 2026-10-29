/**
 * Plugin configuration schema (Schemastery).
 *
 * Safe-by-default: everything that can expose this machine is off until the
 * user explicitly enables it from the desktop panel. The bundle install row
 * (`cordis.patch.yml`) opts `remoteMutations`/`approvalRelay` in but keeps the
 * master switch off.
 */

import Schema from '@deepseek-ai/schemastery'

/**
 * Default environment-variable name for the connector token in `named` mode.
 * A token file may be used instead; setting both to *different* explicit
 * sources is rejected as ambiguous (they are mutually exclusive).
 */
export const DEFAULT_TUNNEL_TOKEN_ENV = 'CLOUDFLARE_TUNNEL_TOKEN'

export const Config = Schema.object({
  enabled: Schema.boolean()
    .default(false)
    .description(
      'Start the remote-control listener. Off by default; enable it from Settings → Remote Control.',
    ),

  autoStart: Schema.boolean()
    .default(false)
    .description(
      'Re-enable a previously enabled listener on the next DSH start. An explicit Off always stays off.',
    ),

  listen: Schema.object({
    host: Schema.string()
      .default('127.0.0.1')
      .description(
        'Concrete IPv4/IPv6 literal to bind (loopback for managed Cloudflare/SSH sessions). A LAN selection requires listen.access="lan" and a concrete LAN address.',
      ),
    port: Schema.natural()
      .max(65535)
      .default(0)
      .description(
        'TCP port for the phone listener; 0 asks the OS for an ephemeral port (required for managed Cloudflare and SSH).',
      ),
    allowLan: Schema.boolean()
      .default(false)
      .description(
        'Legacy alias for listen.access="lan". When true, a concrete non-loopback listen.host is treated as the explicitly selected LAN address. Plain HTTP on a LAN is refused for pairing.',
      ),
    access: Schema.union(['loopback', 'lan'])
      .default('loopback')
      .description(
        'Listener access strategy. loopback: phone reaches the listener only through a tunnel / same machine. lan: explicitly expose the selected LAN address (requires TLS).',
      ),
    lanAddress: Schema.string()
      .default('')
      .description(
        'Explicitly selected LAN interface address for listen.access="lan". Empty falls back to a concrete non-loopback listen.host.',
      ),
    tls: Schema.object({
      certFile: Schema.string().default(''),
      keyFile: Schema.string().default(''),
    })
      .default({ certFile: '', keyFile: '' })
      .description('Optional PEM certificate/key pair. Both must be set together; empty disables TLS.'),
  })
    .default({ host: '127.0.0.1', port: 0, allowLan: false, tls: { certFile: '', keyFile: '' } })
    .description('How the phone listener binds on this machine.'),

  tunnel: Schema.object({
    enabled: Schema.boolean()
      .default(false)
      .description('Expose the phone listener through a tunnel. Off by default.'),
    mode: Schema.union(['quick', 'external', 'named', 'named-local', 'ssh'])
      .default('quick')
      .description(
        'quick: token-free managed cloudflared quick tunnel with a temporary URL. external: operator-provided fixed HTTPS publicUrl (existing connector/service); no child process. named: remotely-managed Cloudflare named tunnel (connector token or token file). named-local: locally-managed named tunnel (UUID + credentials JSON, generated ingress config). ssh: managed OpenSSH reverse tunnel via localhost.run.',
      ),
    cloudflaredPath: Schema.string()
      .default('cloudflared')
      .description('cloudflared executable name on PATH or an absolute path (Cloudflare modes).'),
    startupTimeoutSeconds: Schema.number()
      .min(10)
      .max(180)
      .step(1)
      .default(45)
      .description('How long to wait for the tunnel URL / registration before failing.'),
    publicUrl: Schema.string()
      .default('')
      .description(
        'external mode only: the fixed public HTTPS origin that terminates TLS in front of this listener, e.g. https://rc.example.com.',
      ),
    hostname: Schema.string()
      .default('')
      .description('named / named-local: the fixed public hostname configured for the Cloudflare tunnel.'),
    tokenEnv: Schema.string()
      .default(DEFAULT_TUNNEL_TOKEN_ENV)
      .description(
        'named mode: environment variable that holds the connector token. The token itself is never stored in this config, argv, QR, logs or the PWA. Mutually exclusive with tokenFile.',
      ),
    tokenFile: Schema.string()
      .default('')
      .description(
        'named mode: path to a connector token file passed with --token-file (cloudflared >= 2025.4.0). Mutually exclusive with tokenEnv; the file content is never read into config/logs/argv.',
      ),
    transport: Schema.union(['auto', 'quic', 'http2'])
      .default('auto')
      .description('Cloudflare connector transport. Not a separate tunnel method; `auto` is recommended.'),
    tunnelId: Schema.string()
      .default('')
      .description('named-local mode: the Cloudflare tunnel UUID. Must match the credentials JSON.'),
    credentialsFile: Schema.string()
      .default('')
      .description(
        'named-local mode: path to the tunnel credentials JSON (AccountTag/TunnelSecret/TunnelID). The plugin generates its own runtime config; your global cloudflared config is never modified.',
      ),
    sshPath: Schema.string()
      .default('ssh')
      .description('ssh mode: OpenSSH client executable (name on PATH or absolute path). Never downloaded.'),
    sshUser: Schema.string()
      .default('nokey')
      .description('ssh mode: localhost.run user.'),
    sshHost: Schema.string()
      .default('localhost.run')
      .description('ssh mode: localhost.run SSH host.'),
    sshRemotePort: Schema.number()
      .min(1)
      .max(65535)
      .step(1)
      .default(80)
      .description('ssh mode: remote port requested with -R (localhost.run uses 80).'),
    env: Schema.dict(Schema.string())
      .default({})
      .description(
        'Extra non-credential environment variables for the tunnel child. DSH_* variables and credentials are never inherited by the child.',
      ),
    access: Schema.object({
      required: Schema.boolean()
        .default(false)
        .description(
          'Require a valid Cloudflare Access JWT assertion on the phone surfaces when the fixed hostname is protected by Access. Verification happens at the Host, fail closed.',
        ),
      teamDomain: Schema.string()
        .default('')
        .description('Access team domain for JWKS, e.g. myteam.cloudflareaccess.com (bare host, no scheme/path).'),
      audience: Schema.string()
        .default('')
        .description('Access application audience (aud) tag expected in the JWT assertion.'),
    })
      .default({ required: false, teamDomain: '', audience: '' })
      .description('Optional Cloudflare Access layer for fixed-hostname connectors (never a tunnel method).'),
  })
    .default({
      enabled: false,
      mode: 'quick',
      cloudflaredPath: 'cloudflared',
      startupTimeoutSeconds: 45,
      publicUrl: '',
      hostname: '',
      tokenEnv: DEFAULT_TUNNEL_TOKEN_ENV,
      tokenFile: '',
      transport: 'auto',
      tunnelId: '',
      credentialsFile: '',
      sshPath: 'ssh',
      sshUser: 'nokey',
      sshHost: 'localhost.run',
      sshRemotePort: 80,
      env: {},
      access: { required: false, teamDomain: '', audience: '' },
    })
    .description('Optional public reachability for the phone listener.'),

  pairing: Schema.object({
    ttlSeconds: Schema.number()
      .min(30)
      .max(600)
      .step(1)
      .default(120)
      .description('Lifetime of a one-time pairing code.'),
    maxPendingCodes: Schema.number()
      .min(1)
      .max(5)
      .step(1)
      .default(3)
      .description('Maximum number of outstanding pairing codes.'),
  })
    .default({ ttlSeconds: 120, maxPendingCodes: 3 })
    .description('Pairing code limits. Desktop approval of every new device is always required.'),

  tokens: Schema.object({
    accessTtlMinutes: Schema.number()
      .min(0)
      .max(1440)
      .step(1)
      .default(0)
      .description(
        'Access-token lifetime in minutes. 0 means "use the default (15 minutes) / the legacy accessTtlHours value". Minimum effective lifetime is 10 minutes.',
      ),
    accessTtlHours: Schema.number()
      .min(0)
      .max(72)
      .step(1)
      .default(0)
      .description(
        'Deprecated legacy access-token lifetime in hours. Only used when accessTtlMinutes is 0 and this value is > 0. The default is now 15 minutes; set accessTtlMinutes for new configurations.',
      ),
    refreshTtlDays: Schema.number()
      .min(1)
      .max(90)
      .default(10)
      .description('Refresh-token lifetime; rotated on every use with reuse detection.'),
    refreshAheadSeconds: Schema.number()
      .min(30)
      .max(3600)
      .step(1)
      .default(300)
      .description('Reserved: proactive refresh-ahead rotation is not enforced; refresh tokens rotate on every use and reuse is detected.'),
    maxDevices: Schema.number()
      .min(1)
      .max(4)
      .step(1)
      .default(4)
      .description('Maximum number of paired devices (hard schema ceiling: 4). Only one is active at a time.'),
    deviceStorePath: Schema.string()
      .default('')
      .description(
        'Absolute path for the device store JSON. Empty uses <DSH_HOME>/remote-control/devices.json.',
      ),
  })
    .default({
      accessTtlMinutes: 0,
      accessTtlHours: 0,
      refreshTtlDays: 10,
      refreshAheadSeconds: 300,
      maxDevices: 4,
      deviceStorePath: '',
    })
    .description('Device token lifetimes and limits.'),

  security: Schema.object({
    idleTimeoutMinutes: Schema.number()
      .min(5)
      .max(240)
      .step(1)
      .default(30)
      .description(
        'Close remote access after this many minutes without verified phone activity. Desktop polling, anonymous traffic and server-side pings do not renew it.',
      ),
    failureWindowSeconds: Schema.number()
      .min(10)
      .max(600)
      .step(1)
      .default(60)
      .description('Sliding window used for the per-IP temporary authentication ban.'),
    failuresBeforeBan: Schema.number()
      .min(1)
      .max(50)
      .step(1)
      .default(5)
      .description(
        'Failed authentications from one IP inside the window that trigger the temporary ban (the next failure blocks; default 5 means the 6th fails).',
      ),
    temporaryBanMinutes: Schema.number()
      .min(1)
      .max(60)
      .step(1)
      .default(5)
      .description('How long one IP stays blocked after too many authentication failures.'),
    circuitBreakerFailures: Schema.number()
      .min(3)
      .max(100)
      .step(1)
      .default(10)
      .description(
        'Total failed authentications in one manually started remote-access period before the circuit breaker closes remote access. This threshold is a deliberate DoS trade-off; see SECURITY.md.',
      ),
  })
    .default({
      idleTimeoutMinutes: 30,
      failureWindowSeconds: 60,
      failuresBeforeBan: 5,
      temporaryBanMinutes: 5,
      circuitBreakerFailures: 10,
    })
    .description('Attack-surface and idle-shutdown policy.'),

  remoteMutations: Schema.boolean()
    .default(false)
    .description(
      'Allow prompt, steer and cancel from a paired phone. Off keeps every phone read-only.',
    ),

  approvalRelay: Schema.boolean()
    .default(false)
    .description(
      'Relay approval waterfalls to paired phones as answering clients. The first answer wins; the desktop stays authoritative.',
    ),

  userQuestions: Schema.boolean()
    .default(false)
    .description(
      'Also relay user-question waterfalls (not just tool approvals). The wire shape is unverified against the installed DSH build; keep this off unless you need it.',
    ),

  approvalReminderSeconds: Schema.number()
    .min(30)
    .max(3600)
    .step(1)
    .default(300)
    .description(
      'How long a phone keeps showing a pending approval countdown. The plugin never fabricates a decision on timeout.',
    ),

  allowedOrigins: Schema.array(Schema.string())
    .default([])
    .description(
      'Extra exact HTTP origins accepted by the Host/Origin fence (advanced; e.g. a reverse proxy you control).',
    ),

  logLevel: Schema.union(['error', 'warn', 'info', 'debug'])
    .default('warn')
    .description('Plugin log verbosity. Tokens, prompts and tool output are never logged.'),
}).description(
  'Remote Control: a paired phone/PWA becomes a second client of this local DeepSeek Harness session. The agent loop, tools and files never leave this machine.',
)

/**
 * Structural mirror of the Schema above. Kept explicit so the rest of the code
 * gets hover/type support without inferring through the runtime schema object.
 */
export interface RemoteControlConfig {
  enabled: boolean
  autoStart: boolean
  listen: {
    host: string
    port: number
    allowLan: boolean
    access: 'loopback' | 'lan'
    lanAddress: string
    tls: { certFile: string; keyFile: string }
  }
  tunnel: {
    enabled: boolean
    mode: 'quick' | 'external' | 'named' | 'named-local' | 'ssh'
    cloudflaredPath: string
    startupTimeoutSeconds: number
    publicUrl: string
    hostname: string
    tokenEnv: string
    tokenFile: string
    transport: 'auto' | 'quic' | 'http2'
    tunnelId: string
    credentialsFile: string
    sshPath: string
    sshUser: string
    sshHost: string
    sshRemotePort: number
    env: Record<string, string>
    access: { required: boolean; teamDomain: string; audience: string }
  }
  pairing: {
    ttlSeconds: number
    maxPendingCodes: number
  }
  tokens: {
    accessTtlMinutes: number
    accessTtlHours: number
    refreshTtlDays: number
    refreshAheadSeconds: number
    maxDevices: number
    deviceStorePath: string
  }
  security: {
    idleTimeoutMinutes: number
    failureWindowSeconds: number
    failuresBeforeBan: number
    temporaryBanMinutes: number
    circuitBreakerFailures: number
  }
  remoteMutations: boolean
  approvalRelay: boolean
  userQuestions: boolean
  approvalReminderSeconds: number
  allowedOrigins: string[]
  logLevel: 'error' | 'warn' | 'info' | 'debug'
}

/**
 * Effective access-token lifetime: new `accessTtlMinutes`, then the deprecated
 * `accessTtlHours`, then the 15-minute default. Never below 10 minutes.
 */
export function resolveAccessTtlMs(tokens: RemoteControlConfig['tokens']): number {
  const minutes = Number(tokens.accessTtlMinutes)
  const hours = Number(tokens.accessTtlHours)
  const effective =
    Number.isFinite(minutes) && minutes > 0
      ? minutes
      : Number.isFinite(hours) && hours > 0
        ? hours * 60
        : 15
  return Math.max(10, effective) * 60_000
}

export type ConfigLogger = Pick<RemoteControlConfig, 'logLevel'>
