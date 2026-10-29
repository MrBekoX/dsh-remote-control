/**
 * DSH Remote Control — **client half** (Web GUI).
 *
 * Registers two Cordis client-plugin surfaces:
 *
 * - `settings.section` — the “Remote Control” settings tab. It shows the single
 *   computed connection state (listener, public origin, QR origin, cookie
 *   decision), a method-by-method connection flow (Cloudflare quick / named /
 *   named-local, external connector, SSH, LAN, loopback) with a pre-start
 *   disclosed **plan → explicit Start** confirmation (and an explicit,
 *   user-initiated, SHA-256-verified binary download), stop/disable/emergency
 *   actions, the single-active-device lock with per-device activate/revoke, the
 *   security state and the recent audit log. It polls
 *   `/api/dsh-remote-control/status` every 2 s **only while mounted**.
 * - `shell.overlay` — the desktop pairing-approval modal: while a pairing
 *   window is open (or an approval is already showing) it polls
 *   `/api/dsh-remote-control/pending` every 2 s and asks the user to approve or
 *   deny the claiming device.
 *
 * Everything runs inside the `window.__ModuleLoader__.load({ id, factory })`
 * closure produced by `scripts/build-client.mjs`; the only external module is
 * React (platform seed). No JSX: React.createElement only, and no
 * `innerHTML`/`eval` — all Host-provided strings are rendered as text or as a
 * percent-encoded `data:image/svg+xml` URL.
 *
 * Wire contract: `src/shared/protocol.ts` (frozen; owned by the Lead).
 */

import { RC_ADMIN_PATH, RC_CSRF_HEADER } from '../../src/shared/protocol.js'
import type {
  AdminConnectionPlanResponse,
  AdminConnectionStartResponse,
  AdminConnectionStopResponse,
  AdminControlResponse,
  AdminEmergencyStopResponse,
  AdminInstallResponse,
  AdminPairCreateResponse,
  AdminStatusEnvelope,
  AuditEntryView,
  CloudflaredDownloadInfo,
  ConnectionMethod,
  ConnectionPlan,
  ConnectionPlanStep,
  ConnectionSelection,
  ConnectionStateView,
  DeviceView,
  LanInterfaceView,
  ListenerStatus,
  PairingView,
  SecurityStateView,
  TunnelState,
  TunnelStatus,
  TunnelTransport,
} from '../../src/shared/protocol.js'
import type { ReactElement, ReactNode } from 'react'

/* -------------------------------------------------------------------------- */
/* React binding (platform seed; CJS require is the loader contract)          */
/* -------------------------------------------------------------------------- */

type ReactModule = typeof import('react')
const React = require('react') as ReactModule
const h: ReactModule['createElement'] = React.createElement

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

const NAMESPACE = 'dsh-remote-control'
const SETTINGS_SECTION_SLOT = 'settings.section'
const OVERLAY_SLOT = 'shell.overlay'
const OVERLAY_ID = `${NAMESPACE}.pairing`
const STATUS_POLL_MS = 2_000
const PENDING_POLL_MS = 2_000
const STYLE_ELEMENT_ID = `${NAMESPACE}/panel.css`
const DEFAULT_PAIRING_TTL_MS = 120_000
/** How many audit rows the panel renders (newest first). */
const AUDIT_VISIBLE_ROWS = 40

/**
 * Exact Host admin routes (registered by `src/admin.ts`, frozen with the Lead).
 * Kept in one table so a rename is a one-line change and the build script can
 * statically verify the panel never drifts from the server surface.
 */
const ADMIN_ROUTES = {
  status: 'status',
  pending: 'pending',
  control: 'control',
  pairCreate: 'pair/create',
  pairApprove: 'pair/approve',
  pairDeny: 'pair/deny',
  deviceRevoke: 'device/revoke',
  deviceRevokeAll: 'device/revoke-all',
  deviceActivate: 'device/activate',
  deviceRelease: 'device/release',
  connectionPlan: 'connection/plan',
  connectionStart: 'connection/start',
  connectionStop: 'connection/stop',
  emergencyStop: 'emergency-stop',
  install: 'install',
} as const

/* -------------------------------------------------------------------------- */
/* Copy (en/tr; every language carries the exact English key set)             */
/* -------------------------------------------------------------------------- */

const en = {
  nav: 'Remote Control',
  'panel.title': 'Remote Control',
  'panel.subtitle': 'Pair a phone with this DeepSeek Harness session',
  'panel.loading': 'Loading…',
  'settings.loadFailed': 'Could not load Remote Control status',
  yes: 'Yes',
  no: 'No',
  retry: 'Retry',
  'value.none': '—',
  'state.off': 'Off',
  'state.loopback': 'Loopback only',
  'state.lan': 'LAN',
  'state.tunnel': 'Tunnel',
  'state.ready': 'Ready',
  'state.starting': 'Starting…',
  'state.unverified': 'Connected (unverified)',
  'state.accessRequired': 'Access required',
  'state.mismatch': 'Mismatch',
  'state.missingConfig': 'Configuration missing',
  'state.missingBinary': 'cloudflared missing',
  'state.closed': 'Security closed',
  'state.warn': 'Warning',
  'state.down': 'Down',

  'emergency.stop': 'Emergency stop',
  'emergency.title': 'Emergency stop',
  'emergency.body':
    'Closes remote access immediately: invalidates every phone session and token, cancels pending pairings, stops the listener and the plug-in-owned tunnel. It stays closed until you re-enable Remote Control.',
  'emergency.confirm':
    'EMERGENCY STOP: close remote access now?\n\nAll paired phones lose access immediately and every token is invalidated. Remote access stays closed until you re-enable it.',
  'emergency.done': 'Remote access was closed by the emergency stop.',
  'closed.title': 'Remote access is closed',
  'closed.body':
    'Remote access is closed after a security shutdown. It never reopens automatically.',
  'closed.reason.user-emergency': 'Emergency stop',
  'closed.reason.circuit-breaker': 'Too many failed authentication attempts',
  'closed.reason.idle-timeout': 'Idle timeout',
  'closed.reason.tunnel-lost': 'The tunnel connection was lost',
  'closed.reason.dispose': 'The Host shut the plug-in down',
  'closed.reason.default': 'Security shutdown',
  'closed.reopen': 'Re-enable remote access',
  'closed.reopenConfirm': 'Re-open remote access? A phone will be able to pair again.',

  'control.title': 'Listener',
  'control.on': 'The phone listener is running.',
  'control.off': 'The phone listener is stopped.',
  'control.enable': 'Enable',
  'control.disable': 'Disable',
  'listener.title': 'Listener status',
  'listener.host': 'Host',
  'listener.port': 'Port',
  'listener.secure': 'HTTPS',
  'listener.lan': 'LAN access',
  'listener.url': 'URL',
  'listener.access': 'Access',
  'listener.protocol': 'Protocol',
  'loopback.warning':
    'Phones cannot reach this listener. Enable LAN access or a public connector, then pair again.',

  'connection.title': 'Connection',
  'connection.none': 'No connection is running. Choose a method below to plan one.',
  'connection.method': 'Method',
  'connection.state': 'State',
  'connection.ownership': 'Process ownership',
  'connection.transport': 'Transport',
  'connection.serviceUrl': 'Local service URL',
  'connection.httpCheck': 'HTTP check',
  'connection.wsCheck': 'WebSocket check',
  'connection.verified': 'Verified',
  'connection.notVerified': 'Not verified',
  'connection.publicOrigin': 'Public origin',
  'connection.qrOrigin': 'QR origin',
  'connection.secureCookies': 'Secure cookies',
  'connection.access': 'Cloudflare Access',
  'connection.stop': 'Stop public exposure',
  'connection.stopConfirm':
    'Stop the public tunnel? Phones lose the public URL until you start it again.',
  'connection.error': 'Connection error',
  'connection.detail': 'Detail',
  'connection.running': 'A public connection is active. Stop it before planning a new one.',
  'ownership.plugin': 'Owned by this plug-in',
  'ownership.external': 'External connector (not owned)',
  'ownership.none': 'None',
  'transport.auto': 'Auto',
  'transport.quic': 'QUIC',
  'transport.http2': 'HTTP/2',

  'methods.title': 'Connection method',
  'methods.intro':
    'Pick how the phone reaches this machine. Nothing is started until you review the disclosed plan and press Start.',
  'methods.loopback': 'Loopback only',
  'methods.loopbackHint': 'No phone access. Useful to verify the listener.',
  'methods.lan': 'LAN',
  'methods.lanHint': 'A phone on the same network. Requires a trusted TLS certificate.',
  'methods.cloudflareQuick': 'Cloudflare Quick Tunnel',
  'methods.cloudflareQuickHint': 'Temporary trycloudflare.com URL, no Cloudflare account needed.',
  'methods.cloudflareNamed': 'Cloudflare Named Tunnel (remotely-managed)',
  'methods.cloudflareNamedHint': 'Connector token from an environment variable or token file.',
  'methods.cloudflareNamedLocal': 'Cloudflare Named Tunnel (locally-managed)',
  'methods.cloudflareNamedLocalHint': 'Tunnel UUID plus its credentials JSON.',
  'methods.external': 'External connector',
  'methods.externalHint':
    'Operator-provided fixed HTTPS origin. The plug-in never owns that process.',
  'methods.ssh': 'SSH tunnel (localhost.run)',
  'methods.sshHint': 'Reverse SSH forwarding with the system OpenSSH client.',
  'methods.transport': 'Transport',
  'methods.transportHint': 'Connector transport. Auto is the default; it is not a separate method.',
  'methods.advanced': 'Advanced (optional)',
  'methods.hostname': 'Public hostname',
  'methods.hostnamePlaceholder': 'rc.example.com',
  'methods.loopbackPort': 'Fixed loopback port',
  'methods.loopbackPortHint': '0 or empty = pick a free port automatically.',
  'methods.cloudflaredPath': 'cloudflared path',
  'methods.cloudflaredPathHint': 'Optional. Configured path → PATH → verified cache.',
  'methods.tokenSource': 'Connector token source',
  'methods.tokenSourceEnv': 'Environment variable',
  'methods.tokenSourceFile': 'Token file',
  'methods.tokenEnv': 'Environment variable name',
  'methods.tokenEnvPlaceholder': 'CLOUDFLARE_TUNNEL_TOKEN',
  'methods.tokenFile': 'Token file path',
  'methods.tokenFilePlaceholder': 'C:\\path\\to\\token.txt',
  'methods.tunnelId': 'Tunnel UUID',
  'methods.tunnelIdPlaceholder': '00000000-0000-0000-0000-000000000000',
  'methods.credentialsFile': 'Credentials JSON',
  'methods.credentialsFilePlaceholder': 'C:\\Users\\…\\.cloudflared\\<uuid>.json',
  'methods.publicUrl': 'Public HTTPS origin',
  'methods.publicUrlPlaceholder': 'https://rc.example.com',
  'methods.sshPath': 'ssh executable',
  'methods.sshPathHint': 'Optional. Defaults to the platform OpenSSH client; never downloaded.',
  'methods.sshUser': 'SSH user (optional)',
  'methods.sshHost': 'SSH host (optional)',
  'methods.sshRemotePort': 'Remote port (optional)',
  'methods.accessRequired': 'Require Cloudflare Access on the fixed hostname',
  'methods.lanSelect': 'Interface address',
  'methods.lanNone': 'No recommended LAN address was found on this machine.',
  'methods.lanTlsWarning':
    'LAN pairing needs a trusted HTTPS certificate. Without TLS the plan refuses to start.',
  'methods.lanUnsafe': 'Link-local and other unreachable addresses are not offered.',
  'methods.cloudflaredFound': 'cloudflared found: {version} ({source}) · verified: {verified}',
  'methods.cloudflaredMissing': 'cloudflared is not installed yet. The plan will offer it.',
  'methods.cloudflaredUnsupported':
    'No pinned official cloudflared release exists for this platform; a managed tunnel cannot start.',
  'methods.invalidHostname': 'Enter a valid public hostname (letters, digits, dot, hyphen).',
  'methods.invalidPublicUrl': 'Enter a valid https:// origin.',
  'methods.invalidPort': 'Enter a port between 0 and 65535.',
  'methods.lanAddressRequired': 'Select the LAN interface address explicitly.',
  'methods.tokenRequired': 'Choose an environment variable or a token file.',
  'methods.tunnelIdRequired': 'Enter the tunnel UUID.',
  'methods.credentialsRequired': 'Enter the credentials JSON path.',
  'methods.plan': 'Review plan',
  'methods.planBusy': 'Planning…',
  'methods.starting': 'Starting…',

  'plan.title': 'Review before starting',
  'plan.intro':
    'These are all disclosed effects of the selected method. Nothing is started or downloaded until you press the matching button.',
  'plan.expires': 'Plan expires in {seconds}s',
  'plan.expired': 'This plan expired. Create a new plan to continue.',
  'plan.replan': 'Create a new plan',
  'plan.steps': 'Disclosed steps',
  'plan.noSteps': 'The Host did not disclose any additional steps.',
  'plan.listener': 'Listener',
  'plan.access': 'Listener access',
  'plan.host': 'Host',
  'plan.port': 'Port',
  'plan.protocol': 'Protocol',
  'plan.secure': 'Secure cookies',
  'plan.publicOrigin': 'Public origin',
  'plan.qrOrigin': 'QR origin',
  'plan.accessRequired': 'Cloudflare Access',
  'plan.portDynamic': 'dynamic (chosen at start)',
  'plan.install': 'Download and verify',
  'plan.installing': 'Downloading and verifying…',
  'plan.installConfirm':
    'Download the pinned official cloudflared release and verify its official SHA-256 before use?',
  'plan.installDone': 'cloudflared was downloaded, verified and cached.',
  'plan.installFailedTitle': 'Download/verification failed',
  'plan.startFailed': 'Could not start the connection',
  'plan.start': 'Start',
  'plan.cancel': 'Cancel',
  'plan.download': 'Binary download',
  'plan.downloadIntro':
    'The pinned official cloudflared release is downloaded only when you press the button, then verified against the official SHA-256 before use.',
  'plan.downloadUnsupported':
    'No pinned official asset exists for this platform; a managed tunnel cannot start here.',
  'plan.downloadInstalled': 'Usable binary found — no download is needed.',
  'plan.installedPath': 'Installed binary',
  'plan.downloadInstalledDetail': '{path} ({source}, version {version}, SHA-256 verified: {verified})',
  'plan.version': 'Version',
  'plan.asset': 'Asset',
  'plan.size': 'Size',
  'plan.sha256': 'SHA-256',
  'plan.releaseUrl': 'Release URL',
  'plan.cacheDir': 'Cache directory',
  'plan.provider': 'Provider',

  'step.kind.listener': 'Listener',
  'step.kind.tunnel': 'Tunnel',
  'step.kind.download': 'Download',
  'step.kind.tls': 'TLS',
  'step.kind.access': 'Cloudflare Access',
  'step.kind.origin': 'Public origin',
  'step.kind.warning': 'Warning',
  'step.kind.security': 'Security',
  'step.param.address': 'Address',
  'step.param.host': 'Host',
  'step.param.port': 'Port',
  'step.param.protocol': 'Protocol',
  'step.param.url': 'URL',
  'step.param.origin': 'Origin',
  'step.param.hostname': 'Hostname',
  'step.param.provider': 'Provider',
  'step.param.version': 'Version',
  'step.param.asset': 'Asset',
  'step.param.sha256': 'SHA-256',
  'step.param.sizeBytes': 'Size',
  'step.param.size': 'Size',
  'step.param.secure': 'Secure',
  'step.param.access': 'Access',
  'step.param.transport': 'Transport',
  'step.param.serviceUrl': 'Service URL',
  'step.param.dynamic': 'Dynamic port',
  'step.param.fixedPort': 'Fixed port',
  'step.param.cacheDirectory': 'Cache directory',
  'step.param.releaseUrl': 'Release URL',
  'step.param.detail': 'Detail',

  'pair.title': 'Pair a device',
  'pair.create': 'Pair device',
  'pair.instructions': 'Scan the QR code with your phone, or open the URL on the phone.',
  'pair.enableFirst': 'Enable Remote Control before pairing a phone.',
  'pair.code': 'Pairing code',
  'pair.url': 'Pairing URL',
  'pair.qrAlt': 'Pairing QR code',
  'pair.qrPending': 'QR code is not ready yet.',
  'pair.expires': 'Expires in {seconds}s',
  'pair.expired': 'This pairing request expired.',
  'pair.waiting': 'Waiting for the phone to connect…',
  'pair.dismiss': 'Hide',
  'pair.securityClosed': 'Remote access is closed. Re-enable it before pairing.',
  'pair.selectionRequired':
    'More than one device is registered. Choose the active device before pairing a phone.',
  'pair.activeDeviceLocked':
    'Another device is currently active. Release or revoke it before pairing a new phone (single-device lock).',
  'pair.tlsRequired':
    'LAN pairing requires a trusted HTTPS certificate. Fix TLS on the listener before pairing.',

  'devices.title': 'Paired devices',
  'devices.empty': 'No paired devices.',
  'devices.label': 'Device',
  'devices.platform': 'Platform',
  'devices.lastSeen': 'Last seen',
  'devices.active': 'Active',
  'devices.revoke': 'Revoke',
  'devices.revokeAll': 'Revoke all',
  'devices.activate': 'Make active',
  'devices.release': 'Release lock',
  'devices.confirmRevoke': 'Revoke this device? Its cookies stop working immediately.',
  'devices.confirmRevokeActive':
    'Revoke the ACTIVE device? Remote access ends immediately and its cookies stop working.',
  'devices.confirmRevokeAll': 'Revoke every paired device?',
  'devices.activateConfirm':
    'Make “{device}” the active device? Any other active device loses remote access.',
  'devices.actions': 'Actions',

  'lock.title': 'Single active device',
  'lock.state': 'Lock state',
  'lock.state.none': 'No active device',
  'lock.state.active': 'Active',
  'lock.state.selection-required': 'Selection required',
  'lock.state.released': 'Released',
  'lock.activeDevice': 'Active device',
  'lock.since': 'Active since',
  'lock.lastActivity': 'Last activity',
  'lock.idleExpires': 'Idle closes in',
  'lock.idleTimeout': 'Idle timeout',
  'lock.registered': 'Registered devices',
  'lock.needsSelection':
    'More than one device is registered. Choose the active device explicitly — the plug-in never picks one automatically.',
  'lock.noActive':
    'No device holds the lock. Remote access stays blocked until you activate a device.',
  'lock.activate': 'Make active',
  'lock.release': 'Release lock',
  'lock.activateConfirm':
    'Make “{device}” the active device? Any other active device loses remote access.',
  'lock.releaseConfirm':
    'Release the active-device lock? Remote access stays paired but blocked until a device is activated.',
  'lock.noticeSecondDevice':
    'A second-device attempt was rejected by the single-device lock ({time}).',
  'lock.noticeSecondDeviceDetail': 'Detail: {detail}',
  'lock.minutesValue': '{minutes} min',

  'security.title': 'Security',
  'security.closed': 'Remote access closed',
  'security.reason': 'Reason',
  'security.circuitBreaker': 'Failure circuit breaker',
  'security.breakerOpen': 'Open — remote access closed',
  'security.breakerClosed': 'Closed',
  'security.failures': 'Failures this session',
  'security.blocked': 'Temporarily blocked clients',
  'security.window': 'Failure window',
  'security.ban': 'Temporary ban',
  'security.breakerThreshold': 'Breaker threshold',
  'security.epoch': 'Token revocation epoch',
  'security.idleTimeout': 'Idle timeout',
  'security.windowValue': '{seconds}s',
  'security.banValue': '{minutes} min',
  'security.notifications': 'Security notifications',

  'audit.title': 'Audit log',
  'audit.empty': 'No audit entries yet.',
  'audit.latest': 'Newest first · last {count}',
  'audit.time': 'Time',
  'audit.kind': 'Kind',
  'audit.operation': 'Operation',
  'audit.result': 'Result',
  'audit.device': 'Device',
  'audit.ip': 'IP',
  'audit.userAgent': 'User agent',
  'audit.detail': 'Detail',
  'audit.kind.enable': 'Enable',
  'audit.kind.disable': 'Disable',
  'audit.kind.pair': 'Pairing',
  'audit.kind.approve': 'Approval',
  'audit.kind.deny': 'Denial',
  'audit.kind.revoke': 'Revocation',
  'audit.kind.rpc': 'Remote call',
  'audit.kind.answer': 'Approval answer',
  'audit.kind.tunnel': 'Tunnel',
  'audit.kind.security': 'Security',
  'audit.kind.device-lock': 'Device lock',
  'audit.result.ok': 'ok',
  'audit.result.rejected': 'rejected',
  'audit.result.failed': 'failed',
  'audit.result.notice': 'notice',

  'tunnel.title': 'Tunnel',
  'tunnel.disabled': 'Tunnel is disabled.',
  'tunnel.mode': 'Mode',
  'tunnel.state': 'State',
  'tunnel.url': 'Public URL',
  'tunnel.starting': 'Starting…',
  'tunnel.down': 'Down',
  'tunnel.off': 'Off',
  'tunnel.missingBinary': 'cloudflared not found',
  'tunnel.temporary': 'Temporary URL — devices must pair again when the URL changes.',
  'tunnel.error': 'Tunnel error',

  'info.title': 'Version',
  'info.dshRelease': 'DSH release',
  'info.pluginVersion': 'Plugin version',
  'pending.title': 'New device',
  'pending.body': 'wants to connect to this DeepSeek Harness.',
  'pending.platform': 'Platform',
  'pending.remaining': 'Auto-expires in {seconds}s',
  'pending.approve': 'Approve',
  'pending.deny': 'Deny',
  'pending.more': '{count} more device request(s) waiting.',
  'pending.approveFailed': 'Could not approve the device',
  'error.noStatus': 'No status yet.',
  'error.code.DEVICE_LOCKED':
    'Another device is active. Release or revoke the active device before pairing a new phone.',
  'error.code.SECURITY_CLOSED': 'Remote access is closed after a security shutdown.',
  'error.code.TLS_REQUIRED': 'This LAN address needs a trusted HTTPS certificate.',
  'error.code.INSTALL_REQUIRED': 'The provider binary must be installed first.',
  'error.code.SSH_MISSING': 'The OpenSSH client was not found; it is never downloaded.',
  'error.code.CHECKSUM_MISMATCH': 'The downloaded binary did not match the official SHA-256.',
  'error.code.UNSUPPORTED_PLATFORM': 'No pinned official binary exists for this platform.',
  'error.code.CONSENT_REQUIRED': 'The plan expired or was not confirmed; create a new plan.',
  'error.code.RATE_LIMITED': 'Too many attempts; try again shortly.',
  'error.code.NOT_ALLOWED': 'Not allowed in the current state.',
  'error.code.ACCESS_REQUIRED': 'Cloudflare Access verification is required.',
  'error.code.DEVICE_LIMIT': 'The maximum number of paired devices was reached.',
  'error.code.PAIRING_INVALID': 'The pairing claim is invalid or already used.',
  'error.code.PAIRING_EXPIRED': 'The pairing request expired.',
  'error.code.PAIRING_DENIED': 'The pairing request was denied on the desktop.',
} as const

type MessageKey = keyof typeof en

const tr: Record<MessageKey, string> = {
  nav: 'Uzaktan Kontrol',
  'panel.title': 'Uzaktan Kontrol',
  'panel.subtitle': 'Bu DeepSeek Harness oturumuna bir telefon eşleyin',
  'panel.loading': 'Yükleniyor…',
  'settings.loadFailed': 'Uzaktan Kontrol durumu yüklenemedi',
  yes: 'Evet',
  no: 'Hayır',
  retry: 'Yeniden dene',
  'value.none': '—',
  'state.off': 'Kapalı',
  'state.loopback': 'Yalnız loopback',
  'state.lan': 'LAN',
  'state.tunnel': 'Tünel',
  'state.ready': 'Hazır',
  'state.starting': 'Başlatılıyor…',
  'state.unverified': 'Bağlı (doğrulanmadı)',
  'state.accessRequired': 'Access gerekli',
  'state.mismatch': 'Uyuşmazlık',
  'state.missingConfig': 'Yapılandırma eksik',
  'state.missingBinary': 'cloudflared yok',
  'state.closed': 'Güvenlik kapalı',
  'state.warn': 'Uyarı',
  'state.down': 'Kapalı',

  'emergency.stop': 'Acil durdurma',
  'emergency.title': 'Acil durdurma',
  'emergency.body':
    'Uzaktan erişimi hemen kapatır: tüm telefon oturumlarını ve token’ları geçersiz kılar, bekleyen eşleştirmeleri iptal eder, dinleyiciyi ve plugin’in sahip olduğu tüneli durdurur. Siz yeniden etkinleştirene kadar kapalı kalır.',
  'emergency.confirm':
    'ACİL DURDURMA: uzaktan erişim şimdi kapatılsın mı?\n\nTüm eşleşmiş telefonlar erişimini hemen kaybeder ve tüm token’lar geçersiz olur. Siz yeniden etkinleştirene kadar uzaktan erişim kapalı kalır.',
  'emergency.done': 'Uzaktan erişim acil durdurma ile kapatıldı.',
  'closed.title': 'Uzaktan erişim kapalı',
  'closed.body':
    'Güvenlik kapatması sonrası uzaktan erişim kapalı. Kendiliğinden asla yeniden açılmaz.',
  'closed.reason.user-emergency': 'Acil durdurma',
  'closed.reason.circuit-breaker': 'Çok fazla başarısız kimlik doğrulama denemesi',
  'closed.reason.idle-timeout': 'Boşta kalma süresi',
  'closed.reason.tunnel-lost': 'Tünel bağlantısı kaybedildi',
  'closed.reason.dispose': 'Host plugin’i kapattı',
  'closed.reason.default': 'Güvenlik kapatması',
  'closed.reopen': 'Uzaktan erişimi yeniden etkinleştir',
  'closed.reopenConfirm': 'Uzaktan erişim yeniden açılsın mı? Bir telefon yeniden eşleşebilecek.',

  'control.title': 'Dinleyici',
  'control.on': 'Telefon dinleyicisi çalışıyor.',
  'control.off': 'Telefon dinleyicisi kapalı.',
  'control.enable': 'Etkinleştir',
  'control.disable': 'Kapat',
  'listener.title': 'Dinleyici durumu',
  'listener.host': 'Sunucu',
  'listener.port': 'Port',
  'listener.secure': 'HTTPS',
  'listener.lan': 'LAN erişimi',
  'listener.url': 'URL',
  'listener.access': 'Erişim',
  'listener.protocol': 'Protokol',
  'loopback.warning':
    'Telefonlar bu dinleyiciye erişemez. LAN erişimini veya bir genel bağlayıcıyı açıp yeniden eşleyin.',

  'connection.title': 'Bağlantı',
  'connection.none': 'Çalışan bir bağlantı yok. Planlamak için aşağıdan bir yöntem seçin.',
  'connection.method': 'Yöntem',
  'connection.state': 'Durum',
  'connection.ownership': 'Süreç sahipliği',
  'connection.transport': 'Taşıma',
  'connection.serviceUrl': 'Yerel servis URL’si',
  'connection.httpCheck': 'HTTP kontrolü',
  'connection.wsCheck': 'WebSocket kontrolü',
  'connection.verified': 'Doğrulandı',
  'connection.notVerified': 'Doğrulanmadı',
  'connection.publicOrigin': 'Genel origin',
  'connection.qrOrigin': 'QR origin',
  'connection.secureCookies': 'Secure çerezler',
  'connection.access': 'Cloudflare Access',
  'connection.stop': 'Genel erişimi durdur',
  'connection.stopConfirm':
    'Genel tünel durdurulsun mu? Yeniden başlatana kadar telefonlar genel URL’ye erişemez.',
  'connection.error': 'Bağlantı hatası',
  'connection.detail': 'Ayrıntı',
  'connection.running': 'Etkin bir genel bağlantı var. Yeni plan için önce durdurun.',
  'ownership.plugin': 'Bu plugin sahip',
  'ownership.external': 'Harici bağlayıcı (sahip değil)',
  'ownership.none': 'Yok',
  'transport.auto': 'Otomatik',
  'transport.quic': 'QUIC',
  'transport.http2': 'HTTP/2',

  'methods.title': 'Bağlantı yöntemi',
  'methods.intro':
    'Telefonun bu makineye nasıl erişeceğini seçin. Açıklanan planı inceleyip Başlat’a basana kadar hiçbir şey başlatılmaz.',
  'methods.loopback': 'Yalnız loopback',
  'methods.loopbackHint': 'Telefon erişimi yok. Dinleyiciyi doğrulamak için.',
  'methods.lan': 'LAN',
  'methods.lanHint': 'Aynı ağdaki bir telefon. Güvenilir bir TLS sertifikası gerektirir.',
  'methods.cloudflareQuick': 'Cloudflare Quick Tunnel',
  'methods.cloudflareQuickHint': 'Geçici trycloudflare.com URL’si, Cloudflare hesabı gerekmez.',
  'methods.cloudflareNamed': 'Cloudflare Named Tunnel (uzaktan yönetilen)',
  'methods.cloudflareNamedHint': 'Bağlayıcı token’ı ortam değişkeninden veya token dosyasından.',
  'methods.cloudflareNamedLocal': 'Cloudflare Named Tunnel (yerel yönetilen)',
  'methods.cloudflareNamedLocalHint': 'Tünel UUID’si ve kimlik JSON’u.',
  'methods.external': 'Harici bağlayıcı',
  'methods.externalHint': 'Operatörün sağladığı sabit HTTPS origin. Süreç plugin’e ait değildir.',
  'methods.ssh': 'SSH tüneli (localhost.run)',
  'methods.sshHint': 'Sistem OpenSSH istemcisiyle ters SSH yönlendirme.',
  'methods.transport': 'Taşıma',
  'methods.transportHint': 'Bağlayıcı taşıması. Varsayılan otomatiktir; ayrı bir yöntem değildir.',
  'methods.advanced': 'Gelişmiş (isteğe bağlı)',
  'methods.hostname': 'Genel hostname',
  'methods.hostnamePlaceholder': 'rc.ornek.com',
  'methods.loopbackPort': 'Sabit loopback portu',
  'methods.loopbackPortHint': '0 veya boş = boş port otomatik seçilir.',
  'methods.cloudflaredPath': 'cloudflared yolu',
  'methods.cloudflaredPathHint': 'İsteğe bağlı. Yapılandırılmış yol → PATH → doğrulanmış önbellek.',
  'methods.tokenSource': 'Bağlayıcı token kaynağı',
  'methods.tokenSourceEnv': 'Ortam değişkeni',
  'methods.tokenSourceFile': 'Token dosyası',
  'methods.tokenEnv': 'Ortam değişkeni adı',
  'methods.tokenEnvPlaceholder': 'CLOUDFLARE_TUNNEL_TOKEN',
  'methods.tokenFile': 'Token dosyası yolu',
  'methods.tokenFilePlaceholder': 'C:\\yol\\token.txt',
  'methods.tunnelId': 'Tünel UUID’si',
  'methods.tunnelIdPlaceholder': '00000000-0000-0000-0000-000000000000',
  'methods.credentialsFile': 'Kimlik JSON’u',
  'methods.credentialsFilePlaceholder': 'C:\\Users\\…\\.cloudflared\\<uuid>.json',
  'methods.publicUrl': 'Genel HTTPS origin',
  'methods.publicUrlPlaceholder': 'https://rc.ornek.com',
  'methods.sshPath': 'ssh çalıştırılabilir dosyası',
  'methods.sshPathHint': 'İsteğe bağlı. Varsayılan sistem OpenSSH istemcisi; asla indirilmez.',
  'methods.sshUser': 'SSH kullanıcısı (isteğe bağlı)',
  'methods.sshHost': 'SSH sunucusu (isteğe bağlı)',
  'methods.sshRemotePort': 'Uzak port (isteğe bağlı)',
  'methods.accessRequired': 'Sabit hostname’de Cloudflare Access zorunlu olsun',
  'methods.lanSelect': 'Arayüz adresi',
  'methods.lanNone': 'Bu makinede önerilen bir LAN adresi bulunamadı.',
  'methods.lanTlsWarning':
    'LAN eşleştirmesi güvenilir bir HTTPS sertifikası gerektirir. TLS yoksa plan başlamayı reddeder.',
  'methods.lanUnsafe': 'Link-local ve erişilemeyen diğer adresler önerilmez.',
  'methods.cloudflaredFound': 'cloudflared bulundu: {version} ({source}) · doğrulanmış: {verified}',
  'methods.cloudflaredMissing': 'cloudflared henüz kurulu değil. Plan indirmeyi önerecek.',
  'methods.cloudflaredUnsupported':
    'Bu platform için sabitlenmiş resmî cloudflared sürümü yok; yönetilen tünel başlayamaz.',
  'methods.invalidHostname': 'Geçerli bir genel hostname girin (harf, rakam, nokta, tire).',
  'methods.invalidPublicUrl': 'Geçerli bir https:// origin girin.',
  'methods.invalidPort': '0 ile 65535 arasında bir port girin.',
  'methods.lanAddressRequired': 'LAN arayüz adresini açıkça seçin.',
  'methods.tokenRequired': 'Bir ortam değişkeni veya token dosyası seçin.',
  'methods.tunnelIdRequired': 'Tünel UUID’sini girin.',
  'methods.credentialsRequired': 'Kimlik JSON yolunu girin.',
  'methods.plan': 'Planı incele',
  'methods.planBusy': 'Planlanıyor…',
  'methods.starting': 'Başlatılıyor…',

  'plan.title': 'Başlatmadan önce inceleyin',
  'plan.intro':
    'Bunlar seçilen yöntemin açıklanan tüm etkileridir. İlgili düğmeye basana kadar hiçbir şey başlatılmaz veya indirilmez.',
  'plan.expires': 'Planın süresi {seconds} sn içinde dolacak',
  'plan.expired': 'Bu planın süresi doldu. Devam etmek için yeni bir plan oluşturun.',
  'plan.replan': 'Yeni plan oluştur',
  'plan.steps': 'Açıklanan adımlar',
  'plan.noSteps': 'Host ek bir adım açıklamadı.',
  'plan.listener': 'Dinleyici',
  'plan.access': 'Dinleyici erişimi',
  'plan.host': 'Sunucu',
  'plan.port': 'Port',
  'plan.protocol': 'Protokol',
  'plan.secure': 'Secure çerezler',
  'plan.publicOrigin': 'Genel origin',
  'plan.qrOrigin': 'QR origin',
  'plan.accessRequired': 'Cloudflare Access',
  'plan.portDynamic': 'dinamik (başlangıçta seçilir)',
  'plan.install': 'İndir ve doğrula',
  'plan.installing': 'İndiriliyor ve doğrulanıyor…',
  'plan.installConfirm':
    'Sabitlenmiş resmî cloudflared sürümü indirilip resmî SHA-256 ile doğrulansın mı?',
  'plan.installDone': 'cloudflared indirildi, doğrulandı ve önbelleğe alındı.',
  'plan.installFailedTitle': 'İndirme/doğrulama başarısız',
  'plan.startFailed': 'Bağlantı başlatılamadı',
  'plan.start': 'Başlat',
  'plan.cancel': 'Vazgeç',
  'plan.download': 'İkil indirme',
  'plan.downloadIntro':
    'Sabitlenmiş resmî cloudflared sürümü yalnızca düğmeye bastığınızda indirilir ve kullanılmadan önce resmî SHA-256 ile doğrulanır.',
  'plan.downloadUnsupported':
    'Bu platform için sabitlenmiş resmî ikil yok; yönetilen tünel burada başlayamaz.',
  'plan.downloadInstalled': 'Kullanılabilir ikil bulundu — indirme gerekmiyor.',
  'plan.installedPath': 'Kurulu ikil',
  'plan.downloadInstalledDetail': '{path} ({source}, sürüm {version}, SHA-256 doğrulanmış: {verified})',
  'plan.version': 'Sürüm',
  'plan.asset': 'İkil adı',
  'plan.size': 'Boyut',
  'plan.sha256': 'SHA-256',
  'plan.releaseUrl': 'Sürüm URL’si',
  'plan.cacheDir': 'Önbellek dizini',
  'plan.provider': 'Sağlayıcı',

  'step.kind.listener': 'Dinleyici',
  'step.kind.tunnel': 'Tünel',
  'step.kind.download': 'İndirme',
  'step.kind.tls': 'TLS',
  'step.kind.access': 'Cloudflare Access',
  'step.kind.origin': 'Genel origin',
  'step.kind.warning': 'Uyarı',
  'step.kind.security': 'Güvenlik',
  'step.param.address': 'Adres',
  'step.param.host': 'Sunucu',
  'step.param.port': 'Port',
  'step.param.protocol': 'Protokol',
  'step.param.url': 'URL',
  'step.param.origin': 'Origin',
  'step.param.hostname': 'Hostname',
  'step.param.provider': 'Sağlayıcı',
  'step.param.version': 'Sürüm',
  'step.param.asset': 'İkil adı',
  'step.param.sha256': 'SHA-256',
  'step.param.sizeBytes': 'Boyut',
  'step.param.size': 'Boyut',
  'step.param.secure': 'Secure',
  'step.param.access': 'Erişim',
  'step.param.transport': 'Taşıma',
  'step.param.serviceUrl': 'Servis URL’si',
  'step.param.dynamic': 'Dinamik port',
  'step.param.fixedPort': 'Sabit port',
  'step.param.cacheDirectory': 'Önbellek dizini',
  'step.param.releaseUrl': 'Sürüm URL’si',
  'step.param.detail': 'Ayrıntı',

  'pair.title': 'Cihaz eşleştir',
  'pair.create': 'Cihaz eşle',
  'pair.instructions': 'QR kodunu telefonunuzla okutun veya URL’yi telefonda açın.',
  'pair.enableFirst': 'Telefon eşlemeden önce Uzaktan Kontrol’ü etkinleştirin.',
  'pair.code': 'Eşleşme kodu',
  'pair.url': 'Eşleşme URL’si',
  'pair.qrAlt': 'Eşleşme QR kodu',
  'pair.qrPending': 'QR kodu henüz hazır değil.',
  'pair.expires': 'Kalan: {seconds} sn',
  'pair.expired': 'Bu eşleşme isteğinin süresi doldu.',
  'pair.waiting': 'Telefonun bağlanması bekleniyor…',
  'pair.dismiss': 'Gizle',
  'pair.securityClosed': 'Uzaktan erişim kapalı. Eşleştirmeden önce yeniden etkinleştirin.',
  'pair.selectionRequired':
    'Birden çok cihaz kayıtlı. Telefon eşlemeden önce etkin cihazı seçin.',
  'pair.activeDeviceLocked':
    'Şu anda başka bir cihaz etkin. Yeni telefon eşlemeden önce o cihazın kilidini bırakın veya eşleşmesini kaldırın (tek cihaz kilidi).',
  'pair.tlsRequired':
    'LAN eşleştirmesi güvenilir bir HTTPS sertifikası gerektirir. Önce dinleyicide TLS’i düzeltin.',

  'devices.title': 'Eşleşmiş cihazlar',
  'devices.empty': 'Eşleşmiş cihaz yok.',
  'devices.label': 'Cihaz',
  'devices.platform': 'Platform',
  'devices.lastSeen': 'Son görülme',
  'devices.active': 'Etkin',
  'devices.revoke': 'Kaldır',
  'devices.revokeAll': 'Tümünü kes',
  'devices.activate': 'Etkin yap',
  'devices.release': 'Kilidi bırak',
  'devices.confirmRevoke': 'Bu cihaz kaldırılsın mı? Çerezleri hemen geçersiz olur.',
  'devices.confirmRevokeActive':
    'ETKİN cihaz kaldırılsın mı? Uzaktan erişim hemen biter ve çerezleri geçersiz olur.',
  'devices.confirmRevokeAll': 'Eşleşmiş tüm cihazlar kaldırılsın mı?',
  'devices.activateConfirm':
    '“{device}” etkin cihaz yapılsın mı? Başka bir etkin cihazın uzaktan erişimi kesilir.',
  'devices.actions': 'İşlemler',

  'lock.title': 'Tek etkin cihaz',
  'lock.state': 'Kilit durumu',
  'lock.state.none': 'Etkin cihaz yok',
  'lock.state.active': 'Etkin',
  'lock.state.selection-required': 'Seçim gerekli',
  'lock.state.released': 'Bırakıldı',
  'lock.activeDevice': 'Etkin cihaz',
  'lock.since': 'Etkinleşme',
  'lock.lastActivity': 'Son etkinlik',
  'lock.idleExpires': 'Boşta kapanış',
  'lock.idleTimeout': 'Boşta kalma süresi',
  'lock.registered': 'Kayıtlı cihazlar',
  'lock.needsSelection':
    'Birden çok cihaz kayıtlı. Etkin cihazı açıkça seçin — plugin asla otomatik seçmez.',
  'lock.noActive':
    'Kilidi tutan cihaz yok. Bir cihazı etkinleştirene kadar uzaktan erişim engelli.',
  'lock.activate': 'Etkin yap',
  'lock.release': 'Kilidi bırak',
  'lock.activateConfirm':
    '“{device}” etkin cihaz yapılsın mı? Başka bir etkin cihazın uzaktan erişimi kesilir.',
  'lock.releaseConfirm':
    'Etkin cihaz kilidi bırakılsın mı? Uzaktan erişim eşleşmiş kalır ama bir cihaz etkinleştirilene kadar engellenir.',
  'lock.noticeSecondDevice':
    'İkinci cihaz denemesi tek cihaz kilidi tarafından reddedildi ({time}).',
  'lock.noticeSecondDeviceDetail': 'Ayrıntı: {detail}',
  'lock.minutesValue': '{minutes} dk',

  'security.title': 'Güvenlik',
  'security.closed': 'Uzaktan erişim kapalı',
  'security.reason': 'Neden',
  'security.circuitBreaker': 'Hata devre kesici',
  'security.breakerOpen': 'Açık — uzaktan erişim kapatıldı',
  'security.breakerClosed': 'Kapalı',
  'security.failures': 'Bu oturumdaki hatalar',
  'security.blocked': 'Geçici engelli istemciler',
  'security.window': 'Hata penceresi',
  'security.ban': 'Geçici engel',
  'security.breakerThreshold': 'Devre kesici eşiği',
  'security.epoch': 'Token iptal epoch’u',
  'security.idleTimeout': 'Boşta kalma süresi',
  'security.windowValue': '{seconds} sn',
  'security.banValue': '{minutes} dk',
  'security.notifications': 'Güvenlik bildirimleri',

  'audit.title': 'Denetim kaydı',
  'audit.empty': 'Henüz denetim kaydı yok.',
  'audit.latest': 'En yeniden eskiye · son {count}',
  'audit.time': 'Zaman',
  'audit.kind': 'Tür',
  'audit.operation': 'İşlem',
  'audit.result': 'Sonuç',
  'audit.device': 'Cihaz',
  'audit.ip': 'IP',
  'audit.userAgent': 'User agent',
  'audit.detail': 'Ayrıntı',
  'audit.kind.enable': 'Etkinleştirme',
  'audit.kind.disable': 'Kapatma',
  'audit.kind.pair': 'Eşleştirme',
  'audit.kind.approve': 'Onay',
  'audit.kind.deny': 'Ret',
  'audit.kind.revoke': 'Kaldırma',
  'audit.kind.rpc': 'Uzak çağrı',
  'audit.kind.answer': 'Onay yanıtı',
  'audit.kind.tunnel': 'Tünel',
  'audit.kind.security': 'Güvenlik',
  'audit.kind.device-lock': 'Cihaz kilidi',
  'audit.result.ok': 'başarılı',
  'audit.result.rejected': 'reddedildi',
  'audit.result.failed': 'başarısız',
  'audit.result.notice': 'bildirim',

  'tunnel.title': 'Tünel',
  'tunnel.disabled': 'Tünel kapalı.',
  'tunnel.mode': 'Mod',
  'tunnel.state': 'Durum',
  'tunnel.url': 'Genel URL',
  'tunnel.starting': 'Başlatılıyor…',
  'tunnel.down': 'Kapalı',
  'tunnel.off': 'Kapalı',
  'tunnel.missingBinary': 'cloudflared bulunamadı',
  'tunnel.temporary': 'Geçici URL — URL değişince cihazlar yeniden eşleşmeli.',
  'tunnel.error': 'Tünel hatası',

  'info.title': 'Sürüm',
  'info.dshRelease': 'DSH sürümü',
  'info.pluginVersion': 'Plugin sürümü',
  'pending.title': 'Yeni cihaz',
  'pending.body': 'bu DeepSeek Harness oturumuna bağlanmak istiyor.',
  'pending.platform': 'Platform',
  'pending.remaining': '{seconds} sn içinde sona erer',
  'pending.approve': 'Onayla',
  'pending.deny': 'Reddet',
  'pending.more': '{count} cihaz isteği daha bekliyor.',
  'pending.approveFailed': 'Cihaz onaylanamadı',
  'error.noStatus': 'Henüz durum yok.',
  'error.code.DEVICE_LOCKED':
    'Başka bir cihaz etkin. Yeni telefon eşlemeden önce etkin cihazın kilidini bırakın veya eşleşmesini kaldırın.',
  'error.code.SECURITY_CLOSED': 'Uzaktan erişim güvenlik kapatması sonrası kapalı.',
  'error.code.TLS_REQUIRED': 'Bu LAN adresi güvenilir bir HTTPS sertifikası gerektiriyor.',
  'error.code.INSTALL_REQUIRED': 'Sağlayıcı ikili dosyası önce kurulmalı.',
  'error.code.SSH_MISSING': 'OpenSSH istemcisi bulunamadı; asla indirilmez.',
  'error.code.CHECKSUM_MISMATCH': 'İndirilen ikil resmî SHA-256 ile eşleşmedi.',
  'error.code.UNSUPPORTED_PLATFORM': 'Bu platform için sabitlenmiş resmî ikil yok.',
  'error.code.CONSENT_REQUIRED': 'Planın süresi doldu veya onaylanmadı; yeni plan oluşturun.',
  'error.code.RATE_LIMITED': 'Çok fazla deneme; kısa süre sonra tekrar deneyin.',
  'error.code.NOT_ALLOWED': 'Mevcut durumda izin verilmiyor.',
  'error.code.ACCESS_REQUIRED': 'Cloudflare Access doğrulaması gerekli.',
  'error.code.DEVICE_LIMIT': 'Eşleşmiş cihaz sınırına ulaşıldı.',
  'error.code.PAIRING_INVALID': 'Eşleşme talebi geçersiz veya kullanılmış.',
  'error.code.PAIRING_EXPIRED': 'Eşleşme isteğinin süresi doldu.',
  'error.code.PAIRING_DENIED': 'Eşleşme isteği masaüstünde reddedildi.',
}

const DICTIONARIES: Record<string, Record<string, string>> = { en, tr }

/** Translator bound to this plugin namespace. */
type TFn = (key: MessageKey, params?: Record<string, string | number>) => string

/* -------------------------------------------------------------------------- */
/* Admin fetch (same-origin DSH cookie; CSRF header on every mutation)        */
/* -------------------------------------------------------------------------- */

interface RcFailure {
  code: string
  message: string
}

class AdminError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'AdminError'
    this.code = code
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function failureFromPayload(payload: unknown): RcFailure | null {
  if (!isRecord(payload) || payload['ok'] !== false) return null
  const error = payload['error']
  if (!isRecord(error)) return null
  const code = typeof error['code'] === 'string' ? error['code'] : 'INTERNAL'
  const message = typeof error['message'] === 'string' ? error['message'] : code
  return { code, message }
}

function toFailure(error: unknown): RcFailure {
  if (error instanceof AdminError) return { code: error.code, message: error.message }
  if (error instanceof Error) return { code: 'INTERNAL', message: error.message }
  return { code: 'INTERNAL', message: String(error) }
}

async function adminRequest<T>(
  suffix: string,
  method: 'GET' | 'POST',
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json' }
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers,
  }
  if (method === 'POST') {
    headers['content-type'] = 'application/json'
    headers[RC_CSRF_HEADER] = '1'
    init.body = JSON.stringify(body ?? {})
  }
  const response = await fetch(`${RC_ADMIN_PATH}/${suffix}`, init)
  const text = await response.text()
  let payload: unknown = null
  if (text.length > 0) {
    try {
      payload = JSON.parse(text) as unknown
    } catch {
      payload = null
    }
  }
  if (!response.ok) {
    const failure = failureFromPayload(payload) ?? {
      code: `HTTP_${response.status}`,
      message: response.statusText.length > 0 ? response.statusText : 'request failed',
    }
    throw new AdminError(failure.code, failure.message)
  }
  return payload as T
}

function adminGet<T>(suffix: string): Promise<T> {
  return adminRequest<T>(suffix, 'GET')
}

function adminPost<T>(suffix: string, body: unknown = {}): Promise<T> {
  return adminRequest<T>(suffix, 'POST', body)
}

/* -------------------------------------------------------------------------- */
/* Pairing watch: the overlay only polls the Host while a pairing is possible */
/* -------------------------------------------------------------------------- */

let pendingWatchUntil = 0
const watchListeners = new Set<() => void>()

/** Called after `pair/create` so the overlay starts polling `/pending` now. */
function notifyPairingCreated(expiresAt: number): void {
  const until = Number.isFinite(expiresAt) ? expiresAt : Date.now() + DEFAULT_PAIRING_TTL_MS
  if (until > pendingWatchUntil) pendingWatchUntil = until
  for (const listener of Array.from(watchListeners)) {
    try {
      listener()
    } catch {
      // a listener must never break the panel action that triggered it
    }
  }
}

function subscribePendingWatch(listener: () => void): () => void {
  watchListeners.add(listener)
  return () => {
    watchListeners.delete(listener)
  }
}

function shouldPollPending(pendingCount: number): boolean {
  return pendingCount > 0 || Date.now() < pendingWatchUntil
}

function claimedPairings(pairings: readonly PairingView[]): PairingView[] {
  return pairings.filter(
    (pairing) =>
      pairing.state === 'claimed' &&
      typeof pairing.claimId === 'string' &&
      pairing.claimId.length > 0,
  )
}

/* -------------------------------------------------------------------------- */
/* Small helpers                                                              */
/* -------------------------------------------------------------------------- */

function remainingSeconds(expiresAt: number, now: number): number {
  return Math.max(0, Math.ceil((expiresAt - now) / 1_000))
}

function formatTimestamp(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '—'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return '—'
  }
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

function formatMinutes(minutes: number): string {
  return Number.isFinite(minutes) && minutes > 0 ? String(Math.round(minutes)) : '—'
}

function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '—'
  const totalShelonds = Math.ceil(ms / 1_000)
  if (totalShelonds < 60) return `${totalShelonds}s`
  const minutes = Math.floor(totalShelonds / 60)
  const seconds = totalShelonds % 60
  return seconds === 0 ? `${minutes} min` : `${minutes} min ${seconds}s`
}

function shortId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}…` : value
}

/**
 * Only a Host-produced `svg` element may become an image URL. Encoding the
 * whole document keeps the string out of the DOM as markup (no innerHTML); the
 * `<img>` element cannot execute script even in hostile SVG.
 */
function svgDataUrl(svg: string | null | undefined): string | null {
  if (typeof svg !== 'string') return null
  const trimmed = svg.trim()
  if (!/^<svg[\s>]/i.test(trimmed)) return null
  return `data:image/svg+xml;utf8,${encodeURIComponent(trimmed)}`
}

function confirmAction(message: string): boolean {
  const confirmFunction = globalThis.confirm
  if (typeof confirmFunction !== 'function') return true
  try {
    return confirmFunction(message)
  } catch {
    return true
  }
}

function errorText(failure: RcFailure): string {
  return `${failure.code}: ${failure.message}`
}

/** Localized copy for the canonical Host error codes (falls back to the Host text). */
const ERROR_MESSAGE_KEYS = {
  DEVICE_LOCKED: 'error.code.DEVICE_LOCKED',
  SECURITY_CLOSED: 'error.code.SECURITY_CLOSED',
  TLS_REQUIRED: 'error.code.TLS_REQUIRED',
  INSTALL_REQUIRED: 'error.code.INSTALL_REQUIRED',
  SSH_MISSING: 'error.code.SSH_MISSING',
  CHECKSUM_MISMATCH: 'error.code.CHECKSUM_MISMATCH',
  UNSUPPORTED_PLATFORM: 'error.code.UNSUPPORTED_PLATFORM',
  CONSENT_REQUIRED: 'error.code.CONSENT_REQUIRED',
  RATE_LIMITED: 'error.code.RATE_LIMITED',
  NOT_ALLOWED: 'error.code.NOT_ALLOWED',
  ACCESS_REQUIRED: 'error.code.ACCESS_REQUIRED',
  DEVICE_LIMIT: 'error.code.DEVICE_LIMIT',
  PAIRING_INVALID: 'error.code.PAIRING_INVALID',
  PAIRING_EXPIRED: 'error.code.PAIRING_EXPIRED',
  PAIRING_DENIED: 'error.code.PAIRING_DENIED',
} as const satisfies Record<string, MessageKey>

function localizedFailure(t: TFn, failure: RcFailure): string {
  const key = ERROR_MESSAGE_KEYS[failure.code as keyof typeof ERROR_MESSAGE_KEYS]
  if (key === undefined) return errorText(failure)
  return `${failure.code}: ${t(key)}`
}

/* -------------------------------------------------------------------------- */
/* Labels for contract enums                                                  */
/* -------------------------------------------------------------------------- */

const METHOD_LABEL_KEYS: Record<ConnectionMethod, MessageKey> = {
  loopback: 'methods.loopback',
  lan: 'methods.lan',
  'cloudflare-quick': 'methods.cloudflareQuick',
  'cloudflare-named': 'methods.cloudflareNamed',
  'cloudflare-named-local': 'methods.cloudflareNamedLocal',
  external: 'methods.external',
  ssh: 'methods.ssh',
}

function methodLabel(method: ConnectionMethod, t: TFn): string {
  return t(METHOD_LABEL_KEYS[method])
}

function methodSelection(method: ConnectionMethod): ConnectionMethod {
  return method
}

interface TunnelStateLabel {
  key: MessageKey
  tone: 'ready' | 'warn' | 'error' | 'info' | 'muted'
}

function tunnelStateLabel(state: TunnelState, tunnel: TunnelStatus, t: TFn): TunnelStateLabel {
  switch (state) {
    case 'ready':
    case 'up':
      return { key: 'state.ready', tone: 'ready' }
    case 'starting':
      return { key: 'state.starting', tone: 'info' }
    case 'connected-unverified':
      return { key: 'state.unverified', tone: 'warn' }
    case 'access-required':
      return { key: 'state.accessRequired', tone: 'warn' }
    case 'mismatch':
      return { key: 'state.mismatch', tone: 'error' }
    case 'missing-config':
      return { key: 'state.missingConfig', tone: 'error' }
    case 'missing-binary':
      return { key: 'state.missingBinary', tone: 'error' }
    case 'security-closed':
      return { key: 'state.closed', tone: 'error' }
    case 'down':
      return { key: 'state.down', tone: 'error' }
    case 'off':
    default:
      return { key: tunnel.enabled ? 'state.off' : 'tunnel.disabled', tone: 'muted' }
  }
}

const OWNERSHIP_LABEL_KEYS = {
  plugin: 'ownership.plugin',
  external: 'ownership.external',
  none: 'ownership.none',
} as const

const TRANSPORT_LABEL_KEYS: Record<TunnelTransport, MessageKey> = {
  auto: 'transport.auto',
  quic: 'transport.quic',
  http2: 'transport.http2',
}

const STEP_KIND_KEYS: Record<ConnectionPlanStep['kind'], MessageKey> = {
  listener: 'step.kind.listener',
  tunnel: 'step.kind.tunnel',
  download: 'step.kind.download',
  tls: 'step.kind.tls',
  access: 'step.kind.access',
  origin: 'step.kind.origin',
  warning: 'step.kind.warning',
  security: 'step.kind.security',
}

const STEP_PARAM_KEYS: Record<string, MessageKey> = {
  address: 'step.param.address',
  host: 'step.param.host',
  port: 'step.param.port',
  protocol: 'step.param.protocol',
  url: 'step.param.url',
  origin: 'step.param.origin',
  hostname: 'step.param.hostname',
  provider: 'step.param.provider',
  version: 'step.param.version',
  asset: 'step.param.asset',
  sha256: 'step.param.sha256',
  sizeBytes: 'step.param.sizeBytes',
  size: 'step.param.size',
  secure: 'step.param.secure',
  access: 'step.param.access',
  transport: 'step.param.transport',
  serviceUrl: 'step.param.serviceUrl',
  dynamic: 'step.param.dynamic',
  fixedPort: 'step.param.fixedPort',
  cacheDirectory: 'step.param.cacheDirectory',
  releaseUrl: 'step.param.releaseUrl',
  detail: 'step.param.detail',
}

const AUDIT_KIND_KEYS: Record<string, MessageKey> = {
  enable: 'audit.kind.enable',
  disable: 'audit.kind.disable',
  pair: 'audit.kind.pair',
  approve: 'audit.kind.approve',
  deny: 'audit.kind.deny',
  revoke: 'audit.kind.revoke',
  rpc: 'audit.kind.rpc',
  answer: 'audit.kind.answer',
  tunnel: 'audit.kind.tunnel',
  security: 'audit.kind.security',
  'device-lock': 'audit.kind.device-lock',
}

const AUDIT_RESULT_KEYS: Record<AuditEntryView['result'], MessageKey> = {
  ok: 'audit.result.ok',
  rejected: 'audit.result.rejected',
  failed: 'audit.result.failed',
  notice: 'audit.result.notice',
}

const LOCK_STATE_KEYS: Record<string, MessageKey> = {
  none: 'lock.state.none',
  active: 'lock.state.active',
  'selection-required': 'lock.state.selection-required',
  released: 'lock.state.released',
}

const CLOSED_REASON_KEYS: Record<string, MessageKey> = {
  'user-emergency': 'closed.reason.user-emergency',
  'circuit-breaker': 'closed.reason.circuit-breaker',
  'idle-timeout': 'closed.reason.idle-timeout',
  'tunnel-lost': 'closed.reason.tunnel-lost',
  dispose: 'closed.reason.dispose',
}

/* -------------------------------------------------------------------------- */
/* Fallbacks when the Host does not expose the new connection view yet        */
/* -------------------------------------------------------------------------- */

function fallbackMethod(status: AdminStatusEnvelope): ConnectionMethod {
  switch (status.tunnel.mode) {
    case 'quick':
      return 'cloudflare-quick'
    case 'named':
      return 'cloudflare-named'
    case 'named-local':
      return 'cloudflare-named-local'
    case 'external':
      return 'external'
    case 'ssh':
      return 'ssh'
    default:
      return status.listener.lan ? 'lan' : 'loopback'
  }
}

function effectiveConnection(status: AdminStatusEnvelope): ConnectionStateView {
  if (status.connection !== undefined && status.connection !== null) return status.connection
  const listener: ListenerStatus = status.listener
  const publicOrigin = status.tunnel.url ?? status.publicUrl ?? null
  return {
    method: fallbackMethod(status),
    listener,
    publicOrigin,
    qrOrigin: publicOrigin,
    hostAuthorities: [],
    secureCookies: listener.secure,
    accessRequired: false,
    tunnel: status.tunnel,
  }
}

function isPublicExposed(connection: ConnectionStateView): boolean {
  const state = connection.tunnel.state
  if (connection.publicOrigin !== null && connection.publicOrigin.length > 0) return true
  return state !== 'off' && state !== 'missing-config' && state !== 'missing-binary'
}

function publicExposureActive(status: AdminStatusEnvelope): boolean {
  return isPublicExposed(effectiveConnection(status))
}

/* -------------------------------------------------------------------------- */
/* Presentation primitives (plain elements + namespaced CSS)                  */
/* -------------------------------------------------------------------------- */

interface AlertAction {
  label: string
  onClick: () => void
}

function alertBlock(tone: 'error' | 'warn' | 'info', text: string, action?: AlertAction): ReactElement {
  const children: ReactNode[] = [h('span', { className: 'dsh-rc-alert-text', key: 'text' }, text)]
  if (action !== undefined) {
    children.push(
      h(
        'button',
        {
          type: 'button',
          className: 'dsh-rc-btn dsh-rc-btn-small',
          key: 'action',
          onClick: action.onClick,
        },
        action.label,
      ),
    )
  }
  return h('div', { className: 'dsh-rc-alert', 'data-tone': tone, role: 'alert' }, children)
}

function kvRow(label: string, value: string, key?: string): ReactElement {
  return h(
    'div',
    { className: 'dsh-rc-kv-row', 'data-kv': key ?? null, key: key ?? label },
    h('span', { className: 'dsh-rc-kv-key' }, label),
    h('span', { className: 'dsh-rc-kv-value' }, value),
  )
}

function card(title: string, key: string, children: ReactNode[]): ReactElement {
  return h(
    'div',
    { className: 'dsh-rc-card', key },
    h('h3', { className: 'dsh-rc-card-title' }, title),
    ...children,
  )
}

function iconButton(
  label: string,
  onClick: () => void,
  options: { disabled?: boolean; variant?: 'primary' | 'danger' | 'danger-solid'; small?: boolean; key?: string } = {},
): ReactElement {
  const className = `dsh-rc-btn${options.small === true ? ' dsh-rc-btn-small' : ''}`
  const attrs: Record<string, unknown> = {
    type: 'button',
    className,
    onClick,
    key: options.key ?? label,
    disabled: options.disabled === true,
  }
  if (options.variant !== undefined) attrs['data-variant'] = options.variant
  return h('button', attrs, label)
}

/* -------------------------------------------------------------------------- */
/* Field primitives (controlled inputs for the connection form)               */
/* -------------------------------------------------------------------------- */

interface FieldProps {
  label: string
  value: string
  onChange: (value: string) => void
  placeholder?: string
  hint?: string
  type?: 'text' | 'number'
  id: string
  disabled?: boolean
}

function textField(props: FieldProps): ReactElement {
  const children: ReactNode[] = [
    h('label', { className: 'dsh-rc-field-label', htmlFor: props.id, key: 'label' }, props.label),
    h('input', {
      id: props.id,
      className: 'dsh-rc-input',
      type: props.type ?? 'text',
      value: props.value,
      placeholder: props.placeholder,
      disabled: props.disabled === true,
      spellCheck: false,
      autoComplete: 'off',
      key: 'input',
      onChange: (event: { target: { value: string } }) => props.onChange(event.target.value),
    }),
  ]
  if (props.hint !== undefined) {
    children.push(h('p', { className: 'dsh-rc-muted', key: 'hint' }, props.hint))
  }
  return h('div', { className: 'dsh-rc-field', key: props.id }, children)
}

function selectField(
  id: string,
  label: string,
  value: string,
  options: Array<{ value: string; label: string }>,
  onChange: (value: string) => void,
  disabled = false,
  hint?: string,
): ReactElement {
  const children: ReactNode[] = [
    h('label', { className: 'dsh-rc-field-label', htmlFor: id, key: 'label' }, label),
    h(
      'select',
      {
        id,
        className: 'dsh-rc-input',
        value,
        disabled,
        key: 'select',
        onChange: (event: { target: { value: string } }) => onChange(event.target.value),
      },
      options.map((option) =>
        h('option', { value: option.value, key: option.value }, option.label),
      ),
    ),
  ]
  if (hint !== undefined) children.push(h('p', { className: 'dsh-rc-muted', key: 'hint' }, hint))
  return h('div', { className: 'dsh-rc-field', key: id }, children)
}

function checkboxField(
  id: string,
  label: string,
  checked: boolean,
  onChange: (checked: boolean) => void,
  disabled = false,
): ReactElement {
  return h(
    'div',
    { className: 'dsh-rc-checkbox', key: id },
    h('input', {
      id,
      type: 'checkbox',
      checked,
      disabled,
      key: 'box',
      onChange: (event: { target: { checked: boolean } }) => onChange(event.target.checked),
    }),
    h('label', { htmlFor: id, key: 'label' }, label),
  )
}

/* -------------------------------------------------------------------------- */
/* Connection form model                                                      */
/* -------------------------------------------------------------------------- */

interface ConnectionForm {
  method: ConnectionMethod
  lanAddress: string
  loopbackPort: string
  transport: TunnelTransport
  hostname: string
  tokenSource: 'env' | 'file'
  tokenEnv: string
  tokenFile: string
  cloudflaredPath: string
  tunnelId: string
  credentialsFile: string
  publicUrl: string
  sshPath: string
  sshUser: string
  sshHost: string
  sshRemotePort: string
  accessRequired: boolean
}

function initialForm(status: AdminStatusEnvelope): ConnectionForm {
  const method = status.connection?.method ?? fallbackMethod(status)
  const interfaces = status.networkInterfaces ?? []
  const recommended = interfaces.find((entry) => entry.recommended === true)
  return {
    method,
    lanAddress: recommended?.address ?? '',
    loopbackPort: '',
    transport: 'auto',
    hostname: '',
    tokenSource: 'env',
    tokenEnv: 'CLOUDFLARE_TUNNEL_TOKEN',
    tokenFile: '',
    cloudflaredPath: '',
    tunnelId: '',
    credentialsFile: '',
    publicUrl: '',
    sshPath: '',
    sshUser: '',
    sshHost: '',
    sshRemotePort: '',
    accessRequired: false,
  }
}

const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/

function trimmed(value: string): string {
  return value.trim()
}

function optionalPort(value: string): number | undefined {
  const text = trimmed(value)
  if (text.length === 0) return undefined
  const parsed = Number(text)
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65_535) return undefined
  return parsed
}

type SelectionResult =
  | { ok: true; selection: ConnectionSelection }
  | { ok: false; errorKey: MessageKey }

/**
 * Translate the panel form into the frozen `ConnectionSelection` union. Pure
 * logic (no DOM): the build script type-checks it and the panel shows one
 * precise validation message instead of sending a half-valid selection.
 */
function buildSelection(form: ConnectionForm): SelectionResult {
  const cloudflaredPath = trimmed(form.cloudflaredPath)
  const transport = form.transport
  switch (form.method) {
    case 'loopback':
      return { ok: true, selection: { method: 'loopback' } }
    case 'lan': {
      if (trimmed(form.lanAddress).length === 0) {
        return { ok: false, errorKey: 'methods.lanAddressRequired' }
      }
      return { ok: true, selection: { method: 'lan', lanAddress: trimmed(form.lanAddress) } }
    }
    case 'cloudflare-quick': {
      const selection: ConnectionSelection = { method: 'cloudflare-quick', transport }
      if (cloudflaredPath.length > 0) selection.cloudflaredPath = cloudflaredPath
      return { ok: true, selection }
    }
    case 'cloudflare-named': {
      const hostname = trimmed(form.hostname).toLowerCase()
      if (!HOSTNAME_PATTERN.test(hostname)) return { ok: false, errorKey: 'methods.invalidHostname' }
      const selection: ConnectionSelection = {
        method: 'cloudflare-named',
        hostname,
        transport,
      }
      if (form.tokenSource === 'env') {
        const tokenEnv = trimmed(form.tokenEnv)
        if (tokenEnv.length === 0) return { ok: false, errorKey: 'methods.tokenRequired' }
        if (!ENV_NAME_PATTERN.test(tokenEnv)) return { ok: false, errorKey: 'methods.tokenRequired' }
        selection.tokenEnv = tokenEnv
      } else {
        const tokenFile = trimmed(form.tokenFile)
        if (tokenFile.length === 0) return { ok: false, errorKey: 'methods.tokenRequired' }
        selection.tokenFile = tokenFile
      }
      if (cloudflaredPath.length > 0) selection.cloudflaredPath = cloudflaredPath
      const namedPort = optionalPort(form.loopbackPort)
      if (trimmed(form.loopbackPort).length > 0 && namedPort === undefined) {
        return { ok: false, errorKey: 'methods.invalidPort' }
      }
      // A remotely-managed tunnel's public route is configured on Cloudflare and
      // targets a fixed local port; allow the operator to disclose it explicitly.
      if (namedPort !== undefined) selection.loopbackPort = namedPort
      if (form.accessRequired) selection.accessRequired = true
      return { ok: true, selection }
    }
    case 'cloudflare-named-local': {
      const hostname = trimmed(form.hostname).toLowerCase()
      if (!HOSTNAME_PATTERN.test(hostname)) return { ok: false, errorKey: 'methods.invalidHostname' }
      const tunnelId = trimmed(form.tunnelId)
      if (!UUID_PATTERN.test(tunnelId)) return { ok: false, errorKey: 'methods.tunnelIdRequired' }
      const credentialsFile = trimmed(form.credentialsFile)
      if (credentialsFile.length === 0) return { ok: false, errorKey: 'methods.credentialsRequired' }
      const selection: ConnectionSelection = {
        method: 'cloudflare-named-local',
        hostname,
        tunnelId,
        credentialsFile,
        transport,
      }
      if (cloudflaredPath.length > 0) selection.cloudflaredPath = cloudflaredPath
      if (form.accessRequired) selection.accessRequired = true
      return { ok: true, selection }
    }
    case 'external': {
      const publicUrl = trimmed(form.publicUrl)
      let parsed: URL
      try {
        parsed = new URL(publicUrl)
      } catch {
        return { ok: false, errorKey: 'methods.invalidPublicUrl' }
      }
      if (parsed.protocol !== 'https:' || parsed.origin !== publicUrl.replace(/\/$/, '')) {
        return { ok: false, errorKey: 'methods.invalidPublicUrl' }
      }
      const selection: ConnectionSelection = { method: 'external', publicUrl: parsed.origin }
      const port = optionalPort(form.loopbackPort)
      if (trimmed(form.loopbackPort).length > 0 && port === undefined) {
        return { ok: false, errorKey: 'methods.invalidPort' }
      }
      if (port !== undefined) selection.loopbackPort = port
      if (form.accessRequired) selection.accessRequired = true
      return { ok: true, selection }
    }
    case 'ssh': {
      const selection: ConnectionSelection = { method: 'ssh' }
      const sshPath = trimmed(form.sshPath)
      if (sshPath.length > 0) selection.sshPath = sshPath
      const sshUser = trimmed(form.sshUser)
      if (sshUser.length > 0) selection.sshUser = sshUser
      const sshHost = trimmed(form.sshHost)
      if (sshHost.length > 0) selection.sshHost = sshHost
      const remotePort = optionalPort(form.sshRemotePort)
      if (trimmed(form.sshRemotePort).length > 0 && remotePort === undefined) {
        return { ok: false, errorKey: 'methods.invalidPort' }
      }
      if (remotePort !== undefined) selection.sshRemotePort = remotePort
      return { ok: true, selection }
    }
    default:
      return { ok: false, errorKey: 'methods.loopback' }
  }
}

/* -------------------------------------------------------------------------- */
/* Status badge                                                               */
/* -------------------------------------------------------------------------- */

function statusBadge(
  status: AdminStatusEnvelope,
  t: TFn,
): { tone: string; label: string } {
  const security = status.security
  if (security !== undefined && security !== null && security.closed) {
    return { tone: 'closed', label: t('state.closed') }
  }
  if (!status.enabled) return { tone: 'off', label: t('state.off') }
  const connection = effectiveConnection(status)
  const tunnel = connection.tunnel
  // An external "Stop" closes the listener and revokes the public origin while the
  // logical remote-control session stays enabled: report it as stopped, not as a
  // still-listening loopback connection.
  if (connection.listener.state === 'off' && tunnel.state === 'off' && connection.publicOrigin === null) {
    return { tone: 'off', label: t('state.off') }
  }
  if (connection.publicOrigin !== null || tunnel.state !== 'off') {
    const label = tunnelStateLabel(tunnel.state, tunnel, t)
    const toneMap: Record<TunnelStateLabel['tone'], string> = {
      ready: 'ready',
      warn: 'warn',
      error: 'warn',
      info: 'info',
      muted: 'off',
    }
    return { tone: toneMap[label.tone], label: t(label.key) }
  }
  if (connection.listener.lan) return { tone: 'lan', label: t('state.lan') }
  return { tone: 'loopback', label: t('state.loopback') }
}

/* -------------------------------------------------------------------------- */
/* Connection status card (single computed runtime state)                     */
/* -------------------------------------------------------------------------- */

function formatVerified(verified: boolean | undefined, t: TFn): string {
  if (verified === true) return t('connection.verified')
  if (verified === false) return t('connection.notVerified')
  return t('value.none')
}

function renderConnectionStatus(
  t: TFn,
  status: AdminStatusEnvelope,
  onStop: () => void,
  busy: boolean,
): ReactElement {
  const connection = effectiveConnection(status)
  const tunnel = connection.tunnel
  const listener = connection.listener
  const stateLabel = tunnelStateLabel(tunnel.state, tunnel, t)
  const toneMap: Record<string, string> = {
    ready: 'ready',
    warn: 'warn',
    error: 'closed',
    info: 'info',
    muted: 'off',
  }
  const heroTone = toneMap[stateLabel.tone] ?? 'off'
  const stateChipTone = heroTone === 'ready' ? 'ok' : heroTone === 'info' ? 'brand' : heroTone === 'off' ? '' : 'warn'
  const chips: ReactNode[] = [
    h('span', { className: 'dsh-rc-chip', 'data-tone': 'brand', key: 'method' }, methodLabel(connection.method, t)),
  ]
  if (stateChipTone !== '') {
    chips.push(h('span', { className: 'dsh-rc-chip', 'data-tone': stateChipTone, key: 'state' }, t(stateLabel.key)))
  }
  if (tunnel.ownership !== undefined && tunnel.ownership !== 'none') {
    chips.push(
      h('span', { className: 'dsh-rc-chip', key: 'ownership' }, t(OWNERSHIP_LABEL_KEYS[tunnel.ownership])),
    )
  }
  if (tunnel.transport !== undefined) {
    chips.push(
      h('span', { className: 'dsh-rc-chip', key: 'transport' }, t(TRANSPORT_LABEL_KEYS[tunnel.transport])),
    )
  }
  if (connection.publicOrigin !== null) {
    chips.push(
      h('span', { className: 'dsh-rc-chip', 'data-tone': 'brand', key: 'origin' }, connection.publicOrigin),
    )
  }
  if (connection.secureCookies) {
    chips.push(
      h(
        'span',
        { className: 'dsh-rc-chip', 'data-tone': 'ok', key: 'secure' },
        `${t('connection.secureCookies')}: ${t('yes')}`,
      ),
    )
  }
  if (connection.accessRequired) {
    chips.push(
      h(
        'span',
        { className: 'dsh-rc-chip', 'data-tone': 'brand', key: 'access' },
        `${t('connection.access')}: ${t('yes')}`,
      ),
    )
  }

  const rows: ReactNode[] = []
  const listenerText =
    listener.host === null
      ? t('value.none')
      : `${listener.host}:${listener.port === null ? '—' : String(listener.port)} (${listener.protocol ?? (listener.secure ? 'https' : 'http')})`
  rows.push(kvRow(t('plan.listener'), listenerText, 'listener'))
  if (tunnel.serviceUrl !== undefined && tunnel.serviceUrl !== null) {
    rows.push(kvRow(t('connection.serviceUrl'), tunnel.serviceUrl, 'serviceUrl'))
  }
  rows.push(kvRow(t('connection.publicOrigin'), connection.publicOrigin ?? t('value.none'), 'publicOrigin'))
  rows.push(kvRow(t('connection.qrOrigin'), connection.qrOrigin ?? t('value.none'), 'qrOrigin'))
  if (tunnel.verified !== undefined) {
    rows.push(kvRow(t('connection.httpCheck'), formatVerified(tunnel.verified.http, t), 'http'))
    rows.push(kvRow(t('connection.wsCheck'), formatVerified(tunnel.verified.ws, t), 'ws'))
  }
  if (tunnel.temporary && tunnel.enabled) {
    rows.push(kvRow(t('tunnel.temporary'), t('yes'), 'temporary'))
  }

  const children: ReactNode[] = [
    h(
      'div',
      { className: 'dsh-rc-hero-head', key: 'head' },
      h('span', { className: 'dsh-rc-status-dot', 'data-tone': heroTone, key: 'dot' }),
      h(
        'div',
        { className: 'dsh-rc-hero-title', key: 'titles' },
        h('h3', { className: 'dsh-rc-card-title' }, t('connection.title')),
        h('div', { className: 'dsh-rc-hero-chips', key: 'chips' }, chips),
      ),
    ),
    h('div', { className: 'dsh-rc-kv', key: 'kv' }, rows),
  ]
  if (tunnel.error !== null && tunnel.error.length > 0) {
    children.push(alertBlock('error', `${t('connection.error')}: ${tunnel.error}`))
  }
  if (tunnel.detail !== undefined && tunnel.detail !== null && tunnel.detail.length > 0) {
    children.push(alertBlock('warn', `${t('connection.detail')}: ${tunnel.detail}`))
  }
  const exposed = isPublicExposed(connection)
  if (exposed) {
    children.push(alertBlock('info', t('connection.running')))
    children.push(
      h(
        'div',
        { className: 'dsh-rc-actions', key: 'exposure-actions' },
        iconButton(t('connection.stop'), onStop, { variant: 'danger', small: true, disabled: busy }),
      ),
    )
  } else {
    children.push(h('p', { className: 'dsh-rc-muted', key: 'none' }, t('connection.none')))
  }
  return h(
    'section',
    { className: 'dsh-rc-card dsh-rc-hero', 'data-state': heroTone, key: 'connection-status' },
    ...children,
  )
}

/* -------------------------------------------------------------------------- */
/* Plan disclosure                                                            */
/* -------------------------------------------------------------------------- */

function formatParamValue(key: string, value: string | number | boolean | null, t: TFn): string {
  if (value === null) return t('value.none')
  if (typeof value === 'boolean') return value ? t('yes') : t('no')
  if (typeof value === 'number') {
    if (key.toLowerCase().includes('size') || key.toLowerCase().includes('bytes')) {
      return formatBytes(value)
    }
    return String(value)
  }
  return value
}

function renderStep(step: ConnectionPlanStep, t: TFn, index: number): ReactElement {
  const kindKey = STEP_KIND_KEYS[step.kind] ?? 'step.kind.warning'
  const children: ReactNode[] = [
    h(
      'div',
      { className: 'dsh-rc-step-head', key: 'head' },
      h('span', { className: 'dsh-rc-step-kind' }, t(kindKey)),
    ),
    h('p', { className: 'dsh-rc-step-text', key: 'text' }, step.text),
  ]
  const params = step.params
  if (params !== undefined && params !== null) {
    const entries = Object.entries(params)
    if (entries.length > 0) {
      children.push(
        h(
          'div',
          { className: 'dsh-rc-step-params', key: 'params' },
          entries.map(([key, value]) => {
            const labelKey = STEP_PARAM_KEYS[key]
            const label = labelKey === undefined ? key : t(labelKey)
            return h(
              'span',
              { className: 'dsh-rc-param', key },
              h('span', { className: 'dsh-rc-param-key' }, label),
              h('span', { className: 'dsh-rc-param-value' }, formatParamValue(key, value, t)),
            )
          }),
        ),
      )
    }
  }
  return h(
    'li',
    { className: 'dsh-rc-step', key: `step-${index}-${step.kind}`, 'data-kind': step.kind },
    children,
  )
}

interface DownloadBlockProps {
  download: CloudflaredDownloadInfo
  expired: boolean
  busy: boolean
  onInstall: () => void
}

function renderDownloadBlock(t: TFn, props: DownloadBlockProps): ReactElement {
  const download = props.download
  const children: ReactNode[] = [
    alertBlock('warn', t('plan.downloadIntro')),
    h(
      'div',
      { className: 'dsh-rc-kv', key: 'kv' },
      kvRow(t('plan.provider'), 'cloudflare/cloudflared', 'provider'),
      kvRow(t('plan.version'), download.version, 'version'),
      kvRow(t('plan.asset'), download.asset, 'asset'),
      kvRow(t('plan.size'), formatBytes(download.sizeBytes), 'size'),
      kvRow(t('plan.sha256'), download.sha256, 'sha256'),
      kvRow(t('plan.releaseUrl'), download.releaseUrl, 'releaseUrl'),
      kvRow(t('plan.cacheDir'), download.cacheDirectory, 'cache'),
    ),
  ]
  if (download.supported !== true) {
    children.push(alertBlock('error', t('plan.downloadUnsupported')))
  } else if (download.installed !== null) {
    const installed = download.installed
    children.push(
      h(
        'div',
        { className: 'dsh-rc-kv', key: 'installed' },
        kvRow(t('plan.downloadInstalled'), t('yes'), 'installedYes'),
        kvRow(t('plan.installedPath'), installed.path, 'installedPath'),
        kvRow(t('plan.version'), installed.version ?? t('value.none'), 'installedVersion'),
        kvRow(t('plan.provider'), installed.source, 'installedSource'),
        kvRow(
          t('connection.verified'),
          installed.verified ? t('connection.verified') : t('connection.notVerified'),
          'installedVerified',
        ),
      ),
    )
  } else {
    children.push(
      h(
        'div',
        { className: 'dsh-rc-actions', key: 'install' },
        iconButton(t('plan.install'), props.onInstall, {
          variant: 'primary',
          small: true,
          disabled: props.busy || props.expired,
        }),
      ),
    )
  }
  return h('div', { className: 'dsh-rc-plan-download', key: 'download' }, ...children)
}

interface PlanDisclosureProps {
  plan: ConnectionPlan
  now: number
  busy: boolean
  installing: boolean
  installDone: boolean
  error: RcFailure | null
  installError: RcFailure | null
  onStart: () => void
  onInstall: () => void
  onCancel: () => void
  onReplan: () => void
}

function renderPlanDisclosure(t: TFn, props: PlanDisclosureProps): ReactElement {
  const plan = props.plan
  const remaining = remainingSeconds(plan.expiresAt, props.now)
  const expired = remaining <= 0
  const children: ReactNode[] = [
    h(
      'div',
      { className: 'dsh-rc-row', key: 'head' },
      h(
        'div',
        { className: 'dsh-rc-grow' },
        h('h4', { className: 'dsh-rc-card-title' }, t('plan.title')),
        h('p', { className: 'dsh-rc-muted' }, t('plan.intro')),
      ),
      h(
        'span',
        { className: 'dsh-rc-badge', 'data-tone': expired ? 'closed' : 'info' },
        expired ? t('plan.expired') : t('plan.expires', { seconds: remaining }),
      ),
    ),
    h('h5', { className: 'dsh-rc-subtitle', key: 'steps-title' }, t('plan.steps')),
  ]
  const steps = plan.steps ?? []
  if (steps.length === 0) {
    children.push(h('p', { className: 'dsh-rc-muted', key: 'no-steps' }, t('plan.noSteps')))
  } else {
    children.push(
      h(
        'ul',
        { className: 'dsh-rc-steps', key: 'steps' },
        steps.map((step, index) => renderStep(step, t, index)),
      ),
    )
  }

  const portText =
    plan.listener.port > 0 ? String(plan.listener.port) : t('plan.portDynamic')
  children.push(
    h(
      'div',
      { className: 'dsh-rc-kv', key: 'facts' },
      kvRow(t('plan.listener'), `${plan.listener.host}:${plan.listener.port} (${plan.listener.protocol})`, 'listener'),
      kvRow(t('plan.access'), plan.listener.access, 'access'),
      kvRow(t('plan.port'), portText, 'port'),
      kvRow(t('plan.secure'), plan.secureCookies ? t('yes') : t('no'), 'secure'),
      kvRow(t('plan.publicOrigin'), plan.publicOrigin ?? t('value.none'), 'public'),
      kvRow(t('plan.qrOrigin'), plan.qrOrigin ?? t('value.none'), 'qr'),
      kvRow(t('plan.accessRequired'), plan.accessRequired ? t('yes') : t('no'), 'accessRequired'),
    ),
  )

  if (plan.download !== null) {
    children.push(
      renderDownloadBlock(t, {
        download: plan.download,
        expired,
        busy: props.busy || props.installing,
        onInstall: props.onInstall,
      }),
    )
  }
  if (props.installDone) children.push(alertBlock('info', t('plan.installDone')))
  if (props.installError !== null) {
    children.push(alertBlock('error', `${t('plan.installFailedTitle')}: ${localizedFailure(t, props.installError)}`))
  }
  if (props.error !== null) {
    children.push(alertBlock('error', `${t('plan.startFailed')}: ${localizedFailure(t, props.error)}`))
  }

  children.push(
    h(
      'div',
      { className: 'dsh-rc-actions', key: 'actions' },
      iconButton(t('plan.cancel'), props.onCancel, { small: true, disabled: props.busy || props.installing }),
      expired
        ? iconButton(t('plan.replan'), props.onReplan, { variant: 'primary', small: true })
        : iconButton(props.installing ? t('plan.installing') : t('plan.start'), props.onStart, {
            variant: 'primary',
            disabled: props.busy || props.installing || expired,
          }),
    ),
  )
  return h('div', { className: 'dsh-rc-plan', key: 'plan' }, ...children)
}

/* -------------------------------------------------------------------------- */
/* Connection card: method picker + plan → explicit start                     */
/* -------------------------------------------------------------------------- */

interface ConnectionCardProps {
  t: TFn
  status: AdminStatusEnvelope
  /** More than one device is registered: the desktop must pick one before enabling. */
  needsSelection: boolean
  onChanged: () => Promise<void>
}

function ConnectionCard({ t, status, needsSelection, onChanged }: ConnectionCardProps): ReactElement {
  const [form, setForm] = React.useState<ConnectionForm>(() => initialForm(status))
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<RcFailure | null>(null)
  const [plan, setPlan] = React.useState<ConnectionPlan | null>(null)
  const [planError, setPlanError] = React.useState<RcFailure | null>(null)
  const [installing, setInstalling] = React.useState(false)
  const [installError, setInstallError] = React.useState<RcFailure | null>(null)
  const [installDone, setInstallDone] = React.useState(false)
  const [now, setNow] = React.useState(() => Date.now())

  React.useEffect(() => {
    if (plan === null) return
    const timer = window.setInterval(() => setNow(Date.now()), 1_000)
    return () => window.clearInterval(timer)
  }, [plan])

  React.useEffect(() => {
    if (form.method !== 'lan' || form.lanAddress.length > 0) return
    const recommended = (status.networkInterfaces ?? []).find((entry) => entry.recommended === true)
    if (recommended !== undefined) {
      setForm((current) => ({ ...current, lanAddress: recommended.address }))
    }
  }, [form.method, form.lanAddress, status.networkInterfaces])

  const update = React.useCallback((patch: Partial<ConnectionForm>): void => {
    setForm((current) => ({ ...current, ...patch }))
    setError(null)
  }, [])

  const securityClosed = status.security?.closed === true
  const exposed = publicExposureActive(status)
  const planningDisabled =
    busy || installing || securityClosed || exposed || !status.enabled || needsSelection

  const onPlan = (): void => {
    const result = buildSelection(form)
    if (!result.ok) {
      setError({ code: 'BAD_REQUEST', message: t(result.errorKey) })
      return
    }
    setBusy(true)
    setError(null)
    setPlanError(null)
    setInstallError(null)
    setInstallDone(false)
    void (async (): Promise<void> => {
      try {
        const response = await adminPost<AdminConnectionPlanResponse>(
          ADMIN_ROUTES.connectionPlan,
          result.selection,
        )
        setPlan(response.plan)
        setNow(Date.now())
      } catch (failure) {
        setError(toFailure(failure))
      } finally {
        setBusy(false)
      }
    })()
  }

  const onReplan = (): void => {
    setPlan(null)
    setPlanError(null)
    setInstallError(null)
    setInstallDone(false)
    onPlan()
  }

  const onStart = (): void => {
    const current = plan
    if (current === null) return
    setBusy(true)
    setPlanError(null)
    void (async (): Promise<void> => {
      try {
        await adminPost<AdminConnectionStartResponse>(ADMIN_ROUTES.connectionStart, {
          planId: current.planId,
          confirm: true,
        })
        setPlan(null)
        setInstallDone(false)
        await onChanged()
      } catch (failure) {
        setPlanError(toFailure(failure))
      } finally {
        setBusy(false)
      }
    })()
  }

  const onInstall = (): void => {
    const current = plan
    if (current === null || current.download === null) return
    if (!confirmAction(t('plan.installConfirm'))) return
    setInstalling(true)
    setInstallError(null)
    void (async (): Promise<void> => {
      try {
        await adminPost<AdminInstallResponse>(ADMIN_ROUTES.install, {
          planId: current.planId,
          confirm: true,
        })
        setInstallDone(true)
        // The one-shot plan was consumed by the install; disclose a fresh plan
        // (download now shows the verified cache) before any Start is offered.
        await onChanged()
        setPlan(null)
        setBusy(true)
        const result = buildSelection(form)
        if (!result.ok) {
          setError({ code: 'BAD_REQUEST', message: t(result.errorKey) })
          setBusy(false)
          return
        }
        try {
          const response = await adminPost<AdminConnectionPlanResponse>(
            ADMIN_ROUTES.connectionPlan,
            result.selection,
          )
          setPlan(response.plan)
          setNow(Date.now())
        } catch (failure) {
          setError(toFailure(failure))
        } finally {
          setBusy(false)
        }
      } catch (failure) {
        setInstallError(toFailure(failure))
      } finally {
        setInstalling(false)
      }
    })()
  }

  const onStopExposure = (): void => {
    if (!confirmAction(t('connection.stopConfirm'))) return
    setBusy(true)
    setError(null)
    void (async (): Promise<void> => {
      try {
        await adminPost<AdminConnectionStopResponse>(ADMIN_ROUTES.connectionStop, {})
        await onChanged()
      } catch (failure) {
        setError(toFailure(failure))
      } finally {
        setBusy(false)
      }
    })()
  }

  const children: ReactNode[] = []
  children.push(renderConnectionStatus(t, status, onStopExposure, busy))

  // Method picker
  const methodCardChildren: ReactNode[] = [
    h('h4', { className: 'dsh-rc-card-title', key: 'title' }, t('methods.title')),
    h('p', { className: 'dsh-rc-muted', key: 'intro' }, t('methods.intro')),
  ]
  if (securityClosed) methodCardChildren.push(alertBlock('error', t('pair.securityClosed')))
  if (needsSelection) methodCardChildren.push(alertBlock('warn', t('lock.needsSelection')))
  if (!status.enabled) methodCardChildren.push(alertBlock('info', t('control.off')))
  if (exposed) methodCardChildren.push(alertBlock('warn', t('connection.running')))

  const methods: ConnectionMethod[] = [
    'cloudflare-quick',
    'cloudflare-named',
    'cloudflare-named-local',
    'external',
    'ssh',
    'lan',
    'loopback',
  ]
  const methodHints: Record<ConnectionMethod, MessageKey> = {
    loopback: 'methods.loopbackHint',
    lan: 'methods.lanHint',
    'cloudflare-quick': 'methods.cloudflareQuickHint',
    'cloudflare-named': 'methods.cloudflareNamedHint',
    'cloudflare-named-local': 'methods.cloudflareNamedLocalHint',
    external: 'methods.externalHint',
    ssh: 'methods.sshHint',
  }
  methodCardChildren.push(
    h(
      'div',
      { className: 'dsh-rc-methods', key: 'methods' },
      methods.map((method) =>
        h(
          'label',
          {
            className: 'dsh-rc-method',
            key: method,
            'data-checked': form.method === method ? 'true' : 'false',
          },
          h('input', {
            type: 'radio',
            name: 'dsh-rc-connection-method',
            value: method,
            checked: form.method === method,
            disabled: planningDisabled,
            key: 'radio',
            onChange: () => update({ method: methodSelection(method) }),
          }),
          h(
            'span',
            { className: 'dsh-rc-method-text', key: 'text' },
            h('span', { className: 'dsh-rc-method-title' }, t(METHOD_LABEL_KEYS[method])),
            h('span', { className: 'dsh-rc-muted' }, t(methodHints[method])),
          ),
        ),
      ),
    ),
  )

  // Method-specific fields
  const fields: ReactNode[] = []
  if (form.method === 'lan') {
    const interfaces: LanInterfaceView[] = status.networkInterfaces ?? []
    const selectable = interfaces.filter((entry) => entry.scope !== 'link-local')
    fields.push(
      selectField(
        'dsh-rc-lan-address',
        t('methods.lanSelect'),
        form.lanAddress,
        [
          { value: '', label: t('methods.lanNone') },
          ...selectable.map((entry) => ({
            value: entry.address,
            label: `${entry.address} · ${entry.name} · ${entry.scope}`,
          })),
        ],
        (value) => update({ lanAddress: value }),
        planningDisabled,
      ),
    )
    fields.push(
      h('p', { className: 'dsh-rc-muted', key: 'lan-hint' }, t('methods.lanTlsWarning')),
    )
    if (selectable.length === 0) {
      fields.push(alertBlock('warn', t('methods.lanNone')))
    }
  }
  if (
    form.method === 'cloudflare-quick' ||
    form.method === 'cloudflare-named' ||
    form.method === 'cloudflare-named-local'
  ) {
    fields.push(
      selectField(
        'dsh-rc-transport',
        t('methods.transport'),
        form.transport,
        [
          { value: 'auto', label: t('transport.auto') },
          { value: 'quic', label: t('transport.quic') },
          { value: 'http2', label: t('transport.http2') },
        ],
        (value) => update({ transport: value as TunnelTransport }),
        planningDisabled,
        t('methods.transportHint'),
      ),
    )
  }
  if (form.method === 'cloudflare-named' || form.method === 'cloudflare-named-local') {
    fields.push(
      textField({
        id: 'dsh-rc-hostname',
        label: t('methods.hostname'),
        value: form.hostname,
        placeholder: t('methods.hostnamePlaceholder'),
        onChange: (value) => update({ hostname: value }),
        disabled: planningDisabled,
      }),
    )
  }
  if (form.method === 'cloudflare-named') {
    fields.push(
      selectField(
        'dsh-rc-token-source',
        t('methods.tokenSource'),
        form.tokenSource,
        [
          { value: 'env', label: t('methods.tokenSourceEnv') },
          { value: 'file', label: t('methods.tokenSourceFile') },
        ],
        (value) => update({ tokenSource: value === 'file' ? 'file' : 'env' }),
        planningDisabled,
      ),
    )
    fields.push(
      form.tokenSource === 'env'
        ? textField({
            id: 'dsh-rc-token-env',
            label: t('methods.tokenEnv'),
            value: form.tokenEnv,
            placeholder: t('methods.tokenEnvPlaceholder'),
            onChange: (value) => update({ tokenEnv: value }),
            disabled: planningDisabled,
          })
        : textField({
            id: 'dsh-rc-token-file',
            label: t('methods.tokenFile'),
            value: form.tokenFile,
            placeholder: t('methods.tokenFilePlaceholder'),
            onChange: (value) => update({ tokenFile: value }),
            disabled: planningDisabled,
          }),
    )
    // Cloudflare route -> local service URL is configured on the dashboard; the
    // matching fixed loopback port must be explicitly disclosed here.
    fields.push(
      textField({
        id: 'dsh-rc-loopback-port',
        label: t('methods.loopbackPort'),
        value: form.loopbackPort,
        placeholder: '0',
        hint: t('methods.loopbackPortHint'),
        type: 'number',
        onChange: (value) => update({ loopbackPort: value }),
        disabled: planningDisabled,
      }),
    )
  }
  if (form.method === 'cloudflare-named-local') {
    fields.push(
      textField({
        id: 'dsh-rc-tunnel-id',
        label: t('methods.tunnelId'),
        value: form.tunnelId,
        placeholder: t('methods.tunnelIdPlaceholder'),
        onChange: (value) => update({ tunnelId: value }),
        disabled: planningDisabled,
      }),
      textField({
        id: 'dsh-rc-credentials',
        label: t('methods.credentialsFile'),
        value: form.credentialsFile,
        placeholder: t('methods.credentialsFilePlaceholder'),
        onChange: (value) => update({ credentialsFile: value }),
        disabled: planningDisabled,
      }),
    )
  }
  if (form.method === 'external') {
    fields.push(
      textField({
        id: 'dsh-rc-public-url',
        label: t('methods.publicUrl'),
        value: form.publicUrl,
        placeholder: t('methods.publicUrlPlaceholder'),
        onChange: (value) => update({ publicUrl: value }),
        disabled: planningDisabled,
      }),
      textField({
        id: 'dsh-rc-loopback-port',
        label: t('methods.loopbackPort'),
        value: form.loopbackPort,
        placeholder: '0',
        hint: t('methods.loopbackPortHint'),
        type: 'number',
        onChange: (value) => update({ loopbackPort: value }),
        disabled: planningDisabled,
      }),
    )
  }
  if (form.method === 'ssh') {
    fields.push(
      textField({
        id: 'dsh-rc-ssh-path',
        label: t('methods.sshPath'),
        value: form.sshPath,
        hint: t('methods.sshPathHint'),
        onChange: (value) => update({ sshPath: value }),
        disabled: planningDisabled,
      }),
      textField({
        id: 'dsh-rc-ssh-user',
        label: t('methods.sshUser'),
        value: form.sshUser,
        onChange: (value) => update({ sshUser: value }),
        disabled: planningDisabled,
      }),
      textField({
        id: 'dsh-rc-ssh-host',
        label: t('methods.sshHost'),
        value: form.sshHost,
        onChange: (value) => update({ sshHost: value }),
        disabled: planningDisabled,
      }),
      textField({
        id: 'dsh-rc-ssh-remote-port',
        label: t('methods.sshRemotePort'),
        value: form.sshRemotePort,
        type: 'number',
        onChange: (value) => update({ sshRemotePort: value }),
        disabled: planningDisabled,
      }),
    )
  }
  if (
    form.method === 'cloudflare-quick' ||
    form.method === 'cloudflare-named' ||
    form.method === 'cloudflare-named-local'
  ) {
    fields.push(
      textField({
        id: 'dsh-rc-cloudflared-path',
        label: t('methods.cloudflaredPath'),
        value: form.cloudflaredPath,
        hint: t('methods.cloudflaredPathHint'),
        onChange: (value) => update({ cloudflaredPath: value }),
        disabled: planningDisabled,
      }),
    )
  }
  if (
    form.method === 'cloudflare-named' ||
    form.method === 'cloudflare-named-local' ||
    form.method === 'external'
  ) {
    fields.push(
      checkboxField(
        'dsh-rc-access-required',
        t('methods.accessRequired'),
        form.accessRequired,
        (checked) => update({ accessRequired: checked }),
        planningDisabled,
      ),
    )
  }
  if (fields.length > 0) {
    methodCardChildren.push(h('div', { className: 'dsh-rc-fields', key: 'fields' }, fields))
  }

  // cloudflared availability hint (status only; never triggers a download)
  const cloudflared = status.cloudflared
  if (
    form.method === 'cloudflare-quick' ||
    form.method === 'cloudflare-named' ||
    form.method === 'cloudflare-named-local'
  ) {
    if (cloudflared !== undefined && cloudflared !== null) {
      if (cloudflared.supported !== true) {
        methodCardChildren.push(alertBlock('warn', t('methods.cloudflaredUnsupported')))
      } else if (cloudflared.installed !== null) {
        methodCardChildren.push(
          h(
            'p',
            { className: 'dsh-rc-muted', key: 'cf-found' },
            t('methods.cloudflaredFound', {
              version: cloudflared.installed.version ?? cloudflared.version,
              source: cloudflared.installed.source,
              verified: cloudflared.installed.verified ? t('yes') : t('no'),
            }),
          ),
        )
      } else {
        methodCardChildren.push(alertBlock('info', t('methods.cloudflaredMissing')))
      }
    }
  }

  methodCardChildren.push(
    h(
      'div',
      { className: 'dsh-rc-actions', key: 'actions' },
      iconButton(busy ? t('methods.planBusy') : t('methods.plan'), onPlan, {
        variant: 'primary',
        disabled: planningDisabled,
      }),
    ),
  )
  if (error !== null) {
    methodCardChildren.push(alertBlock('error', localizedFailure(t, error)))
  }
  children.push(card(t('methods.title'), 'methods', methodCardChildren))

  if (plan !== null) {
    children.push(
      renderPlanDisclosure(t, {
        plan,
        now,
        busy,
        installing,
        installDone,
        error: planError,
        installError,
        onStart,
        onInstall,
        onCancel: () => {
          setPlan(null)
          setError(null)
          setPlanError(null)
          setInstallError(null)
          setInstallDone(false)
        },
        onReplan,
      }),
    )
  }

  return h('div', { className: 'dsh-rc-connection', key: 'connection' }, ...children)
}

/* -------------------------------------------------------------------------- */
/* Device lock / devices                                                      */
/* -------------------------------------------------------------------------- */

interface DeviceActions {
  busy: boolean
  onActivate: (device: DeviceView) => void
  onRelease: (device: DeviceView) => void
  onRevoke: (device: DeviceView) => void
  onRevokeAll: () => void
}

function renderDeviceLockCard(
  t: TFn,
  status: AdminStatusEnvelope,
  devices: DeviceView[],
  now: number,
): ReactElement {
  const lock = status.deviceLock
  const security = status.security
  const rows: ReactNode[] = []
  if (lock !== undefined) {
    rows.push(kvRow(t('lock.state'), t(LOCK_STATE_KEYS[lock.state] ?? 'lock.state.none'), 'state'))
    rows.push(
      kvRow(
        t('lock.activeDevice'),
        lock.activeDeviceLabel ?? (lock.activeDeviceId === null ? t('value.none') : shortId(lock.activeDeviceId)),
        'active',
      ),
    )
    rows.push(kvRow(t('lock.since'), formatTimestamp(lock.activeSince ?? 0), 'since'))
    rows.push(kvRow(t('lock.lastActivity'), formatTimestamp(lock.lastActivityAt ?? 0), 'last'))
    rows.push(
      kvRow(
        t('lock.idleExpires'),
        lock.idleExpiresAt === null
          ? t('value.none')
          : remainingSeconds(lock.idleExpiresAt, now) <= 0
            ? t('value.none')
            : formatDuration(lock.idleExpiresAt - now),
        'idle',
      ),
    )
    rows.push(kvRow(t('lock.idleTimeout'), t('lock.minutesValue', { minutes: formatMinutes(lock.idleTimeoutMinutes) }), 'idleTimeout'))
    rows.push(kvRow(t('lock.registered'), String(lock.registeredDevices), 'registered'))
  } else {
    // Legacy fallback: derive the lock view from the device list flags.
    const active = devices.find((device) => device.active === true)
    rows.push(kvRow(t('lock.state'), t(active === undefined ? 'lock.state.none' : 'lock.state.active'), 'state'))
    rows.push(
      kvRow(t('lock.activeDevice'), active === undefined ? t('value.none') : active.label, 'active'),
    )
    rows.push(kvRow(t('lock.registered'), String(devices.length), 'registered'))
  }

  const children: ReactNode[] = [h('div', { className: 'dsh-rc-kv', key: 'kv' }, rows)]
  if (lock !== undefined && lock.needsSelection) {
    children.push(alertBlock('warn', t('lock.needsSelection')))
  } else if (lock !== undefined && lock.activeDeviceId === null && devices.length > 0) {
    children.push(alertBlock('warn', t('lock.noActive')))
  }
  if (security !== undefined && security.closed) {
    children.push(alertBlock('error', t('closed.title')))
  }

  // Surface the latest rejected second-device attempt from the audit ring.
  const audit = status.audit ?? []
  let latestRejection: AuditEntryView | null = null
  for (const entry of audit) {
    if (entry.result !== 'rejected') continue
    if (entry.kind !== 'device-lock' && entry.kind !== 'security') continue
    if (latestRejection === null || entry.time > latestRejection.time) latestRejection = entry
  }
  if (latestRejection !== null) {
    children.push(alertBlock('warn', t('lock.noticeSecondDevice', { time: formatTimestamp(latestRejection.time) })))
    if (latestRejection.detail.length > 0) {
      children.push(
        h(
          'p',
          { className: 'dsh-rc-muted', key: 'rejection-detail' },
          t('lock.noticeSecondDeviceDetail', { detail: latestRejection.detail }),
        ),
      )
    }
  }
  return card(t('lock.title'), 'lock', children)
}

function renderDevicesCard(
  t: TFn,
  devices: DeviceView[],
  actions: DeviceActions,
  /** `undefined` = no lease view (legacy fallback to `DeviceView.active`); `null` = no active device. */
  activeDeviceId: string | null | undefined,
): ReactElement {
  const body: ReactNode =
    devices.length === 0
      ? h('p', { className: 'dsh-rc-muted' }, t('devices.empty'))
      : h(
          'div',
          { className: 'dsh-rc-table-wrap' },
          h(
            'table',
            { className: 'dsh-rc-table' },
            h(
              'thead',
              null,
              h(
                'tr',
                null,
                h('th', null, t('devices.label')),
                h('th', null, t('devices.platform')),
                h('th', null, t('devices.lastSeen')),
                h('th', null, t('devices.active')),
                h('th', { className: 'dsh-rc-table-action' }, t('devices.actions')),
              ),
            ),
            h(
              'tbody',
              null,
              devices.map((device) => {
                // The lease view is the single source of truth when present; the
                // legacy `DeviceView.active` flag is only used without it.
                const active =
                  activeDeviceId === undefined
                    ? device.active === true
                    : activeDeviceId === device.id
                const actionButtons: ReactNode[] = []
                if (active) {
                  actionButtons.push(
                    iconButton(t('devices.release'), () => actions.onRelease(device), {
                      small: true,
                      disabled: actions.busy,
                    }),
                  )
                } else {
                  actionButtons.push(
                    iconButton(t('devices.activate'), () => actions.onActivate(device), {
                      small: true,
                      variant: 'primary',
                      disabled: actions.busy,
                    }),
                  )
                }
                actionButtons.push(
                  iconButton(t('devices.revoke'), () => actions.onRevoke(device), {
                    small: true,
                    variant: 'danger',
                    disabled: actions.busy,
                  }),
                )
                return h(
                  'tr',
                  { key: device.id },
                  h('td', null, device.label),
                  h('td', null, device.platform),
                  h('td', null, formatTimestamp(device.lastSeenAt)),
                  h(
                    'td',
                    null,
                    active
                      ? h('span', { className: 'dsh-rc-badge', 'data-tone': 'ready' }, t('devices.active'))
                      : h('span', { className: 'dsh-rc-muted' }, t('value.none')),
                  ),
                  h('td', { className: 'dsh-rc-table-action' }, actionButtons),
                )
              }),
            ),
          ),
        )
  const children: ReactNode[] = [body]
  children.push(
    h(
      'div',
      { className: 'dsh-rc-actions', key: 'actions' },
      iconButton(t('devices.revokeAll'), actions.onRevokeAll, {
        variant: 'danger',
        small: true,
        disabled: actions.busy || devices.length === 0,
      }),
    ),
  )
  return h(
    'div',
    { className: 'dsh-rc-card', key: 'devices' },
    h('h3', { className: 'dsh-rc-card-title' }, t('devices.title')),
    ...children,
  )
}

/* -------------------------------------------------------------------------- */
/* Security + audit cards                                                     */
/* -------------------------------------------------------------------------- */

function renderSecurityCard(t: TFn, security: SecurityStateView): ReactElement {
  const rows: ReactNode[] = [
    kvRow(t('security.closed'), security.closed ? t('yes') : t('no'), 'closed'),
    kvRow(
      t('security.reason'),
      security.closed
        ? t(CLOSED_REASON_KEYS[security.closedReason ?? ''] ?? 'closed.reason.default')
        : t('value.none'),
      'reason',
    ),
    kvRow(
      t('security.circuitBreaker'),
      security.circuitBreaker === 'open' ? t('security.breakerOpen') : t('security.breakerClosed'),
      'breaker',
    ),
    kvRow(
      t('security.failures'),
      `${security.failureCount} / ${security.maxFailuresBeforeCircuitBreaker}`,
      'failures',
    ),
    kvRow(t('security.blocked'), String(security.blockedClients), 'blocked'),
    kvRow(t('security.window'), t('security.windowValue', { seconds: security.failureWindowSeconds }), 'window'),
    kvRow(t('security.ban'), t('security.banValue', { minutes: security.temporaryBanMinutes }), 'ban'),
    kvRow(t('security.epoch'), String(security.revocationEpoch), 'epoch'),
    kvRow(t('security.idleTimeout'), t('lock.minutesValue', { minutes: formatMinutes(security.idleTimeoutMinutes) }), 'idle'),
  ]
  return card(t('security.title'), 'security', [h('div', { className: 'dsh-rc-kv', key: 'kv' }, rows)])
}

function renderAuditCard(t: TFn, audit: AuditEntryView[]): ReactElement {
  const children: ReactNode[] = []
  if (audit.length === 0) {
    children.push(h('p', { className: 'dsh-rc-muted', key: 'empty' }, t('audit.empty')))
  } else {
    const visible = audit.slice(Math.max(0, audit.length - AUDIT_VISIBLE_ROWS)).reverse()
    children.push(
      h(
        'p',
        { className: 'dsh-rc-muted', key: 'latest' },
        t('audit.latest', { count: visible.length }),
      ),
    )
    children.push(
      h(
        'div',
        { className: 'dsh-rc-table-wrap dsh-rc-audit', key: 'table' },
        h(
          'table',
          { className: 'dsh-rc-table' },
          h(
            'thead',
            null,
            h(
              'tr',
              null,
              h('th', null, t('audit.time')),
              h('th', null, t('audit.kind')),
              h('th', null, t('audit.operation')),
              h('th', null, t('audit.result')),
              h('th', null, t('audit.device')),
              h('th', null, t('audit.ip')),
              h('th', null, t('audit.userAgent')),
              h('th', null, t('audit.detail')),
            ),
          ),
          h(
            'tbody',
            null,
            visible.map((entry) => {
              const kindKey = AUDIT_KIND_KEYS[entry.kind]
              const deviceText =
                entry.deviceLabel !== null && entry.deviceLabel.length > 0
                  ? entry.deviceLabel
                  : entry.deviceId === null
                    ? '—'
                    : shortId(entry.deviceId)
              return h(
                'tr',
                { key: `${entry.id}-${entry.time}`, 'data-result': entry.result },
                h('td', null, formatTimestamp(entry.time)),
                h('td', null, kindKey === undefined ? entry.kind : t(kindKey)),
                h('td', null, entry.operation.length > 0 ? entry.operation : '—'),
                h('td', null, t(AUDIT_RESULT_KEYS[entry.result])),
                h('td', null, deviceText),
                h('td', null, entry.ip ?? '—'),
                h(
                  'td',
                  { className: 'dsh-rc-audit-ua', title: entry.userAgent ?? undefined },
                  entry.userAgent === null ? '—' : entry.userAgent,
                ),
                h('td', { className: 'dsh-rc-audit-detail' }, entry.detail.length > 0 ? entry.detail : '—'),
              )
            }),
          ),
        ),
      ),
    )
  }
  return card(t('audit.title'), 'audit', children)
}

/* -------------------------------------------------------------------------- */
/* Pairing card                                                               */
/* -------------------------------------------------------------------------- */

interface PairingCardProps {
  status: AdminStatusEnvelope
  pairing: AdminPairCreateResponse | null
  remaining: number
  qrUrl: string | null
  busy: boolean
  disabledReason: MessageKey | null
  onCreate: () => void
  onDismiss: () => void
}

function renderPairingCard(t: TFn, props: PairingCardProps): ReactElement {
  const status = props.status
  const active = props.pairing !== null || props.qrUrl !== null
  const children: ReactNode[] = [
    h(
      'div',
      { className: 'dsh-rc-row', key: 'head' },
      h(
        'div',
        { className: 'dsh-rc-grow' },
        h('h3', { className: 'dsh-rc-card-title' }, t('pair.title')),
        h(
          'p',
          { className: 'dsh-rc-muted' },
          status.enabled ? t('pair.instructions') : t('pair.enableFirst'),
        ),
      ),
      iconButton(t('pair.create'), props.onCreate, {
        variant: 'primary',
        disabled: props.busy || props.disabledReason !== null,
      }),
    ),
  ]
  if (props.disabledReason !== null) {
    children.push(alertBlock('warn', t(props.disabledReason)))
  }
  if (active) {
    const info: ReactNode[] = []
    if (props.pairing !== null && props.remaining > 0) {
      info.push(
        h(
          'div',
          { className: 'dsh-rc-kv', key: 'code' },
          kvRow(t('pair.code'), props.pairing.code, 'code'),
          kvRow(t('pair.url'), props.pairing.url, 'url'),
        ),
        h('p', { className: 'dsh-rc-muted', key: 'expires' }, t('pair.expires', { seconds: props.remaining })),
        h('p', { className: 'dsh-rc-muted', key: 'waiting' }, t('pair.waiting')),
      )
    } else if (props.pairing !== null) {
      info.push(alertBlock('warn', t('pair.expired')))
    }
    info.push(
      h(
        'div',
        { className: 'dsh-rc-actions', key: 'dismiss' },
        iconButton(t('pair.dismiss'), props.onDismiss, { small: true }),
      ),
    )
    children.push(
      h(
        'div',
        { className: 'dsh-rc-pair', key: 'pair' },
        props.qrUrl === null
          ? h('p', { className: 'dsh-rc-muted dsh-rc-qr-placeholder' }, t('pair.qrPending'))
          : h('img', {
              className: 'dsh-rc-qr',
              src: props.qrUrl,
              width: 220,
              height: 220,
              alt: t('pair.qrAlt'),
            }),
        h('div', { className: 'dsh-rc-pair-info' }, info),
      ),
    )
  }
  return h('div', { className: 'dsh-rc-card', key: 'pairing' }, children)
}

/* -------------------------------------------------------------------------- */
/* Settings → Remote Control panel                                            */
/* -------------------------------------------------------------------------- */

interface PanelProps {
  t: TFn
}

function RemoteControlSection({ t }: PanelProps): ReactElement {
  const [status, setStatus] = React.useState<AdminStatusEnvelope | null>(null)
  const [loadError, setLoadError] = React.useState<RcFailure | null>(null)
  const [actionError, setActionError] = React.useState<RcFailure | null>(null)
  const [busy, setBusy] = React.useState(false)
  const [pairing, setPairing] = React.useState<AdminPairCreateResponse | null>(null)
  const [pairingHidden, setPairingHidden] = React.useState(false)
  const [now, setNow] = React.useState<number>(() => Date.now())

  const refresh = React.useCallback(async (): Promise<void> => {
    try {
      const next = await adminGet<AdminStatusEnvelope>(ADMIN_ROUTES.status)
      setStatus(next)
      setLoadError(null)
    } catch (error) {
      setLoadError(toFailure(error))
    }
  }, [])

  React.useEffect(() => {
    void refresh()
    const poll = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh()
    }, STATUS_POLL_MS)
    const onVisibilityChange = (): void => {
      if (document.visibilityState === 'visible') void refresh()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => {
      window.clearInterval(poll)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [refresh])

  React.useEffect(() => {
    const tick = window.setInterval(() => setNow(Date.now()), 1_000)
    return () => window.clearInterval(tick)
  }, [])

  React.useEffect(() => {
    if (pairing !== null && now >= pairing.expiresAt) setPairing(null)
  }, [pairing, now])

  const run = React.useCallback(async (action: () => Promise<void>): Promise<void> => {
    setBusy(true)
    setActionError(null)
    try {
      await action()
    } catch (error) {
      setActionError(toFailure(error))
    } finally {
      setBusy(false)
    }
  }, [])

  const onToggle = (): void => {
    const action = status?.enabled === true ? 'disable' : 'enable'
    void run(async () => {
      await adminPost<AdminControlResponse>(ADMIN_ROUTES.control, { action })
      await refresh()
    })
  }

  const onEmergencyStop = (): void => {
    if (!confirmAction(t('emergency.confirm'))) return
    void run(async () => {
      await adminPost<AdminEmergencyStopResponse>(ADMIN_ROUTES.emergencyStop, { confirm: true })
      setPairing(null)
      await refresh()
    })
  }

  const onReopen = (): void => {
    if (!confirmAction(t('closed.reopenConfirm'))) return
    void run(async () => {
      await adminPost<AdminControlResponse>(ADMIN_ROUTES.control, { action: 'enable' })
      await refresh()
    })
  }

  const onCreatePair = (): void => {
    void run(async () => {
      const created = await adminPost<AdminPairCreateResponse>(ADMIN_ROUTES.pairCreate, {})
      setPairing(created)
      setPairingHidden(false)
      notifyPairingCreated(created.expiresAt)
      await refresh()
    })
  }

  const onRevoke = (device: DeviceView): void => {
    const lock = status?.deviceLock
    const active =
      lock !== undefined && lock !== null ? lock.activeDeviceId === device.id : device.active === true
    const message = active ? t('devices.confirmRevokeActive') : t('devices.confirmRevoke')
    if (!confirmAction(message)) return
    void run(async () => {
      await adminPost(ADMIN_ROUTES.deviceRevoke, { deviceId: device.id })
      await refresh()
    })
  }

  const onRevokeAll = (): void => {
    if (!confirmAction(t('devices.confirmRevokeAll'))) return
    void run(async () => {
      await adminPost(ADMIN_ROUTES.deviceRevokeAll, {})
      await refresh()
    })
  }

  const onActivate = (device: DeviceView): void => {
    if (!confirmAction(t('lock.activateConfirm', { device: device.label }))) return
    void run(async () => {
      await adminPost(ADMIN_ROUTES.deviceActivate, { deviceId: device.id })
      await refresh()
    })
  }

  const onRelease = (device: DeviceView): void => {
    if (!confirmAction(t('lock.releaseConfirm'))) return
    void run(async () => {
      await adminPost(ADMIN_ROUTES.deviceRelease, { deviceId: device.id })
      await refresh()
    })
  }

  const qrUrl = svgDataUrl(status?.qrSvg ?? null)
  const badge = status === null ? null : statusBadge(status, t)
  const children: ReactNode[] = []
  const security = status?.security
  const securityClosed = security !== undefined && security !== null && security.closed
  const needsSelection = status?.deviceLock?.needsSelection === true
  const activePairing: AdminPairCreateResponse | null =
    pairing ?? (pairingHidden ? null : (status?.pairing ?? null))

  if (status === null) {
    if (loadError !== null) {
      children.push(
        h('p', { className: 'dsh-rc-muted', key: 'loading' }, t('error.noStatus')),
        alertBlock('error', localizedFailure(t, loadError), {
          label: t('retry'),
          onClick: () => void refresh(),
        }),
      )
    } else {
      children.push(h('p', { className: 'dsh-rc-muted', key: 'loading' }, t('panel.loading')))
    }
  } else {
    if (status.initializationError !== null) {
      children.push(alertBlock('error', status.initializationError))
    }

    if (securityClosed) {
      const reasonKey = CLOSED_REASON_KEYS[security?.closedReason ?? ''] ?? 'closed.reason.default'
      children.push(
        h(
          'div',
          { className: 'dsh-rc-closed', role: 'alert', key: 'closed' },
          h('h3', { className: 'dsh-rc-closed-title' }, t('closed.title')),
          h('p', { className: 'dsh-rc-closed-body' }, `${t(reasonKey)} · ${t('closed.body')}`),
          h(
            'div',
            { className: 'dsh-rc-actions' },
            iconButton(t('closed.reopen'), onReopen, {
              variant: 'danger',
              disabled: busy,
            }),
          ),
        ),
      )
    }

    // Listener on/off (normal disable keeps the security state untouched).
    children.push(
      h(
        'div',
        { className: 'dsh-rc-card', key: 'control' },
        h(
          'div',
          { className: 'dsh-rc-row' },
          h(
            'div',
            { className: 'dsh-rc-grow' },
            h('h3', { className: 'dsh-rc-card-title' }, t('control.title')),
            h(
              'p',
              { className: 'dsh-rc-muted' },
              status.enabled ? t('control.on') : t('control.off'),
            ),
          ),
          iconButton(status.enabled ? t('control.disable') : t('control.enable'), onToggle, {
            variant: status.enabled ? 'danger' : 'primary',
            disabled: busy || securityClosed,
          }),
        ),
        renderListenerFacts(t, status, securityClosed),
      ),
    )

    children.push(
      h(ConnectionCard, {
        key: 'connection-card',
        t,
        status,
        needsSelection,
        onChanged: refresh,
      }),
    )

    if (status.enabled && !securityClosed) {
      const activeLeaseDeviceId = status.deviceLock?.activeDeviceId ?? null
      const pairingDisabled: MessageKey | null = securityClosed
        ? 'pair.securityClosed'
        : needsSelection
          ? 'pair.selectionRequired'
          : activeLeaseDeviceId !== null
            ? 'pair.activeDeviceLocked'
            : effectiveConnection(status).listener.access === 'lan' &&
                effectiveConnection(status).listener.secure !== true
              ? 'pair.tlsRequired'
              : null
      const remaining = activePairing === null ? 0 : remainingSeconds(activePairing.expiresAt, now)
      children.push(
        renderPairingCard(t, {
          status,
          pairing: activePairing,
          remaining,
          qrUrl: activePairing === null ? null : qrUrl,
          busy,
          disabledReason: pairingDisabled,
          onCreate: onCreatePair,
          onDismiss: () => {
            setPairing(null)
            setPairingHidden(true)
          },
        }),
      )
    }

    children.push(renderDeviceLockCard(t, status, status.devices, now))
    // When the Host exposes the lease view it is the single source of truth;
    // `DeviceView.active` is only the legacy fallback used without it.
    const leaseView = status.deviceLock
    const activeDeviceId: string | null | undefined =
      leaseView !== undefined && leaseView !== null ? leaseView.activeDeviceId : undefined
    children.push(
      renderDevicesCard(
        t,
        status.devices,
        {
          busy,
          onActivate,
          onRelease,
          onRevoke,
          onRevokeAll,
        },
        activeDeviceId,
      ),
    )
    if (security !== undefined && security !== null) {
      children.push(renderSecurityCard(t, security))
    }
    children.push(renderAuditCard(t, status.audit ?? []))
    children.push(
      h(
        'div',
        { className: 'dsh-rc-card', key: 'info' },
        h('h3', { className: 'dsh-rc-card-title' }, t('info.title')),
        h(
          'div',
          { className: 'dsh-rc-kv' },
          kvRow(t('info.dshRelease'), status.dshRelease),
          kvRow(t('info.pluginVersion'), status.pluginVersion),
        ),
      ),
    )
  }

  return h(
    'section',
    { className: 'dsh-rc-panel' },
    h(
      'header',
      { className: 'dsh-rc-head' },
      h(
        'div',
        { className: 'dsh-rc-head-text' },
        h(
          'div',
          { className: 'dsh-rc-head-title-row' },
          h('span', { className: 'dsh-rc-brand-mark', 'aria-hidden': 'true' }),
          h('h2', { className: 'dsh-rc-title' }, t('panel.title')),
        ),
        h('p', { className: 'dsh-rc-subtitle' }, t('panel.subtitle')),
      ),
      h(
        'div',
        { className: 'dsh-rc-head-actions' },
        badge === null
          ? null
          : h('span', { className: 'dsh-rc-badge', 'data-tone': badge.tone }, badge.label),
        iconButton(t('emergency.stop'), onEmergencyStop, {
          variant: 'danger',
          small: true,
          disabled: busy || securityClosed || status === null,
        }),
      ),
    ),
    securityClosed && status !== null
      ? h(
          'p',
          { className: 'dsh-rc-muted', key: 'emergency-done' },
          t('emergency.done'),
        )
      : null,
    ...children,
    actionError !== null ? alertBlock('error', localizedFailure(t, actionError)) : null,
  )
}

function renderListenerFacts(
  t: TFn,
  status: AdminStatusEnvelope,
  securityClosed: boolean,
): ReactElement {
  const listener = effectiveConnection(status).listener
  const rows: ReactNode[] = [
    kvRow(t('listener.host'), listener.host ?? '—', 'host'),
    kvRow(t('listener.port'), listener.port === null ? '—' : String(listener.port), 'port'),
    kvRow(t('listener.protocol'), listener.protocol ?? (listener.secure ? 'https' : 'http'), 'protocol'),
    kvRow(t('listener.access'), listener.access ?? (listener.lan ? 'lan' : 'loopback'), 'access'),
    kvRow(t('listener.secure'), listener.secure ? t('yes') : t('no'), 'secure'),
    kvRow(t('listener.url'), listener.url ?? '—', 'url'),
  ]
  const children: ReactNode[] = [h('div', { className: 'dsh-rc-kv', key: 'kv' }, rows)]
  if (status.enabled && status.loopbackOnly && !securityClosed) {
    children.push(alertBlock('error', t('loopback.warning')))
  }
  return h('div', { className: 'dsh-rc-listener', key: 'listener' }, ...children)
}

/* -------------------------------------------------------------------------- */
/* Pairing-approval overlay (shell.overlay)                                   */
/* -------------------------------------------------------------------------- */

interface OverlayProps {
  t: TFn
}

function PairingOverlay({ t }: OverlayProps): ReactElement | null {
  const [pending, setPending] = React.useState<PairingView[]>([])
  const [busyId, setBusyId] = React.useState<string | null>(null)
  const [error, setError] = React.useState<RcFailure | null>(null)
  const [now, setNow] = React.useState<number>(() => Date.now())
  const pendingRef = React.useRef<PairingView[]>([])

  React.useEffect(() => {
    pendingRef.current = pending
  }, [pending])

  const refresh = React.useCallback(async (): Promise<void> => {
    if (!shouldPollPending(pendingRef.current.length)) return
    try {
      const response = await adminGet<{ pairings: PairingView[] }>(ADMIN_ROUTES.pending)
      setPending(claimedPairings(response.pairings))
    } catch {
      // polling failures stay silent; the panel shows the actionable error
    }
  }, [])

  React.useEffect(() => {
    void refresh()
    const poll = window.setInterval(() => void refresh(), PENDING_POLL_MS)
    const unsubscribe = subscribePendingWatch(() => void refresh())
    return () => {
      window.clearInterval(poll)
      unsubscribe()
    }
  }, [refresh])

  React.useEffect(() => {
    const tick = window.setInterval(() => setNow(Date.now()), 1_000)
    return () => window.clearInterval(tick)
  }, [])

  const decide = React.useCallback(
    async (pairing: PairingView, approve: boolean): Promise<void> => {
      if (typeof pairing.claimId !== 'string') return
      setBusyId(pairing.claimId)
      setError(null)
      try {
        await adminPost(
          approve ? ADMIN_ROUTES.pairApprove : ADMIN_ROUTES.pairDeny,
          { claimId: pairing.claimId },
        )
        setPending((current) => current.filter((entry) => entry.claimId !== pairing.claimId))
      } catch (failure) {
        setError(toFailure(failure))
      } finally {
        setBusyId(null)
      }
    },
    [],
  )

  const current = pending[0]
  if (current === undefined) return null

  const remaining = remainingSeconds(current.expiresAt, now)
  const busy = busyId !== null
  const extra: ReactNode[] = []
  if (pending.length > 1) {
    extra.push(
      h('p', { className: 'dsh-rc-muted', key: 'more' }, t('pending.more', { count: pending.length - 1 })),
    )
  }
  if (error !== null) {
    extra.push(alertBlock('error', `${t('pending.approveFailed')}: ${localizedFailure(t, error)}`))
  }

  return h(
    'div',
    { className: 'dsh-rc-overlay', role: 'presentation' },
    h(
      'div',
      {
        className: 'dsh-rc-modal',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-labelledby': 'dsh-rc-pairing-title',
      },
      h('h2', { className: 'dsh-rc-title', id: 'dsh-rc-pairing-title' }, t('pending.title')),
      h(
        'p',
        { className: 'dsh-rc-modal-body' },
        h('strong', { className: 'dsh-rc-device-name' }, current.deviceName),
        ' ',
        t('pending.body'),
      ),
      h(
        'div',
        { className: 'dsh-rc-kv' },
        kvRow(t('pending.platform'), current.platform),
        kvRow(t('pending.remaining'), `${remaining}`),
      ),
      ...extra,
      h(
        'div',
        { className: 'dsh-rc-modal-actions' },
        iconButton(t('pending.deny'), () => void decide(current, false), {
          variant: 'danger',
          disabled: busy,
        }),
        iconButton(t('pending.approve'), () => void decide(current, true), {
          variant: 'primary',
          disabled: busy || remaining <= 0,
        }),
      ),
    ),
  )
}

/* -------------------------------------------------------------------------- */
/* Plugin styles (injected once per page; removed when the plugin disposes)    */
/* -------------------------------------------------------------------------- */

const PANEL_STYLES = `.dsh-rc-panel,.dsh-rc-overlay{
  --rc-brand:var(--dsw-alias-brand-primary-new-colorprimary-new-color,#4176e6);
  --rc-brand-strong:var(--dsw-alias-state-business-primary,#4176e6);
  --rc-brand-soft:var(--dsw-alias-state-business-tertiary,#e4edfd);
  --rc-bubble:var(--dsw-specific-bubble,#edf3fe);
  --rc-surface:var(--dsw-alias-bg-layer-1,#fff);
  --rc-surface-2:var(--dsw-alias-bg-layer-2,#f9fafb);
  --rc-surface-3:var(--dsw-alias-bg-layer-3,#f1f3f5);
  --rc-border:var(--dsw-alias-border-l2,#0000001a);
  --rc-border-strong:var(--dsw-alias-border-l4,#00000029);
  --rc-text:var(--dsw-alias-label-primary,#0f1115);
  --rc-text-2:var(--dsw-alias-label-secondary,#61666b);
  --rc-text-3:var(--dsw-alias-label-tertiary,#81858c);
  --rc-ok:var(--dsw-alias-state-success-primary,#22c55e);
  --rc-warn:var(--dsw-alias-state-warn-primary,#f59e0b);
  --rc-danger:var(--dsw-alias-state-error-primary,#ec1313);
  --rc-btn-bg:var(--dsw-alias-button-primary-fill,#0f1115);
  --rc-btn-hover:var(--dsw-alias-button-primary-hover,#3c3c3d);
  --rc-btn-fg:var(--dsw-alias-label-primary-inverted,#fff);
  --rc-hover:var(--dsw-alias-interactive-bg-hover,#2631480f);
  --rc-radius-xs:var(--dsw-radius-xs,4px);
  --rc-radius-sm:var(--dsw-radius-sm,8px);
  --rc-radius-md:var(--dsw-radius-md,12px);
  --rc-radius-lg:var(--dsw-radius-lg,16px);
  --rc-radius-panel:var(--dsw-radius-panel,28px);
  --rc-font:var(--dsw-font-family,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Helvetica Neue",Helvetica,Arial,sans-serif);
  --rc-font-brand:var(--dsw-font-family-brand,"Montserrat",var(--rc-font));
  --rc-mono:var(--ds-font-family-code,"SF Mono","JetBrains Mono","Fira Code",Consolas,"Liberation Mono",Menlo,monospace);
  --rc-ring:var(--dsw-focus-ring-width,2px) solid var(--dsw-focus-ring-color,var(--rc-brand-strong));
  --rc-elev:var(--dsw-elevation-panel,0 0 0 .5px var(--rc-border-strong),0 3px 8px #00000008,0 0 16px #00000005);
  --rc-elev-prominent:var(--dsw-elevation-prominent,0 0 0 .5px var(--rc-border-strong),0 3px 8px #0000000a,0 0 20px #0000000d);
  --rc-ease:var(--ds-ease-in-out,cubic-bezier(.4,0,.2,1));
  --rc-dur:var(--ds-transition-duration,.2s);
}
.dsh-rc-panel{
  display:flex;flex-direction:column;gap:18px;padding:4px 2px 32px;
  color:var(--rc-text);font:400 14px/22px var(--rc-font);
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
}
@media (prefers-reduced-motion:reduce){.dsh-rc-panel *{transition:none!important;animation:none!important}}
.dsh-rc-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:2px 2px 0}
.dsh-rc-head-text{display:flex;flex-direction:column;gap:6px;min-width:0}
.dsh-rc-head-title-row{display:flex;align-items:center;gap:12px;min-width:0}
.dsh-rc-brand-mark{position:relative;flex:none;width:34px;height:34px;border-radius:12px;background:linear-gradient(140deg,var(--rc-brand-strong),color-mix(in srgb,var(--rc-brand) 60%,#7aaaff));box-shadow:0 1px 2px #0000001f,inset 0 1px 0 #ffffff40;display:grid;place-items:center}
.dsh-rc-brand-mark::before,.dsh-rc-brand-mark::after{content:"";position:absolute;border-radius:50%;border:2px solid #fff;box-sizing:border-box}
.dsh-rc-brand-mark::before{width:13px;height:13px;left:8px;top:9px;opacity:.95}
.dsh-rc-brand-mark::after{width:9px;height:9px;right:7px;bottom:8px;opacity:.72}
.dsh-rc-title{margin:0;font:500 20px/28px var(--rc-font-brand);letter-spacing:-.01em;color:var(--rc-text)}
.dsh-rc-subtitle{margin:0;font-size:13px;line-height:20px;color:var(--rc-text-2);max-width:68ch}
.dsh-rc-head-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}
.dsh-rc-muted{margin:0;font-size:12.5px;line-height:20px;color:var(--rc-text-3)}
.dsh-rc-badge{--tone:var(--rc-text-3);align-self:flex-start;display:inline-flex;align-items:center;gap:6px;border-radius:999px;border:.5px solid color-mix(in srgb,var(--tone) 30%,transparent);background:color-mix(in srgb,var(--tone) 9%,var(--rc-surface));padding:2px 10px;font-size:12px;line-height:18px;font-weight:600;white-space:nowrap;color:var(--tone)}
.dsh-rc-badge[data-tone=off]{--tone:var(--rc-text-3)}
.dsh-rc-badge[data-tone=loopback]{--tone:var(--rc-warn)}
.dsh-rc-badge[data-tone=lan]{--tone:var(--rc-brand-strong)}
.dsh-rc-badge[data-tone=ready]{--tone:var(--rc-ok)}
.dsh-rc-badge[data-tone=info]{--tone:var(--rc-brand-strong)}
.dsh-rc-badge[data-tone=warn]{--tone:var(--rc-warn)}
.dsh-rc-badge[data-tone=closed]{background:var(--rc-danger);border-color:transparent;color:#fff}
.dsh-rc-chip{--tone:var(--rc-text-2);display:inline-flex;align-items:center;gap:6px;max-width:100%;border-radius:999px;border:.5px solid var(--rc-border);background:var(--rc-surface-2);padding:2px 10px;font-size:12px;line-height:18px;color:var(--tone);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dsh-rc-chip[data-tone=ok]{--tone:var(--rc-ok);background:color-mix(in srgb,var(--rc-ok) 9%,var(--rc-surface))}
.dsh-rc-chip[data-tone=warn]{--tone:var(--rc-warn);background:color-mix(in srgb,var(--rc-warn) 10%,var(--rc-surface))}
.dsh-rc-chip[data-tone=brand]{--tone:var(--rc-brand-strong);background:color-mix(in srgb,var(--rc-brand-strong) 9%,var(--rc-surface));border-color:color-mix(in srgb,var(--rc-brand-strong) 24%,transparent)}
.dsh-rc-card{display:flex;flex-direction:column;gap:12px;border:.5px solid var(--rc-border);border-radius:var(--rc-radius-lg);padding:16px 18px;background:var(--rc-surface);box-shadow:var(--rc-elev)}
.dsh-rc-card-title{margin:0;font-size:15px;line-height:22px;font-weight:600;letter-spacing:-.005em;color:var(--rc-text)}
.dsh-rc-hero{position:relative;gap:14px;overflow:hidden;background:radial-gradient(120% 160% at 100% 0%,color-mix(in srgb,var(--rc-brand) 10%,transparent),transparent 58%),var(--rc-surface);border-color:color-mix(in srgb,var(--rc-brand) 18%,var(--rc-border))}
.dsh-rc-hero[data-state=ready]{border-color:color-mix(in srgb,var(--rc-ok) 26%,var(--rc-border))}
.dsh-rc-hero[data-state=closed]{border-color:color-mix(in srgb,var(--rc-danger) 30%,var(--rc-border))}
.dsh-rc-hero-head{display:flex;align-items:flex-start;gap:10px}
.dsh-rc-hero-title{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1}
.dsh-rc-hero-title .dsh-rc-card-title{font-size:15px}
.dsh-rc-hero-chips{display:flex;flex-wrap:wrap;gap:6px;min-width:0}
.dsh-rc-status-dot{flex:none;width:10px;height:10px;margin-top:7px;border-radius:50%;background:var(--rc-text-3);box-shadow:0 0 0 4px color-mix(in srgb,var(--rc-text-3) 14%,transparent)}
.dsh-rc-status-dot[data-tone=ready]{background:var(--rc-ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--rc-ok) 18%,transparent)}
.dsh-rc-status-dot[data-tone=warn]{background:var(--rc-warn);box-shadow:0 0 0 4px color-mix(in srgb,var(--rc-warn) 18%,transparent);animation:rc-pulse 1.9s var(--rc-ease) infinite}
.dsh-rc-status-dot[data-tone=info]{background:var(--rc-brand-strong);box-shadow:0 0 0 4px color-mix(in srgb,var(--rc-brand-strong) 18%,transparent)}
.dsh-rc-status-dot[data-tone=closed]{background:var(--rc-danger);box-shadow:0 0 0 4px color-mix(in srgb,var(--rc-danger) 18%,transparent)}
@keyframes rc-pulse{0%,100%{opacity:1}50%{opacity:.45}}
.dsh-rc-row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.dsh-rc-grow{display:flex;flex-direction:column;gap:2px;min-width:0}
.dsh-rc-kv{display:flex;flex-direction:column;gap:0}
.dsh-rc-kv-row{display:flex;align-items:baseline;justify-content:space-between;gap:18px;padding:6px 0;font-size:13px;line-height:20px;border-bottom:.5px solid color-mix(in srgb,var(--rc-border) 62%,transparent)}
.dsh-rc-kv-row:last-child{border-bottom:0}
.dsh-rc-hero .dsh-rc-kv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 28px;border-top:.5px solid var(--rc-border);padding-top:8px;margin-top:2px}
.dsh-rc-hero .dsh-rc-kv-row[data-kv=publicOrigin],.dsh-rc-hero .dsh-rc-kv-row[data-kv=qrOrigin],.dsh-rc-hero .dsh-rc-kv-row[data-kv=serviceUrl]{grid-column:1/-1}
@media (max-width:640px){.dsh-rc-hero .dsh-rc-kv{grid-template-columns:minmax(0,1fr)}}
.dsh-rc-hero .dsh-rc-kv-row{padding:5px 0}
.dsh-rc-kv-key{color:var(--rc-text-3);white-space:nowrap}
.dsh-rc-kv-value{color:var(--rc-text);text-align:right;word-break:break-all;font:500 12px/20px var(--rc-mono)}
.dsh-rc-btn{appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 14px;border:.5px solid var(--rc-border-strong);border-radius:var(--rc-radius-md);background:transparent;color:var(--rc-text);font:500 13px/20px var(--rc-font);cursor:pointer;transition:background-color var(--rc-dur) var(--rc-ease),border-color var(--rc-dur) var(--rc-ease),color var(--rc-dur) var(--rc-ease),opacity var(--rc-dur) var(--rc-ease)}
.dsh-rc-btn:hover:not(:disabled){background:var(--rc-hover);border-color:var(--rc-border-strong)}
.dsh-rc-btn:active:not(:disabled){transform:translateY(.5px)}
.dsh-rc-btn:focus-visible{outline:var(--rc-ring);outline-offset:2px}
.dsh-rc-btn:disabled{opacity:.42;cursor:default}
.dsh-rc-btn-small{height:28px;padding:0 10px;font-size:12px;border-radius:var(--rc-radius-sm)}
.dsh-rc-btn[data-variant=primary]{background:var(--rc-btn-bg);border-color:transparent;color:var(--rc-btn-fg);font-weight:600}
.dsh-rc-btn[data-variant=primary]:hover:not(:disabled){background:var(--rc-btn-hover);border-color:transparent}
.dsh-rc-btn[data-variant=accent]{background:var(--rc-brand-strong);border-color:transparent;color:var(--dsw-alias-label-primary-inverted,#fff);font-weight:600}
.dsh-rc-btn[data-variant=accent]:hover:not(:disabled){background:color-mix(in srgb,var(--rc-brand-strong) 88%,#fff);border-color:transparent}
.dsh-rc-btn[data-variant=danger]{color:var(--rc-danger);border-color:color-mix(in srgb,var(--rc-danger) 34%,transparent)}
.dsh-rc-btn[data-variant=danger]:hover:not(:disabled){background:color-mix(in srgb,var(--rc-danger) 9%,transparent);border-color:color-mix(in srgb,var(--rc-danger) 46%,transparent)}
.dsh-rc-btn[data-variant=danger-solid]{background:var(--rc-danger);border-color:transparent;color:#fff;font-weight:600}
.dsh-rc-btn[data-variant=danger-solid]:hover:not(:disabled){background:color-mix(in srgb,var(--rc-danger) 88%,#000);border-color:transparent}
.dsh-rc-actions{display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-wrap:wrap}
.dsh-rc-alert{display:flex;align-items:center;justify-content:space-between;gap:10px;border-radius:var(--rc-radius-md);border:.5px solid transparent;padding:9px 13px;font-size:13px;line-height:20px}
.dsh-rc-alert[data-tone=error]{background:color-mix(in srgb,var(--rc-danger) 8%,var(--rc-surface));border-color:color-mix(in srgb,var(--rc-danger) 26%,transparent);color:var(--rc-danger)}
.dsh-rc-alert[data-tone=warn]{background:color-mix(in srgb,var(--rc-warn) 9%,var(--rc-surface));border-color:color-mix(in srgb,var(--rc-warn) 26%,transparent);color:color-mix(in srgb,var(--rc-warn) 72%,var(--rc-text))}
.dsh-rc-alert[data-tone=info]{background:color-mix(in srgb,var(--rc-brand-strong) 7%,var(--rc-surface));border-color:color-mix(in srgb,var(--rc-brand-strong) 22%,transparent);color:var(--rc-brand-strong)}
.dsh-rc-alert-text{flex:1;min-width:0;word-break:break-word;white-space:pre-wrap}
.dsh-rc-pair{display:flex;align-items:flex-start;gap:20px;flex-wrap:wrap}
.dsh-rc-qr{width:224px;height:224px;background:#fff;border-radius:var(--rc-radius-lg);padding:10px;box-sizing:border-box;image-rendering:pixelated;object-fit:contain;border:.5px solid var(--rc-border);box-shadow:var(--rc-elev)}
.dsh-rc-qr-placeholder{display:flex;align-items:center;justify-content:center;width:224px;height:224px;border:1px dashed var(--rc-border-strong);border-radius:var(--rc-radius-lg);background:var(--rc-surface-2)}
.dsh-rc-pair-info{display:flex;flex-direction:column;gap:10px;flex:1;min-width:190px}
.dsh-rc-pairing-title{font-size:13px;font-weight:600;color:var(--rc-text-2);margin:0}
.dsh-rc-table-wrap{overflow-x:auto;border:.5px solid var(--rc-border);border-radius:var(--rc-radius-md);background:var(--rc-surface)}
.dsh-rc-table{width:100%;border-collapse:separate;border-spacing:0;font-size:12.5px}
.dsh-rc-table th,.dsh-rc-table td{text-align:left;padding:8px 12px;border-bottom:.5px solid var(--rc-border);vertical-align:top}
.dsh-rc-table th{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--rc-text-3);white-space:nowrap;background:var(--rc-surface-2);position:sticky;top:0}
.dsh-rc-table tbody tr:last-child td{border-bottom:0}
.dsh-rc-table tbody tr:hover td{background:color-mix(in srgb,var(--rc-hover) 70%,transparent)}
.dsh-rc-table-action{text-align:right;white-space:nowrap}
.dsh-rc-audit{max-height:340px;overflow:auto}
.dsh-rc-audit .dsh-rc-table td{font-size:12px}
.dsh-rc-audit-ua{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--rc-mono);font-size:11px}
.dsh-rc-audit-detail{max-width:300px;word-break:break-word}
.dsh-rc-audit tr[data-result=rejected] td{color:color-mix(in srgb,var(--rc-warn) 74%,var(--rc-text))}
.dsh-rc-audit tr[data-result=failed] td{color:var(--rc-danger)}
.dsh-rc-methods{display:grid;grid-template-columns:repeat(auto-fit,minmax(228px,1fr));gap:10px}
.dsh-rc-method{display:flex;gap:10px;align-items:flex-start;border:.5px solid var(--rc-border);border-radius:var(--rc-radius-md);padding:12px 14px;cursor:pointer;background:var(--rc-surface);transition:background-color var(--rc-dur) var(--rc-ease),border-color var(--rc-dur) var(--rc-ease),box-shadow var(--rc-dur) var(--rc-ease)}
.dsh-rc-method:hover{background:var(--rc-surface-2);border-color:var(--rc-border-strong)}
.dsh-rc-method[data-checked=true]{border-color:transparent;background:color-mix(in srgb,var(--rc-brand-strong) 6%,var(--rc-surface));box-shadow:inset 0 0 0 1.5px var(--rc-brand-strong)}
.dsh-rc-method input{appearance:none;flex:none;width:16px;height:16px;margin:3px 0 0;border:.5px solid var(--rc-border-strong);border-radius:50%;background:var(--rc-surface);cursor:pointer;transition:border-color var(--rc-dur) var(--rc-ease),box-shadow var(--rc-dur) var(--rc-ease)}
.dsh-rc-method input:hover{border-color:var(--rc-brand-strong)}
.dsh-rc-method input:checked{border-color:var(--rc-brand-strong);box-shadow:inset 0 0 0 4px var(--rc-brand-strong)}
.dsh-rc-method input:focus-visible{outline:var(--rc-ring);outline-offset:2px}
.dsh-rc-method-text{display:flex;flex-direction:column;gap:3px;min-width:0}
.dsh-rc-method-title{font-weight:600;font-size:13.5px}
.dsh-rc-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.dsh-rc-field{display:flex;flex-direction:column;gap:6px;min-width:0}
.dsh-rc-field-label{font-size:12px;font-weight:500;color:var(--rc-text-2)}
.dsh-rc-input{height:34px;border:.5px solid var(--rc-border-strong);border-radius:var(--rc-radius-md);padding:0 12px;background:var(--rc-surface-3);color:var(--rc-text);font:inherit;font-size:13px;min-width:0;transition:border-color var(--rc-dur) var(--rc-ease),box-shadow var(--rc-dur) var(--rc-ease),background-color var(--rc-dur) var(--rc-ease)}
.dsh-rc-input:hover:not(:disabled){border-color:color-mix(in srgb,var(--rc-border-strong) 78%,var(--rc-text-3))}
.dsh-rc-input:focus-visible,.dsh-rc-input:focus{outline:none;border-color:var(--rc-brand-strong);box-shadow:0 0 0 3px color-mix(in srgb,var(--rc-brand-strong) 16%,transparent);background:var(--rc-surface)}
.dsh-rc-input:disabled{color:var(--rc-text-3);cursor:default}
.dsh-rc-checkbox{display:flex;gap:8px;align-items:center;font-size:13px;cursor:pointer}
.dsh-rc-checkbox input{accent-color:var(--rc-brand-strong);cursor:pointer}
.dsh-rc-checkbox input:focus-visible{outline:var(--rc-ring);outline-offset:2px}
.dsh-rc-plan{display:flex;flex-direction:column;gap:14px;border:.5px solid color-mix(in srgb,var(--rc-brand-strong) 26%,var(--rc-border));border-radius:var(--rc-radius-lg);padding:16px 18px;background:radial-gradient(110% 140% at 0% 0%,color-mix(in srgb,var(--rc-brand) 7%,transparent),transparent 60%),var(--rc-surface)}
.dsh-rc-subtitle+.dsh-rc-steps{margin-top:2px}
.dsh-rc-steps{display:flex;flex-direction:column;gap:8px;margin:0;padding:0;list-style:none}
.dsh-rc-step{display:flex;flex-direction:column;gap:5px;border:.5px solid var(--rc-border);border-left:2px solid var(--rc-brand-strong);border-radius:var(--rc-radius-md);padding:10px 12px;background:var(--rc-surface-2)}
.dsh-rc-step[data-kind=warning]{border-left-color:var(--rc-warn)}
.dsh-rc-step[data-kind=security]{border-left-color:var(--rc-danger)}
.dsh-rc-step[data-kind=download]{border-left-color:var(--rc-warn)}
.dsh-rc-step[data-kind=access]{border-left-color:var(--rc-brand-strong)}
.dsh-rc-step[data-kind=tls]{border-left-color:var(--rc-ok)}
.dsh-rc-step-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.dsh-rc-step-kind{display:inline-flex;align-items:center;border-radius:var(--rc-radius-xs);background:var(--rc-surface);border:.5px solid var(--rc-border);padding:1px 7px;font-size:10.5px;line-height:16px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--rc-text-3)}
.dsh-rc-step-text{margin:0;font-size:13px;line-height:20px;color:var(--rc-text);white-space:pre-wrap;word-break:break-word}
.dsh-rc-step-params{display:flex;flex-wrap:wrap;gap:6px 10px;font-size:11.5px}
.dsh-rc-param{display:inline-flex;gap:6px;align-items:baseline;min-width:0;border-radius:var(--rc-radius-xs);background:var(--rc-surface);border:.5px solid var(--rc-border);padding:1px 7px}
.dsh-rc-param-key{color:var(--rc-text-3)}
.dsh-rc-param-value{font-family:var(--rc-mono);word-break:break-all;color:var(--rc-text)}
.dsh-rc-plan-download{display:flex;flex-direction:column;gap:10px;border:.5px dashed var(--rc-border-strong);border-radius:var(--rc-radius-md);padding:12px 14px;background:var(--rc-surface-2)}
.dsh-rc-closed{display:flex;flex-direction:column;gap:8px;border:.5px solid color-mix(in srgb,var(--rc-danger) 32%,var(--rc-border));border-radius:var(--rc-radius-lg);padding:16px 18px;background:color-mix(in srgb,var(--rc-danger) 7%,var(--rc-surface))}
.dsh-rc-closed-title{margin:0;font-size:14px;font-weight:650;color:var(--rc-danger)}
.dsh-rc-closed-body{margin:0;font-size:13px;line-height:20px;color:var(--rc-text)}
.dsh-rc-listener{display:flex;flex-direction:column;gap:10px}
.dsh-rc-overlay{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;padding:24px;background:var(--dsw-alias-bg-mask-1,#0000003d);backdrop-filter:var(--dsw-mask-blur,blur(8px) saturate(1.1));animation:rc-fade var(--rc-dur) var(--rc-ease)}
.dsh-rc-modal{position:relative;display:flex;flex-direction:column;gap:12px;width:min(460px,100%);max-height:min(620px,90vh);overflow-y:auto;border:.5px solid var(--rc-border);border-radius:var(--rc-radius-panel);padding:24px;background:var(--rc-surface);color:var(--rc-text);box-shadow:var(--rc-elev-prominent);animation:rc-pop var(--rc-dur) var(--rc-ease)}
.dsh-rc-modal::before{content:"";width:34px;height:34px;border-radius:12px;background:linear-gradient(140deg,var(--rc-brand-strong),color-mix(in srgb,var(--rc-brand) 60%,#7aaaff));margin-bottom:2px;box-shadow:0 1px 2px #0000001f,inset 0 1px 0 #ffffff40}
.dsh-rc-modal .dsh-rc-title{font-size:18px;line-height:26px;font-weight:600}
.dsh-rc-modal-body{margin:0;font-size:14px;line-height:22px;color:var(--rc-text-2)}
.dsh-rc-device-name{font-weight:600;color:var(--rc-text)}
.dsh-rc-modal-actions{display:flex;justify-content:flex-end;gap:10px;flex-wrap:wrap;padding-top:6px}
@keyframes rc-fade{from{opacity:0}to{opacity:1}}
@keyframes rc-pop{from{opacity:0;transform:translateY(6px) scale(.985)}to{opacity:1;transform:none}}
.dsh-rc-connection{display:flex;flex-direction:column;gap:18px}
`

function injectStyles(): () => void {
  if (typeof document === 'undefined') return () => {}
  const existing = document.querySelector(`style[data-dsh-remote-control="${STYLE_ELEMENT_ID}"]`)
  if (existing !== null) return () => {}
  const element = document.createElement('style')
  element.dataset['dshRemoteControl'] = STYLE_ELEMENT_ID
  element.textContent = PANEL_STYLES
  document.head.appendChild(element)
  return () => {
    element.remove()
  }
}

/* -------------------------------------------------------------------------- */
/* Cordis client plugin entry points                                          */
/* -------------------------------------------------------------------------- */

/**
 * Services this client plugin needs from the shell.
 *
 * Must be a plain array: Cordis resolves `plugin.inject` with
 * `Inject.resolve()`, which treats a function value as an empty dependency map
 * (the shipped client plugins export an array for the same reason).
 */
export const inject = ['slots', 'locale']

/** Install the Settings panel, the pairing overlay and their styles. */
export function apply(ctx: RcClientContext): void {
  try {
    ctx.effect(() => ctx.locale.register(NAMESPACE, DICTIONARIES), `${NAMESPACE}: dictionaries`)
    ctx.effect(() => injectStyles(), `${NAMESPACE}: panel styles`)
    const t = ctx.locale.bind(NAMESPACE) as TFn
    ctx.slots.inject(SETTINGS_SECTION_SLOT, () =>
      ctx.slots.register(
        {
          name: SETTINGS_SECTION_SLOT,
          id: NAMESPACE,
          order: 35,
          label: () => t('nav'),
          locale: NAMESPACE,
        },
        () => h(RemoteControlSection, { t }),
      ),
    )
    ctx.slots.inject(OVERLAY_SLOT, () =>
      ctx.slots.register(
        {
          name: OVERLAY_SLOT,
          id: OVERLAY_ID,
          order: 100,
          locale: NAMESPACE,
        },
        () => h(PairingOverlay, { t }),
      ),
    )
  } catch (error) {
    // A client plugin must never throw into the shell boot.
    console.error('[dsh-remote-control] client plugin failed to apply', error)
  }
}
