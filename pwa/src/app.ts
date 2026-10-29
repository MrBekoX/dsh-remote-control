/**
 * DSH Remote Control — phone PWA application.
 *
 * A small vanilla-TypeScript mobile client for the plugin's own HTTP listener:
 *
 * - `#/pair?c=<code>`    pairing claim + 1 s approval polling
 * - `#/sessions`         normalized session list (pull/refresh, running dots)
 * - `#/sessions/:id`     live transcript over `/rc/ws` (`follow` stream), older
 *                        pages through `GET /rc/api/sessions/:id/page`,
 *                        prompt/steer composer, cancel, approval relay
 *
 * Security rules enforced here:
 * - every dynamic string is written with `textContent` / `createElement`
 *   (`innerHTML`, `insertAdjacentHTML`, `eval`, `new Function` are never used);
 * - no token material is persisted — sessions live in HttpOnly cookies, and the
 *   short-lived pairing `pollToken` stays in memory only;
 * - the service worker is registered only in a secure context (see `sw.ts`).
 *
 * Wire contract: `./protocol.ts` → `src/shared/protocol.ts`.
 */

import {
  PROTOCOL_VERSION,
  RC_API_PATH,
  RC_CSRF_HEADER,
  RC_HEARTBEAT,
  RC_LIMITS,
  RC_STREAM_FOLLOW,
  RC_WS_CLOSE,
  RC_WS_PATH,
} from './protocol.js'
import type {
  AnswerResultFrame,
  AnswerOutcome,
  ApprovalCancelFrame,
  ApprovalDecision,
  ApprovalFrame,
  ApprovalView,
  ClientFrame,
  CreateSessionResponse,
  DeviceView,
  HealthResponse,
  PageRequest,
  PairClaimResponse,
  PairStatusResponse,
  PairingState,
  PongFrame,
  PromptContentPart,
  PromptRequest,
  PromptResponse,
  ReadyFrame,
  ServerFrame,
  SessionAttachmentResponse,
  SessionEventRecord,
  SessionPageResponse,
  SessionProjectionsResponse,
  SessionSummary,
  SessionsResponse,
  SnapshotFrame,
  StateResponse,
  UploadFileResponse,
  WorkspaceGroupView,
} from './protocol.js'
import { renderMarkdown } from './markdown.js'

/* -------------------------------------------------------------------------- */
/* i18n (en/tr; key set parity is enforced by the Record type)                */
/* -------------------------------------------------------------------------- */

const en = {
  'app.title': 'DSH Remote Control',
  'nav.sessions': 'Sessions',
  'nav.back': 'Back',
  'nav.reload': 'Reload',
  'pair.title': 'Pair this phone',
  'pair.claiming': 'Pairing…',
  'pair.waitingApproval': 'Waiting for the desktop to approve this phone…',
  'pair.approved': 'Paired. Opening sessions…',
  'pair.denied': 'The desktop denied this pairing request.',
  'pair.expired': 'The pairing code expired. Create a new QR code on the desktop.',
  'pair.invalid': 'Invalid or already used pairing code.',
  'pair.deviceLimit': 'The maximum number of paired devices was reached. Revoke a device on the desktop.',
  'pair.rateLimited': 'Too many attempts. Try again in {seconds}s.',
  'pair.failed': 'Pairing failed',
  'pair.retry': 'Try again',
  'pair.noCodeTitle': 'Scan the desktop QR code',
  'pair.noCodeBody':
    'Open Settings → Remote Control → Pair device on the desktop and scan the QR code with this phone.',
  'pair.disabled': 'Remote Control is disabled on the desktop. Enable it before pairing.',
  'pair.disabledTitle': 'Remote Control is disabled',
  'pair.securityClosedTitle': 'Remote access is closed',
  'pair.securityClosedBody':
    'Remote access was closed by a security shutdown. Re-enable Remote Control on the desktop, then scan a new QR code.',
  'pair.deviceLocked':
    'Another device is currently the active device. The desktop must activate this phone (single-device lock) before it can connect.',
  'pair.tlsTitle': 'HTTPS is required for this LAN address',
  'pair.tlsRequired':
    'This LAN address needs a trusted HTTPS certificate before a phone can pair. Fix the TLS setup on the desktop.',
  'pair.accessRequiredTitle': 'Cloudflare Access sign-in required',
  'pair.accessRequiredBody':
    'Complete the Cloudflare Access sign-in in this browser, then reload this page. Remote Control never asks for Access credentials.',
  'lock.active': 'This phone is the active device',
  'lock.otherDevice': 'Another device is active',
  'lock.selectionRequired': 'Desktop must choose the active device',
  'lock.none': 'No active device',
  'lock.idleFooter': 'Idle timeout: {time}',
  'lock.idleWarning': 'Idle timeout closes remote access in {minutes} min.',
  'lock.idleExpiredTitle': 'Idle timeout',
  'lock.idleExpiredBody':
    'Remote access closed because the phone was idle. Re-enable Remote Control on the desktop and pair again.',
  'lock.leaseLostTitle': 'Active device changed',
  'lock.leaseLostBody':
    'Another device is now the active device. Ask the desktop to activate this phone again, then reload.',
  'security.title': 'Remote access is closed',
  'security.body':
    'Remote access was closed by the security shutdown. Re-enable Remote Control on the desktop to continue.',
  'access.title': 'Cloudflare Access sign-in required',
  'access.body':
    'Complete the Cloudflare Access sign-in for this origin, then reload this page. No Access credentials are stored in this app.',
  'sessions.locked': 'Another device is the active device.',
  'sessions.selectionRequired': 'The desktop must pick the active device.',
  'sessions.title': 'Sessions',
  'sessions.empty': 'No sessions yet.',
  'sessions.error': 'Could not load sessions.',
  'sessions.running': 'running',
  'sessions.idle': 'idle',
  'sessions.blank': 'new',
  'sessions.updated': 'Updated {time}',
  'sessions.unpair': 'Unpair this phone',
  'sessions.unpairConfirm': 'Unpair this phone? It will need a new QR code to reconnect.',
  'sessions.unpairDone': 'This phone was unpaired.',
  'auth.title': 'Pair again',
  'auth.body':
    'This phone is no longer paired. Open Settings → Remote Control on the desktop and scan a new QR code.',
  'auth.pair': 'Pair again',
  'session.notFound': 'Session not found.',
  'session.error': 'Could not load this session.',
  'session.older': 'Load older messages',
  'session.noOlder': 'Start of session',
  'session.olderError': 'Could not load older messages.',
  'session.gap': 'Transcript gap detected — reloading…',
  'session.streamError': 'Live stream error.',
  'conn.connecting': 'Connecting…',
  'conn.connected': 'Connected',
  'conn.reconnecting': 'Reconnecting…',
  'conn.offline': 'Disconnected',
  'conn.disconnectedHint': 'No connection — the agent may still be running.',
  'conn.drain': 'Host is restarting…',
  'role.you': 'You',
  'role.assistant': 'Assistant',
  'role.tool': 'Tool',
  'turn.stopped': 'Turn stopped',
  'turn.failed': 'Turn failed',
  'tool.arguments': 'arguments',
  'composer.placeholder': 'Send a prompt…',
  'composer.send': 'Send',
  'composer.queue': 'Queue',
  'composer.steer': 'Steer',
  'composer.stop': 'Stop',
  'composer.stopConfirm': 'Stop the running turn?',
  'composer.stopped': 'Cancellation requested.',
  'composer.stopError': 'Could not cancel the turn.',
  'composer.sent': 'Sent',
  'composer.sendError': 'Could not send the prompt.',
  'composer.empty': 'Write a message first.',
  'composer.tooLong': 'Message is too long (max {count} characters).',
  'approval.title': 'Approval needed',
  'approval.questionTitle': 'Question from the agent',
  'approval.tool': 'Tool',
  'approval.allowOnce': 'Allow once',
  'approval.reject': 'Reject',
  'approval.expires': '{seconds}s left',
  'approval.expired': 'Expired',
  'approval.answered': 'Answered',
  'approval.answeredElsewhere': 'Answered on another device',
  'approval.cancelled': 'Request cancelled',
  'approval.sendError': 'Could not send the answer.',
  'approval.sending': 'Sending…',
  'approval.delivered': 'Answer delivered.',
  'approval.ackTimeout': 'No confirmation from the desktop; try again.',
  'approval.desktopOnly': 'Answer this question on the desktop.',
  'approval.queuePlaceholder': 'No pending approvals.',
  'reasoning.title': 'Reasoning',
  'home.title': 'How can I help you today?',
  'home.subtitle': 'Ask anything — attach an image or a file when it helps.',
  'nav.menu': 'Menu',
  'nav.newChat': 'New chat',
  'drawer.history': 'History',
  'drawer.empty': 'No sessions yet.',
  'workspace.default': 'Default workspace',
  'workspace.other': 'Other sessions',
  'composer.attach': 'Attach image or file',
  'composer.attachHint': 'Images are sent inline; other files are uploaded first.',
  'attach.image': 'Image',
  'attach.file': 'File',
  'attach.uploading': 'Uploading…',
  'attach.failed': 'Could not attach the file.',
  'attach.tooLarge': 'Attachment is too large (max {size}).',
  'attach.remove': 'Remove attachment',
  'session.newTitle': 'New chat',
  'sessions.refreshing': 'Refreshing…',
  'sessions.refreshed': 'List refreshed.',
  'lang.switch': 'Switch language',
  'footer.version': 'DSH Remote Control',
} as const

type MessageKey = keyof typeof en

const tr: Record<MessageKey, string> = {
  'app.title': 'DSH Uzaktan Kontrol',
  'nav.sessions': 'Oturumlar',
  'nav.back': 'Geri',
  'nav.reload': 'Yenile',
  'pair.title': 'Bu telefonu eşle',
  'pair.claiming': 'Eşleştiriliyor…',
  'pair.waitingApproval': 'Masaüstünün bu telefonu onaylaması bekleniyor…',
  'pair.approved': 'Eşleşti. Oturumlar açılıyor…',
  'pair.denied': 'Masaüstü bu eşleşme isteğini reddetti.',
  'pair.expired': 'Eşleşme kodunun süresi doldu. Masaüstünde yeni bir QR kod oluşturun.',
  'pair.invalid': 'Geçersiz veya kullanılmış eşleşme kodu.',
  'pair.deviceLimit':
    'Eşleşmiş cihaz sınırına ulaşıldı. Masaüstünde bir cihazın eşleşmesini kaldırın.',
  'pair.rateLimited': 'Çok fazla deneme. {seconds} sn sonra tekrar deneyin.',
  'pair.failed': 'Eşleştirme başarısız',
  'pair.retry': 'Tekrar dene',
  'pair.noCodeTitle': 'Masaüstündeki QR kodunu okutun',
  'pair.noCodeBody':
    'Masaüstünde Ayarlar → Uzaktan Kontrol → Cihaz eşle bölümünü açın ve QR kodunu bu telefonla okutun.',
  'pair.disabled': 'Uzaktan Kontrol masaüstünde kapalı. Eşleştirmeden önce etkinleştirin.',
  'pair.disabledTitle': 'Uzaktan Kontrol kapalı',
  'pair.securityClosedTitle': 'Uzaktan erişim kapalı',
  'pair.securityClosedBody':
    'Uzaktan erişim güvenlik nedeniyle kapatıldı. Masaüstünde Uzaktan Kontrol’ü yeniden etkinleştirin ve yeni QR kodunu okutun.',
  'pair.deviceLocked':
    'Şu anda başka bir cihaz etkin. Bu telefonun bağlanabilmesi için masaüstünün bu telefonu etkinleştirmesi gerekir (tek cihaz kilidi).',
  'pair.tlsTitle': 'Bu LAN adresi için HTTPS gerekli',
  'pair.tlsRequired':
    'Bu LAN adresi için güvenilir bir HTTPS sertifikası gerekiyor. Masaüstünde TLS kurulumunu tamamlayın.',
  'pair.accessRequiredTitle': 'Cloudflare Access girişi gerekli',
  'pair.accessRequiredBody':
    'Bu tarayıcıda Cloudflare Access girişini tamamlayıp sayfayı yenileyin. Uzaktan Kontrol hiçbir zaman Access kimlik bilgisi istemez.',
  'lock.active': 'Bu telefon etkin cihaz',
  'lock.otherDevice': 'Başka bir cihaz etkin',
  'lock.selectionRequired': 'Masaüstü etkin cihazı seçmeli',
  'lock.none': 'Etkin cihaz yok',
  'lock.idleFooter': 'Boşta bitişi: {time}',
  'lock.idleWarning': 'Boşta kalma nedeniyle uzaktan erişim {minutes} dk sonra kapanacak.',
  'lock.idleExpiredTitle': 'Boşta kalma süresi',
  'lock.idleExpiredBody':
    'Telefon boşta kaldığı için uzaktan erişim kapandı. Masaüstünde Uzaktan Kontrol’ü yeniden etkinleştirip yeniden eşleşin.',
  'lock.leaseLostTitle': 'Etkin cihaz değişti',
  'lock.leaseLostBody':
    'Artık başka bir cihaz etkin. Masaüstünden bu telefonu yeniden etkinleştirin ve sayfayı yenileyin.',
  'security.title': 'Uzaktan erişim kapalı',
  'security.body':
    'Uzaktan erişim güvenlik kapatmasıyla kapatıldı. Devam etmek için masaüstünde Uzaktan Kontrol’ü yeniden etkinleştirin.',
  'access.title': 'Cloudflare Access girişi gerekli',
  'access.body':
    'Bu origin için Cloudflare Access girişini tamamlayıp sayfayı yenileyin. Bu uygulamada Access kimlik bilgisi saklanmaz.',
  'sessions.locked': 'Başka bir cihaz etkin cihaz.',
  'sessions.selectionRequired': 'Masaüstü etkin cihazı seçmeli.',
  'sessions.title': 'Oturumlar',
  'sessions.empty': 'Henüz oturum yok.',
  'sessions.error': 'Oturumlar yüklenemedi.',
  'sessions.running': 'çalışıyor',
  'sessions.idle': 'boşta',
  'sessions.blank': 'yeni',
  'sessions.updated': 'Güncellendi: {time}',
  'sessions.unpair': 'Bu telefonun eşleşmesini kaldır',
  'sessions.unpairConfirm': 'Bu telefonun eşleşmesi kaldırılsın mı? Yeniden bağlanmak için yeni QR gerekir.',
  'sessions.unpairDone': 'Bu telefonun eşleşmesi kaldırıldı.',
  'auth.title': 'Yeniden eşleş',
  'auth.body':
    'Bu telefon artık eşleşmiş değil. Masaüstünde Ayarlar → Uzaktan Kontrol bölümünü açıp yeni QR kodunu okutun.',
  'auth.pair': 'Yeniden eşleş',
  'session.notFound': 'Oturum bulunamadı.',
  'session.error': 'Bu oturum yüklenemedi.',
  'session.older': 'Daha eski mesajları yükle',
  'session.noOlder': 'Oturumun başlangıcı',
  'session.olderError': 'Daha eski mesajlar yüklenemedi.',
  'session.gap': 'Transcript boşluğu algılandı — yeniden yükleniyor…',
  'session.streamError': 'Canlı akış hatası.',
  'conn.connecting': 'Bağlanıyor…',
  'conn.connected': 'Bağlı',
  'conn.reconnecting': 'Yeniden bağlanıyor…',
  'conn.offline': 'Bağlantı yok',
  'conn.disconnectedHint': 'Bağlantı yok — ajan çalışmaya devam ediyor olabilir.',
  'conn.drain': 'Host yeniden başlıyor…',
  'role.you': 'Siz',
  'role.assistant': 'Asistan',
  'role.tool': 'Araç',
  'turn.stopped': 'Tur durduruldu',
  'turn.failed': 'Tur başarısız',
  'tool.arguments': 'argümanlar',
  'composer.placeholder': 'Bir prompt gönderin…',
  'composer.send': 'Gönder',
  'composer.queue': 'Sıraya al',
  'composer.steer': 'Tura ilet',
  'composer.stop': 'Durdur',
  'composer.stopConfirm': 'Çalışan tur durdurulsun mu?',
  'composer.stopped': 'İptal isteği iletildi.',
  'composer.stopError': 'Tur iptal edilemedi.',
  'composer.sent': 'Gönderildi',
  'composer.sendError': 'Prompt gönderilemedi.',
  'composer.empty': 'Önce bir mesaj yazın.',
  'composer.tooLong': 'Mesaj çok uzun (en fazla {count} karakter).',
  'approval.title': 'Onay gerekiyor',
  'approval.questionTitle': 'Ajandan soru',
  'approval.tool': 'Araç',
  'approval.allowOnce': 'Bir kez izin ver',
  'approval.reject': 'Reddet',
  'approval.expires': '{seconds} sn kaldı',
  'approval.expired': 'Süresi doldu',
  'approval.answered': 'Yanıtlandı',
  'approval.answeredElsewhere': 'Başka bir cihazda yanıtlandı',
  'approval.cancelled': 'İstek iptal edildi',
  'approval.sendError': 'Yanıt gönderilemedi.',
  'approval.sending': 'Gönderiliyor…',
  'approval.delivered': 'Yanıt iletildi.',
  'approval.ackTimeout': 'Masaüstünden onay alınamadı; tekrar deneyin.',
  'approval.desktopOnly': 'Bu soruyu masaüstünde yanıtlayın.',
  'approval.queuePlaceholder': 'Bekleyen onay yok.',
  'reasoning.title': 'Düşünme süreci',
  'home.title': 'Size nasıl yardımcı olabilirim?',
  'home.subtitle': 'Her şeyi sorun — gerektiğinde görsel veya dosya ekleyin.',
  'nav.menu': 'Menü',
  'nav.newChat': 'Yeni sohbet',
  'drawer.history': 'Geçmiş',
  'drawer.empty': 'Henüz oturum yok.',
  'workspace.default': 'Varsayılan çalışma alanı',
  'workspace.other': 'Diğer oturumlar',
  'composer.attach': 'Görsel veya dosya ekle',
  'composer.attachHint': 'Görseller doğrudan gönderilir; diğer dosyalar önce yüklenir.',
  'attach.image': 'Görsel',
  'attach.file': 'Dosya',
  'attach.uploading': 'Yükleniyor…',
  'attach.failed': 'Dosya eklenemedi.',
  'attach.tooLarge': 'Ek çok büyük (en fazla {size}).',
  'attach.remove': 'Eki kaldır',
  'session.newTitle': 'Yeni sohbet',
  'sessions.refreshing': 'Yenileniyor…',
  'sessions.refreshed': 'Liste güncellendi.',
  'lang.switch': 'Dili değiştir',
  'footer.version': 'DSH Uzaktan Kontrol',
}

type Language = 'en' | 'tr'

const dictionaries: Record<Language, Record<MessageKey, string>> = { en, tr }
const LANG_QUERY_PARAM = 'lang'

/** Read an explicit language choice from the hash query (survives reloads). */
function languageFromHash(): Language | null {
  try {
    const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
    const separator = raw.indexOf('?')
    if (separator === -1) return null
    const value = new URLSearchParams(raw.slice(separator + 1)).get(LANG_QUERY_PARAM)
    return value === 'tr' ? 'tr' : value === 'en' ? 'en' : null
  } catch {
    return null
  }
}

function detectLanguage(): Language {
  const explicit = languageFromHash()
  if (explicit !== null) return explicit
  try {
    return navigator.language.toLowerCase().startsWith('tr') ? 'tr' : 'en'
  } catch {
    return 'en'
  }
}

let language: Language = detectLanguage()

function t(key: MessageKey, params?: Record<string, string | number>): string {
  const template = dictionaries[language][key] ?? en[key]
  if (params === undefined) return template
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match: string, name: string) => {
    const value = params[name]
    return value === undefined ? match : String(value)
  })
}

const languageToggles = new Set<HTMLButtonElement>()

function updateLanguageToggles(): void {
  for (const element of languageToggles) {
    if (!element.isConnected) {
      languageToggles.delete(element)
      continue
    }
    element.textContent = language === 'tr' ? 'EN' : 'TR'
    element.setAttribute('aria-label', t('lang.switch'))
    element.title = t('lang.switch')
  }
}

/**
 * Switch the interface language without any persistent-storage API (the PWA is
 * under a storage-free CSP contract): the choice is carried in the hash query
 * (`#/sessions?lang=tr`) and re-applied on reload.
 */
function applyLanguage(next: Language, rerender: boolean): void {
  language = next
  try {
    document.documentElement.lang = next
  } catch {
    // ignore
  }
  try {
    const raw = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
    const separator = raw.indexOf('?')
    const path = separator === -1 ? (raw.length === 0 ? '/' : raw) : raw.slice(0, separator)
    const params = new URLSearchParams(separator === -1 ? '' : raw.slice(separator + 1))
    params.set(LANG_QUERY_PARAM, next)
    history.replaceState(null, '', `#${path}?${params.toString()}`)
  } catch {
    // ignore
  }
  if (rerender) renderRoute()
  updateLanguageToggles()
}

function languageToggle(): HTMLButtonElement {
  const element = create('button', { type: 'button', class: 'btn btn-ghost btn-small lang-toggle' }, [
    language === 'tr' ? 'EN' : 'TR',
  ])
  element.setAttribute('aria-label', t('lang.switch'))
  element.title = t('lang.switch')
  element.addEventListener('click', () => {
    applyLanguage(language === 'tr' ? 'en' : 'tr', true)
  })
  languageToggles.add(element)
  return element
}

/* -------------------------------------------------------------------------- */
/* One-time pairing code handling                                             */
/* -------------------------------------------------------------------------- */

/**
 * Pairing code taken from the boot URL fragment (`#/pair?c=…`). It lives in
 * memory only: the fragment is removed from the address bar *and* from the
 * current history entry before any network request, so the one-time code cannot
 * leak through history, reloads, screenshots or the Referer header.
 */
let bootPairingCode: string | null = null

/**
 * Rewrite the current history entry without its fragment. `replaceState` (not
 * `pushState`) is required: the entry that contained the pairing code must not
 * remain reachable with the back button.
 */
function stripPairingFragment(): void {
  try {
    history.replaceState(history.state ?? null, '', `${location.pathname}${location.search}`)
  } catch {
    // A failed rewrite must not break pairing; the code is still consumed once.
  }
}

/** Move a `#/pair?c=…` code into memory and strip the fragment from the URL. */
function consumePairingCodeFromUrl(): void {
  const raw = location.hash
  if (raw.length === 0 || !raw.startsWith('#/pair')) return
  const separator = raw.indexOf('?')
  if (separator === -1) return
  const params = new URLSearchParams(raw.slice(separator + 1))
  const code = params.get('c')
  if (code === null || code.length === 0) return
  bootPairingCode = code
  stripPairingFragment()
}

/* -------------------------------------------------------------------------- */
/* Tiny DOM helpers (textContent only — never innerHTML)                      */
/* -------------------------------------------------------------------------- */

type Child = Node | string | null | undefined | false

function clearNode(node: Node): void {
  while (node.firstChild !== null) node.removeChild(node.firstChild)
}

function appendChildren(parent: Node, children: readonly Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue
    parent.appendChild(typeof child === 'string' ? document.createTextNode(child) : child)
  }
}

type Attrs = Record<string, string | number | boolean | undefined>

function create<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: readonly Child[] = [],
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag)
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue
    if (value === true) {
      element.setAttribute(name, '')
      continue
    }
    element.setAttribute(name, String(value))
  }
  appendChildren(element, children)
  return element
}

function button(label: string, onClick: () => void, attrs: Attrs = {}): HTMLButtonElement {
  const element = create('button', { type: 'button', class: 'btn', ...attrs }, [label])
  element.addEventListener('click', onClick)
  return element
}

function statusPill(): { element: HTMLElement; update: (status: ConnectionStatus) => void } {
  const label = create('span', { class: 'pill-label' })
  const element = create('span', { class: 'pill', 'data-tone': 'offline' }, [
    create('span', { class: 'pill-dot' }),
    label,
  ])
  const update = (status: ConnectionStatus): void => {
    element.setAttribute('data-tone', status)
    label.textContent = connectionLabel(status)
    if (status === 'connected') element.removeAttribute('title')
    else element.title = t('conn.disconnectedHint')
  }
  update(currentStatus())
  return { element, update }
}

function connectionLabel(status: ConnectionStatus): string {
  switch (status) {
    case 'connected':
      return t('conn.connected')
    case 'connecting':
      return t('conn.connecting')
    case 'reconnecting':
      return t('conn.reconnecting')
    case 'offline':
    default:
      return t('conn.offline')
  }
}

function formatRelativeTime(timestamp: number): string {
  if (!Number.isFinite(timestamp) || timestamp <= 0) return '—'
  try {
    return new Date(timestamp).toLocaleString()
  } catch {
    return '—'
  }
}

function shortSessionId(sessionId: string): string {
  return sessionId.length > 10 ? `${sessionId.slice(0, 8)}…` : sessionId
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max)}…`
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return ''
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function messageText(content: unknown): string {
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const block of content) {
    if (isRecord(block) && block['type'] === 'text' && typeof block['text'] === 'string') {
      parts.push(block['text'])
    }
  }
  return parts.join('\n').trim()
}

interface AttachmentRefView {
  attachmentId: string
  name?: string
}

interface ExtractedContent {
  text: string
  reasoning: string
  images: AttachmentRefView[]
  files: Array<{ name: string; bytes?: number }>
}

/** Extract every durable content block kind the phone can render. */
function extractContent(content: unknown): ExtractedContent {
  const result: ExtractedContent = { text: '', reasoning: '', images: [], files: [] }
  if (!Array.isArray(content)) return result
  const text: string[] = []
  const reasoning: string[] = []
  for (const block of content) {
    if (!isRecord(block)) continue
    const type = block['type']
    if (typeof block['text'] === 'string' && type === 'text') text.push(block['text'])
    else if (typeof block['text'] === 'string' && type === 'reasoning') reasoning.push(block['text'])
    else if (type === 'image') {
      const ref = attachmentRef(block)
      if (ref !== null) result.images.push(ref)
    } else if (type === 'file') {
      const embedded = isRecord(block['attachment']) ? block['attachment'] : block
      const name = typeof embedded['name'] === 'string' && embedded['name'].length > 0 ? embedded['name'] : t('attach.file')
      const bytes = typeof embedded['bytes'] === 'number' ? embedded['bytes'] : undefined
      result.files.push(bytes === undefined ? { name } : { name, bytes })
    }
  }
  result.text = text.join('\n').trim()
  result.reasoning = reasoning.join('\n\n').trim()
  return result
}

function attachmentRef(block: Record<string, unknown>): AttachmentRefView | null {
  const embedded = isRecord(block['attachment']) ? block['attachment'] : block
  const attachmentId = embedded['attachmentId']
  if (typeof attachmentId !== 'string' || attachmentId.length === 0) return null
  const name = typeof embedded['name'] === 'string' && embedded['name'].length > 0 ? embedded['name'] : undefined
  return name === undefined ? { attachmentId } : { attachmentId, name }
}

/** Active session id used to authorize attachment reads; set by the session screen. */
let transcriptSessionId: string | null = null
const attachmentDataUrls = new Map<string, string>()
/** Set by the session screen so late-loading images can re-pin the scroll. */
let requestScrollToBottom: (() => void) | null = null

function renderImageStrip(images: AttachmentRefView[]): HTMLElement | null {
  if (images.length === 0) return null
  const strip = create('div', { class: 'msg-images' })
  for (const image of images) {
    const box = create('div', { class: 'msg-image' })
    const label = image.name ?? t('attach.image')
    const img = create('img', { class: 'msg-image-img', alt: label, loading: 'lazy' })
    img.setAttribute('hidden', '')
    const status = create('span', { class: 'msg-image-status' }, [t('attach.uploading')])
    box.appendChild(img)
    box.appendChild(status)
    const sessionId = transcriptSessionId
    const cached = sessionId === null ? undefined : attachmentDataUrls.get(`${sessionId}:${image.attachmentId}`)
    if (cached !== undefined) {
      img.src = cached
      img.removeAttribute('hidden')
      status.remove()
      requestScrollToBottom?.()
    } else if (sessionId !== null) {
      void phoneApi
        .attachment(sessionId, image.attachmentId)
        .then((result) => {
          const url = `data:${result.attachment.mediaType};base64,${result.data}`
          attachmentDataUrls.set(`${sessionId}:${image.attachmentId}`, url)
          img.src = url
          img.removeAttribute('hidden')
          status.remove()
          requestScrollToBottom?.()
        })
        .catch(() => {
          status.textContent = '⚠'
        })
    }
    strip.appendChild(box)
  }
  return strip
}

function renderFileStrip(files: Array<{ name: string; bytes?: number }>): HTMLElement | null {
  if (files.length === 0) return null
  const strip = create('div', { class: 'msg-files' })
  for (const file of files) {
    const size = typeof file.bytes === 'number' ? ` · ${formatBytes(file.bytes)}` : ''
    strip.appendChild(create('span', { class: 'msg-file-chip' }, [`📎 ${file.name}${size}`]))
  }
  return strip
}

function reasoningPreview(reasoning: string): string {
  const firstLine = reasoning.split('\n').find((line) => line.trim().length > 0) ?? ''
  return truncate(firstLine.trim(), 140)
}

/**
 * DeepSeek-style assistant turn: reasoning disclosure first, then the markdown
 * answer and any images/files. No DOM text sinks (CSP); markdown is built from
 * DOM nodes by `renderMarkdown`.
 */
function renderAssistantMessage(content: ExtractedContent): HTMLElement {
  const article = create('article', { class: 'msg msg-assistant', 'data-role': 'assistant' })
  if (content.reasoning.length > 0) {
    article.appendChild(
      create('details', { class: 'msg-reasoning' }, [
        create('summary', { class: 'msg-reasoning-summary' }, [
          create('span', { class: 'msg-reasoning-label' }, [t('reasoning.title')]),
          create('span', { class: 'msg-reasoning-preview' }, [reasoningPreview(content.reasoning)]),
        ]),
        create('div', { class: 'msg-reasoning-body' }, [content.reasoning]),
      ]),
    )
  }
  if (content.text.length > 0) {
    const body = create('div', { class: 'msg-body msg-markdown' })
    body.appendChild(renderMarkdown(content.text))
    article.appendChild(body)
  }
  const images = renderImageStrip(content.images)
  if (images !== null) article.appendChild(images)
  const files = renderFileStrip(content.files)
  if (files !== null) article.appendChild(files)
  return article
}

function renderUserMessage(content: ExtractedContent): HTMLElement {
  const article = create('article', { class: 'msg msg-user', 'data-role': 'user' })
  const images = renderImageStrip(content.images)
  if (images !== null) article.appendChild(images)
  const files = renderFileStrip(content.files)
  if (files !== null) article.appendChild(files)
  if (content.text.length > 0) article.appendChild(create('div', { class: 'msg-body' }, [content.text]))
  return article
}

/** DSH injects runtime/time/skill context as user-role messages; never render them. */
function isUserAuthoredRecord(record: SessionEventRecord): boolean {
  if (record.type !== 'user/message') return true
  const data = isRecord(record.data) ? record.data : null
  if (data === null) return true
  const source = isRecord(data['source']) ? data['source'] : null
  if (source === null || source['kind'] === undefined) return true
  return source['kind'] === 'user'
}

/**
 * Resolve an approval reason exactly like the desktop client does: an explicit
 * `displayReason` string wins; then the active locale in a locale map; then any
 * other localized value; then the raw `reason`; the caller falls back to the
 * tool name. Tool arguments are never present on the wire.
 */
function resolveApprovalReason(view: ApprovalView): string | null {
  const request = view.request
  if (!('toolName' in request)) return null
  const display = request.displayReason
  if (typeof display === 'string' && display.trim().length > 0) return display
  if (isRecord(display)) {
    const preferred = display[language]
    if (typeof preferred === 'string' && preferred.trim().length > 0) return preferred
    const fallback = display['en']
    if (typeof fallback === 'string' && fallback.trim().length > 0) return fallback
    for (const value of Object.values(display)) {
      if (typeof value === 'string' && value.trim().length > 0) return value
    }
  }
  if (typeof request.reason === 'string' && request.reason.trim().length > 0) return request.reason
  return null
}

/* -------------------------------------------------------------------------- */
/* HTTP layer (`/rc/api/*`, JSON error envelope, silent access refresh)       */
/* -------------------------------------------------------------------------- */

class ApiError extends Error {
  readonly code: string
  readonly retryAfterMs: number | undefined

  constructor(code: string, message: string, retryAfterMs?: number) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.retryAfterMs = retryAfterMs
  }
}

function apiError(payload: unknown, status: number): ApiError {
  if (isRecord(payload) && payload['ok'] === false && isRecord(payload['error'])) {
    const error = payload['error']
    const code = typeof error['code'] === 'string' ? error['code'] : `HTTP_${status}`
    const message = typeof error['message'] === 'string' ? error['message'] : code
    const retryAfterMs = typeof error['retryAfterMs'] === 'number' ? error['retryAfterMs'] : undefined
    return new ApiError(code, message, retryAfterMs)
  }
  return new ApiError(`HTTP_${status}`, `HTTP ${status}`)
}

/**
 * Cloudflare Access fronts fixed-hostname deployments. When its login page (or a
 * challenge page) is answered instead of our JSON API, the browser sees HTML.
 * That is never a valid remote-control response, so surface it as an actionable
 * `ACCESS_REQUIRED` error instead of a JSON parse failure. No Access secret ever
 * reaches this app.
 */
function isHtmlResponse(response: Response): boolean {
  try {
    return (response.headers.get('content-type') ?? '').toLowerCase().includes('text/html')
  } catch {
    return false
  }
}

function isAuthFailure(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    (error.code === 'AUTH_REQUIRED' ||
      error.code === 'TOKEN_EXPIRED' ||
      error.code === 'DEVICE_REVOKED' ||
      error.code === 'ACCESS_REQUIRED')
  )
}

let refreshInFlight: Promise<boolean> | null = null

async function refreshSession(): Promise<boolean> {
  if (refreshInFlight !== null) return refreshInFlight
  const pending = (async (): Promise<boolean> => {
    try {
      const response = await fetch(`${RC_API_PATH}/session/refresh`, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
          [RC_CSRF_HEADER]: '1',
        },
        body: '{}',
      })
      // An Access login/challenge page means "not refreshed", never success.
      if (isHtmlResponse(response)) return false
      return response.ok
    } catch {
      return false
    }
  })()
  refreshInFlight = pending
  try {
    return await pending
  } finally {
    refreshInFlight = null
  }
}

interface ApiRequestOptions {
  method?: 'GET' | 'POST'
  body?: unknown
  auth?: boolean
}

async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
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
    init.body = JSON.stringify(options.body ?? {})
  }
  const response = await fetch(`${RC_API_PATH}${path}`, init)
  // Cloudflare Access can answer with its login page for fixed-hostname setups.
  // Treat that as an actionable re-auth state; it is never a valid API response.
  if (isHtmlResponse(response)) {
    throw new ApiError('ACCESS_REQUIRED', 'Cloudflare Access sign-in required')
  }
  if (response.redirected) {
    let origin: string | null = null
    try {
      origin = new URL(response.url).origin
    } catch {
      origin = null
    }
    if (origin !== null && origin !== location.origin) {
      throw new ApiError('ACCESS_REQUIRED', 'Cloudflare Access sign-in required')
    }
  }
  const text = await response.text()
  let payload: unknown = null
  if (text.length > 0) {
    try {
      payload = JSON.parse(text) as unknown
    } catch {
      payload = null
    }
  }
  if (response.ok && options.auth === false) {
    return payload as T
  }
  if (!response.ok) {
    const failure = apiError(payload, response.status)
    const canRefresh =
      isAuthFailure(failure) && failure.code !== 'DEVICE_REVOKED' && failure.code !== 'ACCESS_REQUIRED'
    if (canRefresh) {
      const refreshed = await refreshSession()
      if (refreshed) return apiRequest<T>(path, { ...options, auth: false })
    }
    throw failure
  }
  return payload as T
}

const phoneApi = {
  health(): Promise<HealthResponse> {
    return apiRequest<HealthResponse>('/health', { auth: false })
  },
  state(): Promise<StateResponse> {
    return apiRequest<StateResponse>('/state')
  },
  pairClaim(code: string, deviceName: string, platform: string): Promise<PairClaimResponse> {
    return apiRequest<PairClaimResponse>('/pair/claim', {
      method: 'POST',
      body: { code, deviceName, platform },
      auth: false,
    })
  },
  /**
   * Pairing approval poll. The polling secret is a POST body field (never a GET
   * query value) so it cannot end up in proxy or server access logs; the CSRF
   * header plus an allowed same-origin `Origin` are enforced by the host.
   */
  pairStatus(claimId: string, pollToken: string): Promise<PairStatusResponse> {
    return apiRequest<PairStatusResponse>('/pair/status', {
      method: 'POST',
      body: { claimId, pollToken },
      auth: false,
    })
  },
  sessions(): Promise<SessionsResponse> {
    return apiRequest<SessionsResponse>('/sessions')
  },
  createSession(workspaceId?: string, cwd?: string): Promise<CreateSessionResponse> {
    const body = workspaceId !== undefined ? { workspaceId } : cwd !== undefined ? { cwd } : {}
    return apiRequest<CreateSessionResponse>('/sessions', { method: 'POST', body })
  },
  uploadFile(sessionId: string, name: string, data: string): Promise<UploadFileResponse> {
    return apiRequest<UploadFileResponse>(`/sessions/${encodeURIComponent(sessionId)}/files`, {
      method: 'POST',
      body: { name, data },
    })
  },
  attachment(sessionId: string, attachmentId: string): Promise<SessionAttachmentResponse> {
    return apiRequest<SessionAttachmentResponse>(
      `/sessions/${encodeURIComponent(sessionId)}/attachments/${encodeURIComponent(attachmentId)}`,
    )
  },
  projections(sessionId: string): Promise<SessionProjectionsResponse> {
    return apiRequest<SessionProjectionsResponse>(`/sessions/${encodeURIComponent(sessionId)}/projections`)
  },
  page(sessionId: string, request: PageRequest): Promise<SessionPageResponse> {
    const query = new URLSearchParams()
    if (request.throughSeq !== undefined) query.set('throughSeq', String(request.throughSeq))
    if (request.beforeSeq !== undefined) query.set('beforeSeq', String(request.beforeSeq))
    if (request.maxMessages !== undefined) query.set('maxMessages', String(request.maxMessages))
    return apiRequest<SessionPageResponse>(
      `/sessions/${encodeURIComponent(sessionId)}/page?${query.toString()}`,
    )
  },
  prompt(sessionId: string, request: PromptRequest): Promise<PromptResponse> {
    return apiRequest<PromptResponse>(`/sessions/${encodeURIComponent(sessionId)}/prompt`, {
      method: 'POST',
      body: request,
    })
  },
  cancel(sessionId: string): Promise<{ ok: true; accepted: boolean }> {
    return apiRequest<{ ok: true; accepted: boolean }>(
      `/sessions/${encodeURIComponent(sessionId)}/cancel`,
      { method: 'POST', body: {} },
    )
  },
  logout(): Promise<{ ok: true }> {
    return apiRequest<{ ok: true }>('/session/logout', { method: 'POST', body: {} })
  },
}

/* -------------------------------------------------------------------------- */
/* WebSocket connection manager (`/rc/ws`, hello/sub/rpc/answer/ping)         */
/* -------------------------------------------------------------------------- */

type ConnectionStatus = 'connecting' | 'connected' | 'reconnecting' | 'offline'

/** Client → server frames; the shared `ClientFrame` union plus the heartbeat pong. */
type ClientOutFrame = ClientFrame | PongFrame

interface ActiveStream {
  streamId: string
  sessionId: string
  maxMessages: number
}

type FrameListener = (frame: ServerFrame) => void
type StatusListener = (status: ConnectionStatus) => void
type HostEventListener = (event: string, args: unknown[]) => void

const frameListeners = new Set<FrameListener>()
const statusListeners = new Set<StatusListener>()
const hostEventListeners = new Set<HostEventListener>()

let socket: WebSocket | null = null
let connectionStatus: ConnectionStatus = 'offline'
let reconnectAttempt = 0
let reconnectTimer: number | null = null
let heartbeatTimer: number | null = null
let lastInboundAt = 0
let readyReceived = false
let manualStop = true
let activeStream: ActiveStream | null = null
let currentDevice: DeviceView | null = null
let drainUntil = 0

function currentStatus(): ConnectionStatus {
  return connectionStatus
}

function setStatus(next: ConnectionStatus): void {
  if (connectionStatus === next) return
  connectionStatus = next
  for (const listener of Array.from(statusListeners)) {
    try {
      listener(next)
    } catch {
      // listener failures must not break the socket lifecycle
    }
  }
}

function onStatus(listener: StatusListener): () => void {
  statusListeners.add(listener)
  return () => statusListeners.delete(listener)
}

function onFrame(listener: FrameListener): () => void {
  frameListeners.add(listener)
  return () => frameListeners.delete(listener)
}

function onHostEvent(listener: HostEventListener): () => void {
  hostEventListeners.add(listener)
  return () => hostEventListeners.delete(listener)
}

function webSocketUrl(): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${location.host}${RC_WS_PATH}`
}

function sendFrame(frame: ClientOutFrame): boolean {
  const current = socket
  if (current === null || current.readyState !== WebSocket.OPEN) return false
  try {
    current.send(JSON.stringify(frame))
    return true
  } catch {
    return false
  }
}

function backoffDelay(attempt: number): number {
  const delay = 500 * Math.pow(2, Math.max(0, attempt))
  return Math.min(10_000, Math.max(500, delay))
}

function cancelReconnectTimer(): void {
  if (reconnectTimer === null) return
  window.clearTimeout(reconnectTimer)
  reconnectTimer = null
}

function scheduleReconnect(): void {
  if (manualStop || reconnectTimer !== null) return
  const delay = Math.max(backoffDelay(reconnectAttempt), drainUntil - Date.now())
  reconnectAttempt += 1
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null
    connectSocket()
  }, Math.max(0, delay))
}

function closeSocket(): void {
  const current = socket
  socket = null
  readyReceived = false
  stopHeartbeatWatchdog()
  if (current === null) return
  try {
    current.close()
  } catch {
    // already closing
  }
}

function connectSocket(): void {
  if (manualStop) return
  if (socket !== null && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return
  }
  cancelReconnectTimer()
  setStatus(reconnectAttempt === 0 ? 'connecting' : 'reconnecting')
  let next: WebSocket
  try {
    next = new WebSocket(webSocketUrl())
  } catch {
    scheduleReconnect()
    return
  }
  socket = next
  next.addEventListener('open', () => {
    if (socket !== next) return
    reconnectAttempt = 0
    lastInboundAt = Date.now()
    setStatus('connected')
    sendFrame({
      type: 'hello',
      protocol: PROTOCOL_VERSION,
      clientTimeZone: resolvedTimeZone(),
    })
    startHeartbeatWatchdog()
  })
  next.addEventListener('message', (event: MessageEvent) => {
    lastInboundAt = Date.now()
    handleSocketMessage(event.data)
  })
  next.addEventListener('close', (event: CloseEvent) => {
    if (socket === next) socket = null
    readyReceived = false
    stopHeartbeatWatchdog()
    if (manualStop) {
      setStatus('offline')
      return
    }
    // The plugin uses private-range close codes for security/session outcomes.
    // Retrying a revoked/closed/locked session would only hammer the host, so
    // each of these ends the session with a safe, actionable screen instead.
    const code = typeof event.code === 'number' ? event.code : 1006
    if (code === RC_WS_CLOSE.deviceLost || code === RC_WS_CLOSE.policyViolation) {
      endSession('device-lost')
      return
    }
    if (code === RC_WS_CLOSE.securityClosed) {
      endSession('security-closed')
      return
    }
    if (code === RC_WS_CLOSE.idleTimeout) {
      endSession('idle-timeout')
      return
    }
    if (code === RC_WS_CLOSE.leaseLost) {
      endSession('lease-lost')
      return
    }
    setStatus('reconnecting')
    scheduleReconnect()
  })
  next.addEventListener('error', () => {
    // A close event follows; reconnect is scheduled there.
  })
}

function handleSocketMessage(raw: unknown): void {
  if (typeof raw !== 'string') return
  let parsed: unknown
  try {
    parsed = JSON.parse(raw) as unknown
  } catch {
    return
  }
  if (!isRecord(parsed) || typeof parsed['type'] !== 'string') return
  const type = parsed['type']
  if (type === 'ping') {
    const pingTime = typeof parsed['t'] === 'number' ? parsed['t'] : Date.now()
    sendFrame({ type: 'pong', t: pingTime })
    return
  }
  if (type === 'ready') {
    readyReceived = true
    const ready = parsed as unknown as ReadyFrame
    if (ready.device !== undefined) currentDevice = ready.device
    if (activeStream !== null) sendSub(activeStream)
  }
  if (type === 'server-drain') {
    const retryAfterMs = typeof parsed['retryAfterMs'] === 'number' ? parsed['retryAfterMs'] : 1_500
    drainUntil = Date.now() + Math.max(0, retryAfterMs)
  }
  if (type === 'event') {
    const name = typeof parsed['event'] === 'string' ? parsed['event'] : ''
    const args = Array.isArray(parsed['args']) ? (parsed['args'] as unknown[]) : []
    for (const listener of Array.from(hostEventListeners)) {
      try {
        listener(name, args)
      } catch {
        // ignore listener errors
      }
    }
  }
  const frame = parsed as unknown as ServerFrame
  for (const listener of Array.from(frameListeners)) {
    try {
      listener(frame)
    } catch {
      // ignore listener errors
    }
  }
}

function sendSub(stream: ActiveStream): void {
  sendFrame({
    type: 'sub',
    streamId: stream.streamId,
    kind: RC_STREAM_FOLLOW,
    sessionId: stream.sessionId,
    maxMessages: stream.maxMessages,
  })
}

function setActiveStream(stream: ActiveStream | null): void {
  const previous = activeStream
  activeStream = stream
  if (previous !== null) sendFrame({ type: 'unsub', streamId: previous.streamId })
  if (stream !== null) {
    if (socket !== null && socket.readyState === WebSocket.OPEN) {
      if (readyReceived) sendSub(stream)
    } else {
      ensureConnection()
    }
  }
}

function ensureConnection(): void {
  manualStop = false
  if (socket === null) {
    connectSocket()
    return
  }
  if (socket.readyState === WebSocket.CLOSED || socket.readyState === WebSocket.CLOSING) {
    connectSocket()
  }
}

function stopConnection(): void {
  manualStop = true
  cancelReconnectTimer()
  closeSocket()
  setStatus('offline')
}

function startHeartbeatWatchdog(): void {
  stopHeartbeatWatchdog()
  heartbeatTimer = window.setInterval(() => {
    if (socket === null) return
    if (Date.now() - lastInboundAt > RC_HEARTBEAT.pongTimeoutMs) {
      // The server pings every 15 s; silence for 30 s means the link is dead.
      closeSocket()
      scheduleReconnect()
    }
  }, 5_000)
}

function stopHeartbeatWatchdog(): void {
  if (heartbeatTimer === null) return
  window.clearInterval(heartbeatTimer)
  heartbeatTimer = null
}

function resolvedTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone
  } catch {
    return 'UTC'
  }
}

/* -------------------------------------------------------------------------- */
/* Session end (security close codes, revocation, Access, device lock)        */
/* -------------------------------------------------------------------------- */

type SessionEndReason =
  | 'device-lost'
  | 'security-closed'
  | 'idle-timeout'
  | 'lease-lost'
  | 'access-required'

const STATE_POLL_MS = 10_000
/** How long before the idle deadline the phone starts warning the user. */
const IDLE_WARNING_MS = 5 * 60_000

let sessionEnd: SessionEndReason | null = null

/** End the session once, tear the socket down and show the matching safe screen. */
function endSession(reason: SessionEndReason): void {
  if (sessionEnd === null) sessionEnd = reason
  manualStop = true
  cancelReconnectTimer()
  closeSocket()
  setStatus('offline')
  renderRoute()
}

function clearSessionEnd(): void {
  sessionEnd = null
}

/**
 * Map a REST error to the matching session-end screen. Returns true when the
 * error was an authentication/security/lock outcome that the caller must not
 * retry (the UI already switched to the right guidance screen).
 */
function handleAuthLikeFailure(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false
  switch (error.code) {
    case 'DEVICE_REVOKED':
    case 'AUTH_REQUIRED':
    case 'TOKEN_EXPIRED':
      endSession('device-lost')
      return true
    case 'SECURITY_CLOSED':
      endSession('security-closed')
      return true
    case 'ACCESS_REQUIRED':
      endSession('access-required')
      return true
    case 'DEVICE_LOCKED':
      endSession('lease-lost')
      return true
    default:
      return false
  }
}

/**
 * Poll `GET /rc/api/state` (device lease, idle deadline). Only used by signed-in
 * screens; auth/security failures are routed to the shared session-end screens.
 */
function startStateWatch(onState: (state: StateResponse) => void): () => void {
  let disposed = false
  const poll = async (): Promise<void> => {
    if (disposed) return
    try {
      const state = await phoneApi.state()
      if (disposed) return
      onState(state)
    } catch (error) {
      if (disposed) return
      handleAuthLikeFailure(error)
    }
  }
  void poll()
  const timer = window.setInterval(() => {
    if (disposed) return
    if (document.visibilityState === 'visible') void poll()
  }, STATE_POLL_MS)
  return () => {
    disposed = true
    window.clearInterval(timer)
  }
}

function idleRemainingMs(state: StateResponse | null): number | null {
  if (state === null) return null
  const candidate =
    typeof state.idleExpiresAt === 'number'
      ? state.idleExpiresAt
      : typeof state.deviceLock?.idleExpiresAt === 'number'
        ? state.deviceLock.idleExpiresAt
        : null
  if (candidate === null || !Number.isFinite(candidate) || candidate <= 0) return null
  return Math.max(0, candidate - Date.now())
}

function formatIdleDeadline(state: StateResponse | null): string | null {
  if (state === null) return null
  const candidate =
    typeof state.idleExpiresAt === 'number'
      ? state.idleExpiresAt
      : typeof state.deviceLock?.idleExpiresAt === 'number'
        ? state.deviceLock.idleExpiresAt
        : null
  if (candidate === null || !Number.isFinite(candidate) || candidate <= 0) return null
  return formatRelativeTime(candidate)
}

/** Device-lock summary for the phone header. */
function lockSummary(
  state: StateResponse,
): { labelKey: MessageKey; tone: 'ok' | 'warn' | 'muted' } | null {
  const lock = state.deviceLock
  if (lock === undefined) return null
  if (lock.state === 'selection-required') return { labelKey: 'lock.selectionRequired', tone: 'warn' }
  if (lock.activeDeviceId !== null && lock.activeDeviceId === state.device.id) {
    return { labelKey: 'lock.active', tone: 'ok' }
  }
  if (lock.activeDeviceId !== null) return { labelKey: 'lock.otherDevice', tone: 'warn' }
  return { labelKey: 'lock.none', tone: 'muted' }
}

function lockPill(): {
  element: HTMLElement
  update: (state: StateResponse | null) => void
} {
  const label = create('span', { class: 'pill-label' })
  const element = create('span', { class: 'pill lock-pill', hidden: '' }, [
    create('span', { class: 'pill-dot' }),
    label,
  ])
  const update = (state: StateResponse | null): void => {
    if (state === null || state.deviceLock === undefined) {
      element.setAttribute('hidden', '')
      return
    }
    const summary = lockSummary(state)
    if (summary === null) {
      element.setAttribute('hidden', '')
      return
    }
    element.removeAttribute('hidden')
    element.setAttribute('data-tone', summary.tone)
    label.textContent = t(summary.labelKey)
    const deadline = formatIdleDeadline(state)
    element.title = deadline === null ? '' : t('lock.idleFooter', { time: deadline })
  }
  return { element, update }
}

/* -------------------------------------------------------------------------- */
/* Approval relay cards (global, independent of the active route)             */
/* -------------------------------------------------------------------------- */

interface PendingApproval {
  view: ApprovalView
  receivedAt: number
  deadline: number
  state: 'open' | 'submitting' | 'answered' | 'cancelled' | 'expired'
  cancelReason: ApprovalCancelFrame['reason'] | null
  error: string | null
}

const pendingApprovals = new Map<string, PendingApproval>()
const approvalTimers = new Map<string, number>()
let approvalRoot: HTMLElement | null = null
let approvalTicker: number | null = null

/** How long the phone waits for the explicit `answer-result` acknowledgement. */
const APPROVAL_ACK_TIMEOUT_MS = 8_000

function clearApprovalTimer(eventId: string): void {
  const timer = approvalTimers.get(eventId)
  if (timer === undefined) return
  approvalTimers.delete(eventId)
  window.clearTimeout(timer)
}

function registerApprovalFrame(frame: ApprovalFrame): void {
  const deadline = Date.now() + Math.max(0, frame.expiresInMs)
  clearApprovalTimer(frame.eventId)
  pendingApprovals.set(frame.eventId, {
    view: {
      eventId: frame.eventId,
      kind: frame.kind,
      request: frame.request,
      agentId: frame.agentId,
      answerable: frame.answerable,
      expiresInMs: frame.expiresInMs,
    },
    receivedAt: Date.now(),
    deadline,
    state: 'open',
    cancelReason: null,
    error: null,
  })
  renderApprovals()
}

function applyApprovalCancel(frame: ApprovalCancelFrame): void {
  const entry = pendingApprovals.get(frame.eventId)
  if (entry === undefined) return
  clearApprovalTimer(frame.eventId)
  entry.state = 'cancelled'
  entry.cancelReason = frame.reason
  renderApprovals()
}

/**
 * Resolve a card from an authoritative session record (`approval/decided`).
 * This is the safety net for cards the relay can no longer settle (desktop or
 * auto-review answered first, or the cancel frame was lost on a reconnect).
 */
function settleApprovalFromEvent(record: SessionEventRecord): void {
  if (record.type !== 'approval/decided') return
  const data = isRecord(record.data) ? record.data : null
  if (data === null || typeof data['id'] !== 'string') return
  const eventId = data['id']
  if (!pendingApprovals.has(eventId)) return
  clearApprovalTimer(eventId)
  // The durable decision is the source of truth: keeping an answered/cancelled
  // card on screen made a completed approval look like a stuck one.
  pendingApprovals.delete(eventId)
  renderApprovals()
}

function answerApproval(eventId: string, decision: ApprovalDecision): void {
  const entry = pendingApprovals.get(eventId)
  if (entry === undefined || entry.state !== 'open') return
  const outcome: AnswerOutcome = { kind: 'result', value: decision }
  if (!sendFrame({ type: 'answer', eventId, outcome })) {
    entry.error = t('approval.sendError')
    renderApprovals()
    return
  }
  entry.state = 'submitting'
  entry.error = null
  renderApprovals()
  // Never close a card on an optimistic assumption: wait for the relay's
  // explicit acknowledgement, then reopen on failure/timeout so the user can
  // retry instead of believing a lost answer was delivered.
  clearApprovalTimer(eventId)
  approvalTimers.set(
    eventId,
    window.setTimeout(() => {
      approvalTimers.delete(eventId)
      const pending = pendingApprovals.get(eventId)
      if (pending === undefined || pending.state !== 'submitting') return
      pending.state = 'open'
      pending.error = t('approval.ackTimeout')
      renderApprovals()
    }, APPROVAL_ACK_TIMEOUT_MS),
  )
}

function applyAnswerResult(frame: AnswerResultFrame): void {
  const entry = pendingApprovals.get(frame.eventId)
  if (entry === undefined) return
  clearApprovalTimer(frame.eventId)
  if (frame.ok) {
    // The relay accepted the decision (DSH settles the waterfall and cancels the
    // other deliveries); the card has served its purpose.
    pendingApprovals.delete(frame.eventId)
    renderApprovals()
    return
  }
  entry.state = 'open'
  const code = frame.error?.code
  entry.error = code === undefined ? t('approval.sendError') : `${t('approval.sendError')} (${code})`
  renderApprovals()
}

function approvalStatusText(entry: PendingApproval): string {
  switch (entry.state) {
    case 'submitting':
      return t('approval.sending')
    case 'answered':
      return t('approval.answered')
    case 'expired':
      return t('approval.expired')
    case 'cancelled':
      return entry.cancelReason === 'answered-elsewhere'
        ? t('approval.answeredElsewhere')
        : entry.cancelReason === 'expired'
          ? t('approval.expired')
          : t('approval.cancelled')
    case 'open':
    default: {
      const remaining = Math.max(0, Math.ceil((entry.deadline - Date.now()) / 1_000))
      return t('approval.expires', { seconds: remaining })
    }
  }
}

function renderApprovals(): void {
  if (approvalRoot === null) return
  clearNode(approvalRoot)
  if (pendingApprovals.size === 0) {
    approvalRoot.setAttribute('hidden', '')
    return
  }
  approvalRoot.removeAttribute('hidden')
  for (const [eventId, entry] of pendingApprovals) {
    const view = entry.view
    const request = view.request
    const isApproval = view.kind === 'approval' && 'toolName' in request
    const toolName = isApproval && 'toolName' in request ? request.toolName : null
    const reason = resolveApprovalReason(view)
    const title = isApproval ? t('approval.title') : t('approval.questionTitle')
    const children: Child[] = [
      create('h3', { class: 'approval-title' }, [title]),
    ]
    if (toolName !== null) {
      children.push(
        create('p', { class: 'approval-tool' }, [`${t('approval.tool')}: ${toolName}`]),
      )
    }
    if (reason !== null) children.push(create('p', { class: 'approval-reason' }, [reason]))
    if (!isApproval) children.push(create('p', { class: 'approval-note' }, [t('approval.desktopOnly')]))
    children.push(create('p', { class: 'approval-status' }, [approvalStatusText(entry)]))

    if (entry.error !== null) {
      children.push(create('p', { class: 'approval-error' }, [entry.error]))
    }

    if (entry.state === 'open') {
      if (isApproval && view.answerable) {
        children.push(
          create('div', { class: 'approval-actions' }, [
            button(t('approval.reject'), () => answerApproval(eventId, 'rejected'), {
              class: 'btn btn-danger',
            }),
            button(t('approval.allowOnce'), () => answerApproval(eventId, 'allowed-once'), {
              class: 'btn btn-primary',
            }),
          ]),
        )
      } else if (isApproval) {
        children.push(create('p', { class: 'approval-note' }, [t('approval.desktopOnly')]))
      }
    }

    const card = create('div', { class: 'approval-card', 'data-event-id': eventId }, children)
    approvalRoot.appendChild(card)
  }
}

function expireApprovals(): void {
  let changed = false
  let hasOpen = false
  for (const entry of pendingApprovals.values()) {
    if (entry.state === 'open') {
      if (Date.now() >= entry.deadline) {
        entry.state = 'expired'
        changed = true
      } else {
        hasOpen = true
      }
    }
  }
  if (changed || hasOpen) renderApprovals()
}

function startApprovalTicker(): void {
  if (approvalTicker !== null) return
  approvalTicker = window.setInterval(expireApprovals, 1_000)
}

/* -------------------------------------------------------------------------- */
/* Router                                                                     */
/* -------------------------------------------------------------------------- */

type Route =
  | { view: 'pair'; code: string | null }
  | { view: 'sessions' }
  | { view: 'session'; sessionId: string }
  | { view: 'notfound' }

function parseRoute(): Route {
  const rawHash = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash
  const separator = rawHash.indexOf('?')
  const pathPart = separator === -1 ? rawHash : rawHash.slice(0, separator)
  const queryPart = separator === -1 ? '' : rawHash.slice(separator + 1)
  const path = pathPart.length === 0 ? '/' : pathPart
  if (path === '/' || path === '/sessions') return { view: 'sessions' }
  if (path === '/pair') {
    const params = new URLSearchParams(queryPart)
    const code = params.get('c')
    return { view: 'pair', code: code !== null && code.length > 0 ? code : null }
  }
  const sessionMatch = /^\/sessions\/([^/]+)$/.exec(path)
  if (sessionMatch !== null) {
    return { view: 'session', sessionId: decodeURIComponent(sessionMatch[1] ?? '') }
  }
  return { view: 'notfound' }
}

function navigate(hash: string): void {
  location.hash = hash
}

/* -------------------------------------------------------------------------- */
/* App shell                                                                  */
/* -------------------------------------------------------------------------- */

const appRoot = document.getElementById('app')
const rootElement: HTMLElement = appRoot ?? document.body
approvalRoot = document.getElementById('approval-root')

let disposeRoute: (() => void) | null = null
let handlerInstalled = false

function installGlobalHandlers(): void {
  if (handlerInstalled) return
  handlerInstalled = true
  window.addEventListener('hashchange', () => {
    consumePairingCodeFromUrl()
    renderRoute()
  })
  window.addEventListener('online', () => {
    if (sessionEnd !== null) return
    if (!manualStop) {
      reconnectAttempt = 0
      cancelReconnectTimer()
      connectSocket()
    }
  })
  window.addEventListener('offline', () => {
    setStatus('offline')
  })
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'visible') return
    if (sessionEnd !== null) return
    if (manualStop) return
    if (socket === null || socket.readyState !== WebSocket.OPEN) {
      reconnectAttempt = 0
      cancelReconnectTimer()
      connectSocket()
    }
  })
  startApprovalTicker()
  onFrame((frame) => {
    if (frame.type === 'approval') registerApprovalFrame(frame)
    else if (frame.type === 'approval-cancel') applyApprovalCancel(frame)
    else if (frame.type === 'answer-result') applyAnswerResult(frame)
  })
}

function renderRoute(): void {
  if (disposeRoute !== null) {
    try {
      disposeRoute()
    } catch {
      // route disposers must not break navigation
    }
    disposeRoute = null
  }
  clearNode(rootElement)
  // A pending one-time pairing code always wins: scanning a (new) QR code is an
  // explicit intent to pair, which also clears any previous session-end state.
  const pendingPairingCode = bootPairingCode
  bootPairingCode = null
  if (pendingPairingCode !== null) {
    sessionEnd = null
    disposeRoute = renderPairScreen(pendingPairingCode)
    return
  }
  if (sessionEnd !== null) {
    renderSessionEndScreen(sessionEnd)
    return
  }
  const route = parseRoute()
  switch (route.view) {
    case 'pair':
      disposeRoute = renderPairScreen(route.code)
      break
    case 'sessions':
      disposeRoute = renderSessionsScreen()
      break
    case 'session':
      disposeRoute = renderSessionScreen(route.sessionId)
      break
    default:
      disposeRoute = renderNotFoundScreen()
      break
  }
}

function screenShell(): {
  header: HTMLElement
  main: HTMLElement
  footer: HTMLElement
  mount: HTMLElement
} {
  const header = create('header', { class: 'app-header' })
  const main = create('main', { class: 'app-main' })
  const footer = create('footer', { class: 'app-footer' })
  const screen = create('div', { class: 'screen' }, [header, main, footer])
  rootElement.appendChild(screen)
  return { header, main, footer, mount: screen }
}

function renderPairScreen(fragmentCode: string | null): () => void {
  stopConnection()
  const shell = screenShell()
  shell.header.appendChild(create('h1', { class: 'app-title' }, [t('pair.title')]))
  const card = create('section', { class: 'card' })
  shell.main.appendChild(card)
  shell.footer.appendChild(create('p', { class: 'muted' }, [t('footer.version')]))

  const pairingCode: string | null = fragmentCode ?? bootPairingCode
  let disposed = false
  let claimed = false

  if (pairingCode === null) {
    card.appendChild(create('h2', { class: 'card-title' }, [t('pair.noCodeTitle')]))
    card.appendChild(create('p', { class: 'card-body' }, [t('pair.noCodeBody')]))
    card.appendChild(
      button(t('nav.sessions'), () => navigate('#/sessions'), { class: 'btn btn-primary btn-block' }),
    )
    return () => {}
  }

  const statusLine = create('p', { class: 'card-body pair-status' })
  const actions = create('div', { class: 'card-actions' })
  const title = create('h2', { class: 'card-title' }, [t('pair.claiming')])
  card.appendChild(title)
  card.appendChild(statusLine)
  card.appendChild(actions)

  const setStatus = (message: string): void => {
    statusLine.textContent = message
  }

  /** Replace the whole card with a safe, non-retrying guidance state. */
  const showBlocking = (
    titleKey: MessageKey,
    bodyKey: MessageKey,
    actionLabelKey: MessageKey,
    action: () => void,
  ): void => {
    card.classList.add('card-error')
    clearNode(card)
    card.appendChild(create('h2', { class: 'card-title' }, [t(titleKey)]))
    card.appendChild(create('p', { class: 'card-body' }, [t(bodyKey)]))
    card.appendChild(
      create('div', { class: 'card-actions' }, [button(t(actionLabelKey), action, { class: 'btn btn-primary' })]),
    )
  }

  const showFailure = (message: string, canRetry: boolean): void => {
    setStatus(message)
    clearNode(actions)
    if (canRetry) {
      actions.appendChild(
        button(
          t('pair.retry'),
          () => {
            void claim()
          },
          { class: 'btn btn-primary' },
        ),
      )
    } else {
      actions.appendChild(button(t('nav.reload'), () => location.reload(), { class: 'btn' }))
    }
  }

  /** Shared mapping for every pairing error code the host can return. */
  const showPairError = (error: ApiError): void => {
    switch (error.code) {
      case 'PAIRING_INVALID':
        showFailure(t('pair.invalid'), false)
        return
      case 'PAIRING_EXPIRED':
        showFailure(t('pair.expired'), false)
        return
      case 'PAIRING_DENIED':
        showFailure(t('pair.denied'), false)
        return
      case 'DEVICE_LIMIT':
        showFailure(t('pair.deviceLimit'), false)
        return
      case 'DEVICE_LOCKED':
        showFailure(t('pair.deviceLocked'), false)
        return
      case 'SECURITY_CLOSED':
        showBlocking('pair.securityClosedTitle', 'pair.securityClosedBody', 'nav.reload', () =>
          location.reload(),
        )
        return
      case 'TLS_REQUIRED':
        showBlocking('pair.tlsTitle', 'pair.tlsRequired', 'nav.reload', () => location.reload())
        return
      case 'ACCESS_REQUIRED':
        showBlocking('pair.accessRequiredTitle', 'pair.accessRequiredBody', 'nav.reload', () =>
          location.reload(),
        )
        return
      case 'RATE_LIMITED': {
        const seconds = Math.max(1, Math.ceil((error.retryAfterMs ?? 60_000) / 1_000))
        showFailure(t('pair.rateLimited', { seconds }), true)
        return
      }
      default:
        showFailure(`${t('pair.failed')}: ${error.code}`, true)
        return
    }
  }

  /** Security/availability precheck; best-effort so a probe failure never blocks. */
  const checkAvailability = async (): Promise<boolean> => {
    let health: HealthResponse
    try {
      health = await phoneApi.health()
    } catch (error) {
      if (disposed) return false
      if (error instanceof ApiError) {
        if (error.code === 'SECURITY_CLOSED' || error.code === 'ACCESS_REQUIRED') {
          showPairError(error)
          return false
        }
      }
      // Network hiccup: let the claim itself surface the real state.
      return true
    }
    if (disposed) return false
    if (health.securityClosed === true) {
      showBlocking('pair.securityClosedTitle', 'pair.securityClosedBody', 'nav.reload', () =>
        location.reload(),
      )
      return false
    }
    if (health.pairingAvailable === false) {
      showBlocking('pair.disabledTitle', 'pair.disabled', 'nav.reload', () => location.reload())
      return false
    }
    return true
  }

  const claim = async (): Promise<void> => {
    if (claimed || disposed) return
    clearNode(actions)
    setStatus(t('pair.claiming'))
    let claimResult: PairClaimResponse
    try {
      claimResult = await phoneApi.pairClaim(pairingCode, deviceName(), devicePlatform())
    } catch (error) {
      if (disposed) return
      if (error instanceof ApiError) showPairError(error)
      else showFailure(`${t('pair.failed')}: ${String(error)}`, true)
      return
    }
    claimed = true
    // Once the claim is accepted the one-time code is spent; drop it from memory.
    bootPairingCode = null
    setStatus(t('pair.waitingApproval'))
    await pollStatus(claimResult)
  }

  const pollStatus = async (claimResult: PairClaimResponse): Promise<void> => {
    const deadline = Math.max(Date.now() + 30_000, claimResult.expiresAt + 30_000)
    while (!disposed && Date.now() < deadline) {
      try {
        const status = await phoneApi.pairStatus(claimResult.claimId, claimResult.pollToken)
        if (disposed) return
        if (handlePairStatus(status)) return
      } catch (error) {
        if (disposed) return
        if (error instanceof ApiError) {
          // Denial/expiry/security outcomes are terminal; transient network or
          // rate-limit failures keep polling until the deadline.
          if (
            error.code === 'PAIRING_DENIED' ||
            error.code === 'PAIRING_EXPIRED' ||
            error.code === 'PAIRING_INVALID' ||
            error.code === 'DEVICE_LOCKED' ||
            error.code === 'SECURITY_CLOSED'
          ) {
            showPairError(error)
            return
          }
        }
      }
      await sleep(1_000)
    }
    if (!disposed) showFailure(t('pair.expired'), false)
  }

  const handlePairStatus = (status: PairStatusResponse): boolean => {
    const state: PairingState = status.status
    if (state === 'approved') {
      setStatus(t('pair.approved'))
      clearSessionEnd()
      navigate('#/sessions')
      return true
    }
    if (state === 'denied') {
      showFailure(t('pair.denied'), false)
      return true
    }
    if (state === 'expired' || state === 'claimed-timeout') {
      showFailure(t('pair.expired'), false)
      return true
    }
    setStatus(t('pair.waitingApproval'))
    return false
  }

  void (async (): Promise<void> => {
    if (!(await checkAvailability())) return
    await claim()
  })()

  return () => {
    disposed = true
  }
}

function renderSessionsScreen(): () => void {
  const shell = screenShell()
  shell.mount.classList.add('screen-home')
  const menuButton = button('☰', () => toggleDrawer(true), {
    class: 'btn btn-ghost btn-small btn-icon',
    'aria-label': t('nav.menu'),
    title: t('nav.menu'),
  })
  const headerLeft = create('div', { class: 'header-left home-brand' }, [
    create('img', { class: 'brand-icon', src: '/rc/dsh-icon.png', alt: '' }),
    menuButton,
    create('span', { class: 'brand-wordmark' }, ['deepseek']),
    create('span', { class: 'brand-badge' }, ['HARNESS']),
  ])
  const pill = statusPill()
  const lock = lockPill()
  const newChatButton = button('＋', () => void createNewChat(), {
    class: 'btn btn-ghost btn-small btn-icon',
    'aria-label': t('nav.newChat'),
    title: t('nav.newChat'),
  })
  const reloadButton = button('⟳', () => void refreshSessions(), {
    class: 'btn btn-ghost btn-small btn-icon',
    'aria-label': t('nav.reload'),
    title: t('nav.reload'),
  })
  shell.header.appendChild(headerLeft)
  shell.header.appendChild(create('div', { class: 'header-actions' }, [newChatButton, reloadButton, pill.element]))

  const lockNotice = create('p', { class: 'banner', hidden: '', 'data-tone': 'warn' })
  const idleBanner = create('div', { class: 'banner', hidden: '', 'data-tone': 'warn' })
  const hero = create('section', { class: 'home-hero' }, [
    create('h1', { class: 'home-title' }, [t('home.title')]),
    create('p', { class: 'home-subtitle' }, [t('home.subtitle')]),
    create('div', { class: 'home-meta' }, [lock.element]),
  ])
  shell.main.appendChild(lockNotice)
  shell.main.appendChild(idleBanner)
  shell.main.appendChild(hero)

  /* Slide-in history drawer (DeepSeek mobile sidebar). */
  const drawerOverlay = create('div', { class: 'drawer-overlay' })
  drawerOverlay.setAttribute('hidden', '')
  const drawerPanel = create('aside', { class: 'drawer' })
  drawerPanel.setAttribute('hidden', '')
  const drawerHead = create('div', { class: 'drawer-head' }, [
    create('div', { class: 'home-brand' }, [
      create('img', { class: 'brand-icon', src: '/rc/dsh-icon.png', alt: '' }),
      create('span', { class: 'brand-wordmark' }, ['deepseek']),
      create('span', { class: 'brand-badge' }, ['HARNESS']),
    ]),
    button('×', () => toggleDrawer(false), {
      class: 'btn btn-ghost btn-small btn-icon',
      'aria-label': t('nav.back'),
      title: t('nav.back'),
    }),
  ])
  const drawerNewChat = button(`＋ ${t('nav.newChat')}`, () => {
    toggleDrawer(false)
    void createNewChat()
  }, { class: 'btn btn-primary btn-block drawer-new-chat' })
  const historyTitle = create('p', { class: 'history-title' }, [t('drawer.history')])
  const list = create('div', { class: 'list history-list' })
  const message = create('p', { class: 'muted' })
  const idleFooter = create('p', { class: 'muted' })
  const drawerFooter = create('div', { class: 'drawer-footer' }, [
    button(t('sessions.unpair'), () => void unpair(), { class: 'btn btn-ghost btn-small' }),
    create('p', { class: 'muted' }, [t('footer.version')]),
  ])
  drawerPanel.appendChild(drawerHead)
  drawerPanel.appendChild(drawerNewChat)
  drawerPanel.appendChild(historyTitle)
  drawerPanel.appendChild(message)
  drawerPanel.appendChild(list)
  drawerPanel.appendChild(idleFooter)
  drawerPanel.appendChild(drawerFooter)
  shell.mount.appendChild(drawerOverlay)
  shell.mount.appendChild(drawerPanel)
  const footerIdle = create('p', { class: 'muted' })
  shell.footer.appendChild(footerIdle)
  shell.footer.appendChild(create('p', { class: 'muted' }, [t('footer.version')]))

  let drawerOpen = false
  function toggleDrawer(open: boolean): void {
    drawerOpen = open
    if (open) {
      drawerOverlay.removeAttribute('hidden')
      drawerPanel.removeAttribute('hidden')
      drawerPanel.classList.add('drawer-open')
      shell.mount.classList.add('drawer-open')
    } else {
      drawerOverlay.setAttribute('hidden', '')
      drawerPanel.setAttribute('hidden', '')
      drawerPanel.classList.remove('drawer-open')
      shell.mount.classList.remove('drawer-open')
    }
  }
  drawerOverlay.addEventListener('click', () => toggleDrawer(false))

  let disposed = false
  let latest: SessionSummary[] = []
  let latestGroups: WorkspaceGroupView[] = []
  let creating = false
  let state: StateResponse | null = null

  /**
   * Device-lock and idle-clock summary for the header/footer. Remote access is
   * single-device: when another device holds the lease, or the desktop still has
   * to choose the active device, the phone must not pretend it can work.
   */
  const updateLockUi = (): void => {
    lock.update(state)
    const remaining = idleRemainingMs(state)
    if (remaining !== null && remaining > 0 && remaining <= IDLE_WARNING_MS) {
      idleBanner.removeAttribute('hidden')
      idleBanner.textContent = t('lock.idleWarning', {
        minutes: Math.max(1, Math.ceil(remaining / 60_000)),
      })
    } else {
      idleBanner.setAttribute('hidden', '')
      idleBanner.textContent = ''
    }
    const deadline = formatIdleDeadline(state)
    idleFooter.textContent = deadline === null ? '' : t('lock.idleFooter', { time: deadline })
    footerIdle.textContent = deadline === null ? '' : t('lock.idleFooter', { time: deadline })
    let notice: string | null = null
    if (state !== null) {
      const summary = lockSummary(state)
      if (summary !== null) {
        if (summary.labelKey === 'lock.otherDevice') notice = t('sessions.locked')
        else if (summary.labelKey === 'lock.selectionRequired') notice = t('sessions.selectionRequired')
      }
    }
    if (notice === null) {
      lockNotice.setAttribute('hidden', '')
      lockNotice.textContent = ''
    } else {
      lockNotice.removeAttribute('hidden')
      lockNotice.textContent = notice
    }
  }

  const groupTitle = (group: WorkspaceGroupView): string => {
    if (group.title === 'default-workspace') return t('workspace.default')
    if (group.title.trim().length > 0) return group.title
    const parts = group.path.split(/[\\/]+/).filter((part) => part.length > 0)
    return parts.length > 0 ? parts[parts.length - 1]! : t('workspace.other')
  }

  const renderList = (sessions: SessionSummary[], groups: WorkspaceGroupView[]): void => {
    latest = sessions
    latestGroups = groups
    clearNode(list)
    if (sessions.length === 0) {
      message.textContent = t('drawer.empty')
      return
    }
    message.textContent = ''
    const byId = new Map(sessions.map((session) => [session.sessionId, session]))
    const rendered = new Set<string>()
    for (const group of groups) {
      const members = group.sessionIds
        .map((id) => byId.get(id))
        .filter((session): session is SessionSummary => session !== undefined)
      if (members.length === 0) continue
      const section = create('section', { class: 'history-group' }, [
        create('p', { class: 'history-group-title' }, [groupTitle(group)]),
      ])
      for (const session of members) {
        rendered.add(session.sessionId)
        section.appendChild(renderSessionRow(session))
      }
      list.appendChild(section)
    }
    const ungrouped = sessions.filter((session) => !rendered.has(session.sessionId))
    if (ungrouped.length > 0) {
      const section = create('section', { class: 'history-group' }, [
        create('p', { class: 'history-group-title' }, [t('workspace.other')]),
      ])
      for (const session of ungrouped) section.appendChild(renderSessionRow(session))
      list.appendChild(section)
    }
  }

  const renderSessionRow = (session: SessionSummary): HTMLElement => {
    const running = session.running
    const title = session.title !== null && session.title.length > 0 ? session.title : t('session.newTitle')
    const row = create('button', { type: 'button', class: 'list-row history-row' }, [
      create('span', { class: 'list-row-main' }, [
        create('span', { class: 'list-row-title' }, [title]),
        create('span', { class: 'list-row-meta' }, [
          t('sessions.updated', { time: formatRelativeTime(session.updatedAt) }),
        ]),
      ]),
      running ? create('span', { class: 'dot dot-running', title: t('sessions.running') }) : create('span', { class: 'dot' }),
    ])
    row.addEventListener('click', () => {
      navigate(`#/sessions/${encodeURIComponent(session.sessionId)}`)
    })
    return row
  }

  const load = async (): Promise<boolean> => {
    try {
      const response = await phoneApi.sessions()
      if (disposed) return false
      renderList(response.sessions, response.workspaces ?? [])
      ensureConnection()
      return true
    } catch (error) {
      if (disposed) return false
      if (handleAuthLikeFailure(error)) return false
      message.textContent = t('sessions.error')
      return false
    }
  }

  const createNewChat = async (): Promise<void> => {
    if (creating) return
    creating = true
    newChatButton.disabled = true
    try {
      const created = await phoneApi.createSession()
      if (disposed) return
      navigate(`#/sessions/${encodeURIComponent(created.sessionId)}`)
    } catch (error) {
      if (disposed) return
      if (handleAuthLikeFailure(error)) return
      message.textContent = t('sessions.error')
    } finally {
      creating = false
      if (!disposed) newChatButton.disabled = false
    }
  }

  let refreshing = false
  /**
   * Explicit refresh with visible feedback: the previous handler silently
   * re-fetched the list, so a tap looked like a no-op on a stable session set.
   */
  const refreshSessions = async (): Promise<void> => {
    if (refreshing) return
    refreshing = true
    reloadButton.disabled = true
    reloadButton.textContent = t('sessions.refreshing')
    message.textContent = ''
    try {
      const ok = await load()
      if (!disposed && ok) message.textContent = t('sessions.refreshed')
    } finally {
      refreshing = false
      if (!disposed) {
        reloadButton.disabled = false
        reloadButton.textContent = t('nav.reload')
      }
    }
  }

  const refreshRow = (sessionId: string, running: boolean): void => {
    const updated = latest.map((session) =>
      session.sessionId === sessionId ? { ...session, running } : session,
    )
    renderList(updated, latestGroups)
  }

  const stopState = startStateWatch((next) => {
    state = next
    updateLockUi()
  })
  const idleTicker = window.setInterval(updateLockUi, 15_000)
  const offStatus = onStatus(pill.update)
  const offEvents = onHostEvent((event, args) => {
    if (event === 'api-session/status' && args.length >= 2) {
      const sessionId = args[0]
      const running = args[1]
      if (typeof sessionId === 'string' && typeof running === 'boolean') {
        refreshRow(sessionId, running)
      }
    }
  })
  void load()

  return () => {
    disposed = true
    stopState()
    window.clearInterval(idleTicker)
    offStatus()
    offEvents()
  }
}

function renderSessionScreen(sessionId: string): () => void {
  ensureConnection()
  transcriptSessionId = sessionId
  const shell = screenShell()
  shell.mount.classList.add('screen-session')
  const pill = statusPill()

  const titleElement = create('h1', { class: 'app-title app-title-small' }, [shortSessionId(sessionId)])
  const subtitle = create('p', { class: 'app-subtitle' }, [sessionId])
  const newChatButton = button('＋', () => {
    void (async (): Promise<void> => {
      try {
        const created = await phoneApi.createSession()
        navigate(`#/sessions/${encodeURIComponent(created.sessionId)}`)
      } catch (error) {
        if (!handleAuthLikeFailure(error)) subtitle.textContent = t('sessions.error')
      }
    })()
  }, {
    class: 'btn btn-ghost btn-small btn-icon',
    'aria-label': t('nav.newChat'),
    title: t('nav.newChat'),
  })
  shell.header.appendChild(
    create('div', { class: 'header-left' }, [
      button('←', () => navigate('#/sessions'), {
        class: 'btn btn-ghost btn-small btn-icon',
        'aria-label': t('nav.back'),
        title: t('nav.back'),
      }),
      titleElement,
      subtitle,
    ]),
  )
  const lock = lockPill()
  shell.header.appendChild(create('div', { class: 'header-actions' }, [newChatButton, lock.element, pill.element]))

  const banner = create('div', { class: 'banner', hidden: '' })
  const lockNotice = create('div', { class: 'banner', hidden: '', 'data-tone': 'warn' })
  const idleBanner = create('div', { class: 'banner', hidden: '', 'data-tone': 'warn' })
  const transcript = create('div', { class: 'transcript' })
  const olderSlot = create('div', { class: 'older-slot' })
  const transcriptBody = create('div', { class: 'transcript-body' })
  transcript.appendChild(olderSlot)
  transcript.appendChild(transcriptBody)
  shell.main.appendChild(banner)
  shell.main.appendChild(lockNotice)
  shell.main.appendChild(idleBanner)
  shell.main.appendChild(transcript)

  const composer = create('form', { class: 'composer' })
  const modeGroup = create('div', { class: 'mode-group', role: 'group' })
  const queueButton = create('button', {
    type: 'button',
    class: 'mode-btn mode-btn-active',
    'aria-pressed': 'true',
  }, [t('composer.queue')])
  const steerButton = create('button', {
    type: 'button',
    class: 'mode-btn',
    'aria-pressed': 'false',
  }, [t('composer.steer')])
  modeGroup.appendChild(queueButton)
  modeGroup.appendChild(steerButton)
  const attachInput = create('input', {
    class: 'file-input',
    type: 'file',
    multiple: '',
    'aria-hidden': 'true',
    tabindex: '-1',
  })
  attachInput.setAttribute('hidden', '')
  const attachButton = button('＋', () => attachInput.click(), {
    type: 'button',
    class: 'btn composer-attach',
    'aria-label': t('composer.attach'),
    title: t('composer.attach'),
  })
  const attachmentTray = create('div', { class: 'attachment-tray' })
  attachmentTray.setAttribute('hidden', '')
  const textArea = create('textarea', {
    class: 'composer-input',
    rows: '1',
    placeholder: t('composer.placeholder'),
    'aria-label': t('composer.placeholder'),
  })
  const sendButton = create('button', {
    type: 'submit',
    class: 'btn btn-primary composer-send',
    'aria-label': t('composer.send'),
    title: t('composer.send'),
  }, ['↑'])
  const stopButton = create('button', {
    type: 'button',
    class: 'btn btn-danger composer-stop',
    hidden: '',
    'aria-label': t('composer.stop'),
    title: t('composer.stop'),
  }, ['■'])
  const composerRow = create('div', { class: 'composer-row' }, [attachButton, modeGroup, sendButton, stopButton])
  composer.appendChild(attachmentTray)
  composer.appendChild(textArea)
  composer.appendChild(composerRow)
  composer.appendChild(attachInput)
  shell.main.appendChild(composer)

  interface PendingAttachment {
    kind: 'image' | 'file'
    name: string
    mediaType?: string
    data?: string
    receiptId?: string
  }
  let pendingAttachments: PendingAttachment[] = []
  let attaching = false

  const IMAGE_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif'])

  const renderAttachmentTray = (): void => {
    clearNode(attachmentTray)
    if (pendingAttachments.length === 0) {
      attachmentTray.setAttribute('hidden', '')
      return
    }
    attachmentTray.removeAttribute('hidden')
    for (const [index, attachment] of pendingAttachments.entries()) {
      const label = attachment.name.length > 0 ? attachment.name : t('attach.file')
      const removeButton = button('×', () => {
        pendingAttachments.splice(index, 1)
        renderAttachmentTray()
      }, { class: 'btn btn-ghost attachment-remove', 'aria-label': t('attach.remove'), title: t('attach.remove') })
      attachmentTray.appendChild(
        create('span', { class: 'attachment-chip', 'data-kind': attachment.kind }, [
          create('span', { class: 'attachment-kind' }, [attachment.kind === 'image' ? '🖼' : '📎']),
          create('span', { class: 'attachment-name' }, [label]),
          removeButton,
        ]),
      )
    }
  }

  const readFileBase64 = (file: File): Promise<string> =>
    new Promise<string>((resolve, reject) => {
      try {
        const reader = new FileReader()
        reader.onerror = () => reject(new Error('read failed'))
        reader.onload = () => {
          const result = typeof reader.result === 'string' ? reader.result : ''
          const comma = result.indexOf(',')
          resolve(comma >= 0 ? result.slice(comma + 1) : '')
        }
        reader.readAsDataURL(file)
      } catch (error) {
        reject(error)
      }
    })

  const addFiles = async (files: FileList | null): Promise<void> => {
    if (files === null || files.length === 0 || attaching) return
    attaching = true
    attachButton.disabled = true
    try {
      for (const file of Array.from(files)) {
        if (pendingAttachments.length >= RC_LIMITS.maxAttachmentsPerMessage) break
        if (file.size > RC_LIMITS.maxAttachmentBytes) {
          setBanner(t('attach.tooLarge', { size: formatBytes(RC_LIMITS.maxAttachmentBytes) }), 'error')
          continue
        }
        const data = await readFileBase64(file)
        if (data.length === 0) continue
        if (IMAGE_TYPES.has(file.type)) {
          pendingAttachments.push({ kind: 'image', name: file.name, mediaType: file.type, data })
        } else {
          const uploaded = await phoneApi.uploadFile(sessionId, file.name, data)
          pendingAttachments.push({ kind: 'file', name: uploaded.file.name, receiptId: uploaded.receiptId })
        }
        renderAttachmentTray()
      }
    } catch (error) {
      if (!disposed && !handleAuthLikeFailure(error)) setBanner(t('attach.failed'), 'error')
    } finally {
      attaching = false
      if (!disposed) attachButton.disabled = false
    }
  }
  attachInput.addEventListener('change', () => {
    void addFiles(attachInput.files)
    attachInput.value = ''
  })

  let disposed = false
  let mode: 'queue' | 'steer' = 'queue'
  let cursor = 0
  let oldestSeq: number | null = null
  let hasOlder = false
  let running = false
  let loadingOlder = false
  let liveText = ''
  let liveReasoning = ''
  let liveBubble: HTMLElement | null = null
  let liveReasoningDetails: HTMLElement | null = null
  let liveReasoningBody: HTMLElement | null = null
  let liveTextBody: HTMLElement | null = null
  const entries = new Map<number, SessionEventRecord>()
  const streamId = `follow-${sessionId}-${Math.random().toString(36).slice(2, 8)}`

  let sessionState: StateResponse | null = null

  /** Header lease chip + idle warning + "another device is active" notice. */
  const updateLockUi = (): void => {
    lock.update(sessionState)
    const remaining = idleRemainingMs(sessionState)
    if (remaining !== null && remaining > 0 && remaining <= IDLE_WARNING_MS) {
      idleBanner.removeAttribute('hidden')
      idleBanner.textContent = t('lock.idleWarning', {
        minutes: Math.max(1, Math.ceil(remaining / 60_000)),
      })
    } else {
      idleBanner.setAttribute('hidden', '')
      idleBanner.textContent = ''
    }
    let notice: string | null = null
    if (sessionState !== null) {
      const summary = lockSummary(sessionState)
      if (summary !== null) {
        if (summary.labelKey === 'lock.otherDevice') notice = t('sessions.locked')
        else if (summary.labelKey === 'lock.selectionRequired') notice = t('sessions.selectionRequired')
      }
    }
    if (notice === null) {
      lockNotice.setAttribute('hidden', '')
      lockNotice.textContent = ''
    } else {
      lockNotice.removeAttribute('hidden')
      lockNotice.textContent = notice
    }
  }

  const olderButton = button(t('session.older'), () => void loadOlder(), { class: 'btn btn-small' })
  const olderEnd = create('p', { class: 'muted older-end' }, [t('session.noOlder')])

  const setBanner = (text: string | null, tone: 'warn' | 'error' = 'warn'): void => {
    if (text === null) {
      banner.setAttribute('hidden', '')
      banner.textContent = ''
      return
    }
    banner.removeAttribute('hidden')
    banner.setAttribute('data-tone', tone)
    banner.textContent = text
  }

  const updateStopButton = (): void => {
    if (running) stopButton.removeAttribute('hidden')
    else stopButton.setAttribute('hidden', '')
  }

  const updateStatusBanner = (status: ConnectionStatus): void => {
    pill.update(status)
    if (status === 'connected') {
      if (!running) setBanner(null)
      return
    }
    setBanner(t('conn.disconnectedHint'), 'warn')
  }

  /**
   * The scroll container is `.app-main` (the transcript itself has no overflow).
   * Scrolling the transcript element was why a freshly opened session stayed at
   * the beginning instead of the latest message.
   */
  const scrollToBottom = (force = false): void => {
    const container = shell.main
    const nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 160
    if (!force && !nearBottom) return
    container.scrollTop = container.scrollHeight
    if (typeof window.requestAnimationFrame === 'function') {
      window.requestAnimationFrame(() => {
        container.scrollTop = container.scrollHeight
      })
    }
  }
  requestScrollToBottom = () => {
    if (!disposed) scrollToBottom()
  }

  const clearLiveBubble = (): void => {
    liveText = ''
    liveReasoning = ''
    if (liveBubble !== null) {
      liveBubble.remove()
      liveBubble = null
    }
    liveReasoningDetails = null
    liveReasoningBody = null
    liveTextBody = null
  }

  const renderLiveBubble = (): void => {
    if (liveText.length === 0 && liveReasoning.length === 0) {
      clearLiveBubble()
      return
    }
    if (liveBubble === null) {
      liveBubble = create('div', { class: 'msg msg-assistant msg-live' }, [
        create('p', { class: 'msg-role' }, [t('role.assistant')]),
      ])
      liveReasoningDetails = create('details', { class: 'msg-reasoning msg-reasoning-live' }, [
        create('summary', { class: 'msg-reasoning-summary' }, [
          create('span', { class: 'msg-reasoning-label' }, [t('reasoning.title')]),
          create('span', { class: 'msg-reasoning-preview' }),
        ]),
        create('div', { class: 'msg-reasoning-body' }),
      ])
      // Live reasoning is expanded: the point of the stream is to show what the
      // model is thinking while it is still thinking.
      liveReasoningDetails.setAttribute('open', '')
      liveReasoningBody = liveReasoningDetails.querySelector('.msg-reasoning-body')
      liveTextBody = create('div', { class: 'msg-body' })
      liveBubble.appendChild(liveReasoningDetails)
      liveBubble.appendChild(liveTextBody)
      transcriptBody.appendChild(liveBubble)
    }
    if (liveReasoningDetails !== null) {
      if (liveReasoning.length === 0) {
        liveReasoningDetails.setAttribute('hidden', '')
      } else {
        liveReasoningDetails.removeAttribute('hidden')
        const preview = liveReasoningDetails.querySelector('.msg-reasoning-preview')
        if (preview !== null) preview.textContent = reasoningPreview(liveReasoning)
        if (liveReasoningBody !== null) liveReasoningBody.textContent = liveReasoning
      }
    }
    if (liveTextBody !== null) {
      liveTextBody.textContent = liveText
      if (liveText.length === 0) liveTextBody.setAttribute('hidden', '')
      else liveTextBody.removeAttribute('hidden')
    }
    scrollToBottom()
  }

  const appendRecord = (record: SessionEventRecord): void => {
    if (typeof record.seq !== 'number' || entries.has(record.seq)) return
    entries.set(record.seq, record)
    // A decided approval is authoritative: close any stale phone card even when
    // the answering device was the desktop or auto-review.
    settleApprovalFromEvent(record)
    if (oldestSeq === null || record.seq < oldestSeq) oldestSeq = record.seq
    if (record.seq > cursor) cursor = record.seq
    const node = renderTranscriptRecord(record)
    if (node !== null) {
      transcriptBody.appendChild(node)
      scrollToBottom()
    }
    if (record.type === 'turn/start') {
      running = true
      updateStopButton()
    } else if (record.type === 'turn/end') {
      running = false
      clearLiveBubble()
      updateStopButton()
    }
    if (record.type === 'assistant/message') clearLiveBubble()
  }

  const renderSnapshot = (frame: SnapshotFrame): void => {
    entries.clear()
    cursor = typeof frame.cursor === 'number' ? frame.cursor : 0
    oldestSeq = null
    hasOlder = frame.hasMore === true
    clearNode(transcriptBody)
    clearLiveBubble()
    for (const record of frame.records) {
      if (typeof record.seq !== 'number') continue
      entries.set(record.seq, record)
      if (oldestSeq === null || record.seq < oldestSeq) oldestSeq = record.seq
      settleApprovalFromEvent(record)
      const node = renderTranscriptRecord(record)
      if (node !== null) transcriptBody.appendChild(node)
    }
    if (cursor === 0 && frame.records.length > 0) {
      const maxSeq = Math.max(...frame.records.map((record) => record.seq))
      cursor = Number.isFinite(maxSeq) ? maxSeq : 0
    }
    const title = projectionTitle(frame.projections)
    if (title !== null) titleElement.textContent = title
    const cwd = snapshotCwd(frame.header)
    subtitle.textContent = cwd ?? sessionId
    running = snapshotRunning(frame.records)
    updateStopButton()
    updateOlder()
    scrollToBottom(true)
    // Markdown/images can grow after the first paint; pin to the latest message
    // again once the layout has settled.
    window.setTimeout(() => {
      if (!disposed) scrollToBottom(true)
    }, 250)
  }

  const updateOlder = (): void => {
    clearNode(olderSlot)
    if (hasOlder) {
      olderSlot.appendChild(olderButton)
    } else if (entries.size > 0) {
      olderSlot.appendChild(olderEnd)
    }
    if (running) stopButton.removeAttribute('hidden')
  }

  const loadOlder = async (): Promise<void> => {
    if (loadingOlder || !hasOlder || oldestSeq === null) return
    loadingOlder = true
    olderButton.disabled = true
    const previousHeight = transcript.scrollHeight
    try {
      const request: PageRequest = {
        throughSeq: cursor,
        beforeSeq: oldestSeq,
        maxMessages: RC_LIMITS.pageDefaultMessages,
      }
      const page = await phoneApi.page(sessionId, request)
      if (disposed) return
      const older = page.records.filter(
        (record) => typeof record.seq === 'number' && (oldestSeq === null || record.seq < oldestSeq),
      )
      hasOlder = page.hasMore
      if (older.length > 0) {
        const anchor = transcriptBody.firstChild
        const fragment = document.createDocumentFragment()
        for (const record of older) {
          if (typeof record.seq === 'number') entries.set(record.seq, record)
          const node = renderTranscriptRecord(record)
          if (node !== null) fragment.appendChild(node)
        }
        if (anchor !== null) transcriptBody.insertBefore(fragment, anchor)
        else transcriptBody.appendChild(fragment)
        const minSeq = Math.min(...older.map((record) => record.seq))
        if (Number.isFinite(minSeq)) oldestSeq = minSeq
        transcript.scrollTop = transcript.scrollHeight - previousHeight + transcript.scrollTop
      }
      updateOlder()
    } catch (error) {
      if (disposed) return
      if (handleAuthLikeFailure(error)) return
      setBanner(t('session.olderError'), 'error')
    } finally {
      loadingOlder = false
      olderButton.disabled = false
    }
  }

  const sendPrompt = async (): Promise<void> => {
    const text = textArea.value.trim()
    if (text.length === 0 && pendingAttachments.length === 0) {
      setBanner(t('composer.empty'), 'error')
      return
    }
    if (text.length > RC_LIMITS.maxPromptChars) {
      setBanner(t('composer.tooLong', { count: RC_LIMITS.maxPromptChars }), 'error')
      return
    }
    const content: PromptContentPart[] = []
    if (text.length > 0) content.push({ type: 'text', text })
    for (const attachment of pendingAttachments) {
      if (attachment.kind === 'image' && attachment.data !== undefined && attachment.mediaType !== undefined) {
        content.push({
          type: 'image',
          mediaType: attachment.mediaType as 'image/png' | 'image/jpeg' | 'image/webp' | 'image/gif',
          data: attachment.data,
          name: attachment.name,
        })
      } else if (attachment.receiptId !== undefined) {
        content.push({ type: 'file', receiptId: attachment.receiptId })
      }
    }
    sendButton.disabled = true
    try {
      const request: PromptRequest = {
        requestId: createRequestId(),
        mode,
        content,
        clientTimeZone: resolvedTimeZone(),
      }
      await phoneApi.prompt(sessionId, request)
      if (disposed) return
      textArea.value = ''
      pendingAttachments = []
      renderAttachmentTray()
      setBanner(t('composer.sent'), 'warn')
      window.setTimeout(() => {
        if (!disposed && !running) setBanner(null)
      }, 2_000)
    } catch (error) {
      if (disposed) return
      if (handleAuthLikeFailure(error)) return
      if (error instanceof ApiError) {
        setBanner(`${t('composer.sendError')} (${error.code})`, 'error')
      } else {
        setBanner(t('composer.sendError'), 'error')
      }
    } finally {
      if (!disposed) sendButton.disabled = false
    }
  }

  const cancelTurn = async (): Promise<void> => {
    if (!window.confirm(t('composer.stopConfirm'))) return
    stopButton.disabled = true
    try {
      await phoneApi.cancel(sessionId)
      if (!disposed) setBanner(t('composer.stopped'), 'warn')
    } catch (error) {
      if (disposed) return
      if (handleAuthLikeFailure(error)) return
      setBanner(t('composer.stopError'), 'error')
    } finally {
      if (!disposed) stopButton.disabled = false
    }
  }

  queueButton.addEventListener('click', () => {
    mode = 'queue'
    queueButton.classList.add('mode-btn-active')
    steerButton.classList.remove('mode-btn-active')
    queueButton.setAttribute('aria-pressed', 'true')
    steerButton.setAttribute('aria-pressed', 'false')
  })
  steerButton.addEventListener('click', () => {
    mode = 'steer'
    steerButton.classList.add('mode-btn-active')
    queueButton.classList.remove('mode-btn-active')
    steerButton.setAttribute('aria-pressed', 'true')
    queueButton.setAttribute('aria-pressed', 'false')
  })

  composer.addEventListener('submit', (event: Event) => {
    event.preventDefault()
    void sendPrompt()
  })
  stopButton.addEventListener('click', () => void cancelTurn())

  const offFrame = onFrame((frame) => {
    switch (frame.type) {
      case 'ready':
        if (activeStream === null) {
          setActiveStream({ streamId, sessionId, maxMessages: RC_LIMITS.defaultMessages })
        }
        break
      case 'snapshot':
        if (frame.streamId === streamId) renderSnapshot(frame)
        break
      case 'frame':
        if (frame.streamId !== streamId) break
        if (frame.kind === 'event') {
          const record = frame.event
          if (typeof record.seq === 'number' && record.seq > cursor + 1 && entries.size > 0) {
            setBanner(t('session.gap'), 'warn')
            setActiveStream(null)
            setActiveStream({ streamId, sessionId, maxMessages: RC_LIMITS.defaultMessages })
            break
          }
          appendRecord(record)
        } else if (frame.kind === 'assistant-stream') {
          const delta = streamDelta(frame.frame)
          if (delta !== null) {
            if (delta.kind === 'reasoning') liveReasoning += delta.text
            else liveText += delta.text
            renderLiveBubble()
          } else if (streamEnded(frame.frame)) {
            clearLiveBubble()
          }
        }
        break
      case 'stream-error':
        if (frame.streamId === streamId) {
          setBanner(`${t('session.streamError')} (${frame.error.code})`, 'error')
        }
        break
      case 'server-drain':
        setBanner(t('conn.drain'), 'warn')
        break
      case 'degraded':
        break
      case 'approval':
      case 'approval-cancel':
      case 'pong':
      case 'event':
      case 'rpc-result':
      default:
        break
    }
  })
  const offStatus = onStatus(updateStatusBanner)
  const offEvents = onHostEvent((event, args) => {
    if (event !== 'api-session/status' || args.length < 2) return
    if (args[0] !== sessionId || typeof args[1] !== 'boolean') return
    running = args[1]
    updateStopButton()
    if (!running) clearLiveBubble()
  })

  setActiveStream({ streamId, sessionId, maxMessages: RC_LIMITS.defaultMessages })
  updateStatusBanner(currentStatus())
  const stopState = startStateWatch((next) => {
    sessionState = next
    updateLockUi()
  })
  const idleTicker = window.setInterval(updateLockUi, 15_000)
  void phoneApi
    .projections(sessionId)
    .then((projections) => {
      if (disposed) return
      const values = projections.values
      const title = values['title']
      if (typeof title === 'string' && title.length > 0) titleElement.textContent = title
    })
    .catch((error: unknown) => {
      // Projections are best-effort; only auth/security failures change screens.
      if (!disposed) handleAuthLikeFailure(error)
    })

  return () => {
    disposed = true
    if (transcriptSessionId === sessionId) transcriptSessionId = null
    requestScrollToBottom = null
    stopState()
    window.clearInterval(idleTicker)
    setActiveStream(null)
    offFrame()
    offStatus()
    offEvents()
  }
}

function renderNotFoundScreen(): () => void {
  const shell = screenShell()
  shell.header.appendChild(create('h1', { class: 'app-title' }, [t('session.notFound')]))
  shell.main.appendChild(
    button(t('nav.sessions'), () => navigate('#/sessions'), { class: 'btn btn-primary' }),
  )
  return () => {}
}

/**
 * One safe, non-retrying screen per session-end outcome. Server close codes
 * (4001–4004) and REST security/auth errors all land here; the app never loops
 * reconnect attempts against a revoked, closed, locked or idle session.
 */
function renderSessionEndScreen(reason: SessionEndReason): void {
  const titles: Record<SessionEndReason, MessageKey> = {
    'device-lost': 'auth.title',
    'security-closed': 'security.title',
    'idle-timeout': 'lock.idleExpiredTitle',
    'lease-lost': 'lock.leaseLostTitle',
    'access-required': 'access.title',
  }
  const bodies: Record<SessionEndReason, MessageKey> = {
    'device-lost': 'auth.body',
    'security-closed': 'security.body',
    'idle-timeout': 'lock.idleExpiredBody',
    'lease-lost': 'lock.leaseLostBody',
    'access-required': 'access.body',
  }
  const labels: Record<SessionEndReason, MessageKey> = {
    'device-lost': 'auth.pair',
    'security-closed': 'nav.reload',
    'idle-timeout': 'nav.reload',
    'lease-lost': 'nav.reload',
    'access-required': 'nav.reload',
  }
  const act = (): void => {
    clearSessionEnd()
    if (reason === 'device-lost') {
      navigate('#/pair')
      return
    }
    // Re-enabling Remote Control (or fixing the Access sign-in) happens outside
    // this app; a reload re-runs the health precheck with fresh state.
    location.reload()
  }
  const shell = screenShell()
  shell.header.appendChild(create('h1', { class: 'app-title' }, [t(titles[reason])]))
  shell.main.appendChild(
    create('section', { class: 'card card-error' }, [
      create('h2', { class: 'card-title' }, [t(titles[reason])]),
      create('p', { class: 'card-body' }, [t(bodies[reason])]),
      create('div', { class: 'card-actions' }, [
        button(t(labels[reason]), act, { class: 'btn btn-primary' }),
      ]),
    ]),
  )
  shell.footer.appendChild(create('p', { class: 'muted' }, [t('footer.version')]))
}

function unpair(): void {
  if (!window.confirm(t('sessions.unpairConfirm'))) return
  void phoneApi
    .logout()
    .then(() => {
      navigate('#/pair')
    })
    .catch(() => {
      navigate('#/pair')
    })
}

/* -------------------------------------------------------------------------- */
/* Transcript record rendering                                                */
/* -------------------------------------------------------------------------- */

function renderTranscriptRecord(record: SessionEventRecord): HTMLElement | null {
  const data = isRecord(record.data) ? record.data : null
  switch (record.type) {
    case 'user/message': {
      if (!isUserAuthoredRecord(record)) return null
      const content = extractContent(data === null ? null : data['content'])
      if (content.text.length === 0 && content.images.length === 0 && content.files.length === 0) return null
      return renderUserMessage(content)
    }
    case 'assistant/message': {
      if (data === null) return null
      const message = data['message']
      const content = extractContent(isRecord(message) ? message['content'] : null)
      if (
        content.text.length === 0 &&
        content.reasoning.length === 0 &&
        content.images.length === 0 &&
        content.files.length === 0
      ) {
        return null
      }
      return renderAssistantMessage(content)
    }
    case 'tool/call': {
      if (data === null) return null
      const name = typeof data['name'] === 'string' ? data['name'] : t('role.tool')
      const args = typeof data['arguments'] === 'string' ? data['arguments'] : ''
      const details = create('details', { class: 'tool-call' }, [
        create('summary', { class: 'tool-call-summary' }, [`${t('role.tool')}: ${name}`]),
      ])
      if (args.length > 0) {
        details.appendChild(
          create('pre', { class: 'tool-call-args' }, [truncate(args, 4_000)]),
        )
      }
      return details
    }
    case 'tool/result': {
      if (data === null) return null
      const message = data['message']
      const text = isRecord(message) ? messageText(message['content']) : ''
      const isError = isRecord(data['error']) || (isRecord(message) && message['isError'] === true)
      const details = create('details', { class: `tool-result${isError ? ' tool-result-error' : ''}` }, [
        create('summary', { class: 'tool-call-summary' }, [
          isError ? `${t('role.tool')}: error` : `${t('role.tool')}: result`,
        ]),
      ])
      if (text.length > 0) {
        details.appendChild(create('pre', { class: 'tool-call-args' }, [truncate(text, 4_000)]))
      }
      return details
    }
    case 'turn/end': {
      if (data === null) return null
      const reason = data['reason']
      if (!isRecord(reason)) return null
      const kind = reason['kind']
      if (kind === 'completed' || kind === 'forked') return create('div', { class: 'turn-divider' })
      if (kind === 'aborted' || kind === 'interrupted') {
        return create('div', { class: 'turn-note' }, [t('turn.stopped')])
      }
      if (kind === 'error' || kind === 'blocked' || kind === 'max-tokens') {
        return create('div', { class: 'turn-note turn-note-error' }, [t('turn.failed')])
      }
      return create('div', { class: 'turn-divider' })
    }
    case 'approval/decided': {
      if (data === null) return null
      const outcome = data['outcome']
      if (typeof outcome !== 'string') return null
      const label = outcome === 'allowed-once' ? t('approval.allowOnce') : outcome === 'rejected' ? t('approval.reject') : outcome
      return create('div', { class: 'turn-note' }, [`${t('approval.title')}: ${label}`])
    }
    default:
      return null
  }
}

function renderMessage(role: 'user' | 'assistant', roleLabel: string, text: string): HTMLElement {
  return create('article', { class: `msg msg-${role}`, 'data-role': role }, [
    create('p', { class: 'msg-role' }, [roleLabel]),
    create('div', { class: 'msg-body' }, [text]),
  ])
}

function snapshotCwd(header: unknown): string | null {
  if (!isRecord(header)) return null
  const cwd = header['cwd']
  return typeof cwd === 'string' && cwd.length > 0 ? cwd : null
}

function projectionTitle(projections: SnapshotFrame['projections']): string | null {
  if (projections === null) return null
  const values = projections.values
  const title = values['title']
  return typeof title === 'string' && title.length > 0 ? title : null
}

function snapshotRunning(records: readonly SessionEventRecord[]): boolean {
  let running = false
  for (const record of records) {
    if (record.type === 'turn/start') running = true
    else if (record.type === 'turn/end') running = false
  }
  return running
}

function streamDelta(frame: unknown): { kind: 'text' | 'reasoning'; text: string } | null {
  if (!isRecord(frame) || frame['type'] !== 'chunk') return null
  const chunk = frame['chunk']
  if (!isRecord(chunk)) return null
  const type = chunk['type']
  if (type !== 'text-delta' && type !== 'reasoning-delta') return null
  if (typeof chunk['text'] !== 'string') return null
  return { kind: type === 'reasoning-delta' ? 'reasoning' : 'text', text: chunk['text'] }
}

function streamEnded(frame: unknown): boolean {
  return isRecord(frame) && frame['type'] === 'end'
}

function createRequestId(): string {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID()
    }
  } catch {
    // fall through to the time-based id
  }
  return `rc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
}

function devicePlatform(): string {
  const userAgent = navigator.userAgent
  if (/android/i.test(userAgent)) return 'android'
  if (/iphone|ipad|ipod/i.test(userAgent)) return 'ios'
  if (/windows/i.test(userAgent)) return 'windows'
  if (/mac os x/i.test(userAgent)) return 'macos'
  if (/linux/i.test(userAgent)) return 'linux'
  return 'web'
}

function deviceName(): string {
  const platform = devicePlatform()
  switch (platform) {
    case 'ios':
      return 'iPhone'
    case 'android':
      return 'Android phone'
    case 'windows':
      return 'Windows browser'
    case 'macos':
      return 'Mac browser'
    case 'linux':
      return 'Linux browser'
    default:
      return 'Phone browser'
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms)
  })
}

/* -------------------------------------------------------------------------- */
/* Service worker registration (secure context only)                          */
/* -------------------------------------------------------------------------- */

function registerServiceWorker(): void {
  try {
    if (!('serviceWorker' in navigator)) return
    if (window.isSecureContext !== true) return
    void navigator.serviceWorker.register('/rc/sw.js', { scope: '/rc/' }).catch(() => {
      // offline shell is an enhancement; failure never blocks the app
    })
  } catch {
    // ignore
  }
}

/* -------------------------------------------------------------------------- */
/* Boot                                                                       */
/* -------------------------------------------------------------------------- */

function start(): void {
  // Strip the one-time pairing code from the URL/history before anything else
  // (it must never survive in the address bar, history or a later reload).
  consumePairingCodeFromUrl()
  installGlobalHandlers()
  registerServiceWorker()
  try {
    document.documentElement.lang = language
  } catch {
    // ignore
  }
  // Global TR/EN switch: fixed and reachable from every route without storage.
  document.body.appendChild(languageToggle())
  renderRoute()
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start, { once: true })
} else {
  start()
}
