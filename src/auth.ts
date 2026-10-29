/**
 * HTTP security helpers shared by the phone API, the WebSocket upgrade and the
 * desktop admin routes.
 *
 * The module is deliberately dependency-free (node:http/node:net/node:crypto
 * only) and implements the defence primitives from design §9:
 *
 * - cookie serialization/parsing (`rc_access` / `rc_refresh`, HttpOnly,
 *   SameSite=Strict, Path=/rc, `Secure` only when the listener terminates TLS),
 * - fixed-window rate limiting (pairing 5/min per IP + 20/min global),
 *   keyed by the caller-supplied bucket key,
 * - the canonical Host/Origin/`Sec-Fetch-Site` fence (DNS-rebinding defence):
 *   the *controller API* is `createOriginPolicy` + `checkOriginFence`, which
 *   match a serialized origin exactly (scheme + host + effective port) and the
 *   `Host` authority exactly; the older `isAuthorityAllowed` helper keeps its
 *   historical authority-only semantics for existing callers,
 * - provider-scoped client-IP resolution (`resolveClientIp`): only the
 *   plugin's own cloudflared loopback peer may supply `CF-Connecting-IP`;
 *   SSH/external loopback peers have no trustworthy identity (explicit
 *   `unknown` + shared rate-limit bucket); `X-Forwarded-For` is never trusted,
 * - bounded `sanitizeUserAgent`/`sanitizeExternalText` for audit metadata
 *   (no control/ANSI/line-break injection),
 * - constant-time secret comparison (`hashExternalSecret`/`secretsEqual`) that
 *   never throws on malformed input,
 * - CSRF header check (`X-RC-CSRF: 1`),
 * - a bounded JSON body reader and the single REST error envelope
 *   `{ok:false,error:{code,message,retryAfterMs?}}`.
 *
 * No token, pairing code, prompt or cookie value is ever logged or retained
 * here; values only live in the caller's cookie HashMap and in the response.
 */

import { createHash, timingSafeEqual } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { isIP } from 'node:net'

import type { RcErrorCode, RcErrorEnvelope, TunnelMode } from './shared/protocol.js'
import { RC_CSRF_HEADER } from './shared/protocol.js'

/* ------------------------------------------------------------------------- */
/* Errors                                                                    */
/* ------------------------------------------------------------------------- */

/**
 * Error carrying an HTTP status and a canonical RC error code. Callers (the
 * controller, admin routes) can pass it straight to `sendError`.
 */
export class HttpError extends Error {
  readonly status: number
  readonly code: RcErrorCode

  constructor(status: number, code: RcErrorCode, message: string) {
    super(message)
    this.name = 'HttpError'
    this.status = status
    this.code = code
  }
}

/* ------------------------------------------------------------------------- */
/* Header helpers                                                            */
/* ------------------------------------------------------------------------- */

function headerValue(headers: IncomingMessage['headers'], name: string): string | undefined {
  const raw = headers[name]
  if (raw === undefined) return undefined
  const value = Array.isArray(raw) ? raw[0] : raw
  return typeof value === 'string' ? value : undefined
}

/* ------------------------------------------------------------------------- */
/* Cookies                                                                   */
/* ------------------------------------------------------------------------- */

const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

export interface CookieOptions {
  maxAgeSeconds?: number
  path?: string
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
}

/** Parse a `Cookie` request header into a name→value map (never throws). */
export function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {}
  if (header === undefined || header.trim() === '') return cookies
  for (const part of header.split(';')) {
    const separator = part.indexOf('=')
    if (separator <= 0) continue
    const name = part.slice(0, separator).trim()
    if (name === '') continue
    const rawValue = part.slice(separator + 1).trim()
    let value = rawValue
    try {
      value = decodeURIComponent(rawValue)
    } catch {
      // Keep the raw value: a malformed escape must not break cookie parsing.
    }
    cookies[name] = value
  }
  return cookies
}

/**
 * Serialize one `Set-Cookie` value. Defaults match the design: HttpOnly,
 * SameSite=Strict, Path=/rc; `Secure` is only added when the caller says the
 * connection is TLS-terminated.
 */
export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
  if (!COOKIE_NAME.test(name)) throw new Error('invalid cookie name')
  const parts: string[] = [`${name}=${encodeURIComponent(String(value))}`]
  const path = options.path ?? '/rc'
  if (path !== '') parts.push(`Path=${path}`)
  if (options.maxAgeSeconds !== undefined) {
    const seconds = Math.max(0, Math.floor(options.maxAgeSeconds))
    parts.push(`Max-Age=${seconds}`)
  }
  if (options.httpOnly !== false) parts.push('HttpOnly')
  if (options.secure === true) parts.push('Secure')
  const sameSite = options.sameSite ?? 'Strict'
  parts.push(`SameSite=${sameSite}`)
  return parts.join('; ')
}

/** Expire a cookie (used by logout/revoke flows). */
export function clearCookie(
  name: string,
  options: Omit<CookieOptions, 'maxAgeSeconds'> = {},
): string {
  return serializeCookie(name, '', { ...options, maxAgeSeconds: 0 })
}

/* ------------------------------------------------------------------------- */
/* Rate limiting                                                             */
/* ------------------------------------------------------------------------- */

export interface RateLimitRule {
  limit: number
  windowMs: number
}

/**
 * Fixed-window in-memory rate limiter. `allow()` returns false once `limit`
 * hits inside the current window. Used for pairing claims (IP + global) and
 * repeated auth failures; not a security boundary by itself.
 */
export function createRateLimiter(rule: RateLimitRule): { allow(key: string): boolean } {
  const limit = Math.max(1, Math.floor(rule.limit))
  const windowMs = Math.max(1, Math.floor(rule.windowMs))
  const buckets = new Map<string, { count: number; resetAt: number }>()
  return {
    allow(key: string): boolean {
      const now = Date.now()
      if (buckets.size > 4096) {
        for (const [bucketKey, bucket] of buckets) {
          if (bucket.resetAt <= now) buckets.delete(bucketKey)
        }
      }
      const bucket = buckets.get(key)
      if (bucket === undefined || bucket.resetAt <= now) {
        buckets.set(key, { count: 1, resetAt: now + windowMs })
        return true
      }
      // Every call counts, including rejected ones (caller-visible rate pressure).
      bucket.count += 1
      return bucket.count <= limit
    },
  }
}

/* ------------------------------------------------------------------------- */
/* Host / Origin fence                                                       */
/* ------------------------------------------------------------------------- */

function normalizeAuthority(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, '')
}

function hasAuthority(authorities: ReadonlySet<string>, value: string): boolean {
  const normalized = normalizeAuthority(value)
  if (authorities.has(normalized)) return true
  for (const authority of authorities) {
    if (normalizeAuthority(authority) === normalized) return true
  }
  return false
}

/**
 * DNS-rebinding / cross-origin fence (design §10.2).
 *
 * `host` must be one of the known exact authorities. When an `Origin` header is
 * present it must be an http(s) origin whose authority is both allowed and the
 * same as the request `Host`. `Sec-Fetch-Site: cross-site` is always rejected;
 * `requireOrigin` (WebSocket upgrades) rejects requests without `Origin`.
 */
export function isAuthorityAllowed(
  request: IncomingMessage,
  authorities: ReadonlySet<string>,
  requireOrigin: boolean,
): boolean {
  const site = headerValue(request.headers, 'sec-fetch-site')
  if (site !== undefined && site.trim().toLowerCase() === 'cross-site') return false

  const host = headerValue(request.headers, 'host')
  if (host === undefined || host.trim() === '') return false
  if (!hasAuthority(authorities, host)) return false

  const origin = headerValue(request.headers, 'origin')
  if (origin === undefined || origin.trim() === '') return !requireOrigin

  let parsed: URL
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
  if (parsed.username !== '' || parsed.password !== '') return false
  if (!hasAuthority(authorities, parsed.host)) return false
  return normalizeAuthority(parsed.host) === normalizeAuthority(host)
}

/** Every authenticated mutation must carry `X-RC-CSRF: 1`. */
export function isCsrfOk(request: IncomingMessage): boolean {
  return headerValue(request.headers, RC_CSRF_HEADER) === '1'
}

/* ------------------------------------------------------------------------- */
/* Canonical Host/Origin fence (controller API)                              */
/* ------------------------------------------------------------------------- */

/** Scheme of a canonical origin; the listener is either plain HTTP or TLS. */
export type OriginProtocol = 'http' | 'https'

/** Why the canonical fence rejected a request. Never contains request values. */
export type OriginFenceFailure =
  | 'cross-site'
  | 'host-missing'
  | 'host-malformed'
  | 'host-not-allowed'
  | 'origin-missing'
  | 'origin-null'
  | 'origin-malformed'
  | 'origin-disallowed'
  | 'origin-host-mismatch'

/**
 * Result of `checkOriginFence`. On success `origin` is the canonicalized
 * `Origin` value, or `null` for a non-browser same-origin request that is
 * allowed not to send one (HTTP reads). Every rejection carries the public
 * `ORIGIN` error code plus a non-sensitive machine-readable reason.
 */
export type FenceResult =
  | { ok: true; host: string; origin: string | null }
  | { ok: false; code: 'ORIGIN'; reason: OriginFenceFailure }

/**
 * The exact allowlist the canonical fence matches against.
 *
 * - `allowedOrigins`: canonical serialized origins (`scheme://host[:port]`,
 *   default ports omitted). A browser `Origin` header must match one of these
 *   *exactly* — the scheme and effective port are part of the comparison.
 * - `allowedAuthorities`: canonical `Host` values (`host[:port]`, lowercase,
 *   trailing dot removed, default port omitted). The request `Host` must match
 *   one exactly, and the `Origin` authority must equal the `Host` authority.
 */
export interface OriginFencePolicy {
  readonly allowedOrigins: ReadonlySet<string>
  readonly allowedAuthorities: ReadonlySet<string>
}

export interface OriginFenceOptions {
  /**
   * Reject a request that carries no `Origin` header (WebSocket upgrades and
   * browser mutations). HTTP GET reads may leave it false.
   */
  requireOrigin?: boolean
}

export interface OriginPolicyInput {
  /** Extra allowed origins (raw strings; non-canonical entries are ignored). */
  origins?: Iterable<string>
  /** Allowed `Host` authorities (raw strings; non-canonical entries are ignored). */
  authorities?: Iterable<string>
}

const ORIGIN_INPUT = /^https?:\/\/[^/?#]+$/i
const HOST_INPUT = /^[^\s/\\?#@,]+$/
const MAX_ORIGIN_INPUT = 512

function fenceHeader(request: IncomingMessage, name: string): { value: string | undefined; ambiguous: boolean } {
  const raw = request.headers[name]
  if (raw === undefined) return { value: undefined, ambiguous: false }
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return { value: undefined, ambiguous: true }
    return { value: typeof raw[0] === 'string' ? raw[0] : undefined, ambiguous: false }
  }
  return { value: typeof raw === 'string' ? raw : undefined, ambiguous: false }
}

function fenceFailure(reason: OriginFenceFailure): FenceResult {
  return { ok: false, code: 'ORIGIN', reason }
}

/** Canonical origin authority (lowercase, trailing dot removed, default port omitted). */
function canonicalAuthorityFromUrl(url: URL): string | null {
  let hostname = url.hostname
  while (hostname.endsWith('.')) hostname = hostname.slice(0, -1)
  if (hostname === '') return null
  const port = url.port
  if (port !== '') {
    const numeric = Number(port)
    if (!Number.isInteger(numeric) || numeric < 1 || numeric > 65_535) return null
  }
  return port === '' ? hostname : `${hostname}:${port}`
}

/**
 * Canonicalize a serialized http(s) origin: `scheme://host[:port]`.
 *
 * Rejects a missing/malformed value, any non-http(s) scheme, credentials,
 * a path/query/fragment, and normalizes case, a trailing dot, IPv6 brackets
 * and the scheme's default port. `{ allowTrailingSlash: true }` accepts a
 * single trailing `/` (config-friendly); request headers stay strict.
 */
export function canonicalOrigin(value: unknown, options: { allowTrailingSlash?: boolean } = {}): string | null {
  if (typeof value !== 'string') return null
  let raw = value.trim()
  if (raw === '' || raw.length > MAX_ORIGIN_INPUT) return null
  if (options.allowTrailingSlash === true) raw = raw.replace(/\/+$/, '')
  if (!ORIGIN_INPUT.test(raw)) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
  if (url.username !== '' || url.password !== '') return null
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') return null
  const authority = canonicalAuthorityFromUrl(url)
  if (authority === null) return null
  return `${url.protocol}//${authority}`
}

/**
 * Canonicalize a `Host` authority: lowercase `host[:port]`, trailing dot
 * removed, IPv6 kept bracketed. Rejects empty/malformed values, credentials and
 * anything that is not a bare authority.
 */
export function canonicalAuthority(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const raw = value.trim()
  if (raw === '' || raw.length > MAX_ORIGIN_INPUT) return null
  if (!HOST_INPUT.test(raw)) return null
  let url: URL
  try {
    url = new URL(`http://${raw}`)
  } catch {
    return null
  }
  if (url.username !== '' || url.password !== '') return null
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') return null
  if (!/^[0-9]*$/.test(url.port)) return null
  return canonicalAuthorityFromUrl(url)
}

/** Derive a canonical origin from a bind `Host` authority and protocol. */
export function originForAuthority(authority: unknown, protocol: OriginProtocol): string | null {
  if (protocol !== 'http' && protocol !== 'https') return null
  const canonical = canonicalAuthority(authority)
  if (canonical === null) return null
  return canonicalOrigin(`${protocol}://${canonical}`)
}

/** Build the exact allowlist the canonical fence enforces. Invalid entries are ignored (fail closed). */
export function createOriginPolicy(input: OriginPolicyInput = {}): OriginFencePolicy {
  const allowedOrigins = new Set<string>()
  for (const value of input.origins ?? []) {
    const canonical = canonicalOrigin(value, { allowTrailingSlash: true })
    if (canonical !== null) allowedOrigins.add(canonical)
  }
  const allowedAuthorities = new Set<string>()
  for (const value of input.authorities ?? []) {
    const canonical = canonicalAuthority(value)
    if (canonical !== null) allowedAuthorities.add(canonical)
  }
  return { allowedOrigins, allowedAuthorities }
}

/**
 * The canonical DNS-rebinding / cross-origin fence (design §9.2).
 *
 * `Host` must be an exact allowed authority. `Sec-Fetch-Site: cross-site` is
 * always rejected. When `Origin` is present it must be a serialized http(s)
 * origin that is *exactly* in `policy.allowedOrigins` (scheme + host + effective
 * port), and its authority must equal the request `Host`. `null`, malformed,
 * duplicate, credential-bearing, non-http(s) origins and Origin/Host mismatches
 * are rejected. With `requireOrigin` (WS upgrades, browser mutations) a missing
 * `Origin` is rejected too.
 */
export function checkOriginFence(
  request: IncomingMessage,
  policy: OriginFencePolicy,
  options: OriginFenceOptions = {},
): FenceResult {
  const site = fenceHeader(request, 'sec-fetch-site')
  if (site.ambiguous) return fenceFailure('cross-site')
  if (site.value !== undefined && site.value.trim().toLowerCase() === 'cross-site') {
    return fenceFailure('cross-site')
  }

  const hostHeader = fenceHeader(request, 'host')
  if (hostHeader.ambiguous) return fenceFailure('host-malformed')
  const rawHost = hostHeader.value?.trim() ?? ''
  if (rawHost === '') return fenceFailure('host-missing')
  const host = canonicalAuthority(rawHost)
  if (host === null) return fenceFailure('host-malformed')
  if (!policy.allowedAuthorities.has(host)) return fenceFailure('host-not-allowed')

  const originHeader = fenceHeader(request, 'origin')
  if (originHeader.ambiguous) return fenceFailure('origin-malformed')
  const rawOrigin = originHeader.value?.trim() ?? ''
  if (rawOrigin === '') {
    return options.requireOrigin === true ? fenceFailure('origin-missing') : { ok: true, host, origin: null }
  }
  // Browsers serialize opaque origins as the literal string "null".
  if (rawOrigin.toLowerCase() === 'null') return fenceFailure('origin-null')
  const origin = canonicalOrigin(rawOrigin)
  if (origin === null) return fenceFailure('origin-malformed')
  if (!policy.allowedOrigins.has(origin)) return fenceFailure('origin-disallowed')

  const authoritySeparator = origin.indexOf('://')
  const originAuthority = canonicalAuthority(origin.slice(authoritySeparator + 3))
  if (originAuthority === null || originAuthority !== host) return fenceFailure('origin-host-mismatch')
  return { ok: true, host, origin }
}

/* ------------------------------------------------------------------------- */
/* Client address                                                            */
/* ------------------------------------------------------------------------- */

function normalizeAddress(value: string | undefined): string | null {
  if (typeof value !== 'string' || value === '') return null
  const trimmed = value.trim()
  if (trimmed.toLowerCase().startsWith('::ffff:')) return trimmed.slice(7)
  return trimmed
}

function isLoopbackAddress(value: string | null): boolean {
  if (value === null) return false
  if (value === '::1' || value === '0:0:0:0:0:0:0:1') return true
  return isIP(value) === 4 && value.startsWith('127.')
}

/**
 * Best-effort client address for rate-limit buckets.
 *
 * Legacy helper kept for the current controller: behind the plugin's own
 * cloudflared tunnel every socket comes from loopback, so `CF-Connecting-IP` is
 * honoured *only* for loopback peers. New code must use provider-scoped
 * `resolveClientIp` instead (an SSH/external loopback peer has no trustworthy
 * client IP, and a loopback peer without the CF header is not "127.0.0.1").
 */
export function clientIp(request: IncomingMessage): string {
  const remote = normalizeAddress(request.socket?.remoteAddress)
  if (isLoopbackAddress(remote)) {
    const forwarded = headerValue(request.headers, 'cf-connecting-ip')
    if (forwarded !== undefined) {
      const candidate = forwarded.trim()
      if (isIP(candidate) !== 0) return candidate
    }
  }
  return remote ?? 'unknown'
}

/* ------------------------------------------------------------------------- */
/* Provider-scoped client address resolution                                 */
/* ------------------------------------------------------------------------- */

/**
 * Who terminates the public connection in front of the listener:
 * - `cloudflare`: the plugin's own cloudflared child forwards from loopback and
 *   sets `CF-Connecting-IP`;
 * - `ssh`: localhost.run-style reverse tunnel from a loopback SSH client; the
 *   peer is trusted infrastructure but carries no trustworthy client address;
 * - `external`: operator-managed connector; no client-identity header policy;
 * - `none`: the socket peer is the real client (loopback or direct LAN).
 */
export type TrustedProxyPolicy = 'none' | 'cloudflare' | 'ssh' | 'external'

/** Literal used when the real client address cannot be established. */
export const UNKNOWN_CLIENT_IP = 'unknown'

/**
 * Shared rate-limit bucket for clients whose address cannot be established.
 * Unknown clients must share one conservative bucket instead of bypassing the
 * per-IP limits.
 */
export const UNKNOWN_CLIENT_IP_BUCKET = 'shared:unknown-client'

export interface ClientIpOptions {
  /** Provider-scoped trusted-proxy policy. Defaults to `none` (trust no header). */
  trustedProxy?: TrustedProxyPolicy
}

export interface ClientIpResolution {
  /** Resolved client IP, or null when it cannot be established reliably. */
  ip: string | null
  /** Bucket key for limiting; unknown clients share `UNKNOWN_CLIENT_IP_BUCKET`. */
  bucket: string
  /** How `ip` was established. */
  source: 'socket' | 'cloudflare' | 'unknown'
  /** True when the TCP peer is loopback (tunnel/connector territory). */
  peerLoopback: boolean
  /** True when the peer is loopback but the policy provides no trustworthy identity. */
  untrusted: boolean
  /** Spoofable header that was present but deliberately ignored (never trusted). */
  ignoredHeader: 'cf-connecting-ip' | 'x-forwarded-for' | 'forwarded' | null
}

const SPOOFABLE_HEADERS = ['cf-connecting-ip', 'x-forwarded-for', 'forwarded'] as const

function ignoredSpoofableHeader(
  request: IncomingMessage,
  usedHeader: (typeof SPOOFABLE_HEADERS)[number] | null,
): ClientIpResolution['ignoredHeader'] {
  for (const name of SPOOFABLE_HEADERS) {
    if (name === usedHeader) continue
    if (request.headers[name] !== undefined) return name
  }
  return null
}

function unknownClientIp(
  peerLoopback: boolean,
  ignoredHeader: ClientIpResolution['ignoredHeader'],
): ClientIpResolution {
  return {
    ip: null,
    bucket: UNKNOWN_CLIENT_IP_BUCKET,
    source: 'unknown',
    peerLoopback,
    untrusted: true,
    ignoredHeader,
  }
}

/**
 * Resolve the real client address under an explicit trusted-proxy policy.
 *
 * - Direct (non-loopback) peers: the socket address is the client address; any
 *   `CF-Connecting-IP`/`X-Forwarded-For`/`Forwarded` header is ignored.
 * - Loopback peer + `cloudflare`: the peer is the plugin's own connector, so a
 *   well-formed `CF-Connecting-IP` is honoured; a missing/malformed one yields
 *   an explicit unknown + shared bucket (never the connector's 127.0.0.1).
 * - Loopback peer + `ssh`/`external`: no trustworthy client identity -> unknown
 *   + shared bucket.
 * - Loopback peer + `none`: the peer is the real local client.
 * - `X-Forwarded-For` and `Forwarded` are never trusted.
 *
 * Never throws; a missing socket address yields an unknown/resolved shared
 * result. No header value is ever logged by this module.
 */
export function resolveClientIp(request: IncomingMessage, options: ClientIpOptions = {}): ClientIpResolution {
  const policy = options.trustedProxy ?? 'none'
  const remote = normalizeAddress(request.socket?.remoteAddress)
  const peerLoopback = isLoopbackAddress(remote)
  const ignored = () => ignoredSpoofableHeader(request, null)

  if (remote === null) return unknownClientIp(false, ignored())

  if (!peerLoopback) {
    return {
      ip: remote,
      bucket: remote,
      source: 'socket',
      peerLoopback: false,
      untrusted: false,
      ignoredHeader: ignored(),
    }
  }

  if (policy === 'cloudflare') {
    const forwarded = headerValue(request.headers, 'cf-connecting-ip')
    if (forwarded !== undefined) {
      const candidate = normalizeAddress(forwarded.trim())
      if (candidate !== null && isIP(candidate) !== 0) {
        return {
          ip: candidate,
          bucket: candidate,
          source: 'cloudflare',
          peerLoopback: true,
          untrusted: false,
          ignoredHeader: ignoredSpoofableHeader(request, 'cf-connecting-ip'),
        }
      }
    }
    return unknownClientIp(true, ignoredSpoofableHeader(request, null))
  }

  if (policy === 'ssh' || policy === 'external') {
    // A loopback peer here is trusted tunnel infrastructure, not a client, and
    // no header scheme is defined that could establish the real client address.
    return unknownClientIp(true, ignoredSpoofableHeader(request, null))
  }

  // `none`: direct loopback client (same machine / local test harness).
  return {
    ip: remote,
    bucket: remote,
    source: 'socket',
    peerLoopback: true,
    untrusted: false,
    ignoredHeader: ignoredSpoofableHeader(request, null),
  }
}

/** Map the configured tunnel mode to the trusted-proxy policy it implies. */
export function proxyPolicyForTunnelMode(mode: TunnelMode | null | undefined): TrustedProxyPolicy {
  switch (mode) {
    case 'quick':
    case 'named':
    case 'named-local':
      return 'cloudflare'
    case 'ssh':
      return 'ssh'
    case 'external':
      return 'external'
    default:
      return 'none'
  }
}

/* ------------------------------------------------------------------------- */
/* External text sanitization (audit / display metadata)                     */
/* ------------------------------------------------------------------------- */

/** Default bound for sanitized User-Agent / external audit metadata. */
export const MAX_EXTERNAL_TEXT_LENGTH = 256

/* ANSI/VT escape sequences (CSI, OSC, and single-character escapes). */
const ANSI_OSC = /\u001b\][\s\S]*?(?:\u0007|\u001b\\)/g
const ANSI_CSI = /[\u001b\u009b]\[[0-?]*[ -/]*[@-~]/g
const ANSI_SIMPLE = /\u001b[@-Z\\-_]/g
/* Line breaks become a space (line-injection defence). */
const LINE_BREAKS = /[\t\n\v\f\r\u2028\u2029]/g
/* Remaining C0/C1/DEL controls plus bidi/format overrides are removed. */
const CONTROL_CHARS = /[\u0000-\u0008\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g

function boundText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text
  // Never cut a surrogate pair in half.
  let bounded = text.slice(0, maxLength)
  const last = bounded.charCodeAt(bounded.length - 1)
  if (last >= 0xd800 && last <= 0xdbff) bounded = bounded.slice(0, -1)
  return bounded
}

/**
 * Sanitize untrusted external text (User-Agent, provider text, audit metadata)
 * into a bounded single-line string safe for logs and the desktop panel.
 *
 * Strips ANSI escape sequences and C0/C1/DEL control characters, turns tabs and
 * line breaks into spaces, collapses whitespace and truncates to `maxLength`.
 * A non-string, empty or fully stripped value returns `null`; malformed input
 * never throws.
 */
export function sanitizeExternalText(value: unknown, maxLength: number = MAX_EXTERNAL_TEXT_LENGTH): string | null {
  if (typeof value !== 'string') return null
  const limit =
    Number.isSafeInteger(maxLength) && maxLength > 0 ? Math.min(4096, maxLength) : MAX_EXTERNAL_TEXT_LENGTH
  let text = value.replace(ANSI_OSC, '').replace(ANSI_CSI, '').replace(ANSI_SIMPLE, '')
  text = text.replace(LINE_BREAKS, ' ').replace(CONTROL_CHARS, '')
  text = boundText(text, limit).replace(/ +/g, ' ').trim()
  return text === '' ? null : text
}

/** Sanitize an untrusted User-Agent for audit metadata (bounded single line). */
export function sanitizeUserAgent(value: unknown): string | null {
  return sanitizeExternalText(value, MAX_EXTERNAL_TEXT_LENGTH)
}

/* ------------------------------------------------------------------------- */
/* Constant-time secret comparison                                           */
/* ------------------------------------------------------------------------- */

/**
 * SHA-256 hex digest of an external secret (refresh/cookie/CSRF material) for
 * constant-length comparisons. Non-string input returns null (never throws).
 */
export function hashExternalSecret(value: unknown): string | null {
  if (typeof value !== 'string') return null
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/**
 * Constant-time equality for two secret strings. Both inputs are SHA-256
 * digested first so the comparison length never depends on the input length
 * (and a malformed/non-string/empty input can never throw or be equal).
 */
export function secretsEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  if (left === '' || right === '') return false
  const a = createHash('sha256').update(left, 'utf8').digest()
  const b = createHash('sha256').update(right, 'utf8').digest()
  return timingSafeEqual(a, b)
}

/* ------------------------------------------------------------------------- */
/* Body parsing                                                              */
/* ------------------------------------------------------------------------- */

const DEFAULT_BODY_LIMIT = 64 * 1024

/**
 * Read and JSON-parse a request body, bounded by `limitBytes`. Empty bodies
 * resolve to `null`; invalid/malformed bodies reject with an `HttpError`
 * carrying `BAD_REQUEST` (and 413 for oversize payloads).
 */
export function readJsonBody(
  request: IncomingMessage,
  limitBytes: number = DEFAULT_BODY_LIMIT,
): Promise<unknown> {
  const limit = Math.max(1, Math.floor(limitBytes))
  return new Promise<unknown>((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    let settled = false

    const fail = (error: Error): void => {
      if (settled) return
      settled = true
      request.removeListener('data', onData)
      request.removeListener('end', onEnd)
      request.removeListener('error', onError)
      reject(error)
    }

    const onData = (chunk: Buffer | string): void => {
      if (settled) return
      const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
      size += buffer.length
      if (size > limit) {
        fail(new HttpError(413, 'BAD_REQUEST', 'Request body is too large'))
        return
      }
      chunks.push(buffer)
    }

    const onEnd = (): void => {
      if (settled) return
      settled = true
      if (size === 0) {
        resolve(null)
        return
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown)
      } catch {
        reject(new HttpError(400, 'BAD_REQUEST', 'Invalid JSON body'))
      }
    }

    const onError = (): void => {
      fail(new HttpError(400, 'BAD_REQUEST', 'Could not read the request body'))
    }

    request.on('data', onData)
    request.on('end', onEnd)
    request.on('error', onError)
  })
}

/* ------------------------------------------------------------------------- */
/* Responses                                                                 */
/* ------------------------------------------------------------------------- */

/**
 * Send a JSON response with the no-store/nosniff/referrer security headers.
 * Extra headers override the defaults. Safe to call once per response.
 */
export function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  if (response.headersSent || response.destroyed) return
  let payload: string
  try {
    payload = JSON.stringify(body)
  } catch {
    payload = JSON.stringify({ ok: false, error: { code: 'INTERNAL', message: 'Response is not serializable' } })
  }
  response.statusCode = status
  response.setHeader('Content-Type', 'application/json; charset=utf-8')
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.setHeader('Referrer-Policy', 'no-referrer')
  for (const [name, value] of Object.entries(headers)) response.setHeader(name, value)
  response.setHeader('Content-Length', String(Buffer.byteLength(payload)))
  response.end(payload)
}

/** The one and only REST error envelope. */
export function sendError(
  response: ServerResponse,
  status: number,
  code: RcErrorCode,
  message: string,
  retryAfterMs?: number,
): void {
  const error: RcErrorEnvelope['error'] = { code, message }
  const headers: Record<string, string> = {}
  if (retryAfterMs !== undefined) {
    const retryAfter = Math.max(1, Math.ceil(retryAfterMs / 1000))
    error.retryAfterMs = Math.max(0, Math.floor(retryAfterMs))
    headers['Retry-After'] = String(retryAfter)
  }
  sendJson(response, status, { ok: false, error } satisfies RcErrorEnvelope, headers)
}

/** Respond 405 with the allowed methods for the route. */
export function methodNotAllowed(response: ServerResponse, allow: string[]): void {
  if (!response.headersSent && !response.destroyed) {
    response.setHeader('Allow', allow.join(', '))
  }
  sendError(response, 405, 'NOT_ALLOWED', 'Method not allowed')
}
