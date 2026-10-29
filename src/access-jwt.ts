/**
 * Optional Cloudflare Access assertion verification (main §2.1 / CF extensions).
 *
 * When the fixed public hostname is protected by Cloudflare Access, every phone
 * surface request must carry a valid `Cf-Access-Jwt-Assertion`. Verification
 * happens at the Host, fail closed:
 * - enforcement is disabled unless `required` is set; a `required` but
 *   misconfigured verifier (bad team domain / empty audience / no fetch) never
 *   falls open,
 * - the assertion must be a compact RS256 JWT; signature verification uses the
 *   team-domain JWKS fetched from `https://<teamDomain>/cdn-cgi/access/certs`
 *   (strict bare host, HTTPS only, redirects refused),
 * - `iss` must be `https://<teamDomain>`, `aud` must contain the configured
 *   audience tag, `exp` must be in the future and `nbf` (when present) must not
 *   be in the future,
 * - the JWKS fetch has a hard timeout, a response-size cap and a bounded cache
 *   (bounded lifetime, `no-store` disables it, unknown `kid` triggers at most
 *   one rate-limited refresh for key rotation),
 * - the assertion (and its signature) is never logged or returned; failures
 *   yield a generic `ACCESS_REQUIRED` result.
 *
 * Unit-testable with injected `fetch`/`now`; no network calls in tests.
 */

import type { IncomingMessage } from 'node:http'
import { createPublicKey, verify as verifySignature, type JsonWebKey, type KeyObject } from 'node:crypto'

import type { AccessVerification, AccessVerifier, Logger } from './shared/internal.js'
import { RC_ACCESS_JWT_HEADER } from './shared/protocol.js'

const JWKS_PATH = '/cdn-cgi/access/certs'
const B64URL = /^[A-Za-z0-9_-]+$/
/** Bare DNS host: at least two labels, no scheme/port/path/userinfo/IP literal. */
const TEAM_HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
const MAX_TOKEN_CHARS = 16_384
const MAX_HEADER_BYTES = 4 * 1024
const MAX_PAYLOAD_BYTES = 16 * 1024
const MAX_SIGNATURE_BYTES = 1_024
const MAX_JWKS_KEYS = 32
const MIN_RSA_MODULUS_BYTES = 256 // 2048-bit
const MAX_RSA_MODULUS_BYTES = 1_024 // 8192-bit
const MIN_CACHE_TTL_MS = 60_000
const MAX_CACHE_TTL_MS = 3_600_000
const MAX_JWKS_BYTES = 65_536

export interface AccessVerifierOptions {
  /** Enforcement switch: when false, verification is a no-op. */
  required: boolean
  /** Access team domain, bare host (e.g. `myteam.cloudflareaccess.com`). */
  teamDomain: string
  /** Access application audience tag expected in `aud`. */
  audience: string
  log: Logger
  /** Test seam; defaults to the global `fetch`. */
  fetch?: typeof fetch
  /** Test seam; defaults to `Date.now`. */
  now?: () => number
  /** Default JWKS cache lifetime when the response carries no usable max-age. */
  jwksCacheTtlMs?: number
  /** Per-JWKS-fetch timeout. */
  requestTimeoutMs?: number
  /** Hard cap on the JWKS response body size. */
  maxJwksBytes?: number
  /** Minimum interval between forced JWKS refreshes (unknown-kid short-circuit). */
  minRefetchMs?: number
}

interface CachedKey {
  kid: string | null
  key: KeyObject
}

interface JwksCache {
  keys: CachedKey[]
  fetchedAt: number
  expiresAt: number
}

interface ParsedJwt {
  alg: string
  kid: string | null
  payload: Record<string, unknown>
  signingInput: string
  signature: Buffer
}

function boundedInt(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return fallback
  return Math.min(max, Math.max(min, Math.floor(value)))
}

function normalizeTeamDomain(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const candidate = value.trim().toLowerCase()
  if (candidate === '') return null
  if (!TEAM_HOST.test(candidate)) return null
  return candidate
}

function headerValue(request: IncomingMessage, name: string): string | null {
  const headers = request?.headers
  if (headers === undefined || headers === null) return null
  const raw = (headers as Record<string, string | string[] | undefined>)[name]
  if (typeof raw === 'string') return raw
  if (Array.isArray(raw) && typeof raw[0] === 'string') return raw[0]
  return null
}

function decodeB64Url(part: string, maxBytes: number): Buffer | null {
  if (typeof part !== 'string' || part.length === 0 || part.length > MAX_TOKEN_CHARS) return null
  if (!B64URL.test(part)) return null
  let decoded: Buffer
  try {
    decoded = Buffer.from(part, 'base64url')
  } catch {
    return null
  }
  if (decoded.length === 0 || decoded.length > maxBytes) return null
  return decoded
}

function parseJwt(token: string): ParsedJwt | null {
  if (token.length === 0 || token.length > MAX_TOKEN_CHARS) return null
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [headerRaw, payloadRaw, signatureRaw] = parts
  const headerBytes = decodeB64Url(headerRaw ?? '', MAX_HEADER_BYTES)
  const payloadBytes = decodeB64Url(payloadRaw ?? '', MAX_PAYLOAD_BYTES)
  const signature = decodeB64Url(signatureRaw ?? '', MAX_SIGNATURE_BYTES)
  if (headerBytes === null || payloadBytes === null || signature === null) return null

  let header: unknown
  let payload: unknown
  try {
    header = JSON.parse(headerBytes.toString('utf8'))
    payload = JSON.parse(payloadBytes.toString('utf8'))
  } catch {
    return null
  }
  if (typeof header !== 'object' || header === null || Array.isArray(header)) return null
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null
  const headerRecord = header as Record<string, unknown>
  if (typeof headerRecord.alg !== 'string') return null
  const kid =
    typeof headerRecord.kid === 'string' && headerRecord.kid.length > 0 && headerRecord.kid.length <= 128
      ? headerRecord.kid
      : null
  return {
    alg: headerRecord.alg,
    kid,
    payload: payload as Record<string, unknown>,
    signingInput: `${String(headerRaw)}.${String(payloadRaw)}`,
    signature,
  }
}

function claimsValid(
  payload: Record<string, unknown>,
  expectedIssuer: string,
  expectedAudience: string,
  at: number,
): boolean {
  if (payload.iss !== expectedIssuer) return false

  const audience = payload.aud
  let audienceOk = false
  if (typeof audience === 'string') audienceOk = audience === expectedAudience
  else if (Array.isArray(audience)) audienceOk = audience.some((value) => value === expectedAudience)
  if (!audienceOk) return false

  const exp = payload.exp
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return false
  if (exp * 1000 <= at) return false

  const nbf = payload.nbf
  if (nbf !== undefined) {
    if (typeof nbf !== 'number' || !Number.isFinite(nbf)) return false
    if (nbf * 1000 > at) return false
  }
  return true
}

export function createAccessVerifier(options: AccessVerifierOptions): AccessVerifier {
  let required = options.required === true
  const teamDomain = normalizeTeamDomain(options.teamDomain)
  const audience = typeof options.audience === 'string' ? options.audience.trim() : ''
  const now = typeof options.now === 'function' ? options.now : Date.now
  const log = options.log
  let fetchImpl: typeof fetch | undefined
  if (typeof options.fetch === 'function') fetchImpl = options.fetch
  else if (typeof globalThis.fetch === 'function') fetchImpl = globalThis.fetch.bind(globalThis)

  const jwksCacheTtlMs = boundedInt(options.jwksCacheTtlMs, 300_000, MIN_CACHE_TTL_MS, MAX_CACHE_TTL_MS)
  const requestTimeoutMs = boundedInt(options.requestTimeoutMs, 5_000, 100, 60_000)
  const maxJwksBytes = boundedInt(options.maxJwksBytes, MAX_JWKS_BYTES, 1_024, 1_048_576)
  const minRefetchMs = boundedInt(options.minRefetchMs, 30_000, 0, MAX_CACHE_TTL_MS)

  let disposed = false
  let cache: JwksCache | null = null
  let inflight: Promise<JwksCache> | null = null

  const fail = (message: string): AccessVerification => ({
    ok: false,
    code: 'ACCESS_REQUIRED',
    message,
  })

  function parseKeys(body: unknown): CachedKey[] {
    if (typeof body !== 'object' || body === null || Array.isArray(body)) return []
    const rawKeys = (body as { keys?: unknown }).keys
    if (!Array.isArray(rawKeys)) return []
    const keys: CachedKey[] = []
    for (const entry of rawKeys.slice(0, MAX_JWKS_KEYS)) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue
      const record = entry as Record<string, unknown>
      if (record.kty !== 'RSA') continue
      if (record.alg !== undefined && record.alg !== 'RS256') continue
      const n = record.n
      const e = record.e
      if (typeof n !== 'string' || typeof e !== 'string') continue
      if (!B64URL.test(n) || !B64URL.test(e)) continue
      let modulus: Buffer
      let exponent: Buffer
      try {
        modulus = Buffer.from(n, 'base64url')
        exponent = Buffer.from(e, 'base64url')
      } catch {
        continue
      }
      if (modulus.length < MIN_RSA_MODULUS_BYTES || modulus.length > MAX_RSA_MODULUS_BYTES) continue
      if (exponent.length < 3 || exponent.length > 8) continue
      const kid =
        typeof record.kid === 'string' && record.kid.length > 0 && record.kid.length <= 128
          ? record.kid
          : null
      try {
        const key = createPublicKey({ key: { kty: 'RSA', n, e } as JsonWebKey, format: 'jwk' })
        keys.push({ kid, key })
      } catch {
        // A malformed key is skipped; verification fails closed if no usable key remains.
      }
    }
    return keys
  }

  function cacheTtl(headers: Headers | undefined): number {
    let raw = ''
    try {
      raw = typeof headers?.get === 'function' ? headers.get('cache-control') ?? '' : ''
    } catch {
      raw = ''
    }
    if (/\bno-store\b|\bno-cache\b/i.test(raw)) return 0
    const match = /(?:^|,)\s*max-age\s*=\s*(\d+)/i.exec(raw)
    if (match !== null) {
      const seconds = Number(match[1])
      if (Number.isFinite(seconds)) {
        return Math.min(MAX_CACHE_TTL_MS, Math.max(MIN_CACHE_TTL_MS, Math.floor(seconds * 1000)))
      }
    }
    return jwksCacheTtlMs
  }

  async function fetchJwks(): Promise<JwksCache> {
    if (teamDomain === null) throw new Error('cloudflare access team domain is not configured')
    if (fetchImpl === undefined) throw new Error('fetch is not available')
    const url = `https://${teamDomain}${JWKS_PATH}`
    let parsedUrl: URL
    try {
      parsedUrl = new URL(url)
    } catch {
      throw new Error('invalid cloudflare access JWKS URL')
    }
    if (
      parsedUrl.protocol !== 'https:' ||
      parsedUrl.host !== teamDomain ||
      parsedUrl.port !== '' ||
      parsedUrl.pathname !== JWKS_PATH ||
      parsedUrl.username !== '' ||
      parsedUrl.password !== ''
    ) {
      throw new Error('invalid cloudflare access JWKS URL')
    }

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs)
    timeout.unref()
    try {
      let response: Response
      try {
        response = await fetchImpl(url, {
          method: 'GET',
          redirect: 'error',
          headers: { accept: 'application/json' },
          signal: controller.signal,
        })
      } catch {
        throw new Error(
          controller.signal.aborted ? 'cloudflare access JWKS request timed out' : 'cloudflare access JWKS request failed',
        )
      }
      if (!response.ok) throw new Error('cloudflare access JWKS endpoint returned an error')

      const contentLength = response.headers.get('content-length')
      if (contentLength !== null) {
        const length = Number(contentLength)
        if (Number.isFinite(length) && length > maxJwksBytes) {
          throw new Error('cloudflare access JWKS response is too large')
        }
      }
      let text: string
      try {
        text = await response.text()
      } catch {
        throw new Error('cloudflare access JWKS response could not be read')
      }
      if (Buffer.byteLength(text, 'utf8') > maxJwksBytes) {
        throw new Error('cloudflare access JWKS response is too large')
      }
      let body: unknown
      try {
        body = JSON.parse(text)
      } catch {
        throw new Error('cloudflare access JWKS response is not JSON')
      }
      const keys = parseKeys(body)
      if (keys.length === 0) throw new Error('cloudflare access JWKS has no usable signing keys')

      const at = now()
      const ttl = cacheTtl(response.headers)
      const next: JwksCache = {
        keys,
        fetchedAt: at,
        expiresAt: ttl <= 0 ? 0 : at + ttl,
      }
      cache = next
      log.debug('cloudflare access JWKS refreshed', { keys: keys.length })
      return next
    } finally {
      clearTimeout(timeout)
    }
  }

  function refreshJwks(): Promise<JwksCache> {
    if (inflight !== null) return inflight
    const pending = fetchJwks().finally(() => {
      if (inflight === pending) inflight = null
    })
    inflight = pending
    return pending
  }

  async function signingKeys(kid: string | null): Promise<CachedKey[]> {
    const at = now()
    if (cache !== null && cache.expiresAt > at) {
      if (kid === null) return cache.keys
      const matches = cache.keys.filter((candidate) => candidate.kid === kid)
      if (matches.length > 0) return matches
      // Unknown kid might be a key rotation; refresh at most once per window.
      if (at - cache.fetchedAt < minRefetchMs) return []
    }
    const fresh = await refreshJwks()
    if (kid === null) return fresh.keys
    return fresh.keys.filter((candidate) => candidate.kid === kid)
  }

  function signatureValid(parsed: ParsedJwt, keys: CachedKey[]): boolean {
    const data = Buffer.from(parsed.signingInput, 'utf8')
    for (const candidate of keys) {
      try {
        if (verifySignature('RSA-SHA256', data, candidate.key, parsed.signature)) return true
      } catch {
        // Try the next candidate key; a bad key must not abort verification.
      }
    }
    return false
  }

  async function verify(request: IncomingMessage): Promise<AccessVerification> {
    if (!required) return { ok: true }
    if (disposed) return fail('cloudflare access verifier is not available')
    if (teamDomain === null || audience === '' || fetchImpl === undefined) {
      return fail('cloudflare access is not configured')
    }
    try {
      const raw = headerValue(request, RC_ACCESS_JWT_HEADER)
      if (raw === null || raw.trim() === '') return fail('Cloudflare Access assertion is required')
      const token = raw.trim()
      if (token.length > MAX_TOKEN_CHARS) return fail('Cloudflare Access assertion is too large')
      const parsed = parseJwt(token)
      if (parsed === null) return fail('Cloudflare Access assertion is malformed')
      if (parsed.alg !== 'RS256') return fail('Cloudflare Access assertion algorithm is not supported')

      const keys = await signingKeys(parsed.kid)
      if (keys.length === 0) return fail('Cloudflare Access assertion was not signed by a trusted key')
      if (!signatureValid(parsed, keys)) return fail('Cloudflare Access assertion signature is invalid')
      if (!claimsValid(parsed.payload, `https://${teamDomain}`, audience, now())) {
        return fail('Cloudflare Access assertion claims are invalid')
      }
      log.debug('cloudflare access assertion verified')
      return { ok: true }
    } catch (error) {
      // Never include the assertion/token in logs or results.
      log.warn('cloudflare access verification failed', {
        message: error instanceof Error ? error.message : 'unknown',
      })
      return fail('Cloudflare Access verification failed')
    }
  }

  function dispose(): void {
    disposed = true
    cache = null
    inflight = null
  }

  return {
    enabled: () => required,
    setRequired: (next: boolean) => {
      required = next === true
    },
    verify,
    dispose,
  }
}
