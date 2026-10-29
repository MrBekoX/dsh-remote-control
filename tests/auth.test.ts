/**
 * HTTP security primitives (design §9): cookies, rate limiting, the
 * Host/Origin/Sec-Fetch-Site fence, CSRF header, client address, bounded JSON
 * bodies and the single REST error envelope.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'

import type { Logger } from '../src/shared/internal.js'
import { createListener } from '../src/listener.js'
import {
  HttpError,
  UNKNOWN_CLIENT_IP_BUCKET,
  canonicalAuthority,
  canonicalOrigin,
  checkOriginFence,
  clearCookie,
  clientIp,
  createOriginPolicy,
  createRateLimiter,
  hashExternalSecret,
  isAuthorityAllowed,
  isCsrfOk,
  methodNotAllowed,
  originForAuthority,
  parseCookies,
  proxyPolicyForTunnelMode,
  readJsonBody,
  resolveClientIp,
  sanitizeExternalText,
  sanitizeUserAgent,
  secretsEqual,
  sendError,
  sendJson,
  serializeCookie,
} from '../src/auth.js'

/* ------------------------------------------------------------------------- */
/* Fakes                                                                     */
/* ------------------------------------------------------------------------- */

interface RequestInit {
  headers?: Record<string, string | string[]>
  remoteAddress?: string
  body?: string
}

function makeRequest(init: RequestInit = {}): IncomingMessage {
  const stream = Readable.from(init.body === undefined ? [] : [Buffer.from(init.body, 'utf8')])
  const request = stream as unknown as IncomingMessage
  request.headers = init.headers ?? {}
  ;(request as unknown as { socket: { remoteAddress?: string } }).socket = {
    remoteAddress: init.remoteAddress ?? '127.0.0.1',
  }
  return request
}

interface CapturedResponse {
  statusCode: number
  headers: Record<string, string>
  body: string
  ended: boolean
}

function makeResponse(): { response: ServerResponse; captured: CapturedResponse } {
  const captured: CapturedResponse = { statusCode: 0, headers: {}, body: '', ended: false }
  const response = {
    statusCode: 200,
    headersSent: false,
    destroyed: false,
    setHeader(name: string, value: string) {
      captured.headers[name.toLowerCase()] = String(value)
    },
    end(payload?: string) {
      captured.statusCode = response.statusCode
      captured.body = payload ?? ''
      captured.ended = true
      response.headersSent = true
    },
  }
  return { response: response as unknown as ServerResponse, captured }
}

function parseBody(captured: CapturedResponse): unknown {
  return JSON.parse(captured.body)
}

/* ------------------------------------------------------------------------- */
/* Cookies                                                                   */
/* ------------------------------------------------------------------------- */

const SILENT_LOGGER: Logger = {
  error: () => undefined,
  warn: () => undefined,
  info: () => undefined,
  debug: () => undefined,
}

test('auth: serializeCookie defaults to HttpOnly, SameSite=Strict, Path=/rc', () => {
  assert.equal(serializeCookie('rc_access', 'token-value'), 'rc_access=token-value; Path=/rc; HttpOnly; SameSite=Strict')
})

test('auth: serializeCookie includes Max-Age/Secure and honours overrides', () => {
  assert.equal(
    serializeCookie('rc_refresh', 'refresh', { maxAgeSeconds: 60, secure: true }),
    'rc_refresh=refresh; Path=/rc; Max-Age=60; HttpOnly; Secure; SameSite=Strict',
  )
  assert.equal(
    serializeCookie('rc_access', 'token', {
      maxAgeSeconds: 42,
      path: '/rc/api',
      httpOnly: false,
      sameSite: 'Lax',
    }),
    'rc_access=token; Path=/rc/api; Max-Age=42; SameSite=Lax',
  )
})

test('auth: serializeCookie URL-encodes values and rejects invalid names', () => {
  const serialized = serializeCookie('rc_access', 'a b;c=d')
  assert.match(serialized, /^rc_access=a%20b%3Bc%3Dd; /)
  assert.throws(() => serializeCookie('bad name', 'x'), /cookie name/i)
  assert.throws(() => serializeCookie('bad;name', 'x'), /cookie name/i)
})

test('auth: clearCookie expires the cookie', () => {
  assert.equal(clearCookie('rc_access'), 'rc_access=; Path=/rc; Max-Age=0; HttpOnly; SameSite=Strict')
})

test('auth: parseCookies handles encoding, malformed escapes and junk segments', () => {
  assert.deepEqual(parseCookies('rc_access=abc; rc_refresh=def'), { rc_access: 'abc', rc_refresh: 'def' })
  assert.deepEqual(parseCookies('a=%E2%9C%93'), { a: '✓' })
  // A broken percent escape must not break parsing: the raw value is kept.
  assert.deepEqual(parseCookies('a=%E0%A4%A'), { a: '%E0%A4%A' })
  assert.deepEqual(parseCookies(undefined), {})
  assert.deepEqual(parseCookies(''), {})
  assert.deepEqual(parseCookies('novalue; b=2; =3'), { b: '2' })
  assert.deepEqual(parseCookies('a=1; a=2'), { a: '2' })
})

test('auth: cookie serialize/parse round-trips a hostile value', () => {
  const value = 'x;y=z ✓'
  const serialized = serializeCookie('rc_access', value)
  // A request Cookie header only carries `name=value` pairs, not Set-Cookie
  // attributes, so round-trip the pair segment only.
  const pair = serialized.split(';')[0] ?? ''
  assert.deepEqual(parseCookies(pair), { rc_access: value })
})

/* ------------------------------------------------------------------------- */
/* Rate limiting                                                             */
/* ------------------------------------------------------------------------- */

test('auth: rate limiter enforces the limit per key and counts rejections', () => {
  const limiter = createRateLimiter({ limit: 3, windowMs: 60_000 })

  assert.equal(limiter.allow('1.2.3.4'), true)
  assert.equal(limiter.allow('1.2.3.4'), true)
  assert.equal(limiter.allow('1.2.3.4'), true)
  assert.equal(limiter.allow('1.2.3.4'), false)
  assert.equal(limiter.allow('1.2.3.4'), false)
})

test('auth: rate limiter buckets are independent per key', () => {
  const limiter = createRateLimiter({ limit: 1, windowMs: 60_000 })

  assert.equal(limiter.allow('ip-a'), true)
  assert.equal(limiter.allow('ip-b'), true)
  assert.equal(limiter.allow('ip-a'), false)
  assert.equal(limiter.allow('ip-b'), false)
})

test('auth: rate limiter opens a new window after windowMs', async () => {
  const limiter = createRateLimiter({ limit: 1, windowMs: 80 })

  assert.equal(limiter.allow('key'), true)
  assert.equal(limiter.allow('key'), false)
  await new Promise((resolve) => setTimeout(resolve, 120))
  assert.equal(limiter.allow('key'), true, 'a new window must allow the key again')
})

/* ------------------------------------------------------------------------- */
/* Host / Origin / Sec-Fetch-Site fence                                      */
/* ------------------------------------------------------------------------- */

const AUTHORITIES = new Set(['127.0.0.1:8080', 'localhost:8080', 'rc.example.com'])

test('auth: fence accepts a matching Host with no Origin for HTTP requests', () => {
  const request = makeRequest({ headers: { host: '127.0.0.1:8080' } })
  assert.equal(isAuthorityAllowed(request, AUTHORITIES, false), true)
})

test('auth: fence requires Origin for WebSocket upgrades', () => {
  const bare = makeRequest({ headers: { host: '127.0.0.1:8080' } })
  assert.equal(isAuthorityAllowed(bare, AUTHORITIES, true), false)

  const withOrigin = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8080' },
  })
  assert.equal(isAuthorityAllowed(withOrigin, AUTHORITIES, true), true)
})

test('auth: fence rejects an unknown Host (DNS re-binding defence)', () => {
  const unknown = makeRequest({ headers: { host: 'evil.example.com' } })
  assert.equal(isAuthorityAllowed(unknown, AUTHORITIES, false), false)

  const missing = makeRequest({ headers: {} })
  assert.equal(isAuthorityAllowed(missing, AUTHORITIES, false), false)
})

test('auth: fence rejects a cross-origin Origin even for an allowed Host', () => {
  const cross = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'https://evil.example.com' },
  })
  assert.equal(isAuthorityAllowed(cross, AUTHORITIES, false), false)
})

test('auth: fence rejects Origin/Host mismatches and non-http(s) schemes', () => {
  const mismatch = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'http://localhost:8080' },
  })
  assert.equal(isAuthorityAllowed(mismatch, AUTHORITIES, false), false)

  const fileScheme = makeRequest({ headers: { host: '127.0.0.1:8080', origin: 'file://127.0.0.1:8080/x' } })
  assert.equal(isAuthorityAllowed(fileScheme, AUTHORITIES, false), false)

  const withCredentials = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'http://user:pass@127.0.0.1:8080' },
  })
  assert.equal(isAuthorityAllowed(withCredentials, AUTHORITIES, false), false)

  const garbage = makeRequest({ headers: { host: '127.0.0.1:8080', origin: 'not a url' } })
  assert.equal(isAuthorityAllowed(garbage, AUTHORITIES, false), false)
})

test('auth: fence rejects Sec-Fetch-Site: cross-site even when Host/Origin look right', () => {
  const crossSite = makeRequest({
    headers: {
      host: '127.0.0.1:8080',
      origin: 'http://127.0.0.1:8080',
      'sec-fetch-site': 'cross-site',
    },
  })
  assert.equal(isAuthorityAllowed(crossSite, AUTHORITIES, false), false)

  const sameOrigin = makeRequest({
    headers: {
      host: '127.0.0.1:8080',
      origin: 'http://127.0.0.1:8080',
      'sec-fetch-site': 'same-origin',
    },
  })
  assert.equal(isAuthorityAllowed(sameOrigin, AUTHORITIES, false), true)
})

test('auth: fence normalizes case and a trailing dot in the authority', () => {
  const uppercase = makeRequest({ headers: { host: 'RC.EXAMPLE.COM' } })
  assert.equal(isAuthorityAllowed(uppercase, AUTHORITIES, false), true)

  const trailingDot = makeRequest({ headers: { host: 'rc.example.com.' } })
  assert.equal(isAuthorityAllowed(trailingDot, AUTHORITIES, false), true)
})

/* ------------------------------------------------------------------------- */
/* CSRF & client address                                                     */
/* ------------------------------------------------------------------------- */

test('auth: CSRF header must be exactly 1', () => {
  assert.equal(isCsrfOk(makeRequest({ headers: { 'x-rc-csrf': '1' } })), true)
  assert.equal(isCsrfOk(makeRequest({ headers: { 'x-rc-csrf': ['1'] } })), true)
  assert.equal(isCsrfOk(makeRequest({ headers: { 'x-rc-csrf': '0' } })), false)
  assert.equal(isCsrfOk(makeRequest({ headers: { 'x-rc-csrf': 'true' } })), false)
  assert.equal(isCsrfOk(makeRequest({ headers: {} })), false)
})

test('auth: clientIp trusts CF-Connecting-IP only for loopback peers', () => {
  const throughTunnel = makeRequest({
    remoteAddress: '::ffff:127.0.0.1',
    headers: { 'cf-connecting-ip': '203.0.113.5' },
  })
  assert.equal(clientIp(throughTunnel), '203.0.113.5')

  const spoofAttempt = makeRequest({
    remoteAddress: '10.1.2.3',
    headers: { 'cf-connecting-ip': '203.0.113.5' },
  })
  assert.equal(clientIp(spoofAttempt), '10.1.2.3', 'a direct LAN peer cannot spoof the tunnel header')

  const malformed = makeRequest({
    remoteAddress: '127.0.0.1',
    headers: { 'cf-connecting-ip': 'not-an-ip' },
  })
  assert.equal(clientIp(malformed), '127.0.0.1')

  const plain = makeRequest({ remoteAddress: '127.0.0.1' })
  assert.equal(clientIp(plain), '127.0.0.1')

  const unknown = makeRequest()
  ;(unknown as unknown as { socket: Record<string, unknown> }).socket = {}
  assert.equal(clientIp(unknown), 'unknown')
})

/* ------------------------------------------------------------------------- */
/* Body parsing                                                              */
/* ------------------------------------------------------------------------- */

test('auth: readJsonBody parses objects and treats an empty body as null', async () => {
  assert.deepEqual(await readJsonBody(makeRequest({ body: '{"a":1}' })), { a: 1 })
  assert.equal(await readJsonBody(makeRequest({ body: '' })), null)
  assert.deepEqual(await readJsonBody(makeRequest({ body: '[1,2]' })), [1, 2])
})

test('auth: readJsonBody fails closed on invalid JSON', async () => {
  await assert.rejects(
    readJsonBody(makeRequest({ body: '{not json' })),
    (error: unknown) =>
      error instanceof HttpError && error.status === 400 && error.code === 'BAD_REQUEST',
  )
})

test('auth: readJsonBody rejects an oversized payload with 413', async () => {
  const oversized = makeRequest({ body: JSON.stringify({ payload: 'x'.repeat(200) }) })
  await assert.rejects(
    readJsonBody(oversized, 64),
    (error: unknown) =>
      error instanceof HttpError && error.status === 413 && error.code === 'BAD_REQUEST',
  )
})

/* ------------------------------------------------------------------------- */
/* Response helpers                                                          */
/* ------------------------------------------------------------------------- */

test('auth: sendJson writes the JSON response with security headers', () => {
  const { response, captured } = makeResponse()
  sendJson(response, 200, { ok: true })

  assert.equal(captured.statusCode, 200)
  assert.equal(captured.headers['content-type'], 'application/json; charset=utf-8')
  assert.equal(captured.headers['cache-control'], 'no-store')
  assert.equal(captured.headers['x-content-type-options'], 'nosniff')
  assert.equal(captured.headers['referrer-policy'], 'no-referrer')
  assert.equal(captured.headers['content-length'], String(Buffer.byteLength(captured.body)))
  assert.deepEqual(parseBody(captured), { ok: true })
})

test('auth: sendJson is a no-op once headers are sent', () => {
  const { response, captured } = makeResponse()
  ;(response as unknown as { headersSent: boolean }).headersSent = true
  sendJson(response, 200, { ok: true })
  assert.equal(captured.ended, false)
})

test('auth: sendError writes the canonical error envelope with Retry-After', () => {
  const { response, captured } = makeResponse()
  sendError(response, 429, 'RATE_LIMITED', 'slow down', 2500)

  assert.equal(captured.statusCode, 429)
  assert.equal(captured.headers['retry-after'], '3')
  assert.deepEqual(parseBody(captured), {
    ok: false,
    error: { code: 'RATE_LIMITED', message: 'slow down', retryAfterMs: 2500 },
  })
})

test('auth: methodNotAllowed answers 405 with Allow and the canonical code', () => {
  const { response, captured } = makeResponse()
  methodNotAllowed(response, ['GET', 'POST'])

  assert.equal(captured.statusCode, 405)
  assert.equal(captured.headers.allow, 'GET, POST')
  const body = parseBody(captured) as { ok: boolean; error: { code: string } }
  assert.equal(body.ok, false)
  assert.equal(body.error.code, 'NOT_ALLOWED')
})

/* ------------------------------------------------------------------------- */
/* Canonical origin fence (new controller API)                               */
/* ------------------------------------------------------------------------- */

/**
 * Canonical fence: `allowedOrigins` are exact serialized origins
 * (scheme + host + effective port, `null`/path/credentials rejected), and
 * `allowedAuthorities` are the exact `Host` values. The legacy
 * `isAuthorityAllowed` above keeps its historical semantics for the current
 * controller; this API is what the new controller wires to.
 */
const FENCE_POLICY = createOriginPolicy({
  origins: ['http://127.0.0.1:8080', 'https://rc.example.com'],
  authorities: ['127.0.0.1:8080', 'rc.example.com'],
})

test('auth: canonicalOrigin normalizes exact http(s) origins', () => {
  assert.equal(canonicalOrigin('http://127.0.0.1:8080'), 'http://127.0.0.1:8080')
  assert.equal(canonicalOrigin('HTTPS://RC.Example.COM:443'), 'https://rc.example.com')
  assert.equal(canonicalOrigin('https://rc.example.com:444'), 'https://rc.example.com:444')
  assert.equal(canonicalOrigin('http://[::1]:8080'), 'http://[::1]:8080')
  assert.equal(canonicalOrigin('https://rc.example.com.'), 'https://rc.example.com')
  assert.equal(canonicalOrigin('http://127.0.0.1:8080/', { allowTrailingSlash: true }), 'http://127.0.0.1:8080')
  // Effective default ports are part of the canonical origin, not the string form.
  assert.equal(canonicalOrigin('http://rc.example.com:80'), 'http://rc.example.com')
  assert.equal(canonicalOrigin('https://rc.example.com:443'), 'https://rc.example.com')
  assert.equal(canonicalOrigin('https://rc.example.com:80'), 'https://rc.example.com:80')
})

test('auth: canonicalOrigin rejects null, malformed, credential and non-http(s) origins', () => {
  for (const bad of [
    '',
    '   ',
    'null',
    'NULL',
    'not a url',
    'http://',
    'file://127.0.0.1:8080',
    'ftp://rc.example.com',
    'ws://rc.example.com',
    'http://user:pass@127.0.0.1:8080',
    'http://127.0.0.1:8080/path',
    'http://127.0.0.1:8080?query=1',
    'http://127.0.0.1:8080#frag',
    'http://127.0.0.1:8080/',
  ]) {
    assert.equal(canonicalOrigin(bad), null, `expected rejection: ${bad}`)
  }
})

test('auth: canonicalAuthority normalizes host[:port] and rejects junk', () => {
  assert.equal(canonicalAuthority('127.0.0.1:8080'), '127.0.0.1:8080')
  assert.equal(canonicalAuthority('RC.EXAMPLE.COM'), 'rc.example.com')
  assert.equal(canonicalAuthority('rc.example.com.'), 'rc.example.com')
  assert.equal(canonicalAuthority('[::1]:8080'), '[::1]:8080')
  for (const bad of ['', '   ', 'evil.example.com/path', 'a b', 'user@host:1', 'host,other:1']) {
    assert.equal(canonicalAuthority(bad), null, `expected rejection: ${bad}`)
  }
})

test('auth: originForAuthority derives canonical origins from a bind authority', () => {
  assert.equal(originForAuthority('127.0.0.1:8080', 'http'), 'http://127.0.0.1:8080')
  assert.equal(originForAuthority('rc.example.com', 'https'), 'https://rc.example.com')
  assert.equal(originForAuthority('[::1]:8080', 'https'), 'https://[::1]:8080')
  assert.equal(originForAuthority('not a host', 'http'), null)
})

test('auth: canonical fence accepts an exact allowed Origin/Host pair', () => {
  const http = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8080' },
  })
  assert.deepEqual(checkOriginFence(http, FENCE_POLICY), {
    ok: true,
    host: '127.0.0.1:8080',
    origin: 'http://127.0.0.1:8080',
  })

  const https = makeRequest({ headers: { host: 'rc.example.com', origin: 'https://rc.example.com' } })
  assert.equal(checkOriginFence(https, FENCE_POLICY, { requireOrigin: true }).ok, true)
})

test('auth: canonical fence allows a missing Origin only when not required', () => {
  const request = makeRequest({ headers: { host: '127.0.0.1:8080' } })
  assert.deepEqual(checkOriginFence(request, FENCE_POLICY), {
    ok: true,
    host: '127.0.0.1:8080',
    origin: null,
  })
  assert.deepEqual(checkOriginFence(request, FENCE_POLICY, { requireOrigin: true }), {
    ok: false,
    code: 'ORIGIN',
    reason: 'origin-missing',
  })
})

test('auth: canonical fence rejects Origin: null and malformed origins', () => {
  const nullOrigin = makeRequest({ headers: { host: '127.0.0.1:8080', origin: 'null' } })
  assert.deepEqual(checkOriginFence(nullOrigin, FENCE_POLICY), {
    ok: false,
    code: 'ORIGIN',
    reason: 'origin-null',
  })

  const malformed = makeRequest({ headers: { host: '127.0.0.1:8080', origin: 'not a url' } })
  assert.deepEqual(checkOriginFence(malformed, FENCE_POLICY), {
    ok: false,
    code: 'ORIGIN',
    reason: 'origin-malformed',
  })

  const userinfo = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'http://user:pass@127.0.0.1:8080' },
  })
  assert.equal(checkOriginFence(userinfo, FENCE_POLICY).ok, false)
})

test('auth: canonical fence rejects duplicate/ambiguous Origin headers', () => {
  const duplicated = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: ['http://127.0.0.1:8080', 'http://evil.example.com'] },
  })
  const result = checkOriginFence(duplicated, FENCE_POLICY)
  assert.equal(result.ok, false)
  if (!result.ok) assert.equal(result.reason, 'origin-malformed')
})

test('auth: canonical fence is exact about scheme and effective port', () => {
  // Same authority, different scheme: the http origin is allowed, https is not.
  const httpsSameAuthority = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'https://127.0.0.1:8080' },
  })
  const result = checkOriginFence(httpsSameAuthority, FENCE_POLICY)
  assert.equal(result.ok, false)
  if (!result.ok) assert.equal(result.reason, 'origin-disallowed')

  // Different port on the same host is a different origin.
  const otherPort = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8081' },
  })
  const portResult = checkOriginFence(otherPort, FENCE_POLICY)
  assert.equal(portResult.ok, false)
  if (!portResult.ok) assert.equal(portResult.reason, 'origin-disallowed')
})

test('auth: canonical fence rejects Origin/Host mismatches and unknown Hosts', () => {
  const mismatch = makeRequest({
    headers: { host: 'rc.example.com', origin: 'https://127.0.0.1:8080' },
  })
  // 127.0.0.1:8080 is an allowed *http* origin, not an https one, so this fails
  // before the host comparison; both checks are covered here.
  const result = checkOriginFence(mismatch, FENCE_POLICY)
  assert.equal(result.ok, false)

  const wrongHost = makeRequest({ headers: { host: 'evil.example.com', origin: 'https://rc.example.com' } })
  assert.deepEqual(checkOriginFence(wrongHost, FENCE_POLICY), {
    ok: false,
    code: 'ORIGIN',
    reason: 'host-not-allowed',
  })

  const missingHost = makeRequest({ headers: { origin: 'https://rc.example.com' } })
  assert.deepEqual(checkOriginFence(missingHost, FENCE_POLICY, { requireOrigin: true }), {
    ok: false,
    code: 'ORIGIN',
    reason: 'host-missing',
  })
})

test('auth: canonical fence keeps another allowed origin with a mismatched Host rejected', () => {
  // https://rc.example.com is allowed, but Host is the loopback listener: a
  // browser would never send this pair, so it must fail closed.
  const mismatchedPair = makeRequest({
    headers: { host: '127.0.0.1:8080', origin: 'https://rc.example.com' },
  })
  const result = checkOriginFence(mismatchedPair, FENCE_POLICY)
  assert.equal(result.ok, false)
  if (!result.ok) assert.equal(result.reason, 'origin-host-mismatch')
})

test('auth: canonical fence always rejects Sec-Fetch-Site: cross-site', () => {
  const crossSite = makeRequest({
    headers: {
      host: '127.0.0.1:8080',
      origin: 'http://127.0.0.1:8080',
      'sec-fetch-site': 'cross-site',
    },
  })
  assert.deepEqual(checkOriginFence(crossSite, FENCE_POLICY), {
    ok: false,
    code: 'ORIGIN',
    reason: 'cross-site',
  })
  // Even a same-origin request without Origin must fail if it claims cross-site.
  const siteOnly = makeRequest({ headers: { host: '127.0.0.1:8080', 'sec-fetch-site': 'Cross-Site' } })
  assert.deepEqual(checkOriginFence(siteOnly, FENCE_POLICY), {
    ok: false,
    code: 'ORIGIN',
    reason: 'cross-site',
  })
  const sameOrigin = makeRequest({
    headers: {
      host: '127.0.0.1:8080',
      origin: 'http://127.0.0.1:8080',
      'sec-fetch-site': 'same-origin',
    },
  })
  assert.equal(checkOriginFence(sameOrigin, FENCE_POLICY).ok, true)
})

test('auth: canonical fence tolerates case/trailing dot in Host but keeps it exact otherwise', () => {
  const uppercase = makeRequest({ headers: { host: 'RC.EXAMPLE.COM', origin: 'https://rc.example.com' } })
  assert.equal(checkOriginFence(uppercase, FENCE_POLICY, { requireOrigin: true }).ok, true)
  const trailingDot = makeRequest({ headers: { host: 'rc.example.com.', origin: 'https://rc.example.com' } })
  assert.equal(checkOriginFence(trailingDot, FENCE_POLICY, { requireOrigin: true }).ok, true)
})

test('auth: origin policy ignores entries that are not canonical origins/authorities', () => {
  const policy = createOriginPolicy({
    origins: ['javascript:alert(1)', 'https://ok.example.com', 'https://ok.example.com/path'],
    authorities: ['ok.example.com', 'bad host'],
  })
  assert.equal(
    checkOriginFence(
      makeRequest({ headers: { host: 'ok.example.com', origin: 'https://ok.example.com' } }),
      policy,
    ).ok,
    true,
  )
  assert.equal(
    checkOriginFence(makeRequest({ headers: { host: 'bad host' } }), policy, { requireOrigin: false }).ok,
    false,
  )
})

/* ------------------------------------------------------------------------- */
/* Provider-scoped client IP resolution                                      */
/* ------------------------------------------------------------------------- */

test('auth: resolveClientIp uses the socket address for direct clients', () => {
  const direct = makeRequest({ remoteAddress: '192.168.1.50' })
  assert.deepEqual(resolveClientIp(direct), {
    ip: '192.168.1.50',
    bucket: '192.168.1.50',
    source: 'socket',
    peerLoopback: false,
    untrusted: false,
    ignoredHeader: null,
  })

  const loopback = makeRequest({ remoteAddress: '::ffff:127.0.0.1' })
  assert.deepEqual(resolveClientIp(loopback), {
    ip: '127.0.0.1',
    bucket: '127.0.0.1',
    source: 'socket',
    peerLoopback: true,
    untrusted: false,
    ignoredHeader: null,
  })
})

test('auth: resolveClientIp never trusts proxy headers from a non-loopback peer', () => {
  const spoofed = makeRequest({
    remoteAddress: '192.168.1.50',
    headers: {
      'cf-connecting-ip': '203.0.113.5',
      'x-forwarded-for': '198.51.100.7',
    },
  })
  const result = resolveClientIp(spoofed, { trustedProxy: 'cloudflare' })
  assert.equal(result.ip, '192.168.1.50')
  assert.equal(result.source, 'socket')
  assert.equal(result.ignoredHeader, 'cf-connecting-ip')
  assert.equal(result.bucket, '192.168.1.50')
})

test('auth: resolveClientIp honours CF-Connecting-IP only for loopback + cloudflare policy', () => {
  const cloudflare = makeRequest({
    remoteAddress: '127.0.0.1',
    headers: { 'cf-connecting-ip': '203.0.113.5', 'x-forwarded-for': '198.51.100.7' },
  })
  const result = resolveClientIp(cloudflare, { trustedProxy: 'cloudflare' })
  assert.deepEqual(result, {
    ip: '203.0.113.5',
    bucket: '203.0.113.5',
    source: 'cloudflare',
    peerLoopback: true,
    untrusted: false,
    ignoredHeader: 'x-forwarded-for',
  })

  // Loopback peer + no trustworthy header => explicit unknown + shared bucket.
  const missing = makeRequest({ remoteAddress: '127.0.0.1' })
  const unknown = resolveClientIp(missing, { trustedProxy: 'cloudflare' })
  assert.equal(unknown.ip, null)
  assert.equal(unknown.source, 'unknown')
  assert.equal(unknown.untrusted, true)
  assert.equal(unknown.bucket, UNKNOWN_CLIENT_IP_BUCKET)

  // A malformed header must not be trusted either.
  const malformed = makeRequest({
    remoteAddress: '127.0.0.1',
    headers: { 'cf-connecting-ip': 'not-an-ip' },
  })
  const malformedResult = resolveClientIp(malformed, { trustedProxy: 'cloudflare' })
  assert.equal(malformedResult.ip, null)
  assert.equal(malformedResult.bucket, UNKNOWN_CLIENT_IP_BUCKET)

  // The legacy helper (current controller) keeps its historical behavior.
  assert.equal(clientIp(cloudflare), '203.0.113.5')
})

test('auth: resolveClientIp reports SSH/external loopback peers as unknown (shared bucket)', () => {
  for (const policy of ['ssh', 'external'] as const) {
    const request = makeRequest({
      remoteAddress: '127.0.0.1',
      headers: { 'cf-connecting-ip': '203.0.113.5', 'x-forwarded-for': '198.51.100.7' },
    })
    const result = resolveClientIp(request, { trustedProxy: policy })
    assert.equal(result.ip, null, `${policy}: a loopback tunnel peer has no trustworthy client ip`)
    assert.equal(result.source, 'unknown')
    assert.equal(result.untrusted, true)
    assert.equal(result.bucket, UNKNOWN_CLIENT_IP_BUCKET)
    assert.equal(result.ignoredHeader, 'cf-connecting-ip')
  }
})

test('auth: resolveClientIp ignores X-Forwarded-For even for a loopback cloudflare peer', () => {
  const onlyXff = makeRequest({
    remoteAddress: '127.0.0.1',
    headers: { 'x-forwarded-for': '198.51.100.7' },
  })
  const result = resolveClientIp(onlyXff, { trustedProxy: 'cloudflare' })
  assert.equal(result.ip, null, 'X-Forwarded-For must never be trusted')
  assert.equal(result.ignoredHeader, 'x-forwarded-for')
})

test('auth: resolveClientIp returns a shared bucket when no socket address exists', () => {
  const missingSocket = makeRequest()
  ;(missingSocket as unknown as { socket: Record<string, unknown> }).socket = {}
  assert.deepEqual(resolveClientIp(missingSocket), {
    ip: null,
    bucket: UNKNOWN_CLIENT_IP_BUCKET,
    source: 'unknown',
    peerLoopback: false,
    untrusted: true,
    ignoredHeader: null,
  })
})

test('auth: proxyPolicyForTunnelMode maps provider modes to trusted-proxy policy', () => {
  assert.equal(proxyPolicyForTunnelMode('quick'), 'cloudflare')
  assert.equal(proxyPolicyForTunnelMode('named'), 'cloudflare')
  assert.equal(proxyPolicyForTunnelMode('named-local'), 'cloudflare')
  assert.equal(proxyPolicyForTunnelMode('ssh'), 'ssh')
  assert.equal(proxyPolicyForTunnelMode('external'), 'external')
  assert.equal(proxyPolicyForTunnelMode(undefined), 'none')
  assert.equal(proxyPolicyForTunnelMode(null), 'none')
})

/* ------------------------------------------------------------------------- */
/* External text sanitization (audit metadata)                               */
/* ------------------------------------------------------------------------- */

test('auth: sanitizeUserAgent keeps ordinary user agents', () => {
  assert.equal(
    sanitizeUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36'),
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36',
  )
})

test('auth: sanitizeUserAgent strips ANSI escapes and control characters', () => {
  assert.equal(sanitizeUserAgent('\u001b[31mred\u001b[0m agent'), 'red agent')
  assert.equal(sanitizeUserAgent('a\u0000b\u0001c\u0007d\u007fe'), 'abcde')
  assert.equal(sanitizeUserAgent('a\u009bb\u0085c'), 'abc')
  assert.equal(sanitizeUserAgent('a\u202eb'), 'ab', 'bidi overrides are control characters')
})

test('auth: sanitizeUserAgent turns line breaks/tabs into spaces and collapses runs', () => {
  assert.equal(sanitizeUserAgent('a\nb\tc\r\nd'), 'a b c d')
  assert.equal(sanitizeUserAgent('  a   b  '), 'a b')
  assert.equal(sanitizeUserAgent('line1\u2028line2\u2029line3'), 'line1 line2 line3')
})

test('auth: sanitizeUserAgent bounds the length and returns null for empty/malformed input', () => {
  assert.equal(sanitizeUserAgent('x'.repeat(10_000))?.length, 256)
  assert.equal(sanitizeUserAgent(''), null)
  assert.equal(sanitizeUserAgent('   '), null)
  assert.equal(sanitizeUserAgent('\u0000\u001b[0m'), null)
  for (const malformed of [null, undefined, 42, {}, [], Symbol('x')]) {
    assert.doesNotThrow(() => sanitizeUserAgent(malformed))
    assert.equal(sanitizeUserAgent(malformed), null)
  }
})

test('auth: sanitizeExternalText honours a custom bound', () => {
  assert.equal(sanitizeExternalText('abcdefghij', 4), 'abcd')
  assert.equal(sanitizeExternalText('a\r\nb', 10), 'a b')
  assert.equal(sanitizeExternalText(null), null)
})

/* ------------------------------------------------------------------------- */
/* Constant-time secret helpers                                              */
/* ------------------------------------------------------------------------- */

test('auth: hashExternalSecret is a stable sha256 hex digest', () => {
  assert.match(hashExternalSecret('secret') ?? '', /^[0-9a-f]{64}$/)
  assert.equal(hashExternalSecret('secret'), hashExternalSecret('secret'))
  assert.notEqual(hashExternalSecret('secret'), hashExternalSecret('secreu'))
  assert.equal(hashExternalSecret(null), null)
  assert.equal(hashExternalSecret(42), null)
  assert.equal(hashExternalSecret({}), null)
})

test('auth: secretsEqual compares in constant time and never throws on malformed input', () => {
  assert.equal(secretsEqual('correct horse', 'correct horse'), true)
  assert.equal(secretsEqual('correct horse', 'correct horsf'), false)
  assert.equal(secretsEqual('short', 'a much longer secret value'), false)
  assert.equal(secretsEqual('', ''), false, 'empty secrets are never equal')
  for (const [left, right] of [
    [null, 'x'],
    ['x', undefined],
    [42, 42],
    [{}, {}],
    [Symbol('x'), Symbol('x')],
  ] as const) {
    assert.doesNotThrow(() => secretsEqual(left as never, right as never))
    assert.equal(secretsEqual(left as never, right as never), false)
  }
})

/* ------------------------------------------------------------------------- */
/* Listener status / bind policy                                             */
/* ------------------------------------------------------------------------- */

test('auth: listener exposes access/protocol status and keeps serving the PWA with CSP', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'rc-listener-'))
  t.after(async () => {
    await rm(root, { recursive: true, force: true })
  })
  await writeFile(join(root, 'index.html'), '<!doctype html><title>rc</title>', 'utf8')

  const handle = createListener({
    bind: () => ({ host: '127.0.0.1', port: 0, allowLan: false, tls: null }),
    staticRoot: root,
    api: (_request, response) => sendJson(response, 200, { ok: true }),
    upgrade: (_request, socket) => socket.destroy(),
    log: SILENT_LOGGER,
  })
  t.after(async () => {
    await handle.stop()
  })

  const status = await handle.start()
  assert.equal(status.state, 'listening')
  assert.equal(status.access, 'loopback')
  assert.equal(status.protocol, 'http')
  assert.equal(status.secure, false)
  assert.equal(status.lan, false)
  assert.ok(status.url !== null)

  const pwa = await fetch(`${status.url}/rc/`)
  assert.equal(pwa.status, 200)
  assert.equal(pwa.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"), true)
  assert.equal(pwa.headers.get('x-content-type-options'), 'nosniff')
  await pwa.text()
  assert.equal(handle.status().access, 'loopback')
})

test('auth: listener refuses a wildcard bind and LAN without allowLan before listening', async (t) => {
  const wildcard = createListener({
    bind: () => ({ host: '0.0.0.0', port: 0, allowLan: true, tls: null }),
    staticRoot: tmpdir(),
    api: () => undefined,
    upgrade: () => undefined,
    log: SILENT_LOGGER,
  })
  t.after(async () => {
    await wildcard.stop()
  })
  await assert.rejects(wildcard.start(), /wildcard bind is not allowed/)
  assert.equal(wildcard.status().state, 'off')

  const lanWithoutFlag = createListener({
    bind: () => ({ host: '192.0.2.10', port: 0, allowLan: false, tls: null }),
    staticRoot: tmpdir(),
    api: () => undefined,
    upgrade: () => undefined,
    log: SILENT_LOGGER,
  })
  t.after(async () => {
    await lanWithoutFlag.stop()
  })
  await assert.rejects(lanWithoutFlag.start(), /allowLan=true/)
})

test('auth: listener fails closed when its TLS files cannot be read', async (t) => {
  const handle = createListener({
    bind: () => ({
      host: '127.0.0.1',
      port: 0,
      allowLan: false,
      tls: { certFile: join(tmpdir(), 'missing-cert.pem'), keyFile: join(tmpdir(), 'missing-key.pem') },
    }),
    staticRoot: tmpdir(),
    api: () => undefined,
    upgrade: () => undefined,
    log: SILENT_LOGGER,
  })
  t.after(async () => {
    await handle.stop()
  })
  await assert.rejects(handle.start(), /TLS files/)
  assert.equal(handle.status().state, 'off')
})
