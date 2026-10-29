/**
 * Optional Cloudflare Access assertion verification (main §2.1, CF ext):
 * - enforcement is off unless `required` is set; a required but misconfigured
 *   verifier fails closed (never open),
 * - reads `Cf-Access-Jwt-Assertion`, verifies RS256 against the team-domain
 *   JWKS over strict HTTPS, then `iss`/`aud`/`exp`/`nbf`,
 * - JWKS fetch has timeouts, size limits and a bounded cache,
 * - malformed/expired/forged tokens fail closed, never throw and never leak the
 *   JWT into results or logs.
 *
 * Unit-tested with an injected fetch, clock and locally generated RSA keys; no
 * network is touched.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto'
import type { IncomingMessage } from 'node:http'

import { createAccessVerifier, type AccessVerifierOptions } from '../src/access-jwt.js'
import type { Logger } from '../src/shared/internal.js'
import { RC_ACCESS_JWT_HEADER } from '../src/shared/protocol.js'

const TEAM_DOMAIN = 'team.cloudflareaccess.com'
const AUDIENCE = 'aud-tag-123'
const FIXED_NOW = 1_700_000_000_000
const NOW_S = Math.floor(FIXED_NOW / 1000)

interface KeyMaterial {
  kid: string
  privateKey: KeyObject
  publicKey: KeyObject
}

let keySequence = 0

function makeKey(kid?: string): KeyMaterial {
  keySequence += 1
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return { kid: kid ?? `key-${keySequence}`, privateKey: pair.privateKey, publicKey: pair.publicKey }
}

function jwkOf(key: KeyMaterial): Record<string, unknown> {
  const jwk = key.publicKey.export({ format: 'jwk' }) as { kty: string; n: string; e: string }
  return { kty: 'RSA', kid: key.kid, alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e }
}

function b64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

function makeJwt(
  payload: Record<string, unknown>,
  key: KeyMaterial,
  header: Record<string, unknown> = { alg: 'RS256', typ: 'JWT', kid: key.kid },
): string {
  const signingInput = `${b64url(header)}.${b64url(payload)}`
  const signature = sign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), key.privateKey)
  return `${signingInput}.${signature.toString('base64url')}`
}

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'user@example.com',
    iss: `https://${TEAM_DOMAIN}`,
    aud: AUDIENCE,
    exp: NOW_S + 300,
    nbf: NOW_S - 10,
    iat: NOW_S - 10,
    ...overrides,
  }
}

type FetchHandler = (url: string, init: RequestInit | undefined) => Response | Promise<Response>

function fakeFetch(handler: FetchHandler): { calls: Array<{ url: string; init?: RequestInit }>; fetch: typeof fetch } {
  const calls: Array<{ url: string; init?: RequestInit }> = []
  const fn = async (input: unknown, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : String(input)
    calls.push({ url, init })
    return handler(url, init)
  }
  return { calls, fetch: fn as unknown as typeof fetch }
}

function jwksResponse(keys: unknown[], headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ keys }), {
    status: 200,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

function silentLogger(): Logger & { calls: Array<{ level: string; message: string; detail?: unknown }> } {
  const calls: Array<{ level: string; message: string; detail?: unknown }> = []
  const record = (level: string) => (message: string, detail?: unknown) => {
    calls.push({ level, message, detail })
  }
  return { calls, error: record('error'), warn: record('warn'), info: record('info'), debug: record('debug') }
}

function requestWithJwt(value?: string | string[]): IncomingMessage {
  const headers: Record<string, string | string[]> = {}
  if (value !== undefined) headers[RC_ACCESS_JWT_HEADER] = value
  return { headers } as unknown as IncomingMessage
}

function makeVerifier(
  fetchImpl: typeof fetch,
  options: Partial<AccessVerifierOptions> = {},
  clock: { now: number } = { now: FIXED_NOW },
): { verifier: ReturnType<typeof createAccessVerifier>; clock: { now: number } } {
  const verifier = createAccessVerifier({
    required: true,
    teamDomain: TEAM_DOMAIN,
    audience: AUDIENCE,
    log: silentLogger(),
    fetch: fetchImpl,
    now: () => clock.now,
    ...options,
  })
  return { verifier, clock }
}

const EXPECTED_JWKS_URL = `https://${TEAM_DOMAIN}/cdn-cgi/access/certs`

/* ------------------------------------------------------------------------- */
/* Enforcement switch                                                        */
/* ------------------------------------------------------------------------- */

test('access-jwt: disabled enforcement is a no-op', async (t) => {
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
  const verifier = createAccessVerifier({
    required: false,
    teamDomain: TEAM_DOMAIN,
    audience: AUDIENCE,
    log: silentLogger(),
    fetch: fetchImpl,
  })
  t.after(() => verifier.dispose())

  assert.equal(verifier.enabled(), false)
  assert.deepEqual(await verifier.verify(requestWithJwt()), { ok: true })
  assert.deepEqual(await verifier.verify(requestWithJwt('garbage')), { ok: true })
  assert.equal(calls.length, 0)
})

test('access-jwt: a required verifier reports enabled()', (t) => {
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())
  assert.equal(verifier.enabled(), true)
})

test('access-jwt: setRequired() turns enforcement on and off at runtime', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const verifier = createAccessVerifier({
    required: false,
    teamDomain: TEAM_DOMAIN,
    audience: AUDIENCE,
    log: silentLogger(),
    fetch: fetchImpl,
    now: () => FIXED_NOW,
  })
  t.after(() => verifier.dispose())

  assert.equal(verifier.enabled(), false)
  assert.deepEqual(await verifier.verify(requestWithJwt()), { ok: true })

  // A desktop plan may require Access for one run even when the config default is off.
  verifier.setRequired(true)
  assert.equal(verifier.enabled(), true)
  const missing = await verifier.verify(requestWithJwt())
  assert.equal(missing.ok, false)
  assert.equal(missing.code, 'ACCESS_REQUIRED')
  assert.deepEqual(await verifier.verify(requestWithJwt(makeJwt(claims(), key))), { ok: true })

  verifier.setRequired(false)
  assert.equal(verifier.enabled(), false)
  assert.deepEqual(await verifier.verify(requestWithJwt()), { ok: true })
})

/* ------------------------------------------------------------------------- */
/* Happy path & cache                                                        */
/* ------------------------------------------------------------------------- */

test('access-jwt: a valid RS256 assertion passes and fetches the exact HTTPS JWKS URL', async (t) => {
  const key = makeKey()
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const token = makeJwt(claims(), key)
  assert.deepEqual(await verifier.verify(requestWithJwt(token)), { ok: true })
  assert.deepEqual(calls.map((call) => call.url), [EXPECTED_JWKS_URL])
  assert.equal(calls[0]?.init?.redirect, 'error', 'JWKS redirects must be refused')
  assert.ok(calls[0]?.init?.signal instanceof AbortSignal, 'the JWKS fetch must be abortable')
})

test('access-jwt: the JWKS cache serves subsequent assertions', async (t) => {
  const key = makeKey()
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  assert.equal((await verifier.verify(requestWithJwt(makeJwt(claims(), key)))).ok, true)
  assert.equal((await verifier.verify(requestWithJwt(makeJwt(claims(), key)))).ok, true)
  assert.equal(calls.length, 1, 'two valid assertions must share one JWKS fetch')
})

test('access-jwt: header arrays use the first value', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const token = makeJwt(claims(), key)
  assert.deepEqual(await verifier.verify(requestWithJwt([token, token])), { ok: true })
})

test('access-jwt: a token without a kid is checked against the available keys', async (t) => {
  const first = makeKey()
  const second = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(first), jwkOf(second)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const token = makeJwt(claims(), second, { alg: 'RS256', typ: 'JWT' })
  assert.equal((await verifier.verify(requestWithJwt(token))).ok, true)
})

/* ------------------------------------------------------------------------- */
/* Missing / malformed / rejected tokens                                     */
/* ------------------------------------------------------------------------- */

test('access-jwt: a missing or empty header fails closed when required', async (t) => {
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  for (const request of [requestWithJwt(), requestWithJwt(''), requestWithJwt([])]) {
    const result = await verifier.verify(request)
    assert.equal(result.ok, false)
    assert.equal(result.code, 'ACCESS_REQUIRED')
  }
  assert.equal(calls.length, 0)
})

test('access-jwt: malformed assertions are rejected without a JWKS fetch', async (t) => {
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const key = makeKey()
  const valid = makeJwt(claims(), key)
  const [header, payload] = valid.split('.')
  const malformed = [
    'not-a-jwt',
    'one.two',
    'one.two.three.four',
    '!!!.???.###',
    `${header}.${payload}.`,
    `${header}.${b64url('not-an-object')}.AAAA`,
    `${header}.${payload}.${'A'.repeat(10_000)}`,
    ` .${payload}.AAAA`,
  ]
  for (const token of malformed) {
    const result = await verifier.verify(requestWithJwt(token))
    assert.equal(result.ok, false, `must reject ${JSON.stringify(token.slice(0, 32))}`)
    assert.equal(result.code, 'ACCESS_REQUIRED')
  }
  assert.equal(calls.length, 0, 'structurally invalid assertions must not trigger a JWKS fetch')
})

test('access-jwt: non-RS256 algorithms are rejected without a JWKS fetch', async (t) => {
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())
  const key = makeKey()

  const hs = makeJwt(claims(), key, { alg: 'HS256', typ: 'JWT', kid: key.kid })
  const none = `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(claims())}.`
  for (const token of [hs, none]) {
    const result = await verifier.verify(requestWithJwt(token))
    assert.equal(result.ok, false)
  }
  assert.equal(calls.length, 0)
})

test('access-jwt: a tampered payload or signature is rejected', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const valid = makeJwt(claims(), key)
  const [header, payload, signature] = valid.split('.')
  const tamperedPayload = `${header}.${b64url(claims({ sub: 'attacker' }))}.${signature}`
  const tamperedSignature = `${header}.${payload}.${'A'.repeat(String(signature).length)}`
  const nonJwtJsonBody = `${header}.${b64url({ not: 'jwt-claims' })}.${signature}`

  for (const token of [tamperedPayload, tamperedSignature, nonJwtJsonBody]) {
    const result = await verifier.verify(requestWithJwt(token))
    assert.equal(result.ok, false)
    assert.equal(result.code, 'ACCESS_REQUIRED')
  }
})

test('access-jwt: an assertion signed by an unknown key is rejected', async (t) => {
  const trusted = makeKey()
  const attacker = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(trusted)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const forged = makeJwt(claims(), attacker, { alg: 'RS256', typ: 'JWT', kid: attacker.kid })
  assert.equal((await verifier.verify(requestWithJwt(forged))).ok, false)
})

/* ------------------------------------------------------------------------- */
/* Claim checks                                                              */
/* ------------------------------------------------------------------------- */

test('access-jwt: expired assertions fail closed at the exp boundary', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  for (const exp of [NOW_S - 1, NOW_S]) {
    const result = await verifier.verify(requestWithJwt(makeJwt(claims({ exp }), key)))
    assert.equal(result.ok, false, `exp=${exp} must be rejected`)
    assert.equal(result.code, 'ACCESS_REQUIRED')
  }
  assert.equal((await verifier.verify(requestWithJwt(makeJwt(claims({ exp: NOW_S + 1 }), key)))).ok, true)
})

test('access-jwt: a future nbf fails closed', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  assert.equal((await verifier.verify(requestWithJwt(makeJwt(claims({ nbf: NOW_S + 120 }), key)))).ok, false)
})

test('access-jwt: wrong audience, wrong issuer and missing exp fail closed', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const rejected = [
    claims({ aud: 'someone-else' }),
    claims({ aud: ['other', 'also-other'] }),
    claims({ iss: 'https://evil.cloudflareaccess.com' }),
    claims({ iss: 'http://team.cloudflareaccess.com' }),
    claims({ exp: undefined }),
    claims({ exp: 'tomorrow' }),
    claims({ aud: undefined }),
  ]
  for (const payload of rejected) {
    assert.equal((await verifier.verify(requestWithJwt(makeJwt(payload, key)))).ok, false)
  }

  assert.equal(
    (await verifier.verify(requestWithJwt(makeJwt(claims({ aud: ['other', AUDIENCE] }), key)))).ok,
    true,
    'aud may be an array containing the configured tag',
  )
})

/* ------------------------------------------------------------------------- */
/* Configuration errors fail closed                                          */
/* ------------------------------------------------------------------------- */

test('access-jwt: required but misconfigured fails closed (never open)', async (t) => {
  for (const overrides of [
    { teamDomain: '' },
    { teamDomain: 'http://team.cloudflareaccess.com' },
    { teamDomain: 'team.cloudflareaccess.com/path' },
    { teamDomain: 'team.cloudflareaccess.com:443' },
    { teamDomain: 'localhost' },
    { teamDomain: '127.0.0.1' },
    { audience: '' },
  ]) {
    const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
    const verifier = createAccessVerifier({
      required: true,
      teamDomain: TEAM_DOMAIN,
      audience: AUDIENCE,
      log: silentLogger(),
      fetch: fetchImpl,
      ...overrides,
    })
    t.after(() => verifier.dispose())
    const result = await verifier.verify(requestWithJwt('some.jwt.value'))
    assert.equal(result.ok, false, `misconfigured ${JSON.stringify(overrides)} must fail closed`)
    assert.equal(result.code, 'ACCESS_REQUIRED')
    assert.equal(calls.length, 0)
  }
})

/* ------------------------------------------------------------------------- */
/* JWKS fetch robustness                                                     */
/* ------------------------------------------------------------------------- */

test('access-jwt: JWKS HTTP/parse/size failures fail closed', async (t) => {
  const key = makeKey()
  const token = makeJwt(claims(), key)
  const handlers: FetchHandler[] = [
    () => new Response('nope', { status: 500 }),
    () => new Response('<html>not json</html>', { status: 200 }),
    () => new Response(JSON.stringify({ keys: [] }), { status: 200 }),
    () => new Response(JSON.stringify({ notKeys: [] }), { status: 200 }),
    () => new Response('x'.repeat(4_096), { status: 200, headers: { 'cache-control': 'max-age=300' } }),
    () => {
      throw new Error('network down')
    },
  ]
  for (const handler of handlers) {
    const { fetch: fetchImpl } = fakeFetch(handler)
    const { verifier } = makeVerifier(fetchImpl, { maxJwksBytes: 1_024 })
    t.after(() => verifier.dispose())
    const result = await verifier.verify(requestWithJwt(token))
    assert.equal(result.ok, false)
    assert.equal(result.code, 'ACCESS_REQUIRED')
  }
})

test('access-jwt: the JWKS request has a bounded timeout', async (t) => {
  const fetchImpl = (async (_input: unknown, init?: RequestInit): Promise<Response> => {
    return new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal ?? null
      if (signal !== null && signal.aborted) {
        reject(new Error('aborted'))
        return
      }
      signal?.addEventListener('abort', () => reject(new Error('aborted')))
    })
  }) as unknown as typeof fetch
  const { verifier } = makeVerifier(fetchImpl, { requestTimeoutMs: 25 })
  t.after(() => verifier.dispose())

  const started = Date.now()
  const result = await verifier.verify(requestWithJwt('some.jwt.value'))
  assert.equal(result.ok, false)
  assert.ok(Date.now() - started < 2_000, 'the fetch must be aborted by the timeout')
})

/* ------------------------------------------------------------------------- */
/* Cache validity                                                            */
/* ------------------------------------------------------------------------- */

test('access-jwt: cached JWKS expires after the configured TTL', async (t) => {
  const key = makeKey()
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier, clock } = makeVerifier(fetchImpl, { jwksCacheTtlMs: 60_000 })
  t.after(() => verifier.dispose())

  const token = makeJwt(claims(), key)
  assert.equal((await verifier.verify(requestWithJwt(token))).ok, true)
  clock.now += 30_000
  assert.equal((await verifier.verify(requestWithJwt(token))).ok, true)
  assert.equal(calls.length, 1)
  clock.now += 30_001
  assert.equal((await verifier.verify(requestWithJwt(token))).ok, true)
  assert.equal(calls.length, 2, 'an expired cache must be refetched')
})

test('access-jwt: Cache-Control no-store disables caching', async (t) => {
  const key = makeKey()
  const { calls, fetch: fetchImpl } = fakeFetch(() =>
    jwksResponse([jwkOf(key)], { 'cache-control': 'no-store' }),
  )
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const token = makeJwt(claims(), key)
  await verifier.verify(requestWithJwt(token))
  await verifier.verify(requestWithJwt(token))
  assert.equal(calls.length, 2)
})

test('access-jwt: max-age is clamped to a bounded cache lifetime', async (t) => {
  const key = makeKey()
  const { calls, fetch: fetchImpl } = fakeFetch(() =>
    jwksResponse([jwkOf(key)], { 'cache-control': 'max-age=1' }),
  )
  const { verifier, clock } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const token = makeJwt(claims(), key)
  await verifier.verify(requestWithJwt(token))
  clock.now += 30_000
  await verifier.verify(requestWithJwt(token))
  assert.equal(calls.length, 1, 'a tiny max-age is floored to the bounded minimum')
  clock.now += 31_000
  await verifier.verify(requestWithJwt(token))
  assert.equal(calls.length, 2)
})

test('access-jwt: a rotated key is picked up via one bounded refresh', async (t) => {
  const first = makeKey()
  const second = makeKey()
  const keysRef = { keys: [jwkOf(first)] }
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse(keysRef.keys))
  const { verifier, clock } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  assert.equal((await verifier.verify(requestWithJwt(makeJwt(claims(), first)))).ok, true)
  assert.equal(calls.length, 1)

  keysRef.keys = [jwkOf(second)]
  clock.now += 31_000
  assert.equal((await verifier.verify(requestWithJwt(makeJwt(claims(), second)))).ok, true)
  assert.equal(calls.length, 2, 'an unknown kid forces exactly one refresh')
})

test('access-jwt: unknown-kid refreshes are rate limited', async (t) => {
  const trusted = makeKey()
  const stranger = makeKey()
  const { calls, fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(trusted)]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  await verifier.verify(requestWithJwt(makeJwt(claims(), trusted)))
  assert.equal(calls.length, 1)
  const forged = makeJwt(claims(), stranger, { alg: 'RS256', typ: 'JWT', kid: 'rotated-key' })
  await verifier.verify(requestWithJwt(forged))
  assert.equal(calls.length, 1, 'the forced refresh is rate limited right after a fetch')
})

/* ------------------------------------------------------------------------- */
/* No leakage / lifecycle                                                    */
/* ------------------------------------------------------------------------- */

test('access-jwt: failures never leak the assertion or its signature into results or logs', async (t) => {
  const key = makeKey()
  const logger = silentLogger()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const verifier = createAccessVerifier({
    required: true,
    teamDomain: TEAM_DOMAIN,
    audience: AUDIENCE,
    log: logger,
    fetch: fetchImpl,
    now: () => FIXED_NOW,
  })
  t.after(() => verifier.dispose())

  const token = makeJwt(claims({ exp: NOW_S - 10 }), key)
  const signature = token.split('.')[2] ?? ''
  const result = await verifier.verify(requestWithJwt(token))
  assert.equal(result.ok, false)
  const serialized = JSON.stringify({ result, log: logger.calls })
  assert.equal(serialized.includes(token), false)
  assert.equal(serialized.includes(signature), false)
})

test('access-jwt: dispose() fails closed for a required verifier', async (t) => {
  const key = makeKey()
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([jwkOf(key)]))
  const { verifier } = makeVerifier(fetchImpl)
  const token = makeJwt(claims(), key)
  assert.equal((await verifier.verify(requestWithJwt(token))).ok, true)
  verifier.dispose()
  const result = await verifier.verify(requestWithJwt(token))
  assert.equal(result.ok, false)
  assert.equal(result.code, 'ACCESS_REQUIRED')
})

test('access-jwt: verify never throws on hostile header values', async (t) => {
  const { fetch: fetchImpl } = fakeFetch(() => jwksResponse([]))
  const { verifier } = makeVerifier(fetchImpl)
  t.after(() => verifier.dispose())

  const hostile = [
    'a.b.c',
    '\u0000.\u0000.\u0000',
    'x'.repeat(20_000),
    '...',
    Array.from({ length: 50 }, () => 'x').join('.'),
  ]
  for (const token of hostile) {
    await assert.doesNotReject(async () => {
      const result = await verifier.verify(requestWithJwt(token))
      assert.equal(result.ok, false)
    })
  }
})
