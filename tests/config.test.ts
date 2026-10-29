/**
 * Config schema contract: safe-by-default values, runtime validation, and the
 * hard ceilings that keep a misconfiguration from exposing the machine.
 *
 * Schemastery schemas are callable validators; `Config({})` fills defaults and
 * `Config({...})` throws on any invalid value.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { Config, resolveAccessTtlMs, type RemoteControlConfig } from '../src/config.js'

const validate = Config as unknown as (value?: unknown) => RemoteControlConfig

function parse(value: unknown): RemoteControlConfig {
  return validate(value)
}

test('config: safe defaults (remote control is off unless explicitly enabled)', () => {
  const config = parse({})

  assert.equal(config.enabled, false)
  assert.equal(config.autoStart, false)
  assert.equal(config.remoteMutations, false)
  assert.equal(config.approvalRelay, false)
  assert.equal(config.userQuestions, false)
  assert.equal(config.logLevel, 'warn')
  assert.deepEqual(config.allowedOrigins, [])
})

test('config: listener defaults to loopback on an ephemeral port', () => {
  const config = parse({})

  assert.equal(config.listen.host, '127.0.0.1')
  assert.equal(config.listen.port, 0)
  assert.equal(config.listen.allowLan, false)
  assert.equal(config.listen.access, 'loopback')
  assert.equal(config.listen.lanAddress, '')
  assert.deepEqual(config.listen.tls, { certFile: '', keyFile: '' })
})

test('config: LAN is an explicit listener access strategy', () => {
  const config = parse({ listen: { access: 'lan', lanAddress: '192.168.1.104', port: 8443 } })

  assert.equal(config.listen.access, 'lan')
  assert.equal(config.listen.lanAddress, '192.168.1.104')
  assert.throws(() => parse({ listen: { access: 'wildcard' } }), TypeError)
  assert.throws(() => parse({ listen: { access: 'public' } }), TypeError)
})

test('config: tunnel defaults to off with the token-free quick mode', () => {
  const config = parse({})

  assert.equal(config.tunnel.enabled, false)
  assert.equal(config.tunnel.mode, 'quick')
  assert.equal(config.tunnel.publicUrl, '')
  assert.equal(config.tunnel.hostname, '')
  assert.equal(config.tunnel.tokenEnv, 'CLOUDFLARE_TUNNEL_TOKEN')
  assert.equal(config.tunnel.tokenFile, '')
  assert.equal(config.tunnel.transport, 'auto')
  assert.equal(config.tunnel.tunnelId, '')
  assert.equal(config.tunnel.credentialsFile, '')
  assert.equal(config.tunnel.sshPath, 'ssh')
  assert.equal(config.tunnel.sshUser, 'nokey')
  assert.equal(config.tunnel.sshHost, 'localhost.run')
  assert.equal(config.tunnel.sshRemotePort, 80)
  assert.deepEqual(config.tunnel.access, { required: false, teamDomain: '', audience: '' })
  assert.deepEqual(config.tunnel.env, {})
})

test('config: new tunnel modes are accepted and legacy modes are preserved', () => {
  for (const mode of ['quick', 'external', 'named', 'named-local', 'ssh'] as const) {
    assert.equal(parse({ tunnel: { mode } }).tunnel.mode, mode)
  }
  assert.throws(() => parse({ tunnel: { mode: 'lan' } }), TypeError)
  assert.throws(() => parse({ tunnel: { transport: 'tcp' } }), TypeError)
})

test('config: pairing/token limits match the documented ceilings', () => {
  const config = parse({})

  assert.equal(config.pairing.ttlSeconds, 120)
  assert.equal(config.pairing.maxPendingCodes, 3)
  assert.equal(config.tokens.accessTtlMinutes, 0)
  assert.equal(config.tokens.accessTtlHours, 0)
  assert.equal(config.tokens.refreshTtlDays, 10)
  assert.equal(config.tokens.refreshAheadSeconds, 300)
  assert.equal(config.tokens.maxDevices, 4)
  assert.equal(config.tokens.deviceStorePath, '')
})

test('config: effective access TTL defaults to 15 minutes and honours migration', () => {
  assert.equal(resolveAccessTtlMs(parse({}).tokens), 15 * 60_000)
  assert.equal(resolveAccessTtlMs(parse({ tokens: { accessTtlHours: 8 } }).tokens), 8 * 3_600_000)
  assert.equal(resolveAccessTtlMs(parse({ tokens: { accessTtlMinutes: 30 } }).tokens), 30 * 60_000)
  // New minutes value wins over the deprecated hours field.
  assert.equal(
    resolveAccessTtlMs(parse({ tokens: { accessTtlMinutes: 20, accessTtlHours: 8 } }).tokens),
    20 * 60_000,
  )
  // Never below the 10-minute safety floor.
  assert.equal(resolveAccessTtlMs({ ...parse({}).tokens, accessTtlMinutes: 1 }), 10 * 60_000)
})

test('config: security policy defaults match the required attack-surface policy', () => {
  const config = parse({})

  assert.deepEqual(config.security, {
    idleTimeoutMinutes: 30,
    failureWindowSeconds: 60,
    failuresBeforeBan: 5,
    temporaryBanMinutes: 5,
    circuitBreakerFailures: 10,
  })
})

test('config: explicit values survive validation', () => {
  const config = parse({
    enabled: true,
    autoStart: true,
    remoteMutations: true,
    approvalRelay: true,
    userQuestions: true,
    logLevel: 'debug',
    allowedOrigins: ['https://rc.example.com'],
    listen: { host: '::1', port: 8443, allowLan: true },
    tunnel: { enabled: true, mode: 'external', publicUrl: 'https://rc.example.com' },
    pairing: { ttlSeconds: 300, maxPendingCodes: 5 },
    tokens: { accessTtlHours: 1, refreshTtlDays: 90, maxDevices: 2 },
  })

  assert.equal(config.enabled, true)
  assert.equal(config.autoStart, true)
  assert.equal(config.remoteMutations, true)
  assert.equal(config.approvalRelay, true)
  assert.equal(config.userQuestions, true)
  assert.equal(config.logLevel, 'debug')
  assert.deepEqual(config.allowedOrigins, ['https://rc.example.com'])
  assert.equal(config.listen.host, '::1')
  assert.equal(config.listen.port, 8443)
  assert.equal(config.listen.allowLan, true)
  assert.equal(config.tunnel.mode, 'external')
  assert.equal(config.tunnel.publicUrl, 'https://rc.example.com')
  assert.equal(config.pairing.ttlSeconds, 300)
  assert.equal(config.pairing.maxPendingCodes, 5)
  assert.equal(config.tokens.maxDevices, 2)
})

test('config: invalid tunnel mode is rejected', () => {
  assert.throws(() => parse({ tunnel: { mode: 'bogus' } }), TypeError)
})

test('config: invalid log level is rejected', () => {
  assert.throws(() => parse({ logLevel: 'verbose' }), TypeError)
})

test('config: maxDevices above the hard ceiling of 4 is rejected', () => {
  assert.throws(() => parse({ tokens: { maxDevices: 5 } }), TypeError)
  assert.throws(() => parse({ tokens: { maxDevices: 0 } }), TypeError)
})

test('config: out-of-range token/pairing lifetimes are rejected', () => {
  assert.throws(() => parse({ tokens: { accessTtlHours: 73 } }), TypeError)
  assert.throws(() => parse({ tokens: { accessTtlMinutes: 1441 } }), TypeError)
  assert.throws(() => parse({ tokens: { refreshTtlDays: 91 } }), TypeError)
  assert.throws(() => parse({ pairing: { ttlSeconds: 10 } }), TypeError)
  assert.throws(() => parse({ pairing: { maxPendingCodes: 6 } }), TypeError)
  assert.throws(() => parse({ tunnel: { startupTimeoutSeconds: 5 } }), TypeError)
  assert.throws(() => parse({ listen: { port: 70000 } }), TypeError)
})

test('config: out-of-range security policy is rejected', () => {
  assert.throws(() => parse({ security: { idleTimeoutMinutes: 1 } }), TypeError)
  assert.throws(() => parse({ security: { idleTimeoutMinutes: 241 } }), TypeError)
  assert.throws(() => parse({ security: { failuresBeforeBan: 0 } }), TypeError)
  assert.throws(() => parse({ security: { temporaryBanMinutes: 0 } }), TypeError)
  assert.throws(() => parse({ security: { circuitBreakerFailures: 1 } }), TypeError)
})

test('config: wrong primitive types are rejected', () => {
  assert.throws(() => parse({ enabled: 'yes' }), TypeError)
  assert.throws(() => parse({ listen: { host: 127 } }), TypeError)
  assert.throws(() => parse({ allowedOrigins: [42] }), TypeError)
  assert.throws(() => parse({ tunnel: { env: { BROKEN: 1 } } }), TypeError)
})
