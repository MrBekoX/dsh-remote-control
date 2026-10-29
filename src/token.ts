/**
 * Token minting/verification for paired devices (design §5.2, contract v2).
 *
 * - access token: stateless HMAC, format
 *   `rc1.<deviceId>.<expEpochMs>.<tokenVersion>.<epoch>.<nonceB64url>.<sigB64url>`
 *   where
 *   `sig = HMAC-SHA256(base64url(tokenKey), "rc1|deviceId|exp|tokenVersion|epoch|nonce")`.
 *   The epoch binding is the persisted token-revocation epoch: an emergency
 *   shutdown bumps the persisted epoch, so every access token minted before the
 *   bump fails verification even across a DSH restart. The service only returns
 *   claims; the controller also checks the device store (`device exists`,
 *   `tokenVersion`, expiry vs. now) before trusting a request.
 * - refresh token: random 32-byte secret, format `rcr1.<deviceId>.<secretB64url>`.
 *   Only `sha256(token)` is persisted (by the controller in the device store).
 * - pairing codes / refresh lookups use `hashSecret` (sha256 hex).
 *
 * All comparisons of secrets are constant-time (`timingSafeEqual`). Malformed
 * input always returns null/never throws; only programmer errors (invalid
 * device ids, key material, TTLs or epochs at issue time) throw.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

import type {
  AccessClaims,
  AccessVerificationState,
  StoredDevice,
  TokenService,
} from './shared/internal.js'

const ACCESS_PREFIX = 'rc1'
const REFRESH_PREFIX = 'rcr1'
const B64URL = /^[A-Za-z0-9_-]+$/
const DEVICE_ID = /^[A-Za-z0-9_-]{1,128}$/
const SIGNATURE_BYTES = 32
const TOKEN_KEY_BYTES = 32
const NONCE_BYTES = 12
const REFRESH_BYTES = 32
/** Epochs are monotonic counters; larger than safe-integer values are invalid. */
const MAX_EPOCH = Number.MAX_SAFE_INTEGER
const EPOCH_PATTERN = /^[0-9]{1,16}$/

export interface TokenServiceOptions {
  accessTtlMs: number
  refreshTtlMs: number
  /**
   * Controller wiring. `verifyAccess` needs the per-device `tokenKey` from the
   * device store; without this lookup only devices seen by this service
   * instance (`issueAccess`/`issueRefresh`) can be verified.
   */
  getDevice?: (deviceId: string) => StoredDevice | undefined
  /** Test seam; defaults to `Date.now`. */
  now?: () => number
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

function decodeTokenKey(tokenKey: string): Buffer {
  if (!B64URL.test(tokenKey)) throw new Error('device token key is not base64url')
  const key = Buffer.from(tokenKey, 'base64url')
  if (key.length !== TOKEN_KEY_BYTES) throw new Error('device token key must be 32 bytes')
  return key
}

function assertDuration(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer of milliseconds`)
  }
  return value
}

/** A revocation epoch is a small non-negative integer; anything else is a bug. */
function assertEpoch(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_EPOCH) {
    throw new Error('revocation epoch must be a non-negative integer')
  }
  return value
}

export function createTokenService(options: TokenServiceOptions): TokenService {
  const now = options.now ?? Date.now
  const accessTtlMs = assertDuration('accessTtlMs', options.accessTtlMs)
  const refreshTtlMs = assertDuration('refreshTtlMs', options.refreshTtlMs)
  /** Last-seen device snapshots, so a same-process verify works without a resolver. */
  const known = new Map<string, StoredDevice>()

  const resolveDevice = (deviceId: string): StoredDevice | undefined => {
    const fromStore = options.getDevice?.(deviceId)
    if (fromStore !== undefined) {
      known.set(fromStore.id, fromStore)
      return fromStore
    }
    return known.get(deviceId)
  }

  const remember = (device: StoredDevice): void => {
    known.set(device.id, { ...device })
    if (known.size > 64) {
      const oldest = known.keys().next()
      if (!oldest.done) known.delete(oldest.value)
    }
  }

  const signAccess = (
    device: StoredDevice,
    expiresAt: number,
    epoch: number,
    nonce: string,
  ): string => {
    const payload = `${ACCESS_PREFIX}|${device.id}|${expiresAt}|${device.tokenVersion}|${epoch}|${nonce}`
    return createHmac('sha256', decodeTokenKey(device.tokenKey)).update(payload, 'utf8').digest('base64url')
  }

  function issueAccess(device: StoredDevice, epoch = 0): { token: string; expiresAt: number } {
    if (!DEVICE_ID.test(device.id)) throw new Error('invalid device id')
    const boundEpoch = assertEpoch(epoch)
    const expiresAt = now() + accessTtlMs
    const nonce = randomBytes(NONCE_BYTES).toString('base64url')
    const signature = signAccess(device, expiresAt, boundEpoch, nonce)
    remember(device)
    return {
      token: `${ACCESS_PREFIX}.${device.id}.${expiresAt}.${device.tokenVersion}.${boundEpoch}.${nonce}.${signature}`,
      expiresAt,
    }
  }

  /**
   * Full access-token verification shared by `verifyAccess` and
   * `verifyAccessDetailed`.
   *
   * Order matters for the security monitor: the signature/token material and
   * the revocation epoch are validated first, so only a genuinely trustworthy
   * token can be reported as merely `expired` (which the controller answers with
   * TOKEN_EXPIRED and does not count as an authentication failure). Every
   * malformed/tampered/revoked token is `invalid`.
   */
  function inspectAccess(token: string, expectedEpoch?: number): AccessVerificationState {
    if (typeof token !== 'string') return { state: 'invalid' }
    const parts = token.split('.')
    if (parts.length !== 7 || parts[0] !== ACCESS_PREFIX) return { state: 'invalid' }
    const [, deviceId, expiresRaw, versionRaw, epochRaw, nonce, signature] = parts
    if (deviceId === undefined || !DEVICE_ID.test(deviceId)) return { state: 'invalid' }
    if (!/^[0-9]{1,16}$/.test(expiresRaw ?? '') || !/^[0-9]{1,10}$/.test(versionRaw ?? '')) {
      return { state: 'invalid' }
    }
    if (!EPOCH_PATTERN.test(epochRaw ?? '')) return { state: 'invalid' }
    if (!B64URL.test(nonce ?? '') || !B64URL.test(signature ?? '')) return { state: 'invalid' }
    const expiresAt = Number(expiresRaw)
    const tokenVersion = Number(versionRaw)
    const epoch = Number(epochRaw)
    if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(tokenVersion)) return { state: 'invalid' }
    if (!Number.isSafeInteger(epoch) || epoch < 0 || epoch > MAX_EPOCH) return { state: 'invalid' }

    const decoder = Buffer.from(signature, 'base64url')
    if (decoder.length !== SIGNATURE_BYTES) return { state: 'invalid' }

    const device = resolveDevice(deviceId)
    if (device === undefined) return { state: 'invalid' }
    let expected: Buffer
    try {
      expected = createHmac('sha256', decodeTokenKey(device.tokenKey))
        .update(`${ACCESS_PREFIX}|${deviceId}|${expiresAt}|${tokenVersion}|${epoch}|${nonce}`, 'utf8')
        .digest()
    } catch {
      return { state: 'invalid' }
    }
    if (decoder.length !== expected.length || !timingSafeEqual(decoder, expected)) {
      return { state: 'invalid' }
    }
    if (expectedEpoch !== undefined) {
      if (!Number.isSafeInteger(expectedEpoch) || expectedEpoch < 0 || expectedEpoch > MAX_EPOCH) {
        return { state: 'invalid' }
      }
      if (epoch !== expectedEpoch) return { state: 'invalid' }
    }
    const claims: AccessClaims = { deviceId, tokenVersion, expiresAt, epoch }
    if (expiresAt <= now()) return { state: 'expired', claims }
    return { state: 'valid', claims }
  }

  /**
   * Verify one access token. Returns null for malformed/tampered/expired tokens
   * and when the token's revocation epoch differs from `expectedEpoch` (a bump
   * permanently invalidates previously minted tokens). `expectedEpoch` is
   * optional only for lightweight fakes/legacy integrations; the controller
   * always passes the persisted epoch.
   */
  function verifyAccess(token: string, expectedEpoch?: number): AccessClaims | null {
    const result = inspectAccess(token, expectedEpoch)
    return result.state === 'valid' ? result.claims : null
  }

  /**
   * Like `verifyAccess`, but separates a normally expired (but authentic) token
   * from an invalid one so the controller can avoid counting the ordinary
   * expired-access → refresh flow as an attack. Never throws.
   */
  function verifyAccessDetailed(token: string, expectedEpoch?: number): AccessVerificationState {
    return inspectAccess(token, expectedEpoch)
  }

  function issueRefresh(device: StoredDevice): { token: string; hash: string; expiresAt: number } {
    if (!DEVICE_ID.test(device.id)) throw new Error('invalid device id')
    const token = `${REFRESH_PREFIX}.${device.id}.${randomBytes(REFRESH_BYTES).toString('base64url')}`
    remember(device)
    return { token, hash: sha256Hex(token), expiresAt: now() + refreshTtlMs }
  }

  /**
   * Parse-only subject extraction for refresh rotation: the token shape embeds
   * the device id, but the secret is validated by the controller with
   * `equalRefresh` against the stored hash.
   */
  function readRefreshSubject(token: string): { deviceId: string } | null {
    if (typeof token !== 'string') return null
    const parts = token.split('.')
    if (parts.length !== 3 || parts[0] !== REFRESH_PREFIX) return null
    const deviceId = parts[1] ?? ''
    const secret = parts[2] ?? ''
    if (!DEVICE_ID.test(deviceId)) return null
    if (!B64URL.test(secret) || secret.length < 20) return null
    return { deviceId }
  }

  function hashRefresh(token: string): string {
    return sha256Hex(String(token ?? ''))
  }

  function equalRefresh(a: string, b: string): boolean {
    return constantTimeEqual(String(a ?? ''), String(b ?? ''))
  }

  function hashSecret(secret: string): string {
    return sha256Hex(String(secret ?? ''))
  }

  function equalHex(a: string, b: string): boolean {
    return constantTimeEqual(String(a ?? ''), String(b ?? ''))
  }

  return {
    issueAccess,
    verifyAccess,
    verifyAccessDetailed,
    issueRefresh,
    readRefreshSubject,
    hashRefresh,
    equalRefresh,
    hashSecret,
    equalHex,
  }
}
