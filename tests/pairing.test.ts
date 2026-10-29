/**
 * Pairing state machine (design §5.1):
 * one-time hashed codes, TTL, desktop claim→approve/deny, single use,
 * maxPendingCodes and the DEVICE_LIMIT guard.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import {
  createPairingManager,
  sanitizeDeviceName,
  sanitizePlatform,
  type PairingManagerOptions,
} from '../src/pairing.js'
import type { Logger, PairingFailure } from '../src/shared/internal.js'

const TTL_MS = 60_000
const FIXED_NOW = 1_700_000_000_000

function silentLogger(): Logger {
  return {
    error: () => undefined,
    warn: () => undefined,
    info: () => undefined,
    debug: () => undefined,
  }
}

interface Harness {
  manager: ReturnType<typeof createPairingManager>
  clock: { now: number }
  dispose(): void
}

function makeHarness(options: Partial<PairingManagerOptions> = {}): Harness {
  const clock = { now: FIXED_NOW }
  const manager = createPairingManager({
    ttlMs: TTL_MS,
    maxPendingCodes: 3,
    log: silentLogger(),
    now: () => clock.now,
    ...options,
  })
  return { manager, clock, dispose: () => manager.dispose() }
}

function isFailure(value: unknown): value is PairingFailure {
  return typeof value === 'object' && value !== null && (value as PairingFailure).ok === false
}

/* ------------------------------------------------------------------------- */
/* Code creation                                                             */
/* ------------------------------------------------------------------------- */

test('pairing: create() mints a random one-time code with the configured TTL', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()

  assert.notEqual(created, null)
  assert.match(created?.code ?? '', /^[A-Za-z0-9_-]{40,}$/)
  assert.equal(created?.expiresAt, FIXED_NOW + TTL_MS)
})

test('pairing: create() returns null at maxPendingCodes and recovers after TTL', (t) => {
  const harness = makeHarness({ maxPendingCodes: 2 })
  t.after(() => harness.dispose())

  assert.notEqual(harness.manager.create(), null)
  assert.notEqual(harness.manager.create(), null)
  assert.equal(harness.manager.create(), null, 'third outstanding code must be refused')

  // Codes are swept after their TTL, freeing slots again.
  harness.clock.now += TTL_MS + 1
  assert.notEqual(harness.manager.create(), null)
})

test('pairing: created codes are unique', (t) => {
  const harness = makeHarness({ maxPendingCodes: 5 })
  t.after(() => harness.dispose())
  const codes = new Set<string>()
  for (let index = 0; index < 5; index += 1) {
    const created = harness.manager.create()
    assert.notEqual(created, null)
    codes.add(String(created?.code))
  }
  assert.equal(codes.size, 5)
})

/* ------------------------------------------------------------------------- */
/* Claiming                                                                  */
/* ------------------------------------------------------------------------- */

test('pairing: a valid code can be claimed exactly once', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  assert.notEqual(created, null)

  const claimed = harness.manager.claim({
    code: String(created?.code),
    deviceName: '  Pixel   8  ',
    platform: 'Android',
  })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  assert.equal(claimed.ok, true)
  assert.match(claimed.claimId, /^[A-Za-z0-9_-]{20,}$/)
  assert.match(claimed.pollToken, /^[A-Za-z0-9_-]{40,}$/)
  assert.equal(claimed.expiresAt, FIXED_NOW + TTL_MS)
  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'claimed')

  const second = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(second), true, 'a code must not be reusable')
  // The prompt requires the second use of a claimed code to be a replay (403),
  // distinct from an unknown/invalid code.
  if (isFailure(second)) assert.equal(second.code, 'PAIRING_CONSUMED')

  // An unrelated random code still reports the generic invalid code.
  const invalid = harness.manager.claim({ code: 'not-a-real-code', deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(invalid), true)
  if (isFailure(invalid)) assert.equal(invalid.code, 'PAIRING_INVALID')
})

test('pairing: claim fails closed for unknown, empty or expired codes', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())

  for (const code of ['', 'not-a-code', 'A'.repeat(43)]) {
    const result = harness.manager.claim({ code, deviceName: 'x', platform: 'web' })
    assert.equal(isFailure(result), true)
    if (isFailure(result)) assert.equal(result.code, 'PAIRING_INVALID')
  }

  const created = harness.manager.create()
  assert.notEqual(created, null)
  harness.clock.now += TTL_MS + 1
  const expired = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(expired), true, 'an expired code must never be claimable')
})

test('pairing: claim rejects with DEVICE_LIMIT when the store is full', (t) => {
  const harness = makeHarness({ deviceCount: () => 4, maxDevices: 4 })
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  assert.notEqual(created, null)

  const result = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(result), true)
  if (isFailure(result)) assert.equal(result.code, 'DEVICE_LIMIT')

  const under = makeHarness({ deviceCount: () => 3, maxDevices: 4 })
  t.after(() => under.dispose())
  const code = under.manager.create()
  const accepted = under.manager.claim({ code: String(code?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(accepted), false)
})

test('pairing: device name and platform are sanitized for display', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({
    code: String(created?.code),
    deviceName: '  Ümit\u0000\u202e   iPhone\n15  ',
    platform: 'iOS Mobile',
  })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  const pending = harness.manager.pendingApprovals()
  assert.equal(pending.length, 1)
  // Control characters (including newlines) are deleted before whitespace collapse.
  assert.equal(pending[0]?.deviceName, 'Ümit iPhone15')
  assert.equal(pending[0]?.platform, 'web', 'invalid platform tags fall back to web')
})

/* ------------------------------------------------------------------------- */
/* Status polling                                                           */
/* ------------------------------------------------------------------------- */

test('pairing: status requires the matching poll token', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'claimed')
  assert.equal(harness.manager.status(claimed.claimId, 'wrong-token'), 'expired')
  assert.equal(harness.manager.status(claimed.claimId, ''), 'expired')
  assert.equal(harness.manager.status('unknown-claim', claimed.pollToken), 'expired')
})

test('pairing: an unapproved claim times out and is then dropped', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  harness.clock.now += TTL_MS + 1
  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'claimed-timeout')

  harness.clock.now += TTL_MS + 1
  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'expired')
})

/* ------------------------------------------------------------------------- */
/* Desktop decision                                                          */
/* ------------------------------------------------------------------------- */

test('pairing: approve exposes the claimed details and is idempotent', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'Pixel', platform: 'android' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  const approved = harness.manager.approve(claimed.claimId)
  assert.notEqual(approved, null)
  assert.equal(approved?.deviceName, 'Pixel')
  assert.equal(approved?.platform, 'android')
  assert.equal(approved?.pollToken, claimed.pollToken)
  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'approved')
  assert.deepEqual(harness.manager.approve(claimed.claimId), approved, 'approve must be idempotent')

  assert.equal(harness.manager.approve('unknown-claim'), null)
})

test('pairing: approved claims expire with the claim TTL', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return
  harness.manager.approve(claimed.claimId)

  harness.clock.now += TTL_MS + 1
  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'expired')
})

test('pairing: deny wins over approve for the same claim', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  assert.equal(harness.manager.deny(claimed.claimId), true)
  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'denied')
  assert.equal(harness.manager.approve(claimed.claimId), null, 'a denied claim cannot be approved')
  assert.equal(harness.manager.deny(claimed.claimId), false)
  assert.equal(harness.manager.deny('unknown-claim'), false)
})

test('pairing: consume removes the claim after tokens were issued', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return
  harness.manager.approve(claimed.claimId)
  harness.manager.consume(claimed.claimId)

  assert.equal(harness.manager.status(claimed.claimId, claimed.pollToken), 'expired')
  assert.deepEqual(harness.manager.pendingApprovals(), [])
  assert.deepEqual(harness.manager.list(), [])
})

/* ------------------------------------------------------------------------- */
/* Views                                                                     */
/* ------------------------------------------------------------------------- */

test('pairing: list/pendingApprovals expose only display-safe fields', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const unclaimed = harness.manager.create()
  assert.notEqual(unclaimed, null)
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'Pixel', platform: 'android' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  assert.equal(harness.manager.list().length, 2, 'one pending code + one claim')
  const pending = harness.manager.pendingApprovals()
  assert.equal(pending.length, 1)
  assert.deepEqual(Object.keys(pending[0] ?? {}).sort(), [
    'claimId',
    'createdAt',
    'deviceName',
    'expiresAt',
    'platform',
    'state',
  ])
  assert.equal(JSON.stringify(pending).includes(claimed.pollToken), false, 'poll token must never leak into a view')

  harness.manager.approve(claimed.claimId)
  assert.deepEqual(harness.manager.pendingApprovals(), [])
})

test('pairing: dispose clears all state', (t) => {
  const harness = makeHarness()
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return
  harness.dispose()

  assert.deepEqual(harness.manager.list(), [])
  assert.deepEqual(harness.manager.pendingApprovals(), [])
})

/* ------------------------------------------------------------------------- */
/* Atomic issue reservation (beginIssue)                                     */
/* ------------------------------------------------------------------------- */

function claimApproved(harness: Harness): { claimId: string; pollToken: string } | null {
  const created = harness.manager.create()
  if (created === null) return null
  const claimed = harness.manager.claim({ code: created.code, deviceName: 'Pixel', platform: 'android' })
  if (isFailure(claimed)) return null
  if (harness.manager.approve(claimed.claimId) === null) return null
  return { claimId: claimed.claimId, pollToken: claimed.pollToken }
}

test('pairing: beginIssue reserves an approved claim exactly once before device creation', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const approved = claimApproved(harness)
  assert.notEqual(approved, null)
  if (approved === null) return

  // The phone must not be able to self-issue: an unapproved claim has no reservation.
  const unapproved = (() => {
    const created = harness.manager.create()
    const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
    return isFailure(claimed) ? null : claimed
  })()
  assert.notEqual(unapproved, null)
  if (unapproved !== null) {
    assert.equal(harness.manager.beginIssue?.(unapproved.claimId, unapproved.pollToken), null)
  }

  const details = harness.manager.beginIssue?.(approved.claimId, approved.pollToken)
  assert.deepEqual(details, { deviceName: 'Pixel', platform: 'android' })
  assert.equal(
    Object.prototype.hasOwnProperty.call(details ?? {}, 'pollToken'),
    false,
    'the poll secret must never be part of the issue details',
  )

  assert.equal(
    harness.manager.beginIssue?.(approved.claimId, approved.pollToken),
    null,
    'a second reservation must fail closed',
  )
})

test('pairing: concurrent status polls can never mint two devices (single reservation winner)', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const approved = claimApproved(harness)
  assert.notEqual(approved, null)
  if (approved === null) return

  const winners = []
  for (let index = 0; index < 25; index += 1) {
    winners.push(harness.manager.beginIssue?.(approved.claimId, approved.pollToken) ?? null)
  }
  assert.equal(winners.filter((winner) => winner !== null).length, 1, 'exactly one poll may reserve the claim')
  assert.equal(harness.manager.beginIssue?.(approved.claimId, approved.pollToken) ?? null, null)
})

test('pairing: beginIssue fails closed for unknown claims, wrong tokens, wrong states and expiry', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const approved = claimApproved(harness)
  assert.notEqual(approved, null)
  if (approved === null) return

  assert.equal(harness.manager.beginIssue?.(approved.claimId, 'wrong-poll-token'), null)
  assert.equal(harness.manager.beginIssue?.(approved.claimId, ''), null)
  assert.equal(harness.manager.beginIssue?.('unknown-claim', approved.pollToken), null)
  assert.equal(harness.manager.beginIssue?.('', approved.pollToken), null)
  assert.equal(
    harness.manager.beginIssue?.(undefined as unknown as string, undefined as unknown as string),
    null,
  )
  assert.equal(harness.manager.beginIssue?.(42 as unknown as string, 43 as unknown as string), null)

  // A denied claim can never be reserved (deny is only possible while claimed).
  const deniedCreated = harness.manager.create()
  const deniedClaim = harness.manager.claim({
    code: String(deniedCreated?.code),
    deviceName: 'x',
    platform: 'web',
  })
  assert.equal(isFailure(deniedClaim), false)
  if (!isFailure(deniedClaim)) {
    assert.equal(harness.manager.deny(deniedClaim.claimId), true)
    assert.equal(harness.manager.beginIssue?.(deniedClaim.claimId, deniedClaim.pollToken), null)
  }

  // An approved claim that idled out can never be reserved.
  const third = claimApproved(harness)
  assert.notEqual(third, null)
  if (third !== null) {
    harness.clock.now += TTL_MS + 1
    assert.equal(harness.manager.beginIssue?.(third.claimId, third.pollToken), null)
    assert.equal(harness.manager.status(third.claimId, third.pollToken), 'expired')
  }
})

test('pairing: beginIssue does not expose the claim until the desktop approved it', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const created = harness.manager.create()
  const claimed = harness.manager.claim({ code: String(created?.code), deviceName: 'x', platform: 'web' })
  assert.equal(isFailure(claimed), false)
  if (isFailure(claimed)) return

  assert.equal(harness.manager.beginIssue?.(claimed.claimId, claimed.pollToken), null)
  assert.notEqual(harness.manager.approve(claimed.claimId), null)
  assert.notEqual(harness.manager.beginIssue?.(claimed.claimId, claimed.pollToken), null)
})

test('pairing: after a reservation the claim still reports approved until consumed, then expires', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const approved = claimApproved(harness)
  assert.notEqual(approved, null)
  if (approved === null) return

  assert.notEqual(harness.manager.beginIssue?.(approved.claimId, approved.pollToken) ?? null, null)
  // The phone's winning poll still finishes its response; a second poll cannot issue.
  assert.equal(harness.manager.status(approved.claimId, approved.pollToken), 'approved')
  assert.equal(harness.manager.beginIssue?.(approved.claimId, approved.pollToken) ?? null, null)
  assert.deepEqual(harness.manager.pendingApprovals(), [], 'a reserved claim is not pending anymore')

  harness.manager.consume(approved.claimId)
  assert.equal(harness.manager.status(approved.claimId, approved.pollToken), 'expired')
})

test('pairing: approve() cannot re-open an already reserved claim', (t) => {
  const harness = makeHarness()
  t.after(() => harness.dispose())
  const approved = claimApproved(harness)
  assert.notEqual(approved, null)
  if (approved === null) return

  assert.notEqual(harness.manager.beginIssue?.(approved.claimId, approved.pollToken) ?? null, null)
  assert.equal(harness.manager.approve(approved.claimId), null, 'a reserved claim must not re-issue details')
  assert.equal(harness.manager.deny(approved.claimId), false)
})

/* ------------------------------------------------------------------------- */
/* Sanitizers                                                                */
/* ------------------------------------------------------------------------- */

test('pairing: sanitizeDeviceName strips control/bidi characters and caps length', () => {
  assert.equal(sanitizeDeviceName('  Pixel 8  '), 'Pixel 8')
  // Control characters (including newlines) are deleted, then whitespace is collapsed.
  assert.equal(sanitizeDeviceName('Pixel\n8'), 'Pixel8')
  assert.equal(sanitizeDeviceName('a\u0000b\u202ec'), 'abc')
  assert.equal(sanitizeDeviceName(''), 'Unknown device')
  assert.equal(sanitizeDeviceName(null), 'Unknown device')
  assert.equal(sanitizeDeviceName('x'.repeat(200)).length, 64)
})

test('pairing: sanitizePlatform keeps only short lowercase tokens', () => {
  assert.equal(sanitizePlatform('Android'), 'android')
  assert.equal(sanitizePlatform(' iOS '), 'ios')
  assert.equal(sanitizePlatform('some platform'), 'web')
  assert.equal(sanitizePlatform(''), 'web')
  assert.equal(sanitizePlatform(42), '42')
  assert.equal(sanitizePlatform('a'.repeat(33)), 'web')
})

test('pairing: codes are minted from 32 random bytes (defensive smoke test)', () => {
  const bytes = randomBytes(32)
  assert.equal(bytes.length, 32)
  const harness = makeHarness()
  try {
    const created = harness.manager.create()
    assert.ok(created !== null)
    assert.equal(Buffer.from(String(created?.code), 'base64url').length, 32)
  } finally {
    harness.dispose()
  }
})
