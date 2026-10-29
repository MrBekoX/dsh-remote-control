/**
 * Single active logical device lease (main §5).
 *
 * Rules encoded here:
 * - exactly one device may hold the lease; a second `activate()` is refused so
 *   the controller can answer `DEVICE_LOCKED`,
 * - re-activating the current device is a no-op refresh: multiple tabs, WS
 *   reconnects and short disconnects keep the same logical lease. There is no
 *   "disconnect" API at all — only an explicit `release()` (manual/revoke/
 *   emergency/idle/restart/security) ends a lease early,
 * - the idle clock is renewed only by `touch()` for the active device
 *   (verified phone activity); desktop polling / anonymous traffic never call it,
 * - when the idle window elapses the lease fails closed immediately
 *   (`isActive()`/`touch()` return false) and the one-shot idle handler fires
 *   exactly once. The handler must run the safe-shutdown path; it is invoked
 *   asynchronously as a microtask, its errors are logged and never crash the
 *   process, and repeated expiry cannot invoke it twice,
 * - restart rule: `restore(persistedState)` rehydrates the lease from the v2
 *   state file. A lease that already idled out while DSH was down is NOT
 *   restorable: it is marked expired and the handler fires exactly once after
 *   it is registered (so a restart after a long outage cannot silently reopen
 *   remote access),
 * - IP address / User-Agent are deliberately not part of this API and are never
 *   treated as device identity evidence.
 *
 * The lease is the logical security decision only; persistence of its raw
 * fields is the controller's job (via `raw()` + `securityClosed` state).
 */

import type {
  DeviceLease,
  LeaseRawState,
  LeaseReleaseReason,
  Logger,
  PersistedState,
} from './shared/internal.js'

const MAX_DEVICE_ID = 128
const DEVICE_ID = /^[A-Za-z0-9_-]{1,128}$/
/** Node's maximum single `setTimeout` delay; longer windows are clamped. */
const MAX_TIMER_MS = 2 ** 31 - 1

export interface DeviceLeaseOptions {
  /** Idle window after which the one-shot idle handler fires (30 min default config). */
  idleTimeoutMs: number
  log: Logger
  /** Test seam; defaults to `Date.now`. */
  now?: () => number
}

function assertIdleTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error('device lease idleTimeoutMs must be a positive integer of milliseconds')
  }
  return value
}

function validDeviceId(value: unknown): value is string {
  return typeof value === 'string' && value.length <= MAX_DEVICE_ID && DEVICE_ID.test(value)
}

function validLeaseTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export function createDeviceLease(options: DeviceLeaseOptions): DeviceLease {
  const idleTimeoutMs = assertIdleTimeout(options.idleTimeoutMs)
  const now = typeof options.now === 'function' ? options.now : Date.now
  const log = options.log

  let deviceId: string | null = null
  let startedAt: number | null = null
  let lastActivityAt: number | null = null
  /** True once the idle window elapsed; the lease is unusable until released. */
  let expired = false
  let timer: NodeJS.Timeout | null = null
  /** Bumped on every timer (re)schedule so a stale callback cannot fire. */
  let timerGeneration = 0
  let idleHandler: (() => void | Promise<void>) | null = null
  /** The one-shot handler was already invoked for the current lease period. */
  let handlerNotified = false
  /** The lease expired before a handler was registered; notify exactly once later. */
  let pendingNotification = false
  let disposed = false

  function clearTimer(): void {
    timerGeneration += 1
    if (timer !== null) {
      clearTimeout(timer)
      timer = null
    }
  }

  function invokeHandler(): void {
    const handler = idleHandler
    if (handler === null) return
    handlerNotified = true
    void Promise.resolve()
      .then(() => handler())
      .catch((error: unknown) => {
        log.warn('device lease idle handler failed', {
          message: error instanceof Error ? error.message : 'unknown',
        })
      })
  }

  /** Fire the one-shot idle notification (exactly once per lease period). */
  function notifyIdle(): void {
    if (handlerNotified) return
    if (idleHandler === null) {
      pendingNotification = true
      return
    }
    log.info('device lease idle timeout fired', { deviceId })
    invokeHandler()
  }

  function schedule(at: number): void {
    clearTimer()
    if (disposed || deviceId === null || expired) return
    const last = lastActivityAt ?? at
    const remaining = last + idleTimeoutMs - at
    const delay = Math.max(0, Math.min(remaining, MAX_TIMER_MS))
    const generation = timerGeneration
    const scheduled: NodeJS.Timeout = setTimeout(() => {
      if (disposed || generation !== timerGeneration) return
      timer = null
      onTimer()
    }, delay)
    scheduled.unref()
    timer = scheduled
  }

  function onTimer(): void {
    if (disposed || deviceId === null || expired) return
    expired = true
    log.debug('device lease idle window elapsed', { deviceId })
    notifyIdle()
  }

  function resetMemory(): void {
    clearTimer()
    deviceId = null
    startedAt = null
    lastActivityAt = null
    expired = false
    handlerNotified = false
    pendingNotification = false
    timer = null
  }

  function activeDeviceId(): string | null {
    return disposed || expired ? null : deviceId
  }

  function isActive(candidate: string): boolean {
    return validDeviceId(candidate) && !disposed && !expired && deviceId === candidate
  }

  function activate(candidate: string): boolean {
    if (!validDeviceId(candidate) || disposed || expired) return false
    const at = now()
    if (deviceId === candidate) {
      // Multi-tab / reconnect: same logical device keeps the lease. This is a
      // refresh, not a transfer.
      lastActivityAt = at
      schedule(at)
      return true
    }
    if (deviceId !== null) {
      log.warn('device lease activation refused: another device is active', { deviceId })
      return false
    }
    deviceId = candidate
    startedAt = at
    lastActivityAt = at
    expired = false
    handlerNotified = false
    pendingNotification = false
    schedule(at)
    log.info('device lease activated', { deviceId })
    return true
  }

  function touch(candidate: string): boolean {
    if (!isActive(candidate)) return false
    const at = now()
    lastActivityAt = at
    schedule(at)
    return true
  }

  function release(reason: LeaseReleaseReason): void {
    if (disposed) return
    if (deviceId !== null) log.debug('device lease released', { deviceId, reason })
    resetMemory()
  }

  function idleExpiresAt(): number | null {
    if (disposed || deviceId === null || expired || lastActivityAt === null) return null
    return lastActivityAt + idleTimeoutMs
  }

  function raw(): LeaseRawState {
    return { deviceId, startedAt, lastActivityAt }
  }

  function restore(persisted: PersistedState): void {
    resetMemory()
    if (disposed) return
    const candidateId = persisted?.activeDeviceId
    const candidateStarted = persisted?.leaseStartedAt
    const candidateActivity = persisted?.leaseLastActivityAt
    if (!validDeviceId(candidateId) || !validLeaseTime(candidateStarted) || !validLeaseTime(candidateActivity)) {
      return
    }
    const at = now()
    // Clock skew: a lease timestamp from the future is clamped to now instead
    // of granting a longer idle window than the restart allows.
    const lastActivity = Math.min(candidateActivity, at)
    const started = Math.min(candidateStarted, lastActivity)
    deviceId = candidateId
    startedAt = started
    lastActivityAt = lastActivity

    if (lastActivity + idleTimeoutMs <= at) {
      // The lease idled out while DSH was down: fail closed and fire the
      // one-shot handler once it is registered.
      expired = true
      pendingNotification = true
      log.warn('restored device lease had already idled out; closing remote access', { deviceId })
      notifyIdle()
      return
    }
    expired = false
    schedule(at)
    log.info('device lease restored', { deviceId })
  }

  function setIdleHandler(handler: () => void | Promise<void>): void {
    idleHandler = typeof handler === 'function' ? handler : null
    if (pendingNotification && !handlerNotified && idleHandler !== null) {
      pendingNotification = false
      invokeHandler()
    }
  }

  function dispose(): void {
    disposed = true
    resetMemory()
    idleHandler = null
  }

  return {
    raw,
    restore,
    activeDeviceId,
    isActive,
    activate,
    touch,
    release,
    idleExpiresAt,
    setIdleHandler,
    dispose,
  }
}
