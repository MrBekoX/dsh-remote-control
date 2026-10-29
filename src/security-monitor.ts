/**
 * Shared authentication-failure accounting (main §6).
 *
 * All failed authentication paths (pairing secret, polling secret, access
 * token, refresh token, WS verification) must call `blocked()` first, then
 * `recordFailure(ip, path)` exactly once for the request on failure; a blocked
 * request is rejected once and is NOT counted again and never extends the ban.
 * Successful authentication calls `recordSuccess(ip)` (clears that client's
 * sliding failure window; it cannot lift an active ban).
 *
 * Policy:
 * - `failuresBeforeBan` failures inside `failureWindowMs` are tolerated; the
 *   NEXT failure from the same client triggers a `temporaryBanMs` block
 *   (default: 5 failures in 60 s → the 6th failure blocks the client for 5 min),
 * - `circuitBreakerFailures` total failures inside one manually started
 *   remote-access period open the one-shot circuit breaker: the handler runs
 *   exactly once and remote access must be closed (no auto re-open). An
 *   explicit user re-enable calls `beginSession()`, which starts a fresh
 *   manually started period (fresh counters and a re-armed breaker),
 * - `endSession()` stops period accounting but never clears the breaker state,
 * - memory is bounded: at most `maxTrackedClients` client keys are tracked; the
 *   oldest entry is evicted under pressure (bans are short-lived by design),
 * - malformed client keys are normalized to `unknown`; every method is
 *   total and never throws.
 *
 * The 10-failure breaker is a deliberate DoS trade-off: an attacker who can
 * fail 10 authentications can force a safe shutdown; that is preferred over an
 * unbounded retry surface and is documented in SECURITY.md by the docs lane.
 * The plugin never kills the DSH main process.
 */

import { RC_SECURITY_DEFAULTS } from './shared/protocol.js'
import type {
  FailureRecordResult,
  Logger,
  SecurityMonitor,
} from './shared/internal.js'

const DEFAULT_MAX_TRACKED_CLIENTS = 1_024
const MAX_CLIENT_KEY_CHARS = 128
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f]/g

export interface SecurityMonitorOptions {
  /** Sliding failure window for the per-client temporary ban. */
  failureWindowMs: number
  /** Failures tolerated inside the window before the next one bans the client. */
  failuresBeforeBan: number
  /** How long a banned client stays blocked. */
  temporaryBanMs: number
  /** Total failures in one manually started session that open the circuit breaker. */
  circuitBreakerFailures: number
  log: Logger
  /** Test seam; defaults to `Date.now`. */
  now?: () => number
  /** Upper bound on tracked client keys (bounded memory). */
  maxTrackedClients?: number
}

function positiveInt(value: unknown, fallback: number, min: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) return fallback
  return value
}

interface ClientWindow {
  /** Timestamps of counted failures inside the sliding window. */
  times: number[]
  /** Epoch ms until which the client is temporarily blocked (0 = not blocked). */
  blockedUntil: number
}

export function createSecurityMonitor(options: SecurityMonitorOptions): SecurityMonitor {
  const failureWindowMs = positiveInt(
    options.failureWindowMs,
    RC_SECURITY_DEFAULTS.failureWindowMs,
    1,
  )
  const failuresBeforeBan = positiveInt(
    options.failuresBeforeBan,
    RC_SECURITY_DEFAULTS.failuresBeforeBan,
    1,
  )
  const temporaryBanMs = positiveInt(
    options.temporaryBanMs,
    RC_SECURITY_DEFAULTS.temporaryBanMs,
    1,
  )
  const circuitBreakerFailures = positiveInt(
    options.circuitBreakerFailures,
    RC_SECURITY_DEFAULTS.circuitBreakerFailures,
    2,
  )
  const maxTrackedClients = positiveInt(
    options.maxTrackedClients,
    DEFAULT_MAX_TRACKED_CLIENTS,
    1,
  )
  const now = typeof options.now === 'function' ? options.now : Date.now
  const log = options.log

  const clients = new Map<string, ClientWindow>()
  let sessionActive = false
  let totalFailures = 0
  let breakerOpen = false
  let breakerHandler: (() => void | Promise<void>) | null = null
  let breakerNotified = false
  let disposed = false

  function normalizeClient(value: unknown): string {
    if (typeof value !== 'string') return 'unknown'
    const trimmed = value.replace(UNSAFE_CHARS, '').trim()
    if (trimmed === '') return 'unknown'
    return trimmed.slice(0, MAX_CLIENT_KEY_CHARS)
  }

  function prune(at: number): void {
    for (const [key, window] of clients) {
      if (window.blockedUntil !== 0 && window.blockedUntil <= at) window.blockedUntil = 0
      if (window.times.length > 0) {
        window.times = window.times.filter((time) => time > at - failureWindowMs)
      }
      if (window.blockedUntil === 0 && window.times.length === 0) clients.delete(key)
    }
  }

  /** Bounded-memory insertion: prune expired state, then evict the oldest key. */
  function ensureCapacity(at: number): void {
    if (clients.size < maxTrackedClients) return
    prune(at)
    while (clients.size >= maxTrackedClients) {
      const oldest = clients.keys().next()
      if (oldest.done) break
      clients.delete(oldest.value)
    }
  }

  function fireBreaker(): void {
    if (breakerNotified) return
    const handler = breakerHandler
    if (handler === null) return
    breakerNotified = true
    void Promise.resolve()
      .then(() => handler())
      .catch((error: unknown) => {
        log.warn('security circuit breaker handler failed', {
          message: error instanceof Error ? error.message : 'unknown',
        })
      })
  }

  function emptyResult(): FailureRecordResult {
    return { banned: false, retryAfterMs: 0, circuitBreakerOpen: false, totalFailures }
  }

  function blocked(client: unknown): { blocked: boolean; retryAfterMs: number } {
    if (disposed) return { blocked: false, retryAfterMs: 0 }
    const window = clients.get(normalizeClient(client))
    if (window === undefined) return { blocked: false, retryAfterMs: 0 }
    const at = now()
    if (window.blockedUntil > at) {
      return { blocked: true, retryAfterMs: window.blockedUntil - at }
    }
    if (window.blockedUntil !== 0) window.blockedUntil = 0
    return { blocked: false, retryAfterMs: 0 }
  }

  function recordFailure(client: unknown, path: string): FailureRecordResult {
    if (disposed) return emptyResult()
    const at = now()
    const key = normalizeClient(client)
    const failurePath = typeof path === 'string' ? path.replace(UNSAFE_CHARS, '').slice(0, 32) : 'unknown'

    if (breakerOpen) {
      // One-shot: after the safe shutdown nothing else is counted or fired.
      return { banned: false, retryAfterMs: 0, circuitBreakerOpen: false, totalFailures }
    }

    let window = clients.get(key)
    if (window !== undefined && window.blockedUntil > at) {
      // Blocked repeats are rejected once, not counted, and never extend the ban.
      const retryAfterMs = window.blockedUntil - at
      log.debug('blocked authentication attempt rejected', { path: failurePath, retryAfterMs })
      return { banned: true, retryAfterMs, circuitBreakerOpen: false, totalFailures }
    }
    if (window === undefined) {
      ensureCapacity(at)
      window = { times: [], blockedUntil: 0 }
      clients.set(key, window)
    }

    window.times = window.times.filter((time) => time > at - failureWindowMs)
    window.times.push(at)
    // Keep only what the threshold needs (bounded per-client memory).
    if (window.times.length > failuresBeforeBan + 2) {
      window.times.splice(0, window.times.length - (failuresBeforeBan + 2))
    }

    let banned = false
    if (window.times.length > failuresBeforeBan) {
      window.blockedUntil = at + temporaryBanMs
      banned = true
    }

    let circuitBreakerOpen = false
    if (sessionActive) {
      totalFailures += 1
      if (totalFailures >= circuitBreakerFailures) {
        breakerOpen = true
        circuitBreakerOpen = true
      }
    }

    if (circuitBreakerOpen) {
      log.warn('security circuit breaker opened: closing remote access', {
        totalFailures,
        threshold: circuitBreakerFailures,
      })
      fireBreaker()
    } else if (banned) {
      log.warn('authentication failure triggered a temporary client ban', {
        path: failurePath,
        retryAfterMs: temporaryBanMs,
        failures: window.times.length,
      })
    } else {
      log.debug('authentication failure recorded', {
        path: failurePath,
        failures: window.times.length,
        totalFailures,
      })
    }

    return {
      banned,
      retryAfterMs: banned ? temporaryBanMs : 0,
      circuitBreakerOpen,
      totalFailures,
    }
  }

  function recordSuccess(client: unknown): void {
    if (disposed) return
    const key = normalizeClient(client)
    const window = clients.get(key)
    if (window === undefined) return
    const at = now()
    // A valid authentication clears the sliding failure window for that client.
    window.times = []
    if (window.blockedUntil <= at) clients.delete(key)
  }

  function beginSession(): void {
    if (disposed) return
    sessionActive = true
    totalFailures = 0
    clients.clear()
    breakerOpen = false
    breakerNotified = false
    log.info('security failure accounting session started')
  }

  function endSession(): void {
    if (disposed) return
    sessionActive = false
    log.info('security failure accounting session stopped', { totalFailures })
  }

  function isCircuitBreakerOpen(): boolean {
    return !disposed && breakerOpen
  }

  function failureCount(): number {
    return totalFailures
  }

  function blockedCount(): number {
    if (disposed) return 0
    const at = now()
    prune(at)
    let count = 0
    for (const window of clients.values()) {
      if (window.blockedUntil > at) count += 1
    }
    return count
  }

  function setCircuitBreakerHandler(handler: () => void | Promise<void>): void {
    if (disposed) return
    breakerHandler = typeof handler === 'function' ? handler : null
    if (breakerOpen && !breakerNotified && breakerHandler !== null) fireBreaker()
  }

  function dispose(): void {
    disposed = true
    sessionActive = false
    breakerOpen = false
    breakerNotified = true
    breakerHandler = null
    clients.clear()
  }

  return {
    blocked,
    recordFailure,
    recordSuccess,
    beginSession,
    endSession,
    isCircuitBreakerOpen,
    failureCount,
    blockedCount,
    setCircuitBreakerHandler,
    dispose,
  }
}
