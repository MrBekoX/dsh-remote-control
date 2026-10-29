/**
 * Shared authentication-failure accounting (main §6):
 * - one shared counter for pair/poll/access/refresh/ws verification failures,
 * - 6th failure from one client inside the 60 s window bans it for 5 minutes
 *   (config `failuresBeforeBan: 5`), independently per client,
 * - a request rejected by an active temporary ban is NOT counted as a new
 *   failure and never extends the ban,
 * - 10 total failures in one manually started remote-access period open the
 *   circuit breaker exactly once (one-shot safe shutdown; no auto re-open),
 * - blocked/successful paths, bounded memory, malformed input never throws.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityMonitor } from '../src/security-monitor.js';
const WINDOW_MS = 60_000;
const BAN_MS = 5 * 60_000;
const FAILURES_BEFORE_BAN = 5;
const BREAKER_FAILURES = 10;
const FIXED_NOW = 1_700_000_000_000;
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
function makeMonitor(options = {}) {
    const clock = { now: FIXED_NOW };
    const monitor = createSecurityMonitor({
        failureWindowMs: WINDOW_MS,
        failuresBeforeBan: FAILURES_BEFORE_BAN,
        temporaryBanMs: BAN_MS,
        circuitBreakerFailures: BREAKER_FAILURES,
        log: silentLogger(),
        now: () => clock.now,
        ...options,
    });
    return { monitor, clock };
}
/** Let the one-shot async circuit-breaker callback run. */
const drain = () => new Promise((resolve) => setImmediate(resolve));
function fail(monitor, ip, times) {
    const results = [];
    for (let index = 0; index < times; index += 1)
        results.push(monitor.recordFailure(ip, 'access'));
    return results;
}
/* ------------------------------------------------------------------------- */
/* Per-client temporary ban (exact threshold)                                */
/* ------------------------------------------------------------------------- */
test('security-monitor: the 6th failure inside the window bans the client for 5 minutes', (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    const ip = '203.0.113.7';
    for (let index = 1; index <= FAILURES_BEFORE_BAN; index += 1) {
        const result = monitor.recordFailure(ip, 'access');
        assert.equal(result.banned, false, `failure ${index} must not ban yet`);
        assert.equal(result.retryAfterMs, 0);
    }
    assert.deepEqual(monitor.blocked(ip), { blocked: false, retryAfterMs: 0 });
    const sixth = monitor.recordFailure(ip, 'access');
    assert.equal(sixth.banned, true, 'the 6th failure must trigger the temporary ban');
    assert.equal(sixth.retryAfterMs, BAN_MS);
    assert.equal(sixth.circuitBreakerOpen, false);
    const blocked = monitor.blocked(ip);
    assert.equal(blocked.blocked, true);
    assert.ok(blocked.retryAfterMs > 0 && blocked.retryAfterMs <= BAN_MS);
});
test('security-monitor: per-client bans expire and never affect other clients', (t) => {
    const { monitor, clock } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    fail(monitor, '198.51.100.1', 6);
    assert.equal(monitor.blocked('198.51.100.1').blocked, true);
    assert.equal(monitor.blocked('198.51.100.2').blocked, false, 'another client is unaffected');
    clock.now += BAN_MS;
    assert.equal(monitor.blocked('198.51.100.1').blocked, false, 'ban expires after temporaryBanMs');
    assert.equal(monitor.recordFailure('198.51.100.1', 'access').banned, false, 'the counter starts fresh');
});
test('security-monitor: the failure window slides', (t) => {
    // Keep the session breaker out of the way so only the sliding window is tested.
    const { monitor, clock } = makeMonitor({ circuitBreakerFailures: 1_000 });
    t.after(() => monitor.dispose());
    monitor.beginSession();
    const ip = '203.0.113.9';
    fail(monitor, ip, FAILURES_BEFORE_BAN);
    clock.now += WINDOW_MS + 1;
    const afterWindow = monitor.recordFailure(ip, 'access');
    assert.equal(afterWindow.banned, false, 'failures older than the window are pruned');
    const rest = fail(monitor, ip, FAILURES_BEFORE_BAN - 1);
    assert.equal(rest.at(-1)?.banned, false, 'the new window now holds exactly 5 failures');
    assert.equal(monitor.recordFailure(ip, 'access').banned, true);
});
/* ------------------------------------------------------------------------- */
/* Blocked requests are rejected once, never counted, never extend the ban    */
/* ------------------------------------------------------------------------- */
test('security-monitor: a blocked repeat is not counted and does not extend the ban', (t) => {
    const { monitor, clock } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    const ip = '203.0.113.20';
    fail(monitor, ip, 6);
    const failuresAtBan = monitor.failureCount();
    const initialBlocked = monitor.blocked(ip).retryAfterMs;
    clock.now += 100_000;
    const priorBlocked = monitor.blocked(ip).retryAfterMs;
    assert.ok(priorBlocked <= initialBlocked);
    const repeat = monitor.recordFailure(ip, 'access');
    assert.equal(repeat.banned, true, 'the request is rejected as blocked');
    assert.ok(repeat.retryAfterMs > 0, 'caller gets the remaining retry hint');
    assert.ok(repeat.retryAfterMs < BAN_MS, 'remaining time, not a fresh ban window');
    assert.equal(monitor.failureCount(), failuresAtBan, 'blocked repeats must not be counted as new failures');
    clock.now += BAN_MS;
    assert.equal(monitor.blocked(ip).blocked, false, 'repeated blocked calls must not extend the ban');
});
test('security-monitor: blocked() is a pure read (polling it never mutates accounting)', (t) => {
    const { monitor, clock } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    fail(monitor, '203.0.113.30', 6);
    const before = monitor.failureCount();
    for (let index = 0; index < 50; index += 1)
        monitor.blocked('203.0.113.30');
    assert.equal(monitor.failureCount(), before);
    clock.now += 1;
    assert.equal(monitor.blocked('203.0.113.30').blocked, true);
});
/* ------------------------------------------------------------------------- */
/* Circuit breaker (one-shot)                                                */
/* ------------------------------------------------------------------------- */
test('security-monitor: the 10th session failure opens the breaker exactly once', async (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    let handlerCalls = 0;
    monitor.setCircuitBreakerHandler(() => {
        handlerCalls += 1;
    });
    monitor.beginSession();
    const results = [];
    // Distinct clients so the per-IP ban never masks the total-failure count.
    for (let index = 0; index < BREAKER_FAILURES; index += 1) {
        results.push(monitor.recordFailure(`10.0.0.${index}`, 'access'));
    }
    assert.equal(results.slice(0, -1).every((result) => result.circuitBreakerOpen === false), true);
    assert.equal(results.at(-1)?.circuitBreakerOpen, true, 'the 10th failure crosses the threshold');
    assert.equal(monitor.isCircuitBreakerOpen(), true);
    assert.equal(monitor.failureCount(), BREAKER_FAILURES);
    await drain();
    assert.equal(handlerCalls, 1, 'the one-shot shutdown callback must fire');
    await drain();
    assert.equal(handlerCalls, 1, 'and exactly once');
    const afterOpen = monitor.recordFailure('10.0.0.250', 'access');
    assert.equal(afterOpen.circuitBreakerOpen, false, 'a one-shot breaker does not re-fire');
    assert.equal(afterOpen.totalFailures, BREAKER_FAILURES);
    await drain();
    assert.equal(handlerCalls, 1);
});
test('security-monitor: an open breaker never auto-reopens but beginSession() is fresh', async (t) => {
    const { monitor, clock } = makeMonitor();
    t.after(() => monitor.dispose());
    let handlerCalls = 0;
    monitor.setCircuitBreakerHandler(() => {
        handlerCalls += 1;
    });
    monitor.beginSession();
    for (let index = 0; index < BREAKER_FAILURES; index += 1) {
        monitor.recordFailure(`192.0.2.${index}`, 'access');
    }
    await drain();
    assert.equal(handlerCalls, 1);
    clock.now += 24 * 3_600_000;
    assert.equal(monitor.isCircuitBreakerOpen(), true, 'time alone must never reopen remote access');
    // Explicit user re-enable starts a fresh manually started period.
    monitor.beginSession();
    assert.equal(monitor.isCircuitBreakerOpen(), false);
    assert.equal(monitor.failureCount(), 0);
    assert.equal(monitor.blockedCount(), 0, 'the new session clears stale client bans');
    for (let index = 0; index < BREAKER_FAILURES; index += 1) {
        monitor.recordFailure(`198.18.0.${index}`, 'access');
    }
    await drain();
    assert.equal(handlerCalls, 2, 'a new session may fire the one-shot breaker again');
});
test('security-monitor: a handler registered after the breach receives the callback once', async (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    for (let index = 0; index < BREAKER_FAILURES; index += 1) {
        monitor.recordFailure(`172.16.0.${index}`, 'access');
    }
    await drain();
    let calls = 0;
    monitor.setCircuitBreakerHandler(() => {
        calls += 1;
    });
    await drain();
    assert.equal(calls, 1);
    monitor.setCircuitBreakerHandler(() => {
        calls += 100;
    });
    await drain();
    assert.equal(calls, 1, 'replacing the handler must not replay the breach');
});
test('security-monitor: a throwing breaker handler is contained', async (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    let calls = 0;
    monitor.setCircuitBreakerHandler(() => {
        calls += 1;
        throw new Error('shutdown exploded');
    });
    monitor.beginSession();
    for (let index = 0; index < BREAKER_FAILURES; index += 1) {
        monitor.recordFailure(`100.64.0.${index}`, 'access');
    }
    await drain();
    assert.equal(calls, 1);
    assert.equal(monitor.isCircuitBreakerOpen(), true);
});
/* ------------------------------------------------------------------------- */
/* Session lifecycle / success / accounting symmetry                         */
/* ------------------------------------------------------------------------- */
test('security-monitor: endSession() stops session accounting but keeps the open breaker', (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    fail(monitor, '203.0.113.40', 3);
    monitor.endSession();
    for (let index = 0; index < BREAKER_FAILURES; index += 1) {
        monitor.recordFailure(`100.64.1.${index}`, 'access');
    }
    assert.equal(monitor.isCircuitBreakerOpen(), false, 'no manual period is active');
    assert.equal(monitor.failureCount(), 3, 'the last session count is preserved for the panel');
});
test('security-monitor: recordSuccess clears the client failure window', (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    const ip = '203.0.113.50';
    fail(monitor, ip, FAILURES_BEFORE_BAN);
    monitor.recordSuccess(ip);
    assert.equal(monitor.recordFailure(ip, 'access').banned, false, 'success resets the sliding window');
    assert.equal(monitor.failureCount(), 6, 'success does not rewrite the session attack total');
});
test('security-monitor: recordSuccess cannot lift an active ban', (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    const ip = '203.0.113.51';
    fail(monitor, ip, 6);
    monitor.recordSuccess(ip);
    assert.equal(monitor.blocked(ip).blocked, true);
});
/* ------------------------------------------------------------------------- */
/* Bounded memory, defaults, robustness                                      */
/* ------------------------------------------------------------------------- */
test('security-monitor: tracked client memory is bounded (oldest entries evicted)', (t) => {
    const { monitor } = makeMonitor({ circuitBreakerFailures: 1_000, maxTrackedClients: 2 });
    t.after(() => monitor.dispose());
    monitor.beginSession();
    for (let index = 0; index < 10; index += 1) {
        fail(monitor, `10.10.0.${index}`, 6);
    }
    assert.equal(monitor.blocked('10.10.0.9').blocked, true, 'the newest client is tracked/blocked');
    assert.equal(monitor.blocked('10.10.0.0').blocked, false, 'the oldest client entry was evicted');
    assert.ok(monitor.blockedCount() <= 2, 'blocked-client count stays bounded');
});
test('security-monitor: malformed client keys and paths never throw', (t) => {
    const { monitor } = makeMonitor();
    t.after(() => monitor.dispose());
    monitor.beginSession();
    const hostileKeys = [null, undefined, 42, {}, [], '', 'x'.repeat(10_000), '1.2.3.4\ninjected'];
    for (const key of hostileKeys) {
        const result = monitor.recordFailure(key, undefined);
        assert.equal(typeof result.totalFailures, 'number');
        assert.equal(typeof result.banned, 'boolean');
        const blocked = monitor.blocked(key);
        assert.equal(typeof blocked.blocked, 'boolean');
        assert.doesNotThrow(() => monitor.recordSuccess(key));
    }
});
test('security-monitor: invalid options fall back to safe effective limits', (t) => {
    const monitor = createSecurityMonitor({
        failureWindowMs: Number.NaN,
        failuresBeforeBan: 0,
        temporaryBanMs: -1,
        circuitBreakerFailures: 1,
        log: silentLogger(),
    });
    t.after(() => monitor.dispose());
    monitor.beginSession();
    // The 6th failure still bans with the documented default threshold and window.
    const results = fail(monitor, '203.0.113.60', 6);
    assert.equal(results.at(-1)?.banned, true);
    assert.equal(monitor.isCircuitBreakerOpen(), false, 'invalid breaker threshold falls back to the default');
});
test('security-monitor: dispose() deactivates accounting and the breaker callback', async (t) => {
    const { monitor } = makeMonitor();
    monitor.beginSession();
    let calls = 0;
    monitor.setCircuitBreakerHandler(() => {
        calls += 1;
    });
    monitor.dispose();
    const result = monitor.recordFailure('203.0.113.70', 'access');
    assert.equal(result.totalFailures, 0);
    assert.equal(monitor.blocked('203.0.113.70').blocked, false);
    assert.equal(monitor.isCircuitBreakerOpen(), false);
    monitor.beginSession();
    await drain();
    assert.equal(calls, 0);
});
