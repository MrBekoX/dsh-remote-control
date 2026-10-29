/**
 * Single active-device lease (main §5):
 * - one logical device at a time; re-activating the same device (multi-tab /
 *   reconnect) is a no-op refresh, a different device is refused,
 * - a short disconnect never releases/transfers the lease (no implicit release),
 * - the idle clock is renewed only by verified activity for the active device,
 * - the one-shot idle handler fires exactly once and an idle-expired lease is
 *   immediately unusable (fail closed), even after a restart restore,
 * - dispose() is silent; invalid/legacy persisted state never activates.
 *
 * IP / User-Agent are deliberately not part of this API: they are never device
 * identity evidence.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceLease } from '../src/device-lease.js';
const IDLE_MS = 60_000;
const FIXED_NOW = 1_700_000_000_000;
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
function makeLease(options = {}) {
    const clock = { now: FIXED_NOW };
    const lease = createDeviceLease({
        idleTimeoutMs: IDLE_MS,
        log: silentLogger(),
        now: () => clock.now,
        ...options,
    });
    return { lease, clock };
}
function state(overrides = {}) {
    return {
        v: 2,
        lastEnabled: true,
        updatedAt: '2026-01-01T00:00:00.000Z',
        revocationEpoch: 0,
        securityClosed: false,
        securityClosedReason: null,
        activeDeviceId: null,
        leaseStartedAt: null,
        leaseLastActivityAt: null,
        ...overrides,
    };
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/* ------------------------------------------------------------------------- */
/* Activation                                                               */
/* ------------------------------------------------------------------------- */
test('device-lease: starts empty and activates one device', (t) => {
    const { lease, clock } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activeDeviceId(), null);
    assert.equal(lease.isActive('dev-1'), false);
    assert.deepEqual(lease.raw(), { deviceId: null, startedAt: null, lastActivityAt: null });
    assert.equal(lease.idleExpiresAt(), null);
    assert.equal(lease.activate('dev-1'), true);
    assert.equal(lease.activeDeviceId(), 'dev-1');
    assert.equal(lease.isActive('dev-1'), true);
    assert.equal(lease.isActive('dev-2'), false);
    assert.deepEqual(lease.raw(), {
        deviceId: 'dev-1',
        startedAt: FIXED_NOW,
        lastActivityAt: FIXED_NOW,
    });
    assert.equal(lease.idleExpiresAt(), FIXED_NOW + IDLE_MS);
    assert.equal(clock.now, FIXED_NOW);
});
test('device-lease: a second device is refused while the first is active', (t) => {
    const { lease } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activate('dev-1'), true);
    assert.equal(lease.activate('dev-2'), false, 'single active-device lock');
    assert.equal(lease.activeDeviceId(), 'dev-1');
});
test('device-lease: re-activating the same device keeps the lease (multi-tab/reconnect)', (t) => {
    const { lease, clock } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activate('dev-1'), true);
    const startedAt = lease.raw().startedAt;
    clock.now += 5_000;
    assert.equal(lease.activate('dev-1'), true, 'same device re-activation must succeed');
    assert.equal(lease.activeDeviceId(), 'dev-1');
    assert.equal(lease.raw().startedAt, startedAt, 'the lease start time does not move');
    assert.equal(lease.raw().lastActivityAt, FIXED_NOW + 5_000);
    assert.equal(lease.idleExpiresAt(), FIXED_NOW + 5_000 + IDLE_MS);
});
test('device-lease: touch renews the idle clock only for the active device', (t) => {
    const { lease, clock } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activate('dev-1'), true);
    clock.now += 10_000;
    assert.equal(lease.touch('dev-1'), true);
    assert.equal(lease.idleExpiresAt(), FIXED_NOW + 10_000 + IDLE_MS);
    clock.now += 10_000;
    assert.equal(lease.touch('dev-2'), false, 'a non-active device cannot renew the idle clock');
    assert.equal(lease.idleExpiresAt(), FIXED_NOW + 10_000 + IDLE_MS);
});
test('device-lease: invalid device ids are refused without throwing', (t) => {
    const { lease } = makeLease();
    t.after(() => lease.dispose());
    for (const candidate of ['', 'bad id!', 'x'.repeat(200), null, undefined, 42]) {
        assert.equal(lease.activate(candidate), false, `must refuse ${String(candidate)}`);
        assert.equal(lease.touch(candidate), false);
        assert.equal(lease.isActive(candidate), false);
    }
    assert.equal(lease.activeDeviceId(), null);
});
test('device-lease: invalid idle timeout is rejected at construction', () => {
    for (const idleTimeoutMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1.5]) {
        assert.throws(() => createDeviceLease({ idleTimeoutMs, log: silentLogger() }), /idle/i);
    }
});
/* ------------------------------------------------------------------------- */
/* Release                                                                   */
/* ------------------------------------------------------------------------- */
test('device-lease: release is idempotent and lets the next device take over', (t) => {
    const { lease, clock } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activate('dev-1'), true);
    clock.now += 5_000;
    lease.release('manual');
    assert.equal(lease.activeDeviceId(), null);
    assert.equal(lease.isActive('dev-1'), false);
    assert.equal(lease.idleExpiresAt(), null);
    lease.release('manual');
    lease.release('revoke');
    clock.now += 1_000;
    assert.equal(lease.activate('dev-2'), true, 'after a release another device may activate');
    assert.equal(lease.raw().startedAt, FIXED_NOW + 6_000);
});
/* ------------------------------------------------------------------------- */
/* Idle timeout (real timers, short window)                                  */
/* ------------------------------------------------------------------------- */
test('device-lease: the idle handler fires exactly once and the lease fails closed', async (t) => {
    const calls = [];
    const { lease } = makeLease({ idleTimeoutMs: 25 });
    t.after(() => lease.dispose());
    lease.setIdleHandler(() => {
        calls.push(1);
    });
    assert.equal(lease.activate('dev-1'), true);
    assert.equal(lease.idleExpiresAt() !== null, true);
    await sleep(90);
    assert.equal(calls.length, 1, 'idle handler must fire exactly once');
    assert.equal(lease.isActive('dev-1'), false, 'an idle-expired lease is no longer usable');
    assert.equal(lease.idleExpiresAt(), null);
    assert.equal(lease.touch('dev-1'), false, 'an idle-expired lease cannot be renewed by activity');
    await sleep(80);
    assert.equal(calls.length, 1, 'the idle handler must not repeat');
});
test('device-lease: release before the idle deadline cancels the handler', async (t) => {
    const calls = [];
    const { lease } = makeLease({ idleTimeoutMs: 25 });
    t.after(() => lease.dispose());
    lease.setIdleHandler(() => {
        calls.push(1);
    });
    lease.activate('dev-1');
    lease.release('manual');
    await sleep(80);
    assert.deepEqual(calls, [], 'a released lease must not trigger the idle handler');
});
test('device-lease: an idle-expired lease must be released before a new activation', async (t) => {
    const { lease } = makeLease({ idleTimeoutMs: 20 });
    t.after(() => lease.dispose());
    lease.setIdleHandler(() => undefined);
    lease.activate('dev-1');
    await sleep(70);
    assert.equal(lease.activate('dev-2'), false, 'an expired lease must not silently transfer');
    lease.release('idle');
    assert.equal(lease.activate('dev-2'), true);
});
test('device-lease: a throwing idle handler is contained (and still fires once)', async (t) => {
    const calls = [];
    const { lease } = makeLease({ idleTimeoutMs: 20 });
    t.after(() => lease.dispose());
    lease.setIdleHandler(() => {
        calls.push(1);
        throw new Error('handler exploded');
    });
    lease.activate('dev-1');
    await sleep(70);
    assert.equal(calls.length, 1);
    assert.equal(lease.isActive('dev-1'), false);
});
test('device-lease: dispose clears the lease and never fires the idle handler', async (t) => {
    const calls = [];
    const { lease } = makeLease({ idleTimeoutMs: 20 });
    lease.setIdleHandler(() => {
        calls.push(1);
    });
    lease.activate('dev-1');
    lease.dispose();
    await sleep(70);
    assert.deepEqual(calls, []);
    assert.equal(lease.activeDeviceId(), null);
    assert.equal(lease.activate('dev-2'), false);
});
/* ------------------------------------------------------------------------- */
/* Restart / restore rules                                                   */
/* ------------------------------------------------------------------------- */
test('device-lease: restore() rehydrates a live lease and keeps its idle deadline', (t) => {
    const { lease, clock } = makeLease();
    t.after(() => lease.dispose());
    const startedAt = FIXED_NOW - 120_000;
    const lastActivityAt = FIXED_NOW - 10_000;
    lease.restore(state({ activeDeviceId: 'dev-9', leaseStartedAt: startedAt, leaseLastActivityAt: lastActivityAt }));
    assert.equal(lease.activeDeviceId(), 'dev-9');
    assert.equal(lease.isActive('dev-9'), true);
    assert.deepEqual(lease.raw(), { deviceId: 'dev-9', startedAt, lastActivityAt });
    assert.equal(lease.idleExpiresAt(), lastActivityAt + IDLE_MS);
    assert.equal(clock.now, FIXED_NOW);
});
test('device-lease: restoring an already idle-expired lease fires the handler once and fails closed', async (t) => {
    const calls = [];
    const { lease } = makeLease({ idleTimeoutMs: 30_000 });
    t.after(() => lease.dispose());
    const stale = FIXED_NOW - 120_000;
    lease.restore(state({ activeDeviceId: 'dev-9', leaseStartedAt: stale, leaseLastActivityAt: stale }));
    assert.equal(lease.isActive('dev-9'), false, 'a stale restored lease is immediately unusable');
    assert.equal(lease.idleExpiresAt(), null);
    lease.setIdleHandler(() => {
        calls.push(1);
    });
    await sleep(10);
    assert.equal(calls.length, 1, 'the stale-lease shutdown must fire exactly once');
    lease.setIdleHandler(() => {
        calls.push(2);
    });
    await sleep(10);
    assert.equal(calls.length, 1);
});
test('device-lease: a future lastActivityAt from clock skew is clamped to now', (t) => {
    const { lease } = makeLease();
    t.after(() => lease.dispose());
    lease.restore(state({
        activeDeviceId: 'dev-9',
        leaseStartedAt: FIXED_NOW + 60_000,
        leaseLastActivityAt: FIXED_NOW + 60_000,
    }));
    assert.equal(lease.isActive('dev-9'), true);
    assert.equal(lease.raw().lastActivityAt, FIXED_NOW);
    assert.equal(lease.idleExpiresAt(), FIXED_NOW + IDLE_MS);
});
test('device-lease: v1 state and malformed lease fields restore to no lease', (t) => {
    const { lease } = makeLease();
    t.after(() => lease.dispose());
    lease.restore({ v: 1, lastEnabled: true, updatedAt: '2026-01-01T00:00:00.000Z' });
    assert.equal(lease.activeDeviceId(), null);
    const malformed = [
        { activeDeviceId: 'bad id!' },
        { activeDeviceId: 'dev-1', leaseStartedAt: null, leaseLastActivityAt: null },
        { activeDeviceId: 'dev-1', leaseStartedAt: -1, leaseLastActivityAt: -1 },
        { activeDeviceId: 'dev-1', leaseStartedAt: FIXED_NOW, leaseLastActivityAt: Number.NaN },
        { activeDeviceId: 42, leaseStartedAt: FIXED_NOW, leaseLastActivityAt: FIXED_NOW },
    ];
    for (const fields of malformed) {
        lease.restore(state(fields));
        assert.equal(lease.activeDeviceId(), null, `malformed state ${JSON.stringify(fields)} must not activate`);
        assert.equal(lease.isActive('dev-1'), false);
    }
});
test('device-lease: restore() replaces any previous in-memory lease', (t) => {
    const { lease } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activate('dev-1'), true);
    lease.restore(state());
    assert.equal(lease.activeDeviceId(), null);
});
test('device-lease: a mere disconnect or reconnect never releases/transfers the lease', (t) => {
    const { lease, clock } = makeLease();
    t.after(() => lease.dispose());
    assert.equal(lease.activate('dev-1'), true);
    // A disconnect is not an API call: sockets/tabs disappear but the logical
    // device lease is untouched (only explicit release or the idle clock ends it).
    clock.now += 5 * 60_000;
    assert.equal(lease.isActive('dev-1'), true, 'a short disconnect must not transfer the lock');
    assert.equal(lease.activate('dev-2'), false, 'another device cannot grab a disconnected lease');
    // Reconnect / a second tab of the same device re-activates the same logical lease.
    assert.equal(lease.activate('dev-1'), true);
    assert.equal(lease.raw().deviceId, 'dev-1');
    assert.equal(lease.isActive('dev-2'), false);
    // Only verified activity for the active device renews the idle clock; the
    // disconnect itself is not activity.
    clock.now += 5 * 60_000;
    assert.equal(lease.touch('dev-2'), false);
    assert.equal(lease.touch('dev-1'), true);
    assert.equal(lease.idleExpiresAt(), clock.now + IDLE_MS);
});
