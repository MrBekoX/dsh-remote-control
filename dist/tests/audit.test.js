/**
 * Expanded audit ring (main §8):
 * - monotonic ids and timestamps, bounded capacity, snapshot isolation,
 * - metadata sanitization for user-agent / IP / detail / device label
 *   (bounded length, no control characters, ANSI escapes or newline injection),
 * - desktop audit view projection never carries sensitive material.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuditRing, sanitizeAuditIp, sanitizeAuditText, toAuditEntryView, } from '../src/audit.js';
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;
const BASE = { deviceId: null, kind: 'pair', detail: 'pair.claim' };
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
void silentLogger;
/* ------------------------------------------------------------------------- */
/* Ring mechanics                                                           */
/* ------------------------------------------------------------------------- */
test('audit: push assigns a monotonic id and the injected clock time', () => {
    let now = 1_000;
    const ring = createAuditRing(10, { now: () => now });
    ring.push(BASE);
    now = 2_000;
    ring.push({ ...BASE, kind: 'approve', detail: 'approve' });
    const [first, second] = ring.snapshot();
    assert.equal(first?.id, 1);
    assert.equal(second?.id, 2);
    assert.equal(first?.time, 1_000);
    assert.equal(second?.time, 2_000);
    assert.equal(ring.size, 2);
    // Caller-supplied id/time are never trusted (the ring owns both).
    ring.push({ ...BASE, id: 999, time: 42 });
    assert.equal(ring.snapshot()[2]?.id, 3);
    assert.equal(ring.snapshot()[2]?.time, 2_000);
});
test('audit: capacity is a hard bound and the newest entries win', () => {
    const ring = createAuditRing(3);
    for (let index = 0; index < 10; index += 1) {
        ring.push({ ...BASE, detail: `entry-${index}` });
    }
    const snapshot = ring.snapshot();
    assert.equal(ring.size, 3);
    assert.deepEqual(snapshot.map((entry) => entry.detail), ['entry-7', 'entry-8', 'entry-9']);
    assert.deepEqual(snapshot.map((entry) => entry.id), [8, 9, 10]);
});
test('audit: snapshot returns copies (callers cannot mutate the ring)', () => {
    const ring = createAuditRing(5);
    ring.push(BASE);
    const snapshot = ring.snapshot();
    const entry = snapshot[0];
    entry.detail = 'mutated';
    entry.deviceId = 'injected';
    assert.equal(ring.snapshot()[0]?.detail, 'pair.claim');
    assert.equal(ring.snapshot()[0]?.deviceId, null);
});
test('audit: defaults are applied for optional metadata', () => {
    const ring = createAuditRing(5);
    ring.push({ ...BASE, kind: 'security' });
    const entry = ring.snapshot()[0];
    assert.equal(entry.operation, '');
    assert.equal(entry.result, 'notice');
    assert.equal(entry.deviceLabel, null);
    assert.equal(entry.ip, null);
    assert.equal(entry.userAgent, null);
});
test('audit: an unknown result value degrades to notice', () => {
    const ring = createAuditRing(5);
    const hostile = {
        ...BASE,
        result: 'totally-not-a-result',
    };
    ring.push(hostile);
    assert.equal(ring.snapshot()[0]?.result, 'notice');
});
test('audit: dispose clears the ring and later pushes are ignored', () => {
    const ring = createAuditRing(5);
    ring.push(BASE);
    ring.dispose();
    assert.equal(ring.size, 0);
    assert.deepEqual(ring.snapshot(), []);
    ring.push(BASE);
    assert.equal(ring.size, 0);
});
test('audit: capacity falls back to a sane bound for invalid input', () => {
    for (const capacity of [0, -5, Number.NaN]) {
        const ring = createAuditRing(capacity);
        for (let index = 0; index < 5; index += 1)
            ring.push({ ...BASE, detail: `e${index}` });
        assert.ok(ring.size >= 1, `capacity ${capacity} must still record something`);
    }
});
/* ------------------------------------------------------------------------- */
/* Sanitizers                                                               */
/* ------------------------------------------------------------------------- */
test('audit: sanitizeAuditText removes ANSI escapes and control characters', () => {
    assert.equal(sanitizeAuditText('\u001b[31mred\u001b[0m'), 'red');
    assert.equal(sanitizeAuditText('line1\nline2'), 'line1 line2');
    assert.equal(sanitizeAuditText('tab\there'), 'tabhere');
    assert.equal(sanitizeAuditText('a\u0000b\u0007c'), 'abc');
    const cleaned = sanitizeAuditText('x\u001b[2Jy\u000bz');
    assert.equal(CONTROL_CHARS.test(cleaned), false);
    assert.equal(cleaned.includes('\u001b'), false);
});
test('audit: sanitizeAuditText bounds length and coerces only safe primitives', () => {
    assert.equal(sanitizeAuditText('x'.repeat(500), 64).length, 64);
    assert.equal(sanitizeAuditText(null), '');
    assert.equal(sanitizeAuditText(undefined), '');
    assert.equal(sanitizeAuditText(42), '42');
    assert.equal(sanitizeAuditText(true), 'true');
    assert.equal(sanitizeAuditText({ nested: 'object' }), '');
    assert.equal(sanitizeAuditText(['array']), '');
});
test('audit: sanitizeAuditIp keeps only real IP literals', () => {
    assert.equal(sanitizeAuditIp('192.168.1.104'), '192.168.1.104');
    assert.equal(sanitizeAuditIp('::1'), '::1');
    assert.equal(sanitizeAuditIp('2001:db8::1'), '2001:db8::1');
    assert.equal(sanitizeAuditIp('999.1.1.1'), null);
    assert.equal(sanitizeAuditIp('not-an-ip'), null);
    assert.equal(sanitizeAuditIp('1.2.3.4\ninjected'), null);
    assert.equal(sanitizeAuditIp(''), null);
    assert.equal(sanitizeAuditIp(null), null);
    assert.equal(sanitizeAuditIp(42), null);
});
test('audit: push sanitizes hostile user agents, labels, detail and ip', () => {
    const ring = createAuditRing(5);
    ring.push({
        deviceId: 'dev-1',
        deviceLabel: 'Pixel\u0000\u202e8\nInjected',
        kind: 'pair',
        operation: 'pair.claim',
        result: 'ok',
        ip: '192.168.1.104',
        userAgent: 'Mozilla/5.0\u001b[31m\nEvil: injected\r\n',
        detail: 'detail'.repeat(1_000),
    });
    const entry = ring.snapshot()[0];
    assert.equal(CONTROL_CHARS.test(entry.userAgent ?? ''), false);
    assert.equal((entry.userAgent ?? '').includes('\u001b'), false);
    assert.ok((entry.userAgent ?? '').length <= 160, 'user agent must be bounded');
    assert.ok(entry.detail.length <= 200, 'detail must be bounded');
    assert.equal(CONTROL_CHARS.test(entry.deviceLabel ?? ''), false);
    assert.equal(entry.ip, '192.168.1.104');
});
test('audit: a spoofable/invalid ip from unverified input is dropped', () => {
    const ring = createAuditRing(5);
    ring.push({ ...BASE, ip: 'cf-connecting-ip: 1.2.3.4' });
    ring.push({ ...BASE, detail: 'second', ip: 'evil\r\nheader: injected' });
    const [first, second] = ring.snapshot();
    assert.equal(first?.ip, null);
    assert.equal(second?.ip, null);
});
/* ------------------------------------------------------------------------- */
/* Desktop audit view                                                        */
/* ------------------------------------------------------------------------- */
test('audit: toAuditEntryView fills every field the panel expects', () => {
    const entry = {
        id: 7,
        time: 1_700_000_000_000,
        deviceId: 'dev-1',
        deviceLabel: 'Pixel',
        kind: 'pair',
        operation: 'pair.approve',
        result: 'ok',
        ip: '192.168.1.104',
        userAgent: 'Mozilla/5.0',
        detail: 'approved',
    };
    const view = toAuditEntryView(entry);
    assert.deepEqual(view, {
        id: 7,
        time: 1_700_000_000_000,
        kind: 'pair',
        operation: 'pair.approve',
        result: 'ok',
        deviceId: 'dev-1',
        deviceLabel: 'Pixel',
        ip: '192.168.1.104',
        userAgent: 'Mozilla/5.0',
        detail: 'approved',
    });
});
test('audit: toAuditEntryView never emits control characters', () => {
    const ring = createAuditRing(5);
    ring.push({ ...BASE, userAgent: 'ua\ninjected', deviceLabel: 'x\u001b[31my' });
    const view = toAuditEntryView(ring.snapshot()[0]);
    for (const value of [view.operation, view.detail, view.userAgent ?? '', view.deviceLabel ?? '']) {
        assert.equal(CONTROL_CHARS.test(value), false);
    }
});
