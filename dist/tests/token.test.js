/**
 * Token service contract (design §5.2, contract v2):
 * - access tokens are stateless HMAC-SHA256 with the exact
 *   `rc1.<deviceId>.<exp>.<version>.<epoch>.<nonce>.<sig>` shape, carrying the
 *   persisted revocation epoch and a hard expiry,
 * - `verifyAccess(token, expectedEpoch?)` fails closed on epoch mismatch and
 *   never accepts the legacy 6-part shape,
 * - refresh tokens are random secrets whose sha256 (only) is comparable,
 * - every tampering / malformed input path fails closed,
 * - comparisons are constant-time helpers.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { createTokenService } from '../src/token.js';
const ACCESS_TTL_MS = 8 * 3_600_000;
const REFRESH_TTL_MS = 10 * 86_400_000;
const FIXED_NOW = 1_700_000_000_000;
function makeDevice(overrides = {}) {
    return {
        id: 'dev-1',
        label: 'Phone',
        platform: 'ios',
        createdAt: FIXED_NOW - 60_000,
        lastSeenAt: FIXED_NOW - 1_000,
        refreshExpiresAt: FIXED_NOW + REFRESH_TTL_MS,
        tokenVersion: 1,
        tokenKey: randomBytes(32).toString('base64url'),
        refreshHash: '',
        ...overrides,
    };
}
function makeService(options = {}) {
    const clock = { now: FIXED_NOW };
    const service = createTokenService({
        accessTtlMs: ACCESS_TTL_MS,
        refreshTtlMs: REFRESH_TTL_MS,
        now: () => clock.now,
        ...options,
    });
    return { service, clock };
}
function sha256Hex(value) {
    return createHash('sha256').update(value, 'utf8').digest('hex');
}
function verifyDetailed(service, token, expectedEpoch) {
    const detailed = service.verifyAccessDetailed;
    assert.equal(typeof detailed, 'function', 'TokenService must expose verifyAccessDetailed');
    return detailed?.call(service, token, expectedEpoch) ?? { state: 'invalid' };
}
test('token: verifyAccessDetailed reports a valid token as valid with claims', () => {
    const device = makeDevice();
    const { service, clock } = makeService();
    const issued = service.issueAccess(device, 3);
    clock.now = issued.expiresAt - 1;
    assert.deepEqual(verifyDetailed(service, issued.token, 3), {
        state: 'valid',
        claims: {
            deviceId: device.id,
            tokenVersion: device.tokenVersion,
            expiresAt: issued.expiresAt,
            epoch: 3,
        },
    });
});
test('token: verifyAccessDetailed reports a normally expired token as expired (not invalid)', () => {
    const device = makeDevice();
    const { service, clock } = makeService();
    const issued = service.issueAccess(device, 5);
    clock.now = issued.expiresAt;
    const result = verifyDetailed(service, issued.token, 5);
    assert.equal(result.state, 'expired');
    if (result.state === 'expired') {
        assert.deepEqual(result.claims, {
            deviceId: device.id,
            tokenVersion: device.tokenVersion,
            expiresAt: issued.expiresAt,
            epoch: 5,
        });
    }
    // The legacy API still fails closed on expiry.
    assert.equal(service.verifyAccess(issued.token, 5), null);
});
test('token: verifyAccessDetailed reports malformed, tampered or mismatched tokens as invalid', () => {
    const device = makeDevice();
    const { service } = makeService();
    const issued = service.issueAccess(device, 2);
    const parts = issued.token.split('.');
    const tampered = [...parts];
    tampered[6] = `${String(parts[6]).slice(0, -2)}AA`;
    const invalid = [
        '',
        'rc1',
        'not-a-token',
        `${issued.token}.extra`,
        'rc1.dev-1.123.1.0.nonce',
        'rc1.dev-1.123.1.0.nonce.sig',
        tampered.join('.'),
    ];
    for (const token of invalid) {
        assert.deepEqual(verifyDetailed(service, token, 2), { state: 'invalid' }, `must reject ${token.slice(0, 24)}`);
    }
});
test('token: verifyAccessDetailed treats wrong device keys and epoch mismatches as invalid', () => {
    const device = makeDevice();
    const issuer = makeService({ getDevice: () => device }).service;
    const issued = issuer.issueAccess(device, 2);
    const rotatedKey = { ...device, tokenKey: randomBytes(32).toString('base64url') };
    const stranger = makeService({ getDevice: () => rotatedKey }).service;
    assert.deepEqual(verifyDetailed(stranger, issued.token, 2), { state: 'invalid' });
    const unknownDevice = makeService({ getDevice: () => undefined }).service;
    assert.deepEqual(verifyDetailed(unknownDevice, issued.token, 2), { state: 'invalid' });
    // Mocked clock far in the future: epoch mismatch is invalid, not "expired".
    const timing = makeService({ getDevice: () => device });
    timing.clock.now = issued.expiresAt + 60_000;
    assert.deepEqual(verifyDetailed(timing.service, issued.token, 3), { state: 'invalid' });
    // ...while the correct epoch legitimately reports expiry.
    assert.equal(verifyDetailed(timing.service, issued.token, 2).state, 'expired');
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 60]) {
        assert.deepEqual(verifyDetailed(issuer, issued.token, bad), { state: 'invalid' });
    }
});
test('token: verifyAccessDetailed never throws and is total for hostile inputs', () => {
    const device = makeDevice();
    const { service } = makeService();
    const issued = service.issueAccess(device, 0);
    for (const token of [undefined, null, 42, {}, [], issued.token]) {
        assert.doesNotThrow(() => verifyDetailed(service, token, 0));
    }
    assert.deepEqual(verifyDetailed(service, undefined, 0), { state: 'invalid' });
    assert.deepEqual(verifyDetailed(service, {}, 0), { state: 'invalid' });
    assert.equal(verifyDetailed(service, issued.token, 0).state, 'valid');
});
test('token: verifyAccessDetailed agrees with verifyAccess on which tokens are usable', () => {
    const device = makeDevice();
    const { service, clock } = makeService();
    const issued = service.issueAccess(device, 1);
    const usable = verifyDetailed(service, issued.token, 1);
    assert.equal(usable.state, 'valid');
    assert.deepEqual(service.verifyAccess(issued.token, 1), usable.state === 'valid' ? usable.claims : null);
    clock.now = issued.expiresAt;
    assert.equal(verifyDetailed(service, issued.token, 1).state, 'expired');
    assert.equal(service.verifyAccess(issued.token, 1), null);
});
/* ------------------------------------------------------------------------- */
/* Access token shape & verification                                         */
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */
test('token: access token has the seven-part rc1 format with a real HMAC signature', () => {
    const device = makeDevice();
    const { service } = makeService();
    const issued = service.issueAccess(device);
    const parts = issued.token.split('.');
    assert.equal(parts.length, 7, 'access token must have exactly 7 dot-separated parts');
    assert.equal(parts[0], 'rc1');
    assert.equal(parts[1], device.id);
    assert.equal(parts[2], String(issued.expiresAt));
    assert.equal(parts[3], String(device.tokenVersion));
    assert.equal(parts[4], '0', 'the default revocation epoch is 0');
    assert.match(parts[5] ?? '', /^[A-Za-z0-9_-]+$/, 'nonce must be base64url');
    assert.match(parts[6] ?? '', /^[A-Za-z0-9_-]+$/, 'signature must be base64url');
    assert.equal(issued.expiresAt, FIXED_NOW + ACCESS_TTL_MS);
});
test('token: issueAccess carries the persisted revocation epoch', () => {
    const device = makeDevice();
    const { service } = makeService();
    const issued = service.issueAccess(device, 7);
    assert.equal(issued.token.split('.')[4], '7');
    const claims = service.verifyAccess(issued.token);
    assert.equal(claims?.epoch, 7);
    assert.throws(() => service.issueAccess(device, -1), /epoch/i);
    assert.throws(() => service.issueAccess(device, 1.5), /epoch/i);
    assert.throws(() => service.issueAccess(device, Number.NaN), /epoch/i);
    assert.throws(() => service.issueAccess(device, 2 ** 53), /epoch/i);
});
test('token: issueAccess generates a fresh nonce on every call', () => {
    const device = makeDevice();
    const { service } = makeService();
    const first = service.issueAccess(device);
    const second = service.issueAccess(device);
    assert.notEqual(first.token, second.token);
    assert.notEqual(first.token.split('.')[5], second.token.split('.')[5]);
});
test('token: verifyAccess returns the device claims for an untampered token', () => {
    const device = makeDevice();
    const { service, clock } = makeService();
    const issued = service.issueAccess(device);
    clock.now = FIXED_NOW + 1_000;
    assert.deepEqual(service.verifyAccess(issued.token), {
        deviceId: device.id,
        tokenVersion: device.tokenVersion,
        expiresAt: issued.expiresAt,
        epoch: 0,
    });
});
test('token: verifyAccess enforces the expected revocation epoch', () => {
    const device = makeDevice();
    const { service } = makeService();
    const issued = service.issueAccess(device, 3);
    assert.notEqual(service.verifyAccess(issued.token, 3), null, 'matching epoch verifies');
    assert.equal(service.verifyAccess(issued.token, 4), null, 'a bumped epoch invalidates the token');
    assert.equal(service.verifyAccess(issued.token, 0), null, 'an older epoch never revalidates a token');
    assert.notEqual(service.verifyAccess(issued.token), null, 'an undefined expected epoch skips the check');
    // Malformed expected epochs fail closed instead of throwing.
    for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 60]) {
        assert.equal(service.verifyAccess(issued.token, bad), null);
    }
});
test('token: verifyAccess rejects tampering with every field', () => {
    const device = makeDevice();
    const { service } = makeService();
    const issued = service.issueAccess(device, 2);
    const parts = issued.token.split('.');
    const mutations = [
        ['signature', 6, `${String(parts[6]).slice(0, -2)}AA`],
        ['epoch', 4, '3'],
        ['expiry', 2, String(Number(parts[2]) + 60_000)],
        ['version', 3, String(Number(parts[3]) + 1)],
        ['nonce', 5, `${String(parts[5]).slice(0, -2)}AA`],
        ['device id', 1, 'someone-else'],
        ['prefix', 0, 'rc2'],
    ];
    for (const [name, index, value] of mutations) {
        const copy = [...parts];
        copy[index] = value;
        assert.equal(service.verifyAccess(copy.join('.')), null, `tampered ${name} must be rejected`);
    }
});
test('token: verifyAccess fails closed for malformed input', () => {
    const device = makeDevice();
    const { service } = makeService();
    const valid = service.issueAccess(device).token;
    const malformed = [
        '',
        'rc1',
        'rc1.dev-1',
        `${valid}.extra`,
        'rc1.dev-1.notanumber.1.0.nonce.sig',
        'rc1.dev-1.123.1.0.nonce',
        'rc1.dev-1.123.1.nonce.sig',
        'rc1.!!!.123.1.0.nonce.sig',
        'rc1.dev-1.123.1.-1.nonce.sig',
        'rc1.dev-1.123.1.1.5.nonce.sig',
        'rc1.dev-1.123.1.99999999999999999999.nonce.sig',
        'rc1.dev-1.123.1.0.!!!.sig',
        'rc1.dev-1.123.1.0.nonce.!!!',
        'rc1.dev-1.123.1.0.nonce.c2hvcnQ',
        '\u0000rc1.dev-1.123.1.0.nonce.sig',
    ];
    for (const candidate of malformed) {
        assert.equal(service.verifyAccess(candidate), null, `must reject ${JSON.stringify(candidate)}`);
    }
    assert.equal(service.verifyAccess(undefined), null);
    assert.equal(service.verifyAccess(null), null);
    assert.equal(service.verifyAccess(42), null);
});
test('token: a legacy six-part access token is never accepted after the epoch bump', () => {
    const device = makeDevice();
    const { service } = makeService({ getDevice: () => device });
    const valid = service.issueAccess(device).token;
    const legacy = valid.split('.').filter((_part, index) => index !== 4).join('.');
    assert.equal(legacy.split('.').length, 6);
    assert.equal(service.verifyAccess(legacy), null);
    assert.equal(service.verifyAccess(legacy, 0), null);
});
test('token: access token expires at its exp boundary', () => {
    const device = makeDevice();
    const { service, clock } = makeService();
    const issued = service.issueAccess(device);
    clock.now = issued.expiresAt - 1;
    assert.notEqual(service.verifyAccess(issued.token), null, 'valid one millisecond before expiry');
    clock.now = issued.expiresAt;
    assert.equal(service.verifyAccess(issued.token), null, 'expired at exactly exp');
});
test('token: an unknown device cannot verify even with a structurally valid token', () => {
    const device = makeDevice();
    const issuer = makeService().service;
    const token = issuer.issueAccess(device).token;
    const stranger = createTokenService({
        accessTtlMs: ACCESS_TTL_MS,
        refreshTtlMs: REFRESH_TTL_MS,
        now: () => FIXED_NOW,
    });
    assert.equal(stranger.verifyAccess(token), null);
    const withStore = createTokenService({
        accessTtlMs: ACCESS_TTL_MS,
        refreshTtlMs: REFRESH_TTL_MS,
        now: () => FIXED_NOW,
        getDevice: (id) => (id === device.id ? device : undefined),
    });
    assert.equal(withStore.verifyAccess(token)?.deviceId, device.id);
});
test('token: tokenVersion is carried in the claims so revoke/rotation can be detected', () => {
    const device = makeDevice({ tokenVersion: 7 });
    const { service } = makeService({ getDevice: () => device });
    const issued = service.issueAccess(device);
    assert.equal(service.verifyAccess(issued.token)?.tokenVersion, 7);
    const rotated = { ...device, tokenVersion: 8 };
    const next = service.issueAccess(rotated);
    assert.equal(service.verifyAccess(next.token)?.tokenVersion, 8);
    // The old token's claim still says 7: the controller compares it with the store.
    assert.equal(service.verifyAccess(issued.token)?.tokenVersion, 7);
});
test('token: invalid token keys or device ids are rejected at issue time', () => {
    const { service } = makeService();
    assert.throws(() => service.issueAccess(makeDevice({ tokenKey: 'not base64url!!!' })), /token key/i);
    assert.throws(() => service.issueAccess(makeDevice({ tokenKey: Buffer.alloc(16).toString('base64url') })), /32 bytes/);
    assert.throws(() => service.issueAccess(makeDevice({ id: 'bad id!' })), /device id/i);
    assert.throws(() => service.issueRefresh(makeDevice({ id: 'bad/id' })), /device id/i);
});
test('token: durations must be positive integers', () => {
    assert.throws(() => createTokenService({ accessTtlMs: 0, refreshTtlMs: 1 }), /accessTtlMs/);
    assert.throws(() => createTokenService({ accessTtlMs: 1, refreshTtlMs: -5 }), /refreshTtlMs/);
    assert.throws(() => createTokenService({ accessTtlMs: 1.5, refreshTtlMs: 1 }), /accessTtlMs/);
});
/* ------------------------------------------------------------------------- */
/* Refresh tokens                                                            */
/* ------------------------------------------------------------------------- */
test('token: refresh token shape is rcr1.<deviceId>.<secret> and only its hash is comparable', () => {
    const device = makeDevice();
    const { service } = makeService();
    const refresh = service.issueRefresh(device);
    const parts = refresh.token.split('.');
    assert.equal(parts.length, 3);
    assert.equal(parts[0], 'rcr1');
    assert.equal(parts[1], device.id);
    assert.match(parts[2] ?? '', /^[A-Za-z0-9_-]{40,}$/);
    assert.equal(refresh.hash, sha256Hex(refresh.token));
    assert.match(refresh.hash, /^[0-9a-f]{64}$/);
    assert.equal(refresh.expiresAt, FIXED_NOW + REFRESH_TTL_MS);
    assert.equal(service.hashRefresh(refresh.token), refresh.hash);
    // The raw secret must not appear in the persisted hash.
    assert.equal(refresh.hash.includes(String(parts[2])), false);
});
test('token: refresh tokens are unique per issue and hashes differ', () => {
    const device = makeDevice();
    const { service } = makeService();
    const first = service.issueRefresh(device);
    const second = service.issueRefresh(device);
    assert.notEqual(first.token, second.token);
    assert.notEqual(first.hash, second.hash);
    assert.equal(service.equalRefresh(first.hash, first.hash), true);
    assert.equal(service.equalRefresh(first.hash, second.hash), false);
});
test('token: readRefreshSubject extracts the device id without trusting the secret', () => {
    const device = makeDevice();
    const { service } = makeService();
    const refresh = service.issueRefresh(device);
    assert.deepEqual(service.readRefreshSubject(refresh.token), { deviceId: device.id });
    assert.equal(service.readRefreshSubject('rcr1.other.abcdefghijklmnopqrstuvwxyz0123456789')?.deviceId, 'other');
    assert.equal(service.readRefreshSubject('rc_access=abc'), null);
    assert.equal(service.readRefreshSubject('rcr1'), null);
    assert.equal(service.readRefreshSubject('rcr1.dev-1'), null);
    assert.equal(service.readRefreshSubject('rcr1.dev-1.short'), null);
    assert.equal(service.readRefreshSubject('rcr1.bad id.abcdefghijklmnopqrstuvwxyz'), null);
    assert.equal(service.readRefreshSubject(''), null);
});
/* ------------------------------------------------------------------------- */
/* Constant-time helpers                                                     */
/* ------------------------------------------------------------------------- */
test('token: hashSecret/equalHex implement sha256 hex equality', () => {
    const { service } = makeService();
    assert.equal(service.hashSecret('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(service.equalHex(service.hashSecret('code-1'), service.hashSecret('code-1')), true);
    assert.equal(service.equalHex(service.hashSecret('code-1'), service.hashSecret('code-2')), false);
    assert.equal(service.equalHex('', ''), true);
    assert.equal(service.equalHex('abc', 'abcd'), false);
    assert.equal(service.equalHex('abc', ''), false);
});
test('token: pairing-code hashes are stable across service instances', () => {
    const first = makeService().service;
    const second = makeService().service;
    assert.equal(first.hashSecret('123456'), second.hashSecret('123456'));
});
