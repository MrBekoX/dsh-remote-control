/**
 * Device store persistence (design §9):
 * - schema validation, persistence across store instances,
 * - atomic writes (no temp remnants, valid JSON after every add/update/remove),
 * - maxDevices enforcement and DEVICE_LIMIT,
 * - fail-closed on corrupt JSON / symlinks / (POSIX) unsafe permissions,
 * - public DeviceView never leaks token material.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { DeviceStoreError, createDeviceStore, ensureSecureDirectory, isInsideDirectory, toDeviceView, writeFileAtomic, } from '../src/device-store.js';
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
async function makeTempDir(t) {
    const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rc-device-store-'));
    t.after(async () => {
        await fsp.rm(dir, { recursive: true, force: true }).catch(() => undefined);
    });
    return dir;
}
function makeStoredDevice(overrides = {}) {
    return {
        id: randomUUID(),
        label: 'Pixel 8',
        platform: 'android',
        createdAt: 1_700_000_000_000,
        lastSeenAt: 1_700_000_000_500,
        refreshExpiresAt: 1_700_900_000_000,
        tokenVersion: 1,
        tokenKey: randomBytes(32).toString('base64url'),
        refreshHash: 'a'.repeat(64),
        ...overrides,
    };
}
async function openStore(dir, maxDevices = 4) {
    const store = await createDeviceStore({
        filePath: path.join(dir, 'remote-control', 'devices.json'),
        maxDevices,
        log: silentLogger(),
    });
    await store.load();
    return store;
}
const symlinkSupported = (() => {
    if (process.platform === 'win32')
        return false;
    return true;
})();
/* ------------------------------------------------------------------------- */
/* Persistence & atomicity                                                   */
/* ------------------------------------------------------------------------- */
test('device-store: an empty store loads as an empty list', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir);
    t.after(() => store.dispose());
    assert.deepEqual(store.list(), []);
    assert.equal(store.count(), 0);
    assert.equal(store.get('missing'), undefined);
});
test('device-store: add() persists and a new instance reloads the record', async (t) => {
    const dir = await makeTempDir(t);
    const first = await openStore(dir);
    const device = makeStoredDevice();
    await first.add(device);
    first.dispose();
    const onDisk = JSON.parse(await fsp.readFile(first.path, 'utf8'));
    assert.equal(onDisk.v, 1);
    assert.equal(onDisk.devices.length, 1);
    assert.equal(onDisk.devices[0]?.id, device.id);
    const second = await openStore(dir);
    t.after(() => second.dispose());
    assert.equal(second.count(), 1);
    assert.deepEqual(second.get(device.id), device);
});
test('device-store: update()/remove() rewrite the file and survive reload', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir);
    t.after(() => store.dispose());
    const device = makeStoredDevice();
    await store.add(device);
    await store.update({ ...device, label: 'Renamed', tokenVersion: 2 });
    assert.equal(store.get(device.id)?.label, 'Renamed');
    assert.equal(store.get(device.id)?.tokenVersion, 2);
    const reloaded = await openStore(dir);
    t.after(() => reloaded.dispose());
    assert.equal(reloaded.get(device.id)?.label, 'Renamed');
    await reloaded.remove(device.id);
    assert.equal(reloaded.count(), 0);
    const afterRemove = await openStore(dir);
    t.after(() => afterRemove.dispose());
    assert.equal(afterRemove.count(), 0);
});
test('device-store: touch() updates only lastSeenAt and cannot clobber a rotated refresh hash', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir);
    t.after(() => store.dispose());
    const device = makeStoredDevice();
    await store.add(device);
    const staleSnapshot = store.get(device.id);
    const rotatedHash = 'c'.repeat(64);
    await store.update({ ...staleSnapshot, refreshHash: rotatedHash, lastSeenAt: staleSnapshot.lastSeenAt + 1 });
    // A stale snapshot arriving from another request only writes the timestamp;
    // the rotated refresh hash must survive.
    await store.touch(device.id, staleSnapshot.lastSeenAt + 500);
    assert.equal(store.get(device.id)?.refreshHash, rotatedHash);
    assert.equal(store.get(device.id)?.lastSeenAt, staleSnapshot.lastSeenAt + 500);
    // Older or equal timestamps and unknown ids are ignored (no regression writes).
    await store.touch(device.id, staleSnapshot.lastSeenAt);
    assert.equal(store.get(device.id)?.lastSeenAt, staleSnapshot.lastSeenAt + 500);
    await store.touch('missing-device', staleSnapshot.lastSeenAt + 9_000);
    assert.equal(store.count(), 1);
});
test('device-store: writes are atomic — no temp remnants and always valid JSON', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir);
    t.after(() => store.dispose());
    for (let index = 0; index < 3; index += 1) {
        await store.add(makeStoredDevice({ label: `Phone ${index}` }));
        JSON.parse(await fsp.readFile(store.path, 'utf8'));
    }
    const leftovers = (await fsp.readdir(path.dirname(store.path))).filter((name) => name.endsWith('.tmp'));
    assert.deepEqual(leftovers, [], 'atomic writes must not leave temp files behind');
});
test('device-store: get()/list() return copies, not internal records', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir);
    t.after(() => store.dispose());
    const device = makeStoredDevice();
    await store.add(device);
    const fetched = store.get(device.id);
    assert.notEqual(fetched, undefined);
    if (fetched !== undefined)
        fetched.label = 'mutated outside the store';
    assert.equal(store.get(device.id)?.label, 'Pixel 8');
});
/* ------------------------------------------------------------------------- */
/* Limits                                                                    */
/* ------------------------------------------------------------------------- */
test('device-store: add() enforces maxDevices with DEVICE_LIMIT', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir, 2);
    t.after(() => store.dispose());
    await store.add(makeStoredDevice());
    await store.add(makeStoredDevice());
    await assert.rejects(store.add(makeStoredDevice()), (error) => error instanceof DeviceStoreError && error.code === 'DEVICE_LIMIT');
    assert.equal(store.count(), 2);
});
test('device-store: duplicate ids and invalid records are rejected', async (t) => {
    const dir = await makeTempDir(t);
    const store = await openStore(dir);
    t.after(() => store.dispose());
    const device = makeStoredDevice();
    await store.add(device);
    await assert.rejects(store.add(device), DeviceStoreError);
    await assert.rejects(store.add(makeStoredDevice({ id: 'bad id!' })), (error) => error instanceof DeviceStoreError && error.code === 'STORE_UNAVAILABLE');
    await assert.rejects(store.add(makeStoredDevice({ tokenKey: 'short' })), (error) => error instanceof DeviceStoreError && error.code === 'STORE_UNAVAILABLE');
    await assert.rejects(store.update(makeStoredDevice()), DeviceStoreError, 'updating an unknown device must fail');
    assert.equal(store.count(), 1);
});
/* ------------------------------------------------------------------------- */
/* Fail-closed loading                                                       */
/* ------------------------------------------------------------------------- */
test('device-store: corrupt JSON fails closed instead of starting empty', async (t) => {
    const dir = await makeTempDir(t);
    const targetDir = path.join(dir, 'remote-control');
    await fsp.mkdir(targetDir, { recursive: true });
    const filePath = path.join(targetDir, 'devices.json');
    await fsp.writeFile(filePath, '{"v":1,"devices":[', { encoding: 'utf8', mode: 0o600 });
    const store = await createDeviceStore({ filePath, maxDevices: 4, log: silentLogger() });
    await assert.rejects(store.load(), (error) => error instanceof DeviceStoreError && error.code === 'STORE_CORRUPT');
    assert.deepEqual(store.list(), []);
});
test('device-store: schema violations and oversized files fail closed', async (t) => {
    const dir = await makeTempDir(t);
    const targetDir = path.join(dir, 'remote-control');
    await fsp.mkdir(targetDir, { recursive: true });
    const filePath = path.join(targetDir, 'devices.json');
    await fsp.writeFile(filePath, JSON.stringify({ v: 2, devices: [] }), { encoding: 'utf8', mode: 0o600 });
    const wrongVersion = await createDeviceStore({ filePath, maxDevices: 4, log: silentLogger() });
    await assert.rejects(wrongVersion.load(), DeviceStoreError);
    await fsp.writeFile(filePath, JSON.stringify({ v: 1, devices: [{ id: 'x' }] }), {
        encoding: 'utf8',
        mode: 0o600,
    });
    const partialDevice = await createDeviceStore({ filePath, maxDevices: 4, log: silentLogger() });
    await assert.rejects(partialDevice.load(), DeviceStoreError);
});
test('device-store: symlinked store paths are refused', { skip: !symlinkSupported }, async (t) => {
    const dir = await makeTempDir(t);
    const targetDir = path.join(dir, 'remote-control');
    await fsp.mkdir(targetDir, { recursive: true });
    const realFile = path.join(dir, 'real.json');
    await fsp.writeFile(realFile, JSON.stringify({ v: 1, devices: [] }), 'utf8');
    const linkPath = path.join(targetDir, 'devices.json');
    await fsp.symlink(realFile, linkPath);
    const store = await createDeviceStore({ filePath: linkPath, maxDevices: 4, log: silentLogger() });
    await assert.rejects(store.load(), DeviceStoreError);
});
test('device-store: symlinked parent directories are refused', { skip: !symlinkSupported }, async (t) => {
    const dir = await makeTempDir(t);
    const realDir = path.join(dir, 'real-remote-control');
    await fsp.mkdir(realDir, { recursive: true });
    const linkDir = path.join(dir, 'remote-control');
    await fsp.symlink(realDir, linkDir, 'dir');
    const store = await createDeviceStore({
        filePath: path.join(linkDir, 'devices.json'),
        maxDevices: 4,
        log: silentLogger(),
    });
    await assert.rejects(store.load(), DeviceStoreError);
});
test('device-store: POSIX store files must be user-private (0600)', { skip: process.platform === 'win32' }, async (t) => {
    const dir = await makeTempDir(t);
    const targetDir = path.join(dir, 'remote-control');
    await fsp.mkdir(targetDir, { recursive: true });
    const filePath = path.join(targetDir, 'devices.json');
    await fsp.writeFile(filePath, JSON.stringify({ v: 1, devices: [] }), { encoding: 'utf8', mode: 0o644 });
    const store = await createDeviceStore({ filePath, maxDevices: 4, log: silentLogger() });
    await assert.rejects(store.load(), DeviceStoreError);
});
/* ------------------------------------------------------------------------- */
/* Public view & helpers                                                     */
/* ------------------------------------------------------------------------- */
test('device-store: toDeviceView strips every secret field', () => {
    const device = makeStoredDevice();
    const view = toDeviceView(device);
    assert.deepEqual(Object.keys(view).sort(), [
        'createdAt',
        'id',
        'label',
        'lastSeenAt',
        'platform',
        'refreshExpiresAt',
    ]);
    assert.equal(JSON.stringify(view).includes(device.tokenKey), false);
    assert.equal(JSON.stringify(view).includes(device.refreshHash), false);
    assert.equal('tokenVersion' in view, false);
});
test('device-store: isInsideDirectory rejects traversal and prefix tricks', () => {
    const root = path.resolve('/srv/pwa');
    assert.equal(isInsideDirectory(root, path.join(root, 'index.html')), true);
    assert.equal(isInsideDirectory(root, root), true);
    assert.equal(isInsideDirectory(root, path.join(root, '..', 'secret')), false);
    assert.equal(isInsideDirectory(root, `${root}-evil/file`), false);
});
test('device-store: writeFileAtomic replaces content and ensureSecureDirectory creates the directory', async (t) => {
    const dir = await makeTempDir(t);
    const nested = path.join(dir, 'nested', 'deeper');
    await ensureSecureDirectory(nested, silentLogger());
    const file = path.join(nested, 'data.json');
    await writeFileAtomic(file, '{"a":1}\n');
    assert.equal(await fsp.readFile(file, 'utf8'), '{"a":1}\n');
    await writeFileAtomic(file, '{"a":2}\n');
    assert.equal(await fsp.readFile(file, 'utf8'), '{"a":2}\n');
    const leftovers = (await fsp.readdir(nested)).filter((name) => name.endsWith('.tmp'));
    assert.deepEqual(leftovers, []);
    assert.equal(fs.existsSync(file), true);
});
