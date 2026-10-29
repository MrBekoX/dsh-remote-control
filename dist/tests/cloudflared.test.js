/**
 * cloudflared lane: pinned official release facts, verified download/cache,
 * safe archive extraction, output parsers and argv construction.
 *
 * FAILING-FIRST: this file is written before the implementation. It compiles
 * against the planned public API of `src/cloudflared.ts`; every test below is
 * expected to be red until the implementation lands. No network and no real
 * `cloudflared` execution happens here: the HTTP client and child-process
 * factory are injected fakes.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { deflateRawSync, gzipSync, crc32 } from 'node:zlib';
import { PINNED_CLOUDFLARED_RELEASE, buildCloudflaredArgs, createCloudflaredInstaller, createCloudflaredOutputParser, parseCloudflaredVersion, pinnedAssetFor, } from '../src/cloudflared.js';
import { TunnelError } from '../src/tunnel-errors.js';
/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
function sha256(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
}
let root = '';
before(async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-rc-cloudflared-'));
});
after(async () => {
    if (root !== '')
        await rm(root, { recursive: true, force: true });
});
/** A tiny fake pinned release so tests never download 40–55 MB fixtures. */
function testRelease(executable, overrides = {}) {
    const asset = {
        platform: 'linux',
        arch: 'x64',
        asset: 'cloudflared-linux-amd64',
        sizeBytes: executable.length,
        sha256: sha256(executable),
        archive: 'none',
        executableName: 'cloudflared',
        ...overrides,
    };
    return {
        asset,
        release: {
            version: '2026.10.5',
            releaseBaseUrl: 'https://github.com/cloudflare/cloudflared/releases/download/2026.10.5',
            assets: { [`${asset.platform}-${asset.arch}`]: asset },
        },
    };
}
function cacheFileName(release, asset) {
    const extension = asset.platform === 'win32' ? '.exe' : '';
    return `cloudflared-${release.version}-${asset.platform}-${asset.arch}${extension}`;
}
function makeCommandChild(options) {
    const child = new EventEmitter();
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    Object.assign(child, { stdout, stderr, exitCode: null, signalCode: null, kill: () => true });
    setImmediate(() => {
        if (options.error !== undefined) {
            child.emit('error', options.error);
            return;
        }
        if (options.stdout !== undefined)
            stdout.emit('data', options.stdout);
        if (options.stderr !== undefined)
            stderr.emit('data', options.stderr);
        Object.assign(child, { exitCode: options.code ?? 0, signalCode: options.signal ?? null });
        child.emit('exit', options.code ?? 0, options.signal ?? null);
    });
    return child;
}
function makeSpawn(handler) {
    const calls = [];
    const spawn = (command, args, options) => {
        const call = { command, args, options };
        calls.push(call);
        return handler(call);
    };
    return { spawn, calls };
}
const probeSpawn = (version = 'cloudflared version 2026.10.5 (built 2026-10-27T06:05 UTC)') => makeSpawn((call) => call.args[0] === '--version'
    ? makeCommandChild({ code: 0, stderr: `${version}\n` })
    : makeCommandChild({ code: 1 }));
/** No cloudflared on PATH (each spawn reports ENOENT through the error event). */
const noBinarySpawn = () => makeSpawn(() => makeCommandChild({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }) }));
function fakeResponse(bytes, init = {}) {
    const headers = new Headers(init.headers);
    if (!headers.has('content-length'))
        headers.set('content-length', String(bytes.length));
    return new Response(new Uint8Array(bytes), { status: init.status ?? 200, headers });
}
function redirectResponse(location, status = 302) {
    return new Response(null, { status, headers: { location } });
}
function makeFetch(handler) {
    const calls = [];
    const fetchFn = (async (input, init) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        const redirect = init?.redirect;
        calls.push({ url, redirect });
        return handler({ url, redirect }, calls.length - 1);
    });
    return { fetch: fetchFn, calls };
}
function installerDeps(overrides = {}) {
    return {
        configuredPath: '',
        cacheDir: join(root, `cache-${Math.random().toString(16).slice(2)}`),
        platform: 'linux',
        arch: 'x64',
        log: silentLogger(),
        ...overrides,
    };
}
async function expectTunnelError(action, code) {
    try {
        await action();
    }
    catch (error) {
        assert.ok(error instanceof TunnelError, `expected TunnelError, got ${String(error)}`);
        assert.equal(error.code, code);
        return error;
    }
    assert.fail(`expected TunnelError ${code}`);
}
function tarHeader(entry, size) {
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100, 'utf8');
    header.write('0000644\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii');
    header.write('        ', 148, 8, 'ascii');
    header.write(entry.type ?? '0', 156, 1, 'ascii');
    header.write(entry.linkName ?? '', 157, 100, 'utf8');
    header.write('ustar\0', 257, 6, 'ascii');
    header.write('00', 263, 2, 'ascii');
    let checksum = 0;
    for (const byte of header)
        checksum += byte;
    header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii');
    return header;
}
function buildTarGz(entries) {
    const blocks = [];
    for (const entry of entries) {
        const data = entry.data ?? Buffer.alloc(0);
        blocks.push(tarHeader(entry, data.length));
        if (data.length > 0) {
            blocks.push(data);
            const padding = (512 - (data.length % 512)) % 512;
            if (padding > 0)
                blocks.push(Buffer.alloc(padding));
        }
    }
    blocks.push(Buffer.alloc(1024));
    return gzipSync(Buffer.concat(blocks));
}
function buildZip(entries) {
    const locals = [];
    const centrals = [];
    let offset = 0;
    for (const entry of entries) {
        const name = Buffer.from(entry.name, 'utf8');
        const data = entry.data ?? Buffer.alloc(0);
        const crc = crc32(data);
        let method = 0;
        let payload = data;
        const deflated = deflateRawSync(data);
        if (deflated.length < data.length) {
            method = 8;
            payload = deflated;
        }
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt16LE(0x0800, 6);
        local.writeUInt16LE(method, 8);
        local.writeUInt16LE(0, 10);
        local.writeUInt16LE(0, 12);
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(payload.length, 18);
        local.writeUInt32LE(data.length, 22);
        local.writeUInt16LE(name.length, 26);
        local.writeUInt16LE(0, 28);
        locals.push(local, name, payload);
        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(entry.symlink === true ? 0x0314 : 20, 4);
        central.writeUInt16LE(20, 6);
        central.writeUInt16LE(0x0800, 8);
        central.writeUInt16LE(method, 10);
        central.writeUInt16LE(0, 12);
        central.writeUInt16LE(0, 14);
        central.writeUInt32LE(crc, 16);
        central.writeUInt32LE(payload.length, 20);
        central.writeUInt32LE(data.length, 24);
        central.writeUInt16LE(name.length, 28);
        central.writeUInt16LE(0, 30);
        central.writeUInt16LE(0, 32);
        central.writeUInt16LE(0, 34);
        central.writeUInt16LE(0, 36);
        central.writeUInt32LE(entry.symlink === true ? (0o120777 << 16) >>> 0 : 0, 38);
        central.writeUInt32LE(offset, 42);
        centrals.push(central, name);
        offset += local.length + name.length + payload.length;
    }
    const centralSize = centrals.reduce((total, part) => total + part.length, 0);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralSize, 12);
    eocd.writeUInt32LE(offset, 16);
    eocd.writeUInt16LE(0, 20);
    return Buffer.concat([...locals, ...centrals, eocd]);
}
/* ------------------------------------------------------------------------- */
/* 1. Pinned official release facts (scratch/research-methods-facts.md)      */
/* ------------------------------------------------------------------------- */
test('pinned release: exact 2026.10.5 official asset names, sizes and API digests', () => {
    assert.equal(PINNED_CLOUDFLARED_RELEASE.version, '2026.10.5');
    const windows = pinnedAssetFor('win32', 'x64');
    assert.ok(windows !== null);
    assert.equal(windows.asset, 'cloudflared-windows-amd64.exe');
    assert.equal(windows.sizeBytes, 55_343_328);
    assert.equal(windows.sha256, 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9');
    assert.equal(windows.archive, 'none');
    assert.equal(windows.executableName, 'cloudflared.exe');
    const linux = pinnedAssetFor('linux', 'x64');
    assert.ok(linux !== null);
    assert.equal(linux.asset, 'cloudflared-linux-amd64');
    assert.equal(linux.sizeBytes, 40_263_303);
    assert.equal(linux.sha256, 'e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298');
    assert.equal(linux.archive, 'none');
    // macOS: the release-body checksum is the INNER binary; the API digest is the
    // .tgz bytes. Both are pinned and must never be mixed (research report A2d).
    const darwin = pinnedAssetFor('darwin', 'arm64');
    assert.ok(darwin !== null);
    assert.equal(darwin.asset, 'cloudflared-darwin-arm64.tgz');
    assert.equal(darwin.sizeBytes, 19_840_425);
    assert.equal(darwin.sha256, '184c7d4f5f977348243a6d7ca8f6cf6073b9b2746cfe8c1fe15aa59e9a522bf0');
    assert.equal(darwin.archive, 'tgz');
    assert.equal(darwin.executableName, 'cloudflared');
    assert.equal(darwin.binarySha256, '2b23964528ddcd641c1449275df8b5b51e3c7193b5257919846331bc5bc13b0f');
    const darwinIntel = pinnedAssetFor('darwin', 'x64');
    assert.ok(darwinIntel !== null);
    assert.equal(darwinIntel.asset, 'cloudflared-darwin-amd64.tgz');
    assert.equal(darwinIntel.sha256, '6699392fed92367808c248c2d90bed66e49bbf66e1b4ee3e4141230f3f7391b3');
    assert.equal(darwinIntel.binarySha256, 'cb09afb9b4d0a4730de477ac710aebb6107568930a8345775629bf264f70c284');
    // No wildcard/unknown platforms: fail closed.
    assert.equal(pinnedAssetFor('freebsd', 'x64'), null);
    assert.equal(pinnedAssetFor('win32', 'mips'), null);
});
test('pinnedAssetFor fails closed when a pinned digest is missing or empty', () => {
    const broken = {
        version: '2026.10.5',
        releaseBaseUrl: 'https://github.com/cloudflare/cloudflared/releases/download/2026.10.5',
        assets: {
            'linux-x64': {
                platform: 'linux',
                arch: 'x64',
                asset: 'cloudflared-linux-amd64',
                sizeBytes: 10,
                sha256: '',
                archive: 'none',
                executableName: 'cloudflared',
            },
        },
    };
    assert.equal(pinnedAssetFor('linux', 'x64', broken), null);
    assert.equal(pinnedAssetFor('linux', 'arm64', broken), null);
});
test('parseCloudflaredVersion understands the official --version output', () => {
    assert.equal(parseCloudflaredVersion('cloudflared version 2026.10.5 (built 2026-10-27T06:05 UTC)\n'), '2026.10.5');
    assert.equal(parseCloudflaredVersion('cloudflared version 2025.4.0'), '2025.4.0');
    assert.equal(parseCloudflaredVersion('not a version'), null);
    assert.equal(parseCloudflaredVersion(''), null);
});
/* ------------------------------------------------------------------------- */
/* 2. argv + output parser                                                   */
/* ------------------------------------------------------------------------- */
test('cloudflared argv: quick tunnel forwards only the actual local URL', () => {
    const args = buildCloudflaredArgs({
        mode: 'quick',
        localUrl: 'http://127.0.0.1:47123',
        transport: 'auto',
    });
    assert.deepEqual(args, [
        'tunnel',
        '--no-autoupdate',
        '--protocol',
        'auto',
        '--url',
        'http://127.0.0.1:47123',
    ]);
    assert.ok(!args.some((arg) => arg.includes('dsh.example')), 'no operator origin becomes an argument');
    const http2 = buildCloudflaredArgs({ mode: 'quick', localUrl: 'http://127.0.0.1:1', transport: 'http2' });
    assert.deepEqual(http2.slice(0, 4), ['tunnel', '--no-autoupdate', '--protocol', 'http2']);
});
test('cloudflared argv: remotely-managed named tunnel keeps the token out of argv', () => {
    const envToken = buildCloudflaredArgs({
        mode: 'named',
        transport: 'quic',
        tokenSource: { kind: 'env', envName: 'CF_TUNNEL_TOKEN' },
    });
    assert.deepEqual(envToken, ['tunnel', '--no-autoupdate', '--protocol', 'quic', 'run']);
    const fileToken = buildCloudflaredArgs({
        mode: 'named',
        transport: 'auto',
        tokenSource: { kind: 'file', path: 'C:\\private\\tunnel.token' },
    });
    assert.deepEqual(fileToken, [
        'tunnel',
        '--no-autoupdate',
        '--protocol',
        'auto',
        'run',
        '--token-file',
        'C:\\private\\tunnel.token',
    ]);
});
test('cloudflared argv: locally-managed named tunnel uses the plugin-owned config and UUID', () => {
    const args = buildCloudflaredArgs({
        mode: 'named-local',
        transport: 'http2',
        configFile: '/home/user/.dsh/remote-control/runtime/cloudflared-abc.yml',
        tunnelId: '11111111-2222-3333-4444-555555555555',
    });
    assert.deepEqual(args, [
        'tunnel',
        '--no-autoupdate',
        '--protocol',
        'http2',
        '--config',
        '/home/user/.dsh/remote-control/runtime/cloudflared-abc.yml',
        'run',
        '11111111-2222-3333-4444-555555555555',
    ]);
});
test('output parser: fragmented quick-tunnel banner still yields the origin + registration', () => {
    const parser = createCloudflaredOutputParser({ mode: 'quick' });
    parser.push('INF Requesting new quick Tunnel on trycloudflare');
    parser.push('.com...\nINF +--------------------------------------+\nINF |  https://bases-switching-');
    parser.push('photography-garage.trycloudflare.com   |\n');
    assert.equal(parser.url(), 'https://bases-switching-photography-garage.trycloudflare.com');
    assert.equal(parser.connected(), false, 'URL alone is not a registered connection');
    parser.push('INF Registered tunnel connection connIndex=0 event=0\n');
    assert.equal(parser.connected(), true);
});
test('output parser: accepts only exact https://<label>.trycloudflare.com origins', () => {
    const cases = [
        ['https://ok-name.trycloudflare.com', 'https://ok-name.trycloudflare.com'],
        ['https://evil.example', null],
        ['https://ok.trycloudflare.com.evil.example', null],
        ['https://trycloudflare.com', null],
        ['http://ok.trycloudflare.com', null],
        ['https://ok.trycloudflare.com/path', null],
        ['https://user:pass@ok.trycloudflare.com', null],
        ['https://ok.trycloudflare.com:8443', null],
        ['https://UPPER.trycloudflare.com', 'https://upper.trycloudflare.com'],
    ];
    for (const [input, expected] of cases) {
        const parser = createCloudflaredOutputParser({ mode: 'quick' });
        parser.push(`INF visit it at ${input}\nINF Registered tunnel connection\n`);
        assert.equal(parser.url(), expected, `url for ${input}`);
    }
});
test('output parser: named connector readiness requires a started connector, not just a URL', () => {
    const parser = createCloudflaredOutputParser({ mode: 'named' });
    parser.push('INF Starting tunnel tunnelID=11111111-2222-3333-4444-555555555555\n');
    assert.equal(parser.connected(), false);
    parser.push('INF Initial protocol quic\n');
    assert.equal(parser.connected(), true);
    assert.equal(parser.protocol(), 'quic');
    const withRegistration = createCloudflaredOutputParser({ mode: 'named' });
    withRegistration.push('INF Starting tunnel tunnelID=x\nINF Registered tunnel connection connIndex=1\n');
    assert.equal(withRegistration.connected(), true);
});
test('output parser: bounded + sanitized error capture (no ANSI/newlines, capped length)', () => {
    const parser = createCloudflaredOutputParser({ mode: 'quick' });
    parser.push('\u001b[31mERR \u001b[0mRegister tunnel error from server side error="bad token"\n');
    const errors = parser.errors();
    assert.equal(errors.length, 1);
    const captured = errors[0];
    assert.ok(!captured.includes('\u001b'));
    assert.ok(!captured.includes('\n'));
    assert.ok(captured.length <= 240);
    for (let index = 0; index < 200; index += 1)
        parser.push(`noise line ${index}\n`);
    assert.ok(parser.text().length <= 16_384, 'retained output tail stays bounded');
});
/* ------------------------------------------------------------------------- */
/* 3. Discovery order: configured path -> PATH -> verified cache             */
/* ------------------------------------------------------------------------- */
test('discovery: configured path wins, its pinned digest marks it verified, and the probe env is minimal', async () => {
    const { release, asset } = testRelease(Buffer.from('official linux binary'));
    const spawned = probeSpawn();
    const installer = createCloudflaredInstaller(installerDeps({
        configuredPath: '/opt/official/cloudflared',
        release,
        spawn: spawned.spawn,
        fileExists: async () => true,
        hashFile: async () => asset.sha256,
        env: { PATH: '/usr/bin', DSH_SECRET: 'must-not-leak', CLOUDFLARE_API_TOKEN: 'nope', HTTPS_PROXY: 'http://p' },
    }));
    const resolved = await installer.resolve();
    assert.ok(resolved.installed !== null);
    assert.equal(resolved.installed.source, 'configured');
    assert.equal(resolved.installed.path, '/opt/official/cloudflared');
    assert.equal(resolved.installed.version, '2026.10.5');
    assert.equal(resolved.installed.verified, true);
    assert.equal(resolved.supported, true);
    const probe = spawned.calls.find((call) => call.args[0] === '--version');
    assert.ok(probe !== undefined);
    assert.equal(probe.options.env?.PATH, '/usr/bin');
    assert.equal(probe.options.env?.DSH_SECRET, undefined);
    assert.equal(probe.options.env?.CLOUDFLARE_API_TOKEN, undefined);
    assert.equal(probe.options.env?.HTTPS_PROXY, undefined);
});
test('discovery: an unusable configured path falls back to a PATH probe (unverified operator install)', async () => {
    const { release } = testRelease(Buffer.from('x'));
    const spawned = probeSpawn();
    const installer = createCloudflaredInstaller(installerDeps({
        configuredPath: '/nope/cloudflared',
        release,
        spawn: spawned.spawn,
        fileExists: async () => false,
    }));
    const resolved = await installer.resolve();
    assert.ok(resolved.installed !== null);
    assert.equal(resolved.installed.source, 'path');
    assert.equal(resolved.installed.path, 'cloudflared');
    assert.equal(resolved.installed.verified, false);
    assert.ok(spawned.calls.some((call) => call.command === 'cloudflared'));
});
test('discovery: no configured/PATH binary falls back to the verified cache only', async () => {
    const executable = Buffer.from('cached official bytes');
    const { release, asset } = testRelease(executable);
    const cacheDir = join(root, 'cache-verified');
    await mkdir(cacheDir, { recursive: true });
    const cachedPath = join(cacheDir, cacheFileName(release, asset));
    await writeFile(cachedPath, executable);
    const installer = createCloudflaredInstaller(installerDeps({
        release,
        cacheDir,
        spawn: makeSpawn(() => makeCommandChild({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }) })).spawn,
    }));
    const resolved = await installer.resolve();
    assert.ok(resolved.installed !== null);
    assert.equal(resolved.installed.source, 'cache');
    assert.equal(resolved.installed.path, cachedPath);
    assert.equal(resolved.installed.verified, true);
    assert.equal(resolved.installed.version, '2026.10.5');
});
test('discovery: a corrupt cache file is deleted, never reported as usable', async () => {
    const executable = Buffer.from('real bytes');
    const { release, asset } = testRelease(executable);
    const cacheDir = join(root, 'cache-corrupt');
    await mkdir(cacheDir, { recursive: true });
    const cachedPath = join(cacheDir, cacheFileName(release, asset));
    await writeFile(cachedPath, Buffer.from('tampered bytes'));
    const logged = [];
    const log = silentLogger();
    log.warn = (message) => logged.push(message);
    const installer = createCloudflaredInstaller(installerDeps({
        release,
        cacheDir,
        log,
        spawn: makeSpawn(() => makeCommandChild({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }) })).spawn,
    }));
    const resolved = await installer.resolve();
    assert.equal(resolved.installed, null);
    assert.deepEqual(await readdir(cacheDir), []);
    assert.ok(logged.length >= 1, 'corrupt cache is reported (without digest content)');
});
/* ------------------------------------------------------------------------- */
/* 3b. Ordered configured candidates (desktop selection override)            */
/* ------------------------------------------------------------------------- */
test('discovery: an ordered configured candidate list is tried in order before PATH/cache', async () => {
    const { release, asset } = testRelease(Buffer.from('override binary'));
    const spawned = probeSpawn();
    const installer = createCloudflaredInstaller(installerDeps({
        configuredPath: '/config/cloudflared',
        release,
        spawn: spawned.spawn,
        fileExists: async (path) => path === '/opt/second',
        hashFile: async () => asset.sha256,
    }));
    const resolved = await installer.resolve(['/opt/first', '/opt/second']);
    assert.equal(resolved.installed?.path, '/opt/second');
    assert.equal(resolved.installed?.source, 'configured');
    assert.equal(resolved.installed?.verified, true);
    const probeCommands = spawned.calls.filter((call) => call.args[0] === '--version').map((call) => call.command);
    assert.deepEqual(probeCommands, ['/opt/second'], 'candidates are tried in order; missing ones are skipped');
    assert.ok(!spawned.calls.some((call) => call.command === '/config/cloudflared'), 'the config path is not consulted');
});
test('discovery: an unusable ordered candidate list falls back to PATH and then the verified cache', async () => {
    const { release } = testRelease(Buffer.from('x'));
    const spawned = probeSpawn();
    const installer = createCloudflaredInstaller(installerDeps({
        configuredPath: '/config/cloudflared',
        release,
        spawn: spawned.spawn,
        fileExists: async () => false,
    }));
    const resolved = await installer.resolve(['/opt/first', '/opt/second']);
    assert.equal(resolved.installed?.source, 'path');
    assert.equal(resolved.installed?.path, 'cloudflared');
    assert.ok(spawned.calls.some((call) => call.command === 'cloudflared'));
});
test('info: an ordered candidate list changes the disclosed installed binary', async () => {
    const { release, asset } = testRelease(Buffer.from('cached'));
    const cacheDir = join(root, 'cache-ordered-info');
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, cacheFileName(release, asset)), Buffer.from('cached'));
    const selectionPath = '/opt/selection/cloudflared';
    // Only the explicitly selected candidate is executable; PATH is absent.
    const spawned = makeSpawn((call) => call.command === selectionPath && call.args[0] === '--version'
        ? makeCommandChild({ code: 0, stderr: 'cloudflared version 2026.10.5 (built 2026-10-27T06:05 UTC)\n' })
        : makeCommandChild({ error: Object.assign(new Error('not found'), { code: 'ENOENT' }) }));
    const installer = createCloudflaredInstaller(installerDeps({
        release,
        cacheDir,
        spawn: spawned.spawn,
        fileExists: async (path) => path === selectionPath,
        hashFile: async () => asset.sha256,
    }));
    const withoutOverride = await installer.info();
    assert.equal(withoutOverride.installed?.source, 'cache', 'the verified cache is disclosed without an override');
    assert.equal(withoutOverride.installed?.verified, true);
    const withList = await installer.info(['/opt/missing/cloudflared', selectionPath]);
    assert.equal(withList.installed?.path, selectionPath);
    assert.equal(withList.installed?.source, 'configured');
    assert.equal(withList.installed?.verified, true);
    assert.deepEqual(spawned.calls.filter((call) => call.args[0] === '--version').map((call) => call.command), ['cloudflared', selectionPath], 'the default PATH probe happens first; the ordered candidates are then tried in order');
});
/* ------------------------------------------------------------------------- */
/* 4. install(): user-initiated, HTTPS + redirect validation, digest, atomic */
/* ------------------------------------------------------------------------- */
test('install: downloads over HTTPS, verifies the pinned digest and atomically caches the executable', async () => {
    const executable = Buffer.from('official cloudflared binary bytes');
    const { release, asset } = testRelease(executable);
    const cacheDir = join(root, 'cache-install-ok');
    const fetchFake = makeFetch((call) => call.url === 'https://github.com/cloudflare/cloudflared/releases/download/2026.10.5/cloudflared-linux-amd64'
        ? fakeResponse(executable)
        : new Response(null, { status: 404 }));
    const installer = createCloudflaredInstaller(installerDeps({ release, cacheDir, fetch: fetchFake.fetch, spawn: noBinarySpawn().spawn }));
    const info = await installer.install();
    assert.equal(info.supported, true);
    assert.equal(info.installed?.source, 'cache');
    assert.equal(info.installed?.verified, true);
    const cachedPath = join(cacheDir, cacheFileName(release, asset));
    assert.deepEqual(await readFile(cachedPath), executable);
    assert.equal(await stat(cachedPath).then((entry) => entry.isFile()), true);
    // No temporary download artifacts are left behind.
    assert.deepEqual((await readdir(cacheDir)).sort(), [cacheFileName(release, asset)].sort());
    assert.equal(fetchFake.calls.length, 1);
    assert.equal(fetchFake.calls[0].redirect, 'manual', 'redirects are followed manually and validated');
});
test('install: a checksum mismatch deletes the download and never caches or executes it', async () => {
    const executable = Buffer.from('expected bytes');
    const { release } = testRelease(executable);
    const cacheDir = join(root, 'cache-bad-digest');
    const fetchFake = makeFetch(() => fakeResponse(Buffer.from('tampered payload of some length')));
    const installer = createCloudflaredInstaller(installerDeps({ release, cacheDir, fetch: fetchFake.fetch, spawn: noBinarySpawn().spawn }));
    await expectTunnelError(() => installer.install(), 'CHECKSUM_MISMATCH');
    assert.deepEqual(await readdir(cacheDir), [], 'nothing is cached after a digest mismatch');
    assert.equal((await installer.info()).installed, null);
});
test('install: unsupported platform fails closed with UNSUPPORTED_PLATFORM and makes no request', async () => {
    const fetchFake = makeFetch(() => new Response('nope', { status: 500 }));
    const installer = createCloudflaredInstaller(installerDeps({ platform: 'freebsd', fetch: fetchFake.fetch, spawn: noBinarySpawn().spawn }));
    const info = await installer.info();
    assert.equal(info.supported, false);
    const error = await expectTunnelError(() => installer.install(), 'UNSUPPORTED_PLATFORM');
    assert.ok(!error.message.toLowerCase().includes('sha'), 'no fabricated hash is shown');
    assert.equal(fetchFake.calls.length, 0, 'no download is attempted without pinned metadata');
});
test('install: redirect targets must stay on GitHub-controlled HTTPS hosts', async () => {
    const executable = Buffer.from('bytes');
    const { release } = testRelease(executable);
    const evil = makeFetch(() => redirectResponse('https://evil.example/inject/cloudflared'));
    const cacheDir = join(root, 'cache-redirect-evil');
    await expectTunnelError(() => createCloudflaredInstaller(installerDeps({ release, cacheDir, fetch: evil.fetch, spawn: noBinarySpawn().spawn })).install(), 'BAD_REQUEST');
    assert.deepEqual(await readdir(cacheDir), []);
    const insecure = makeFetch(() => redirectResponse('http://objects.githubusercontent.com/x'));
    await expectTunnelError(() => createCloudflaredInstaller(installerDeps({ release, cacheDir: `${cacheDir}-2`, fetch: insecure.fetch, spawn: noBinarySpawn().spawn })).install(), 'BAD_REQUEST');
    // A validated redirect must become the next requested URL (not be re-requested
    // from the pinned URL). The fake is keyed by URL so call-order cannot hide a
    // missing currentUrl update.
    const pinnedUrl = 'https://github.com/cloudflare/cloudflared/releases/download/2026.10.5/cloudflared-linux-amd64';
    const assetUrl = 'https://objects.githubusercontent.com/signed/cloudflared';
    const allowed = makeFetch((call) => {
        if (call.url === pinnedUrl)
            return redirectResponse(assetUrl);
        if (call.url === assetUrl)
            return fakeResponse(executable);
        return new Response(null, { status: 404 });
    });
    const ok = await createCloudflaredInstaller(installerDeps({ release, cacheDir: `${cacheDir}-3`, fetch: allowed.fetch, spawn: noBinarySpawn().spawn })).install();
    assert.equal(ok.installed?.verified, true);
    assert.deepEqual(allowed.calls.map((call) => call.url), [pinnedUrl, assetUrl], 'the validated redirect target must be the next request');
    // A second hop is followed too, still bounded by maxRedirects.
    const secondHop = 'https://release-assets.githubusercontent.com/github-production/cloudflared';
    const chained = makeFetch((call) => {
        if (call.url === pinnedUrl)
            return redirectResponse(assetUrl);
        if (call.url === assetUrl)
            return redirectResponse(secondHop);
        if (call.url === secondHop)
            return fakeResponse(executable);
        return new Response(null, { status: 404 });
    });
    const chainedOk = await createCloudflaredInstaller(installerDeps({ release, cacheDir: `${cacheDir}-4`, fetch: chained.fetch, spawn: noBinarySpawn().spawn })).install();
    assert.equal(chainedOk.installed?.verified, true);
    assert.deepEqual(chained.calls.map((call) => call.url), [pinnedUrl, assetUrl, secondHop]);
});
test('install: declared size and streamed byte budget are enforced', async () => {
    const executable = Buffer.from('small');
    const { release } = testRelease(executable);
    const cacheDir = join(root, 'cache-size');
    const wrongLength = makeFetch(() => {
        const response = fakeResponse(executable);
        response.headers.set('content-length', String(executable.length + 1));
        return response;
    });
    await expectTunnelError(() => createCloudflaredInstaller(installerDeps({ release, cacheDir, fetch: wrongLength.fetch, spawn: noBinarySpawn().spawn })).install(), 'CHECKSUM_MISMATCH');
    const oversized = makeFetch(() => fakeResponse(Buffer.concat([executable, Buffer.alloc(1024)])));
    await expectTunnelError(() => createCloudflaredInstaller(installerDeps({ release, cacheDir: `${cacheDir}-2`, fetch: oversized.fetch, spawn: noBinarySpawn().spawn })).install(), 'CHECKSUM_MISMATCH');
});
test('install: temp download failures leave the cache directory clean', async () => {
    const executable = Buffer.from('expected');
    const { release } = testRelease(executable);
    const cacheDir = join(root, 'cache-fetch-fail');
    const fetchFake = makeFetch(() => {
        throw new Error('network down');
    });
    const installer = createCloudflaredInstaller(installerDeps({ release, cacheDir, fetch: fetchFake.fetch, spawn: noBinarySpawn().spawn }));
    await assert.rejects(() => installer.install());
    assert.deepEqual(await readdir(cacheDir), []);
});
/* ------------------------------------------------------------------------- */
/* 5. Archive downloads: verify before extraction, safe extractor            */
/* ------------------------------------------------------------------------- */
test('install: darwin-style tgz is verified before extraction and the inner binary is verified too', async () => {
    const executable = Buffer.from('#!/bin/sh\n# extracted cloudflared\n');
    const tarball = buildTarGz([{ name: 'cloudflared', data: executable }]);
    const { release, asset } = testRelease(executable, {
        platform: 'darwin',
        arch: 'arm64',
        asset: 'cloudflared-darwin-arm64.tgz',
        archive: 'tgz',
        sizeBytes: tarball.length,
        sha256: sha256(tarball),
        binarySha256: sha256(executable),
        binarySizeBytes: executable.length,
    });
    const cacheDir = join(root, 'cache-tgz');
    const fetchFake = makeFetch(() => fakeResponse(tarball));
    const installer = createCloudflaredInstaller(installerDeps({ release, cacheDir, platform: 'darwin', arch: 'arm64', fetch: fetchFake.fetch, spawn: noBinarySpawn().spawn }));
    const info = await installer.install();
    assert.equal(info.installed?.verified, true);
    const cachedPath = join(cacheDir, cacheFileName(release, asset));
    assert.deepEqual(await readFile(cachedPath), executable);
    assert.deepEqual((await readdir(cacheDir)).sort(), [cacheFileName(release, asset)].sort());
});
test('install: inner binary digest mismatch after extraction never reaches the cache', async () => {
    const executable = Buffer.from('archive executable');
    const tarball = buildTarGz([{ name: 'cloudflared', data: executable }]);
    const { release } = testRelease(executable, {
        platform: 'darwin',
        arch: 'arm64',
        asset: 'cloudflared-darwin-arm64.tgz',
        archive: 'tgz',
        sizeBytes: tarball.length,
        sha256: sha256(tarball),
        binarySha256: sha256('a different pinned binary'),
    });
    const cacheDir = join(root, 'cache-tgz-bad-inner');
    const installer = createCloudflaredInstaller(installerDeps({
        release,
        cacheDir,
        platform: 'darwin',
        arch: 'arm64',
        fetch: makeFetch(() => fakeResponse(tarball)).fetch,
        spawn: noBinarySpawn().spawn,
    }));
    await expectTunnelError(() => installer.install(), 'CHECKSUM_MISMATCH');
    assert.deepEqual(await readdir(cacheDir), []);
});
test('extraction: tar traversal and symlink escape entries are refused before writing anything', async () => {
    const executable = Buffer.from('cloudflared');
    const cases = [
        ['parent traversal', buildTarGz([
                { name: '../../evil.txt', data: Buffer.from('pwn') },
                { name: 'cloudflared', data: executable },
            ])],
        ['symlink entry', buildTarGz([
                { name: 'cloudflared', type: '2', linkName: '../../../etc/passwd' },
            ])],
        ['hardlink entry', buildTarGz([{ name: 'cloudflared', type: '1', linkName: '/etc/shadow' }])],
    ];
    for (const [label, tarball] of cases) {
        const { release } = testRelease(executable, {
            platform: 'darwin',
            arch: 'arm64',
            asset: 'cloudflared-darwin-arm64.tgz',
            archive: 'tgz',
            sizeBytes: tarball.length,
            sha256: sha256(tarball),
            binarySha256: sha256(executable),
        });
        const cacheDir = join(root, `cache-attack-${label.replace(/\s+/g, '-')}`);
        const installer = createCloudflaredInstaller(installerDeps({
            release,
            cacheDir,
            platform: 'darwin',
            arch: 'arm64',
            fetch: makeFetch(() => fakeResponse(tarball)).fetch,
            spawn: noBinarySpawn().spawn,
        }));
        const error = await expectTunnelError(() => installer.install(), 'BAD_REQUEST');
        assert.ok(error.message.length > 0);
        assert.deepEqual(await readdir(cacheDir), [], `${label}: cache stays empty`);
        await assert.rejects(() => readFile(join(root, 'evil.txt')), /ENOENT/);
    }
});
test('extraction: zip traversal, absolute paths and symlink entries are refused', async () => {
    const executable = Buffer.from('cloudflared');
    const cases = [
        ['dotdot', buildZip([{ name: '../evil.txt', data: Buffer.from('pwn') }, { name: 'cloudflared', data: executable }])],
        ['absolute', buildZip([{ name: '/tmp/evil.txt', data: Buffer.from('pwn') }, { name: 'cloudflared', data: executable }])],
        ['backslash', buildZip([{ name: '..\\evil.txt', data: Buffer.from('pwn') }, { name: 'cloudflared', data: executable }])],
        ['symlink', buildZip([{ name: 'cloudflared', symlink: true }])],
    ];
    for (const [label, archive] of cases) {
        const { release } = testRelease(executable, {
            platform: 'darwin',
            arch: 'x64',
            asset: 'cloudflared-darwin-amd64.tgz',
            archive: 'zip',
            sizeBytes: archive.length,
            sha256: sha256(archive),
            binarySha256: sha256(executable),
        });
        const cacheDir = join(root, `cache-zip-attack-${label}`);
        const installer = createCloudflaredInstaller(installerDeps({
            release,
            cacheDir,
            platform: 'darwin',
            arch: 'x64',
            fetch: makeFetch(() => fakeResponse(archive)).fetch,
            spawn: noBinarySpawn().spawn,
        }));
        await expectTunnelError(() => installer.install(), 'BAD_REQUEST');
        assert.deepEqual(await readdir(cacheDir), []);
    }
});
test('extraction: a valid zip yields exactly the expected executable', async () => {
    const executable = Buffer.from('zip executable bytes');
    const archive = buildZip([
        { name: 'cloudflared', data: executable },
        { name: 'README.md', data: Buffer.from('docs') },
    ]);
    const { release, asset } = testRelease(executable, {
        platform: 'darwin',
        arch: 'x64',
        asset: 'cloudflared-darwin-amd64.tgz',
        archive: 'zip',
        sizeBytes: archive.length,
        sha256: sha256(archive),
        binarySha256: sha256(executable),
        binarySizeBytes: executable.length,
    });
    const cacheDir = join(root, 'cache-zip-ok');
    const installer = createCloudflaredInstaller(installerDeps({
        release,
        cacheDir,
        platform: 'darwin',
        arch: 'x64',
        fetch: makeFetch(() => fakeResponse(archive)).fetch,
        spawn: noBinarySpawn().spawn,
    }));
    const info = await installer.install();
    assert.equal(info.installed?.verified, true);
    assert.deepEqual(await readFile(join(cacheDir, cacheFileName(release, asset))), executable);
});
/* ------------------------------------------------------------------------- */
/* 6. info(): disclosure without side effects or network                     */
/* ------------------------------------------------------------------------- */
test('info: reports the pinned download plan without fetching, downloading or spawning anything', async () => {
    const fetchFake = makeFetch(() => {
        throw new Error('info must not fetch');
    });
    const spawned = noBinarySpawn();
    const installer = createCloudflaredInstaller(installerDeps({ fetch: fetchFake.fetch, spawn: spawned.spawn }));
    const info = await installer.info();
    assert.equal(info.version, '2026.10.5');
    assert.equal(info.asset, 'cloudflared-linux-amd64');
    assert.equal(info.sha256, 'e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298');
    assert.equal(info.sizeBytes, 40_263_303);
    assert.equal(info.releaseUrl, 'https://github.com/cloudflare/cloudflared/releases/download/2026.10.5/cloudflared-linux-amd64');
    assert.equal(info.supported, true);
    assert.equal(info.installed, null);
    assert.equal(fetchFake.calls.length, 0);
    // Only the PATH discovery probe may run; install() itself is user initiated.
    assert.ok(spawned.calls.every((call) => call.args[0] === '--version'));
});
test('info: an already verified cache binary is disclosed with its source and version', async () => {
    const executable = Buffer.from('cached');
    const { release, asset } = testRelease(executable);
    const cacheDir = join(root, 'cache-info');
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, cacheFileName(release, asset)), executable);
    const installer = createCloudflaredInstaller(installerDeps({
        release,
        cacheDir,
        spawn: makeSpawn(() => makeCommandChild({ error: Object.assign(new Error('missing'), { code: 'ENOENT' }) })).spawn,
    }));
    const info = await installer.info();
    assert.equal(info.installed?.source, 'cache');
    assert.equal(info.installed?.verified, true);
});
