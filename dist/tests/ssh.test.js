/**
 * SSH/localhost.run provider lane.
 *
 * FAILING-FIRST: this file is written before `src/ssh.ts` exists. It pins the
 * hardened OpenSSH invocation (no shell, no user config, plugin-owned known
 * hosts, no agent forwarding, no interactive prompts, no `-N`), the strict
 * provider-domain allowlist for the printed HTTPS origin, bounded/fragmented
 * output parsing and the child lifecycle (timeout, early exit, kill escalation).
 *
 * No real ssh process and no network are used: spawn is a fake seam.
 */
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { buildSshArgs, createSshOutputParser, createSshTunnel, discoverSsh, ensureKnownHosts, normalizeProviderUrl, normalizeSshHost, normalizeSshUser, validateSshRemotePort, } from '../src/ssh.js';
import { TunnelError } from '../src/tunnel-errors.js';
function silentLogger() {
    return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined };
}
let root = '';
before(async () => {
    root = await mkdtemp(join(tmpdir(), 'dsh-rc-ssh-'));
});
after(async () => {
    if (root !== '')
        await rm(root, { recursive: true, force: true });
});
function makeControllableChild() {
    const child = new EventEmitter();
    const stdout = new EventEmitter();
    const stderr = new EventEmitter();
    const killed = [];
    const state = {
        child,
        killed,
        killMode: 'exit-on-term',
        emitStdout: (text) => stdout.emit('data', text),
        emitStderr: (text) => stderr.emit('data', text),
        exit: (code, signal = null) => {
            Object.assign(child, { exitCode: code, signalCode: signal });
            child.emit('exit', code, signal);
        },
    };
    Object.assign(child, {
        stdout,
        stderr,
        exitCode: null,
        signalCode: null,
        kill: (signal) => {
            const effective = signal ?? 'SIGTERM';
            killed.push(effective);
            if (state.killMode === 'exit-on-term' && effective === 'SIGTERM') {
                setImmediate(() => state.exit(null, 'SIGTERM'));
            }
            else if (state.killMode === 'exit-on-kill' && effective === 'SIGKILL') {
                setImmediate(() => state.exit(null, 'SIGKILL'));
            }
            return true;
        },
    });
    return state;
}
function makeSpawn(handler) {
    const calls = [];
    const spawn = (command, args, options) => {
        const call = { command, args, options: options };
        calls.push(call);
        return handler(call);
    };
    return { spawn, calls };
}
function makeVersionChild(version = 'OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2') {
    const child = new EventEmitter();
    const stderr = new EventEmitter();
    Object.assign(child, {
        stdout: new EventEmitter(),
        stderr,
        exitCode: null,
        signalCode: null,
        kill: () => true,
    });
    setImmediate(() => {
        ;
        stderr.emit('data', `${version}\n`);
        Object.assign(child, { exitCode: 0 });
        child.emit('exit', 0, null);
    });
    return child;
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
/* ------------------------------------------------------------------------- */
/* Hardened invocation                                                       */
/* ------------------------------------------------------------------------- */
test('ssh argv: exact hardened reverse-forward invocation, no -N, no shell, no agent forwarding', () => {
    const args = buildSshArgs({
        sshHost: 'localhost.run',
        sshUser: 'nokey',
        sshRemotePort: 80,
        localPort: 47_123,
        knownHostsFile: 'C:\\Users\\u\\.dsh\\remote-control\\ssh\\known_hosts',
    });
    assert.equal(args[0], '-F');
    assert.equal(args[1], 'none', 'the user ~/.ssh/config is never read');
    assert.ok(args.includes('-R'));
    assert.equal(args[args.indexOf('-R') + 1], '80:127.0.0.1:47123');
    assert.equal(args[args.length - 1], 'nokey@localhost.run');
    assert.ok(!args.includes('-N'), 'localhost.run suppresses the URL with -N');
    assert.ok(!args.some((arg) => /ClearAllForwardings/i.test(arg)));
    assert.ok(!args.includes('-A'), 'agent forwarding is disabled');
    assert.ok(!args.some((arg) => /^ProxyCommand=/i.test(arg)), 'the user ProxyCommand is never used');
    const option = (name) => {
        const found = args.find((arg) => arg.toLowerCase().startsWith(`${name.toLowerCase()}=`));
        return found?.slice(found.indexOf('=') + 1);
    };
    assert.equal(option('batchmode'), 'yes');
    assert.equal(option('stricthostkeychecking'), 'accept-new');
    assert.equal(option('userknownhostsfile'), 'C:\\Users\\u\\.dsh\\remote-control\\ssh\\known_hosts');
    assert.equal(option('exitonforwardfailure'), 'yes');
    assert.equal(option('serveraliveinterval'), '30');
    assert.equal(option('serveralivecountmax'), '3');
    assert.equal(option('forwardagent'), 'no');
    assert.equal(option('forwardx11'), 'no');
    assert.equal(option('permitlocalcommand'), 'no');
    assert.equal(option('identitiesonly'), 'yes');
    assert.equal(option('connecttimeout'), '15');
});
test('ssh argv: provider host/user/remote-port allowlists fail closed', () => {
    assert.equal(normalizeSshHost('localhost.run'), 'localhost.run');
    assert.equal(normalizeSshHost('LOCALHOST.RUN'), 'localhost.run');
    assert.equal(normalizeSshHost('evil.example'), null);
    assert.equal(normalizeSshHost('localhost.run.evil.example'), null);
    assert.equal(normalizeSshHost('localhost.run@evil'), null);
    assert.equal(normalizeSshUser('nokey'), 'nokey');
    assert.equal(normalizeSshUser('root'), null);
    assert.equal(validateSshRemotePort(80), 80);
    assert.equal(validateSshRemotePort(443), 443);
    assert.equal(validateSshRemotePort(1234), null);
    assert.equal(validateSshRemotePort(0), null);
    assert.throws(() => buildSshArgs({
        sshHost: 'evil.example',
        sshUser: 'nokey',
        sshRemotePort: 80,
        localPort: 1,
        knownHostsFile: '/tmp/kh',
    }), (error) => error instanceof TunnelError && error.code === 'BAD_REQUEST');
});
/* ------------------------------------------------------------------------- */
/* Provider URL allowlist + fragmented parsing                               */
/* ------------------------------------------------------------------------- */
test('provider URL: accepts only verified localhost.run-family HTTPS origins', () => {
    assert.equal(normalizeProviderUrl('https://fdbf4f40573d56.lhr.life'), 'https://fdbf4f40573d56.lhr.life');
    assert.equal(normalizeProviderUrl('https://abc.localhost.run'), 'https://abc.localhost.run');
    assert.equal(normalizeProviderUrl('HTTPS://ABC.LHR.LIFE'), 'https://abc.lhr.life');
    assert.equal(normalizeProviderUrl('https://evil.example'), null);
    assert.equal(normalizeProviderUrl('https://abc.lhr.life.evil.example'), null);
    assert.equal(normalizeProviderUrl('https://lhr.life'), null);
    assert.equal(normalizeProviderUrl('http://abc.lhr.life'), null);
    assert.equal(normalizeProviderUrl('https://abc.lhr.life/path'), null);
    assert.equal(normalizeProviderUrl('https://user:pass@abc.lhr.life'), null);
    assert.equal(normalizeProviderUrl('https://abc.lhr.life:8443'), null);
    assert.equal(normalizeProviderUrl('https://abc.lhr.life?x=1'), null);
});
test('ssh output parser: URL on stdout is found across fragmented chunks', () => {
    const parser = createSshOutputParser();
    parser.push('fdbf4f40573d56.lhr.life tunneled with tls termination, https://fdbf4f405');
    assert.equal(parser.url(), null);
    parser.push('73d56.lhr.life\ncreate an account and add your key');
    assert.equal(parser.url(), 'https://fdbf4f40573d56.lhr.life');
    assert.equal(parser.connectionLost(), false);
});
test('ssh output parser: rejects non-provider URLs printed in the banner', () => {
    const parser = createSshOutputParser();
    parser.push('read https://localhost.run/docs/forever-free/ for more\n');
    parser.push('visit https://evil.example/rc for a tunnel\n');
    assert.equal(parser.url(), null);
    parser.push('connect https://okname.lhr.life\n');
    assert.equal(parser.url(), 'https://okname.lhr.life');
});
test('ssh output parser: detects connection loss and keeps output bounded', () => {
    const parser = createSshOutputParser();
    parser.push('Connection to localhost.run closed by remote host.\n');
    assert.equal(parser.connectionLost(), true);
    for (let index = 0; index < 500; index += 1)
        parser.push(`banner line ${index}\n`);
    assert.ok(parser.text().length <= 16_384);
});
/* ------------------------------------------------------------------------- */
/* Discovery + plugin-owned known_hosts                                      */
/* ------------------------------------------------------------------------- */
test('discoverSsh: explicit configured executable is probed with -V and minimal env', async () => {
    const spawned = makeSpawn(() => makeVersionChild());
    const found = await discoverSsh({
        configuredPath: 'C:\\OpenSSH\\ssh.exe',
        platform: 'win32',
        spawn: spawned.spawn,
        log: silentLogger(),
        fileExists: async () => true,
        env: { PATH: 'C:\\Windows', DSH_SECRET: 'nope', SSH_AUTH_SOCK: 'agent-socket' },
    });
    assert.equal(found.path, 'C:\\OpenSSH\\ssh.exe');
    assert.match(found.version ?? '', /OpenSSH/);
    assert.equal(spawned.calls.length, 1);
    assert.equal(spawned.calls[0].command, 'C:\\OpenSSH\\ssh.exe');
    assert.deepEqual(spawned.calls[0].args, ['-V']);
    assert.equal(spawned.calls[0].options.env?.PATH, 'C:\\Windows');
    assert.equal(spawned.calls[0].options.env?.DSH_SECRET, undefined);
    assert.equal(spawned.calls[0].options.env?.SSH_AUTH_SOCK, undefined);
});
test('discoverSsh: uses the OS-shipped Windows OpenSSH path before PATH', async () => {
    const spawned = makeSpawn(() => makeVersionChild());
    const found = await discoverSsh({
        configuredPath: 'ssh',
        platform: 'win32',
        spawn: spawned.spawn,
        log: silentLogger(),
        fileExists: async (path) => path.toLowerCase() === 'c:\\windows\\system32\\openssh\\ssh.exe',
        windir: 'C:\\Windows',
    });
    assert.equal(found.path, 'C:\\Windows\\System32\\OpenSSH\\ssh.exe');
});
test('discoverSsh: a missing ssh client fails with SSH_MISSING and is never downloaded', async () => {
    const spawned = makeSpawn(() => makeMissingChild());
    await expectTunnelError(() => discoverSsh({
        configuredPath: 'ssh',
        platform: 'linux',
        spawn: spawned.spawn,
        log: silentLogger(),
        fileExists: async () => false,
    }), 'SSH_MISSING');
    assert.ok(spawned.calls.every((call) => call.args[0] === '-V'));
});
function makeMissingChild() {
    const child = new EventEmitter();
    Object.assign(child, {
        stdout: new EventEmitter(),
        stderr: new EventEmitter(),
        exitCode: null,
        signalCode: null,
        kill: () => true,
    });
    setImmediate(() => child.emit('error', Object.assign(new Error('spawn ssh ENOENT'), { code: 'ENOENT' })));
    return child;
}
test('ensureKnownHosts: creates a plugin-private directory outside ~/.ssh and refuses symlinks', async (t) => {
    const managedDir = join(root, 'known-hosts-ok');
    const first = await ensureKnownHosts(managedDir);
    assert.equal(first.knownHostsFile, join(managedDir, 'ssh', 'known_hosts'));
    assert.ok(!first.knownHostsFile.includes('.ssh'), 'never touches the user known_hosts');
    assert.deepEqual(await readdir(join(managedDir, 'ssh')), []);
    if (process.platform !== 'win32') {
        assert.equal((await stat(join(managedDir, 'ssh'))).mode & 0o777, 0o700);
    }
    const symlinkRoot = join(root, 'known-hosts-symlink');
    const sshDir = join(symlinkRoot, 'ssh');
    await mkdir(sshDir, { recursive: true });
    const target = join(root, 'attacker-known-hosts');
    await writeFile(target, 'evil');
    try {
        await symlink(target, join(sshDir, 'known_hosts'));
    }
    catch {
        t.skip('creating symlinks is not permitted on this host');
        return;
    }
    await expectTunnelError(() => ensureKnownHosts(symlinkRoot), 'BAD_REQUEST');
});
/* ------------------------------------------------------------------------- */
/* Child lifecycle                                                           */
/* ------------------------------------------------------------------------- */
test('ssh tunnel: start resolves with the provider URL from fragmented stdout and spawns a hardened argv', async () => {
    const child = makeControllableChild();
    const spawned = makeSpawn(() => child.child);
    const tunnel = createSshTunnel({
        executable: 'ssh',
        sshHost: 'localhost.run',
        sshUser: 'nokey',
        sshRemotePort: 80,
        localPort: 47_123,
        knownHostsFile: join(root, 'kh', 'known_hosts'),
        spawn: spawned.spawn,
        log: silentLogger(),
        env: { PATH: '/usr/bin', DSH_TOKEN: 'nope', SSH_AUTH_SOCK: 'agent' },
        startupTimeoutMs: 1_000,
        killGraceMs: 50,
    });
    const started = tunnel.start();
    child.emitStdout('fdbf4f40573d56.lhr.life tunneled with ');
    child.emitStdout('tls termination, https://fdbf4f40573d56.lhr.life\n');
    const { url } = await started;
    assert.equal(url, 'https://fdbf4f40573d56.lhr.life');
    assert.equal(spawned.calls.length, 1);
    const call = spawned.calls[0];
    assert.equal(call.command, 'ssh');
    const remoteIndex = call.args.indexOf('-R');
    assert.equal(call.args[remoteIndex + 1], '80:127.0.0.1:47123');
    assert.equal(call.args[call.args.length - 1], 'nokey@localhost.run');
    assert.equal(call.options.shell, undefined, 'never uses a shell');
    assert.equal(call.options.env?.PATH, '/usr/bin');
    assert.equal(call.options.env?.DSH_TOKEN, undefined);
    assert.equal(call.options.env?.SSH_AUTH_SOCK, undefined);
    assert.equal(tunnel.url, url);
    await tunnel.stop();
});
test('ssh tunnel: early exit before the URL is announced rejects with a safe error', async () => {
    const child = makeControllableChild();
    const tunnel = createSshTunnel({
        executable: 'ssh',
        sshHost: 'localhost.run',
        sshUser: 'nokey',
        sshRemotePort: 80,
        localPort: 1,
        knownHostsFile: join(root, 'kh2', 'known_hosts'),
        spawn: makeSpawn(() => child.child).spawn,
        log: silentLogger(),
        startupTimeoutMs: 1_000,
        killGraceMs: 50,
    });
    const started = tunnel.start();
    child.emitStderr('Permission denied (publickey).\n');
    child.exit(255);
    const error = await expectTunnelError(() => started, 'INTERNAL');
    assert.ok(!/token|secret/i.test(error.message));
});
test('ssh tunnel: startup timeout kills the child (SIGTERM then SIGKILL escalation)', async () => {
    const child = makeControllableChild();
    child.killMode = 'ignore-term';
    const tunnel = createSshTunnel({
        executable: 'ssh',
        sshHost: 'localhost.run',
        sshUser: 'nokey',
        sshRemotePort: 80,
        localPort: 1,
        knownHostsFile: join(root, 'kh3', 'known_hosts'),
        spawn: makeSpawn(() => child.child).spawn,
        log: silentLogger(),
        startupTimeoutMs: 30,
        killGraceMs: 20,
    });
    const error = await expectTunnelError(() => tunnel.start(), 'INTERNAL');
    assert.match(error.message, /did not announce/i);
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.deepEqual(child.killed, ['SIGTERM', 'SIGKILL']);
});
test('ssh tunnel: unexpected connection loss calls the exit handler; stop is idempotent', async () => {
    const child = makeControllableChild();
    const tunnel = createSshTunnel({
        executable: 'ssh',
        sshHost: 'localhost.run',
        sshUser: 'nokey',
        sshRemotePort: 80,
        localPort: 1,
        knownHostsFile: join(root, 'kh4', 'known_hosts'),
        spawn: makeSpawn(() => child.child).spawn,
        log: silentLogger(),
        startupTimeoutMs: 1_000,
        killGraceMs: 20,
    });
    let lossDetail = '';
    tunnel.setExitHandler((detail) => {
        lossDetail = detail;
    });
    const started = tunnel.start();
    child.emitStdout('https://fdbf4f40573d56.lhr.life\n');
    await started;
    child.exit(255);
    await new Promise((resolve) => setImmediate(resolve));
    assert.match(lossDetail, /exit/i);
    await tunnel.stop();
    await tunnel.stop();
});
