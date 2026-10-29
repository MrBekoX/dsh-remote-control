/**
 * SSH / localhost.run provider.
 *
 * Security posture:
 * - OpenSSH is used through executable+argv only (`shell` is never set); a
 *   `.cmd`/`.bat` shim is refused instead of being launched through cmd.exe;
 * - the user's `~/.ssh/config` is bypassed with `-F none` (a config file could
 *   contain `ProxyCommand`/`LocalCommand`), and the user's known_hosts/global
 *   known_hosts are NOT used: the plugin pins the host key into its own
 *   plugin-private known_hosts with `accept-new` (TOFU, never claimed pre-verified);
 * - no agent forwarding, no X11, no local command, no interactive prompts
 *   (BatchMode=yes), no `-N` (localhost.run only prints the public URL from the
 *   remote session), no ClearAllForwardings (it would cancel `-R`);
 * - only `nokey@localhost.run` is allowed and only localhost.run-family
 *   `*.lhr.life` / `*.lhr.rocks` / `*.localhost.run` HTTPS origins printed by the
 *   service are accepted; missing ssh => SSH_MISSING (never downloads a binary).
 *
 * A dead free tunnel is normal (localhost.run documents flaky connections), so
 * the TunnelManager supervises restarts with backoff; this module owns one
 * child process and reports readiness/loss.
 */
import { lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { TunnelError, errorMessage } from './tunnel-errors.js';
import { BoundedOutput, assertExecutableNotShim, buildChildEnv, probeCommand, sanitizeProviderText, terminateChild, } from './tunnel-process.js';
import { ensurePrivateDirectory } from './tunnel-config.js';
const MAX_PROVIDER_HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const PROVIDER_URL_SUFFIXES = ['lhr.life', 'lhr.rocks', 'localhost.run'];
const SSH_HOST_SUFFIXES = ['localhost.run'];
const SSH_USERS = new Set(['nokey']);
const PROVIDER_URL_CANDIDATE = /https:\/\/[^\s"'<>\\)|,]+/gi;
const CONNECTION_LOST = /connection (?:to .* )?closed by remote host|connection reset|client_loop: send disconnect|packet_write_wait|broken pipe|connection timed out|remote host closed the connection/i;
/** Only localhost.run-family SSH hosts are allowed (keep this in sync with the docs). */
export function normalizeSshHost(raw) {
    const host = raw.trim().toLowerCase().replace(/\.$/, '');
    if (host === '' || host.length > 253)
        return null;
    if (host.includes('/') || host.includes(':') || host.includes('@'))
        return null;
    if (!/^[a-z0-9.-]+$/.test(host))
        return null;
    for (const suffix of SSH_HOST_SUFFIXES) {
        if (host === suffix || host.endsWith(`.${suffix}`)) {
            const labels = host.split('.');
            if (labels.every((label) => MAX_PROVIDER_HOST_LABEL.test(label)))
                return host;
        }
    }
    return null;
}
/** localhost.run free tunnels use the keyless `nokey` user. */
export function normalizeSshUser(raw) {
    const user = raw.trim().toLowerCase();
    return SSH_USERS.has(user) ? user : null;
}
/** localhost.run accepts bind ports 80 or 443 only. */
export function validateSshRemotePort(value) {
    return Number.isInteger(value) && (value === 80 || value === 443) ? value : null;
}
/**
 * Accept only a canonical provider-owned HTTPS origin printed by localhost.run:
 * `https://<label>(.<label>)*.<lhr.life|lhr.rocks|localhost.run>`.
 */
export function normalizeProviderUrl(raw) {
    let parsed;
    try {
        parsed = new URL(raw.trim());
    }
    catch {
        return null;
    }
    if (parsed.protocol !== 'https:')
        return null;
    if (parsed.username !== '' || parsed.password !== '')
        return null;
    if (parsed.port !== '')
        return null;
    if (parsed.pathname !== '/' && parsed.pathname !== '')
        return null;
    if (parsed.search !== '' || parsed.hash !== '')
        return null;
    const hostname = parsed.hostname.toLowerCase();
    for (const suffix of PROVIDER_URL_SUFFIXES) {
        if (!hostname.endsWith(`.${suffix}`))
            continue;
        const prefix = hostname.slice(0, -(suffix.length + 1));
        if (prefix === '')
            return null;
        const labels = prefix.split('.');
        if (!labels.every((label) => MAX_PROVIDER_HOST_LABEL.test(label)))
            return null;
        return `https://${hostname}`;
    }
    return null;
}
/**
 * localhost.run prints its URL on STDOUT (banner/MOTD on stderr) and the line can
 * be split arbitrarily; it also prints documentation URLs, so only the strict
 * provider-domain allowlist above decides acceptance.
 */
export function createSshOutputParser() {
    const tail = new BoundedOutput(16_384);
    return {
        push(chunk) {
            tail.push(chunk);
        },
        url() {
            PROVIDER_URL_CANDIDATE.lastIndex = 0;
            const text = tail.text();
            for (;;) {
                const match = PROVIDER_URL_CANDIDATE.exec(text);
                if (match === null)
                    return null;
                const candidate = normalizeProviderUrl(match[0]);
                if (candidate !== null)
                    return candidate;
            }
        },
        connectionLost() {
            return CONNECTION_LOST.test(tail.text());
        },
        text() {
            return tail.text();
        },
    };
}
const FORBIDDEN_ARGUMENT = /[\u0000\r\n]/;
function requireOptionValue(value, label) {
    if (value === '' || FORBIDDEN_ARGUMENT.test(value)) {
        throw new TunnelError('BAD_REQUEST', `${label} is invalid`);
    }
    return value;
}
/**
 * Hardened OpenSSH reverse-forward argv for localhost.run. Verified against the
 * research report (E14): `-F none`, explicit known_hosts, no `-N`, no
 * ClearAllForwardings, no remote command.
 */
export function buildSshArgs(input) {
    const sshHost = normalizeSshHost(input.sshHost);
    if (sshHost === null)
        throw new TunnelError('BAD_REQUEST', 'the SSH host is not an allowed localhost.run host');
    const sshUser = normalizeSshUser(input.sshUser);
    if (sshUser === null)
        throw new TunnelError('BAD_REQUEST', 'the SSH user must be "nokey" for localhost.run');
    const sshRemotePort = validateSshRemotePort(input.sshRemotePort);
    if (sshRemotePort === null)
        throw new TunnelError('BAD_REQUEST', 'the SSH remote port must be 80 or 443');
    if (!Number.isInteger(input.localPort) || input.localPort < 1 || input.localPort > 65_535) {
        throw new TunnelError('BAD_REQUEST', 'the local listener port is invalid');
    }
    const knownHostsFile = requireOptionValue(input.knownHostsFile.trim(), 'the SSH known_hosts path');
    return [
        '-F',
        'none',
        '-o',
        'BatchMode=yes',
        '-o',
        'StrictHostKeyChecking=accept-new',
        '-o',
        `UserKnownHostsFile=${knownHostsFile}`,
        '-o',
        'GlobalKnownHostsFile=none',
        '-o',
        'ExitOnForwardFailure=yes',
        '-o',
        'ServerAliveInterval=30',
        '-o',
        'ServerAliveCountMax=3',
        '-o',
        'ForwardAgent=no',
        '-o',
        'ForwardX11=no',
        '-o',
        'PermitLocalCommand=no',
        '-o',
        'IdentitiesOnly=yes',
        '-o',
        'ConnectTimeout=15',
        '-R',
        `${sshRemotePort}:127.0.0.1:${input.localPort}`,
        `${sshUser}@${sshHost}`,
    ];
}
/**
 * Create the plugin-private SSH directory and return its known_hosts path.
 * Never touches `~/.ssh`; an existing symlinked known_hosts is refused.
 */
export async function ensureKnownHosts(managedDir) {
    const directory = join(managedDir.replace(/[\\/]+$/, ''), 'ssh');
    await ensurePrivateDirectory(directory);
    const knownHostsFile = join(directory, 'known_hosts');
    try {
        const info = await lstat(knownHostsFile);
        if (info.isSymbolicLink()) {
            throw new TunnelError('BAD_REQUEST', 'the plugin known_hosts file must not be a symbolic link');
        }
        if (!info.isFile()) {
            throw new TunnelError('BAD_REQUEST', 'the plugin known_hosts path is not a regular file');
        }
    }
    catch (error) {
        if (error instanceof TunnelError)
            throw error;
        // ENOENT: first use, ssh will create the file on TOFU.
    }
    return { directory, knownHostsFile };
}
function isPathLike(value) {
    return value.includes('/') || value.includes('\\') || /^[A-Za-z]:/.test(value);
}
const SSH_MISSING_MESSAGE = 'the OpenSSH client executable was not found; install the OS OpenSSH client (the plugin never downloads an SSH binary)';
/**
 * Discover the OpenSSH client: explicit configured path -> OS-shipped Windows
 * OpenSSH -> `ssh` on PATH. Missing => SSH_MISSING (there is no download path).
 */
export async function discoverSsh(deps) {
    const platform = deps.platform ?? process.platform;
    const configured = deps.configuredPath.trim() === '' ? 'ssh' : deps.configuredPath.trim();
    const probeTimeoutMs = deps.probeTimeoutMs ?? 5_000;
    const fileExists = deps.fileExists;
    const candidates = [];
    if (isPathLike(configured)) {
        candidates.push({ command: configured, requireFile: true });
    }
    else {
        if (platform === 'win32' && configured === 'ssh') {
            const windir = deps.windir ?? deps.env?.WINDIR ?? deps.env?.windir ?? process.env.WINDIR ?? 'C:\\Windows';
            candidates.push({ command: `${windir}\\System32\\OpenSSH\\ssh.exe`, requireFile: true });
        }
        candidates.push({ command: configured, requireFile: false });
    }
    for (const candidate of candidates) {
        if (candidate.requireFile) {
            const exists = fileExists !== undefined ? await fileExists(candidate.command) : await pathIsFile(candidate.command);
            if (!exists)
                continue;
        }
        if (deps.spawn === undefined)
            continue;
        const env = buildChildEnv({}, {}, deps.log, deps.env ?? process.env);
        const probe = await probeCommand(deps.spawn, candidate.command, ['-V'], { timeoutMs: probeTimeoutMs, env, log: deps.log });
        if (!probe.ok)
            continue;
        const versionText = sanitizeProviderText(`${probe.stderr} ${probe.stdout}`, 200);
        return { path: candidate.command, version: versionText === '' ? null : versionText };
    }
    throw new TunnelError('SSH_MISSING', SSH_MISSING_MESSAGE);
}
async function pathIsFile(path) {
    try {
        const info = await lstat(path);
        return info.isFile();
    }
    catch {
        return false;
    }
}
/**
 * Start one hardened ssh child. `start()` resolves when localhost.run announces
 * a provider-owned URL; connection loss after that is reported through the exit
 * handler (the manager decides whether to supervise a restart).
 */
export function createSshTunnel(deps) {
    const spawn = deps.spawn;
    const args = buildSshArgs({
        sshHost: deps.sshHost,
        sshUser: deps.sshUser,
        sshRemotePort: deps.sshRemotePort,
        localPort: deps.localPort,
        knownHostsFile: deps.knownHostsFile,
    });
    const parser = createSshOutputParser();
    let child = null;
    let currentUrl = null;
    let stopping = false;
    let exitHandler = null;
    let startupTimer = null;
    let startPromise = null;
    let settleStart = null;
    let startupSettled = false;
    const clearStartupTimer = () => {
        if (startupTimer !== null) {
            clearTimeout(startupTimer);
            startupTimer = null;
        }
    };
    const readOutput = (chunk) => {
        parser.push(chunk);
        const announced = parser.url();
        if (!startupSettled && announced !== null) {
            currentUrl = announced;
            startupSettled = true;
            clearStartupTimer();
            settleStart?.resolve({ url: announced });
            settleStart = null;
        }
    };
    const onExit = (code, signal) => {
        child = null;
        clearStartupTimer();
        if (!startupSettled) {
            startupSettled = true;
            const detail = `ssh exited before the tunnel URL was announced (code=${code ?? 'null'}, signal=${signal ?? 'none'})`;
            settleStart?.reject(new TunnelError('INTERNAL', detail));
            settleStart = null;
            return;
        }
        if (stopping)
            return;
        const detail = `ssh exited unexpectedly (code=${code ?? 'null'}, signal=${signal ?? 'none'})`;
        deps.log.warn('ssh tunnel connection lost');
        exitHandler?.(detail);
    };
    const start = () => {
        if (startPromise !== null)
            return startPromise;
        assertExecutableNotShim(deps.executable);
        startPromise = new Promise((resolve, reject) => {
            settleStart = { resolve, reject };
            const env = buildChildEnv({}, {}, deps.log, deps.env ?? process.env);
            let proc;
            try {
                proc = spawn(deps.executable, args, {
                    env,
                    stdio: ['ignore', 'pipe', 'pipe'],
                    windowsHide: true,
                });
            }
            catch (error) {
                startupSettled = true;
                settleStart = null;
                const code = error.code;
                reject(new TunnelError(code === 'ENOENT' ? 'SSH_MISSING' : 'INTERNAL', errorMessage(error)));
                return;
            }
            child = proc;
            proc.stdout?.on('data', readOutput);
            proc.stderr?.on('data', readOutput);
            proc.once('exit', onExit);
            proc.once('error', (error) => {
                if (child === proc)
                    child = null;
                clearStartupTimer();
                if (!startupSettled) {
                    startupSettled = true;
                    const detail = error.code === 'ENOENT'
                        ? SSH_MISSING_MESSAGE
                        : `ssh could not start (${error.code ?? 'unknown error'})`;
                    settleStart?.reject(new TunnelError(error.code === 'ENOENT' ? 'SSH_MISSING' : 'INTERNAL', detail));
                    settleStart = null;
                }
            });
            startupTimer = setTimeout(() => {
                startupTimer = null;
                if (startupSettled)
                    return;
                startupSettled = true;
                const detail = `ssh did not announce a provider URL within ${Math.round(deps.startupTimeoutMs / 1_000)}s`;
                settleStart?.reject(new TunnelError('INTERNAL', detail));
                settleStart = null;
                void terminateChild(proc, deps.killGraceMs);
            }, Math.max(50, deps.startupTimeoutMs));
            startupTimer.unref();
        });
        return startPromise;
    };
    const stop = async () => {
        stopping = true;
        clearStartupTimer();
        const proc = child;
        child = null;
        if (proc !== null)
            await terminateChild(proc, deps.killGraceMs);
    };
    return {
        start,
        stop,
        setExitHandler(handler) {
            exitHandler = handler;
        },
        get url() {
            return currentUrl;
        },
    };
}
/** Test/diagnostic helper: the provider URL domains this provider accepts. */
export function sshProviderUrlSuffixes() {
    return [...PROVIDER_URL_SUFFIXES];
}
