/**
 * Low-level process helpers for provider children.
 *
 * Security rules enforced here:
 * - executable + argv only (`shell` is never set; batch `.cmd`/`.bat` shims are
 *   refused instead of being launched through `cmd.exe`);
 * - the child environment is an allowlist (no `DSH_*`, no credentials, no
 *   `SSH_AUTH_SOCK`, no proxy variables);
 * - retry/kill logic always escalates SIGTERM -> SIGKILL within a bounded grace.
 */
import { TunnelError } from './tunnel-errors.js';
/** Environment variables a provider child may inherit (no credentials). */
const PASSTHROUGH_ENV = [
    'PATH',
    'Path',
    'PATHEXT',
    'SYSTEMROOT',
    'SystemRoot',
    'SYSTEMDRIVE',
    'WINDIR',
    'COMSPEC',
    'TEMP',
    'TMP',
    'HOME',
    'USERPROFILE',
    'APPDATA',
    'LOCALAPPDATA',
    'PROGRAMDATA',
    'PROGRAMFILES',
    'PROGRAMFILES(X86)',
    'OS',
    'PROCESSOR_ARCHITECTURE',
    'NUMBER_OF_PROCESSORS',
    'LANG',
    'LC_ALL',
    'TZ',
];
const BLOCKED_ENV_NAMES = [/^DSH_/i, /^TUNNEL_/i, /^CF_TUNNEL_/i, /^(?:HTTP|HTTPS|ALL|NO)_PROXY$/i];
const BLOCKED_ENV_HINTS = /(TOKEN|SECRET|CREDENTIAL|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH_SOCK)/i;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const SECRET_ENV_NAMES = /^TUNNEL_TOKEN$/i;
/**
 * Build the minimal child environment: allowlisted OS variables only, plus the
 * explicitly provided additions (`TUNNEL_TOKEN`). Credential-looking extras are
 * ignored with a warning instead of being forwarded.
 */
export function buildChildEnv(extra, additions, log, baseEnv = process.env) {
    const env = {};
    for (const key of PASSTHROUGH_ENV) {
        const value = baseEnv[key];
        if (value !== undefined)
            env[key] = value;
    }
    for (const [key, value] of Object.entries(extra)) {
        if (!ENV_NAME.test(key) || typeof value !== 'string') {
            log.warn('ignoring malformed tunnel env entry', { name: String(key).slice(0, 64) });
            continue;
        }
        if (BLOCKED_ENV_NAMES.some((pattern) => pattern.test(key)) || BLOCKED_ENV_HINTS.test(key)) {
            log.warn('ignoring credential-like tunnel env entry', { name: key });
            continue;
        }
        env[key] = value;
    }
    for (const [key, value] of Object.entries(additions)) {
        if (!ENV_NAME.test(key))
            throw new TunnelError('BAD_REQUEST', 'invalid child environment variable name');
        env[key] = value;
    }
    return env;
}
/** Secret additions are limited to the connector token variable. */
export function assertAllowedSecretEnvName(name) {
    return SECRET_ENV_NAMES.test(name);
}
/**
 * Reject executable shims/values that would require a shell. `shell: false` is
 * always used, so a `.cmd`/`.bat` wrapper cannot be executed safely.
 */
export function assertExecutableNotShim(executable) {
    const trimmed = executable.trim();
    if (trimmed === '')
        throw new TunnelError('BAD_REQUEST', 'the provider executable path is empty');
    if (/[\u0000\r\n]/.test(trimmed)) {
        throw new TunnelError('BAD_REQUEST', 'the provider executable path contains control characters');
    }
    if (/\.(?:cmd|bat|ps1)$/i.test(trimmed)) {
        throw new TunnelError('BAD_REQUEST', 'refusing to launch a Windows script shim; configure the real executable (no shell is ever used)');
    }
}
/** Bounded rolling output tail. Output is untrusted provider text. */
export class BoundedOutput {
    maxChars;
    tail = '';
    constructor(maxChars = 16_384) {
        this.maxChars = Math.max(256, maxChars);
    }
    push(chunk) {
        const text = typeof chunk === 'string' ? chunk : chunk.toString('utf8');
        const combined = this.tail + text;
        this.tail = combined.length > this.maxChars ? combined.slice(-this.maxChars) : combined;
    }
    text() {
        return this.tail;
    }
    clear() {
        this.tail = '';
    }
}
/** Strip ANSI escapes and control characters, collapse whitespace, bound length. */
export function sanitizeProviderText(value, maxLength = 240) {
    return value
        .replace(/\u001b\[[0-9;?]*[a-zA-Z]/g, '')
        .replace(/[\u0000-\u001f\u007f]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .slice(0, maxLength);
}
/**
 * Run a short-lived executable+argv probe (e.g. `--version`) with a minimal
 * environment and a hard timeout. Never throws: a missing executable or timeout
 * is reported as `ok: false`.
 */
export async function probeCommand(spawn, command, args, options) {
    return new Promise((resolve) => {
        let settled = false;
        let stdout = '';
        let stderr = '';
        let timer = null;
        let proc = null;
        const finish = (result) => {
            if (settled)
                return;
            settled = true;
            if (timer !== null)
                clearTimeout(timer);
            resolve(result);
        };
        try {
            proc = spawn(command, args, {
                env: options.env,
                stdio: ['ignore', 'pipe', 'pipe'],
                windowsHide: true,
            });
        }
        catch (error) {
            finish({
                ok: false,
                code: null,
                stdout,
                stderr: error instanceof Error ? error.message : String(error),
            });
            return;
        }
        proc.stdout?.on('data', (chunk) => {
            if (stdout.length < 8_192)
                stdout += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
        });
        proc.stderr?.on('data', (chunk) => {
            if (stderr.length < 8_192)
                stderr += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
        });
        proc.once('error', (error) => {
            finish({ ok: false, code: null, stdout, stderr: `${stderr}${error.message}` });
        });
        proc.once('exit', (code) => {
            finish({ ok: code === 0, code, stdout, stderr });
        });
        timer = setTimeout(() => {
            try {
                proc?.kill('SIGKILL');
            }
            catch {
                // Already gone.
            }
            options.log.warn('provider version probe timed out', { command: command.slice(-64) });
            finish({ ok: false, code: null, stdout, stderr });
        }, Math.max(100, options.timeoutMs));
        timer.unref();
    });
}
/** SIGTERM, then SIGKILL after `graceMs`; resolves when the process is gone (or best effort). */
export function terminateChild(proc, graceMs) {
    if (proc.exitCode !== null || proc.signalCode !== null)
        return Promise.resolve();
    return new Promise((resolve) => {
        let settled = false;
        let killTimer = null;
        let fallbackTimer = null;
        const finish = () => {
            if (settled)
                return;
            settled = true;
            if (killTimer !== null)
                clearTimeout(killTimer);
            if (fallbackTimer !== null)
                clearTimeout(fallbackTimer);
            resolve();
        };
        proc.once('exit', finish);
        proc.once('error', finish);
        try {
            proc.kill('SIGTERM');
        }
        catch {
            finish();
            return;
        }
        killTimer = setTimeout(() => {
            try {
                if (proc.exitCode === null && proc.signalCode === null)
                    proc.kill('SIGKILL');
            }
            catch {
                // Already gone.
            }
            fallbackTimer = setTimeout(finish, Math.max(10, graceMs));
            fallbackTimer.unref();
        }, Math.max(10, graceMs));
        killTimer.unref();
    });
}
