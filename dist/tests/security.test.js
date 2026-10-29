/**
 * Static security guards for the shipped sources.
 *
 * The remote-control surface is a second client of a local agent loop, so the
 * browser code must never build DOM from strings and the repository must never
 * contain credential material. These are source-level invariants; runtime auth
 * behaviour is covered by the auth/integration suites.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SCAN_ROOTS = [
    { dir: 'src', required: true },
    { dir: 'client/src', required: false },
    { dir: 'pwa/src', required: false },
];
const SCAN_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.html', '.htm']);
/** DOM sink patterns that would turn user/tool data into markup or code. */
const DOM_SINK_PATTERNS = [
    { id: 'innerHTML', pattern: /\binnerHTML\b/ },
    { id: 'outerHTML assignment', pattern: /\bouterHTML\s*=/ },
    { id: 'insertAdjacentHTML', pattern: /\binsertAdjacentHTML\s*\(/ },
    { id: 'dangerouslySetInnerHTML', pattern: /\bdangerouslySetInnerHTML\b/ },
    { id: 'eval()', pattern: /(^|[^.\w$])eval\s*\(/ },
    { id: 'new Function()', pattern: /\bnew\s+Function\s*\(/ },
    { id: 'document.write()', pattern: /\bdocument\s*\.\s*write(?:ln)?\s*\(/ },
];
/** Credential shapes that must never be committed. */
const SECRET_PATTERNS = [
    { id: 'PEM private key', pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
    { id: 'AWS access key id', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
    { id: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
    { id: 'Slack token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
    {
        id: 'hardcoded secret literal',
        pattern: /(?:secret|password|passwd|api[_-]?key|private[_-]?key)\s*[:=]\s*['"`][^'"`\s]{16,}['"`]/i,
    },
    { id: 'hardcoded bearer token', pattern: /['"`]Bearer\s+[A-Za-z0-9._~+/-]{20,}['"`]/ },
];
function walkFiles(absoluteDir) {
    const out = [];
    const stack = [absoluteDir];
    while (stack.length > 0) {
        const dir = stack.pop();
        if (dir === undefined)
            break;
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const absolute = path.join(dir, entry.name);
            if (entry.isDirectory())
                stack.push(absolute);
            else if (entry.isFile() && SCAN_EXTENSIONS.has(path.extname(entry.name).toLowerCase()))
                out.push(absolute);
        }
    }
    return out.sort();
}
function stripComments(text) {
    return text
        .replace(/\/\*[\s\S]*?\*\//g, ' ')
        .replace(/(^|[^\\:"])\/\/[^\n]*/g, '$1');
}
function collectScannedFiles() {
    const files = [];
    const missingRoots = [];
    for (const root of SCAN_ROOTS) {
        const absolute = path.join(ROOT, root.dir);
        if (!fs.existsSync(absolute)) {
            if (root.required)
                missingRoots.push(root.dir);
            continue;
        }
        files.push(...walkFiles(absolute));
    }
    // Also scan the PWA shell document (inline scripts would violate the CSP).
    const indexHtml = path.join(ROOT, 'pwa', 'index.html');
    if (fs.existsSync(indexHtml))
        files.push(indexHtml);
    return { files, missingRoots };
}
test('security: the source tree is present and scannable', () => {
    const { files, missingRoots } = collectScannedFiles();
    assert.deepEqual(missingRoots, [], `required source roots missing: ${missingRoots.join(', ')}`);
    assert.ok(files.length >= 5, `expected at least 5 scannable source files, found ${files.length}`);
    assert.ok(files.some((file) => file.includes(`${path.sep}src${path.sep}`)), 'src/ sources must be scanned');
});
test('security: no DOM-from-string or dynamic-code sinks in shipped sources', () => {
    const { files } = collectScannedFiles();
    const violations = [];
    for (const file of files) {
        const source = stripComments(fs.readFileSync(file, 'utf8'));
        for (const rule of DOM_SINK_PATTERNS) {
            if (rule.pattern.test(source)) {
                violations.push(`${path.relative(ROOT, file)}: ${rule.id}`);
            }
        }
    }
    assert.deepEqual(violations, [], `forbidden DOM sinks found: ${violations.join('; ')}`);
});
test('security: no credential material or hardcoded secrets in shipped sources', () => {
    const { files } = collectScannedFiles();
    // Secret scanning is not comment-stripped: a key pasted into a comment is
    // still a leaked key.
    const violations = [];
    for (const file of files) {
        const source = fs.readFileSync(file, 'utf8');
        for (const rule of SECRET_PATTERNS) {
            if (rule.pattern.test(source)) {
                violations.push(`${path.relative(ROOT, file)}: ${rule.id}`);
            }
        }
    }
    assert.deepEqual(violations, [], `credential-like literals found: ${violations.join('; ')}`);
});
test('security: PWA shell document has no inline script (CSP-safe)', () => {
    const htmlPath = path.join(ROOT, 'pwa', 'index.html');
    if (!fs.existsSync(htmlPath)) {
        // The PWA shell must exist by the time the suite runs; the pack-check also
        // requires the built `dist/pwa/index.html`.
        assert.fail('pwa/index.html is missing');
    }
    const html = fs.readFileSync(htmlPath, 'utf8');
    const scriptTags = [...html.matchAll(/<script\b([^>]*)>/gi)].map((match) => match[1] ?? '');
    assert.ok(scriptTags.length > 0, 'pwa/index.html should reference at least one external script');
    const inline = scriptTags.filter((attributes) => !/\bsrc\s*=/.test(attributes));
    assert.deepEqual(inline, [], `inline <script> blocks are not allowed: ${inline.join(' | ')}`);
    assert.equal(/\bon[a-z]+\s*=/i.test(html), false, 'inline event handlers (on*=) are not allowed');
});
test('security: locale and config files never carry token material', () => {
    const scanFiles = [
        path.join(ROOT, 'cordis.patch.yml'),
        path.join(ROOT, 'locale', 'en.json'),
        path.join(ROOT, 'locale', 'tr.json'),
    ].filter((file) => fs.existsSync(file));
    assert.ok(scanFiles.length > 0, 'expected at least one config/locale file to scan');
    const violations = [];
    for (const file of scanFiles) {
        const source = fs.readFileSync(file, 'utf8');
        for (const rule of SECRET_PATTERNS) {
            if (rule.pattern.test(source))
                violations.push(`${path.relative(ROOT, file)}: ${rule.id}`);
        }
    }
    assert.deepEqual(violations, [], `credential-like literals found: ${violations.join('; ')}`);
});
/* ------------------------------------------------------------------------- */
/* Surface-lane source invariants (auth / listener / ws broker)              */
/* ------------------------------------------------------------------------- */
function readSurfaceSource(relative) {
    return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}
test('security: WebSocket close paths use the shared RC_WS_CLOSE codes, not magic numbers', () => {
    const source = readSurfaceSource('src/ws-broker.ts');
    // Codes the broker sends itself must come from the shared contract.
    for (const name of ['deviceLost', 'leaseLost', 'policyViolation']) {
        assert.match(source, new RegExp(`RC_WS_CLOSE\\.${name}\\b`), `ws-broker must reference RC_WS_CLOSE.${name} for its security close path`);
    }
    // The controller-facing handle exposes the shared-code close path; the
    // behavior of closeWithCode(securityClosed/idleTimeout) is covered against
    // the RC_WS_CLOSE constants in tests/ws-broker.test.ts.
    assert.match(source, /closeWithCode\(code: number, reason: string\): void/);
    // 4001..4004 are reserved policy codes owned by the shared protocol module.
    assert.equal(/close\(\s*400[1-4]\b/.test(source), false, 'raw 400x close codes must not be inlined');
});
test('security: the auth surface compares secrets with crypto.timingSafeEqual', () => {
    const source = readSurfaceSource('src/auth.ts');
    assert.match(source, /timingSafeEqual/);
    // A plain `===` comparison of two secret-looking values would leak timing.
    assert.equal(/secretsEqual\([^)]*\)\s*===/.test(source), false);
});
test('security: listener keeps CSP and refuses wildcard binds', () => {
    const source = readSurfaceSource('src/listener.ts');
    assert.match(source, /frame-ancestors 'none'/, 'CSP must keep framing disabled');
    assert.match(source, /default-src 'self'/, 'CSP must keep the self-only default policy');
    assert.match(source, /wildcard bind is not allowed/);
    assert.match(source, /allowLan/, 'non-loopback binds must stay gated by allowLan');
});
test('security: the surface modules never log cookie/token/secret values', () => {
    for (const relative of ['src/auth.ts', 'src/listener.ts', 'src/ws-broker.ts']) {
        const source = readSurfaceSource(relative);
        // Logging calls must never interpolate token/cookie/pairing material.
        assert.equal(/(?:log\.(?:error|warn|info|debug)|console\.\w+)\([^)]*(?:token|cookie|secret|pollToken|pairingCode)/i.test(source), false, `${relative} must not log secret values`);
    }
});
