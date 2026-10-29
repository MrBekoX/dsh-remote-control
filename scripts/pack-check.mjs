#!/usr/bin/env node
/**
 * Packaging gate for `dsh-remote-control`.
 *
 * Runs `npm pack --dry-run --json --ignore-scripts` and validates the exact
 * file set that a `link:` / registry install would receive:
 *   - every runtime asset is present (host bundle, client bundle, PWA, locale,
 *     bundle patch, docs),
 *   - no source/test/research/scratch/secret material leaks into the tarball,
 *   - the built client bundle carries the DSH ModuleLoader wrapper and plugin id,
 *   - the built host bundle exports `inject` + `apply`,
 *   - every `package.json` `exports` target resolves on disk.
 *
 * Exit codes: 0 = PASS, 1 = FAIL.
 *
 * Usage: node scripts/pack-check.mjs
 */

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

const REQUIRED_FILES = [
  'dist/host/index.js',
  'dist/client.js',
  'dist/pwa/index.html',
  'dist/pwa/app.js',
  'dist/pwa/app.css',
  'dist/pwa/manifest.webmanifest',
  'dist/pwa/sw.js',
  'locale/en.json',
  'locale/tr.json',
  'cordis.patch.yml',
  'icon.svg',
  'README.md',
  'SECURITY.md',
  'PROTOCOL.md',
  'package.json',
]

/** Forbidden tarball content. Each rule is matched against the POSIX path. */
const FORBIDDEN_RULES = [
  { id: 'src-ts', label: 'source TypeScript under src/', test: (p) => p.startsWith('src/') },
  { id: 'tests', label: 'test sources (tests/)', test: (p) => p.startsWith('tests/') },
  { id: 'research', label: 'research notes (research/)', test: (p) => p.startsWith('research/') },
  { id: 'scratch', label: 'scratch evidence (scratch/)', test: (p) => p.startsWith('scratch/') },
  { id: 'node-modules', label: 'node_modules/', test: (p) => p.startsWith('node_modules/') },
  { id: 'git', label: '.git/', test: (p) => p.startsWith('.git/') },
  {
    id: 'ts-outside-dist',
    label: 'TypeScript files outside dist/',
    test: (p) => p.endsWith('.ts') && !p.startsWith('dist/'),
  },
  { id: 'dotenv', label: '.env files', test: (p) => p === '.env' || p.startsWith('.env.') },
  { id: 'pem', label: '*.pem certificates/keys', test: (p) => p.endsWith('.pem') },
  { id: 'log', label: '*.log files', test: (p) => p.endsWith('.log') },
]

/** The DSH client-plugin wrapper, as required by dsh-client-modules. */
const CLIENT_MARKERS = ['window.__ModuleLoader__.load', 'dsh-remote-control']

class Reporter {
  constructor() {
    this.checks = []
  }

  add(id, title, status, detail, notes = []) {
    this.checks.push({ id, title, status, detail, notes })
  }

  pass(id, title, detail, notes = []) {
    this.add(id, title, 'pass', detail, notes)
  }

  fail(id, title, detail, notes = []) {
    this.add(id, title, 'fail', detail, notes)
  }

  get failed() {
    return this.checks.filter((check) => check.status === 'fail')
  }

  get warned() {
    return this.checks.filter((check) => check.status === 'warn')
  }
}

/* ------------------------------------------------------------------------- */
/* npm pack                                                                  */
/* ------------------------------------------------------------------------- */

function npmArgs() {
  return ['pack', '--dry-run', '--json', '--ignore-scripts']
}

/**
 * `npm` on Windows is `npm.cmd`, which Node cannot spawn without a shell.
 * Try the direct spawn first (POSIX + future Node behaviour) and fall back to
 * `cmd.exe /d /s /c npm ...`, quoting only static arguments.
 */
function runNpmPack() {
  const args = npmArgs()
  const base = {
    cwd: ROOT,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 120_000,
    maxBuffer: 32 * 1024 * 1024,
  }

  const attempts = []
  if (process.platform === 'win32') {
    attempts.push({ label: 'npm.cmd', result: spawnSync('npm.cmd', args, { ...base, shell: false }) })
    if (!succeeded(attempts[0].result)) {
      const command = `npm ${args.join(' ')}`
      attempts.push({
        label: 'cmd /c npm',
        result: spawnSync(process.env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', command], {
          ...base,
          shell: false,
        }),
      })
    }
  } else {
    attempts.push({ label: 'npm', result: spawnSync('npm', args, { ...base, shell: false }) })
  }

  for (const attempt of attempts) {
    const result = attempt.result
    if (succeeded(result) && result.stdout.trim()) {
      return { ok: true, attempt: attempt.label, stdout: result.stdout, stderr: result.stderr, attempts }
    }
  }
  const last = attempts[attempts.length - 1]
  return {
    ok: false,
    attempt: last?.label,
    attempts,
    error: last?.result?.error ? String(last.result.error.message ?? last.result.error) : null,
    status: last?.result?.status ?? null,
    stderr: attempts.map((attempt) => attempt.result?.stderr ?? '').join('\n').trim(),
  }
}

function succeeded(result) {
  return !!result && !result.error && result.status === 0
}

function parsePackJson(stdout) {
  const from = stdout.indexOf('[')
  const to = stdout.lastIndexOf(']')
  if (from === -1 || to === -1 || to < from) throw new Error('npm pack printed no JSON array')
  return JSON.parse(stdout.slice(from, to + 1))
}

/* ------------------------------------------------------------------------- */
/* Checks                                                                    */
/* ------------------------------------------------------------------------- */

function checkPackedFiles(reporter, fileRows) {
  const packed = new Set(fileRows.map((row) => row.path))

  const missing = REQUIRED_FILES.filter((required) => !packed.has(required))
  if (missing.length === 0) {
    reporter.pass('required-files', `Required runtime files (${REQUIRED_FILES.length}/${REQUIRED_FILES.length} packed)`, {
      packedCount: REQUIRED_FILES.length,
    })
  } else {
    reporter.fail(
      'required-files',
      `Required runtime files missing from the tarball (${missing.length}/${REQUIRED_FILES.length})`,
      { missing },
      ['run `pnpm run build` and make sure README.md / SECURITY.md / PROTOCOL.md exist'],
    )
  }

  const violations = []
  for (const row of fileRows) {
    for (const rule of FORBIDDEN_RULES) {
      if (rule.test(row.path)) {
        violations.push({ path: row.path, rule: rule.id, label: rule.label })
        break
      }
    }
  }
  if (violations.length === 0) {
    reporter.pass('forbidden-files', 'No forbidden files in the tarball (src/tests/research/scratch/node_modules/.git, *.ts outside dist, secrets/logs)', {
      packedCount: fileRows.length,
    })
  } else {
    reporter.fail('forbidden-files', `Forbidden files leaked into the tarball (${violations.length})`, {
      violations,
    })
  }
}

function readRepoFile(reporter, id, relativePath) {
  const absolute = path.join(ROOT, relativePath)
  if (!fs.existsSync(absolute)) {
    reporter.fail(id, `${relativePath} missing on disk`, { file: relativePath })
    return null
  }
  try {
    return fs.readFileSync(absolute, 'utf8')
  } catch (error) {
    reporter.fail(id, `${relativePath} unreadable`, { file: relativePath, error: String(error.message ?? error) })
    return null
  }
}

function checkClientBundle(reporter) {
  const text = readRepoFile(reporter, 'client-bundle', 'dist/client.js')
  if (text === null) return
  const missing = CLIENT_MARKERS.filter((marker) => !text.includes(marker))
  if (missing.length === 0) {
    reporter.pass('client-bundle', 'dist/client.js has the ModuleLoader wrapper and plugin id', {
      markers: CLIENT_MARKERS,
      bytes: text.length,
    })
  } else {
    reporter.fail('client-bundle', 'dist/client.js is missing required markers', { missing })
  }
}

function checkHostBundle(reporter) {
  const text = readRepoFile(reporter, 'host-bundle', 'dist/host/index.js')
  if (text === null) return
  const hasExport = /\bexport\b/.test(text)
  const hasInject = /\binject\b/.test(text)
  const hasApply = /\bapply\b/.test(text)
  // Prefer precise named-export forms when the build keeps them, but accept any
  // `export` + identifier presence (minifiers/re-exports may rename shapes).
  const namedForms = {
    inject: /\bexport\s*(?:async\s+)?(?:function|const|let|var|class|\{[^}]*\binject\b)/.test(text),
    apply: /\bexport\s*(?:async\s+)?(?:function|const|let|var|class|\{[^}]*\bapply\b)/.test(text),
  }
  const missing = []
  if (!hasExport) missing.push('export')
  if (!hasInject) missing.push('inject')
  if (!hasApply) missing.push('apply')
  if (missing.length === 0) {
    reporter.pass('host-bundle', 'dist/host/index.js exports inject + apply', {
      namedExportForms: namedForms,
      bytes: text.length,
    })
  } else {
    reporter.fail('host-bundle', 'dist/host/index.js is missing required exports', { missing })
  }
}

function checkExportTargets(reporter) {
  const pkgPath = path.join(ROOT, 'package.json')
  if (!fs.existsSync(pkgPath)) {
    reporter.fail('exports', 'package.json missing on disk', { file: 'package.json' })
    return
  }
  let pkg
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
  } catch (error) {
    reporter.fail('exports', 'package.json is not valid JSON', { error: String(error.message ?? error) })
    return
  }
  const exportsField = pkg.exports
  if (!exportsField || typeof exportsField !== 'object') {
    reporter.fail('exports', 'package.json has no exports map', { file: 'package.json' })
    return
  }

  const resolved = []
  const missing = []
  for (const [key, value] of Object.entries(exportsField)) {
    for (const target of flattenExportTargets(value)) {
      if (!target.startsWith('./')) continue
      const relative = target.slice(2)
      if (relative.includes('*')) {
        const dir = path.join(ROOT, path.dirname(relative))
        const base = path.basename(relative)
        const prefix = base.slice(0, base.indexOf('*'))
        const suffix = base.slice(base.indexOf('*') + 1)
        let matches = []
        try {
          matches = fs
            .readdirSync(dir)
            .filter((name) => name.startsWith(prefix) && name.endsWith(suffix))
        } catch {
          matches = []
        }
        if (matches.length > 0) resolved.push({ key, target, matches })
        else missing.push({ key, target, reason: 'glob matched no file' })
      } else {
        if (fs.existsSync(path.join(ROOT, relative))) resolved.push({ key, target })
        else missing.push({ key, target, reason: 'file not on disk' })
      }
    }
  }

  if (missing.length === 0) {
    reporter.pass('exports', `package.json exports targets resolve on disk (${resolved.length})`, { resolved })
  } else {
    reporter.fail('exports', 'package.json exports targets do not resolve on disk', { missing })
  }
}

function flattenExportTargets(value) {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap((item) => flattenExportTargets(item))
  if (value && typeof value === 'object') return Object.values(value).flatMap((item) => flattenExportTargets(item))
  return []
}

/** Informational: warn when the committed host build predates the newest source. */
function checkBuildFreshness(reporter) {
  const built = path.join(ROOT, 'dist', 'host', 'index.js')
  const srcDir = path.join(ROOT, 'src')
  if (!fs.existsSync(built) || !fs.existsSync(srcDir)) return
  try {
    const builtMtime = fs.statSync(built).mtimeMs
    let newest = null
    const stack = [srcDir]
    while (stack.length > 0) {
      const dir = stack.pop()
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const absolute = path.join(dir, entry.name)
        if (entry.isDirectory()) stack.push(absolute)
        else if (entry.name.endsWith('.ts')) {
          const mtime = fs.statSync(absolute).mtimeMs
          if (!newest || mtime > newest.mtimeMs) newest = { path: absolute, mtimeMs: mtime }
        }
      }
    }
    if (newest && newest.mtimeMs > builtMtime + 1000) {
      reporter.add(
        'build-freshness',
        'dist/host build is older than the newest src/*.ts (warn)',
        'warn',
        { builtMtime: new Date(builtMtime).toISOString(), newestSource: path.relative(ROOT, newest.path) },
      )
    } else {
      reporter.pass('build-freshness', 'dist/host build is at least as new as src/*.ts', {})
    }
  } catch {
    // best-effort only
  }
}

/* ------------------------------------------------------------------------- */
/* Report                                                                    */
/* ------------------------------------------------------------------------- */

function writeReport(report) {
  // Reports never go into dist/ (it is committed) or the repo root.
  const candidates = [path.join(ROOT, 'scratch'), path.join(ROOT, '.tmp')]
  let destination = null
  for (const dir of candidates) {
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
      destination = path.join(dir, 'pack-report.json')
      break
    }
  }
  if (destination === null) {
    destination = path.join(ROOT, '.tmp', 'pack-report.json')
    fs.mkdirSync(path.dirname(destination), { recursive: true })
  }
  fs.writeFileSync(destination, `${JSON.stringify(report, null, 2)}\n`, 'utf8')
  return destination
}

function printReport(report, reportPath) {
  const lines = []
  lines.push('dsh-remote-control pack check (npm pack --dry-run)')
  lines.push('')
  for (const check of report.checks) {
    const glyph = check.status === 'pass' ? '✓' : check.status === 'warn' ? '⚠' : '✗'
    lines.push(`${glyph} ${check.title}`)
    if (check.status !== 'pass') {
      const detail = check.detail ?? {}
      if (Array.isArray(detail.missing) && detail.missing.length > 0) {
        for (const missing of detail.missing) {
          lines.push(`    missing: ${typeof missing === 'string' ? missing : JSON.stringify(missing)}`)
        }
      }
      if (Array.isArray(detail.violations) && detail.violations.length > 0) {
        for (const violation of detail.violations) lines.push(`    forbidden: ${violation.path} (${violation.label})`)
      }
      if (detail.error) lines.push(`    error: ${detail.error}`)
    }
    for (const note of check.notes ?? []) lines.push(`    note: ${note}`)
  }
  lines.push('')
  const pass = report.checks.filter((check) => check.status === 'pass').length
  const warn = report.checks.filter((check) => check.status === 'warn').length
  lines.push(`checks: ${pass} pass, ${report.failures} fail, ${warn} warn (${report.checks.length} total)`)
  lines.push(`RESULT: ${report.status.toUpperCase()}`)
  if (reportPath) lines.push(`report: ${reportPath}`)
  console.log(lines.join('\n'))
}

/* ------------------------------------------------------------------------- */
/* Main                                                                      */
/* ------------------------------------------------------------------------- */

function main() {
  const reporter = new Reporter()

  const pack = runNpmPack()
  let fileRows = []
  if (!pack.ok) {
    reporter.fail('npm-pack', 'npm pack --dry-run --json failed', {
      error: pack.error,
      status: pack.status,
      stderr: pack.stderr ? pack.stderr.slice(-4000) : '',
      attempts: pack.attempts.map((attempt) => attempt.label),
    })
  } else {
    try {
      const parsed = parsePackJson(pack.stdout)
      const tarballs = Array.isArray(parsed) ? parsed : [parsed]
      fileRows = tarballs.flatMap((tarball) =>
        Array.isArray(tarball.files)
          ? tarball.files.map((file) => ({ path: String(file.path).replace(/\\/g, '/'), size: file.size }))
          : [],
      )
      reporter.pass('npm-pack', `npm pack --dry-run produced a file list (${fileRows.length} files)`, {
        attempt: pack.attempt,
        tarballs: tarballs.length,
      })
    } catch (error) {
      reporter.fail('npm-pack-json', 'could not parse npm pack JSON', { error: String(error.message ?? error) })
    }
  }

  if (fileRows.length > 0) checkPackedFiles(reporter, fileRows)
  else {
    reporter.fail('required-files', 'Required runtime files cannot be verified (no pack file list)', {
      missing: REQUIRED_FILES,
    })
    reporter.fail('forbidden-files', 'Forbidden files cannot be verified (no pack file list)', {})
  }

  checkClientBundle(reporter)
  checkHostBundle(reporter)
  checkExportTargets(reporter)
  checkBuildFreshness(reporter)

  const failures = reporter.failed.length
  const report = {
    status: failures > 0 ? 'fail' : 'pass',
    generatedAt: new Date().toISOString(),
    node: process.version,
    platform: process.platform,
    packAttempt: pack.attempt ?? null,
    packedFiles: fileRows.length,
    checks: reporter.checks,
    failures,
    summary: {
      pass: reporter.checks.filter((check) => check.status === 'pass').length,
      fail: failures,
      warn: reporter.warned.length,
    },
  }
  const reportPath = writeReport(report)
  printReport(report, reportPath)
  process.exit(report.status === 'pass' ? 0 : 1)
}

main()
