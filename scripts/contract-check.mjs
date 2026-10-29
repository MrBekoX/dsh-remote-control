#!/usr/bin/env node
/**
 * M0 contract check: verify that the installed DeepSeek Harness build still
 * exposes the runtime contract this plugin encodes in `src/types/dsh.d.ts`.
 *
 * The script reads the Electron `app.asar` directly with a tiny self-contained
 * ASAR reader (the repo ships no reader of its own; `scratch/` is gitignored).
 *
 * ASAR layout used here (all little-endian u32):
 *   bytes 0..3   = header size of the size-prefixed pickle (u32 @ 0)
 *   bytes 4..7   = header size (u32 @ 4)
 *   bytes 8..11  = JSON payload length (u32 @ 8) ... mirrored at 12 per format
 *   bytes 16..   = header JSON ({ files: { name: node } })
 *   file data    = 8 + headerSize + Number(entry.offset)
 *
 * Usage:
 *   node scripts/contract-check.mjs [--asar <path>]
 *   RC_DSH_ASAR=<path> node scripts/contract-check.mjs
 *
 * Exit codes: 0 = PASS or SKIP, 1 = FAIL.
 *
 * Output: human-readable lines (✓ / ✗ / ⚠) plus a JSON report. The report is
 * written to `scratch/contract-report.json` when `scratch/` exists (gitignored),
 * otherwise to `dist/contract-report.json` when `dist/` exists; never to the
 * repo root (a root-level report must stay uncommitted — lead note).
 */

import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const EXPECTED_DSH_VERSION = '0.2.1-rc.3'

const PKG = (name) => `dsh/node_modules/@deepseek-ai/${name}`
const FILES = {
  sessionController: `${PKG('dsh-api-session-controller')}/lib/typert.host.js`,
  gateway: `${PKG('dsh-api-gateway')}/lib/index.js`,
  gatewayStreamProtocol: `${PKG('dsh-api-gateway')}/lib/types/stream-protocol.js`,
  connection: `${PKG('dsh-client-connection')}/lib/index.js`,
  webServer: `${PKG('dsh-host-webserver')}/lib/index.js`,
  remotes: `${PKG('dsh-api-remotes')}/lib/index.js`,
  remotesEvents: `${PKG('dsh-api-remotes')}/lib/types/remote-events.js`,
  clientModules: `${PKG('dsh-client-modules')}/lib/index.js`,
  dshPackageJson: 'dsh/package.json',
}

/* ------------------------------------------------------------------------- */
/* Minimal read-only ASAR reader                                             */
/* ------------------------------------------------------------------------- */

function openAsar(file) {
  const fd = fs.openSync(file, 'r')
  let header, baseOffset
  try {
    const prefix = Buffer.alloc(16)
    fs.readSync(fd, prefix, 0, 16, 0)
    const headerSize = prefix.readUInt32LE(4)
    const jsonLength = prefix.readUInt32LE(12)
    if (!Number.isFinite(headerSize) || !Number.isFinite(jsonLength) || jsonLength <= 0) {
      throw new Error(`implausible ASAR header (headerSize=${headerSize}, jsonLength=${jsonLength})`)
    }
    const json = Buffer.alloc(jsonLength)
    fs.readSync(fd, json, 0, jsonLength, 16)
    header = JSON.parse(json.toString('utf8'))
    baseOffset = 8 + headerSize
  } finally {
    fs.closeSync(fd)
  }
  if (!header || typeof header !== 'object' || typeof header.files !== 'object') {
    throw new Error('ASAR header has no files map')
  }
  const unpackedDir = `${file}.unpacked`

  function lookup(p) {
    let node = header
    for (const part of p.split('/').filter(Boolean)) {
      if (!node || typeof node.files !== 'object' || !node.files[part]) return null
      node = node.files[part]
    }
    return node
  }

  function isDir(entry) {
    return !!entry && typeof entry.files === 'object'
  }

  function readFile(p) {
    const entry = lookup(p)
    if (!entry) throw new Error(`not found in asar: ${p}`)
    if (isDir(entry)) throw new Error(`not a file in asar: ${p}`)
    if (entry.unpacked) {
      return fs.readFileSync(path.join(unpackedDir, ...p.split('/').filter(Boolean)))
    }
    if (entry.offset === undefined || entry.size === undefined) {
      throw new Error(`asar entry lacks offset/size: ${p}`)
    }
    const target = fs.openSync(file, 'r')
    try {
      const buf = Buffer.alloc(Number(entry.size))
      let read = 0
      while (read < buf.length) {
        const n = fs.readSync(target, buf, read, buf.length - read, baseOffset + Number(entry.offset) + read)
        if (n <= 0) throw new Error(`short read for ${p}`)
        read += n
      }
      return buf
    } finally {
      fs.closeSync(target)
    }
  }

  function stat(p) {
    const entry = lookup(p)
    if (!entry) return null
    return isDir(entry) ? { type: 'dir' } : { type: 'file', size: Number(entry.size ?? 0) }
  }

  function list(prefix = '') {
    const node = prefix ? lookup(prefix) : header
    if (!node || !isDir(node)) return []
    return Object.entries(node.files).map(([name, child]) => ({
      name,
      path: `${prefix}/${name}`.replace(/^\/+/, ''),
      type: isDir(child) ? 'dir' : 'file',
      size: isDir(child) ? undefined : Number(child.size ?? 0),
    }))
  }

  function walk(prefix = '') {
    const out = []
    for (const row of list(prefix)) {
      out.push(row)
      if (row.type === 'dir') out.push(...walk(row.path))
    }
    return out
  }

  return { file, header, baseOffset, readFile, stat, list, walk }
}

/* ------------------------------------------------------------------------- */
/* ASAR discovery                                                            */
/* ------------------------------------------------------------------------- */

function usage() {
  return [
    'Usage: node scripts/contract-check.mjs [--asar <path>]',
    '',
    'Options:',
    '  --asar <path>   Explicit app.asar path (also: RC_DSH_ASAR env var).',
    '  --help          Show this help.',
    '',
    'When no app.asar is found the check reports SKIP and exits 0 (never PASS).',
  ].join('\n')
}

function parseArgs(argv) {
  const out = { asar: null, help: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') out.help = true
    else if (arg === '--asar') out.asar = argv[++i] ?? null
    else if (arg.startsWith('--asar=')) out.asar = arg.slice('--asar='.length)
    else throw new Error(`unknown argument: ${arg}`)
  }
  return out
}

function fileIfExists(p) {
  try {
    return p && fs.statSync(p).isFile() ? p : null
  } catch {
    return null
  }
}

/** Locate an installed DSH app.asar. Returns { path, source } or null. */
function findAsar(explicit, envPath) {
  if (explicit) {
    const found = fileIfExists(path.resolve(explicit))
    if (!found) throw new Error(`--asar path does not exist or is not a file: ${explicit}`)
    return { path: found, source: '--asar' }
  }
  if (envPath) {
    const found = fileIfExists(path.resolve(envPath))
    if (!found) throw new Error(`RC_DSH_ASAR does not exist or is not a file: ${envPath}`)
    return { path: found, source: 'RC_DSH_ASAR' }
  }

  const home = os.homedir()
  const candidates = []
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA
    const roaming = process.env.APPDATA
    const programFiles = process.env.ProgramFiles
    const programFilesX86 = process.env['ProgramFiles(x86)']
    for (const base of [local, roaming, programFiles, programFilesX86]) {
      if (base) candidates.push(path.join(base, 'Programs', 'DeepSeek Harness', 'resources', 'app.asar'))
      if (base) candidates.push(path.join(base, 'DeepSeek Harness', 'resources', 'app.asar'))
    }
    if (programFiles) candidates.push(path.join(programFiles, 'DeepSeek Harness', 'resources', 'app.asar'))
    // This machine may have DSH installed on a non-system drive while %LOCALAPPDATA%
    // still points at C:. Mirror the per-user install path across available drives.
    const user = path.basename(home)
    for (const letter of 'CDEFGHIJKLMNOPQRSTUVWXYZAB') {
      const drive = `${letter}:\\`
      if (!fs.existsSync(drive)) continue
      candidates.push(path.join(drive, 'Users', user, 'AppData', 'Local', 'Programs', 'DeepSeek Harness', 'resources', 'app.asar'))
      candidates.push(path.join(drive, 'Program Files', 'DeepSeek Harness', 'resources', 'app.asar'))
    }
  } else if (process.platform === 'darwin') {
    candidates.push('/Applications/DeepSeek Harness.app/Contents/Resources/app.asar')
    candidates.push(path.join(home, 'Applications', 'DeepSeek Harness.app', 'Contents', 'Resources', 'app.asar'))
  } else {
    candidates.push(path.join(home, '.local', 'share', 'DeepSeek Harness', 'resources', 'app.asar'))
    candidates.push(path.join(home, '.local', 'share', 'deepseek-harness', 'resources', 'app.asar'))
    candidates.push('/opt/DeepSeek Harness/resources/app.asar')
    candidates.push('/usr/lib/deepseek-harness/resources/app.asar')
  }

  const seen = new Set()
  for (const candidate of candidates) {
    if (seen.has(candidate)) continue
    seen.add(candidate)
    const found = fileIfExists(candidate)
    if (found) return { path: found, source: 'default install path' }
  }

  // Last resort: resolve the `dsh` launcher on PATH and look for app.asar in its
  // ancestors (the CLI lives under <app>/resources/runtime/cli/bin).
  const dshFromPath = resolveDshFromPath()
  if (dshFromPath) {
    let dir = path.dirname(dshFromPath)
    for (let depth = 0; depth < 8; depth += 1) {
      for (const rel of [['app.asar'], ['resources', 'app.asar']]) {
        const candidate = path.join(dir, ...rel)
        const found = fileIfExists(candidate)
        if (found) return { path: found, source: `derived from ${dshFromPath}` }
      }
      const parent = path.dirname(dir)
      if (parent === dir) break
      dir = parent
    }
  }

  return { path: null, source: null, attempted: [...seen] }
}

function resolveDshFromPath() {
  try {
    const command = process.platform === 'win32' ? 'where' : 'which'
    const result = spawnSync(command, ['dsh'], { encoding: 'utf8', timeout: 5000, windowsHide: true })
    if (result.error || result.status !== 0) return null
    const first = (result.stdout || '').split(/\r?\n/).map((line) => line.trim()).find(Boolean)
    return first && fs.existsSync(first) ? first : null
  } catch {
    return null
  }
}

/* ------------------------------------------------------------------------- */
/* Checks                                                                    */
/* ------------------------------------------------------------------------- */

/** Each spec is one console line / JSON check. */
const SPECS = [
  // session-controller typert descriptors (task-5 / blueprint §12.1)
  ...['session/list', 'session/follow', 'session/page', 'session/prompt', 'session/cancel', 'session/projections'].map(
    (descriptor) => ({
      id: `descriptor:${descriptor}`,
      title: `session-controller descriptor ${descriptor}`,
      files: [FILES.sessionController],
      pattern: new RegExp(`["'\`]${descriptor.replace('/', '\\/')}["'\`]`),
      describe: `quoted "${descriptor}" descriptor name`,
    }),
  ),
  // typertGateway service surface (internal.ts TypertGatewayService)
  {
    id: 'gateway:invoke',
    title: 'typertGateway.invoke',
    files: [FILES.gateway],
    pattern: /\binvoke\b/,
    describe: 'invoke method',
  },
  {
    id: 'gateway:stream',
    title: 'typertGateway.stream',
    files: [FILES.gateway],
    pattern: /\bstream\b/,
    describe: 'stream method',
  },
  {
    id: 'gateway:wireStream',
    title: 'typertGateway.wireStream',
    files: [FILES.gateway],
    pattern: /\bwireStream\b/,
    describe: 'wireStream API',
  },
  {
    id: 'gateway:dispatchRpc',
    title: 'typertGateway.dispatchRpc',
    files: [FILES.gateway],
    pattern: /\bdispatchRpc\b/,
    describe: 'dispatchRpc method',
  },
  {
    id: 'gateway:hasLiveClient',
    title: 'typertGateway.hasLiveClient',
    files: [FILES.gateway],
    pattern: /\bhasLiveClient\b/,
    describe: 'hasLiveClient method',
  },
  // connection service (internal.ts ConnectionService)
  {
    id: 'connection:createPeer',
    title: 'connection.createPeer',
    files: [FILES.connection],
    pattern: /\bcreatePeer\b/,
    describe: 'createPeer method',
  },
  {
    id: 'connection:requestRejection',
    title: 'connection.requestRejection',
    files: [FILES.connection],
    pattern: /\brequestRejection\b/,
    describe: 'requestRejection method',
  },
  {
    id: 'connection:admit',
    title: 'connection.admit',
    files: [FILES.connection],
    pattern: /\badmit\b/,
    describe: 'admit method',
  },
  {
    id: 'connection:authenticatedUrl',
    title: 'connection.authenticatedUrl',
    files: [FILES.connection],
    pattern: /\bauthenticatedUrl\b/,
    describe: 'authenticatedUrl method',
  },
  // host web server (internal.ts WebServerService)
  {
    id: 'webServer:register',
    title: 'webServer.register',
    files: [FILES.webServer],
    pattern: /\bregister\b/,
    describe: 'register method',
  },
  {
    id: 'webServer:registerUpgrade',
    title: 'webServer.registerUpgrade',
    files: [FILES.webServer],
    pattern: /\bregisterUpgrade\b/,
    describe: 'registerUpgrade method',
  },
  // forwarded waterfall events + $events result route
  {
    id: 'remotes:approval-request',
    title: 'api-remotes forwarded approval/request',
    files: [FILES.remotes],
    pattern: /["'`]approval\/request["'`]/,
    describe: 'quoted "approval/request" waterfall event',
  },
  {
    id: 'remotes:user-questions-request',
    title: 'api-remotes forwarded user-questions/request',
    files: [FILES.remotes],
    pattern: /["'`]user-questions\/request["'`]/,
    describe: 'quoted "user-questions/request" waterfall event',
  },
  {
    id: 'remotes:events-result',
    title: '$events/result endpoint',
    // The check list expects this in dsh-api-remotes; in the installed 0.2.1-rc.3
    // build the HTTP RPC is implemented by dsh-api-gateway and only the forwarded
    // waterfall event names live in dsh-api-remotes. Scan both packages so a
    // relocation is reported instead of turning the check red for the wrong file.
    files: [FILES.remotes, FILES.remotesEvents, FILES.gateway, FILES.gatewayStreamProtocol],
    pattern: /\$events\/result/,
    describe: '$events/result route',
    noteWhenFoundOutsidePrimary: FILES.remotes,
  },
  // client plugin manifest scanning (dsh.client field + /plugins combo route)
  {
    id: 'clientModules:plugin-route',
    title: "client-modules /plugins route",
    files: [FILES.clientModules],
    pattern: /["'`]\/plugins["'`]/,
    describe: 'quoted "/plugins" PLUGIN_ROUTE',
  },
  {
    id: 'clientModules:dsh-client-scan',
    title: 'client-modules dsh.client manifest scan',
    files: [FILES.clientModules],
    pattern: /\bdsh\.client\b/,
    describe: 'dsh.client manifest field handling',
  },
]

function runChecks(asar) {
  const checks = []
  const textCache = new Map()

  function readText(file) {
    if (textCache.has(file)) return textCache.get(file)
    const text = asar.readFile(file).toString('utf8')
    textCache.set(file, text)
    return text
  }

  for (const spec of SPECS) {
    const missingFiles = []
    let hit = null
    let failures = []
    for (const file of spec.files) {
      let text
      try {
        text = readText(file)
      } catch (error) {
        missingFiles.push({ file, error: String(error.message ?? error) })
        continue
      }
      const match = spec.pattern.exec(text)
      if (match) {
        const index = match.index
        hit = {
          file,
          pattern: String(spec.pattern),
          index,
          occurrences: countOccurrences(text, spec.pattern),
        }
        break
      } else {
        failures.push(file)
      }
    }

    if (hit) {
      const notes = []
      if (spec.noteWhenFoundOutsidePrimary && hit.file !== spec.noteWhenFoundOutsidePrimary) {
        notes.push(
          `implemented by ${hit.file}; the expected ${spec.noteWhenFoundOutsidePrimary} location does not own this route in this build (relocated, wire contract present)`,
        )
      }
      checks.push({
        id: spec.id,
        title: spec.title,
        status: 'pass',
        evidence: { file: hit.file, describe: spec.describe, pattern: hit.pattern, index: hit.index, occurrences: hit.occurrences },
        notes,
      })
    } else {
      checks.push({
        id: spec.id,
        title: spec.title,
        status: 'fail',
        evidence: {
          expected: spec.describe,
          files: spec.files,
          scannedWithoutMatch: failures,
          missingFiles,
        },
        notes: missingFiles.length > 0 ? [`missing/unreadable asar entries: ${missingFiles.map((m) => m.file).join(', ')}`] : [],
      })
    }
  }

  // DSH version is a warning, never a failure (npm may ship a patched rc build).
  let version = null
  let versionCheck
  try {
    const pkg = JSON.parse(readText(FILES.dshPackageJson))
    version = typeof pkg.version === 'string' ? pkg.version : null
    if (version === EXPECTED_DSH_VERSION) {
      versionCheck = {
        id: 'dsh:version',
        title: `DSH runtime version ${EXPECTED_DSH_VERSION}`,
        status: 'pass',
        evidence: { file: FILES.dshPackageJson, value: version, expected: EXPECTED_DSH_VERSION },
        notes: [],
      }
    } else {
      versionCheck = {
        id: 'dsh:version',
        title: `DSH runtime version ${EXPECTED_DSH_VERSION}`,
        status: 'warn',
        evidence: { file: FILES.dshPackageJson, value: version, expected: EXPECTED_DSH_VERSION },
        notes: [`installed version ${String(version)} differs from the tested ${EXPECTED_DSH_VERSION}; descriptor checks still ran`],
      }
    }
  } catch (error) {
    versionCheck = {
      id: 'dsh:version',
      title: `DSH runtime version ${EXPECTED_DSH_VERSION}`,
      status: 'warn',
      evidence: { file: FILES.dshPackageJson, error: String(error.message ?? error) },
      notes: ['could not read dsh/package.json version'],
    }
  }
  checks.push(versionCheck)

  return { checks, version }
}

function countOccurrences(text, pattern) {
  const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`
  const global = new RegExp(pattern.source, flags)
  let count = 0
  while (global.exec(text) !== null) {
    count += 1
    if (count > 10_000) break
  }
  return count
}

/* ------------------------------------------------------------------------- */
/* Report                                                                    */
/* ------------------------------------------------------------------------- */

function writeReport(report) {
  // Reports never go into dist/ (it is committed) or the repo root.
  const candidates = [path.join(ROOT, 'scratch'), path.join(ROOT, '.tmp')]
  let dir = null
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
      dir = candidate
      break
    }
  }
  if (dir === null) {
    dir = path.join(ROOT, '.tmp')
    fs.mkdirSync(dir, { recursive: true })
  }
  const destination = path.join(dir, 'contract-report.json')
  fs.writeFileSync(destination, `${JSON.stringify(report, null, 2)}\n`, 'utf8')
  return {
    path: destination,
    note: 'reports are written to scratch/ or .tmp/, both gitignored; never commit this report',
  }
}

function printReport(report, reportInfo, attempted) {
  const lines = []
  lines.push(`dsh-remote-control contract check (expected DSH ${EXPECTED_DSH_VERSION})`)
  lines.push(`asar: ${report.asar ?? '<not found>'}`)
  if (report.asarDetection) lines.push(`detection: ${report.asarDetection}`)
  lines.push('')

  if (report.status === 'skip') {
    lines.push('SKIP: no DeepSeek Harness app.asar found on this machine.')
    lines.push('      Contract checks were NOT run and this is not a PASS.')
    lines.push('      Provide one explicitly:')
    lines.push('        node scripts/contract-check.mjs --asar <path-to-app.asar>')
    lines.push('        RC_DSH_ASAR=<path-to-app.asar> node scripts/contract-check.mjs')
    if (attempted && attempted.length > 0) {
      lines.push('      tried:')
      for (const candidate of attempted) lines.push(`        - ${candidate}`)
    }
  } else {
    for (const check of report.checks) {
      const glyph = check.status === 'pass' ? '✓' : check.status === 'warn' ? '⚠' : '✗'
      const location = check.evidence?.file ? ` [${check.evidence.file}]` : ''
      lines.push(`${glyph} ${check.title}${location}`)
      for (const note of check.notes ?? []) lines.push(`    note: ${note}`)
      if (check.status === 'fail') {
        lines.push(`    expected: ${check.evidence?.expected ?? ''}`)
        for (const file of check.evidence?.files ?? []) lines.push(`    scanned: ${file}`)
      }
    }
    const summary = report.summary
    lines.push('')
    lines.push(`checks: ${summary.pass} pass, ${summary.fail} fail, ${summary.warn} warn (${checksCount(report)} total)`)
    lines.push(`RESULT: ${report.status.toUpperCase()}`)
  }

  lines.push(reportInfo.path ? `report: ${reportInfo.path}` : `report: not written (${reportInfo.note})`)
  lines.push(`note: ${reportInfo.note}`)
  console.log(lines.join('\n'))
}

function checksCount(report) {
  return Array.isArray(report.checks) ? report.checks.length : 0
}

/* ------------------------------------------------------------------------- */
/* Main                                                                      */
/* ------------------------------------------------------------------------- */

function main() {
  let parsed
  try {
    parsed = parseArgs(process.argv.slice(2))
  } catch (error) {
    console.error(`FAIL: ${error.message}\n\n${usage()}`)
    process.exit(1)
  }
  if (parsed.help) {
    console.log(usage())
    process.exit(0)
  }

  const generatedAt = new Date().toISOString()
  let found
  try {
    found = findAsar(parsed.asar, process.env.RC_DSH_ASAR)
  } catch (error) {
    console.error(`FAIL: ${error.message}`)
    process.exit(1)
  }

  if (!found?.path) {
    const report = {
      status: 'skip',
      generatedAt,
      expectedDshVersion: EXPECTED_DSH_VERSION,
      asar: null,
      asarDetection: null,
      checks: [],
      summary: { pass: 0, fail: 0, warn: 0, skip: 0 },
      note: 'No installed DSH app.asar found; contract not verified (SKIP is not PASS).',
    }
    const reportInfo = writeReport(report)
    printReport(report, reportInfo, found?.attempted ?? [])
    process.exit(0)
  }

  let asar
  let report
  try {
    asar = openAsar(found.path)
    const { checks, version } = runChecks(asar)
    const summary = { pass: 0, fail: 0, warn: 0, skip: 0 }
    for (const check of checks) summary[check.status] += 1
    const status = summary.fail > 0 ? 'fail' : 'pass'
    report = {
      status,
      generatedAt,
      expectedDshVersion: EXPECTED_DSH_VERSION,
      asar: found.path,
      asarDetection: found.source,
      dshVersion: version,
      checks,
      summary,
    }
  } catch (error) {
    report = {
      status: 'fail',
      generatedAt,
      expectedDshVersion: EXPECTED_DSH_VERSION,
      asar: found.path,
      asarDetection: found.source,
      error: String(error.stack ?? error.message ?? error),
      checks: [],
      summary: { pass: 0, fail: 1, warn: 0, skip: 0 },
    }
  }

  const reportInfo = writeReport(report)
  printReport(report, reportInfo)
  process.exit(report.status === 'pass' ? 0 : 1)
}

main()
