#!/usr/bin/env node
/**
 * Build the DSH Remote Control **phone PWA** (`dist/pwa/`).
 *
 * Output (served by the Host listener under `/rc/`):
 *
 *   dist/pwa/index.html            pwa/index.html
 *   dist/pwa/app.js                esbuild bundle of pwa/src/app.ts   (ESM, browser)
 *   dist/pwa/sw.js                 esbuild bundle of pwa/src/sw.ts    (IIFE, classic worker)
 *   dist/pwa/app.css               pwa/app.css
 *   dist/pwa/manifest.webmanifest  pwa/manifest.webmanifest
 *   dist/pwa/icon.svg              icon.svg (repo root)
 *
 * `dist/pwa` is removed first so no stale asset survives. Node builtins +
 * esbuild only; every required output is re-read after the build and checked
 * for its contract strings. Any failure exits 1.
 */

import { copyFile, mkdir, readFile, rm, stat } from 'node:fs/promises'
import { dirname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { build } from 'esbuild'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const OUT_DIR = resolve(ROOT, 'dist', 'pwa')
const SOURCE_DIR = resolve(ROOT, 'pwa')

const STATIC_FILES = ['index.html', 'app.css', 'manifest.webmanifest']

function fail(message) {
  console.error(`[build:pwa] FAIL: ${message}`)
  process.exit(1)
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`
  return `${(bytes / 1024).toFixed(1)} KiB`
}

async function esbuildBundle({ entry, outfile, format }) {
  try {
    await build({
      entryPoints: [entry],
      outfile,
      bundle: true,
      format,
      platform: 'browser',
      target: 'es2022',
      write: true,
      logLevel: 'silent',
      sourcemap: false,
      legalComments: 'none',
      absWorkingDir: ROOT,
    })
  } catch (error) {
    fail(`esbuild failed for ${entry}: ${error instanceof Error ? error.message : String(error)}`)
  }
}

async function readRequired(path, label) {
  try {
    return await readFile(path, 'utf8')
  } catch {
    fail(`missing required output: ${label}`)
  }
}

async function assertContains(path, label, needles) {
  const content = await readRequired(path, label)
  for (const needle of needles) {
    if (!content.includes(needle)) {
      fail(`${label} does not contain required text ${JSON.stringify(needle)}`)
    }
  }
  return content
}

async function assertDoesNotContain(path, label, needles) {
  const content = await readRequired(path, label)
  for (const needle of needles) {
    if (content.includes(needle)) {
      fail(`${label} contains forbidden text ${JSON.stringify(needle)}`)
    }
  }
}

async function main() {
  // 1. Clean output tree â€” the listener serves exactly this directory.
  await rm(OUT_DIR, { recursive: true, force: true })
  await mkdir(OUT_DIR, { recursive: true })

  // 2. Bundle the application (ESM module script) and the service worker (classic IIFE).
  await esbuildBundle({
    entry: resolve(SOURCE_DIR, 'src', 'app.ts'),
    outfile: resolve(OUT_DIR, 'app.js'),
    format: 'esm',
  })
  await esbuildBundle({
    entry: resolve(SOURCE_DIR, 'src', 'sw.ts'),
    outfile: resolve(OUT_DIR, 'sw.js'),
    format: 'iife',
  })

  // 3. Copy the static shell and the plugin icon.
  for (const file of STATIC_FILES) {
    try {
      await copyFile(resolve(SOURCE_DIR, file), resolve(OUT_DIR, file))
    } catch (error) {
      fail(`could not copy ${file}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  try {
    await copyFile(resolve(ROOT, 'icon.svg'), resolve(OUT_DIR, 'icon.svg'))
    await copyFile(resolve(SOURCE_DIR, 'dsh-icon.png'), resolve(OUT_DIR, 'dsh-icon.png'))
    await copyFile(resolve(SOURCE_DIR, 'dsh-icon-192.png'), resolve(OUT_DIR, 'dsh-icon-192.png'))
  } catch (error) {
    fail(`could not copy the icons: ${error instanceof Error ? error.message : String(error)}`)
  }

  // 4. Verify the shipped contract, not just file existence.
  await assertContains(resolve(OUT_DIR, 'index.html'), 'index.html', [
    "default-src 'self'",
    "connect-src 'self'",
    "img-src 'self' data:",
    "script-src 'self'",
    'frame-ancestors',
    'href="/rc/manifest.webmanifest"',
    'href="/rc/app.css"',
    'src="/rc/app.js"',
    'type="module"',
  ])
  await assertDoesNotContain(resolve(OUT_DIR, 'index.html'), 'index.html', [
    'sw.js', // registration lives in app.ts (secure-context gate)
    '<script>', // no inline script under the CSP
  ])
  await assertContains(resolve(OUT_DIR, 'app.js'), 'app.js', [
    'RC_API_PATH',
    'RC_WS_PATH',
    '/pair/claim',
    '#/pair',
    '/rc/sw.js',
    'serviceWorker',
    // Pairing poll: CSRF-protected POST with the secrets in the JSON body.
    '/pair/status',
    'claimId',
    'pollToken',
    // One-time code must be stripped from URL + history before any network work.
    'replaceState',
    // New security surfaces: device lock / security closed / Access re-auth.
    'health',
    'deviceLock',
    'pair.deviceLocked',
    'pair.securityClosedTitle',
    'lock.idleWarning',
    'security.title',
    'access.title',
    // WS close codes 4001 deviceLost / 4002 securityClosed / 4003 idleTimeout / 4004 leaseLost.
    '4001',
    '4002',
    '4003',
    '4004',
    // Approval delivery contract: explicit answer ack + timeout retry, reasoning
    // content rendering, and the persistent TR/EN switch.
    'answer-result',
    'approval.sending',
    'approval.ackTimeout',
    'reasoning.title',
    'reasoning-delta',
    'lang.switch',
    'sessions.refreshed',
    // Round-6 features: workspace groups, new sessions, attachments and the
    // CSP-safe Markdown renderer.
    'workspaces',
    '/files',
    '/attachments/',
    'renderMarkdown',
    'attach.failed',
    'workspace.default',
  ])
  await assertDoesNotContain(resolve(OUT_DIR, 'app.js'), 'app.js', [
    // The poll secret never becomes a GET query value.
    '/pair/status?',
    // The one-time pairing code never gets (re)written into the URL.
    '?c=',
    // DOM sinks / eval / persistence of secrets.
    'innerHTML',
    'outerHTML',
    'insertAdjacentHTML',
    'document.write',
    'eval(',
    'new Function',
    'localStorage',
    'sessionStorage',
    'indexedDB',
    'document.cookie',
    'console.log',
  ])
  await assertContains(resolve(OUT_DIR, 'sw.js'), 'sw.js', [
    'dsh-remote-control-shell-v3',
    '/rc/api/',
    '/rc/ws',
  ])
  await assertContains(resolve(OUT_DIR, 'manifest.webmanifest'), 'manifest.webmanifest', [
    '"name": "DSH Remote Control"',
    '"start_url": "/rc/"',
    '"display": "standalone"',
    '/rc/dsh-icon.png',
    '/rc/dsh-icon-192.png',
  ])
  await assertContains(resolve(OUT_DIR, 'index.html'), 'index.html', [
    'viewport-fit=cover',
    'dsh-icon-192.png',
    'dsh-icon.png',
  ])

  // 5. Report.
  const names = [
    'index.html',
    'app.js',
    'sw.js',
    'app.css',
    'manifest.webmanifest',
    'icon.svg',
    'dsh-icon.png',
    'dsh-icon-192.png',
  ]
  console.log('[build:pwa] ok')
  let total = 0
  for (const name of names) {
    const info = await stat(resolve(OUT_DIR, name))
    total += info.size
    const relative = resolve(OUT_DIR, name).split(sep).join('/').replace(`${ROOT.split(sep).join('/')}/`, '')
    console.log(`  ${relative}  ${formatBytes(info.size)}`)
  }
  console.log(`  total: ${formatBytes(total)}`)
  console.log(
    '  checks: CSP + module script + /rc paths + manifest + SW shell/API guards + pairing POST body + fragment strip + WS close codes + no DOM sinks/storage',
  )
}

await main()
