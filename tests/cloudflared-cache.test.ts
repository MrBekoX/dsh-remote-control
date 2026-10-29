/**
 * Cached-cloudflared discovery: the plugin may reuse a binary that an explicit
 * panel-triggered install or the operator placed in the managed cache directory.
 *
 * The second half of this file is FAILING-FIRST: it pins the verified-cache
 * behavior (pinned digest re-verified on every use, symlinks/size mismatches
 * refused, only the exact pinned filename accepted) before implementation.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, readdir, readFile, rm, symlink, utimes, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, test } from 'node:test'

import {
  createCloudflaredInstaller,
  findCachedCloudflared,
  type CloudflaredAsset,
  type CloudflaredRelease,
} from '../src/cloudflared.js'
import type { Logger } from '../src/shared/internal.js'
import type { SpawnFn } from '../src/tunnel-process.js'

let root = ''

before(async () => {
  root = await mkdtemp(join(tmpdir(), 'dsh-rc-cache-'))
})

after(async () => {
  if (root !== '') await rm(root, { recursive: true, force: true })
})

test('returns null for a missing or empty cache directory', async () => {
  assert.equal(await findCachedCloudflared(join(root, 'missing')), null)
  const empty = join(root, 'empty')
  await mkdir(empty, { recursive: true })
  assert.equal(await findCachedCloudflared(empty), null)
})

test('returns the newest matching cloudflared-* file and ignores others', async () => {
  const directory = join(root, 'populated')
  await mkdir(directory, { recursive: true })
  const older = join(directory, 'cloudflared-2026.1.0-win32-x64.exe')
  const newer = join(directory, 'cloudflared-2026.10.5-win32-x64.exe')
  const unrelated = join(directory, 'other-tool.exe')
  await writeFile(older, 'old')
  await writeFile(newer, 'new')
  await writeFile(unrelated, 'x')
  await utimes(older, new Date(1_000), new Date(1_000))
  await utimes(newer, new Date(2_000), new Date(2_000))
  await utimes(unrelated, new Date(3_000), new Date(3_000))
  assert.equal(await findCachedCloudflared(directory), newer)
})

test('ignores a directory whose name looks like a binary', async () => {
  const directory = join(root, 'with-dir')
  await mkdir(join(directory, 'cloudflared-fake'), { recursive: true })
  assert.equal(await findCachedCloudflared(directory), null)
})

/* ------------------------------------------------------------------------- */
/* Verified cache (pinned digest re-checked on every use)                    */
/* ------------------------------------------------------------------------- */

function silentLogger(): Logger {
  return { error: () => undefined, warn: () => undefined, info: () => undefined, debug: () => undefined }
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex')
}

function testRelease(executable: Buffer): { release: CloudflaredRelease; asset: CloudflaredAsset } {
  const asset: CloudflaredAsset = {
    platform: 'linux',
    arch: 'x64',
    asset: 'cloudflared-linux-amd64',
    sizeBytes: executable.length,
    sha256: sha256(executable),
    archive: 'none',
    executableName: 'cloudflared',
  }
  return {
    asset,
    release: {
      version: '2026.10.5',
      releaseBaseUrl: 'https://github.com/cloudflare/cloudflared/releases/download/2026.10.5',
      assets: { 'linux-x64': asset },
    },
  }
}

/** No cloudflared on PATH: every discovery spawn reports ENOENT. */
function noBinarySpawn(): SpawnFn {
  return () => {
    const child = new EventEmitter() as unknown as import('node:child_process').ChildProcess
    Object.assign(child, {
      stdout: new EventEmitter(),
      stderr: new EventEmitter(),
      exitCode: null,
      signalCode: null,
      kill: () => true,
    })
    setImmediate(() => {
      child.emit('error', Object.assign(new Error('not found'), { code: 'ENOENT' }))
    })
    return child
  }
}

test('verified cache: accepts the exact pinned cache file and re-verifies it on every use', async () => {
  const executable = Buffer.from('official cached binary bytes')
  const { release, asset } = testRelease(executable)
  const cacheDir = join(root, 'cache-verified-again')
  await mkdir(cacheDir, { recursive: true })
  const cachedPath = join(cacheDir, `cloudflared-${release.version}-${asset.platform}-${asset.arch}`)
  await writeFile(cachedPath, executable)

  const installer = createCloudflaredInstaller({
    configuredPath: '',
    cacheDir,
    platform: 'linux',
    arch: 'x64',
    release,
    log: silentLogger(),
    spawn: noBinarySpawn(),
  })
  const first = await installer.resolve()
  assert.equal(first.installed?.source, 'cache')
  assert.equal(first.installed?.verified, true)
  assert.equal(first.installed?.version, '2026.10.5')

  // Same file, later use: digest changed out-of-band -> delete, never execute.
  await writeFile(cachedPath, Buffer.from('swapped bytes'))
  const second = await installer.resolve()
  assert.equal(second.installed, null)
  assert.deepEqual(await readdir(cacheDir), [])
})

test('verified cache: a symlinked cache entry is refused (no execution via symlink swap)', async (t) => {
  const executable = Buffer.from('link target bytes')
  const { release, asset } = testRelease(executable)
  const cacheDir = join(root, 'cache-symlink')
  await mkdir(cacheDir, { recursive: true })
  const target = join(root, 'link-target-binary')
  await writeFile(target, executable)
  const linkPath = join(cacheDir, `cloudflared-${release.version}-${asset.platform}-${asset.arch}`)
  try {
    await symlink(target, linkPath)
  } catch {
    t.skip('creating symlinks is not permitted on this host')
    return
  }

  const installer = createCloudflaredInstaller({
    configuredPath: '',
    cacheDir,
    platform: 'linux',
    arch: 'x64',
    release,
    log: silentLogger(),
    spawn: noBinarySpawn(),
  })
  const resolved = await installer.resolve()
  assert.equal(resolved.installed, null)
})

test('verified cache: only the exact pinned filename is accepted, stale versions are ignored', async () => {
  const executable = Buffer.from('current bytes')
  const { release } = testRelease(executable)
  const cacheDir = join(root, 'cache-stale')
  await mkdir(cacheDir, { recursive: true })
  // A file that would have matched the old "newest cloudflared-*" heuristic.
  await writeFile(join(cacheDir, 'cloudflared-2026.1.0-linux-x64'), executable)

  const installer = createCloudflaredInstaller({
    configuredPath: '',
    cacheDir,
    platform: 'linux',
    arch: 'x64',
    release,
    log: silentLogger(),
    spawn: noBinarySpawn(),
  })
  const resolved = await installer.resolve()
  assert.equal(resolved.installed, null)
  assert.deepEqual(await readdir(cacheDir), ['cloudflared-2026.1.0-linux-x64'])
})

test('verified cache: a size mismatch is rejected before hashing/executing', async () => {
  const executable = Buffer.from('expected bytes')
  const { release, asset } = testRelease(executable)
  const cacheDir = join(root, 'cache-size-mismatch')
  await mkdir(cacheDir, { recursive: true })
  const cachedPath = join(cacheDir, `cloudflared-${release.version}-${asset.platform}-${asset.arch}`)
  await writeFile(cachedPath, Buffer.concat([executable, Buffer.from('trailing')]))

  const installer = createCloudflaredInstaller({
    configuredPath: '',
    cacheDir,
    platform: 'linux',
    arch: 'x64',
    release,
    log: silentLogger(),
    spawn: noBinarySpawn(),
  })
  const resolved = await installer.resolve()
  assert.equal(resolved.installed, null)
  assert.deepEqual(await readdir(cacheDir), [])
})

test('verified cache: a valid cache file is re-hashed and reported verified', async () => {
  const executable = Buffer.from('hash me every time')
  const { release, asset } = testRelease(executable)
  const cacheDir = join(root, 'cache-hash-ok')
  await mkdir(cacheDir, { recursive: true })
  const cachedPath = join(cacheDir, `cloudflared-${release.version}-${asset.platform}-${asset.arch}`)
  await writeFile(cachedPath, executable)
  assert.deepEqual(await readFile(cachedPath), executable)

  let hashCalls = 0
  const installer = createCloudflaredInstaller({
    configuredPath: '',
    cacheDir,
    platform: 'linux',
    arch: 'x64',
    release,
    log: silentLogger(),
    spawn: noBinarySpawn(),
    hashFile: async (path) => {
      hashCalls += 1
      return sha256(await readFile(path))
    },
  })
  const resolved = await installer.resolve()
  assert.equal(resolved.installed?.verified, true)
  assert.equal(hashCalls, 1)
})
