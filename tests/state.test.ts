/**
 * Persisted plugin state v2 (`$DSH_HOME/remote-control/state.json`):
 * - v2 shape: `{v:2, lastEnabled, updatedAt, revocationEpoch, securityClosed,
 *   securityClosedReason, activeDeviceId, leaseStartedAt, leaseLastActivityAt}`,
 * - v1 files are migrated in memory (never silently re-enabled / never silently
 *   clears a security closure); a v1 `save()` payload during integration still
 *   preserves previously persisted security fields,
 * - writes remain atomic, corrupt/unexpected files load fail-safe,
 * - malformed security fields fail closed.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { createStateStore } from '../src/state.js'
import type { Logger, PersistedState } from '../src/shared/internal.js'

function makeLogger(): Logger & { warnings: string[] } {
  const warnings: string[] = []
  return {
    warnings,
    error: () => undefined,
    warn: (message: string) => {
      warnings.push(message)
    },
    info: () => undefined,
    debug: () => undefined,
  }
}

async function makeTempHome(t: { after: (fn: () => void | Promise<void>) => void }): Promise<string> {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'rc-state-'))
  t.after(async () => {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => undefined)
  })
  return dir
}

const DEFAULT_STATE: PersistedState = {
  v: 2,
  lastEnabled: false,
  updatedAt: '1970-01-01T00:00:00.000Z',
  revocationEpoch: 0,
  securityClosed: false,
  securityClosedReason: null,
  activeDeviceId: null,
  leaseStartedAt: null,
  leaseLastActivityAt: null,
}

const FULL_STATE: PersistedState = {
  v: 2,
  lastEnabled: true,
  updatedAt: '2026-01-01T00:00:00.000Z',
  revocationEpoch: 4,
  securityClosed: true,
  securityClosedReason: 'user-emergency',
  activeDeviceId: 'dev-1',
  leaseStartedAt: 1_700_000_000_000,
  leaseLastActivityAt: 1_700_000_060_000,
}

function legacyState(): Record<string, unknown> {
  return { v: 1, lastEnabled: true, updatedAt: '2025-01-01T00:00:00.000Z' }
}

const symlinkSupported = process.platform !== 'win32'

/* ------------------------------------------------------------------------- */
/* Load / save                                                               */
/* ------------------------------------------------------------------------- */

test('state: a missing file loads the v2 safe default (lastEnabled:false, epoch 0)', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())
  const loaded = await store.load()

  assert.deepEqual(loaded, DEFAULT_STATE)
  assert.equal(store.path, path.join(home, 'remote-control', 'state.json'))
})

test('state: the full v2 state round-trips through the file', async (t) => {
  const home = await makeTempHome(t)
  const first = createStateStore(home, makeLogger())
  await first.save(FULL_STATE)

  const onDisk = JSON.parse(await fsp.readFile(first.path, 'utf8')) as PersistedState
  assert.deepEqual(onDisk, FULL_STATE)

  const second = createStateStore(home, makeLogger())
  assert.deepEqual(await second.load(), FULL_STATE)
})

test('state: save() is atomic — valid JSON on disk and no temp leftovers', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())

  await store.save(DEFAULT_STATE)
  await store.save(FULL_STATE)

  JSON.parse(await fsp.readFile(store.path, 'utf8'))
  const directory = path.dirname(store.path)
  const leftovers = (await fsp.readdir(directory)).filter((name) => name.endsWith('.tmp'))
  assert.deepEqual(leftovers, [])
})

test('state: an empty updatedAt is replaced with the current time', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())
  await store.save({ ...DEFAULT_STATE, lastEnabled: true, updatedAt: '' })

  const loaded = await createStateStore(home, makeLogger()).load()
  assert.equal(loaded.lastEnabled, true)
  assert.match(loaded.updatedAt, /^\d{4}-\d{2}-\d{2}T/)
})

test('state: invalid save payloads are rejected before touching disk', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())

  await assert.rejects(store.save({ v: 3, lastEnabled: true, updatedAt: '' } as unknown as PersistedState))
  await assert.rejects(store.save({ v: 1, lastEnabled: 'yes', updatedAt: '' } as unknown as PersistedState))
  await assert.rejects(store.save(null as unknown as PersistedState))
  await assert.rejects(store.save(undefined as unknown as PersistedState))

  const directory = path.join(home, 'remote-control')
  await assert.rejects(fsp.readdir(directory), /ENOENT/, 'nothing may be written for an invalid payload')
})

/* ------------------------------------------------------------------------- */
/* v1 → v2 migration                                                         */
/* ------------------------------------------------------------------------- */

test('state: a v1 file is migrated in memory without losing the explicit enable flag', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  const file = path.join(directory, 'state.json')
  await fsp.writeFile(file, JSON.stringify(legacyState()), { encoding: 'utf8', mode: 0o600 })

  const store = createStateStore(home, makeLogger())
  const loaded = await store.load()
  assert.equal(loaded.v, 2)
  assert.equal(loaded.lastEnabled, true, 'the user explicitly enabled it before the upgrade')
  assert.equal(loaded.revocationEpoch, 0)
  assert.equal(loaded.securityClosed, false)
  assert.equal(loaded.securityClosedReason, null)
  assert.equal(loaded.activeDeviceId, null)
  assert.equal(loaded.leaseStartedAt, null)
  assert.equal(loaded.leaseLastActivityAt, null)

  // Migration happens on the next write, not by rewriting during load.
  const onDisk = JSON.parse(await fsp.readFile(file, 'utf8')) as { v: number }
  assert.equal(onDisk.v, 1)
  await store.save({ ...loaded, updatedAt: '2026-02-02T00:00:00.000Z' })
  const migrated = JSON.parse(await fsp.readFile(file, 'utf8')) as { v: number }
  assert.equal(migrated.v, 2)
})

test('state: a v1 file that was disabled stays disabled after migration', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  await fsp.writeFile(
    path.join(directory, 'state.json'),
    JSON.stringify({ v: 1, lastEnabled: false, updatedAt: '2025-01-01T00:00:00.000Z' }),
    { encoding: 'utf8', mode: 0o600 },
  )
  const loaded = await createStateStore(home, makeLogger()).load()
  assert.equal(loaded.v, 2)
  assert.equal(loaded.lastEnabled, false)
})

test('state: v2 security fields survive when a legacy v1-shaped save() payload arrives', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())
  await store.save(FULL_STATE)

  // Old controller code during the integration window saves the v1 shape.
  await store.save({ v: 1, lastEnabled: true, updatedAt: '2026-03-03T00:00:00.000Z' })

  const reloaded = await createStateStore(home, makeLogger()).load()
  assert.equal(reloaded.v, 2)
  assert.equal(reloaded.lastEnabled, true)
  assert.equal(reloaded.revocationEpoch, 4, 'the persisted revocation epoch must never be reset by a v1 payload')
  assert.equal(reloaded.securityClosed, true, 'a security closure must never be silently cleared')
  assert.equal(reloaded.securityClosedReason, 'user-emergency')
  assert.equal(reloaded.activeDeviceId, 'dev-1')
  assert.equal(reloaded.leaseStartedAt, FULL_STATE.leaseStartedAt)
  assert.equal(reloaded.leaseLastActivityAt, FULL_STATE.leaseLastActivityAt)
})

test('state: a v2 save() may explicitly clear the lease and the closure', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())
  await store.save(FULL_STATE)
  await store.save({
    ...FULL_STATE,
    securityClosed: false,
    securityClosedReason: null,
    activeDeviceId: null,
    leaseStartedAt: null,
    leaseLastActivityAt: null,
    revocationEpoch: 5,
  })

  const reloaded = await createStateStore(home, makeLogger()).load()
  assert.equal(reloaded.securityClosed, false)
  assert.equal(reloaded.securityClosedReason, null)
  assert.equal(reloaded.activeDeviceId, null)
  assert.equal(reloaded.leaseStartedAt, null)
  assert.equal(reloaded.revocationEpoch, 5)
})

test('state: a partially specified v2 lease inherits the cached timestamps', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())
  await store.save(FULL_STATE)

  // The controller's persistState() always fills all three fields, but this
  // shape (only activeDeviceId overriding the defaults) must never throw.
  await store.save({
    v: 2,
    lastEnabled: false,
    updatedAt: '2026-04-04T00:00:00.000Z',
    activeDeviceId: FULL_STATE.activeDeviceId,
  })

  const reloaded = await createStateStore(home, makeLogger()).load()
  assert.equal(reloaded.activeDeviceId, 'dev-1')
  assert.equal(reloaded.leaseStartedAt, FULL_STATE.leaseStartedAt)
  assert.equal(reloaded.leaseLastActivityAt, FULL_STATE.leaseLastActivityAt)
  assert.equal(reloaded.revocationEpoch, FULL_STATE.revocationEpoch)
  assert.equal(reloaded.securityClosed, FULL_STATE.securityClosed)
})

test('state: malformed v2 security/lease save payloads are rejected before touching disk', async (t) => {
  const home = await makeTempHome(t)
  const store = createStateStore(home, makeLogger())

  await assert.rejects(store.save({ ...FULL_STATE, revocationEpoch: -1 }))
  await assert.rejects(store.save({ ...FULL_STATE, revocationEpoch: 1.5 }))
  await assert.rejects(store.save({ ...FULL_STATE, securityClosed: 'yes' as unknown as boolean }))
  await assert.rejects(store.save({ ...FULL_STATE, securityClosedReason: 42 as unknown as string }))
  await assert.rejects(store.save({ ...FULL_STATE, activeDeviceId: 'bad id!' }))
  await assert.rejects(store.save({ ...FULL_STATE, leaseStartedAt: 'yesterday' as unknown as number }))
})

/* ------------------------------------------------------------------------- */
/* Fail-safe loading                                                         */
/* ------------------------------------------------------------------------- */

test('state: corrupt JSON loads defaults and logs a warning', async (t) => {
  const home = await makeTempHome(t)
  const logger = makeLogger()
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  await fsp.writeFile(path.join(directory, 'state.json'), '{not json', { encoding: 'utf8', mode: 0o600 })

  const loaded = await createStateStore(home, logger).load()
  assert.deepEqual(loaded, DEFAULT_STATE)
  assert.ok(logger.warnings.length > 0)
})

test('state: unexpected shapes load defaults, never a truthy flag', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })

  const payloads = [
    JSON.stringify({ v: 9, lastEnabled: true }),
    JSON.stringify([1, 2, 3]),
    'null',
    JSON.stringify({ v: 2, lastEnabled: 'yes' }),
    JSON.stringify({ v: 2 }),
  ]
  for (const payload of payloads) {
    await fsp.writeFile(path.join(directory, 'state.json'), payload, { encoding: 'utf8', mode: 0o600 })
    const loaded = await createStateStore(home, makeLogger()).load()
    assert.equal(loaded.lastEnabled, false)
    assert.equal(loaded.v, 2)
  }
})

test('state: malformed security fields fail closed instead of enabling access', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  const file = path.join(directory, 'state.json')
  await fsp.writeFile(
    file,
    JSON.stringify({
      v: 2,
      lastEnabled: true,
      updatedAt: '2026-01-01T00:00:00.000Z',
      revocationEpoch: 'not-a-number',
      securityClosed: 'maybe',
      activeDeviceId: 'bad id!',
      leaseStartedAt: -5,
      leaseLastActivityAt: 'soon',
    }),
    { encoding: 'utf8', mode: 0o600 },
  )

  const logger = makeLogger()
  const loaded = await createStateStore(home, logger).load()
  assert.equal(loaded.v, 2)
  assert.equal(loaded.revocationEpoch, 0)
  assert.equal(loaded.securityClosed, true, 'malformed security fields must fail closed')
  assert.equal(loaded.lastEnabled, false, 'a corrupt security state must never auto-enable remote access')
  assert.equal(loaded.activeDeviceId, null, 'a malformed device id is never trusted')
  assert.equal(loaded.leaseStartedAt, null)
  assert.equal(loaded.leaseLastActivityAt, null)
  assert.ok(logger.warnings.length > 0)
})

test('state: a partially corrupted security closure is preserved as closed', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  await fsp.writeFile(
    path.join(directory, 'state.json'),
    JSON.stringify({
      v: 2,
      lastEnabled: false,
      updatedAt: '2026-01-01T00:00:00.000Z',
      revocationEpoch: 3,
      securityClosed: true,
      securityClosedReason: 'circuit-breaker',
      activeDeviceId: 'dev-1',
      leaseStartedAt: 'garbage',
      leaseLastActivityAt: 1,
    }),
    { encoding: 'utf8', mode: 0o600 },
  )
  const loaded = await createStateStore(home, makeLogger()).load()
  assert.equal(loaded.securityClosed, true)
  assert.equal(loaded.securityClosedReason, 'circuit-breaker')
  assert.equal(loaded.activeDeviceId, null, 'an unusable lease window is cleared entirely')
  assert.equal(loaded.leaseStartedAt, null)
  assert.equal(loaded.leaseLastActivityAt, null)
})

test('state: a failed load does not poison later valid files', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  const file = path.join(directory, 'state.json')
  await fsp.writeFile(file, 'corrupt', { encoding: 'utf8', mode: 0o600 })

  const first = createStateStore(home, makeLogger())
  assert.equal((await first.load()).lastEnabled, false)
  await first.save({ ...DEFAULT_STATE, lastEnabled: true })

  const second = createStateStore(home, makeLogger())
  assert.equal((await second.load()).lastEnabled, true)
})

test('state: a symlinked state file is refused fail-safe', { skip: !symlinkSupported }, async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  const real = path.join(home, 'elsewhere.json')
  await fsp.writeFile(real, JSON.stringify(legacyState()), { encoding: 'utf8', mode: 0o600 })
  await fsp.symlink(real, path.join(directory, 'state.json'))

  const loaded = await createStateStore(home, makeLogger()).load()
  assert.equal(loaded.lastEnabled, false, 'a symlinked state file is never trusted')
})

test('state: an oversized state file loads defaults', async (t) => {
  const home = await makeTempHome(t)
  const directory = path.join(home, 'remote-control')
  await fsp.mkdir(directory, { recursive: true })
  await fsp.writeFile(path.join(directory, 'state.json'), 'x'.repeat(128 * 1024), {
    encoding: 'utf8',
    mode: 0o600,
  })
  const loaded = await createStateStore(home, makeLogger()).load()
  assert.deepEqual(loaded, DEFAULT_STATE)
})

test('state: createStateStore requires a non-empty DSH home', () => {
  assert.throws(() => createStateStore('', makeLogger()))
  assert.throws(() => createStateStore('   ', makeLogger()))
  assert.throws(() => createStateStore(null as unknown as string, makeLogger()))
})
