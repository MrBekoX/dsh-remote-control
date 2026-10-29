/**
 * Device store (`$DSH_HOME/remote-control/devices.json`).
 *
 * Persistence rules (design §9):
 * - schema `{v:1, devices:[...]}`; `StoredDevice` records never leave the host,
 * - atomic write: temp file in the same directory + fsync + rename (+ directory
 *   fsync on POSIX),
 * - POSIX 0600 file / 0700 directory, ownership and group/other-write checks,
 * - Windows: best-effort `icacls` user-only ACL with a `chmod` fallback; the
 *   attempt is logged, never silently ignored,
 * - symlinks/hardlinks are refused (lstat + O_NOFOLLOW where the platform
 *   supports it),
 * - a corrupt/partial file fails closed: `load()` rejects instead of silently
 *   starting from an empty store.
 */

import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'
import type { FileHandle } from 'node:fs/promises'
import { chmod, lstat, mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises'
import { constants as fsConstants } from 'node:fs'
import { basename, dirname, isAbsolute, join, resolve, sep } from 'node:path'
import { promisify } from 'node:util'

import type { DeviceStore, Logger, StoredDevice } from './shared/internal.js'
import type { DeviceView } from './shared/protocol.js'

const execFileAsync = promisify(execFile)

const SCHEMA_VERSION = 1
const MAX_BYTES = 256 * 1024
/** Hard structural ceiling; the configurable `maxDevices` is enforced on add(). */
const HARD_MAX_DEVICES = 64
const DEVICE_ID = /^[A-Za-z0-9_-]{1,128}$/
const TOKEN_KEY = /^[A-Za-z0-9_-]{43}$/
const SHA256_HEX = /^[a-f0-9]{64}$/
const DEFAULT_STORE_ERROR = 'remote-control: device store is unavailable'

export class DeviceStoreError extends Error {
  readonly code: 'STORE_UNAVAILABLE' | 'DEVICE_LIMIT' | 'STORE_CORRUPT'

  constructor(message: string, code: 'STORE_UNAVAILABLE' | 'DEVICE_LIMIT' | 'STORE_CORRUPT') {
    super(message)
    this.name = 'DeviceStoreError'
    this.code = code
  }
}

export interface DeviceStoreOptions {
  /** Absolute path of `devices.json`; the containing directory is created. */
  filePath: string
  maxDevices: number
  log: Logger
}

/* ------------------------------------------------------------------------- */
/* Private directory + atomic writes (also used by state.ts)                  */
/* ------------------------------------------------------------------------- */

const WINDOWS_ACL_DONE = new Set<string>()

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Best-effort Windows hardening: restrict the path to the current user with
 * `icacls`. Falls back to `chmod` and logs when `icacls` is unavailable; never
 * throws (the caller already failed closed for the security-relevant checks).
 */
async function hardenWindowsAcl(target: string, directory: boolean, log?: Logger): Promise<void> {
  if (process.platform !== 'win32') return
  if (WINDOWS_ACL_DONE.has(target)) return
  WINDOWS_ACL_DONE.add(target)
  const username = process.env.USERNAME ?? process.env.USER ?? ''
  try {
    if (username === '') throw new Error('current user name is unavailable')
    // (OI)(CI) makes the directory ACL inheritable by files we create inside it.
    const grant = directory ? `${username}:(OI)(CI)F` : `${username}:F`
    await execFileAsync('icacls', [target, '/inheritance:r', '/grant:r', grant], {
      windowsHide: true,
      timeout: 5_000,
    })
    log?.debug('restricted ACL to the current user', { path: basename(target), directory })
  } catch (error) {
    try {
      await chmod(target, directory ? 0o700 : 0o600)
    } catch {
      // chmod is a no-op for ACLs on Windows; the warn below is the audit trail.
    }
    log?.warn('could not restrict ACL with icacls; fell back to chmod', {
      path: basename(target),
      directory,
      message: errorMessage(error),
    })
  }
}

/**
 * Create (if needed) and validate a private directory: no symlink, owned by the
 * current user on POSIX and not group/other-writable. Windows gets the ACL
 * hardening attempt.
 */
export async function ensureSecureDirectory(directory: string, log?: Logger): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const info = await lstat(directory)
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new DeviceStoreError(DEFAULT_STORE_ERROR, 'STORE_UNAVAILABLE')
  }
  if (process.platform !== 'win32') {
    if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
      throw new DeviceStoreError(DEFAULT_STORE_ERROR, 'STORE_UNAVAILABLE')
    }
    if ((info.mode & 0o022) !== 0) {
      log?.error('directory is group/other-writable; refusing to use it', {
        path: basename(directory),
        mode: (info.mode & 0o777).toString(8),
      })
      throw new DeviceStoreError(DEFAULT_STORE_ERROR, 'STORE_UNAVAILABLE')
    }
  } else {
    await hardenWindowsAcl(directory, true, log)
  }
}

/**
 * Atomically replace a file: temp file in the same directory, fsync, rename.
 * POSIX files are created with `mode`; Windows relies on the directory ACL.
 */
export async function writeFileAtomic(filePath: string, text: string, mode = 0o600): Promise<void> {
  const directory = dirname(filePath)
  const temporary = join(directory, `.${basename(filePath)}.${randomUUID()}.tmp`)
  let handle: FileHandle | undefined
  try {
    handle = await open(temporary, 'wx', mode)
    if (process.platform !== 'win32') await handle.chmod(mode)
    await handle.writeFile(text, 'utf8')
    await handle.sync()
    await handle.close()
    handle = undefined
    await rename(temporary, filePath)
    if (process.platform !== 'win32') {
      // Persist the rename itself; unsupported on Windows (EISDIR/EPERM).
      let directoryHandle: FileHandle | undefined
      try {
        directoryHandle = await open(directory, 'r')
        await directoryHandle.sync()
      } catch {
        // Directory fsync is a durability best-effort, never a correctness gate.
      } finally {
        if (directoryHandle !== undefined) await directoryHandle.close().catch(() => undefined)
      }
    }
  } finally {
    if (handle !== undefined) await handle.close().catch(() => undefined)
    await unlink(temporary).catch(() => undefined)
  }
}

/* ------------------------------------------------------------------------- */
/* Validation                                                                */
/* ------------------------------------------------------------------------- */

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requireString(value: unknown, name: string, min: number, max: number): string {
  if (typeof value !== 'string') throw new Error(`${name} must be a string`)
  const trimmed = value.trim()
  if (trimmed.length < min || trimmed.length > max) throw new Error(`${name} has an invalid length`)
  return trimmed
}

function requireNonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new Error(`${name} must be a non-negative integer`)
  }
  return value as number
}

function validateDevice(value: unknown): StoredDevice {
  if (!isRecord(value)) throw new Error('device must be an object')
  const id = requireString(value.id, 'id', 1, 128)
  if (!DEVICE_ID.test(id)) throw new Error('id is not a valid device id')
  const label = requireString(value.label, 'label', 1, 128)
  const platform = requireString(value.platform, 'platform', 1, 32)
  const tokenKey = requireString(value.tokenKey, 'tokenKey', 43, 43)
  if (!TOKEN_KEY.test(tokenKey)) throw new Error('tokenKey is not base64url-encoded 32 bytes')
  if (Buffer.from(tokenKey, 'base64url').length !== 32) throw new Error('tokenKey is not 32 bytes')
  const refreshHash = requireString(value.refreshHash, 'refreshHash', 64, 64)
  if (!SHA256_HEX.test(refreshHash)) throw new Error('refreshHash is not sha256 hex')
  return {
    id,
    label,
    platform,
    createdAt: requireNonNegativeInteger(value.createdAt, 'createdAt'),
    lastSeenAt: requireNonNegativeInteger(value.lastSeenAt, 'lastSeenAt'),
    refreshExpiresAt: requireNonNegativeInteger(value.refreshExpiresAt, 'refreshExpiresAt'),
    tokenVersion: requireNonNegativeInteger(value.tokenVersion, 'tokenVersion'),
    tokenKey,
    refreshHash,
  }
}

function validateDeviceList(value: unknown): StoredDevice[] {
  if (!isRecord(value)) throw new Error('root must be an object')
  if (value.v !== SCHEMA_VERSION) throw new Error('unsupported schema version')
  if (!Array.isArray(value.devices)) throw new Error('devices must be an array')
  if (value.devices.length > HARD_MAX_DEVICES) throw new Error('too many devices')
  const devices = value.devices.map(validateDevice)
  const ids = new Set<string>()
  for (const device of devices) {
    if (ids.has(device.id)) throw new Error('duplicate device id')
    ids.add(device.id)
  }
  return devices
}

/* ------------------------------------------------------------------------- */
/* Public device view                                                        */
/* ------------------------------------------------------------------------- */

/** Strip every secret (tokenKey / refreshHash / tokenVersion) from a record. */
export function toDeviceView(device: StoredDevice): DeviceView {
  return {
    id: device.id,
    label: device.label,
    platform: device.platform,
    createdAt: device.createdAt,
    lastSeenAt: device.lastSeenAt,
    refreshExpiresAt: device.refreshExpiresAt,
  }
}

/* ------------------------------------------------------------------------- */
/* Store                                                                     */
/* ------------------------------------------------------------------------- */

export async function createDeviceStore(options: DeviceStoreOptions): Promise<DeviceStore> {
  const requestedPath = options.filePath
  if (typeof requestedPath !== 'string' || requestedPath.trim() === '') {
    throw new DeviceStoreError(DEFAULT_STORE_ERROR, 'STORE_UNAVAILABLE')
  }
  const filePath = isAbsolute(requestedPath) ? resolve(requestedPath) : resolve(process.cwd(), requestedPath)
  const directory = dirname(filePath)
  const maxDevices = Math.max(1, Math.floor(options.maxDevices))
  const log = options.log

  let devices: StoredDevice[] | null = null
  let disposed = false
  /**
   * All mutations are chained: concurrent add/update/remove calls can never
   * interleave their read-modify-write cycles (the controller also serializes,
   * but the store stays correct on its own).
   */
  let writeChain: Promise<void> = Promise.resolve()

  function serializeWrites<T>(task: () => Promise<T>): Promise<T> {
    const run = writeChain.then(task, task)
    writeChain = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  const clone = (device: StoredDevice): StoredDevice => ({ ...device })

  const unavailable = (detail: unknown, code: 'STORE_UNAVAILABLE' | 'STORE_CORRUPT' = 'STORE_UNAVAILABLE'): DeviceStoreError => {
    log.error('device store is unavailable', detail)
    return new DeviceStoreError(DEFAULT_STORE_ERROR, code)
  }

  async function readSnapshot(): Promise<StoredDevice[]> {
    if (devices !== null) return devices
    await ensureSecureDirectory(directory, log).catch((error: unknown) => {
      throw unavailable({ reason: errorMessage(error) })
    })

    let info
    try {
      info = await lstat(filePath)
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        devices = []
        return devices
      }
      throw unavailable({ reason: errorMessage(error) })
    }
    if (info.isSymbolicLink() || !info.isFile()) {
      throw unavailable({ reason: 'device store path is not a regular file' })
    }
    if (info.size > MAX_BYTES) {
      throw unavailable({ reason: 'device store is larger than the size limit' })
    }
    if (process.platform === 'win32') {
      await hardenWindowsAcl(filePath, false, log)
    } else {
      if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
        throw unavailable({ reason: 'device store is not owned by the current user' })
      }
      if ((info.mode & 0o777) !== 0o600) {
        throw unavailable({ reason: `unexpected device store permissions (${(info.mode & 0o777).toString(8)})` })
      }
    }

    let handle: FileHandle | undefined
    let text: string
    try {
      // O_NOFOLLOW is only meaningful (and portable) on POSIX.
      const flags = process.platform === 'win32'
        ? 'r'
        : fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW
      handle = await open(filePath, flags)
      const opened = await handle.stat()
      if (!opened.isFile()) throw new Error('device store path is not a regular file')
      if (process.platform !== 'win32' && opened.nlink !== 1) throw new Error('device store must not be hardlinked')
      if (opened.size > MAX_BYTES) throw new Error('device store is larger than the size limit')
      text = await handle.readFile('utf8')
    } catch (error) {
      throw unavailable({ reason: errorMessage(error) })
    } finally {
      if (handle !== undefined) await handle.close().catch(() => undefined)
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(text)
    } catch {
      throw unavailable({ reason: 'device store JSON is corrupt' }, 'STORE_CORRUPT')
    }
    try {
      devices = validateDeviceList(parsed)
    } catch (error) {
      throw unavailable({ reason: errorMessage(error) }, 'STORE_CORRUPT')
    }
    if (devices.length > maxDevices) {
      log.warn('device store holds more devices than the configured limit; revoke extras', {
        devices: devices.length,
        maxDevices,
      })
    }
    return devices
  }

  async function persist(next: StoredDevice[]): Promise<void> {
    const text = `${JSON.stringify({ v: SCHEMA_VERSION, devices: next })}\n`
    if (Buffer.byteLength(text, 'utf8') > MAX_BYTES) {
      throw unavailable({ reason: 'device store would exceed the size limit' })
    }
    try {
      await ensureSecureDirectory(directory, log)
      await writeFileAtomic(filePath, text, 0o600)
      if (process.platform === 'win32') await hardenWindowsAcl(filePath, false, log)
    } catch (error) {
      if (error instanceof DeviceStoreError) throw error
      throw unavailable({ reason: errorMessage(error) })
    }
    devices = next
  }

  async function load(): Promise<void> {
    if (disposed) throw new DeviceStoreError(DEFAULT_STORE_ERROR, 'STORE_UNAVAILABLE')
    await readSnapshot()
  }

  function list(): StoredDevice[] {
    return (devices ?? []).map(clone)
  }

  function get(id: string): StoredDevice | undefined {
    const match = (devices ?? []).find((device) => device.id === id)
    return match === undefined ? undefined : clone(match)
  }

  function count(): number {
    return (devices ?? []).length
  }

  async function add(device: StoredDevice): Promise<void> {
    return serializeWrites(async () => {
      let validated: StoredDevice
      try {
        validated = validateDevice(device)
      } catch (error) {
        throw unavailable({ reason: errorMessage(error) })
      }
      const current = await readSnapshot()
      if (current.some((entry) => entry.id === validated.id)) {
        throw new DeviceStoreError('remote-control: device already exists', 'STORE_UNAVAILABLE')
      }
      if (current.length >= maxDevices) {
        log.warn('device limit reached', { maxDevices })
        throw new DeviceStoreError('remote-control: device limit reached', 'DEVICE_LIMIT')
      }
      await persist([...current, validated])
    })
  }

  async function update(device: StoredDevice): Promise<void> {
    return serializeWrites(async () => {
      let validated: StoredDevice
      try {
        validated = validateDevice(device)
      } catch (error) {
        throw unavailable({ reason: errorMessage(error) })
      }
      const current = await readSnapshot()
      const index = current.findIndex((entry) => entry.id === validated.id)
      if (index === -1) {
        throw new DeviceStoreError('remote-control: unknown device', 'STORE_UNAVAILABLE')
      }
      const next = current.slice()
      next[index] = validated
      await persist(next)
    })
  }

  async function touch(id: string, lastSeenAt: number): Promise<void> {
    const at = typeof lastSeenAt === 'number' && Number.isFinite(lastSeenAt) && lastSeenAt > 0 ? Math.floor(lastSeenAt) : 0
    if (at === 0 || typeof id !== 'string' || id === '') return
    return serializeWrites(async () => {
      const current = await readSnapshot()
      const index = current.findIndex((entry) => entry.id === id)
      if (index === -1) return
      const existing = current[index]!
      if (existing.lastSeenAt >= at) return
      const next = current.slice()
      next[index] = { ...existing, lastSeenAt: at }
      await persist(next)
    })
  }

  async function remove(id: string): Promise<void> {
    return serializeWrites(async () => {
      const current = await readSnapshot()
      const next = current.filter((entry) => entry.id !== id)
      if (next.length === current.length) return
      await persist(next)
    })
  }

  function dispose(): void {
    disposed = true
    devices = null
  }

  return {
    path: filePath,
    load,
    list,
    get,
    count,
    add,
    update,
    touch,
    remove,
    dispose,
  }
}

/* ------------------------------------------------------------------------- */
/* Small helpers shared with state.ts                                         */
/* ------------------------------------------------------------------------- */

/** Absolute file path helper used by the controller (`$DSH_HOME/remote-control/...`). */
export function remoteControlDirectory(dshHome: string): string {
  return join(resolve(dshHome), 'remote-control')
}

/** True when `child` is inside `parent` (path-traversal guard for file serving). */
export function isInsideDirectory(parent: string, child: string): boolean {
  const root = parent.endsWith(sep) ? parent : `${parent}${sep}`
  return child === parent || child.startsWith(root)
}

/** Read a file with lstat/size guards; returns null when it does not exist. */
export async function readSmallFile(filePath: string, maxBytes: number): Promise<string | null> {
  try {
    const info = await stat(filePath)
    if (!info.isFile() || info.size > maxBytes) return null
    return await readFile(filePath, 'utf8')
  } catch {
    return null
  }
}
