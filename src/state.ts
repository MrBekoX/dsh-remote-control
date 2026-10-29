/**
 * Persisted listener preference + security state
 * (`$DSH_HOME/remote-control/state.json`).
 *
 * Schema v2:
 * `{v:2, lastEnabled:boolean, updatedAt:string, revocationEpoch:number,
 *   securityClosed:boolean, securityClosedReason:string|null,
 *   activeDeviceId:string|null, leaseStartedAt:number|null,
 *   leaseLastActivityAt:number|null}`
 *
 * Safety rules:
 * - v1 files are migrated in memory (returned as v2) and written as v2 on the
 *   next `save()`; the previous explicit `lastEnabled` decision is preserved,
 * - a v1-shaped `save()` payload (integration window / older callers) never
 *   clears the v2 security fields: `revocationEpoch`, the security closure and
 *   the lease are carried over from the cached state,
 * - malformed security fields fail closed (`securityClosed: true`) instead of
 *   silently re-enabling access; a malformed lease is discarded entirely,
 * - unreadable/oversized/corrupt/symlinked files load safe defaults
 *   (`lastEnabled:false`) with a warning, per the existing policy,
 * - writes stay atomic (`writeFileAtomic`: temp + fsync + rename) and the state
 *   file itself is not a secret store (device keys live in devices.json).
 */

import { lstat, readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { ensureSecureDirectory, writeFileAtomic } from './device-store.js'
import type { PersistedState, Logger, StateStore } from './shared/internal.js'

const SCHEMA_VERSION = 2 as const
const LEGACY_SCHEMA_VERSION = 1 as const
const MAX_STATE_BYTES = 64 * 1024
const DEFAULT_UPDATED_AT = '1970-01-01T00:00:00.000Z'
const MAX_REASON_CHARS = 120
const DEVICE_ID = /^[A-Za-z0-9_-]{1,128}$/
const MAX_EPOCH = Number.MAX_SAFE_INTEGER
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\ufeff]/g

function defaultState(): PersistedState {
  return {
    v: SCHEMA_VERSION,
    lastEnabled: false,
    updatedAt: DEFAULT_UPDATED_AT,
    revocationEpoch: 0,
    securityClosed: false,
    securityClosedReason: null,
    activeDeviceId: null,
    leaseStartedAt: null,
    leaseLastActivityAt: null,
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function validEpoch(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_EPOCH
}

function validLeaseTime(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function sanitizeReason(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const cleaned = value.replace(UNSAFE_CHARS, '').trim()
  return cleaned === '' ? null : cleaned.slice(0, MAX_REASON_CHARS)
}

function updatedAtOrNow(value: unknown): string {
  return typeof value === 'string' && value !== '' ? value : new Date().toISOString()
}

interface NormalizeResult {
  state: PersistedState
  /** True when a security-relevant field was malformed and was failed closed. */
  failedClosed: boolean
}

function normalize(value: unknown, log: Logger, source: string): NormalizeResult {
  if (!isRecord(value)) {
    log.warn('state file does not contain an object; using safe defaults', { source })
    return { state: defaultState(), failedClosed: false }
  }

  // --- v1 → v2 migration ---------------------------------------------------
  if (value.v === LEGACY_SCHEMA_VERSION) {
    if (typeof value.lastEnabled !== 'boolean') {
      log.warn('legacy state file has an unexpected shape; using safe defaults', { source })
      return { state: defaultState(), failedClosed: false }
    }
    log.info('migrating state file v1 to v2 in memory', { source })
    return {
      state: {
        ...defaultState(),
        lastEnabled: value.lastEnabled,
        updatedAt: updatedAtOrNow(value.updatedAt),
      },
      failedClosed: false,
    }
  }

  if (value.v !== SCHEMA_VERSION || typeof value.lastEnabled !== 'boolean') {
    log.warn('state file has an unexpected shape; using safe defaults', { source })
    return { state: defaultState(), failedClosed: false }
  }

  let failedClosed = false

  // Security closure / revocation epoch: a malformed value cannot be trusted,
  // so the state is forced closed rather than silently re-enabling access.
  let revocationEpoch = 0
  if (value.revocationEpoch !== undefined) {
    if (validEpoch(value.revocationEpoch)) revocationEpoch = value.revocationEpoch
    else {
      failedClosed = true
      log.warn('state file has a malformed revocation epoch; failing closed', { source })
    }
  }

  let securityClosed = false
  if (value.securityClosed !== undefined) {
    if (typeof value.securityClosed === 'boolean') securityClosed = value.securityClosed
    else {
      failedClosed = true
      log.warn('state file has a malformed security closure flag; failing closed', { source })
    }
  }

  let securityClosedReason: string | null = null
  if (value.securityClosedReason !== undefined && value.securityClosedReason !== null) {
    if (typeof value.securityClosedReason === 'string') {
      securityClosedReason = sanitizeReason(value.securityClosedReason)
    } else {
      failedClosed = true
      log.warn('state file has a malformed security closure reason; failing closed', { source })
    }
  }

  // Lease: only a coherent (device id, startedAt, lastActivityAt) triple is
  // restored; anything else is discarded so a corrupt file can never pin an
  // active device.
  let activeDeviceId: string | null = null
  let leaseStartedAt: number | null = null
  let leaseLastActivityAt: number | null = null
  const hasLeaseFields =
    value.activeDeviceId !== undefined ||
    value.leaseStartedAt !== undefined ||
    value.leaseLastActivityAt !== undefined
  if (hasLeaseFields) {
    const candidateId = value.activeDeviceId
    const candidateStarted = value.leaseStartedAt
    const candidateActivity = value.leaseLastActivityAt
    const coherent =
      typeof candidateId === 'string' &&
      DEVICE_ID.test(candidateId) &&
      validLeaseTime(candidateStarted) &&
      validLeaseTime(candidateActivity)
    const allEmpty =
      (candidateId === null || candidateId === undefined) &&
      (candidateStarted === null || candidateStarted === undefined) &&
      (candidateActivity === null || candidateActivity === undefined)
    if (coherent) {
      activeDeviceId = candidateId as string
      leaseStartedAt = candidateStarted as number
      leaseLastActivityAt = candidateActivity as number
    } else if (!allEmpty) {
      // A partially specified lease is discarded; this is a safe default, not a
      // security closure (the user simply gets to re-activate a device).
      log.warn('state file has a malformed device lease; discarding it', { source })
    }
  }

  const state: PersistedState = {
    v: SCHEMA_VERSION,
    // A file whose security fields were malformed cannot be trusted to auto
    // start remote access: fail closed on both axes (closed + not auto-enabled).
    lastEnabled: failedClosed ? false : value.lastEnabled,
    updatedAt: updatedAtOrNow(value.updatedAt),
    revocationEpoch,
    securityClosed: failedClosed ? true : securityClosed,
    securityClosedReason: failedClosed ? securityClosedReason ?? 'state-corrupt' : securityClosedReason,
    activeDeviceId,
    leaseStartedAt,
    leaseLastActivityAt,
  }
  return { state, failedClosed }
}

/** Validate a lease triple supplied to `save()`; throws on an incoherent set. */
function validateSaveLease(state: PersistedState): {
  activeDeviceId: string | null
  leaseStartedAt: number | null
  leaseLastActivityAt: number | null
} | null {
  const anyProvided =
    state.activeDeviceId !== undefined ||
    state.leaseStartedAt !== undefined ||
    state.leaseLastActivityAt !== undefined
  if (!anyProvided) return null
  const id = state.activeDeviceId ?? null
  const started = state.leaseStartedAt ?? null
  const activity = state.leaseLastActivityAt ?? null
  if (id === null && started === null && activity === null) {
    return { activeDeviceId: null, leaseStartedAt: null, leaseLastActivityAt: null }
  }
  if (typeof id !== 'string' || !DEVICE_ID.test(id)) {
    throw new Error('invalid state payload: activeDeviceId')
  }
  if (!validLeaseTime(started) || !validLeaseTime(activity)) {
    throw new Error('invalid state payload: lease timestamps')
  }
  return { activeDeviceId: id, leaseStartedAt: started, leaseLastActivityAt: activity }
}

export function createStateStore(dshHome: string, log: Logger): StateStore {
  if (typeof dshHome !== 'string' || dshHome.trim() === '') {
    throw new Error('state store requires a DSH home directory')
  }
  const directory = join(resolve(dshHome), 'remote-control')
  const filePath = join(directory, 'state.json')
  let cached: PersistedState | null = null

  function remember(state: PersistedState): PersistedState {
    cached = { ...state }
    return { ...cached }
  }

  async function load(): Promise<PersistedState> {
    if (cached !== null) return { ...cached }

    let size: number
    try {
      const info = await lstat(filePath)
      if (info.isSymbolicLink() || !info.isFile()) {
        log.warn('state path is not a regular file; using safe defaults')
        return remember(defaultState())
      }
      size = info.size
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code !== 'ENOENT') {
        log.warn('state file could not be read; using safe defaults', { reason: code ?? 'unknown' })
      }
      return remember(defaultState())
    }
    if (size > MAX_STATE_BYTES) {
      log.warn('state file is larger than expected; using safe defaults')
      return remember(defaultState())
    }

    let text: string
    try {
      text = await readFile(filePath, 'utf8')
    } catch (error) {
      log.warn('state file could not be read; using safe defaults', {
        reason: (error as NodeJS.ErrnoException).code ?? 'unknown',
      })
      return remember(defaultState())
    }

    let parsed: unknown
    try {
      parsed = JSON.parse(text)
    } catch {
      log.warn('state file JSON is corrupt; using safe defaults')
      return remember(defaultState())
    }
    const normalized = normalize(parsed, log, 'state.json')
    return remember(normalized.state)
  }

  async function save(state: PersistedState): Promise<void> {
    if (!isRecord(state)) throw new Error('invalid state payload')
    if (state.v !== LEGACY_SCHEMA_VERSION && state.v !== SCHEMA_VERSION) {
      throw new Error('invalid state payload')
    }
    if (typeof state.lastEnabled !== 'boolean') throw new Error('invalid state payload')

    const previous = cached
    const isV2 = state.v === SCHEMA_VERSION

    // v2 save: validate explicitly supplied fields. v1 save (integration window
    // / older controller code): preserve whatever security fields are already
    // cached, so a stale payload can never clear the epoch or a closure.
    let revocationEpoch: number
    if (isV2 && state.revocationEpoch !== undefined) {
      if (!validEpoch(state.revocationEpoch)) throw new Error('invalid state payload: revocationEpoch')
      revocationEpoch = state.revocationEpoch
    } else {
      revocationEpoch = previous?.revocationEpoch ?? 0
    }

    let securityClosed: boolean
    if (isV2 && state.securityClosed !== undefined) {
      if (typeof state.securityClosed !== 'boolean') throw new Error('invalid state payload: securityClosed')
      securityClosed = state.securityClosed
    } else {
      securityClosed = previous?.securityClosed ?? false
    }

    let securityClosedReason: string | null
    if (isV2 && state.securityClosedReason !== undefined) {
      if (state.securityClosedReason !== null && typeof state.securityClosedReason !== 'string') {
        throw new Error('invalid state payload: securityClosedReason')
      }
      securityClosedReason = sanitizeReason(state.securityClosedReason)
    } else {
      securityClosedReason = previous?.securityClosedReason ?? null
    }

    let lease:
      | { activeDeviceId: string | null; leaseStartedAt: number | null; leaseLastActivityAt: number | null }
      | null = null
    if (isV2) {
      // Merge: omitted fields inherit the cached lease (a caller may only pass
      // `activeDeviceId` while the controller's defaults carry the timestamps).
      // An explicit `activeDeviceId: null` always clears the whole lease.
      const explicitId = state.activeDeviceId
      const merged = {
        activeDeviceId: explicitId !== undefined ? explicitId : previous?.activeDeviceId ?? null,
        leaseStartedAt:
          explicitId === null
            ? null
            : state.leaseStartedAt !== undefined
              ? state.leaseStartedAt
              : previous?.leaseStartedAt ?? null,
        leaseLastActivityAt:
          explicitId === null
            ? null
            : state.leaseLastActivityAt !== undefined
              ? state.leaseLastActivityAt
              : previous?.leaseLastActivityAt ?? null,
      }
      lease = validateSaveLease({
        ...state,
        activeDeviceId: merged.activeDeviceId,
        leaseStartedAt: merged.leaseStartedAt,
        leaseLastActivityAt: merged.leaseLastActivityAt,
      })
    }
    if (lease === null) {
      lease = {
        activeDeviceId: previous?.activeDeviceId ?? null,
        leaseStartedAt: previous?.leaseStartedAt ?? null,
        leaseLastActivityAt: previous?.leaseLastActivityAt ?? null,
      }
    }

    const next: PersistedState = {
      v: SCHEMA_VERSION,
      lastEnabled: state.lastEnabled,
      updatedAt: updatedAtOrNow(state.updatedAt),
      revocationEpoch,
      securityClosed,
      securityClosedReason,
      activeDeviceId: lease.activeDeviceId,
      leaseStartedAt: lease.leaseStartedAt,
      leaseLastActivityAt: lease.leaseLastActivityAt,
    }
    await ensureSecureDirectory(directory, log)
    await writeFileAtomic(filePath, `${JSON.stringify(next)}\n`, 0o600)
    cached = next
  }

  function dispose(): void {
    cached = null
  }

  // `dispose()` is part of the lifecycle contract shared with the device store;
  // it is not declared on the minimal StateStore interface yet.
  const store: StateStore & { dispose(): void } = { path: filePath, load, save, dispose }
  return store
}
