/**
 * Bounded in-memory audit ring.
 *
 * Only non-sensitive metadata is recorded (endpoint names, tool names, device
 * ids). Prompts, tokens, pairing codes, cookies, QR secrets and tool arguments
 * are never stored.
 *
 * Security properties:
 * - hard capacity bound (oldest entries are dropped first),
 * - every record gets a monotonic id and the ring-owned timestamp,
 * - externally-influenced text (User-Agent, labels, details, operation names)
 *   is sanitized before storage: ANSI escape sequences and C0/C1 control
 *   characters are removed, newlines collapse to spaces, length is bounded, so
 *   hostile metadata cannot inject log/terminal lines,
 * - `ip` is only kept when it is a real IP literal (the caller must establish
 *   it from a trusted source; a spoofable header value is dropped here too).
 */

import { isIP } from 'node:net'

import type { AuditEntry, AuditResult, AuditRing } from './shared/internal.js'
import type { AuditEntryView } from './shared/protocol.js'
import { RC_LIMITS } from './shared/protocol.js'

const DEFAULT_CAPACITY = RC_LIMITS.auditCapacity
const DEFAULT_DETAIL_CHARS = 200
const DEFAULT_USER_AGENT_CHARS = 160
const DEFAULT_LABEL_CHARS = 64
const DEFAULT_OPERATION_CHARS = 64
const MAX_TEXT_CHARS = 4_096
const DEVICE_ID = /^[A-Za-z0-9_-]{1,128}$/
const KINDS = new Set<string>([
  'enable',
  'disable',
  'pair',
  'approve',
  'deny',
  'revoke',
  'rpc',
  'answer',
  'tunnel',
  'security',
  'device-lock',
])
const RESULTS = new Set<AuditResult>(['ok', 'rejected', 'failed', 'notice'])

/** CSI/OSC/other ANSI escape sequences (must be stripped before controls). */
const ANSI_ESCAPE =
  /\u001b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\u0007]*(?:\u0007|\u001b\\)|[@-Z\\-_])/g
/** C0/C1 control characters, bidi controls and zero-width/BOM characters. */
const UNSAFE_CHARS =
  /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g
const NEWLINES = /[\r\n\u0085\u2028\u2029]+/g
const WHITESPACE = /\s+/g

export interface AuditRingOptions {
  /** Test seam; defaults to `Date.now`. */
  now?: () => number
  maxDetailChars?: number
  maxUserAgentChars?: number
  maxDeviceLabelChars?: number
  maxOperationChars?: number
}

function positiveInt(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) return fallback
  return Math.min(max, Math.max(min, value))
}

function safeTime(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0
}

/**
 * Sanitize one externally-influenced text value for audit storage/display:
 * strips ANSI escapes and control characters, collapses line breaks and
 * whitespace, trims and hard-truncates. Non-string scalars are coerced;
 * objects/arrays/functions become an empty string (never `[object Object]`).
 */
export function sanitizeAuditText(value: unknown, maxLength = DEFAULT_DETAIL_CHARS): string {
  let raw: string
  if (typeof value === 'string') raw = value
  else if (typeof value === 'number' && Number.isFinite(value)) raw = String(value)
  else if (typeof value === 'boolean') raw = String(value)
  else return ''
  const limit = positiveInt(maxLength, DEFAULT_DETAIL_CHARS, 1, MAX_TEXT_CHARS)
  const cleaned = raw
    .replace(ANSI_ESCAPE, '')
    .replace(NEWLINES, ' ')
    .replace(UNSAFE_CHARS, '')
    .replace(WHITESPACE, ' ')
    .trim()
  return cleaned.slice(0, limit).trim()
}

/** Keep an `ip` audit field only when it is a literal IP address. */
export function sanitizeAuditIp(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const candidate = value.trim()
  if (candidate === '' || candidate.length > 64) return null
  return isIP(candidate) === 0 ? null : candidate
}

function sanitizeKind(value: unknown): AuditEntry['kind'] {
  const kind = sanitizeAuditText(value, 32)
  return (KINDS.has(kind) ? kind : 'rpc') as AuditEntry['kind']
}

function sanitizeResult(value: unknown): AuditResult {
  const result = sanitizeAuditText(value, 16) as AuditResult
  return RESULTS.has(result) ? result : 'notice'
}

function sanitizeDeviceId(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const candidate = value.trim()
  return DEVICE_ID.test(candidate) ? candidate : null
}

/** Project one ring entry into the desktop-panel shape (sanitized again). */
export function toAuditEntryView(entry: AuditEntry): AuditEntryView {
  const userAgent = sanitizeAuditText(entry.userAgent, DEFAULT_USER_AGENT_CHARS)
  const deviceLabel = sanitizeAuditText(entry.deviceLabel, DEFAULT_LABEL_CHARS)
  return {
    id: safeTime(entry.id),
    time: safeTime(entry.time),
    kind: sanitizeKind(entry.kind),
    operation: sanitizeAuditText(entry.operation, DEFAULT_OPERATION_CHARS),
    result: sanitizeResult(entry.result),
    deviceId: sanitizeDeviceId(entry.deviceId),
    deviceLabel: deviceLabel === '' ? null : deviceLabel,
    ip: sanitizeAuditIp(entry.ip),
    userAgent: userAgent === '' ? null : userAgent,
    detail: sanitizeAuditText(entry.detail, DEFAULT_DETAIL_CHARS),
  }
}

export function createAuditRing(
  capacity: number = DEFAULT_CAPACITY,
  options: AuditRingOptions = {},
): AuditRing {
  const limit = positiveInt(capacity, DEFAULT_CAPACITY, 1, 10_000)
  const now = typeof options.now === 'function' ? options.now : Date.now
  const maxDetail = positiveInt(options.maxDetailChars, DEFAULT_DETAIL_CHARS, 1, MAX_TEXT_CHARS)
  const maxUserAgent = positiveInt(
    options.maxUserAgentChars,
    DEFAULT_USER_AGENT_CHARS,
    1,
    MAX_TEXT_CHARS,
  )
  const maxLabel = positiveInt(options.maxDeviceLabelChars, DEFAULT_LABEL_CHARS, 1, MAX_TEXT_CHARS)
  const maxOperation = positiveInt(
    options.maxOperationChars,
    DEFAULT_OPERATION_CHARS,
    1,
    MAX_TEXT_CHARS,
  )

  const entries: AuditEntry[] = []
  let nextId = 1
  let disposed = false

  function normalize(input: Omit<AuditEntry, 'time'>): AuditEntry | null {
    if (typeof input !== 'object' || input === null) return null
    const userAgent = sanitizeAuditText(input.userAgent, maxUserAgent)
    const deviceLabel = sanitizeAuditText(input.deviceLabel, maxLabel)
    return {
      id: nextId++,
      time: safeTime(now()),
      deviceId: sanitizeDeviceId(input.deviceId),
      deviceLabel: deviceLabel === '' ? null : deviceLabel,
      kind: sanitizeKind(input.kind),
      operation: sanitizeAuditText(input.operation, maxOperation),
      result: sanitizeResult(input.result),
      ip: sanitizeAuditIp(input.ip),
      userAgent: userAgent === '' ? null : userAgent,
      detail: sanitizeAuditText(input.detail, maxDetail),
    }
  }

  return {
    push(entry) {
      if (disposed) return
      let normalized: AuditEntry | null
      try {
        normalized = normalize(entry)
      } catch {
        normalized = null
      }
      if (normalized === null) return
      entries.push(normalized)
      if (entries.length > limit) entries.splice(0, entries.length - limit)
    },
    snapshot() {
      return entries.map((entry) => ({ ...entry }))
    },
    get size() {
      return entries.length
    },
    dispose() {
      disposed = true
      entries.length = 0
    },
  }
}
