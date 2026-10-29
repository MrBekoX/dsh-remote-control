/**
 * Tunnel provider configuration helpers: validation and the plugin-owned
 * cloudflared runtime config for locally-managed named tunnels.
 *
 * The generated config never reuses the operator's global `~/.cloudflared`
 * config and only ever publishes the Remote Control listener (loopback origin),
 * followed by the mandatory catch-all `http_status: 404` rule.
 */

import { randomBytes as nodeRandomBytes } from 'node:crypto'
import type { Stats } from 'node:fs'
import { chmod, lstat, mkdir, open, readdir, rename, rm } from 'node:fs/promises'
import type { FileHandle } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import { TunnelError } from './tunnel-errors.js'

const MAX_CREDENTIALS_BYTES = 64 * 1024
const MAX_TOKEN_BYTES = 16 * 1024
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ACCOUNT_TAG_PATTERN = /^[0-9a-f]{32}$/i

/** Bare DNS hostname (lowercase, no scheme/port/path, no wildcard, no IP literals). */
export function normalizeHostname(raw: string): string | null {
  const hostname = raw.trim().toLowerCase().replace(/\.$/, '')
  if (hostname === '' || hostname.length > 253) return null
  if (hostname.includes('/') || hostname.includes(':') || hostname.includes('@')) return null
  if (hostname.startsWith('*') || hostname.includes('*')) return null
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return null
  const labels = hostname.split('.')
  if (labels.length < 2) return null
  return labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ? hostname : null
}

/** Canonical `https://host[:port]` origin with no path/query/credentials. */
export function normalizeHttpsOrigin(raw: string): string | null {
  const trimmed = raw.trim()
  if (trimmed === '') return null
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return null
  }
  if (parsed.protocol !== 'https:') return null
  if (parsed.username !== '' || parsed.password !== '') return null
  if (parsed.pathname !== '/' && parsed.pathname !== '') return null
  if (parsed.search !== '' || parsed.hash !== '') return null
  if (parsed.hostname === '') return null
  return parsed.origin
}

export function normalizeUuid(raw: string): string | null {
  const value = raw.trim().toLowerCase()
  return UUID_PATTERN.test(value) ? value : null
}

/** A loopback service URL (`http(s)://127.0.0.1|localhost|[::1]:port`). */
export function normalizeLoopbackServiceUrl(raw: string): string | null {
  let parsed: URL
  try {
    parsed = new URL(raw.trim())
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
  if (parsed.username !== '' || parsed.password !== '') return null
  if (parsed.pathname !== '/' && parsed.pathname !== '') return null
  if (parsed.search !== '' || parsed.hash !== '') return null
  const host = parsed.hostname.toLowerCase()
  if (host !== '127.0.0.1' && host !== '::1' && host !== 'localhost') return null
  if (parsed.port === '') return null
  return parsed.origin
}

export interface CredentialsValidation {
  ok: boolean
  accountTag?: string
  reason?: string
}

/** Validate the cloudflared tunnel credentials JSON shape and UUID binding. */
export function validateCredentialsObject(value: unknown, expectedTunnelId: string): CredentialsValidation {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, reason: 'credentials JSON must be an object' }
  }
  const record = value as Record<string, unknown>
  const accountTag = record['AccountTag']
  const tunnelSecret = record['TunnelSecret']
  const tunnelId = record['TunnelID']
  if (typeof accountTag !== 'string' || !ACCOUNT_TAG_PATTERN.test(accountTag)) {
    return { ok: false, reason: 'credentials JSON AccountTag is missing or malformed' }
  }
  if (typeof tunnelSecret !== 'string' || tunnelSecret.length < 16 || tunnelSecret.length > 256) {
    return { ok: false, reason: 'credentials JSON TunnelSecret is missing or malformed' }
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(tunnelSecret)) {
    return { ok: false, reason: 'credentials JSON TunnelSecret is not base64' }
  }
  const normalized = typeof tunnelId === 'string' ? normalizeUuid(tunnelId) : null
  if (normalized === null) {
    return { ok: false, reason: 'credentials JSON TunnelID is missing or malformed' }
  }
  const expected = normalizeUuid(expectedTunnelId)
  if (expected === null || normalized !== expected) {
    return { ok: false, reason: 'credentials JSON TunnelID does not match the selected tunnel UUID' }
  }
  return { ok: true, accountTag }
}

async function readCheckedFile(filePath: string, maxBytes: number, label: string): Promise<string> {
  const resolved = filePath.trim()
  if (resolved === '') throw new TunnelError('BAD_REQUEST', `${label} path is empty`)
  let before: Stats
  try {
    before = await lstat(resolved)
    if (before.isSymbolicLink()) {
      throw new TunnelError('BAD_REQUEST', `${label} must not be a symbolic link`)
    }
    if (!before.isFile()) throw new TunnelError('BAD_REQUEST', `${label} is not a regular file`)
  } catch (error) {
    if (error instanceof TunnelError) throw error
    throw new TunnelError('BAD_REQUEST', `${label} is not readable`)
  }
  if (before.size > maxBytes) throw new TunnelError('BAD_REQUEST', `${label} is too large`)
  let handle: FileHandle | undefined
  try {
    handle = await open(resolved, 'r')
    const opened = await handle.stat()
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      throw new TunnelError('BAD_REQUEST', `${label} changed while it was being opened`)
    }
    const buffer = Buffer.alloc(opened.size)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead <= 0) break
      offset += bytesRead
    }
    if (offset > maxBytes) throw new TunnelError('BAD_REQUEST', `${label} is too large`)
    return buffer.subarray(0, offset).toString('utf8')
  } catch (error) {
    if (error instanceof TunnelError) throw error
    throw new TunnelError('BAD_REQUEST', `${label} could not be read`)
  } finally {
    await handle?.close().catch(() => undefined)
  }
}

/** Read the JSON tunnel credentials file, refusing symlinks and racing replacements. */
export async function readCredentialsFile(filePath: string): Promise<string> {
  return readCheckedFile(filePath, MAX_CREDENTIALS_BYTES, 'cloudflared credentials file')
}

/** Read a connector token file (trimmed; the content is never logged or put in argv). */
export async function readTokenFile(filePath: string): Promise<string> {
  const raw = await readCheckedFile(filePath, MAX_TOKEN_BYTES, 'cloudflared token file')
  const token = raw.trim()
  if (token === '') throw new TunnelError('BAD_REQUEST', 'cloudflared token file is empty')
  if (/\s/.test(token)) throw new TunnelError('BAD_REQUEST', 'cloudflared token file must contain a single token')
  return token
}

export interface GeneratedCloudflaredConfigInput {
  tunnelId: string
  credentialsFile: string
  hostname: string
  serviceUrl: string
}

/**
 * Generate the plugin-owned cloudflared config for a locally-managed tunnel.
 * Throws when any value would produce a non-loopback ingress rule.
 */
export function buildCloudflaredConfig(input: GeneratedCloudflaredConfigInput): string {
  const tunnelId = normalizeUuid(input.tunnelId)
  if (tunnelId === null) throw new TunnelError('BAD_REQUEST', 'the tunnel UUID is malformed')
  const hostname = normalizeHostname(input.hostname)
  if (hostname === null) throw new TunnelError('BAD_REQUEST', 'the tunnel hostname is not a bare DNS hostname')
  const serviceUrl = normalizeLoopbackServiceUrl(input.serviceUrl)
  if (serviceUrl === null) {
    throw new TunnelError('BAD_REQUEST', 'the tunnel service URL must be a loopback http(s) origin')
  }
  const credentialsFile = input.credentialsFile.trim()
  if (credentialsFile === '') throw new TunnelError('BAD_REQUEST', 'the credentials file path is empty')
  const quotedCredentials = JSON.stringify(credentialsFile)
  return [
    `tunnel: ${tunnelId}`,
    `credentials-file: ${quotedCredentials}`,
    'ingress:',
    `  - hostname: ${hostname}`,
    `    service: ${serviceUrl}`,
    '  - service: http_status:404',
    '',
  ].join('\n')
}

/** Create (or tighten) a plugin-private directory. */
export async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 })
  if (process.platform !== 'win32') {
    await chmod(directory, 0o700).catch(() => undefined)
  }
}

/**
 * Atomically write a private runtime file (temp + rename) and return its path.
 * The directory must be plugin-owned and private.
 */
export async function writePrivateRuntimeFile(
  directory: string,
  fileNamePrefix: string,
  content: string,
  randomBytes: (size: number) => Buffer = nodeRandomBytes,
): Promise<string> {
  await ensurePrivateDirectory(directory)
  const suffix = randomBytes(8).toString('hex')
  const tempPath = join(directory, `.${fileNamePrefix}-${suffix}.tmp`)
  const finalPath = join(directory, `${fileNamePrefix}-${suffix}.yml`)
  await rm(tempPath, { force: true })
  const handle = await open(tempPath, 'wx', 0o600)
  try {
    await handle.writeFile(content, 'utf8')
  } finally {
    await handle.close().catch(() => undefined)
  }
  await rename(tempPath, finalPath)
  return finalPath
}

/** Remove a generated runtime file; missing files are fine. */
export async function removeFileQuietly(filePath: string | null): Promise<void> {
  if (filePath === null) return
  await rm(filePath, { force: true }).catch(() => undefined)
}

/** Remove stale generated configs from a previous crash (best effort). */
export async function cleanRuntimeDirectory(directory: string): Promise<void> {
  try {
    const entries = await readdir(directory)
    await Promise.all(
      entries
        .filter((name) => name.startsWith('.cloudflared-') || /^cloudflared-[0-9a-f]+\.yml$/.test(name))
        .map((name) => rm(join(directory, name), { force: true }).catch(() => undefined)),
    )
  } catch {
    // A missing runtime directory means nothing to clean.
  }
}

/** Parent directory of the managed binary directory (used for runtime/ssh state). */
export function parentDirectory(directory: string): string {
  return dirname(directory)
}
