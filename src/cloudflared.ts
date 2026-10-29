/**
 * cloudflared provider: pinned official release metadata, discovery, verified
 * user-initiated download, safe archive extraction, verified cache, argv and
 * bounded output parsing.
 *
 * Trust model (see `scratch/research-methods-facts.md`):
 * - the release is PINNED (version + per-OS/arch asset + size + official
 *   SHA-256); there is no "latest" lookup and no unverified download;
 * - for bare binaries the pinned SHA-256 is the downloaded bytes (GitHub release
 *   API asset `digest`, equal to the release-body checksum);
 * - for the macOS `.tgz` assets the API `digest` covers the `.tgz` bytes while
 *   the release-body checksum covers the extracted binary: both are pinned and
 *   verified separately, never mixed;
 * - an unsupported platform/architecture, or any missing/malformed pinned
 *   digest, fails closed (no download, `UNSUPPORTED_PLATFORM`);
 * - discovery order: explicit configured path -> `cloudflared` on PATH ->
 *   verified cache. Only a cache entry whose digest matches the pinned hash is
 *   `verified: true`; operator installs are usable but reported as unverified;
 * - downloads are HTTPS only with manual redirect validation, bounded time and
 *   size, written to a temp file inside the cache directory, digest-verified
 *   before execution/caching, and atomically renamed into place. The cache is
 *   re-verified on every later use.
 */

import { createHash, randomBytes as defaultRandomBytes } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { chmod, lstat, mkdir, open, readdir, rename, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { inflateRawSync, gunzipSync } from 'node:zlib'

import type { Logger } from './shared/internal.js'
import type { CloudflaredDownloadInfo, TunnelTransport } from './shared/protocol.js'
import { TunnelError, errorMessage } from './tunnel-errors.js'
import { normalizeLoopbackServiceUrl, normalizeUuid } from './tunnel-config.js'
import {
  BoundedOutput,
  buildChildEnv,
  probeCommand,
  sanitizeProviderText,
  type FetchLike,
  type SpawnFn,
} from './tunnel-process.js'

/* ------------------------------------------------------------------------- */
/* Pinned official release                                                   */
/* ------------------------------------------------------------------------- */

export interface CloudflaredAsset {
  platform: string
  arch: string
  /** Exact official asset filename for this release. */
  asset: string
  /** Exact asset byte size (GitHub release API `assets[].size`). */
  sizeBytes: number
  /** Official SHA-256 of exactly the downloaded asset bytes (API `digest`). */
  sha256: string
  /** How the executable is obtained from the download. */
  archive: 'none' | 'tgz' | 'zip'
  /** Executable filename inside the archive and inside the plugin cache. */
  executableName: string
  /** Archive assets only: SHA-256 of the extracted executable (release-body value). */
  binarySha256?: string
  /** Archive assets only: extracted executable size in bytes when published. */
  binarySizeBytes?: number
}

export interface CloudflaredRelease {
  version: string
  /** Base URL of the official pinned release (`.../releases/download/<version>`). */
  releaseBaseUrl: string
  assets: Record<string, CloudflaredAsset>
}

const PINNED_VERSION = '2026.10.5'
const PINNED_BASE_URL = `https://github.com/cloudflare/cloudflared/releases/download/${PINNED_VERSION}`

/**
 * Official `cloudflare/cloudflared` release 2026.10.5.
 * Sources: GitHub release API `assets[].digest` + release-body SHA256 block,
 * observed 2026-10-28 (research report A2d/A2e).
 */
export const PINNED_CLOUDFLARED_RELEASE: CloudflaredRelease = {
  version: PINNED_VERSION,
  releaseBaseUrl: PINNED_BASE_URL,
  assets: {
    'win32-x64': {
      platform: 'win32',
      arch: 'x64',
      asset: 'cloudflared-windows-amd64.exe',
      sizeBytes: 55_343_328,
      sha256: 'db4e4c413612a0916f3e1679d3caaf376f94911952d163028fb726fb2e0516a9',
      archive: 'none',
      executableName: 'cloudflared.exe',
    },
    'win32-ia32': {
      platform: 'win32',
      arch: 'ia32',
      asset: 'cloudflared-windows-386.exe',
      sizeBytes: 38_078_600,
      sha256: '66cba8003e4f87a8e6b772f331b8c04c7d41ac4f2dc30dd2c13ae09de3b6007e',
      archive: 'none',
      executableName: 'cloudflared.exe',
    },
    'linux-x64': {
      platform: 'linux',
      arch: 'x64',
      asset: 'cloudflared-linux-amd64',
      sizeBytes: 40_263_303,
      sha256: 'e1bc0cf084fd9e590554fe769a86b1db46701c3f847a43d902f7b974a4e16298',
      archive: 'none',
      executableName: 'cloudflared',
    },
    'linux-arm64': {
      platform: 'linux',
      arch: 'arm64',
      asset: 'cloudflared-linux-arm64',
      sizeBytes: 37_662_975,
      sha256: '72e0d05a67e09da87cf495e409a28c3cc5994dd23fc66a982eebea6a55923b7d',
      archive: 'none',
      executableName: 'cloudflared',
    },
    'linux-arm': {
      platform: 'linux',
      arch: 'arm',
      asset: 'cloudflared-linux-arm',
      sizeBytes: 37_132_381,
      sha256: 'a018911e1bbfd739937f3011f589e9e73245baeee14742f8b3413472bb007adc',
      archive: 'none',
      executableName: 'cloudflared',
    },
    'linux-ia32': {
      platform: 'linux',
      arch: 'ia32',
      asset: 'cloudflared-linux-386',
      sizeBytes: 37_680_533,
      sha256: 'f2de713829081837130b38e27f3c95aa9d7fc1a4f48b833362d21234dd8780d8',
      archive: 'none',
      executableName: 'cloudflared',
    },
    'darwin-arm64': {
      platform: 'darwin',
      arch: 'arm64',
      asset: 'cloudflared-darwin-arm64.tgz',
      sizeBytes: 19_840_425,
      sha256: '184c7d4f5f977348243a6d7ca8f6cf6073b9b2746cfe8c1fe15aa59e9a522bf0',
      archive: 'tgz',
      executableName: 'cloudflared',
      binarySha256: '2b23964528ddcd641c1449275df8b5b51e3c7193b5257919846331bc5bc13b0f',
      binarySizeBytes: 39_485_536,
    },
    'darwin-x64': {
      platform: 'darwin',
      arch: 'x64',
      asset: 'cloudflared-darwin-amd64.tgz',
      sizeBytes: 21_798_374,
      sha256: '6699392fed92367808c248c2d90bed66e49bbf66e1b4ee3e4141230f3f7391b3',
      archive: 'tgz',
      executableName: 'cloudflared',
      binarySha256: 'cb09afb9b4d0a4730de477ac710aebb6107568930a8345775629bf264f70c284',
    },
  },
}

const SHA256_HEX = /^[0-9a-f]{64}$/i

/**
 * Resolve the pinned official asset for one platform/architecture. Returns null
 * (fail closed) when the platform is unsupported or any pinned value needed for
 * verification is missing/malformed.
 */
export function pinnedAssetFor(
  platform: string,
  arch: string,
  release: CloudflaredRelease = PINNED_CLOUDFLARED_RELEASE,
): CloudflaredAsset | null {
  const asset = release.assets[`${platform}-${arch}`]
  if (asset === undefined) return null
  if (!SHA256_HEX.test(asset.sha256)) return null
  if (!Number.isSafeInteger(asset.sizeBytes) || asset.sizeBytes <= 0) return null
  if (asset.archive !== 'none') {
    if (asset.binarySha256 === undefined || !SHA256_HEX.test(asset.binarySha256)) return null
  }
  return asset
}

export function pinnedDownloadUrl(
  asset: CloudflaredAsset,
  release: CloudflaredRelease = PINNED_CLOUDFLARED_RELEASE,
): string {
  return `${release.releaseBaseUrl}/${asset.asset}`
}

/** Parse `cloudflared version 2026.10.5 (...)` / `Version 2026.10.5` output. */
export function parseCloudflaredVersion(text: string): string | null {
  const match = /(?:cloudflared\s+version|version)\s+(\d{4}\.\d+\.\d+)/i.exec(text)
  return match?.[1] ?? null
}

/** True when `current` >= `minimum` (dotted numeric versions). */
export function versionAtLeast(current: string, minimum: string): boolean {
  const parse = (value: string): number[] =>
    value
      .split('.')
      .map((part) => Number.parseInt(part, 10))
      .map((part) => (Number.isFinite(part) ? part : 0))
  const left = parse(current)
  const right = parse(minimum)
  const length = Math.max(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    const a = left[index] ?? 0
    const b = right[index] ?? 0
    if (a !== b) return a > b
  }
  return true
}

/* ------------------------------------------------------------------------- */
/* Output parsing + argv                                                     */
/* ------------------------------------------------------------------------- */

const TRYCLOUDFLARE_CANDIDATE = /https:\/\/[^\s"'<>\\)|,]+/gi
const REGISTERED = /registered tunnel connection/i
const STARTED_TUNNEL = /starting tunnel tunnelid=/i
const INITIAL_PROTOCOL = /initial protocol\s+(quic|http2|auto)/i
const ANALOG_ERROR = /\bERR\b|error=/i

/** Accept only a canonical `https://<label>.trycloudflare.com` origin. */
export function normalizeTrycloudflareUrl(raw: string): string | null {
  let parsed: URL
  try {
    parsed = new URL(raw.trim())
  } catch {
    return null
  }
  if (parsed.protocol !== 'https:') return null
  if (parsed.username !== '' || parsed.password !== '') return null
  if (parsed.port !== '') return null
  if (parsed.pathname !== '/' && parsed.pathname !== '') return null
  if (parsed.search !== '' || parsed.hash !== '') return null
  const hostname = parsed.hostname.toLowerCase()
  if (!hostname.endsWith('.trycloudflare.com')) return null
  const prefix = hostname.slice(0, -'.trycloudflare.com'.length)
  if (prefix === '') return null
  if (!prefix.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null
  return `https://${hostname}`
}

export type CloudflaredProviderMode = 'quick' | 'named' | 'named-local'

export interface CloudflaredOutputParser {
  push(chunk: Buffer | string): void
  /** Quick tunnel origin (null until a valid URL was printed). */
  url(): string | null
  /** Connector believes it is registered/connecting to the edge. */
  connected(): boolean
  protocol(): string | null
  /** Sanitized, bounded provider error lines (never token-bearing). */
  errors(): string[]
  text(): string
}

/**
 * Bounded parser for cloudflared's streamed output. Everything (including the
 * quick-tunnel URL) is printed on stderr and can be fragmented arbitrarily; the
 * URL sits inside a box-drawing banner, so the parser runs a regex over a
 * bounded rolling tail instead of splitting lines.
 */
export function createCloudflaredOutputParser(options: {
  mode: CloudflaredProviderMode
  maxTailChars?: number
}): CloudflaredOutputParser {
  const tail = new BoundedOutput(options.maxTailChars ?? 16_384)
  const errors: string[] = []

  const refreshErrors = (): void => {
    const text = tail.text()
    for (const line of text.split('\n')) {
      if (!ANALOG_ERROR.test(line)) continue
      const clean = sanitizeProviderText(line)
      if (clean === '') continue
      if (!errors.includes(clean)) errors.push(clean)
    }
    if (errors.length > 5) errors.splice(0, errors.length - 5)
  }

  return {
    push(chunk) {
      tail.push(chunk)
      refreshErrors()
    },
    url() {
      if (options.mode !== 'quick') return null
      TRYCLOUDFLARE_CANDIDATE.lastIndex = 0
      const text = tail.text()
      for (;;) {
        const match = TRYCLOUDFLARE_CANDIDATE.exec(text)
        if (match === null) return null
        const candidate = normalizeTrycloudflareUrl(match[0])
        if (candidate !== null) return candidate
      }
    },
    connected() {
      const text = tail.text()
      if (options.mode === 'quick') {
        return this.url() !== null && REGISTERED.test(text)
      }
      return STARTED_TUNNEL.test(text) && (REGISTERED.test(text) || INITIAL_PROTOCOL.test(text))
    },
    protocol() {
      const match = INITIAL_PROTOCOL.exec(tail.text())
      return match?.[1]?.toLowerCase() ?? null
    },
    errors() {
      return [...errors]
    },
    text() {
      return tail.text()
    },
  }
}

export interface CloudflaredTokenSource {
  kind: 'env' | 'file'
  envName?: string
  path?: string
}

export interface CloudflaredArgsInput {
  mode: CloudflaredProviderMode
  transport: TunnelTransport
  localUrl?: string
  configFile?: string
  tunnelId?: string
  tokenSource?: CloudflaredTokenSource
}

const TRANSPORTS: ReadonlySet<string> = new Set(['auto', 'quic', 'http2'])

/** Build the executable argv (never contains a token; `--token-file` takes a path only). */
export function buildCloudflaredArgs(input: CloudflaredArgsInput): string[] {
  if (!TRANSPORTS.has(input.transport)) {
    throw new TunnelError('BAD_REQUEST', 'unsupported connector transport (auto|quic|http2 only)')
  }
  const args = ['tunnel', '--no-autoupdate', '--protocol', input.transport]
  if (input.mode === 'quick') {
    const localUrl = input.localUrl === undefined ? null : normalizeLoopbackServiceUrl(input.localUrl)
    if (localUrl === null) {
      throw new TunnelError('BAD_REQUEST', 'the quick tunnel needs a loopback local service URL')
    }
    args.push('--url', localUrl)
    return args
  }
  if (input.mode === 'named') {
    args.push('run')
    if (input.tokenSource?.kind === 'file') {
      if (input.tokenSource.path === undefined || input.tokenSource.path.trim() === '') {
        throw new TunnelError('BAD_REQUEST', 'the connector token file path is missing')
      }
      args.push('--token-file', input.tokenSource.path)
    }
    return args
  }
  const configFile = input.configFile?.trim() ?? ''
  const tunnelId = input.tunnelId === undefined ? null : normalizeUuid(input.tunnelId)
  if (configFile === '' || tunnelId === null) {
    throw new TunnelError('BAD_REQUEST', 'the locally-managed tunnel needs a config file and tunnel UUID')
  }
  args.push('--config', configFile, 'run', tunnelId)
  return args
}

/* ------------------------------------------------------------------------- */
/* Safe archive extraction (zip / tar.gz)                                    */
/* ------------------------------------------------------------------------- */

const MAX_ARCHIVE_ENTRIES = 4_096
const MAX_EXTRACTED_BYTES = 256 * 1024 * 1024

function isSafeArchivePath(name: string): boolean {
  if (name === '' || name.length > 1_024) return false
  if (name.includes('\u0000') || name.includes('\\')) return false
  if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) return false
  for (const segment of name.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') return false
  }
  return true
}

function tarString(block: Buffer, offset: number, length: number): string {
  const slice = block.subarray(offset, offset + length)
  const end = slice.indexOf(0)
  return (end === -1 ? slice : slice.subarray(0, end)).toString('utf8')
}

function tarOctal(block: Buffer, offset: number, length: number): number | null {
  const text = tarString(block, offset, length).trim()
  if (text === '') return 0
  if (!/^[0-7]+$/.test(text)) return null
  const value = Number.parseInt(text, 8)
  return Number.isSafeInteger(value) ? value : null
}

function extractTarMember(archive: Buffer, expectedName: string): Buffer {
  let data: Buffer
  try {
    data = gunzipSync(archive)
  } catch {
    throw new TunnelError('BAD_REQUEST', 'archive is not a valid gzip stream')
  }
  let offset = 0
  let expected: Buffer | null = null
  let entries = 0
  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512)
    let empty = true
    for (const byte of header) {
      if (byte !== 0) {
        empty = false
        break
      }
    }
    if (empty) break
    entries += 1
    if (entries > MAX_ARCHIVE_ENTRIES) throw new TunnelError('BAD_REQUEST', 'archive has too many entries')
    const name = tarString(header, 0, 100)
    const prefix = tarString(header, 345, 155)
    const fullName = prefix === '' ? name : `${prefix}/${name}`
    const typeFlagByte = header[156] ?? 0
    const typeFlag = typeFlagByte === 0 ? '0' : String.fromCharCode(typeFlagByte)
    const size = tarOctal(header, 124, 12)
    if (size === null || size < 0 || size > MAX_EXTRACTED_BYTES) {
      throw new TunnelError('BAD_REQUEST', 'archive entry has an invalid size')
    }
    if (typeFlag !== '0') {
      throw new TunnelError('BAD_REQUEST', 'archive contains a non-regular entry (symlink/hardlink/directory)')
    }
    if (!isSafeArchivePath(fullName)) {
      throw new TunnelError('BAD_REQUEST', 'archive contains an unsafe path')
    }
    const dataStart = offset + 512
    if (dataStart + size > data.length) throw new TunnelError('BAD_REQUEST', 'archive is truncated')
    if (fullName === expectedName) {
      if (expected !== null) throw new TunnelError('BAD_REQUEST', 'archive contains duplicate executable entries')
      expected = data.subarray(dataStart, dataStart + size)
    }
    offset = dataStart + Math.ceil(size / 512) * 512
  }
  if (expected === null) throw new TunnelError('BAD_REQUEST', 'archive does not contain the expected executable')
  return expected
}

interface ZipCentralEntry {
  name: string
  flags: number
  method: number
  compressedSize: number
  uncompressedSize: number
  externalAttributes: number
  localOffset: number
}

function readZipEntries(archive: Buffer): ZipCentralEntry[] {
  let eocd = -1
  const earliest = Math.max(0, archive.length - 65_557)
  for (let index = archive.length - 22; index >= earliest; index -= 1) {
    if (archive.readUInt32LE(index) === 0x06054b50) {
      eocd = index
      break
    }
  }
  if (eocd === -1) throw new TunnelError('BAD_REQUEST', 'archive is not a valid zip file')
  const totalEntries = archive.readUInt16LE(eocd + 10)
  const centralSize = archive.readUInt32LE(eocd + 12)
  const centralOffset = archive.readUInt32LE(eocd + 16)
  if (totalEntries === 0xffff || centralOffset === 0xffffffff || centralSize === 0xffffffff) {
    throw new TunnelError('BAD_REQUEST', 'zip64 archives are not supported')
  }
  if (totalEntries > MAX_ARCHIVE_ENTRIES) throw new TunnelError('BAD_REQUEST', 'archive has too many entries')
  if (centralOffset + centralSize > archive.length) throw new TunnelError('BAD_REQUEST', 'zip central directory is truncated')
  const entries: ZipCentralEntry[] = []
  let position = centralOffset
  for (let index = 0; index < totalEntries; index += 1) {
    if (position + 46 > archive.length || archive.readUInt32LE(position) !== 0x02014b50) {
      throw new TunnelError('BAD_REQUEST', 'zip central directory is malformed')
    }
    const flags = archive.readUInt16LE(position + 8)
    const method = archive.readUInt16LE(position + 10)
    const compressedSize = archive.readUInt32LE(position + 20)
    const uncompressedSize = archive.readUInt32LE(position + 24)
    const nameLength = archive.readUInt16LE(position + 28)
    const extraLength = archive.readUInt16LE(position + 30)
    const commentLength = archive.readUInt16LE(position + 32)
    const externalAttributes = archive.readUInt32LE(position + 38)
    const localOffset = archive.readUInt32LE(position + 42)
    const nameStart = position + 46
    if (nameStart + nameLength > archive.length) throw new TunnelError('BAD_REQUEST', 'zip entry name is truncated')
    const name = archive.subarray(nameStart, nameStart + nameLength).toString('utf8')
    entries.push({ name, flags, method, compressedSize, uncompressedSize, externalAttributes, localOffset })
    position = nameStart + nameLength + extraLength + commentLength
  }
  return entries
}

function extractZipMember(archive: Buffer, expectedName: string): Buffer {
  const entries = readZipEntries(archive)
  let expected: Buffer | null = null
  for (const entry of entries) {
    if (!isSafeArchivePath(entry.name)) throw new TunnelError('BAD_REQUEST', 'archive contains an unsafe path')
    if ((entry.flags & 0x1) !== 0) throw new TunnelError('BAD_REQUEST', 'encrypted zip entries are not supported')
    const unixType = (entry.externalAttributes >>> 16) & 0xf000
    if (unixType === 0xa000) throw new TunnelError('BAD_REQUEST', 'archive contains a symbolic link')
    if (entry.name.endsWith('/')) continue
    if (entry.method !== 0 && entry.method !== 8) {
      throw new TunnelError('BAD_REQUEST', 'unsupported zip compression method')
    }
    if (entry.compressedSize > MAX_EXTRACTED_BYTES || entry.uncompressedSize > MAX_EXTRACTED_BYTES) {
      throw new TunnelError('BAD_REQUEST', 'archive entry is too large')
    }
    if (entry.localOffset + 30 > archive.length || archive.readUInt32LE(entry.localOffset) !== 0x04034b50) {
      throw new TunnelError('BAD_REQUEST', 'zip local header is malformed')
    }
    const localNameLength = archive.readUInt16LE(entry.localOffset + 26)
    const localExtraLength = archive.readUInt16LE(entry.localOffset + 28)
    const dataStart = entry.localOffset + 30 + localNameLength + localExtraLength
    if (dataStart + entry.compressedSize > archive.length) {
      throw new TunnelError('BAD_REQUEST', 'zip entry data is truncated')
    }
    const payload = archive.subarray(dataStart, dataStart + entry.compressedSize)
    let content: Buffer
    if (entry.method === 0) {
      content = payload
    } else {
      try {
        content = inflateRawSync(payload)
      } catch {
        throw new TunnelError('BAD_REQUEST', 'zip entry could not be decompressed')
      }
    }
    if (content.length !== entry.uncompressedSize) {
      throw new TunnelError('BAD_REQUEST', 'zip entry size does not match its header')
    }
    if (entry.name === expectedName) {
      if (expected !== null) throw new TunnelError('BAD_REQUEST', 'archive contains duplicate executable entries')
      expected = content
    }
  }
  if (expected === null) throw new TunnelError('BAD_REQUEST', 'archive does not contain the expected executable')
  return expected
}

function extractExpectedExecutable(archive: Buffer, asset: CloudflaredAsset): Buffer {
  if (asset.archive === 'none') throw new TunnelError('INTERNAL', 'the selected asset is not an archive')
  return asset.archive === 'tgz'
    ? extractTarMember(archive, asset.executableName)
    : extractZipMember(archive, asset.executableName)
}

/* ------------------------------------------------------------------------- */
/* Discovery / installer                                                     */
/* ------------------------------------------------------------------------- */

export type CloudflaredInstalled = NonNullable<CloudflaredDownloadInfo['installed']>

export interface CloudflaredResolveResult {
  installed: CloudflaredInstalled | null
  asset: CloudflaredAsset | null
  supported: boolean
  cacheDirectory: string
  release: CloudflaredRelease
}

export interface CloudflaredFacade {
  /**
   * Discovery only (no network, no download).
   *
   * `candidates` is an optional ordered list that replaces the configured path:
   * the desktop panel's explicit selection first, then the configured path. An
   * empty/absent list falls back to the configured path, PATH and the verified
   * cache exactly as before.
   */
  resolve(candidates?: readonly string[]): Promise<CloudflaredResolveResult>
  /** Disclosed pinned download plan + installed binary, no side effects. */
  info(candidates?: readonly string[]): Promise<CloudflaredDownloadInfo>
  /** Explicit user-requested verified download. */
  install(): Promise<CloudflaredDownloadInfo>
}

export interface CloudflaredInstallerDeps {
  /** `tunnel.cloudflaredPath`: a name on PATH or an explicit path. */
  configuredPath: string
  /** Plugin-private binary cache directory (`<DSH_HOME>/remote-control/bin`). */
  cacheDir: string
  platform?: NodeJS.Platform | string
  arch?: string
  /** Test seam: override the pinned release table. */
  release?: CloudflaredRelease
  spawn?: SpawnFn
  log: Logger
  /** Base environment for child probes (defaults to `process.env`). */
  env?: NodeJS.ProcessEnv
  fetch?: FetchLike
  randomBytes?: (size: number) => Buffer
  now?: () => number
  fileExists?: (path: string) => Promise<boolean>
  hashFile?: (path: string) => Promise<string>
  probeTimeoutMs?: number
  downloadTimeoutMs?: number
  maxRedirects?: number
}

const GITHUB_DOWNLOAD_HOSTS: ReadonlySet<string> = new Set([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
])

const DEFAULT_PROBE_TIMEOUT_MS = 5_000
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 120_000

function isPathLike(value: string): boolean {
  return value.includes('/') || value.includes('\\') || /^[A-Za-z]:/.test(value)
}

function cacheFileName(release: CloudflaredRelease, asset: CloudflaredAsset): string {
  const extension = asset.platform === 'win32' ? '.exe' : ''
  return `cloudflared-${release.version}-${asset.platform}-${asset.arch}${extension}`
}

function executableDigest(asset: CloudflaredAsset): string {
  return asset.binarySha256 ?? asset.sha256
}

function executableSize(asset: CloudflaredAsset): number | null {
  return asset.binarySizeBytes ?? (asset.archive === 'none' ? asset.sizeBytes : null)
}

async function hashFileStream(path: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(path)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.once('error', reject)
    stream.once('end', () => resolve(hash.digest('hex')))
  })
}

async function defaultFileExists(path: string): Promise<boolean> {
  try {
    const info = await lstat(path)
    return info.isFile()
  } catch {
    return false
  }
}

async function fileSignature(path: string): Promise<string> {
  try {
    const info = await lstat(path)
    return `${info.mtimeMs}:${info.size}:${info.ino}`
  } catch {
    return 'missing'
  }
}

interface ResolveMemo {
  key: string
  at: number
  value: CloudflaredResolveResult
}

export function createCloudflaredInstaller(deps: CloudflaredInstallerDeps): CloudflaredFacade {
  const log = deps.log
  const release = deps.release ?? PINNED_CLOUDFLARED_RELEASE
  const platform = deps.platform ?? process.platform
  const arch = deps.arch ?? process.arch
  const cacheDir = deps.cacheDir
  const baseEnv = deps.env ?? process.env
  const spawn = deps.spawn
  const fetchImpl: FetchLike = deps.fetch ?? fetch
  const now = deps.now ?? Date.now
  const randomBytes = deps.randomBytes ?? defaultRandomBytes
  const fileExists = deps.fileExists ?? defaultFileExists
  const hashFile = deps.hashFile ?? hashFileStream
  const probeTimeoutMs = deps.probeTimeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS
  const downloadTimeoutMs = deps.downloadTimeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS
  const maxRedirects = deps.maxRedirects ?? 5

  const digestMemo = new Map<string, { fingerprint: string; verified: boolean; at: number }>()
  let resolveMemo: ResolveMemo | null = null

  const childEnv = (): NodeJS.ProcessEnv => buildChildEnv({}, {}, log, baseEnv)

  const probeVersion = async (command: string): Promise<string | null> => {
    if (spawn === undefined) return null
    const probe = await probeCommand(spawn, command, ['--version'], {
      timeoutMs: probeTimeoutMs,
      env: childEnv(),
      log,
    })
    if (!probe.ok) return null
    return parseCloudflaredVersion(`${probe.stdout}\n${probe.stderr}`) ?? 'unknown'
  }

  const digestMatchesPinned = async (path: string, asset: CloudflaredAsset): Promise<boolean> => {
    let fingerprint = await fileSignature(path)
    if (fingerprint === 'missing') {
      // Explicit-path existence may be provided by a test/system seam (or the
      // file may live on a filesystem where lstat is unavailable to the probe).
      if (!(await fileExists(path))) return false
      fingerprint = 'existence-seam'
    }
    const cached = digestMemo.get(path)
    if (cached !== undefined && cached.fingerprint === fingerprint && now() - cached.at < 10_000) {
      return cached.verified
    }
    let verified = false
    try {
      const digest = (await hashFile(path)).toLowerCase()
      verified = digest === executableDigest(asset).toLowerCase()
    } catch {
      verified = false
    }
    digestMemo.set(path, { fingerprint, verified, at: now() })
    return verified
  }

  const verifyCacheEntry = async (cachePath: string, asset: CloudflaredAsset): Promise<CloudflaredInstalled | null> => {
    let info
    try {
      info = await lstat(cachePath)
    } catch {
      return null
    }
    if (info.isSymbolicLink()) {
      log.warn('refusing a symlinked cloudflared cache entry')
      await rm(cachePath, { force: true }).catch(() => undefined)
      return null
    }
    if (!info.isFile()) {
      log.warn('refusing a non-file cloudflared cache entry')
      return null
    }
    const expectedSize = executableSize(asset)
    if (expectedSize !== null && info.size !== expectedSize) {
      log.warn('cloudflared cache entry has an unexpected size; removing it')
      await rm(cachePath, { force: true }).catch(() => undefined)
      return null
    }
    let digest: string
    try {
      digest = (await hashFile(cachePath)).toLowerCase()
    } catch {
      return null
    }
    if (digest !== executableDigest(asset).toLowerCase()) {
      log.warn('cloudflared cache entry failed digest re-verification; removing it')
      await rm(cachePath, { force: true }).catch(() => undefined)
      return null
    }
    return { path: cachePath, source: 'cache', version: release.version, verified: true }
  }

  /**
   * Ordered binary candidates for one resolution. An explicit list replaces the
   * configured path; callers that want both pass both. Empty and duplicate
   * entries are dropped rather than guessed at.
   */
  const normalizeCandidates = (candidates: readonly string[] | undefined): string[] => {
    const source = candidates === undefined ? [deps.configuredPath] : candidates
    const normalized: string[] = []
    for (const value of source) {
      if (typeof value !== 'string') continue
      const trimmed = value.trim()
      if (trimmed === '' || normalized.includes(trimmed)) continue
      normalized.push(trimmed)
    }
    return normalized
  }

  const resolveUncached = async (
    asset: CloudflaredAsset | null,
    candidates: readonly string[],
  ): Promise<CloudflaredResolveResult> => {
    // 1. Ordered explicit paths (desktop selection first, then the configured path).
    for (const candidate of candidates) {
      if (!isPathLike(candidate)) continue
      if (!(await fileExists(candidate))) {
        log.warn('a configured cloudflared candidate does not exist; trying the next candidate')
        continue
      }
      const version = await probeVersion(candidate)
      if (version === null) {
        log.warn('a configured cloudflared candidate could not be executed; trying the next candidate')
        continue
      }
      const verified = asset !== null ? await digestMatchesPinned(candidate, asset) : false
      return { installed: { path: candidate, source: 'configured', version, verified }, asset, supported: asset !== null, cacheDirectory: cacheDir, release }
    }
    // 2. Existing install on PATH (operator-trusted, not cryptographically verified).
    //    A bare configured name is the PATH command; otherwise the default name.
    const configuredName = candidates.find((candidate) => !isPathLike(candidate))
    const pathCommand = configuredName ?? 'cloudflared'
    const pathVersion = await probeVersion(pathCommand)
    if (pathVersion !== null) {
      return { installed: { path: pathCommand, source: 'path', version: pathVersion, verified: false }, asset, supported: asset !== null, cacheDirectory: cacheDir, release }
    }
    // 3. Verified plugin cache (digest matches the pinned official hash).
    if (asset !== null) {
      const cached = await verifyCacheEntry(join(cacheDir, cacheFileName(release, asset)), asset)
      if (cached !== null) return { installed: cached, asset, supported: true, cacheDirectory: cacheDir, release }
    }
    return { installed: null, asset, supported: asset !== null, cacheDirectory: cacheDir, release }
  }

  const resolve = async (candidates?: readonly string[]): Promise<CloudflaredResolveResult> => {
    const asset = pinnedAssetFor(String(platform), arch, release)
    const effective = normalizeCandidates(candidates)
    const fingerprints: string[] = [String(platform), arch, cacheDir, effective.join('\u0000')]
    fingerprints.push(asset === null ? 'unsupported' : await fileSignature(join(cacheDir, cacheFileName(release, asset))))
    for (const candidate of effective) {
      if (isPathLike(candidate)) fingerprints.push(await fileSignature(candidate))
    }
    const key = fingerprints.join('|')
    if (resolveMemo !== null && resolveMemo.key === key && now() - resolveMemo.at < 12_000) {
      return resolveMemo.value
    }
    const value = await resolveUncached(asset, effective)
    resolveMemo = { key, at: now(), value }
    return value
  }

  const download = async (asset: CloudflaredAsset, destination: string): Promise<void> => {
    const initialUrl = pinnedDownloadUrl(asset, release)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), downloadTimeoutMs)
    timer.unref()
    const handle = await open(destination, 'wx', 0o600)
    const hash = createHash('sha256')
    let bytes = 0
    try {
      let currentUrl = initialUrl
      let redirects = 0
      for (;;) {
        const response = await fetchImpl(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: { accept: 'application/octet-stream', 'user-agent': 'dsh-remote-control-installer' },
        })
        if (response.status >= 300 && response.status < 400) {
          redirects += 1
          if (redirects > maxRedirects) throw new TunnelError('BAD_REQUEST', 'too many download redirects')
          const location = response.headers.get('location')
          if (location === null || location === '') throw new TunnelError('BAD_REQUEST', 'download redirect without a location')
          let next: URL
          try {
            next = new URL(location, currentUrl)
          } catch {
            throw new TunnelError('BAD_REQUEST', 'download redirect target is not a valid URL')
          }
          if (next.protocol !== 'https:') throw new TunnelError('BAD_REQUEST', 'download redirect must stay on HTTPS')
          if (next.username !== '' || next.password !== '') {
            throw new TunnelError('BAD_REQUEST', 'download redirect must not contain credentials')
          }
          if (!GITHUB_DOWNLOAD_HOSTS.has(next.hostname.toLowerCase())) {
            throw new TunnelError('BAD_REQUEST', 'download redirect target is not an official GitHub host')
          }
          // Follow the validated target: the next request must use it, otherwise
          // the same URL is re-requested until the redirect budget is exhausted.
          currentUrl = next.href
          continue
        }
        if (response.status !== 200) {
          throw new TunnelError('INTERNAL', `cloudflared download failed with HTTP ${response.status}`)
        }
        const declaredLength = response.headers.get('content-length')
        if (declaredLength !== null) {
          const declared = Number.parseInt(declaredLength, 10)
          if (!Number.isSafeInteger(declared) || declared !== asset.sizeBytes) {
            throw new TunnelError('CHECKSUM_MISMATCH', 'the downloaded asset size does not match the pinned official size')
          }
        }
        if (response.body === null) throw new TunnelError('INTERNAL', 'cloudflared download returned an empty body')
        for await (const chunk of response.body) {
          const buffer = Buffer.from(chunk)
          bytes += buffer.length
          if (bytes > asset.sizeBytes) {
            throw new TunnelError('CHECKSUM_MISMATCH', 'the downloaded asset is larger than the pinned official size')
          }
          hash.update(buffer)
          await handle.write(buffer)
        }
        break
      }
      if (bytes !== asset.sizeBytes) {
        throw new TunnelError('CHECKSUM_MISMATCH', 'the downloaded asset size does not match the pinned official size')
      }
      const digest = hash.digest('hex')
      if (digest !== asset.sha256.toLowerCase()) {
        throw new TunnelError('CHECKSUM_MISMATCH', 'the downloaded asset does not match the pinned official SHA-256')
      }
    } catch (error) {
      if (controller.signal.aborted) {
        throw new TunnelError('INTERNAL', 'cloudflared download timed out')
      }
      if (error instanceof TunnelError) throw error
      throw new TunnelError('INTERNAL', `cloudflared download failed: ${errorMessage(error)}`)
    } finally {
      clearTimeout(timer)
      await handle.close().catch(() => undefined)
    }
  }

  const install = async (): Promise<CloudflaredDownloadInfo> => {
    const asset = pinnedAssetFor(String(platform), arch, release)
    if (asset === null) {
      throw new TunnelError(
        'UNSUPPORTED_PLATFORM',
        `no pinned official cloudflared asset exists for ${String(platform)}/${arch}`,
      )
    }
    await mkdir(cacheDir, { recursive: true, mode: 0o700 })
    const suffix = randomBytes(8).toString('hex')
    const archiveTemp = join(cacheDir, `.download-${suffix}`)
    const extractTemp = join(cacheDir, `.extract-${suffix}`)
    const finalPath = join(cacheDir, cacheFileName(release, asset))
    try {
      await download(asset, archiveTemp)
      let executablePath = archiveTemp
      if (asset.archive !== 'none') {
        if (asset.binarySha256 === undefined) {
          throw new TunnelError('UNSUPPORTED_PLATFORM', 'the pinned archive asset has no executable digest')
        }
        let extracted: Buffer
        try {
          extracted = extractExpectedExecutable(await readFileBuffer(archiveTemp, asset.sizeBytes), asset)
        } catch (error) {
          if (error instanceof TunnelError) throw error
          throw new TunnelError('BAD_REQUEST', `cloudflared archive could not be extracted: ${errorMessage(error)}`)
        }
        const extractedDigest = createHash('sha256').update(extracted).digest('hex')
        if (extractedDigest !== asset.binarySha256.toLowerCase()) {
          throw new TunnelError('CHECKSUM_MISMATCH', 'the extracted cloudflared binary does not match the pinned official SHA-256')
        }
        if (asset.binarySizeBytes !== undefined && extracted.length !== asset.binarySizeBytes) {
          throw new TunnelError('CHECKSUM_MISMATCH', 'the extracted cloudflared binary has an unexpected size')
        }
        const handle = await open(extractTemp, 'wx', 0o600)
        try {
          await handle.writeFile(extracted)
        } finally {
          await handle.close().catch(() => undefined)
        }
        await chmod(extractTemp, 0o700).catch(() => undefined)
        executablePath = extractTemp
      } else {
        await chmod(archiveTemp, 0o700).catch(() => undefined)
      }
      if (asset.archive === 'none') {
        await rename(archiveTemp, finalPath)
      } else {
        await rename(extractTemp, finalPath)
      }
      // Re-verify the atomically placed cache file before reporting it usable.
      const installed = await verifyCacheEntry(finalPath, asset)
      if (installed === null) {
        throw new TunnelError('CHECKSUM_MISMATCH', 'the cached cloudflared binary failed re-verification')
      }
      resolveMemo = null
      digestMemo.delete(finalPath)
      log.info('cloudflared installed into the verified cache', { version: release.version, platform: String(platform), arch })
      return await info()
    } finally {
      await rm(archiveTemp, { force: true }).catch(() => undefined)
      await rm(extractTemp, { force: true }).catch(() => undefined)
    }
  }

  const info = async (candidates?: readonly string[]): Promise<CloudflaredDownloadInfo> => {
    const resolved = await resolve(candidates)
    const asset = resolved.asset
    return {
      version: release.version,
      asset: asset?.asset ?? '',
      sizeBytes: asset?.sizeBytes ?? 0,
      sha256: asset?.sha256 ?? '',
      releaseUrl: asset === null ? '' : pinnedDownloadUrl(asset, release),
      cacheDirectory: cacheDir,
      installed: resolved.installed,
      supported: resolved.supported,
    }
  }

  return { resolve, info, install }
}

/** Read a bounded artifact into memory (the pinned archives are < 22 MiB). */
async function readFileBuffer(path: string, maxBytes: number): Promise<Buffer> {
  const info = await stat(path)
  if (info.size > maxBytes) throw new TunnelError('BAD_REQUEST', 'downloaded archive is larger than expected')
  const handle = await open(path, 'r')
  try {
    const buffer = Buffer.alloc(info.size)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead <= 0) break
      offset += bytesRead
    }
    return buffer.subarray(0, offset)
  } finally {
    await handle.close().catch(() => undefined)
  }
}

/* ------------------------------------------------------------------------- */
/* Legacy cache discovery (kept for backward compatibility)                  */
/* ------------------------------------------------------------------------- */

/**
 * Return the newest already-present cloudflared binary in the managed cache
 * directory, or `null`. This helper never verifies anything; the tunnel manager
 * uses the verified resolver above. Kept for compatibility with older layouts.
 */
export async function findCachedCloudflared(directory: string): Promise<string | null> {
  try {
    const entries = await readdir(directory, { withFileTypes: true })
    const candidates: { path: string; mtimeMs: number }[] = []
    for (const entry of entries) {
      if (!entry.isFile() || !entry.name.startsWith('cloudflared-')) continue
      const candidate = join(directory, entry.name)
      try {
        const info = await stat(candidate)
        candidates.push({ path: candidate, mtimeMs: info.mtimeMs })
      } catch {
        // A racing removal simply drops the candidate.
      }
    }
    candidates.sort((left, right) => right.mtimeMs - left.mtimeMs)
    return candidates[0]?.path ?? null
  } catch {
    return null
  }
}
