/**
 * LAN interface discovery and address classification.
 *
 * The desktop panel may expose the phone listener on the LAN, but only after an
 * explicit address selection by the user. This module never guesses "the right"
 * address: it lists concrete non-loopback interfaces with a conservative scope
 * classification and marks only plausible phone-reachable addresses as
 * recommended.
 *
 * Rules (main §2C / §3):
 * - RFC1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`) is a private LAN address;
 * - Tailscale uses `100.64.0.0/10`; other `100.*` addresses are NOT Tailscale
 *   and are never recommended;
 * - `169.254/16` (and IPv6 `fe80::/10`) link-local addresses are excluded from
 *   recommendations (they cannot be relied on for a phone to reach the host);
 * - everything else keeps its concrete address visible (explicit selection is
 *   still possible) but is not recommended;
 * - the first interface found is never assumed correct.
 */

import { networkInterfaces } from 'node:os'
import { isIP } from 'node:net'

import type { LanInterfaceView } from './shared/protocol.js'

export type InterfaceScope = LanInterfaceView['scope']

function ipv4Octets(address: string): number[] | null {
  const parts = address.split('.')
  if (parts.length !== 4) return null
  const octets = parts.map((part) => Number.parseInt(part, 10))
  if (octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return null
  return octets
}

/** `127.0.0.0/8` and the IPv6 loopback literals. */
export function isLoopbackAddress(address: string): boolean {
  const trimmed = address.trim()
  if (trimmed === '::1' || trimmed === '0:0:0:0:0:0:0:1') return true
  return trimmed.startsWith('127.')
}

/** RFC1918 private IPv4 (`10/8`, `172.16/12`, `192.168/16`). */
export function isRfc1918Address(address: string): boolean {
  const octets = ipv4Octets(address)
  if (octets === null) return false
  const [a = 0, b = 0] = octets
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  return false
}

/**
 * Tailscale's carrier-grade NAT range `100.64.0.0/10`. A bare `100.*` address is
 * not Tailscale; only the second octet 64..127 is inside the shared range.
 */
export function isTailscaleAddress(address: string): boolean {
  const octets = ipv4Octets(address)
  if (octets === null) return false
  const [a = 0, b = 0] = octets
  return a === 100 && b >= 64 && b <= 127
}

/** `169.254.0.0/16` and IPv6 `fe80::/10`. */
export function isLinkLocalAddress(address: string): boolean {
  const trimmed = address.trim().toLowerCase()
  if (trimmed.startsWith('169.254.')) return true
  const first = trimmed.split(':')[0] ?? ''
  if (/^fe[89ab]$/.test(first)) return true
  // Parse the full fe80::/10 prefix when the compressed form is not the first group.
  if (first === '' && trimmed.startsWith('::')) return false
  const parsed = trimmed.split(':')
  const group = Number.parseInt(parsed[0] ?? '', 16)
  return Number.isInteger(group) && group >= 0xfe80 && group <= 0xfebf
}

/** Classify one concrete address (IPv4 or IPv6 literal). */
export function classifyInterfaceAddress(address: string): InterfaceScope {
  const family = isIP(address)
  if (family === 4) {
    if (isLinkLocalAddress(address)) return 'link-local'
    if (isTailscaleAddress(address)) return 'tailscale'
    if (isRfc1918Address(address)) return 'private'
    return 'other'
  }
  if (family === 6) {
    if (isLinkLocalAddress(address)) return 'link-local'
    return 'other'
  }
  return 'other'
}

/** Recommended = a phone on the same private/Tailscale network can plausibly reach it. */
export function isRecommendedScope(scope: InterfaceScope): boolean {
  return scope === 'private' || scope === 'tailscale'
}

export interface NetworkInterfaceEntry {
  name: string
  address: string
  family: 'IPv4' | 'IPv6'
  internal: boolean
}

/**
 * Build the panel-facing candidate list from raw OS interface data.
 *
 * Only concrete non-loopback, non-link-local IPv4 addresses are recommended;
 * other concrete addresses stay visible for explicit selection. Ordering is
 * deterministic (recommended first, then name/address).
 */
export function listLanInterfaces(
  interfaces: NodeJS.Dict<NetworkInterfaceEntry[]> = collectRawInterfaces(),
): LanInterfaceView[] {
  const seen = new Set<string>()
  const views: LanInterfaceView[] = []
  for (const [name, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' && entry.family !== 'IPv6') continue
      const address = entry.address.split('%')[0]?.trim() ?? ''
      if (address === '' || seen.has(address)) continue
      const family = isIP(address)
      if (family === 0) continue
      seen.add(address)
      const scope = classifyInterfaceAddress(address)
      const recommended =
        entry.internal !== true && family === 4 && isRecommendedScope(scope) && !isLoopbackAddress(address)
      const interfaceName = name.split(':').slice(1).join(':') || name
      views.push({
        name: interfaceName,
        address,
        family: family === 4 ? 'IPv4' : 'IPv6',
        scope,
        recommended,
      })
    }
  }
  views.sort((left, right) => {
    if (left.recommended !== right.recommended) return left.recommended ? -1 : 1
    if (left.name !== right.name) return left.name.localeCompare(right.name)
    return left.address.localeCompare(right.address)
  })
  return views
}

/** OS adapter name pre-suffixed with its address family, e.g. `Wi-Fi:IPv4`. */
function collectRawInterfaces(): NodeJS.Dict<NetworkInterfaceEntry[]> {
  const raw = networkInterfaces()
  const normalized: NodeJS.Dict<NetworkInterfaceEntry[]> = {}
  for (const [name, entries] of Object.entries(raw)) {
    const result: NetworkInterfaceEntry[] = []
    for (const entry of entries ?? []) {
      const familyCode = isIP(entry.address.split('%')[0] ?? '')
      if (familyCode === 0) continue
      result.push({
        name,
        address: entry.address,
        family: familyCode === 4 ? 'IPv4' : 'IPv6',
        internal: entry.internal,
      })
    }
    normalized[`${name}:${name}`] = result
  }
  return normalized
}

/** Bracket an IPv6 literal for use in a URL authority (`[::1]:8080`). */
export function formatHostForAuthority(host: string): string {
  const trimmed = host.trim()
  if (trimmed.startsWith('[')) return trimmed
  return trimmed.includes(':') ? `[${trimmed}]` : trimmed
}

/** True for `localhost` and loopback literals (wildcards are never loopback-safe). */
export function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[|\]$/g, '')
  return normalized === 'localhost' || isLoopbackAddress(normalized)
}

/** Wildcard bind literals that must stay forbidden. */
export function isWildcardHost(host: string): boolean {
  const normalized = host.trim().toLowerCase().replace(/^\[|\]$/g, '')
  return normalized === '0.0.0.0' || normalized === '::' || normalized === '::0' || normalized === '*'
}
