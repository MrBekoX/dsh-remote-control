/**
 * Plugin version marker.
 *
 * Kept in a separate module so the Host bundle can report its version without
 * importing `package.json` (which would need a bundler or JSON module support).
 * `scripts/pack-check.mjs` asserts that this constant matches package.json.
 */
export const PLUGIN_VERSION = '0.2.0'
