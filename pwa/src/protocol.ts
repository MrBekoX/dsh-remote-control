/**
 * PWA view of the shared wire contract.
 *
 * The single source of truth lives in `src/shared/protocol.ts` (Host + PWA +
 * client plugin). This module only re-exports it so the PWA source can use a
 * local specifier and esbuild can bundle the constants into `dist/pwa/app.js`.
 */

export * from '../../src/shared/protocol.js'
