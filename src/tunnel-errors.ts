/**
 * Tunnel-lane error type.
 *
 * The controller maps any thrown error with a known `RcErrorCode` to the
 * canonical HTTP error envelope (`respondError` in controller.ts), so provider
 * failures stay machine-readable without a second error enum.
 */

import type { RcErrorCode } from './shared/protocol.js'

export class TunnelError extends Error {
  readonly code: RcErrorCode

  constructor(code: RcErrorCode, message: string) {
    super(message)
    this.name = 'TunnelError'
    this.code = code
  }
}

export function isTunnelError(value: unknown): value is TunnelError {
  return value instanceof TunnelError
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Wrap an unknown error in a TunnelError while preserving the message. */
export function asTunnelError(error: unknown, code: RcErrorCode = 'INTERNAL'): TunnelError {
  if (isTunnelError(error)) return error
  return new TunnelError(code, errorMessage(error))
}
