/**
 * Tunnel-lane error type.
 *
 * The controller maps any thrown error with a known `RcErrorCode` to the
 * canonical HTTP error envelope (`respondError` in controller.ts), so provider
 * failures stay machine-readable without a second error enum.
 */
export class TunnelError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'TunnelError';
        this.code = code;
    }
}
export function isTunnelError(value) {
    return value instanceof TunnelError;
}
export function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
/** Wrap an unknown error in a TunnelError while preserving the message. */
export function asTunnelError(error, code = 'INTERNAL') {
    if (isTunnelError(error))
        return error;
    return new TunnelError(code, errorMessage(error));
}
