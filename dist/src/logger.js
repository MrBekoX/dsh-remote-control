/**
 * Logger facade.
 *
 * Wraps the host logger (or console in tests) and enforces a level. Never pass
 * tokens, pairing codes, cookies, prompt text or tool arguments to it.
 */
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const PREFIX = '[remote-control]';
function safeStringify(detail) {
    if (detail === undefined)
        return '';
    if (detail instanceof Error)
        return `: ${detail.name}: ${detail.message}`;
    try {
        return `: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`;
    }
    catch {
        return ': <unserializable>';
    }
}
export function createLogger(base, level) {
    const threshold = LEVELS[level];
    const emit = (scope, message, detail) => {
        if (LEVELS[scope] > threshold)
            return;
        const line = `${PREFIX} ${message}${safeStringify(detail)}`;
        try {
            if (base !== undefined) {
                if (scope === 'error')
                    base.error(line);
                else if (scope === 'warn')
                    base.warn(line);
                else if (scope === 'info')
                    base.info(line);
                else
                    base.debug(line);
            }
            else {
                // eslint-disable-next-line no-console
                const sink = scope === 'error' ? console.error : scope === 'warn' ? console.warn : console.log;
                sink(line);
            }
        }
        catch {
            // Logging must never break the plugin.
        }
    };
    return {
        error: (message, detail) => emit('error', message, detail),
        warn: (message, detail) => emit('warn', message, detail),
        info: (message, detail) => emit('info', message, detail),
        debug: (message, detail) => emit('debug', message, detail),
    };
}
