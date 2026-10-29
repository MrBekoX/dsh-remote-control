/**
 * Bounded public-origin probes.
 *
 * Connector readiness ("Registered tunnel connection") says nothing about
 * whether the public route actually reaches this plugin listener. The manager
 * therefore reports HTTP and WebSocket verification separately and never shows
 * `ready` without both probes succeeding:
 * - HTTP: `GET <origin>/rc/api/health` must return the plugin health JSON
 *   (`ok: true`); a redirect to Cloudflare Access is reported as
 *   `access-required`; any other answer is a `mismatch` signal.
 * - WS: a WSS handshake to `<origin>/rc/ws` must reach the plugin listener. An
 *   unauthenticated handshake is expected to be rejected by the plugin with an
 *   HTTP 400/401/403/426 answer, which still proves the route exists; 3xx to
 *   Cloudflare Access maps to `access-required`.
 */
import { WebSocket as NodeWebSocket } from 'ws';
import { RC_API_PATH, RC_WS_PATH } from './shared/protocol.js';
const DEFAULT_TIMEOUT_MS = 5_000;
const ACCESS_HINT = /cloudflareaccess\.com|cdn-cgi\/access/i;
const ROUTE_REACHABLE_WS_STATUSES = new Set([101, 400, 401, 403, 426]);
function originOf(origin) {
    return origin.replace(/\/+$/, '');
}
function wsUrlFor(origin) {
    const url = new URL(originOf(origin));
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    url.pathname = RC_WS_PATH;
    url.search = '';
    url.hash = '';
    return url.origin.replace(/^http/, 'ws') + RC_WS_PATH;
}
function networkFailure(error) {
    const name = error instanceof Error ? error.name : 'Error';
    return { ok: false, status: null, accessRequired: false, detail: `network error (${name})` };
}
/** Real public-origin probe. Unit tests inject a fake `TunnelProbe` into the manager. */
export function createTunnelProbe(deps = {}) {
    const fetchImpl = deps.fetch ?? fetch;
    const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const webSocketFactory = deps.webSocketFactory ??
        ((url, options) => new NodeWebSocket(url, {
            handshakeTimeout: options.handshakeTimeout,
            followRedirects: options.followRedirects,
            headers: { 'user-agent': 'dsh-remote-control-readiness' },
        }));
    const http = async (origin, overrideTimeoutMs) => {
        const budget = overrideTimeoutMs ?? timeoutMs;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), budget);
        timer.unref();
        try {
            const response = await fetchImpl(`${originOf(origin)}${RC_API_PATH}/health`, {
                method: 'GET',
                redirect: 'manual',
                cache: 'no-store',
                signal: controller.signal,
                headers: { accept: 'application/json' },
            });
            const location = response.headers.get('location') ?? '';
            if (response.status >= 300 && response.status < 400) {
                if (ACCESS_HINT.test(location)) {
                    return { ok: false, status: response.status, accessRequired: true, detail: 'Access login redirect' };
                }
                return { ok: false, status: response.status, accessRequired: false, detail: 'unexpected redirect' };
            }
            if (response.status !== 200) {
                return { ok: false, status: response.status, accessRequired: false, detail: `HTTP ${response.status}` };
            }
            const text = await response.text();
            let body;
            try {
                body = JSON.parse(text);
            }
            catch {
                return { ok: false, status: 200, accessRequired: false, detail: 'health response is not JSON' };
            }
            const ok = typeof body === 'object' && body !== null && body.ok === true;
            return ok
                ? { ok: true, status: 200, accessRequired: false, detail: null }
                : { ok: false, status: 200, accessRequired: false, detail: 'health response is not from this plugin' };
        }
        catch (error) {
            return networkFailure(error);
        }
        finally {
            clearTimeout(timer);
        }
    };
    const ws = (origin, overrideTimeoutMs) => {
        const budget = overrideTimeoutMs ?? timeoutMs;
        return new Promise((resolve) => {
            let settled = false;
            const finish = (result) => {
                if (settled)
                    return;
                settled = true;
                clearTimeout(timer);
                try {
                    socket?.terminate?.();
                }
                catch {
                    // Already closed.
                }
                resolve(result);
            };
            let socket = null;
            const timer = setTimeout(() => finish({ ok: false, status: null, accessRequired: false, detail: 'timeout' }), budget);
            timer.unref();
            try {
                socket = webSocketFactory(wsUrlFor(origin), { handshakeTimeout: budget, followRedirects: false });
            }
            catch (error) {
                finish(networkFailure(error));
                return;
            }
            socket.on('open', () => finish({ ok: true, status: 101, accessRequired: false, detail: null }));
            socket.on('unexpected-response', (_request, response) => {
                const status = typeof response.statusCode === 'number'
                    ? (response.statusCode)
                    : null;
                const headers = response.headers ?? {};
                const rawLocation = headers['location'] ?? headers['Location'];
                const location = Array.isArray(rawLocation) ? rawLocation.join(',') : typeof rawLocation === 'string' ? rawLocation : '';
                if (status !== null && status >= 300 && status < 400 && ACCESS_HINT.test(location)) {
                    finish({ ok: false, status, accessRequired: true, detail: 'Access login redirect' });
                    return;
                }
                if (status !== null && ROUTE_REACHABLE_WS_STATUSES.has(status)) {
                    finish({ ok: true, status, accessRequired: false, detail: null });
                    return;
                }
                finish({ ok: false, status, accessRequired: false, detail: status === null ? 'no HTTP response' : `HTTP ${status}` });
            });
            socket.on('error', (error) => {
                // An unexpected-response rejection may surface as an error as well; the
                // first settled result wins.
                finish(networkFailure(error));
            });
        });
    };
    return { http, ws };
}
/** Test seam helper: a provider-free fake probe factory. */
export function staticProbe(http, ws) {
    return {
        http: async () => ({ ...http }),
        ws: async () => ({ ...ws }),
    };
}
