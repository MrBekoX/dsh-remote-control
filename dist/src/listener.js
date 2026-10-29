/**
 * The plugin's own HTTP(S) listener (design D-02).
 *
 * Responsibilities (thin transport layer only):
 * - serve the built PWA from `deps.staticRoot` under `/rc/` with the CSP /
 *   nosniff / Referrer-Policy headers, safe path resolution (traversal and
 *   symlink escapes rejected, correct MIME types, no-store for the shell),
 * - delegate **every** `/rc/api/*` request to `deps.api` exactly once (auth,
 *   the Host/Origin fence, CSRF, rate limits and JSON envelopes live in the
 *   controller, not here),
 * - delegate `/rc/ws` upgrades to `deps.upgrade` (the WebSocket broker), and
 * - answer everything else with the RC error envelope / plain 404.
 *
 * Fail-closed: wildcard binds are refused, a non-loopback bind needs
 * `allowLan`, and a missing PWA build serves 503 "PWA build missing" instead of
 * a directory listing or a stack trace.
 */
import { createServer as createHttpServer } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFile, realpath, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { basename, extname, resolve, sep } from 'node:path';
import { sendError, methodNotAllowed } from './auth.js';
import { RC_API_PATH, RC_BASE_PATH, RC_WS_PATH } from './shared/protocol.js';
const PWA_MISSING = 'PWA build missing';
const MAX_STATIC_BYTES = 8 * 1024 * 1024;
/** CSP from design §9.8: no inline script/style, no framing, no external origins. */
const SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
};
const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.htm': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.webmanifest': 'application/manifest+json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.txt': 'text/plain; charset=utf-8',
    '.wasm': 'application/wasm',
};
function mimeType(filePath) {
    return MIME_TYPES[extname(filePath).toLowerCase()] ?? 'application/octet-stream';
}
function isNoStoreAsset(fileName) {
    return fileName === 'index.html' || fileName === 'sw.js' || fileName === 'manifest.webmanifest';
}
function formatHost(host) {
    return host.includes(':') ? `[${host}]` : host;
}
function isInside(root, candidate) {
    const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
    return candidate === root || candidate.startsWith(prefix);
}
function parseRequestUrl(request) {
    try {
        return new URL(request.url ?? '/', 'http://remote-control.invalid');
    }
    catch {
        return null;
    }
}
function rejectUpgrade(socket, status, reason) {
    if (socket.destroyed)
        return;
    try {
        socket.write(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    }
    catch {
        // Socket already gone.
    }
    socket.destroy();
}
function validateBind(bind) {
    const trimmedHost = typeof bind.host === 'string' ? bind.host.trim() : '';
    if (trimmedHost === '')
        throw new Error('remote-control listener host is required');
    const bare = trimmedHost.replace(/^\[/, '').replace(/\]$/, '');
    if (bare === '0.0.0.0' || bare === '::' || bare === '0:0:0:0:0:0:0:0') {
        throw new Error('wildcard bind is not allowed; set listen.host to a concrete loopback or LAN address');
    }
    const family = isIP(bare);
    if (family === 0) {
        throw new Error(`listen.host must be a concrete IPv4/IPv6 literal, got "${trimmedHost}"`);
    }
    const loopback = bare === '::1' || (family === 4 && bare.startsWith('127.'));
    if (!loopback && bind.allowLan !== true) {
        throw new Error('non-loopback listen.host requires listen.allowLan=true');
    }
    if (!Number.isInteger(bind.port) || bind.port < 0 || bind.port > 65_535) {
        throw new Error('listen.port must be an integer between 0 and 65535');
    }
    let tls = null;
    if (bind.tls !== null) {
        const certFile = typeof bind.tls.certFile === 'string' ? bind.tls.certFile.trim() : '';
        const keyFile = typeof bind.tls.keyFile === 'string' ? bind.tls.keyFile.trim() : '';
        if (certFile === '' && keyFile === '') {
            tls = null;
        }
        else if (certFile === '' || keyFile === '') {
            throw new Error('listen.tls requires both certFile and keyFile');
        }
        else {
            tls = { certFile, keyFile };
        }
    }
    return { host: bare, port: bind.port, loopback, tls };
}
async function resolveStaticRoot(candidate, log) {
    const absolute = resolve(candidate);
    try {
        const info = await stat(absolute);
        if (!info.isDirectory())
            return null;
        return await realpath(absolute);
    }
    catch {
        log.warn('PWA static root is missing; run the build before enabling remote control', {
            path: basename(absolute),
        });
        return null;
    }
}
function sendPwaMissing(response) {
    if (response.headersSent || response.destroyed)
        return;
    response.statusCode = 503;
    response.setHeader('Content-Type', 'text/plain; charset=utf-8');
    response.setHeader('Cache-Control', 'no-store');
    for (const [name, value] of Object.entries(SECURITY_HEADERS))
        response.setHeader(name, value);
    response.end(PWA_MISSING);
}
export function createListener(deps) {
    const log = deps.log;
    let server = null;
    let bound = null;
    let staticRoot = null;
    let state = 'off';
    let startPromise = null;
    const sockets = new Set();
    function origin() {
        if (state !== 'listening' || bound === null)
            return null;
        return `${bound.tls ? 'https' : 'http'}://${formatHost(bound.host)}:${bound.port}`;
    }
    function status() {
        const lan = bound?.lan ?? false;
        const secure = bound?.tls ?? false;
        return {
            state,
            host: bound?.host ?? null,
            port: bound?.port ?? null,
            url: origin(),
            secure,
            lan,
            /** Effective access strategy: only an explicitly allowing non-loopback bind is `lan`. */
            access: lan ? 'lan' : 'loopback',
            protocol: secure ? 'https' : 'http',
        };
    }
    async function serveStatic(request, response, pathname) {
        const method = request.method ?? 'GET';
        if (method !== 'GET' && method !== 'HEAD') {
            methodNotAllowed(response, ['GET', 'HEAD']);
            return;
        }
        if (staticRoot === null) {
            sendPwaMissing(response);
            return;
        }
        let decoded;
        try {
            decoded = decodeURIComponent(pathname.slice(RC_BASE_PATH.length + 1));
        }
        catch {
            sendError(response, 400, 'BAD_REQUEST', 'Malformed path');
            return;
        }
        if (decoded.includes('\0') || decoded.includes('\\')) {
            sendError(response, 400, 'BAD_REQUEST', 'Malformed path');
            return;
        }
        const segments = decoded.split('/');
        if (segments.some((segment) => segment === '..')) {
            sendError(response, 400, 'BAD_REQUEST', 'Malformed path');
            return;
        }
        const relative = decoded.replace(/^\/+/, '');
        let target = resolve(staticRoot, relative === '' ? 'index.html' : relative);
        if (!isInside(staticRoot, target)) {
            sendError(response, 400, 'BAD_REQUEST', 'Malformed path');
            return;
        }
        try {
            let info = await stat(target);
            if (info.isDirectory()) {
                target = resolve(target, 'index.html');
                if (!isInside(staticRoot, target)) {
                    sendError(response, 404, 'NOT_FOUND', 'Not found');
                    return;
                }
                info = await stat(target);
            }
            if (!info.isFile() || info.size > MAX_STATIC_BYTES) {
                sendError(response, 404, 'NOT_FOUND', 'Not found');
                return;
            }
            // Resolve symlinks and re-check containment to defeat link-escape tricks.
            const real = await realpath(target);
            if (!isInside(staticRoot, real)) {
                sendError(response, 404, 'NOT_FOUND', 'Not found');
                return;
            }
            const body = await readFile(real);
            if (response.headersSent || response.destroyed)
                return;
            const fileName = basename(real);
            response.statusCode = 200;
            response.setHeader('Content-Type', mimeType(fileName));
            response.setHeader('Content-Length', String(body.byteLength));
            response.setHeader('Cache-Control', isNoStoreAsset(fileName) ? 'no-store' : 'public, max-age=300');
            for (const [name, value] of Object.entries(SECURITY_HEADERS))
                response.setHeader(name, value);
            if (method === 'HEAD') {
                response.end();
            }
            else {
                response.end(body);
            }
        }
        catch (error) {
            const code = error.code;
            if (code === 'ENOENT' || code === 'ENOTDIR') {
                if (relative === '' || relative === 'index.html') {
                    sendPwaMissing(response);
                }
                else {
                    sendError(response, 404, 'NOT_FOUND', 'Not found');
                }
                return;
            }
            log.error('static file serving failed', { reason: code ?? 'unknown' });
            if (!response.headersSent)
                sendError(response, 500, 'INTERNAL', 'Internal error');
            else
                response.destroy();
        }
    }
    function routeRequest(request, response) {
        const url = parseRequestUrl(request);
        if (url === null) {
            sendError(response, 400, 'BAD_REQUEST', 'Malformed request URL');
            return;
        }
        const pathname = url.pathname;
        if (pathname === RC_API_PATH || pathname.startsWith(`${RC_API_PATH}/`)) {
            try {
                deps.api(request, response);
            }
            catch (error) {
                log.error('phone API handler threw synchronously', {
                    message: error instanceof Error ? error.message : String(error),
                });
                if (response.headersSent)
                    response.destroy();
                else
                    sendError(response, 500, 'INTERNAL', 'Internal error');
            }
            return;
        }
        if (pathname === RC_BASE_PATH) {
            if (response.headersSent || response.destroyed)
                return;
            response.statusCode = 308;
            response.setHeader('Location', `${RC_BASE_PATH}/`);
            response.setHeader('Cache-Control', 'no-store');
            for (const [name, value] of Object.entries(SECURITY_HEADERS))
                response.setHeader(name, value);
            response.end();
            return;
        }
        if (pathname.startsWith(`${RC_BASE_PATH}/`)) {
            if (pathname === RC_WS_PATH) {
                sendError(response, 404, 'NOT_FOUND', 'Not found');
                return;
            }
            void serveStatic(request, response, pathname).catch((error) => {
                log.error('static handler failed', {
                    message: error instanceof Error ? error.message : String(error),
                });
                if (!response.headersSent && !response.destroyed) {
                    sendError(response, 500, 'INTERNAL', 'Internal error');
                }
                else {
                    response.destroy();
                }
            });
            return;
        }
        sendError(response, 404, 'NOT_FOUND', 'Not found');
    }
    function handleRequest(request, response) {
        try {
            routeRequest(request, response);
        }
        catch (error) {
            log.error('listener request handler failed', {
                message: error instanceof Error ? error.message : String(error),
            });
            if (response.headersSent || response.destroyed)
                response.destroy();
            else
                sendError(response, 500, 'INTERNAL', 'Internal error');
        }
    }
    function handleUpgrade(request, socket, head) {
        const url = parseRequestUrl(request);
        if (url === null || url.pathname !== RC_WS_PATH) {
            rejectUpgrade(socket, 404, 'Not Found');
            return;
        }
        try {
            deps.upgrade(request, socket, head);
        }
        catch (error) {
            log.error('websocket upgrade handler failed', {
                message: error instanceof Error ? error.message : String(error),
            });
            socket.destroy();
        }
    }
    async function startInternal() {
        const bind = validateBind(deps.bind());
        let tlsOptions = null;
        if (bind.tls !== null) {
            try {
                const [cert, key] = await Promise.all([
                    readFile(bind.tls.certFile),
                    readFile(bind.tls.keyFile),
                ]);
                tlsOptions = { cert, key };
            }
            catch (error) {
                throw new Error(`remote-control listener could not read its TLS files: ${error.message}`);
            }
        }
        staticRoot = await resolveStaticRoot(deps.staticRoot, log);
        const handler = (request, response) => {
            handleRequest(request, response);
        };
        const activeServer = tlsOptions === null
            ? createHttpServer(handler)
            : createHttpsServer(tlsOptions, handler);
        activeServer.on('connection', (socket) => {
            sockets.add(socket);
            socket.once('close', () => sockets.delete(socket));
        });
        activeServer.on('upgrade', (request, socket, head) => {
            handleUpgrade(request, socket, head);
        });
        activeServer.on('clientError', (_error, socket) => {
            try {
                socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
            }
            catch {
                // Already gone.
            }
            socket.destroy();
        });
        try {
            await new Promise((resolvePromise, rejectPromise) => {
                const onError = (error) => {
                    activeServer.off('listening', onListening);
                    rejectPromise(error);
                };
                const onListening = () => {
                    activeServer.off('error', onError);
                    resolvePromise();
                };
                activeServer.once('error', onError);
                activeServer.once('listening', onListening);
                activeServer.listen({ host: bind.host, port: bind.port });
            });
        }
        catch (error) {
            try {
                activeServer.close(() => undefined);
            }
            catch {
                // Never started.
            }
            staticRoot = null;
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`remote-control listener could not bind ${bind.host}:${bind.port}: ${message}`);
        }
        const address = activeServer.address();
        const port = typeof address === 'object' && address !== null ? address.port : bind.port;
        server = activeServer;
        bound = { host: bind.host, port, tls: tlsOptions !== null, lan: !bind.loopback };
        state = 'listening';
        activeServer.on('error', (error) => {
            log.error('remote-control listener error', { message: error.message });
        });
        if (!bind.loopback && tlsOptions === null) {
            // The listener only loads TLS; the controller must refuse LAN pairing
            // until a certificate is configured. Surface it so the panel can say so.
            log.warn('remote-control listener is bound to a non-loopback address without TLS; LAN pairing must stay blocked', {
                host: bind.host,
            });
        }
        log.info('remote-control listener is listening', {
            host: bind.host,
            port,
            secure: tlsOptions !== null,
            lan: !bind.loopback,
        });
        return status();
    }
    function start() {
        if (state === 'listening')
            return Promise.resolve(status());
        if (startPromise !== null)
            return startPromise;
        startPromise = startInternal().finally(() => {
            startPromise = null;
        });
        return startPromise;
    }
    async function stop() {
        const activeServer = server;
        server = null;
        const wasListening = state === 'listening';
        state = 'off';
        bound = null;
        staticRoot = null;
        if (activeServer === null)
            return;
        await new Promise((resolvePromise) => {
            let settled = false;
            const finish = () => {
                if (settled)
                    return;
                settled = true;
                resolvePromise();
            };
            try {
                activeServer.close(() => finish());
            }
            catch {
                finish();
            }
            const closable = activeServer;
            try {
                closable.closeAllConnections?.();
            }
            catch {
                // Older Node, or already closed.
            }
            for (const socket of sockets) {
                try {
                    socket.destroy();
                }
                catch {
                    // Already gone.
                }
            }
            sockets.clear();
            const fallback = setTimeout(finish, 2_000);
            fallback.unref();
        });
        if (wasListening)
            log.info('remote-control listener stopped');
    }
    return { start, stop, status, origin };
}
