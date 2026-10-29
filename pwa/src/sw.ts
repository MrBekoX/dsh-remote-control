/**
 * DSH Remote Control PWA â€” offline shell service worker.
 *
 * Scope: same-origin `GET /rc/*` **static shell assets only**. The pairing API
 * (`/rc/api/*`) and the WebSocket (`/rc/ws`) are never cached, and non-GET
 * requests are never intercepted. A cache-first shell keeps the app bootable
 * when the phone briefly loses connectivity, without ever serving stale REST or
 * realtime data.
 *
 * Registered by `app.ts` only in a secure context (HTTPS or localhost origin).
 */

const CACHE_NAME = 'dsh-remote-control-shell-v3'
const SHELL_ASSETS: readonly string[] = [
  '/rc/',
  '/rc/index.html',
  '/rc/app.js',
  '/rc/app.css',
  '/rc/manifest.webmanifest',
  '/rc/dsh-icon.png',
  '/rc/dsh-icon-192.png',
]
const STATIC_EXTENSIONS: readonly string[] = [
  '.js',
  '.css',
  '.webmanifest',
  '.json',
  '.svg',
  '.png',
  '.ico',
  '.webp',
  '.woff2',
]
const API_PREFIX = '/rc/api/'
const WS_PATH = '/rc/ws'
const SHELL_ENTRY = '/rc/'

/** Minimal shape of the worker global scope (avoids lib.dom/lib.webworker drift). */
interface ServiceWorkerScope {
  addEventListener(type: 'install', listener: (event: ExtendableEvent) => void): void
  addEventListener(type: 'activate', listener: (event: ExtendableEvent) => void): void
  addEventListener(type: 'fetch', listener: (event: FetchEvent) => void): void
  skipWaiting(): Promise<void>
  clients: { claim(): Promise<void> }
  location: { origin: string }
}

const worker = self as unknown as ServiceWorkerScope

worker.addEventListener('install', (event: ExtendableEvent) => {
  event.waitUntil(
    (async (): Promise<void> => {
      const cache = await caches.open(CACHE_NAME)
      await Promise.all(
        SHELL_ASSETS.map(async (asset) => {
          try {
            await cache.add(asset)
          } catch {
            // A single missing asset must not abort the whole install.
          }
        }),
      )
      await worker.skipWaiting()
    })(),
  )
})

worker.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(
    (async (): Promise<void> => {
      const keys = await caches.keys()
      await Promise.all(
        keys.map(async (key) => {
          if (key !== CACHE_NAME) await caches.delete(key)
        }),
      )
      await worker.clients.claim()
    })(),
  )
})

function isStaticShellAsset(pathname: string): boolean {
  for (const extension of STATIC_EXTENSIONS) {
    if (pathname.endsWith(extension)) return true
  }
  return false
}

async function cacheFirst(request: Request): Promise<Response> {
  const cache = await caches.open(CACHE_NAME)
  const cached = await cache.match(request, { ignoreSearch: true })
  if (cached !== undefined) return cached
  const response = await fetch(request)
  if (response.ok && response.type === 'basic') {
    await cache.put(request, response.clone())
  }
  return response
}

async function navigationResponse(fallbackPath: string, request: Request): Promise<Response> {
  const cache = await caches.open(CACHE_NAME)
  const cached = await cache.match(fallbackPath, { ignoreSearch: true })
  if (cached !== undefined) return cached
  return fetch(request)
}

worker.addEventListener('fetch', (event: FetchEvent) => {
  const request = event.request
  if (request.method !== 'GET') return
  let url: URL
  try {
    url = new URL(request.url)
  } catch {
    return
  }
  if (url.origin !== worker.location.origin) return
  if (!url.pathname.startsWith('/rc/')) return
  // Realtime and API responses must never be served from (or written to) the cache.
  if (url.pathname === WS_PATH || url.pathname.startsWith(API_PREFIX)) return
  if (request.mode === 'navigate') {
    event.respondWith(navigationResponse(SHELL_ENTRY, request))
    return
  }
  if (!isStaticShellAsset(url.pathname)) return
  event.respondWith(cacheFirst(request))
})
