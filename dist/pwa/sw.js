(() => {
  // pwa/src/sw.ts
  var CACHE_NAME = "dsh-remote-control-shell-v3";
  var SHELL_ASSETS = [
    "/rc/",
    "/rc/index.html",
    "/rc/app.js",
    "/rc/app.css",
    "/rc/manifest.webmanifest",
    "/rc/dsh-icon.png",
    "/rc/dsh-icon-192.png"
  ];
  var STATIC_EXTENSIONS = [
    ".js",
    ".css",
    ".webmanifest",
    ".json",
    ".svg",
    ".png",
    ".ico",
    ".webp",
    ".woff2"
  ];
  var API_PREFIX = "/rc/api/";
  var WS_PATH = "/rc/ws";
  var SHELL_ENTRY = "/rc/";
  var worker = self;
  worker.addEventListener("install", (event) => {
    event.waitUntil(
      (async () => {
        const cache = await caches.open(CACHE_NAME);
        await Promise.all(
          SHELL_ASSETS.map(async (asset) => {
            try {
              await cache.add(asset);
            } catch {
            }
          })
        );
        await worker.skipWaiting();
      })()
    );
  });
  worker.addEventListener("activate", (event) => {
    event.waitUntil(
      (async () => {
        const keys = await caches.keys();
        await Promise.all(
          keys.map(async (key) => {
            if (key !== CACHE_NAME) await caches.delete(key);
          })
        );
        await worker.clients.claim();
      })()
    );
  });
  function isStaticShellAsset(pathname) {
    for (const extension of STATIC_EXTENSIONS) {
      if (pathname.endsWith(extension)) return true;
    }
    return false;
  }
  async function cacheFirst(request) {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(request, { ignoreSearch: true });
    if (cached !== void 0) return cached;
    const response = await fetch(request);
    if (response.ok && response.type === "basic") {
      await cache.put(request, response.clone());
    }
    return response;
  }
  async function navigationResponse(fallbackPath, request) {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(fallbackPath, { ignoreSearch: true });
    if (cached !== void 0) return cached;
    return fetch(request);
  }
  worker.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET") return;
    let url;
    try {
      url = new URL(request.url);
    } catch {
      return;
    }
    if (url.origin !== worker.location.origin) return;
    if (!url.pathname.startsWith("/rc/")) return;
    if (url.pathname === WS_PATH || url.pathname.startsWith(API_PREFIX)) return;
    if (request.mode === "navigate") {
      event.respondWith(navigationResponse(SHELL_ENTRY, request));
      return;
    }
    if (!isStaticShellAsset(url.pathname)) return;
    event.respondWith(cacheFirst(request));
  });
})();
