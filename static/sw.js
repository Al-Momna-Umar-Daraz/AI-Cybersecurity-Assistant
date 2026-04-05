const CACHE_NAME = 'cybershield-static-v9';
const OFFLINE_URL = '/static/offline.html';
const ASSETS = [
  '/static/style.css',
  '/static/script.js',
  '/manifest.webmanifest',
  '/static/offline.html',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => (k !== CACHE_NAME ? caches.delete(k) : null)))).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  const isStatic = url.pathname.startsWith('/static/') || url.pathname === '/manifest.webmanifest';

  if (isStatic) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match(OFFLINE_URL)));
  }
});
