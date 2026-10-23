const SHELL_CACHE = 'zenith-secops-shell-v3';
const DATA_CACHE = 'zenith-secops-data-v3';
const SHELL_FILES = ['/', '/style.css', '/app.js', '/manifest.webmanifest', '/app-icon.svg', '/app-icon-192.png', '/app-icon-512.png', '/offline.html'];
const READ_API = new Set(['/summary', '/incidents', '/quality-issues', '/events', '/briefing', '/assistant/history']);

self.addEventListener('install', event => {
  event.waitUntil(caches.open(SHELL_CACHE).then(cache => cache.addAll(SHELL_FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys
    .filter(key => key.startsWith('zenith-secops-') && ![SHELL_CACHE, DATA_CACHE].includes(key))
    .map(key => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener('message', event => {
  if (event.data?.type === 'clear-data-cache') event.waitUntil(caches.delete(DATA_CACHE));
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).then(response => {
      if (response.ok) caches.open(SHELL_CACHE).then(cache => cache.put('/', response.clone()));
      return response;
    }).catch(async () => (await caches.match('/')) || (await caches.match('/offline.html'))));
    return;
  }

  if (READ_API.has(url.pathname) && !url.searchParams.has('include_raw')) {
    event.respondWith(fetch(request).then(response => {
      if (response.ok && request.headers.has('Authorization')) caches.open(DATA_CACHE).then(cache => cache.put(request, response.clone()));
      return response;
    }).catch(async () => (request.headers.has('Authorization') ? (await caches.match(request)) : null) || new Response(
      JSON.stringify({error:'Offline and no saved result is available for this view.'}),
      {status:503,headers:{'Content-Type':'application/json; charset=utf-8'}}
    )));
    return;
  }

  if (SHELL_FILES.includes(url.pathname)) {
    event.respondWith(caches.match(request).then(cached => cached || fetch(request)));
  }
});

