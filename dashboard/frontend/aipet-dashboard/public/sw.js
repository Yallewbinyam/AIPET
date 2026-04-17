// AIPET X Service Worker v4.0.0
// Provides offline support, caching, and push notifications

const CACHE_NAME = 'aipet-x-v4.0.0';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/static/js/main.chunk.js',
  '/static/js/0.chunk.js',
  '/static/js/bundle.js',
  '/manifest.json',
];

// ── Install ────────────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      console.log('[AIPET SW] Caching static assets');
      return cache.addAll(STATIC_ASSETS).catch(err => {
        console.log('[AIPET SW] Cache error (non-fatal):', err);
      });
    })
  );
  self.skipWaiting();
});

// ── Activate ───────────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(key => key !== CACHE_NAME)
            .map(key => caches.delete(key))
      )
    )
  );
  self.clients.claim();
  console.log('[AIPET SW] Active — v4.0.0');
});

// ── Fetch — Network first, cache fallback ─────────────────
self.addEventListener('fetch', event => {
  // Skip non-GET and API calls
  if (event.request.method !== 'GET') return;
  if (event.request.url.includes('/api/')) return;
  if (event.request.url.includes('localhost:5001')) return;

  event.respondWith(
    fetch(event.request)
      .then(response => {
        // Cache successful responses
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => {
            cache.put(event.request, clone);
          });
        }
        return response;
      })
      .catch(() => {
        // Network failed — serve from cache
        return caches.match(event.request).then(cached => {
          if (cached) return cached;
          // Fallback for navigation requests
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html');
          }
        });
      })
  );
});

// ── Push Notifications ────────────────────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;

  let data;
  try {
    data = event.data.json();
  } catch {
    data = {
      title: 'AIPET X Alert',
      body: event.data.text(),
      icon: '/icons/icon-192.png',
    };
  }

  const options = {
    body: data.body || 'New security alert detected',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-72.png',
    tag: data.tag || 'aipet-alert',
    renotify: true,
    requireInteraction: data.critical || false,
    vibrate: data.critical ? [200, 100, 200] : [100],
    data: {
      url: data.url || '/',
      timestamp: Date.now(),
    },
    actions: [
      { action: 'view',    title: '🔍 View',    icon: '/icons/icon-72.png' },
      { action: 'dismiss', title: '✕ Dismiss',  icon: '/icons/icon-72.png' },
    ],
  };

  event.waitUntil(
    self.registration.showNotification(
      data.title || 'AIPET X Security Alert',
      options
    )
  );
});

// ── Notification click ────────────────────────────────────
self.addEventListener('notificationclick', event => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const url = event.notification.data?.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(windowClients => {
        // Focus existing window if open
        for (const client of windowClients) {
          if (client.url.includes(self.location.origin)) {
            client.focus();
            client.navigate(url);
            return;
          }
        }
        // Open new window
        return clients.openWindow(url);
      })
  );
});

// ── Background sync ───────────────────────────────────────
self.addEventListener('sync', event => {
  if (event.tag === 'aipet-sync') {
    console.log('[AIPET SW] Background sync triggered');
  }
});
