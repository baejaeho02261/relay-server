'use strict';

const CACHE = 'relay-admin-shell-v5.0.1-game-overlay-96';
const SHELL = [
  "/index.html",
  "/manifest.json",
  "/icons/icon-192.png",
  "/admin.css?v=5.0.1-game-overlay-96",
  "/admin-theme.css?v=5.0.1-game-overlay-96",
  "/admin-navigation.css?v=5.0.1-game-overlay-96",
  "/admin-appearance.css?v=5.0.1-game-overlay-96",
  "/admin-controls.css?v=5.0.1-game-overlay-96",
  "/admin-workspace.css?v=5.0.1-game-overlay-96",
  "/admin-desktop.css?v=5.0.1-game-overlay-96",
  "/admin-controls.js?v=5.0.1-game-overlay-96",
  "/admin-appearance.js?v=5.0.1-game-overlay-96",
  "/icons/game.svg",
  "/admin-i18n.js?v=5.0.1-game-overlay-96",
  "/admin.js?v=5.0.1-game-overlay-96",
  "/admin-navigation.js?v=5.0.1-game-overlay-96",
  "/admin-pages-monitoring.js?v=5.0.1-game-overlay-96",
  "/admin-terminal.js?v=5.0.1-game-overlay-96",
  "/admin-pages-traffic.js?v=5.0.1-game-overlay-96",
  "/admin-pages-danger.js?v=5.0.1-game-overlay-96",
  "/admin-pages-access.js?v=5.0.1-game-overlay-96",
  "/admin-pages-reports.js?v=5.0.1-game-overlay-96",
  "/admin-pages-devices.js?v=5.0.1-game-overlay-96",
  "/admin-pages-deployment.js?v=5.0.1-game-overlay-96",
  "/admin-pages-security.js?v=5.0.1-game-overlay-96",
  "/admin-pages-operations.js?v=5.0.1-game-overlay-96",
  "/admin-actions-access.js?v=5.0.1-game-overlay-96",
  "/admin-actions-operations.js?v=5.0.1-game-overlay-96",
  "/admin-actions-traffic.js?v=5.0.1-game-overlay-96",
  "/admin-actions-devices.js?v=5.0.1-game-overlay-96",
  "/admin-actions-policy.js?v=5.0.1-game-overlay-96",
  "/admin-actions-system.js?v=5.0.1-game-overlay-96",
  "/admin-modal.js?v=5.0.1-game-overlay-96",
  "/admin-device-actions.js?v=5.0.1-game-overlay-96",
  "/admin-desktop-licenses.js?v=5.0.1-game-overlay-96",
  "/admin-desktop-security.js?v=5.0.1-game-overlay-96",
  "/admin-desktop-workflow.js?v=5.0.1-game-overlay-96",
  "/admin-actions.js?v=5.0.1-game-overlay-96",
  "/admin-palette.js?v=5.0.1-game-overlay-96",
  "/admin-pages-production.js?v=5.0.1-game-overlay-96",
  "/icons/icon-512.png"
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL.map(url => new Request(url, { cache: 'no-store' })))).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k.startsWith('relay-admin-shell-') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  // Never cache authenticated API/SSE/health data.
  if (url.pathname.startsWith('/api/') || url.pathname === '/health' || url.pathname === '/healthz' || url.pathname === '/ui-version.json' || url.pathname === '/ui-refresh' || url.pathname === '/ui-refresh.html' || url.pathname === '/ui-refresh.js') {
    event.respondWith(fetch(new Request(request, { cache: 'no-store' })));
    return;
  }
  if (request.method !== 'GET') return;
  const navigation = request.mode === 'navigate';
  // Only the administrator entry pages may populate or use the offline shell.
  // Other navigations can contain authenticated or one-time response data.
  const adminNavigation = navigation && (url.pathname === '/' || url.pathname === '/index.html');
  if (navigation && !adminNavigation) {
    event.respondWith(fetch(new Request(request, { cache: 'no-store' })));
    return;
  }
  const cacheable = adminNavigation || SHELL.some(item => new URL(item, self.location.origin).pathname === url.pathname);
  event.respondWith(
    fetch(new Request(request, { cache: 'no-store' })).then(response => {
      if (cacheable && response.ok) {
        const copy = response.clone();
        event.waitUntil(caches.open(CACHE).then(cache => cache.put(navigation ? '/index.html' : request, copy)).catch(() => {}));
      }
      return response;
    }).catch(async () => {
      const cache = await caches.open(CACHE);
      const hit = await cache.match(navigation ? '/index.html' : request);
      // A missing JavaScript/CSS file must never be replaced with HTML.
      return hit || new Response('인터넷 연결 후 이 화면을 다시 열어주세요.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    })
  );
});

self.addEventListener('push', event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) { data = { body: event.data ? event.data.text() : '' }; }
  const severity = String(data.severity || 'INFO').toUpperCase();
  event.waitUntil(self.registration.showNotification(data.title || '중계 서버 운영 알림', {
    body: data.body || '',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-192.png',
    tag: `${data.type || 'SYSTEM'}:${data.entityId || ''}`,
    renotify: severity === 'CRITICAL',
    requireInteraction: severity === 'CRITICAL',
    data: { url: data.url || '/', type: data.type || 'SYSTEM', entityId: data.entityId || '' }
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = event.notification.data && event.notification.data.url || '/';
  event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windows => {
    for (const client of windows) {
      if ('focus' in client) {
        if ('navigate' in client) client.navigate(target);
        return client.focus();
      }
    }
    return clients.openWindow ? clients.openWindow(target) : undefined;
  }));
});
