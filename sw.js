/**
 * Wormhole service worker — notifications only (no caching, no offline mode).
 *
 * Why it exists: Android Chrome does not let a page call `new Notification()`;
 * notifications must be shown through a service worker registration. The page
 * calls registration.showNotification(); this worker handles the tap.
 */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

// Tapping a notification: focus the app (or open it) and jump to that chat.
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const peer = event.notification.data && event.notification.data.peer;
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) {
      if ('focus' in w) {
        await w.focus();
        if (peer) w.postMessage({ type: 'open-chat', peer });
        return;
      }
    }
    await self.clients.openWindow(peer ? '/#chat=' + peer : '/');
  })());
});
