// Endpoint Study - Domain-Only Logger (background service worker)
// =================================================================
// PRIVACY DESIGN: this script deliberately extracts and transmits ONLY the
// registrable domain and scheme of top-level navigations. It never reads or
// sends the path, query string, fragment, page title, cookies, tokens, or any
// page content. It only talks to 127.0.0.1 (the local collector).

const COLLECTOR_ENDPOINT = "http://127.0.0.1:5000/web_visited";

// De-dupe: avoid spamming the collector with the same domain repeatedly within
// a short window (e.g. SPA route changes that fire many navigations).
const recentlySent = new Map();  // domain -> timestamp(ms)
const DEDUP_WINDOW_MS = 15000;

chrome.webNavigation.onCompleted.addListener((details) => {
  // frameId 0 = top-level document only. Ignore sub-frames (ads, iframes,
  // trackers) so we log the page the user navigated to, not everything it loads.
  if (details.frameId !== 0) return;

  let url;
  try {
    url = new URL(details.url);
  } catch (e) {
    return;
  }

  // Only http/https. Skip chrome://, edge://, about:, file://, extensions, etc.
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (scheme !== "http" && scheme !== "https") return;

  // Domain only. No path, no query, no fragment leave this function.
  const domain = url.hostname.toLowerCase();
  if (!domain) return;

  const now = Date.now();
  const last = recentlySent.get(domain);
  if (last && (now - last) < DEDUP_WINDOW_MS) return;
  recentlySent.set(domain, now);

  // Send strictly {domain, scheme}. Nothing else.
  fetch(COLLECTOR_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: domain, scheme: scheme })
  }).catch(() => {
    // Collector not running / not listening: fail silently. The extension
    // must never interfere with normal browsing.
  });
});
