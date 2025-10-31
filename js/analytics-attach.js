// js/analytics-attach.js
// Loads GA4 only AFTER consent, tracks 'file_download', and shows a private
// debug-only badge (tag · count · timestamp) when ?debug=1 is present.

// === GA4 Measurement ID ===
const GA_MEASUREMENT_ID = 'G-0YTLKPFY3R';

// Only send analytics on these hostnames (or when ?debug=1)
const GA_ALLOWED_HOSTS = ['www.custoseye.com', 'custoseye.com'];

// Optional GitHub release debug badge (hidden unless ?debug=1)
const GH_OWNER = 'mardini2';
const GH_REPO = 'CustosEye';
const GH_TAG_OR_LATEST = 'latest';          // 'latest' or a specific tag like 'v0.2.0'
const GH_ASSET_FILENAME = 'CustosEye.zip';  // exact asset filename

function loadScript(src, async = true) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.async = async;
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

function shouldAttachGA() {
  const params = new URLSearchParams(location.search);
  const debugParam = params.get('debug') === '1';
  const allowedHost = GA_ALLOWED_HOSTS.includes(location.hostname);
  return allowedHost || debugParam;
}

async function attachAnalytics() {
  if (!shouldAttachGA()) {
    console.info('[analytics] Skipping GA (host not whitelisted and no ?debug=1).');
    return;
  }
  if (!GA_MEASUREMENT_ID || GA_MEASUREMENT_ID.startsWith('G-XXXX')) {
    console.warn('[analytics] GA_MEASUREMENT_ID not set.');
    return;
  }

  try {
    await loadScript(`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`);

    window.dataLayer = window.dataLayer || [];
    function gtag(){ dataLayer.push(arguments); }
    window.gtag = gtag;

    const debugMode = new URLSearchParams(location.search).get('debug') === '1';

    gtag('js', new Date());
    gtag('config', GA_MEASUREMENT_ID, { anonymize_ip: true, debug_mode: debugMode });

    console.info('[analytics] GA4 attached (debug_mode:', debugMode, ')');

    // Recommended GA4 event for file downloads
    const dl = document.getElementById('download-btn');
    if (dl) {
      dl.addEventListener('click', () => {
        gtag('event', 'file_download', {
          file_name: 'CustosEye.zip',
          link_url: dl.href,
          event_category: 'engagement',
          event_label: window.location.pathname,
          value: 1
        });
      });
    }
  } catch (err) {
    console.error('[analytics] Failed to attach GA', err);
  }
}

window.addEventListener('analytics:consent-granted', attachAnalytics);
document.addEventListener('DOMContentLoaded', () => {
  try {
    if (localStorage.getItem('analytics_consent') === 'granted') attachAnalytics();
  } catch {}
});

// ---- Private debug badge (only if ?debug=1) ----
async function showReleaseDownloadCount() {
  const params = new URLSearchParams(location.search);
  const debugMode = params.get('debug') === '1';
  if (!debugMode) return; // invisible to the public

  try {
    const url = (GH_TAG_OR_LATEST === 'latest')
      ? `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/releases/latest`
      : `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${encodeURIComponent(GH_TAG_OR_LATEST)}`;

    const res = await fetch(url, { headers: { 'Accept': 'application/vnd.github+json' } });
    if (!res.ok) throw new Error(`GitHub API ${res.status}`);
    const data = await res.json();

    // Find asset and figure out the tag label
    const asset = (data.assets || []).find(a => a.name === GH_ASSET_FILENAME);
    const tag = data.tag_name || (data.name || GH_TAG_OR_LATEST);

    if (asset && typeof asset.download_count === 'number') {
      // Build the “tag · count · checked time” string
      const now = new Date();
      const timeStr = now.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
      const info = document.createElement('div');
      info.className = 'debug-download-count';
      info.style.cssText = `
        margin: 12px 24px 0;
        color: #a1f1b0;
        font-family: monospace;
        font-size: 0.9rem;
        opacity: 0.85;
      `;
      info.textContent = `${tag} · ${asset.download_count.toLocaleString()} downloads · checked ${timeStr}`;
      (document.querySelector('footer') || document.body).appendChild(info);
    }
  } catch (err) {
    console.warn('[downloads] Could not load release stats:', err);
  }
}
document.addEventListener('DOMContentLoaded', showReleaseDownloadCount);