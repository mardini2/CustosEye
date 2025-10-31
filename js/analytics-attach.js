// js/analytics-attach.js
// loads Google Analytics 4 only AFTER cookie consent,
// tracks download clicks, and (optionally) shows a GitHub release download count.

// === GA4 Measurement ID ===
// already created a GA4 Web stream for https://www.custoseye.com in GA.
const GA_MEASUREMENT_ID = 'G-0YTLKPFY3R';

// GitHub release download badge ===
// set these to show "Total downloads: N" for a specific asset name.
const GH_OWNER = 'mardini2';
const GH_REPO = 'CustosEye';
const GH_TAG_OR_LATEST = 'latest';          // 'latest' or a specific tag like 'v0.2.0'
const GH_ASSET_FILENAME = 'CustosEye.zip';  // exact asset filename in your release

// small helper to load external scripts (like GA)
function loadScript(src, async = true) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;          // where to load from
    s.async = async;      // do not block page rendering
    s.onload = resolve;   // resolve when it finishes
    s.onerror = reject;   // reject if network error
    document.head.appendChild(s); // attach to <head>
  });
}

// attach Google Analytics ONLY after consent
async function attachAnalytics() {
  // safety check: if the ID is missing, bail (prevents broken calls)
  if (!GA_MEASUREMENT_ID || GA_MEASUREMENT_ID.startsWith('G-XXXX')) {
    console.warn('[analytics] GA_MEASUREMENT_ID not set yet.');
    return;
  }

  try {
    // load GA's library
    await loadScript(`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`);

    // set up GA's dataLayer and the gtag() helper
    window.dataLayer = window.dataLayer || [];
    function gtag(){ dataLayer.push(arguments); }
    window.gtag = gtag;

    // boot GA and (optionally) anonymize IPs
    gtag('js', new Date());
    gtag('config', GA_MEASUREMENT_ID, { anonymize_ip: true });

    console.info('[analytics] GA4 attached');

    // track the download button click as a custom event
    const dl = document.getElementById('download-btn');
    if (dl) {
      dl.addEventListener('click', () => {
        // shows up under GA -> Reports -> Engagement -> Events
        gtag('event', 'download_click', {
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

// listen for consent from consent.js and then attach GA
window.addEventListener('analytics:consent-granted', attachAnalytics);

// if user already accepted on a prior visit, attach immediately
document.addEventListener('DOMContentLoaded', () => {
  try {
    const ok = localStorage.getItem('analytics_consent') === 'granted';
    if (ok) attachAnalytics();
  } catch {
    // if localStorage is blocked, skip silently
  }
});

// show total downloads from your GitHub release ---
// reads the releases API, finds the asset matching GH_ASSET_FILENAME,
// and prints its download_count into #download-stats.
async function showReleaseDownloadCount() {
  const el = document.getElementById('download-stats');
  if (!el) return;

  // only skip if placeholders were NEVER replaced
  const placeholders =
    GH_OWNER === 'OWNER' ||
    GH_REPO === 'REPO' ||
    GH_ASSET_FILENAME === 'ASSET_FILENAME';

  if (placeholders) {
    el.textContent = ''; // not configured
    return;
  }

  try {
    // build the correct endpoint based on tag vs latest
    const url = (GH_TAG_OR_LATEST === 'latest')
      ? `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/releases/latest`
      : `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${encodeURIComponent(GH_TAG_OR_LATEST)}`;

    // call GitHub Releases API
    const res = await fetch(url, { headers: { 'Accept': 'application/vnd.github+json' }});
    if (!res.ok) throw new Error(`GitHub API ${res.status}`);
    const data = await res.json();

    // find the matching asset by file name
    const asset = (data.assets || []).find(a => a.name === GH_ASSET_FILENAME);

    // if found, show the count; otherwise, show nothing
    if (asset && typeof asset.download_count === 'number') {
      el.textContent = `Total downloads: ${asset.download_count.toLocaleString()}`;
    } else {
      el.textContent = '';
    }
  } catch (err) {
    console.warn('[downloads] Could not load release stats:', err);
  }
}

// on page load, try to show the badge
document.addEventListener('DOMContentLoaded', showReleaseDownloadCount);