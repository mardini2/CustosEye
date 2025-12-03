// js/analytics-attach.js
// goal: loads Google Analytics 4 only after user consent, tracks file downloads, and shows
//       a private debug badge with GitHub release download stats when ?debug=1 is in the URL.
//       only runs on whitelisted domains or in debug mode to avoid tracking during development.

// === GA4 Measurement ID ===
const GA_MEASUREMENT_ID = 'G-0YTLKPFY3R';  // google analytics measurement ID for tracking

// only send analytics on these hostnames (or when ?debug=1 is present)
const GA_ALLOWED_HOSTS = ['www.custoseye.com', 'custoseye.com'];

// optional GitHub release debug badge (only if ?debug=1)
const GH_OWNER = 'mardini2';  // GitHub username/organization
const GH_REPO = 'CustosEye';  // repository name
const GH_TAG_OR_LATEST = 'latest';  // 'latest' or a specific tag like 'v0.2.0'
const GH_ASSET_FILENAME = 'CustosEye.zip';  // exact asset filename to look for

// load a script dynamically and return a promise that resolves when it finishes loading
function loadScript(src, async = true) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');  // create a script element
    s.src = src;  // set the script source URL
    s.async = async;  // load asynchronously or not
    s.onload = resolve;  // resolve the promise when script loads successfully
    s.onerror = reject;  // reject the promise if script fails to load
    document.head.appendChild(s);  // add the script to the page head
  });
}

// check if we should attach analytics (only on whitelisted hosts or in debug mode)
function shouldAttachGA() {
  const params = new URLSearchParams(location.search);  // parse URL query parameters
  const debugParam = params.get('debug') === '1';  // check if ?debug=1 is present
  const allowedHost = GA_ALLOWED_HOSTS.includes(location.hostname);  // check if hostname is whitelisted
  return allowedHost || debugParam;  // return true if host is allowed or debug mode is on
}

// attach Google Analytics 4 to the page after consent is granted
async function attachAnalytics() {
  // skip if host is not whitelisted and not in debug mode
  if (!shouldAttachGA()) {
    console.info('[analytics] Skipping GA (host not whitelisted and no ?debug=1).');
    return;
  }
  // skip if measurement ID is not set or is still the placeholder
  if (!GA_MEASUREMENT_ID || GA_MEASUREMENT_ID.startsWith('G-XXXX')) {
    console.warn('[analytics] GA_MEASUREMENT_ID not set.');
    return;
  }

  try {
    // load the Google Analytics script from Google Tag Manager
    await loadScript(`https://www.googletagmanager.com/gtag/js?id=${GA_MEASUREMENT_ID}`);

    // initialize the dataLayer array that GA4 uses to queue events
    window.dataLayer = window.dataLayer || [];
    // create the gtag function that pushes events to dataLayer
    function gtag(){ dataLayer.push(arguments); }
    window.gtag = gtag;  // make it globally available

    // check if we are in debug mode (from URL parameter)
    const debugMode = new URLSearchParams(location.search).get('debug') === '1';

    // initialize GA4 with current timestamp
    gtag('js', new Date());
    // configure GA4 with measurement ID, IP anonymization, and debug mode
    gtag('config', GA_MEASUREMENT_ID, { anonymize_ip: true, debug_mode: debugMode });

    console.info('[analytics] GA4 attached (debug_mode:', debugMode, ')');

    // recommended GA4 event for file downloads
    // track primary download button (installer on index, or both on download page)
    const dl = document.getElementById('download-btn');  // find the primary download button
    if (dl) {
      // listen for clicks on the download button
      dl.addEventListener('click', () => {
        // determine file name from href
        const fileName = dl.href.includes('.exe') ? 'CustosEye-Setup.exe' : 'CustosEye.zip';
        // send a file_download event to GA4 with file details
        gtag('event', 'file_download', {
          file_name: fileName,
          link_url: dl.href,
          event_category: 'engagement',
          event_label: window.location.pathname,
          value: 1
        });
      });
    }
    
    // track installer button on download page
    const dlInstaller = document.getElementById('download-btn-installer');
    if (dlInstaller) {
      dlInstaller.addEventListener('click', () => {
        gtag('event', 'file_download', {
          file_name: 'CustosEye-Setup.exe',
          link_url: dlInstaller.href,
          event_category: 'engagement',
          event_label: window.location.pathname,
          value: 1
        });
      });
    }
    
    // track zip button on download page
    const dlZip = document.getElementById('download-btn-zip');
    if (dlZip) {
      dlZip.addEventListener('click', () => {
        gtag('event', 'file_download', {
          file_name: 'CustosEye.zip',
          link_url: dlZip.href,
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

// listen for the consent granted event and attach analytics when it fires
window.addEventListener('analytics:consent-granted', attachAnalytics);
// also check on page load if consent was already granted (stored in localStorage)
document.addEventListener('DOMContentLoaded', () => {
  try {
    if (localStorage.getItem('analytics_consent') === 'granted') attachAnalytics();
  } catch {}  // ignore errors if localStorage is not available
});

// ---- Private debug badge (only if ?debug=1) ----
// fetch GitHub release download stats and show them in a debug badge
async function showReleaseDownloadCount() {
  const params = new URLSearchParams(location.search);  // parse URL query parameters
  const debugMode = params.get('debug') === '1';  // check if ?debug=1 is present
  if (!debugMode) return;  // invisible to the public, only show in debug mode

  try {
    // build the GitHub API URL for the release (latest or specific tag)
    const url = (GH_TAG_OR_LATEST === 'latest')
      ? `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/releases/latest`
      : `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/releases/tags/${encodeURIComponent(GH_TAG_OR_LATEST)}`;

    // fetch the release data from GitHub API
    const res = await fetch(url, { headers: { 'Accept': 'application/vnd.github+json' } });
    if (!res.ok) throw new Error(`GitHub API ${res.status}`);  // throw error if API request failed
    const data = await res.json();  // parse the JSON response

    // find asset and figure out the tag label
    const asset = (data.assets || []).find(a => a.name === GH_ASSET_FILENAME);  // find the zip file asset
    const tag = data.tag_name || (data.name || GH_TAG_OR_LATEST);  // get the release tag name

    // if we found the asset and it has a download count
    if (asset && typeof asset.download_count === 'number') {
      // build the "tag · count · checked time" string
      const now = new Date();  // get current time
      const timeStr = now.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });  // format time as HH:MM
      const info = document.createElement('div');  // create a div for the debug info
      info.className = 'debug-download-count';  // add a class for styling
      // style it with monospace font and green color
      info.style.cssText = `
        margin: 12px 24px 0;
        color: #a1f1b0;
        font-family: monospace;
        font-size: 0.9rem;
        opacity: 0.85;
      `;
      // set the text content with tag, download count, and time checked
      info.textContent = `${tag} · ${asset.download_count.toLocaleString()} downloads · checked ${timeStr}`;
      // append it to the footer or body
      (document.querySelector('footer') || document.body).appendChild(info);
    }
  } catch (err) {
    console.warn('[downloads] Could not load release stats:', err);
  }
}
// show the download count badge when the page loads
document.addEventListener('DOMContentLoaded', showReleaseDownloadCount);