// js/consent.js

// === simple consent store ===
// we use localStorage to remember the users choice.
// "granted" means we can attach analytics. "denied" means we cannot.
function CE_hasConsent() {
  return localStorage.getItem('analytics_consent') === 'granted';
}
function CE_setConsent(granted) {
  localStorage.setItem('analytics_consent', granted ? 'granted' : 'denied');
  if (granted) {
    // let other scripts know that consent was just granted.
    window.dispatchEvent(new Event('analytics:consent-granted'));
  }
}

// === banner UI creation ===
// we build the DOM for the banner on the fly so you do not need extra HTML markup.
function CE_buildBanner() {
  // if the user already made a choice, do not show the banner.
  if (localStorage.getItem('analytics_consent')) return;

  // create the container that sticks to the bottom.
  const banner = document.createElement('div');
  banner.className = 'cookie-banner';
  banner.setAttribute('role', 'dialog');             // announce as a dialog
  banner.setAttribute('aria-live', 'polite');        // read changes politely
  banner.setAttribute('aria-label', 'Cookie consent');

  // text block that explains what we track.
  const text = document.createElement('div');
  text.className = 'cookie-text';
  // keep the copy short and clear. Mention cookies and analytics.
  text.innerHTML = `
    We use cookies to run analytics after you accept. This helps us count visits,
    see how long people stay, and understand devices and countries. You can change
    your choice any time in “Cookie settings.”
  `;

  // buttons: Accept, Decline, and Settings (re-open later)
  const actions = document.createElement('div');
  actions.className = 'cookie-actions';

  const accept = document.createElement('button');
  accept.className = 'cookie-btn cookie-accept';
  accept.textContent = 'Accept analytics';
  accept.addEventListener('click', () => {
    CE_setConsent(true);       // store granted
    banner.remove();           // hide banner
  });

  const decline = document.createElement('button');
  decline.className = 'cookie-btn cookie-decline';
  decline.textContent = 'Decline';
  decline.addEventListener('click', () => {
    CE_setConsent(false);      // store denied
    banner.remove();           // hide banner
  });

  const settings = document.createElement('button');
  settings.className = 'cookie-btn cookie-settings';
  settings.textContent = 'Cookie settings';
  settings.addEventListener('click', () => {
    // clicking this when the banner is visible does nothing special.
    // we leave it here to match the footer link behavior.
    alert('Use the footer link “Cookie settings” to reopen this banner later.');
  });

  // put it all together and attach to the page.
  actions.appendChild(accept);
  actions.appendChild(decline);
  actions.appendChild(settings);
  banner.appendChild(text);
  banner.appendChild(actions);
  document.body.appendChild(banner);

  // Move keyboard focus to the primary action for accessibility
  accept.focus();
}

// === public helper to reopen the banner ===window.showConsentBanner = function
// this lets the footer link “Cookie settings” bring the banner back.
window.showConsentBanner = function showConsentBanner() {
  // remove any existing choice so the banner appears again.
  localStorage.removeItem('analytics_consent');
  // build the banner UI again.
  CE_buildBanner();
};

// build the banner once the page is ready.
document.addEventListener('DOMContentLoaded', CE_buildBanner);