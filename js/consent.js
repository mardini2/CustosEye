// js/consent.js
// goal: cookie consent modal for analytics opt-in. shows a modal on first visit if no consent
//       choice is stored, allows users to accept or decline analytics cookies, stores the choice
//       in localStorage, and dispatches an event when consent is granted. includes accessibility
//       features like focus trapping and prevents closing with Escape key.

(function () {
  const KEY = 'analytics_consent';  // localStorage key for storing the consent choice

  // nuke any legacy banner/fab if the old CSS/JS ever sneaks in (cleanup for old code)
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.cookie-banner, .cookie-settings-fab').forEach(el => el.remove());
  });

  // check if user has already made a choice (granted or denied)
  function hasChoice() {
    const v = localStorage.getItem(KEY);  // get the stored consent value
    return v === 'granted' || v === 'denied';  // return true if a choice was made
  }
  // save the user's consent choice and dispatch event if granted
  function setConsent(granted) {
    localStorage.setItem(KEY, granted ? 'granted' : 'denied');  // save choice to localStorage
    if (granted) window.dispatchEvent(new Event('analytics:consent-granted'));  // fire event if accepted
  }

  // minimal gate modal (no status text)
  function buildGateModal() {
    // create the overlay that covers the entire page
    const overlay = document.createElement('div');
    overlay.className = 'cookie-modal-overlay';
    overlay.setAttribute('role', 'dialog');  // accessibility: mark as dialog
    overlay.setAttribute('aria-modal', 'true');  // accessibility: mark as modal
    overlay.setAttribute('aria-label', 'Cookie notice');  // accessibility: label for screen readers

    // create the modal card that contains the content
    const modal = document.createElement('div');
    modal.className = 'cookie-modal card';

    // create the heading
    const h = document.createElement('h2');
    h.textContent = 'Cookie settings';
    h.style.marginBottom = '8px';

    // create the description paragraph
    const p = document.createElement('p');
    p.className = 'muted';
    p.style.marginBottom = '16px';
    p.textContent = 'Choose how cookies are used. It is safe and your choice helps us provide a better site experience. You can change this any time inside the Cookie settings.';

    // create a row to hold the buttons
    const row = document.createElement('div');
    row.className = 'btn-row';
    row.style.marginTop = '8px';

    // create the accept button
    const accept = document.createElement('button');
    accept.className = 'btn btn-primary';
    accept.textContent = 'Accept cookies';

    // create the decline button
    const decline = document.createElement('button');
    decline.className = 'btn btn-ghost';
    decline.textContent = 'Decline';

    // optional: a link to the full settings page (opens in a new tab)
    const learn = document.createElement('a');
    learn.className = 'btn btn-ghost';
    learn.href = 'cookies.html';
    learn.target = '_blank';  // open in new tab
    learn.rel = 'noopener';  // security: prevent new tab from accessing opener window
    learn.textContent = 'Open Cookie settings';

    // add buttons to the row
    row.appendChild(accept);
    row.appendChild(decline);
    row.appendChild(learn);

    // add elements to the modal
    modal.appendChild(h);
    modal.appendChild(p);
    modal.appendChild(row);
    // add modal to the overlay
    overlay.appendChild(modal);

    // actions
    accept.addEventListener('click', () => { setConsent(true);  closeModal(overlay); });  // accept and close
    decline.addEventListener('click', () => { setConsent(false); closeModal(overlay); });  // decline and close

    // focus trap + block Escape (force explicit choice)
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); return; }  // block Escape key (force choice)
      if (e.key !== 'Tab') return;  // only handle Tab key for focus trapping
      // find all focusable elements in the modal
      const nodes = modal.querySelectorAll('button, a, [tabindex]:not([tabindex="-1"])');
      if (!nodes.length) return;  // exit if no focusable elements
      const list = Array.from(nodes);  // convert to array
      const first = list[0], last = list[list.length - 1];  // get first and last elements
      // if Shift+Tab on first element, jump to last (focus trap)
      if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
      // if Tab on last element, jump to first (focus trap)
      else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
    });

    // focus the accept button when modal opens (accessibility)
    setTimeout(() => accept.focus(), 0);
    return overlay;  // return the overlay element
  }

  // open the consent modal (if not already open)
  function openModal() {
    if (document.querySelector('.cookie-modal-overlay')) return;  // exit if modal already exists
    const overlay = buildGateModal();  // build the modal
    document.body.appendChild(overlay);  // add it to the page
    document.body.classList.add('no-scroll');  // prevent body scrolling
    document.documentElement.classList.add('no-scroll');  // prevent html scrolling
  }

  // close the consent modal
  function closeModal(overlay) {
    if (overlay && overlay.remove) overlay.remove();  // remove the overlay from the page
    document.body.classList.remove('no-scroll');  // re-enable body scrolling
    document.documentElement.classList.remove('no-scroll');  // re-enable html scrolling
  }

  // public: call from footer if you want to *force* the gate again (optional)
  window.showConsentModal = function showConsentModal() {
    localStorage.removeItem(KEY);  // clear the stored choice
    openModal();  // show the modal again
  };

  // show the gate only when no choice is stored (on page load)
  document.addEventListener('DOMContentLoaded', () => {
    if (!hasChoice()) openModal();  // show modal if user hasn't made a choice yet
  });
})();