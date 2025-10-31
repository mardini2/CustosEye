// js/consent.js - Cookie consent modal for analytics opt-in

(function () {
  const KEY = 'analytics_consent';

  // nuke any legacy banner/fab if the old CSS/JS ever sneaks in
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.cookie-banner, .cookie-settings-fab').forEach(el => el.remove());
  });

  function hasChoice() {
    const v = localStorage.getItem(KEY);
    return v === 'granted' || v === 'denied';
  }
  function setConsent(granted) {
    localStorage.setItem(KEY, granted ? 'granted' : 'denied');
    if (granted) window.dispatchEvent(new Event('analytics:consent-granted'));
  }

  // minimal gate modal (no status text)
  function buildGateModal() {
    const overlay = document.createElement('div');
    overlay.className = 'cookie-modal-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Cookie notice');

    const modal = document.createElement('div');
    modal.className = 'cookie-modal card';

    const h = document.createElement('h2');
    h.textContent = 'Cookie settings';
    h.style.marginBottom = '8px';

    const p = document.createElement('p');
    p.className = 'muted';
    p.style.marginBottom = '16px';
    p.textContent = 'Choose how cookies are used. It is safe and your choice helps us provide a better site experience. You can change this any time inside the Cookie settings.';

    const row = document.createElement('div');
    row.className = 'btn-row';
    row.style.marginTop = '8px';

    const accept = document.createElement('button');
    accept.className = 'btn btn-primary';
    accept.textContent = 'Accept cookies';

    const decline = document.createElement('button');
    decline.className = 'btn btn-ghost';
    decline.textContent = 'Decline';

    // optional: a link to the full settings page (opens in a new tab)
    const learn = document.createElement('a');
    learn.className = 'btn btn-ghost';
    learn.href = 'cookies.html';
    learn.target = '_blank';
    learn.rel = 'noopener';
    learn.textContent = 'Open Cookie settings';

    row.appendChild(accept);
    row.appendChild(decline);
    row.appendChild(learn);

    modal.appendChild(h);
    modal.appendChild(p);
    modal.appendChild(row);
    overlay.appendChild(modal);

    // actions
    accept.addEventListener('click', () => { setConsent(true);  closeModal(overlay); });
    decline.addEventListener('click', () => { setConsent(false); closeModal(overlay); });

    // focus trap + block Escape (force explicit choice)
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); return; }
      if (e.key !== 'Tab') return;
      const nodes = modal.querySelectorAll('button, a, [tabindex]:not([tabindex="-1"])');
      if (!nodes.length) return;
      const list = Array.from(nodes);
      const first = list[0], last = list[list.length - 1];
      if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
      else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
    });

    setTimeout(() => accept.focus(), 0);
    return overlay;
  }

  function openModal() {
    if (document.querySelector('.cookie-modal-overlay')) return;
    const overlay = buildGateModal();
    document.body.appendChild(overlay);
    document.body.classList.add('no-scroll');
    document.documentElement.classList.add('no-scroll');
  }

  function closeModal(overlay) {
    if (overlay && overlay.remove) overlay.remove();
    document.body.classList.remove('no-scroll');
    document.documentElement.classList.remove('no-scroll');
  }

  // public: call from footer if you want to *force* the gate again (optional)
  window.showConsentModal = function showConsentModal() {
    localStorage.removeItem(KEY);
    openModal();
  };

  // show the gate only when no choice is stored
  document.addEventListener('DOMContentLoaded', () => {
    if (!hasChoice()) openModal();
  });
})();