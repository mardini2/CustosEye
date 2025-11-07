// goal: keyboard navigation and click behavior for top navigation menu
// handles arrow keys, enter/space, escape, and click toggling for About submenu

(function() {
  'use strict';

  // track if user is using keyboard (for focus-visible fallback)
  // add user-is-tabbing class on first Tab press to show focus outlines
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !document.body.classList.contains('user-is-tabbing')) {
      document.body.classList.add('user-is-tabbing');
    }
  });

  // remove user-is-tabbing class on first mouse click to hide focus outlines
  document.addEventListener('mousedown', () => {
    if (document.body.classList.contains('user-is-tabbing')) {
      document.body.classList.remove('user-is-tabbing');
    }
  });

  // find the nav and submenu elements
  const nav = document.querySelector('.topbar-nav');
  if (!nav) return;

  const aboutButton = document.getElementById('about-menu-button');
  const aboutSubmenu = aboutButton?.closest('.nav-has-submenu')?.querySelector('.nav-submenu');
  if (!aboutButton || !aboutSubmenu) return;

  const aboutContainer = aboutButton.closest('.nav-has-submenu');
  const submenuItems = Array.from(aboutSubmenu.querySelectorAll('a[role="menuitem"]'));
  const topLevelItems = Array.from(nav.querySelectorAll('a[role="menuitem"]'));

  // toggle submenu open/closed
  function toggleSubmenu(open) {
    const isOpen = aboutContainer.classList.contains('nav-submenu-open');
    if (open === undefined) {
      open = !isOpen;
    }
    
    if (open) {
      aboutContainer.classList.add('nav-submenu-open');
      aboutButton.setAttribute('aria-expanded', 'true');
    } else {
      aboutContainer.classList.remove('nav-submenu-open');
      aboutButton.setAttribute('aria-expanded', 'false');
    }
  }

  // close submenu and return focus to button
  function closeSubmenu() {
    toggleSubmenu(false);
    aboutButton.focus();
  }

  // prevent About button from navigating or opening submenu on click (hover only)
  // make button completely non-clickable - only hover works
  aboutButton.addEventListener('mousedown', (e) => {
    e.preventDefault();
    e.stopPropagation();
    // close submenu immediately and prevent any click behavior
    cancelCloseTimer();
    toggleSubmenu(false);
    // add class to prevent CSS hover from reopening
    aboutContainer.classList.add('click-just-happened');
  });
  
  aboutButton.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    // ensure submenu stays closed
    cancelCloseTimer();
    toggleSubmenu(false);
    // keep class active to prevent hover from reopening
    aboutContainer.classList.add('click-just-happened');
    setTimeout(() => {
      aboutContainer.classList.remove('click-just-happened');
    }, 500);
  });

  // also prevent context menu and other mouse events
  aboutButton.addEventListener('contextmenu', (e) => {
    e.preventDefault();
  });

  // handle keyboard navigation on About button
  aboutButton.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggleSubmenu();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      toggleSubmenu(true);
      if (submenuItems.length > 0) {
        submenuItems[0].focus();
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      closeSubmenu();
    }
  });

  // handle keyboard navigation in submenu
  submenuItems.forEach((item, index) => {
    item.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const next = submenuItems[index + 1] || submenuItems[0];
        next.focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (index === 0) {
          closeSubmenu();
        } else {
          const prev = submenuItems[index - 1];
          prev.focus();
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        closeSubmenu();
      }
    });
  });

  // handle keyboard navigation for all top-level items
  topLevelItems.forEach((item, index) => {
    item.addEventListener('keydown', (e) => {
      // arrow keys: move between top-level items
      if (e.key === 'ArrowRight') {
        e.preventDefault();
        const next = topLevelItems[index + 1] || topLevelItems[0];
        next.focus();
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        const prev = topLevelItems[index - 1] || topLevelItems[topLevelItems.length - 1];
        prev.focus();
      }
      // enter/space: activate link or open About submenu
      else if (e.key === 'Enter' || e.key === ' ') {
        if (item === aboutButton) {
          e.preventDefault();
          toggleSubmenu();
        }
        // for other items, let default behavior (navigation) happen
      }
      // escape: close any open submenu and return focus to parent
      else if (e.key === 'Escape') {
        if (aboutContainer.classList.contains('nav-submenu-open')) {
          e.preventDefault();
          closeSubmenu();
        }
      }
    });
  });

  // hover delay: keep submenu open while pointer is over About or submenu
  let closeTimer = null;
  const CLOSE_DELAY = 400; // 400ms delay (within 350-500ms range, increased for better UX)

  function cancelCloseTimer() {
    if (closeTimer) {
      clearTimeout(closeTimer);
      closeTimer = null;
    }
  }

  // check if pointer or keyboard focus is inside the submenu area
  function isInteracting() {
    const hasHover = aboutContainer.matches(':hover') || aboutSubmenu.matches(':hover');
    const hasFocus = aboutContainer.contains(document.activeElement);
    return hasHover || hasFocus;
  }

  function scheduleClose() {
    cancelCloseTimer();
    closeTimer = setTimeout(() => {
      // only close if pointer and keyboard focus are both outside
      if (!isInteracting()) {
        toggleSubmenu(false);
      }
      closeTimer = null;
    }, CLOSE_DELAY);
  }

  // keep submenu open on hover (but not if click just happened)
  aboutContainer.addEventListener('mouseenter', () => {
    if (!clickBlockActive && !aboutContainer.classList.contains('click-just-happened')) {
      cancelCloseTimer();
      // ensure class is set so submenu stays open even when mouse leaves (during grace period)
      toggleSubmenu(true);
    }
  });

  // keep submenu open when mouse enters submenu
  aboutSubmenu.addEventListener('mouseenter', () => {
    cancelCloseTimer();
    // make sure submenu is open when hovering over it
    if (!clickBlockActive && !aboutContainer.classList.contains('click-just-happened')) {
      toggleSubmenu(true);
    }
  });

  // schedule close on mouse leave (with delay to allow moving to submenu across gap)
  aboutContainer.addEventListener('mouseleave', (e) => {
    // check if mouse is moving to submenu (relatedTarget is submenu or its child)
    const relatedTarget = e.relatedTarget;
    if (!relatedTarget || (!aboutSubmenu.contains(relatedTarget) && relatedTarget !== aboutSubmenu)) {
      // mouse is leaving About and not going to submenu
      // make sure class is set to keep submenu visible (CSS hover is gone, class keeps it open)
      // this allows user time to move mouse to submenu across the gap
      toggleSubmenu(true);
      // give extra time to allow user to move mouse to submenu across the gap
      // check periodically if mouse has entered submenu or returned to About
      let checkCount = 0;
      const maxChecks = 15; // check for 1.5 seconds (15 * 100ms = 1500ms)
      const checkInterval = setInterval(() => {
        checkCount++;
        if (isInteracting()) {
          // mouse has entered submenu or returned to About, cancel close
          clearInterval(checkInterval);
        } else if (checkCount >= maxChecks) {
          // max time reached, close submenu
          clearInterval(checkInterval);
          scheduleClose();
        }
      }, 100);
    }
  });

  aboutSubmenu.addEventListener('mouseleave', (e) => {
    // check if mouse is moving to About button (relatedTarget is About or its parent)
    const relatedTarget = e.relatedTarget;
    if (!relatedTarget || (!aboutContainer.contains(relatedTarget) && relatedTarget !== aboutButton && relatedTarget !== aboutContainer)) {
      // mouse is leaving submenu and not going to About, schedule close
      scheduleClose();
    }
  });

  // keep submenu open when keyboard focus moves inside
  aboutSubmenu.addEventListener('focusin', () => {
    cancelCloseTimer();
    toggleSubmenu(true);
  });

  // also cancel timer when focus moves to About button itself
  aboutButton.addEventListener('focusin', () => {
    cancelCloseTimer();
  });

  // close submenu when clicking outside
  document.addEventListener('click', (e) => {
    if (!aboutContainer.contains(e.target)) {
      cancelCloseTimer();
      toggleSubmenu(false);
    }
  });

  // close submenu on blur if focus moves outside the container
  aboutContainer.addEventListener('focusout', (e) => {
    setTimeout(() => {
      if (!aboutContainer.contains(document.activeElement)) {
        cancelCloseTimer();
        toggleSubmenu(false);
      }
    }, 0);
  });

})();

