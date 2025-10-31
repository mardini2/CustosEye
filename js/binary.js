// binary.js — for design-only binary rain effect on index.html

(function () {
  // ======= KNOBS =======
  const GLYPH_SIZE = 16;     // pixel size of each glyph
  const SPEED_MIN  = 0.04;   // fall speed lower bound
  const SPEED_MAX  = 0.08;   // fall speed upper bound
  const DENSITY    = 1.0;    // 1.0 = normal column spacing
  const TRAIL_FADE = 0.07;   // smaller = longer trails

  // slow flipping: each column keeps its digit for this many frames
  const SWITCH_EVERY_N = 25; // higher number = slower flipping
  // ======================

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const canvas = document.getElementById('binary-canvas');
  if (!canvas) return;
  canvas.style.width = '100%';
  canvas.style.height = '100%';

  const ctx = canvas.getContext('2d', { alpha: true });

  function resizeCanvas() {
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    const rect = canvas.getBoundingClientRect();
    canvas.width  = Math.floor(rect.width * dpr);
    canvas.height = Math.floor(rect.height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  let columns = [];

  function initColumns() {
    const rect = canvas.getBoundingClientRect();
    const step  = GLYPH_SIZE / DENSITY;
    const count = Math.ceil(rect.width / step);
    columns = [];

    for (let i = 0; i < count; i++) {
      columns.push({
        x: (i + 0.5) * step,
        y: -Math.random() * rect.height,
        speed: SPEED_MIN + Math.random() * (SPEED_MAX - SPEED_MIN),
        color: Math.random() < 0.5
          ? 'rgba(34, 197, 94, 0.7)'   // soft green
          : 'rgba(139, 92, 246, 0.7)', // soft purple
        glyph: Math.random() < 0.5 ? '0' : '1',
        framesSinceSwitch: 0
      });
    }
  }

  function applyFont() {
    ctx.font = `${GLYPH_SIZE}px "Consolas","Courier New",monospace`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
  }

  function drawFrame() {
    const rect = canvas.getBoundingClientRect();
    const w = rect.width;
    const h = rect.height;

    // soft background fade — darker, easier on eyes
    ctx.fillStyle = `rgba(10, 14, 24, ${TRAIL_FADE})`;
    ctx.fillRect(0, 0, w, h);

    for (const col of columns) {
      // draw current digit
      ctx.fillStyle = col.color;
      ctx.fillText(col.glyph, col.x, col.y);

      // move downward
      col.y += GLYPH_SIZE * col.speed;

      // slow digit flipping
      col.framesSinceSwitch++;
      if (col.framesSinceSwitch >= SWITCH_EVERY_N) {
        col.glyph = (col.glyph === '0') ? '1' : '0';
        col.framesSinceSwitch = 0;
      }

      // reset column if it leaves screen
      if (col.y > h + GLYPH_SIZE * 2) {
        col.y = -GLYPH_SIZE * (2 + Math.random() * 10);
      }
    }
  }

  function handleResize() {
    resizeCanvas();
    applyFont();
    initColumns();
  }

  let raf;
  function loop() {
    drawFrame();
    raf = requestAnimationFrame(loop);
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
      raf = null;
    } else if (!raf) loop();
  });

  handleResize();
  window.addEventListener('resize', handleResize, { passive: true });
  loop();
})();