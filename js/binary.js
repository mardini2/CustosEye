// binary.js
// goal: creates a binary rain animation effect (falling 0s and 1s) for visual design on the
//       index page. draws animated columns of binary digits that fall down the screen with
//       trailing effects. respects user's motion preferences and pauses when the page is hidden.

(function () {
  // ======= KNOBS =======
  const GLYPH_SIZE = 16;  // pixel size of each binary digit (0 or 1)
  const SPEED_MIN  = 0.04;  // minimum fall speed (lower bound for randomness)
  const SPEED_MAX  = 0.08;  // maximum fall speed (upper bound for randomness)
  const DENSITY    = 1.0;  // column spacing density (1.0 = normal spacing)
  const TRAIL_FADE = 0.07;  // background fade opacity (smaller = longer trails)

  // slow flipping: each column keeps its digit for this many frames
  const SWITCH_EVERY_N = 25;  // higher number = slower flipping between 0 and 1
  // ======================

  // respect user's motion preferences, do not run animation if they prefer reduced motion
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  // get the canvas element from the page
  const canvas = document.getElementById('binary-canvas');
  if (!canvas) return;  // exit if canvas doesn't exist
  canvas.style.width = '100%';  // make canvas fill its container width
  canvas.style.height = '100%';  // make canvas fill its container height

  // get the 2D drawing context with alpha transparency support
  const ctx = canvas.getContext('2d', { alpha: true });

  // resize the canvas to match its display size and handle high-DPI displays
  function resizeCanvas() {
    const dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));  // get device pixel ratio (capped at 2)
    const rect = canvas.getBoundingClientRect();  // get the canvas's actual display size
    canvas.width  = Math.floor(rect.width * dpr);  // set canvas internal width (scaled for DPI)
    canvas.height = Math.floor(rect.height * dpr);  // set canvas internal height (scaled for DPI)
    // scale the drawing context to account for high-DPI displays
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  let columns = [];  // array to store all the falling binary columns

  // initialize the columns array with random positions and properties
  function initColumns() {
    const rect = canvas.getBoundingClientRect();  // get canvas display size
    const step  = GLYPH_SIZE / DENSITY;  // calculate spacing between columns
    const count = Math.ceil(rect.width / step);  // calculate how many columns fit across the width
    columns = [];  // reset the columns array

    // create a column for each position across the width
    for (let i = 0; i < count; i++) {
      columns.push({
        x: (i + 0.5) * step,  // x position (centered in its column)
        y: -Math.random() * rect.height,  // y position (start above the screen, randomized)
        speed: SPEED_MIN + Math.random() * (SPEED_MAX - SPEED_MIN),  // random fall speed
        color: Math.random() < 0.5
          ? 'rgba(34, 197, 94, 0.7)'   // soft green (50% chance)
          : 'rgba(139, 92, 246, 0.7)', // soft purple (50% chance)
        glyph: Math.random() < 0.5 ? '0' : '1',  // random starting digit (0 or 1)
        framesSinceSwitch: 0  // counter for how long since the digit last changed
      });
    }
  }

  // set up the font for drawing the binary digits
  function applyFont() {
    ctx.font = `${GLYPH_SIZE}px "Consolas","Courier New",monospace`;  // use monospace font
    ctx.textAlign = 'center';  // center text horizontally
    ctx.textBaseline = 'top';  // align text to the top
  }

  // draw one frame of the animation
  function drawFrame() {
    const rect = canvas.getBoundingClientRect();  // get current canvas display size
    const w = rect.width;  // canvas width
    const h = rect.height;  // canvas height

    // soft background fade — darker, easier on eyes (creates trailing effect)
    ctx.fillStyle = `rgba(10, 14, 24, ${TRAIL_FADE})`;  // dark background with low opacity
    ctx.fillRect(0, 0, w, h);  // fill the entire canvas (creates fade effect)

    // draw and update each column
    for (const col of columns) {
      // draw current digit
      ctx.fillStyle = col.color;  // set the color for this column
      ctx.fillText(col.glyph, col.x, col.y);  // draw the 0 or 1 at its position

      // move downward
      col.y += GLYPH_SIZE * col.speed;  // move the digit down by its speed

      // slow digit flipping (change 0 to 1 or vice versa periodically)
      col.framesSinceSwitch++;  // increment the frame counter
      if (col.framesSinceSwitch >= SWITCH_EVERY_N) {
        col.glyph = (col.glyph === '0') ? '1' : '0';  // flip the digit
        col.framesSinceSwitch = 0;  // reset the counter
      }

      // reset column if it leaves screen (wrap around to the top)
      if (col.y > h + GLYPH_SIZE * 2) {
        col.y = -GLYPH_SIZE * (2 + Math.random() * 10);  // reset to random position above screen
      }
    }
  }

  // handle window resize - recreate canvas and columns for new size
  function handleResize() {
    resizeCanvas();  // resize the canvas to match new display size
    applyFont();  // reapply font settings
    initColumns();  // recreate columns for the new size
  }

  let raf;  // store the animation frame request ID
  // main animation loop
  function loop() {
    drawFrame();  // draw one frame
    raf = requestAnimationFrame(loop);  // schedule the next frame
  }

  // pause animation when page is hidden, resume when visible (saves CPU)
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);  // stop the animation
      raf = null;  // clear the request ID
    } else if (!raf) loop();  // resume animation if it was paused
  });

  handleResize();  // initialize canvas and columns
  window.addEventListener('resize', handleResize, { passive: true });  // handle window resize
  loop();  // start the animation loop
})();