"""
Goal: Flask dashboard to view live CustosEye events.

Design:
- Local-only HTTP UI (127.0.0.1) served by waitress when available, otherwise Flask dev server.
- When run via app.console, the console passes in an EventBus and this file only serves the UI.
- When run directly (python -m dashboard.app), this file starts its own EventBus + agents.
- Server drains the event bus into an in-memory ring buffer.
- Applies the JSON rules engine on non-integrity events so UI shows level/reason.
- Computes and displays CSC trust for process events (Phase 2).
- Lightweight HTML/CSS/JS (no build tooling), with dark/light theme, filters, search, and pause.
- Intended for local monitoring; not a security boundary.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template_string, request

# Optional waitress (production WSGI). If missing, we fall back to Flask dev server.
try:
    from waitress import serve as _serve

    HAVE_WAITRESS = True
except Exception:
    HAVE_WAITRESS = False
    _serve = None  # type: ignore

# Import rules engine and trust engine; if we run standalone we also import agents.
from agent.rules_engine import RulesEngine
from algorithm.csc_engine import CSCTrustEngine


# ---- Event bus (identical semantics to console's) ----
class EventBus:
    def __init__(self) -> None:
        self._q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)

    def publish(self, event: dict[str, Any]) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            pass  # drop on full to avoid backpressure in UI

    def iter_events(self):
        while True:
            try:
                yield self._q.get(timeout=0.2)
            except queue.Empty:
                yield None


# ---- Shared ring buffer for recent events (server-side) ----
BUFFER_MAX = 1000
BUFFER: deque[dict[str, Any]] = deque(maxlen=BUFFER_MAX)

# Basic rate guard for draining: don't block an API call too long
DRAIN_LIMIT_PER_CALL = 250  # max events to drain per HTTP call
DRAIN_DEADLINE_SEC = 0.25  # ~250ms budget per drain


def _resolve_base_dir() -> Path:
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[1]


BASE_DIR = _resolve_base_dir()
RULES_PATH = str((BASE_DIR / "data" / "rules.json").resolve())
CSC_WEIGHTS_PATH = str((BASE_DIR / "data" / "csc_weights.json").resolve())
CSC_DB_PATH = str((BASE_DIR / "data" / "trust_db.json").resolve())

# Build engines; we hot-reload rules when the file changes
_rules = RulesEngine(path=RULES_PATH)
_rules_mtime = os.path.getmtime(RULES_PATH) if os.path.exists(RULES_PATH) else 0.0
_csc = CSCTrustEngine(weights_path=CSC_WEIGHTS_PATH, db_path=CSC_DB_PATH)


def _maybe_reload_rules() -> None:
    global _rules, _rules_mtime
    try:
        mtime = os.path.getmtime(RULES_PATH)
    except OSError:
        mtime = 0.0
    if mtime != _rules_mtime:
        _rules_mtime = mtime
        _rules.rules = _rules._load_rules()


# ---- HTML template (inline for portability) ----
HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CustosEye · Live Events</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    :root {
      --bg: #0b0f14; --panel: #141a22; --text: #e7eef7; --muted: #9ab;
      --chip-info: #2a6df1; --chip-warning: #e6a700; --chip-critical: #d43c3c; --chip-border: rgba(255,255,255,0.2);
      --accent: #7cc5ff; --ok: #1db954; --border: #1f2a36; --row: #10161e; --rowAlt: #0d131a; --input: #0f141b;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f6f8fb; --panel: #ffffff; --text: #10131a; --muted: #445;
        --chip-info: #2a6df1; --chip-warning: #c27b00; --chip-critical: #b61e1e; --chip-border: rgba(0,0,0,0.15);
        --accent: #1565c0; --ok: #128b3a; --border: #e7ebf0; --row: #ffffff; --rowAlt: #f8fafc; --input: #f3f6fa;
      }
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial; }
    header { position: sticky; top: 0; z-index: 5; backdrop-filter: blur(6px); background: linear-gradient(180deg, rgba(0,0,0,0.2), transparent); border-bottom: 1px solid var(--border); }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
    .title { display: flex; align-items: center; gap: 10px; margin: 4px 0 12px; font-weight: 700; letter-spacing: 0.2px; font-size: 18px; }
    .subtitle { color: var(--muted); font-size: 12px; }
    .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 12px; box-shadow: 0 6px 20px rgba(0,0,0,0.15); }
    .controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .chip { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--chip-border); padding: 4px 10px; border-radius: 999px; font-size: 12px; cursor: pointer; user-select: none; background: transparent; color: var(--text); }
    .chip[data-on="true"] { background: rgba(124,197,255,0.1); border-color: var(--accent); }
    .chip .dot { width: 8px; height: 8px; border-radius: 999px; }
    .chip.info .dot { background: var(--chip-info); }
    .chip.warning .dot { background: var(--chip-warning); }
    .chip.critical .dot { background: var(--chip-critical); }
    .chip.ok .dot { background: var(--ok); }
    .input { background: var(--input); border: 1px solid var(--border); padding: 8px 10px; border-radius: 8px; color: var(--text); min-width: 220px; }
    .btn { background: var(--accent); color: white; border: 0; padding: 8px 12px; border-radius: 8px; cursor: pointer; }
    .list { margin-top: 12px; border-top: 1px dashed var(--border); }
    .row { display: grid; grid-template-columns: 108px 100px 1fr; gap: 14px; padding: 10px 4px; border-bottom: 1px solid var(--border); background: var(--row); }
    .row:nth-child(odd) { background: var(--rowAlt); }
    .lvl { display: inline-flex; align-items: center; gap: 8px; padding: 4px 8px; border-radius: 999px; font-weight: 600; letter-spacing: 0.3px; }
    .lvl.info { color: var(--chip-info); background: color-mix(in oklab, var(--chip-info) 14%, transparent); }
    .lvl.warning { color: var(--chip-warning); background: color-mix(in oklab, var(--chip-warning) 18%, transparent); }
    .lvl.critical { color: var(--chip-critical); background: color-mix(in oklab, var(--chip-critical) 18%, transparent); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size: 12px; }
    .muted { color: var(--muted); }
    .count { font-weight: 600; }
    .nowrap { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <div class="title">CustosEye · Live Events <span class="subtitle">local dashboard</span></div>
      <div class="panel">
        <div class="controls">
          <button class="chip info" data-on="false" data-level="info"><span class="dot"></span>Info</button>
          <button class="chip warning" data-on="true" data-level="warning"><span class="dot"></span>Warning</button>
          <button class="chip critical" data-on="true" data-level="critical"><span class="dot"></span>Critical</button>
          <button class="chip ok" id="pause" data-on="false"><span class="dot"></span><span id="pauseText">Live</span></button>
          <input id="search" class="input" placeholder="Search: reason, source, name, pid..." />
          <button class="btn" id="refresh">Refresh</button>
          <div class="muted">Showing <span id="count" class="count">0</span> / <span id="total" class="count">0</span></div>
        </div>
      </div>
    </div>
  </header>

  <main>
    <div class="wrap">
      <div id="list" class="list"></div>
    </div>
  </main>

  <script>
    const state = { levels: { info: false, warning: true, critical: true }, paused: false, q: "", timer: null };
    const listEl = document.getElementById('list'), searchEl = document.getElementById('search');
    const countEl = document.getElementById('count'), totalEl = document.getElementById('total');
    const pauseBtn = document.getElementById('pause'), pauseText = document.getElementById('pauseText');

    document.querySelectorAll('.chip[data-level]').forEach(btn => {
      btn.addEventListener('click', () => {
        const lvl = btn.getAttribute('data-level');
        const on = btn.getAttribute('data-on') !== 'true';
        btn.setAttribute('data-on', on ? 'true' : 'false');
        state.levels[lvl] = on; render(window.__data || []);
      });
    });

    pauseBtn.addEventListener('click', () => {
      state.paused = !state.paused;
      pauseBtn.setAttribute('data-on', state.paused ? 'true' : 'false');
      pauseText.textContent = state.paused ? 'Paused' : 'Live';
    });

    searchEl.addEventListener('input', (e) => { state.q = e.target.value.toLowerCase().trim(); render(window.__data || []); });
    document.getElementById('refresh').addEventListener('click', fetchData);

    function row(ev) {
      const lvl = (ev.level || 'info').toLowerCase();
      const reason = ev.reason || 'event';
      const src = ev.source || '';
      const pid = ev.pid || '';
      const name = ev.name || '';
      const ts = ev.ts ? new Date(ev.ts * 1000).toLocaleTimeString() : '';
      const trust = (typeof ev.trust === 'number') ? ` | trust=${ev.trust}(${ev.trust_label || ''})` : '';
      return `
        <div class="row">
          <div class="nowrap"><span class="lvl ${lvl}">${lvl.toUpperCase()}</span></div>
          <div class="mono muted nowrap">${ts}</div>
          <div class="mono nowrap">${reason} | source=${src} pid=${pid} name=${name}${trust}</div>
        </div>
      `;
    }

    function render(data) {
      const byLevel = data.filter(ev => state.levels[(ev.level || 'info').toLowerCase()]);
      const q = state.q;
      const byQuery = q ? byLevel.filter(ev => {
        const s = (ev.reason || '') + ' ' + (ev.source || '') + ' ' + (ev.name || '') + ' ' + (ev.pid || '');
        return s.toLowerCase().includes(q);
      }) : byLevel;
      countEl.textContent = byQuery.length; totalEl.textContent = data.length;
      listEl.innerHTML = byQuery.map(row).join('');
    }

    async function fetchData() {
      try {
        const includeInfo = state.levels.info ? '1' : '0';
        const res = await fetch('/api/events?include_info=' + includeInfo);
        const data = await res.json();
        window.__data = data;
        if (!state.paused) render(data);
      } catch (e) { /* ignore */ }
    }

    state.timer = setInterval(fetchData, 1500); fetchData();
  </script>
</body>
</html>
"""


def build_app(event_bus) -> Flask:
    app = Flask(__name__)

    def drain_into_buffer() -> int:
        """
        Non-blocking drain of events from the event bus into BUFFER.
        Also evaluates rules (non-integrity) and computes trust for process events.
        """
        _maybe_reload_rules()
        drained = 0
        deadline = time.time() + DRAIN_DEADLINE_SEC
        it = event_bus.iter_events()

        while time.time() < deadline and drained < DRAIN_LIMIT_PER_CALL:
            try:
                ev = next(it)
            except StopIteration:
                break
            if not ev:
                break

            # Normalize fields and attach timestamp
            ev.setdefault("level", "info")
            ev.setdefault("reason", "event")
            ev.setdefault("ts", time.time())

            # For non-integrity events, compute level/reason via rules
            if ev.get("source") != "integrity":
                decision = _rules.evaluate(ev)
                ev["level"] = decision.get("level", ev.get("level"))
                ev["reason"] = decision.get("reason", ev.get("reason"))

            # Phase 2: compute trust for process events so UI can display it
            if ev.get("source") == "process":
                t = _csc.evaluate(ev)
                ev["trust"] = t["trust"]
                ev["trust_label"] = t["label"]
                ev["trust_reasons"] = t["reasons"]

            # Skip empty network noise (no pid and no name)
            if ev.get("source") == "network" and not (ev.get("pid") or ev.get("name")):
                continue

            BUFFER.append(ev)
            drained += 1

        return drained

    @app.get("/")
    def index():
        return render_template_string(HTML)

    @app.get("/api/events")
    def events():
        # Drain fresh events quickly so the buffer stays current
        drain_into_buffer()

        # Only include INFO if explicitly requested
        include_info = (request.args.get("include_info") or "").lower() in ("1", "true", "yes")

        data = []
        for ev in BUFFER:
            if ev.get("source") == "network" and not (ev.get("pid") or ev.get("name")):
                continue
            lvl = (ev.get("level") or "info").lower()
            if not include_info and lvl == "info":
                continue
            data.append(ev)

        return jsonify(data)

    return app  # <<-- IMPORTANT: return the WSGI app


def run_dashboard(event_bus) -> None:
    app = build_app(event_bus)
    if HAVE_WAITRESS:
        _serve(app, host="127.0.0.1", port=8765)
    else:
        # Dev server fallback
        app.run(host="127.0.0.1", port=8765, debug=False)


# ---- Standalone entry point: python -m dashboard.app ----
if __name__ == "__main__":
    # Build a local EventBus and start agents so the dashboard can run standalone.
    bus = EventBus()

    # Lazy import agents to avoid overhead unless we run standalone
    from agent.integrity_check import IntegrityChecker
    from agent.monitor import ProcessMonitor
    from agent.network_scan import NetworkSnapshot

    # Start background workers (same behavior as console)
    for target, name in (
        (ProcessMonitor(publish=bus.publish).run, "monitor"),
        (NetworkSnapshot(publish=bus.publish).run, "network"),
        (
            IntegrityChecker(
                targets_path=str((BASE_DIR / "data" / "integrity_targets.json").resolve()),
                publish=bus.publish,
                interval_sec=5.0,
            ).run,
            "integrity",
        ),
    ):
        threading.Thread(target=target, name=f"dash-{name}", daemon=True).start()

    # Serve UI
    run_dashboard(bus)
