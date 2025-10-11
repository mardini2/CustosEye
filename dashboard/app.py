"""
Goal: Minimal Flask dashboard that streams recent events and rule decisions.

Design:
- In-memory ring buffer of last N events for the UI.
- Lightweight HTML with no JS build tooling.
- Not a security boundary; local-only by default.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Deque, Dict

from flask import Flask, jsonify, render_template_string

# Shared ring buffer for events across requests
BUFFER: Deque[Dict[str, Any]] = deque(maxlen=500)


HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CustosEye – Live Events</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; }
    .event { padding: 8px 12px; border-bottom: 1px solid #e5e5e5; }
    .tag { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 12px; margin-right: 8px; }
    .info { background: #eef; }
    .warning { background: #ffe9b3; }
    .critical { background: #ffd6d6; }
    code { font-family: Consolas, monospace; }
  </style>
</head>
<body>
  <h1>CustosEye – Live Events</h1>
  <p>This is a minimal local dashboard for Phase 1. Refresh to see latest events.</p>
  <div id="events"></div>
  <script>
    async function load() {
      const res = await fetch('/api/events');
      const data = await res.json();
      const root = document.getElementById('events');
      root.innerHTML = '';
      for (const ev of data) {
        const div = document.createElement('div');
        const cls = ev.level || 'info';
        div.className = 'event';
        div.innerHTML = `<span class="tag ${cls}">${cls.toUpperCase()}</span>` +
                        `<code>${ev.reason || 'event'}</code> | ` +
                        `source=${ev.source || ''} pid=${ev.pid || ''} name=${ev.name || ''}`;
        root.appendChild(div);
      }
    }
    load();
    setInterval(load, 3000);
  </script>
</body>
</html>
"""


def run_dashboard(event_bus) -> None:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template_string(HTML)

    @app.get("/api/events")
    def events():
        # Drain any new items from the queue into our buffer
        drained = 0
        while True:
            ev = None
            try:
                ev = next(event_bus.iter_events())
            except StopIteration:
                break
            if not ev:
                break
            # Tag info level by default so UI can color
            ev.setdefault("level", "info")
            ev.setdefault("reason", "event")
            BUFFER.append(ev)
            drained += 1
            if drained > 100:
                break
        return jsonify(list(BUFFER))

    app.run(host="127.0.0.1", port=8765, debug=False)