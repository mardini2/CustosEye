# ruff: noqa: E501
"""
goal: local Flask dashboard for CustosEye — live telemetry + process tree, fast, simple, offline.

Highlights (this build):
1. fan-out subscription to a shared EventBus (no races with the console).
2. tabs: Live Events, Process Tree, About. no in-page console; terminal only prints “welcome + URL”.
3. live stream: Info/Warning/Critical filters, search, pause, refresh, CSV/JSON/JSONL/XLSX export.
4. trust overlay: CSCTrustEngine integration; trust score/label on rows and in the process tree.
5. process tree: PPID→PID hierarchy via native <details>, search, expand/collapse, copy, JSON/XLSX export.
6. hot-reload of rules.json; suppress noisy network events that lack pid/name.
7. assets: favicon + apple-touch routes (versioned), compatible with PyInstaller bundling.
8. performance guardrails: bounded ring buffer, per-call drain cap, short deadlines to keep the UI snappy.
"""

from __future__ import annotations

import csv
import io
import json
import os
import threading
import time
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    jsonify,
    make_response,
    render_template_string,
    request,
    send_file,
)

# waitress optional
try:
    from waitress import serve as _serve

    HAVE_WAITRESS = True
except Exception:
    HAVE_WAITRESS = False
    _serve = None  # type: ignore

from agent.rules_engine import RulesEngine
from algorithm.csc_engine import CSCTrustEngine


# ---------------- Config / paths ----------------
def _resolve_base_dir() -> Path:
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[1]


def _asset_path(rel: str) -> str:
    import sys

    base = Path(getattr(sys, "_MEIPASS", _resolve_base_dir()))
    return str((base / rel).resolve())


BASE_DIR = _resolve_base_dir()
RULES_PATH = str((BASE_DIR / "data" / "rules.json").resolve())
CSC_WEIGHTS_PATH = str((BASE_DIR / "data" / "csc_weights.json").resolve())
CSC_DB_PATH = str((BASE_DIR / "data" / "trust_db.json").resolve())

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


# ---------------- Buffers / indices ----------------
BUFFER_MAX = 1200
BUFFER: deque[dict[str, Any]] = deque(maxlen=BUFFER_MAX)
PROC_INDEX: dict[int, dict[str, Any]] = {}

DRAIN_LIMIT_PER_CALL = 300
DRAIN_DEADLINE_SEC = 0.25

# ---------------- HTML UI ----------------
HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>CustosEye · Live</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <link rel="icon" href="/favicon.ico?v=2">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png?v=2">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png?v=2">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png?v=2">
  <style>
    :root {
      --bg:#0b0f14; --panel:#141a22; --text:#e7eef7; --muted:#9ab;
      --chip-info:#2a6df1; --chip-warning:#e6a700; --chip-critical:#d43c3c; --chip-border:rgba(255,255,255,0.2);
      --accent:#7cc5ff; --ok:#1db954; --border:#1f2a36; --row:#10161e; --rowAlt:#0d131a; --input:#0f141b;
      --tab:#0f151d; --tabOn:#1b2634;
      --trust-low:#c03d3d; --trust-medium:#c27b00; --trust-high:#1db954;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg:#f6f8fb; --panel:#fff; --text:#10131a; --muted:#445;
        --chip-info:#2a6df1; --chip-warning:#c27b00; --chip-critical:#b61e1e; --chip-border:rgba(0,0,0,0.15);
        --accent:#1565c0; --ok:#128b3a; --border:#e7ebf0; --row:#fff; --rowAlt:#f8fafc; --input:#f3f6fa;
        --tab:#f1f4f8; --tabOn:#e5ebf3;
      }
    }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial; }
    header { position:sticky; top:0; z-index:5; backdrop-filter: blur(6px); background:linear-gradient(180deg,rgba(0,0,0,0.2),transparent); border-bottom:1px solid var(--border); }
    .wrap { max-width:1100px; margin:0 auto; padding:16px; }
    .title { display:flex; align-items:center; gap:10px; margin:4px 0 10px; font-weight:700; letter-spacing:.2px; font-size:18px; }
    .subtitle { color:var(--muted); font-size:12px; }
    .panel { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:12px; box-shadow:0 6px 20px rgba(0,0,0,0.15); }
    .tabs { display:flex; gap:8px; margin-bottom:10px; }
    .tab { background:var(--tab); border:1px solid var(--border); border-radius:8px; padding:6px 10px; cursor:pointer; user-select:none; }
    .tab.on { background:var(--tabOn); border-color:var(--accent); }
    .controls { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
    .chip { display:inline-flex; align-items:center; gap:6px; border:1px solid var(--chip-border); padding:4px 10px; border-radius:999px; font-size:12px; cursor:pointer; user-select:none; background:transparent; color:var(--text); }
    .chip[data-on="true"] { background:rgba(124,197,255,0.1); border-color:var(--accent); }
    .chip .dot { width:8px; height:8px; border-radius:999px; }
    .chip.info .dot { background:var(--chip-info); }
    .chip.warning .dot { background:var(--chip-warning); }
    .chip.critical .dot { background:var(--chip-critical); }
    .chip.ok .dot { background:var(--ok); }
    .input { background:var(--input); border:1px solid var(--border); padding:8px 10px; border-radius:8px; color:var(--text); min-width:220px; }
    .btn { background:var(--accent); color:white; border:0; padding:8px 12px; border-radius:8px; cursor:pointer; }
    .list { margin-top:12px; border-top:1px dashed var(--border); }
    .row { display:grid; grid-template-columns:108px 100px 1fr; gap:14px; padding:10px 4px; border-bottom:1px solid var(--border); background:var(--row); }
    .row:nth-child(odd) { background:var(--rowAlt); }
    .lvl { display:inline-flex; align-items:center; gap:8px; padding:4px 8px; border-radius:999px; font-weight:600; letter-spacing:.3px; }
    .lvl.info { color:var(--chip-info); background: color-mix(in oklab, var(--chip-info) 14%, transparent); }
    .lvl.warning { color:var(--chip-warning); background: color-mix(in oklab, var(--chip-warning) 18%, transparent); }
    .lvl.critical { color:var(--chip-critical); background: color-mix(in oklab, var(--chip-critical) 18%, transparent); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; font-size:12px; }
    .muted { color:var(--muted); }
    .count { font-weight:600; }
    .nowrap { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

    /* Process tree */
    .tree { margin-top:12px; }
    .treebar { display:flex; gap:8px; align-items:center; margin-bottom:8px; }
    .pill { display:inline-block; padding:2px 6px; border-radius:999px; border:1px solid var(--border); font-size:11px; }
    .pill.low { color: var(--trust-low); border-color: color-mix(in oklab, var(--trust-low) 40%, var(--border)); }
    .pill.medium { color: var(--trust-medium); border-color: color-mix(in oklab, var(--trust-medium) 40%, var(--border)); }
    .pill.high { color: var(--trust-high); border-color: color-mix(in oklab, var(--trust-high) 40%, var(--border)); }
    details { border-left:2px solid var(--border); margin-left:10px; padding-left:8px; }
    details > summary { list-style: none; cursor: pointer; }
    summary::-webkit-details-marker { display:none; }
    .caret { display:inline-block; width:0; height:0; border-top:6px solid transparent; border-bottom:6px solid transparent; border-left:6px solid var(--muted); margin-right:6px; transform: translateY(1px) rotate(-90deg); transition: transform .15s ease; }
    details[open] > summary .caret { transform: translateY(1px) rotate(0deg); }
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <div class="title">
        <img src="/favicon.ico" alt="" style="width:20px;height:20px;border-radius:4px;opacity:.9" />
        CustosEye <span class="subtitle">local dashboard</span>
      </div>

      <div class="tabs">
        <div class="tab on" data-tab="live">Live Events</div>
        <div class="tab" data-tab="tree">Process Tree</div>
        <div class="tab" data-tab="about">About</div>
      </div>

      <!-- Live bar -->
      <div class="panel" id="bar-live">
        <div class="controls">
          <button class="chip info" data-on="true" data-level="info"><span class="dot"></span>Info</button>
          <button class="chip warning" data-on="true" data-level="warning"><span class="dot"></span>Warning</button>
          <button class="chip critical" data-on="true" data-level="critical"><span class="dot"></span>Critical</button>
          <button class="chip ok" id="pause" data-on="false"><span class="dot"></span><span id="pauseText">Live</span></button>
          <input id="search" class="input" placeholder="Search: reason, source, name, pid..." />
          <button class="btn" id="refresh">Refresh</button>
          <button class="btn" id="export">Export CSV</button>
          <div class="muted">Showing <span id="count" class="count">0</span> / <span id="total" class="count">0</span></div>
        </div>
      </div>
    </div>
  </header>

  <main>
    <div class="wrap">
      <div id="live" class="list"></div>

      <div id="tree" class="tree" style="display:none">
        <div class="treebar">
          <input id="treeSearch" class="input" placeholder="Search PIDs, names, trust..." />
          <button class="btn" id="treeRefresh">Refresh</button>
          <button class="btn" id="treeExpand">Expand all</button>
          <button class="btn" id="treeCollapse">Collapse all</button>
          <button class="btn" id="treeCopy">Copy</button>
          <button class="btn" id="treeExport">Export JSON/Excel</button>
        </div>
        <div id="treeRoot"></div>
      </div>

      <div id="about" class="panel" style="display:none"></div>
    </div>
  </main>

  <script>
    const state = { tab:"live", levels:{info:false,warning:true,critical:true}, paused:false, q:"", timer:null, treeQ:"" };
    const listEl = document.getElementById('live'), searchEl = document.getElementById('search');
    const countEl = document.getElementById('count'), totalEl = document.getElementById('total');
    const pauseBtn = document.getElementById('pause'), pauseText = document.getElementById('pauseText');
    const treeEl = document.getElementById('treeRoot'), aboutEl = document.getElementById('about');

    // Tabs
    document.querySelectorAll('.tab').forEach(t => {
      t.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(x => x.classList.remove('on'));
        t.classList.add('on'); state.tab = t.getAttribute('data-tab');
        document.getElementById('live').style.display = (state.tab==='live')?'':'none';
        document.getElementById('bar-live').style.display = (state.tab==='live')?'':'none';
        document.getElementById('tree').style.display = (state.tab==='tree')?'':'none';
        aboutEl.style.display = (state.tab==='about')?'':'none';
        if (state.tab==='tree') fetchTree();   // fetch once on enter
        if (state.tab==='about') fetchAbout();
      });
    });

    // Live filters
    document.querySelectorAll('#bar-live .chip[data-level]').forEach(btn => {
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

    // Export live
    document.getElementById('export').addEventListener('click', () => {
      const includeInfo = state.levels.info ? '1' : '0';
      const lvls = Object.entries(state.levels).filter(([k,v]) => v).map(([k])=>k).join(',');
      const url = `/api/export?format=csv&include_info=${includeInfo}&levels=${encodeURIComponent(lvls)}&q=${encodeURIComponent(state.q)}`;
      window.location.href = url;
    });

    // Live list rendering
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
        if (!state.paused && state.tab==='live') render(data);
      } catch (e) { /* ignore */ }
    }

    // ---------------- Process tree ----------------
    const treeSearch = document.getElementById('treeSearch');
    document.getElementById('treeRefresh').addEventListener('click', fetchTree);
    document.getElementById('treeExpand').addEventListener('click', () => toggleAll(true));
    document.getElementById('treeCollapse').addEventListener('click', () => toggleAll(false));
    document.getElementById('treeCopy').addEventListener('click', copyTree);
    document.getElementById('treeExport').addEventListener('click', () => {
      const useXlsx = confirm("Export Process Tree as Excel (OK) or JSON (Cancel)?");
      const fmt = useXlsx ? "xlsx" : "json";
      window.location.href = `/api/proctree?as=${fmt}`;
    });
    treeSearch.addEventListener('input', (e) => { state.treeQ = (e.target.value||'').toLowerCase().trim(); fetchTree(); });

    async function fetchTree() {
      try {
        const res = await fetch('/api/proctree');
        const data = await res.json();
        const filtered = filterTreeList(data, state.treeQ);
        treeEl.innerHTML = filtered.map(n => renderNode(n, 0)).join('');
      } catch (e) {}
    }

    function filterTreeList(list, q) {
      if (!q) return list;
      function match(n) {
        const s = `${n.pid} ${n.name} ${n.trust_label||''}`.toLowerCase();
        return s.includes(q);
      }
      function filterNode(n) {
        const kids = (n.children||[]).map(filterNode).filter(Boolean);
        if (match(n) || kids.length) return { ...n, children: kids };
        return null;
      }
      return list.map(filterNode).filter(Boolean);
    }

    function pill(trust) {
      const t = (trust||'').toLowerCase();
      return `<span class="pill ${t}">${t||''}</span>`;
    }

    function renderNode(n, depth) {
      const openAttr = depth < 1 ? " open" : "";
      const head = `<span class="caret"></span><span class="mono">PID ${n.pid}</span> <span class="mono">${n.name}</span> ${pill(n.trust_label)}`;
      const kids = (n.children||[]).map(c => renderNode(c, depth+1)).join('');
      if (!kids) {
        return `<div style="margin-left:10px"><span class="mono">PID ${n.pid}</span> <span class="mono">${n.name}</span> ${pill(n.trust_label)}</div>`;
      }
      return `<details${openAttr}><summary>${head}</summary>${kids}</details>`;
    }

    function toggleAll(open) {
      document.querySelectorAll('#treeRoot details').forEach(d => {
        if (open) d.setAttribute('open','');
        else d.removeAttribute('open');
      });
    }

    function copyTree() {
      const tmp = document.createElement('textarea');
      tmp.value = document.getElementById('treeRoot').innerText.trim();
      document.body.appendChild(tmp);
      tmp.select(); document.execCommand('copy'); document.body.removeChild(tmp);
    }

    // ---------------- About ----------------
    async function fetchAbout() {
      try {
        const res = await fetch('/api/about'); const a = await res.json();
        aboutEl.innerHTML = `
          <div class="mono"><b>CustosEye</b></div>
          <div class="muted">Local-only dashboard for monitoring.</div>
          <div class="mono" style="margin-top:6px">Version: ${a.version || 'dev'}</div>
          <div class="mono">Build: ${a.build || '-'}</div>
          <div class="mono">Buffer size: ${a.buffer_max}</div>
        `;
      } catch (e) {}
    }

    // poller: only live (tree loads on demand to preserve expand/collapse)
    state.timer = setInterval(() => {
      if (state.tab==='live') fetchData();
    }, 1500);
    fetchData();
  </script>
</body>
</html>
"""


# ---------------- fan-out subscription plumbing ----------------
def _bus_iterator(bus: Any) -> Iterator[dict[str, Any]]:
    """
    Return an iterator that yields events for this subscriber.
    Supports either:
      - bus.subscribe() -> iterator (preferred)
      - bus.iter_events() -> iterator (legacy)
    """
    if hasattr(bus, "subscribe"):
        it = bus.subscribe()
    else:
        it = bus.iter_events()
    # mypy: convince this is an Iterator[dict[str, Any]]
    return it  # type: ignore[return-value]


# ---------------- Flask app build ----------------
def build_app(event_bus) -> Flask:
    app = Flask(__name__)

    # make sure our iterator type is clear for mypy
    _iter: Iterator[dict[str, Any]] = _bus_iterator(event_bus)

    # favicon routes
    @app.get("/favicon.ico")
    def favicon():
        p = Path(_asset_path("assets/favicon.ico"))
        if p.exists():
            return send_file(str(p), mimetype="image/x-icon")
        return ("", 204)

    @app.get("/favicon-32x32.png")
    def favicon_32():
        p = Path(_asset_path("assets/favicon-32x32.png"))
        if p.exists():
            return send_file(str(p), mimetype="image/png")
        return ("", 204)

    @app.get("/favicon-16x16.png")
    def favicon_16():
        p = Path(_asset_path("assets/favicon-16x16.png"))
        if p.exists():
            return send_file(str(p), mimetype="image/png")
        return ("", 204)

    @app.get("/apple-touch-icon.png")
    def apple_touch_icon():
        p = Path(_asset_path("assets/apple-touch-icon.png"))
        if p.exists():
            return send_file(str(p), mimetype="image/png")
        return ("", 204)

    # each Flask app holds its own subscriber iterator
    _iter = _bus_iterator(event_bus)

    def drain_into_buffer() -> int:
        _maybe_reload_rules()
        drained = 0
        deadline = time.time() + DRAIN_DEADLINE_SEC

        while time.time() < deadline and drained < DRAIN_LIMIT_PER_CALL:
            try:
                ev = next(_iter)
            except StopIteration:
                break
            except Exception:
                break
            if not ev:
                break

            ev.setdefault("level", "info")
            ev.setdefault("reason", "event")
            ev.setdefault("ts", time.time())

            if ev.get("source") != "integrity":
                decision = _rules.evaluate(ev)
                ev["level"] = decision.get("level", ev.get("level"))
                ev["reason"] = decision.get("reason", ev.get("reason"))

            if ev.get("source") == "process":
                t = _csc.evaluate(ev)
                ev["trust"], ev["trust_label"], ev["trust_reasons"] = (
                    t["trust"],
                    t["label"],
                    t["reasons"],
                )
                pid = ev.get("pid")
                if isinstance(pid, int):
                    PROC_INDEX[pid] = {
                        "pid": pid,
                        "ppid": ev.get("ppid"),
                        "name": ev.get("name") or "",
                        "trust": t["trust"],
                        "trust_label": t["label"],
                    }

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
        drain_into_buffer()
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

    @app.get("/api/export")
    def export_current():
        """
        export live buffer with current filters.
        format=csv (default) | json | jsonl | xlsx
        """
        drain_into_buffer()

        include_info = (request.args.get("include_info") or "").lower() in ("1", "true", "yes")
        q = (request.args.get("q") or "").lower().strip()
        lvls = (request.args.get("levels") or "").lower().split(",")
        lvls = [x for x in lvls if x] or ["warning", "critical"]
        fmt = (request.args.get("format") or "csv").lower()

        def pass_filters(ev: dict[str, Any]) -> bool:
            lvl = (ev.get("level") or "info").lower()
            if lvl == "info" and not include_info:
                return False
            if lvls and lvl not in lvls:
                return False
            if q:
                s = f"{ev.get('reason','')} {ev.get('source','')} {ev.get('name','')} {ev.get('pid','')}"
                if q not in s.lower():
                    return False
            return True

        rows = [ev for ev in BUFFER if pass_filters(ev)]

        # JSONL
        if fmt == "jsonl":
            lines = [json.dumps(ev, ensure_ascii=False) for ev in rows]
            resp = make_response("\n".join(lines))
            resp.headers["Content-Type"] = "application/json"
            resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_export.jsonl"'
            return resp

        # JSON
        if fmt == "json":
            resp = make_response(json.dumps(rows, ensure_ascii=False, indent=2))
            resp.headers["Content-Type"] = "application/json"
            resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_export.json"'
            return resp

        # common tabular cols
        cols = ["ts", "level", "reason", "source", "pid", "name", "trust", "trust_label"]

        # XLSX
        if fmt == "xlsx":
            try:
                from openpyxl import Workbook
                from openpyxl.utils import get_column_letter
            except Exception:
                return (
                    jsonify(
                        {
                            "error": "xlsx export requires `openpyxl`",
                            "hint": "pip install openpyxl or use format=csv",
                        }
                    ),
                    400,
                )

            wb = Workbook()
            ws = wb.active
            ws.title = "CustosEye"
            ws.append(cols)

            for ev in rows:
                r = {k: ev.get(k, "") for k in cols}
                if isinstance(r["ts"], int | float):
                    try:
                        r["ts"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(r["ts"])))
                    except Exception:
                        pass
                ws.append([r.get(c, "") for c in cols])

            for i, c in enumerate(cols, 1):
                max_len = len(c)
                for row in ws.iter_rows(min_row=2, min_col=i, max_col=i):
                    v = row[0].value
                    if v is None:
                        continue
                    max_len = max(max_len, len(str(v)))
                ws.column_dimensions[get_column_letter(i)].width = max(
                    10, min(60, int(max_len * 1.1 + 2))
                )

            from io import BytesIO

            bio = BytesIO()
            wb.save(bio)
            bio.seek(0)
            return send_file(
                bio,
                as_attachment=True,
                download_name="custoseye_export.xlsx",
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

        # default: CSV (Excel-friendly, BOM + quoted + CRLF; ts as text)
        buf = io.StringIO(newline="")
        writer = csv.DictWriter(
            buf,
            fieldnames=cols,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
            lineterminator="\r\n",
        )
        writer.writeheader()

        for ev in rows:
            r = {k: ev.get(k, "") for k in cols}
            if isinstance(r["ts"], int | float):
                try:
                    r["ts"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(r["ts"])))
                except Exception:
                    pass
            if r.get("ts"):
                r["ts"] = f"'{r['ts']}"
            writer.writerow(r)

        csv_text = buf.getvalue()
        out_bytes = ("\ufeff" + csv_text).encode("utf-8")
        resp = make_response(out_bytes)
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_export.csv"'
        return resp

    @app.get("/api/proctree")
    def proctree():
        """
        Return the compact process tree.

        Query params:
          as=json  -> download pretty JSON (custoseye_proctree.json)
          as=xlsx  -> download Excel (custoseye_proctree.xlsx)
          (none)   -> return JSON to the browser (not as attachment)
        """
        drain_into_buffer()

        children: dict[int, list[int]] = {}
        roots: list[int] = []
        for pid, rec in PROC_INDEX.items():
            ppid = rec.get("ppid")
            if isinstance(ppid, int) and ppid in PROC_INDEX:
                children.setdefault(ppid, []).append(pid)
            else:
                roots.append(pid)

        def build(pid: int) -> dict[str, Any]:
            r = PROC_INDEX.get(pid, {})
            return {
                "pid": pid,
                "ppid": r.get("ppid", None),
                "name": r.get("name", ""),
                "trust_label": r.get("trust_label", ""),
                "children": [build(c) for c in sorted(children.get(pid, []))[:100]],
            }

        tree = [build(p) for p in sorted(roots)[:100]]

        fmt = (request.args.get("as") or "").lower()

        if fmt == "json":
            resp = make_response(json.dumps(tree, indent=2, ensure_ascii=False))
            resp.headers["Content-Type"] = "application/json"
            resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_proctree.json"'
            return resp

        if fmt == "xlsx":
            try:
                from openpyxl import Workbook
                from openpyxl.utils import get_column_letter
            except Exception:
                return (
                    jsonify(
                        {
                            "error": "xlsx export requires `openpyxl`",
                            "hint": "pip install openpyxl or use ?as=json",
                        }
                    ),
                    400,
                )

            wb = Workbook()
            ws = wb.active
            ws.title = "Process Tree"
            ws.append(["PID", "Name", "Trust Label", "Parent PID"])

            for pid, rec in sorted(PROC_INDEX.items()):
                ws.append(
                    [pid, rec.get("name", ""), rec.get("trust_label", ""), rec.get("ppid", "")]
                )

            for col_idx, width in enumerate((10, 32, 14, 12), start=1):
                ws.column_dimensions[get_column_letter(col_idx)].width = width

            from io import BytesIO

            bio = BytesIO()
            wb.save(bio)
            bio.seek(0)
            return send_file(
                bio,
                as_attachment=True,
                download_name="custoseye_proctree.xlsx",
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

        # default inline JSON
        return jsonify(tree)

    @app.get("/api/about")
    def about():
        version = "-"
        build = "-"
        vpath = Path(_resolve_base_dir() / "VERSION.txt")
        if vpath.exists():
            try:
                lines = [
                    line.strip()
                    for line in vpath.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                if len(lines) >= 1:
                    version = lines[0]
                if len(lines) >= 2:
                    build = lines[1]
            except Exception:
                pass
        return jsonify({"version": version, "build": build, "buffer_max": BUFFER_MAX})

    return app


def run_dashboard(event_bus) -> None:
    app = build_app(event_bus)
    if app is None:
        raise RuntimeError(
            "build_app() returned None; check for exceptions or missing `return app`."
        )
    if HAVE_WAITRESS:
        _serve(app, host="127.0.0.1", port=8765)
    else:
        app.run(host="127.0.0.1", port=8765, debug=False)


# standalone mode (optional): if you run "python -m dashboard.app"
if __name__ == "__main__":
    # minimal pub/sub bus for standalone dashboard
    import queue

    class FanoutEventBus:
        def __init__(self) -> None:
            self._subs: list[queue.Queue] = []
            self._lock = threading.Lock()

        def publish(self, event: dict[str, Any]) -> None:
            with self._lock:
                subs = list(self._subs)
            for q in subs:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass

        def subscribe(self):
            q: queue.Queue = queue.Queue(maxsize=1000)
            with self._lock:
                self._subs.append(q)

            def _iter():
                while True:
                    try:
                        yield q.get(timeout=0.2)
                    except queue.Empty:
                        yield None

            return _iter()

    bus = FanoutEventBus()

    # start agents (standalone)
    from agent.integrity_check import IntegrityChecker
    from agent.monitor import ProcessMonitor
    from agent.network_scan import NetworkSnapshot

    for target in (
        ProcessMonitor(publish=bus.publish).run,
        NetworkSnapshot(publish=bus.publish).run,
        IntegrityChecker(
            targets_path=str((BASE_DIR / "data" / "integrity_targets.json").resolve()),
            publish=bus.publish,
            interval_sec=5.0,
        ).run,
    ):
        threading.Thread(target=target, daemon=True).start()

    run_dashboard(bus)
