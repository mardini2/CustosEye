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
import hashlib
import io
import json
import os
import sys
import threading
import time
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

from flask import (
    Flask,
    app,
    jsonify,
    make_response,
    render_template,
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
# import the new v2 engine (same class name for painless upgrades)
from algorithm.csc_engine import CSCTrustEngine  # v2 under the hood

from dashboard.config import load_config, Config
CFG: Config = load_config()


# ---------------- Config / paths ----------------
def _resolve_base_dir() -> Path:
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[1]


BASE_DIR = CFG.base_dir
RULES_PATH = str(CFG.rules_path)
CSC_WEIGHTS_PATH = str(CFG.csc_weights_path)
CSC_DB_PATH = str(CFG.csc_db_path)
INTEGRITY_TARGETS_PATH = str(CFG.integrity_targets_path)
SELF_SUPPRESS_PATH = str(CFG.self_suppress_path)


def _load_self_suppress() -> dict[str, set[str]]:
    try:
        with open(SELF_SUPPRESS_PATH, encoding="utf-8") as f:
            obj = json.load(f) or {}
    except Exception:
        obj = {}
    # normalize to lowercase sets
    return {
        "names": {s.lower() for s in obj.get("names", ["CustosEye.exe"])},
        "exes": {s.lower() for s in obj.get("exes", [])},
        "sha256": {s.lower() for s in obj.get("sha256", [])},
    }


SELF_SUPPRESS = _load_self_suppress()

_rules = RulesEngine(path=RULES_PATH)
_rules_mtime = os.path.getmtime(RULES_PATH) if os.path.exists(RULES_PATH) else 0.0
_csc = CSCTrustEngine(weights_path=CSC_WEIGHTS_PATH, db_path=CSC_DB_PATH)

NAME_TRUST_PATH = str((BASE_DIR / "data" / "name_trust.json").resolve())
_name_trust: dict[str, tuple[str, str, float]] = {}
_name_trust_mtime: float = 0.0

def _maybe_reload_name_trust() -> None:
    global _name_trust, _name_trust_mtime
    try:
        mtime = os.path.getmtime(NAME_TRUST_PATH)
    except OSError:
        mtime = 0.0
    if mtime > _name_trust_mtime:
        _name_trust_mtime = mtime
        try:
            with open(NAME_TRUST_PATH, encoding="utf-8") as f:
                obj = json.load(f)
            # normalize to {name: (verdict, cls, confidence)}
            nt: dict[str, tuple[str, str, float]] = {}
            for k, v in (obj or {}).items():
                if isinstance(v, list) and len(v) == 3:
                    verdict, cls, conf = v
                    nt[str(k).lower()] = (str(verdict), str(cls), float(conf))
            _name_trust = nt
        except Exception:
            _name_trust = {}

def _maybe_promote_to_trusted(ev: dict) -> bool:
    nm = (ev.get("name") or "").lower()
    verdict = _name_trust.get(nm)
    if not verdict:
        return False
    v, cls, conf = verdict
    ev["csc"] = {"version":"v2","verdict":v,"cls":cls,"confidence":conf,
                 "reasons":["name+parent heuristic"],"signals":{}}
    ev["csc_verdict"], ev["csc_class"], ev["csc_confidence"] = v, cls, conf
    ev["csc_reasons"] = ["name+parent heuristic"]
    return True

def _maybe_reload_rules() -> None:
    global _rules, _rules_mtime
    try:
        mtime = os.path.getmtime(RULES_PATH)
    except OSError:
        mtime = 0.0
    if mtime > _rules_mtime:
        _rules_mtime = mtime
        _rules.rules = _rules._load_rules()


# ---------------- Buffers / indices ----------------
BUFFER_MAX = CFG.buffer_max
BUFFER: deque[dict[str, Any]] = deque(maxlen=BUFFER_MAX)
PROC_INDEX: dict[int, dict[str, Any]] = {}

DRAIN_LIMIT_PER_CALL = CFG.drain_limit_per_call
DRAIN_DEADLINE_SEC = CFG.drain_deadline_sec

_DRAIN_LOCK = threading.Lock() # to prevent concurrent drains

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


def _read_integrity_targets() -> list[dict[str, Any]]:
    """
    back-compat:
      - if file is a JSON array: return it.
      - if file is an object with "targets": return that list.
      - if missing/unreadable: return [].
    also augments each row with "rule" (default sha256) and "last_result" if present.
    """
    try:
        with open(INTEGRITY_TARGETS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            rows = cast(list[dict[str, Any]], data)
        elif isinstance(data, dict) and isinstance(data.get("targets"), list):
            rows = cast(list[dict[str, Any]], data["targets"])
        else:
            rows = []
    except Exception:
        rows = []
    # normalize fields for UI
    norm: list[dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        rr = dict(r)
        rr.setdefault("rule", "sha256" if rr.get("sha256") else "mtime+size")
        # last_result is not persisted by us; my agent may add it to events only.
        norm.append(rr)
    return norm


def _write_integrity_targets(rows: list[dict[str, Any]]) -> None:
    """
    persist as a plain array to keep compatibility with your current file.
    """
    try:
        Path(INTEGRITY_TARGETS_PATH).parent.mkdir(parents=True, exist_ok=True)
        with open(INTEGRITY_TARGETS_PATH, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _sha256_file(path: str) -> dict[str, Any]:
    # normalize (env vars, ~, quotes) but keep original text in "path"
    p = _norm_user_path(path)
    out: dict[str, Any] = {"path": path}
    try:
        st = os.stat(p)
        out["size"] = st.st_size
        out["mtime"] = int(st.st_mtime)
    except Exception as e:
        out["error"] = f"stat failed: {e}"
        return out
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        out["sha256"] = h.hexdigest().upper()
    except Exception as e:
        out["error"] = f"hash failed: {e}"
    return out


def _norm_user_path(p: str) -> str:
    # normalize, expand env vars (~, %WINDIR%), strip quotes, keep Unicode
    p = (p or "").strip().strip('"')
    p = os.path.expandvars(os.path.expanduser(p))
    return str(Path(p))


# ---------------- Flask app build ----------------
def build_app(event_bus) -> Flask:
    app = Flask(__name__)

    # make sure our iterator type is clear for mypy
    _iter: Iterator[dict[str, Any]] = _bus_iterator(event_bus)

    # favicon routes
    @app.get("/favicon.ico")
    def favicon():
        return app.send_static_file("assets/favicon.ico")

    @app.get("/favicon-32x32.png")
    def favicon_32():
        return app.send_static_file("assets/favicon-32x32.png")

    @app.get("/favicon-16x16.png")
    def favicon_16():
        return app.send_static_file("assets/favicon-16x16.png")

    @app.get("/apple-touch-icon.png")
    def apple_touch_icon():
        return app.send_static_file("assets/apple-touch-icon.png")

    def drain_into_buffer() -> int:
        with _DRAIN_LOCK:
          _maybe_reload_rules()
          _maybe_reload_name_trust()
          drained = 0
          deadline = time.time() + DRAIN_DEADLINE_SEC

          while time.time() < deadline and drained < DRAIN_LIMIT_PER_CALL:
              try:
                  ev = next(_iter)
              except StopIteration:
                  break
              except Exception:
                  break
              if ev is None:
                continue          # dont exit early; keep trying until deadline

              ev.setdefault("level", "info")
              ev.setdefault("reason", "event")
              ev.setdefault("ts", time.time())

              if ev.get("source") != "integrity":
                  decision = _rules.evaluate(ev)
                  ev["level"] = decision.get("level", ev.get("level"))
                  ev["reason"] = decision.get("reason", ev.get("reason"))

              if ev.get("source") == "process":
                  # --- suppress our own process(es) before any scoring or tree updates ---
                  nm_lc = str(ev.get("name") or "").lower()
                  ex_lc = str(ev.get("exe") or "").lower()
                  h_lc  = str(ev.get("sha256") or "").lower()
                  if (
                      (nm_lc and nm_lc in SELF_SUPPRESS["names"]) or
                      (ex_lc and ex_lc in SELF_SUPPRESS["exes"]) or
                      (h_lc  and h_lc  in SELF_SUPPRESS["sha256"])
                  ):
                      continue  # skip buffering and tree indexing entirely

                  # --- trust scoring: name-based fast-path, then kernel/idle/registry, then model ---
                  pid = ev.get("pid")
                  nm = str(ev.get("name") or "")

                  # 1) known-good names (your NAME_TRUST map)
                  if _maybe_promote_to_trusted(ev):
                      pass  # already set by the heuristic

                  # 2) kernel/idle/registry fast-path
                  elif pid in (0, 4) or nm.lower() in ("system", "system idle process", "registry"):
                      ev["csc"] = {
                          "version": "v2",
                          "verdict": "trusted",
                          "cls": "system",
                          "confidence": 0.98,
                          "reasons": ["kernel/idle/registry fast-path"],
                          "signals": {},
                      }
                      ev["csc_verdict"] = "trusted"
                      ev["csc_class"] = "system"
                      ev["csc_confidence"] = 0.98
                      ev["csc_reasons"] = ["kernel/idle/registry fast-path"]

                  # 3) everything else → model
                  else:
                      csc_out = _csc.evaluate(ev)
                      ev["csc"] = csc_out
                      ev["csc_verdict"] = csc_out.get("verdict", "unknown")
                      ev["csc_class"] = csc_out.get("cls", "unknown")
                      ev["csc_confidence"] = float(csc_out.get("confidence", 0.5))
                      ev["csc_reasons"] = csc_out.get("reasons", [])

                  # process tree index (store the v2 fields)
                  if isinstance(pid, int):
                      PROC_INDEX[pid] = {
                          "pid": pid,
                          "ppid": ev.get("ppid"),
                          "name": ev.get("name") or "",
                          "csc_verdict": ev.get("csc_verdict", "unknown"),
                          "csc_class": ev.get("csc_class", "unknown"),
                          "csc_confidence": ev.get("csc_confidence", 0.5),
                      }

              if ev.get("source") == "network" and not (ev.get("pid") or ev.get("name")):
                  continue

              # if the event is from integrity, make sure we have a display name
              if ev.get("source") == "integrity":
                  p = ev.get("path") or ev.get("file")
                  if p and not ev.get("name"):
                      try:
                          ev["name"] = os.path.basename(str(p))
                      except Exception:
                          ev["name"] = str(p)

              BUFFER.append(ev)
              drained += 1

          return drained

    @app.get("/")
    def index():
        return render_template("index.html")

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

    @app.get("/api/ping")
    def ping():
        """lightweight drain trigger so background ingestion continues on any tab"""
        n = drain_into_buffer()
        return jsonify({"ok": True, "drained": n, "buffer": len(BUFFER)})

    @app.get("/api/export")
    def export_current():
        """
        export live buffer with current filters.
        format=csv (default) | json | jsonl | xlsx
        """
        drain_into_buffer()

        include_info = (request.args.get("include_info") or "").lower() in ("1", "true", "yes")
        q = (request.args.get("q") or "").lower().strip()
        lvls = [x for x in (request.args.get("levels") or "").lower().split(",") if x]
        fmt = (request.args.get("format") or "csv").lower()
        def pass_filters(ev: dict[str, Any]) -> bool:
            lvl = (ev.get("level") or "info").lower()
            if lvl == "info" and not include_info:
                return False
            if lvls and lvl not in lvls:
                return False
            if q:
                s = f"{ev.get('reason','')} {ev.get('source','')} {ev.get('name','')} {ev.get('pid','')} {ev.get('path','')}"
                if q not in s.lower():
                    return False
            return True

        rows = [ev for ev in BUFFER if pass_filters(ev)]

        # JSONL
        if fmt == "jsonl":
            lines = [json.dumps(ev, ensure_ascii=False) for ev in rows]
            resp = make_response("\n".join(lines))
            resp.headers["Content-Type"] = "application/x-ndjson"
            resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_export.jsonl"'
            return resp

        # JSON
        if fmt == "json":
            resp = make_response(json.dumps(rows, ensure_ascii=False, indent=2))
            resp.headers["Content-Type"] = "application/json"
            resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_export.json"'
            return resp

        # common tabular cols
        cols = [
            "ts", "level", "reason", "source", "pid", "name", "path",
            "csc_verdict", "csc_class", "csc_confidence"
        ]

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
                "csc_verdict": r.get("csc_verdict", "unknown"),
                "csc_class": r.get("csc_class", "unknown"),
                "csc_confidence": float(r.get("csc_confidence", 0.5)),
                "children": [build(c) for c in sorted(children.get(pid, []))[:CFG.max_tree_children]],
            }

        tree = [build(p) for p in sorted(roots)[:CFG.max_tree_roots]]

        fmt = (request.args.get("as") or "").lower()
        if fmt == "json":
            resp = make_response(json.dumps(tree, indent=2, ensure_ascii=False))
            resp.headers["Content-Type"] = "application/json"
            resp.headers["Content-Disposition"] = 'attachment; filename="custoseye_proctree.json"'
            return resp

        # default inline JSON
        return jsonify(tree)

    @app.get("/api/about")
    def about():
        version = "-"
        build = "-"
        vpath = BASE_DIR / "VERSION.txt"
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

        # ---------------- integrity endpoints ----------------

    @app.get("/api/integrity/targets")
    def api_integrity_targets_get():
        # return normalized list
        return jsonify(_read_integrity_targets())

    @app.post("/api/integrity/targets")
    def api_integrity_targets_post():
        """
        body: { path, rule, note? }
        rule: "sha256" | "mtime+size"
        behavior: if rule == "sha256" and no baseline stored yet, auto-hash now to set baseline.
        """
        try:
            body = request.get_json(force=True) or {}
            path = str(body.get("path") or "").strip()
            rule = str(body.get("rule") or "sha256").strip().lower()
            note = str(body.get("note") or "").strip()
            if not path:
                return jsonify({"ok": False, "error": "missing path"}), 400
            if rule not in ("sha256", "mtime+size"):
                return jsonify({"ok": False, "error": "invalid rule"}), 400

            rows = _read_integrity_targets()

            # update or insert
            target = None
            for r in rows:
                if str(r.get("path") or "").lower() == path.lower():
                    target = r
                    break
            if target is None:
                target = {"path": path, "rule": rule}
                if note != "":
                    target["note"] = note
                else:
                    # allow clearing the note explicitly with empty string
                    if "note" in target:
                        del target["note"]
                rows.append(target)
            else:
                target["path"] = path  # keep users original text (env vars allowed)
                target["rule"] = rule
                if note != "":
                    target["note"] = note
                else:
                    # allow clearing the note explicitly with empty string
                    if "note" in target:
                        del target["note"]

            # auto-baseline for sha256 if missing
            if rule == "sha256" and not target.get("sha256"):
                info = _sha256_file(path)
                if info.get("sha256"):
                    target["sha256"] = info["sha256"]
                    target["last_result"] = "OK (baseline set)"
                else:
                    # leave baseline empty; UI can re-hash later
                    target["last_result"] = f"ERR: {info.get('error', 'hash failed')}"

            # auto-baseline for mtime+size if missing
            if rule == "mtime+size" and (not target.get("mtime") or not target.get("size")):
                try:
                    st = os.stat(_norm_user_path(path))
                    target["mtime"] = int(st.st_mtime)
                    target["size"] = int(st.st_size)
                    target["last_result"] = "OK (baseline set)"
                except Exception as e:
                    target["last_result"] = f"ERR: {e}"

            _write_integrity_targets(rows)
            return jsonify({"ok": True})

        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.delete("/api/integrity/targets")
    def api_integrity_targets_delete():
        try:
            body = request.get_json(force=True) or {}
            path = str(body.get("path") or "").strip()
            if not path:
                return jsonify({"ok": False, "error": "missing path"}), 400
            rows = _read_integrity_targets()
            rows2 = [r for r in rows if str(r.get("path") or "").lower() != path.lower()]
            _write_integrity_targets(rows2)
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/integrity/hash")
    def api_integrity_hash():
        """
        computes SHA-256 and updates stored target:
          - sets last_result to OK/CHANGED/ERR
          - if baseline missing and rule == sha256, promote this hash to baseline
        """
        try:
            body = request.get_json(force=True) or {}
            path = str(body.get("path") or "").strip()
            if not path:
                return jsonify({"error": "missing path"}), 400

            info = _sha256_file(path)  # handles normalization internally
            rows = _read_integrity_targets()

            # update corresponding row if present
            changed = False
            for r in rows:
                if str(r.get("path") or "").lower() == path.lower():
                    rule = str(r.get("rule") or "sha256").lower()
                    baseline = str(r.get("sha256") or "")
                    if "error" in info:
                        r["last_result"] = f"ERR: {info['error']}"
                    else:
                        new_hash = info.get("sha256", "")
                        if rule == "sha256":
                            if not baseline:
                                r["sha256"] = new_hash
                                r["last_result"] = "OK (baseline set)"
                            else:
                                r["last_result"] = "OK" if baseline == new_hash else "CHANGED"
                        else:
                            # mtime+size rule — compare against baseline (or set it if missing)
                            try:
                                st = os.stat(_norm_user_path(path))
                                cur_mtime = int(st.st_mtime)
                                cur_size = int(st.st_size)
                                if not r.get("mtime") or not r.get("size"):
                                    r["mtime"], r["size"] = cur_mtime, cur_size
                                    r["last_result"] = "OK (baseline set)"
                                else:
                                    r["last_result"] = (
                                        "OK"
                                        if (r["mtime"] == cur_mtime and r["size"] == cur_size)
                                        else "CHANGED"
                                    )
                            except Exception as e:
                                r["last_result"] = f"ERR: {e}"
                    changed = True
                    break

            if changed:
                _write_integrity_targets(rows)

            # return raw info for the alert preview
            return jsonify(info)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/integrity/browse")
    def api_integrity_browse():
        """
        windows-only file picker via tkinter. returns {"path": "..."} or {} if cancelled.
        we keep it very small and guarded. it will no-op on non-Windows.
        """
        try:
            if sys.platform != "win32":
                return jsonify({"error": "browse supported on Windows only"}), 400
            # late imports to avoid importing Tk on non-Windows
            import tkinter as _tk  # type: ignore
            from tkinter import filedialog as _fd  # type: ignore

            root = _tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)  # bring dialog front
            sel = _fd.askopenfilename(title="Select a file to watch")
            try:
                root.destroy()
            except Exception:
                pass
            if sel:
                return jsonify({"path": sel})
            return jsonify({})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app


def run_dashboard(event_bus) -> None:
    app = build_app(event_bus)
    if app is None:
        raise RuntimeError(
            "build_app() returned None; check for exceptions or missing `return app`."
        )
    if HAVE_WAITRESS:
        _serve(app, host=CFG.host, port=CFG.port)
    else:
        app.run(host=CFG.host, port=CFG.port, debug=False)


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
            targets_path=INTEGRITY_TARGETS_PATH,
            publish=bus.publish,
            interval_sec=5.0,
        ).run,
    ):
        threading.Thread(target=target, daemon=True).start()

    run_dashboard(bus)
