# ruff: noqa: E501
"""
goal: Local Flask dashboard for CustosEye — live telemetry, trust-aware process tree, and
       privacy-preserving file-integrity baselining/diff. Fast, simple, offline.

Highlights (this build):
1) Event ingestion & performance
   • Fan-out subscription to a shared EventBus; lightweight /api/ping keeps drains moving.
   • Bounded ring buffer with fingerprint-based coalescing and “worse event” promotion.
   • Guardrails: per-call drain cap + short deadlines + a drain lock to avoid concurrent drains.

2) UI surface
   • Tabs: Live Events, Process Tree, About. Terminal only prints “welcome + URL”.
   • Static assets (favicon + Apple touch icons) are routed and PyInstaller-friendly.

3) Live event stream
   • Level filters (Info/Warning/Critical), free-text search, pause/refresh (client-side).
   • Export current view as CSV / JSON / JSONL / XLSX (Excel-friendly BOM/quoting; auto-sized XLSX).
   • Noise control: drop network events that lack pid/name; self-suppression by name/exe/sha256.

4) Trust overlay (v2)
   • CSCTrustEngine v2 (weights/db from config) scores processes; fields land on rows and in tree:
     csc_verdict / csc_class / csc_confidence (+ reasons/signals blob).
   • Fast-paths: kernel/idle/registry are auto-trusted; optional name_trust.json heuristic map.
   • RulesEngine still evaluates non-integrity events for level/reason tagging (hot-reloaded).

5) Process tree
   • Compact PPID→PID hierarchy (native <details> in UI). Caps for roots/children from config.
   • Trust labels/score propagate to each node. Export pretty JSON via /api/proctree?as=json.

6) Integrity watch list & hashing
   • CRUD: /api/integrity/targets GET/POST/DELETE (paths + rule="sha256" | "mtime+size" + note).
   • Auto-baseline on first hash (sha256 or mtime+size). Emits live integrity events (OK/CHANGED/ERR).
   • Per-chunk baseline hashes for diffs (algo, chunk_size, size, hashes).
   • Optional content-addressed baseline snapshot (ALLOW_MTIME_SNAPSHOTS) with size-cap pruning and
     download endpoint (/api/integrity/baseline/download?path=…).

7) Privacy-preserving diff (Office-aware)
   • /api/integrity/diff returns only: changed chunk ranges, tiny “after” previews (hex+ASCII),
     and an estimated % changed.
   • Office docs (docx/xlsx/pptx) use a ZIP member manifest (added/removed/modified) to estimate
     change without 100% spikes from repacking.

8) Quality-of-life
   • Windows-only file picker (/api/integrity/browse) to add targets.
   • About endpoint reads VERSION.txt (version/build/buffer_max).
   • Config-driven paths/limits (rules_path, csc weights/db, integrity targets, self-suppress list).

9) Packaging/runtime
   • Optional Waitress serve; otherwise Flask dev server (debug off).
   • Base dir and data paths resolve cleanly under PyInstaller bundles.

"""

from __future__ import annotations

# --- standard library ---
import csv
import hashlib
import io
import json
import os
import sys
import threading
import time
import zipfile
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any, TypedDict, cast

# --- third-party ---
from flask import (
    Flask,
    jsonify,
    make_response,
    render_template,
    request,
    send_file,
)

# --- local/project imports (move these up here) ---
from agent.rules_engine import RulesEngine
from algorithm.csc_engine import CSCTrustEngine  # v2 under the hood
from dashboard.config import Config, load_config


# (now we can define classes/variables/etc.)
class RecentMeta(TypedDict, total=False):
    ref: dict[str, Any]
    seen: int
    last_seen: float


# single waitress optional block (we keep only this one, after all imports)
try:
    from waitress import serve as _serve

    HAVE_WAITRESS = True
except Exception:
    HAVE_WAITRESS = False
    _serve = None  # type: ignore

CFG: Config = load_config()

ALLOW_MTIME_SNAPSHOTS: bool = bool(getattr(CFG, "allow_mtime_snapshots", True))

# ---------------- Config / paths ----------------
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
    ev["csc"] = {
        "version": "v2",
        "verdict": v,
        "cls": cls,
        "confidence": conf,
        "reasons": ["name+parent heuristic"],
        "signals": {},
    }
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

# --- dedupe/coalesce guard for live events ---
RECENT_TTL = 15.0  # seconds
RECENT_MAP: dict[str, RecentMeta] = {}  # fp -> {"ref": ev_dict, "seen": int, "last_seen": float}

_SEV_RANK = {"info": 0, "warning": 1, "critical": 2}
_VERDICT_RANK = {"trusted": 0, "caution": 1, "suspicious": 2, "malicious": 3, "unknown": 1}


def _fingerprint_base(ev: dict) -> str:
    key_fields = ("source", "reason", "pid", "name", "path", "rule")
    return json.dumps({k: ev.get(k) for k in key_fields}, sort_keys=True, ensure_ascii=False)


def _is_worse(prev: dict, cur: dict) -> bool:
    pl = _SEV_RANK.get(str(prev.get("level", "info")).lower(), 0)
    cl = _SEV_RANK.get(str(cur.get("level", "info")).lower(), 0)
    if cl > pl:
        return True

    pv = str(prev.get("csc_verdict", "unknown")).lower()
    cv = str(cur.get("csc_verdict", "unknown")).lower()
    if _VERDICT_RANK.get(cv, 1) > _VERDICT_RANK.get(pv, 1):
        return True
    if str(prev.get("csc_class", "")) != str(cur.get("csc_class", "")):
        return True
    try:
        if abs(float(cur.get("csc_confidence", 0)) - float(prev.get("csc_confidence", 0))) >= 0.05:
            return True
    except Exception:
        pass

    if (prev.get("source") == "integrity") or (cur.get("source") == "integrity"):
        if str(prev.get("last_result", "")) != str(cur.get("last_result", "")):
            return True
        if (
            str(cur.get("rule", "")).lower() == "sha256"
            and cur.get("sha256")
            and prev.get("sha256")
            and str(cur.get("sha256")).upper() != str(prev.get("sha256")).upper()
        ):
            return True

    return False


def _coalesce_or_admit(ev: dict) -> bool:
    """
    Returns True to append ev to BUFFER, False if merged into a recent one.
    Keeps a single representative event within RECENT_TTL unless the new event is 'worse'.
    """
    now = time.time()
    # prune expired
    for k, rec in list(RECENT_MAP.items()):  # <— renamed from `entry`
        if now - float(rec.get("last_seen", 0)) > RECENT_TTL:
            RECENT_MAP.pop(k, None)

    fp = _fingerprint_base(ev)
    hit: RecentMeta | None = RECENT_MAP.get(fp)  # <— distinct name

    if hit is None:
        ev["seen"] = 1
        RECENT_MAP[fp] = {"ref": ev, "seen": 1, "last_seen": now}
        return True

    prev: dict[str, Any] = hit["ref"]

    # admit if the new one is worse (higher severity, worse verdict/class/conf)
    if _is_worse(prev, ev):
        ev["seen"] = 1
        RECENT_MAP[fp] = {"ref": ev, "seen": 1, "last_seen": now}
        return True

    # otherwise coalesce
    hit["seen"] = int(hit.get("seen", 1)) + 1
    hit["last_seen"] = now
    prev["seen"] = hit["seen"]
    prev["ts"] = ev.get("ts", now)  # keep the displayed timestamp fresh
    return False


DRAIN_LIMIT_PER_CALL = CFG.drain_limit_per_call
DRAIN_DEADLINE_SEC = CFG.drain_deadline_sec

_DRAIN_LOCK = threading.Lock()  # to prevent concurrent drains


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


# ----- Integrity: chunk hashing + diff utilities -----
def _chunk_hashes(path: str, chunk_size: int = 4096) -> dict[str, Any]:
    # compute sha256 for each fixed-size chunk to enable region-level diffs
    p = _norm_user_path(path)  # normalize the path
    try:
        st = os.stat(p)  # stat to get size quickly
        total = int(st.st_size)  # total file size in bytes
    except Exception as e:
        return {"error": f"stat failed: {e}"}  # bubble error to caller

    hashes: list[str] = []  # per-chunk hex digests
    try:
        with open(p, "rb") as f:  # open file in binary
            while True:
                chunk = f.read(chunk_size)  # read a fixed-size block
                if not chunk:  # EOF
                    break
                h = hashlib.sha256()  # use sha256 for consistency
                h.update(chunk)  # hash the chunk
                hashes.append(h.hexdigest().upper())  # store uppercase hex
    except Exception as e:
        return {"error": f"read failed: {e}"}  # I/O errors return gracefully

    return {
        "algo": "sha256",  # hashing algorithm
        "chunk_size": int(chunk_size),  # size of each chunk in bytes
        "size": total,  # total size at time of baselining
        "hashes": hashes,  # list of per-chunk digests
    }


def _short_hex(s: str, left: int = 8, right: int = 6) -> str:
    # shorten long hex strings for UI readability
    if not s:
        return ""
    if len(s) <= left + right + 1:
        return s
    return f"{s[:left]}…{s[-right:]}"


def _merge_changed_chunks(changed_idxs: list[int]) -> list[tuple[int, int]]:
    # merge consecutive chunk indexes into ranges [start_idx, end_idx] inclusive
    if not changed_idxs:
        return []
    ranges: list[tuple[int, int]] = []
    start = prev = changed_idxs[0]
    for idx in changed_idxs[1:]:
        if idx == prev + 1:
            prev = idx
            continue
        ranges.append((start, prev))
        start = prev = idx
    ranges.append((start, prev))
    return ranges


def _read_region_preview(path: str, start: int, length: int, cap: int = 64) -> bytes:
    # return up to `cap` bytes from the start of a region to preview "after" content
    p = _norm_user_path(path)
    try:
        with open(p, "rb") as f:
            f.seek(max(0, start))  # guard negative offsets
            return f.read(max(0, min(cap, length)))  # clamp to [0, cap]
    except Exception:
        return b""  # on error, no preview


def _zip_manifest(path: str) -> dict[str, dict[str, int]]:
    """
    If file is a ZIP, return { member_name: {size, crc, date} }.
    CRC is stored as unsigned int; date is an int like YYYYMMDD.
    If not ZIP or on error, return {}.
    """
    p = _norm_user_path(path)
    try:
        with open(p, "rb") as f:
            sig = f.read(4)
        if sig != b"PK\x03\x04":
            return {}
    except Exception:
        return {}

    out: dict[str, dict[str, int]] = {}
    try:
        with zipfile.ZipFile(p, "r") as zf:
            for zi in zf.infolist():
                # crc is already computed by the ZipInfo; convert to unsigned 32
                crc = zi.CRC & 0xFFFFFFFF
                # ZipInfo.date_time -> (Y, M, D, h, m, s)
                y, m, d = zi.date_time[:3]
                date = y * 10000 + m * 100 + d
                out[zi.filename] = {"size": zi.file_size, "crc": int(crc), "date": int(date)}
    except Exception:
        return {}
    return out


def _nl_file_kind(path: str) -> str:
    p = (path or "").lower()
    if p.endswith((".pptx", ".ppt")):
        return "PowerPoint"
    if p.endswith((".docx", ".doc")):
        return "Word document"
    if p.endswith((".xlsx", ".xls")):
        return "Excel workbook"
    if p.endswith((".pdf",)):
        return "PDF"
    if p.endswith((".txt", ".log")):
        return "text file"
    if p.endswith(
        (
            ".py",
            ".js",
            ".ts",
            ".c",
            ".cpp",
            ".cs",
            ".java",
            ".rb",
            ".rs",
            ".go",
            ".php",
            ".sh",
            ".ps1",
            ".r",
            ".m",
            ".scala",
            ".kt",
        )
    ):
        return "source code"
    return "file"


def _nl_summary_for_diff(
    path: str,
    approx_bytes_changed: int,
    percent: float,
    ranges: list[tuple[int, int]],
    zip_changes: list[dict[str, Any]],
    chunk_size: int,
    base_size: int,
    cur_size: int,
) -> dict[str, str]:
    """Return {'headline': str, 'details': str}"""
    kind = _nl_file_kind(path)
    # Headline
    if approx_bytes_changed == 0 and not zip_changes:
        headline = f"No differences detected in the {kind}."
        return {"headline": headline, "details": ""}

    # Zip member changes summary
    added = [z for z in zip_changes if z.get("change") == "added"]
    removed = [z for z in zip_changes if z.get("change") == "removed"]
    modified = [z for z in zip_changes if z.get("change") == "modified"]

    chunk_regions = len(ranges)
    headline = f"{kind.capitalize()} changed ~{percent:.2f}% ({approx_bytes_changed} bytes)."

    parts: list[str] = []
    # File sizes
    if base_size and cur_size and base_size != cur_size:
        delta = cur_size - base_size
        sign = "+" if delta >= 0 else ""
        parts.append(f"Size: {base_size} → {cur_size} bytes ({sign}{delta}).")

    # Regions by chunks
    if chunk_regions:
        total_chunks = 0
        for s, e in ranges:
            total_chunks += e - s + 1
        parts.append(
            f"Changed regions: {chunk_regions} ({total_chunks} chunk(s) of {chunk_size} bytes)."
        )

    # Office containers (docx/xlsx/pptx)
    if zip_changes:
        a, r, m = len(added), len(removed), len(modified)
        bits = []
        if a:
            bits.append(f"{a} added")
        if r:
            bits.append(f"{r} removed")
        if m:
            bits.append(f"{m} modified")
        parts.append("ZIP members: " + ", ".join(bits) + ".")

    # Heuristics by type
    if kind in ("PowerPoint", "Word document", "Excel workbook"):
        if zip_changes and modified:
            parts.append("Likely content edits to internal parts (slides, document XML, or media).")
        elif zip_changes and (added or removed):
            parts.append("Likely added or removed embedded media, slides, or sheets.")
        else:
            parts.append("Container changed; content may have been edited or metadata updated.")
    elif kind == "PDF":
        parts.append("Binary regions changed; could be page content or metadata.")
    elif kind == "source code":
        parts.append("Code regions changed; review in your VCS for exact lines.")
    elif kind == "text file":
        parts.append("Text content changed; open in a diff tool for exact lines.")

    details = " ".join(parts)
    return {"headline": headline, "details": details}


# -------- Baseline snapshot storage (content-addressed) --------
BASELINES_DIR = str((BASE_DIR / "data" / "baselines").resolve())
BASELINES_MAX_BYTES: int = int(getattr(CFG, "baselines_max_bytes", 1_000_000_000))  # ~1 GB default


def _shard_dir_from_hex(h: str) -> str:
    # shard to avoid huge directories
    return os.path.join(BASELINES_DIR, h[:2], h[2:4], h)


def _snapshot_file_to_cas(src_path: str) -> dict[str, Any]:
    """
    Save the *bytes* of src_path into content-addressed storage by SHA-256.
    Returns a metadata dict suitable for storing in target["baseline_blob"].
    """
    src = _norm_user_path(src_path)
    st = os.stat(src)
    size = int(st.st_size)

    h = hashlib.sha256()
    with open(src, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    sha = h.hexdigest().upper()

    dst_root = _shard_dir_from_hex(sha)
    os.makedirs(dst_root, exist_ok=True)

    fname = os.path.basename(src_path) or sha
    dst_path = os.path.join(dst_root, fname)

    if not os.path.exists(dst_path):
        tmp = dst_path + ".tmp"
        with open(src, "rb") as rf, open(tmp, "wb") as wf:
            for chunk in iter(lambda: rf.read(1024 * 1024), b""):
                wf.write(chunk)
        os.replace(tmp, dst_path)

    return {
        "sha256": sha,
        "size": size,
        "stored_path": dst_path,
        "created_at": int(time.time()),
    }


def _validate_cas_blob(blob: dict[str, Any]) -> bool:
    try:
        p = blob.get("stored_path")
        if not p or not os.path.exists(p):
            return False
        if int(os.path.getsize(p)) != int(blob.get("size", -1)):
            return False
        # Optional: verify hash matches
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest().upper() == str(blob.get("sha256", "")).upper()
    except Exception:
        return False


def _maybe_prune_baselines() -> None:
    """
    Keep total size of BASELINES_DIR under BASELINES_MAX_BYTES.
    Deletes oldest files first. Called after adding new baseline blobs.
    """
    try:
        files: list[tuple[str, float, int]] = []
        total_size = 0

        # Walk recursively and collect all baseline files
        for root, _dirs, fnames in os.walk(BASELINES_DIR):
            for fn in fnames:
                p = os.path.join(root, fn)
                try:
                    st = os.stat(p)
                    total_size += st.st_size
                    files.append((p, st.st_mtime, st.st_size))
                except Exception:
                    continue

        # If we’re over the cap, remove oldest files until under limit
        if total_size > BASELINES_MAX_BYTES:
            files.sort(key=lambda x: x[1])  # oldest first
            for p, _mtime, sz in files:
                try:
                    os.remove(p)
                    total_size -= sz
                    if total_size <= BASELINES_MAX_BYTES:
                        break
                except Exception:
                    pass
    except Exception:
        pass


# ---------------- Flask app build ----------------
def build_app(event_bus) -> Flask:
    app = Flask(__name__)

    # make sure our iterator type is clear for mypy
    _iter: Iterator[dict[str, Any]] = _bus_iterator(event_bus)

    # publisher helper used to push live events immediately
    def _publish(ev: dict[str, Any]) -> None:
        try:
            if hasattr(event_bus, "publish"):
                event_bus.publish(ev)  # preferred
            else:
                # fallback: push into BUFFER so it appears right away
                BUFFER.append(ev)
        except Exception:
            # never break the request on failed publish
            pass

    def _emit_integrity_event(path: str, status: str, rule: str) -> None:
        """
        Push an integrity-related event into the live event stream.
        Used by /api/integrity/hash so that users see CHANGED/OK immediately.
        """
        lvl = "info"
        s = (status or "").upper()
        if s.startswith("CHANGED"):
            lvl = "critical"
        elif s.startswith("ERR"):
            lvl = "warning"

        ev = {
            "source": "integrity",
            "level": lvl,
            "reason": f"integrity {status or 'update'}",
            "path": path,
            "rule": rule,
            "ts": time.time(),
            "name": os.path.basename(path) if path else "",
        }
        _publish(ev)

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
                    continue  # dont exit early; keep trying until deadline

                ev.setdefault("level", "info")
                ev.setdefault("reason", "event")
                ev.setdefault("ts", time.time())

                if ev.get("source") != "integrity":
                    # makes sure we always have a dict for mypy and runtime safety
                    decision: dict[str, Any] = cast(dict[str, Any], _rules.evaluate(ev) or {})
                    ev["level"] = decision.get("level", ev.get("level"))
                    ev["reason"] = decision.get("reason", ev.get("reason"))

                if ev.get("source") == "process":
                    # --- suppress our own process(es) before any scoring or tree updates ---
                    nm_lc = str(ev.get("name") or "").lower()
                    ex_lc = str(ev.get("exe") or "").lower()
                    h_lc = str(ev.get("sha256") or "").lower()
                    if (
                        (nm_lc and nm_lc in SELF_SUPPRESS["names"])
                        or (ex_lc and ex_lc in SELF_SUPPRESS["exes"])
                        or (h_lc and h_lc in SELF_SUPPRESS["sha256"])
                    ):
                        continue  # skip buffering and tree indexing entirely

                    # --- trust scoring: name-based fast-path, then kernel/idle/registry, then model ---
                    pid = ev.get("pid")
                    nm = str(ev.get("name") or "")

                    # 1) known-good names (your NAME_TRUST map)
                    if _maybe_promote_to_trusted(ev):
                        pass  # already set by the heuristic

                    # 2) kernel/idle/registry fast-path
                    elif pid in (0, 4) or nm.lower() in (
                        "system",
                        "system idle process",
                        "registry",
                    ):
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

                # --- integrity name fill ---
                if ev.get("source") == "integrity":
                    p = ev.get("path") or ev.get("file")
                    if p and not ev.get("name"):
                        try:
                            ev["name"] = os.path.basename(str(p))
                        except Exception:
                            ev["name"] = str(p)

                # --- safe coalesce (don’t drop worse events) ---
                if _coalesce_or_admit(ev):
                    BUFFER.append(ev)
                    drained += 1
                # else: merged into a recent identical event; no append

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
            "ts",
            "level",
            "reason",
            "source",
            "pid",
            "name",
            "path",
            "csc_verdict",
            "csc_class",
            "csc_confidence",
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
                "children": [
                    build(c) for c in sorted(children.get(pid, []))[: CFG.max_tree_children]
                ],
            }

        tree = [build(p) for p in sorted(roots)[: CFG.max_tree_roots]]

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
            body: dict[str, Any] = cast(dict[str, Any], request.get_json(force=True) or {})
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
                    if ALLOW_MTIME_SNAPSHOTS:
                        try:
                            target["baseline_blob"] = _snapshot_file_to_cas(path)
                            _maybe_prune_baselines()
                        except Exception as e:
                            target["baseline_blob"] = {"error": str(e)}
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
                    if ALLOW_MTIME_SNAPSHOTS:
                        try:
                            target["baseline_blob"] = _snapshot_file_to_cas(path)
                            _maybe_prune_baselines()
                        except Exception as e:
                            target["baseline_blob"] = {"error": str(e)}
                except Exception as e:
                    target["last_result"] = f"ERR: {e}"

            # build / refresh chunk baseline for diffs (both rules benefit)
            # note: we don't persist file content, only per-chunk hashes
            info_chunks = _chunk_hashes(path)
            if "error" not in info_chunks:
                target["chunks"] = info_chunks  # algo, chunk_size, size, hashes
            else:
                # leave chunks absent if we couldn't read; UI can re-baseline later
                target.pop("chunks", None)

            # If it's a ZIP (docx, xlsx, etc), store a member manifest for friendlier diffs
            zman = _zip_manifest(path)
            if zman:
                target["zip_manifest"] = zman
            else:
                target.pop("zip_manifest", None)

            _write_integrity_targets(rows)
            return jsonify({"ok": True})

        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.delete("/api/integrity/targets")
    def api_integrity_targets_delete():
        try:
            body: dict[str, Any] = cast(dict[str, Any], request.get_json(force=True) or {})
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
        - sets last_result to OK or CHANGED or ERR
        - if baseline missing and rule == sha256, promote this hash to baseline
        - also ensures we have a per chunk baseline so "View changes" can work
        """
        try:
            body: dict[str, Any] = cast(
                dict[str, Any], request.get_json(force=True) or {}
            )  # parse JSON body
            path = str(body.get("path") or "").strip()  # normalize to a simple string
            if not path:
                return jsonify({"error": "missing path"}), 400  # hard fail if no path

            info = _sha256_file(path)  # compute current file hash and attrs
            rows = _read_integrity_targets()  # load current targets file
            changed = False  # track if we modified the stored record

            # update corresponding row if present
            for r in rows:
                if (
                    str(r.get("path") or "").lower() == path.lower()
                ):  # match on case-insensitive path
                    rule = str(r.get("rule") or "sha256").lower()  # either "sha256" or "mtime+size"
                    baseline = str(r.get("sha256") or "")  # baseline hash if present

                    if "error" in info:
                        # hashing failed, record the error but do not change baselines
                        r["last_result"] = f"ERR: {info['error']}"
                        changed = True
                        _emit_integrity_event(path, r["last_result"], rule)
                    else:
                        new_hash = info.get("sha256", "")  # current SHA-256 hex
                        if rule == "sha256":
                            if not baseline:
                                # first time, promote to baseline
                                r["sha256"] = new_hash
                                r["last_result"] = "OK (baseline set)"
                                changed = True
                                _emit_integrity_event(path, r["last_result"], rule)
                                if ALLOW_MTIME_SNAPSHOTS:
                                    try:
                                        r["baseline_blob"] = _snapshot_file_to_cas(path)
                                        _maybe_prune_baselines()
                                    except Exception as e:
                                        r["baseline_blob"] = {"error": str(e)}
                            else:
                                # simple equality check against baseline
                                r["last_result"] = "OK" if baseline == new_hash else "CHANGED"
                                changed = True
                                _emit_integrity_event(path, r["last_result"], rule)
                        else:
                            # mtime+size rule, compare against or establish baseline
                            try:
                                st = os.stat(_norm_user_path(path))
                                cur_mtime = int(st.st_mtime)
                                cur_size = int(st.st_size)
                                if not r.get("mtime") or not r.get("size"):
                                    # no baseline yet, establish it now
                                    r["mtime"], r["size"] = cur_mtime, cur_size
                                    r["last_result"] = "OK (baseline set)"
                                    changed = True
                                    _emit_integrity_event(path, r["last_result"], rule)
                                    if ALLOW_MTIME_SNAPSHOTS:
                                        try:
                                            r["baseline_blob"] = _snapshot_file_to_cas(path)
                                            _maybe_prune_baselines()
                                        except Exception as e:
                                            r["baseline_blob"] = {"error": str(e)}
                                else:
                                    # compare to existing baseline
                                    r["last_result"] = (
                                        "OK"
                                        if (r["mtime"] == cur_mtime and r["size"] == cur_size)
                                        else "CHANGED"
                                    )
                                    changed = True
                                    _emit_integrity_event(path, r["last_result"], rule)
                            except Exception as e:
                                r["last_result"] = f"ERR: {e}"
                                _emit_integrity_event(path, r["last_result"], rule)
                                changed = True

                    # ensure we have per chunk baseline so the diff endpoint can work
                    # we only store per chunk hashes, not content
                    if "error" not in info:
                        need_chunks = "chunks" not in r or not isinstance(
                            r.get("chunks", {}).get("hashes"), list
                        )
                        if need_chunks:
                            ch = _chunk_hashes(path)  # build per chunk baseline
                            if "error" not in ch:
                                r["chunks"] = ch  # algo, chunk_size, size, hashes
                                changed = True

                        # Only capture zip_manifest when (and only when) we establish a baseline
                        if "error" not in info:
                            if (rule == "sha256" and not baseline) or (
                                rule == "mtime+size" and (not r.get("mtime") or not r.get("size"))
                            ):
                                zman = _zip_manifest(path)
                                if zman:
                                    r["zip_manifest"] = zman
                                    changed = True

                    break  # stop after the first matching record

            # if we edited anything, persist the targets file
            if changed:
                _write_integrity_targets(rows)
            if changed:
                # find the updated row again to read last_result
                for r in rows:
                    if str(r.get("path") or "").lower() == path.lower():
                        info["last_result"] = r.get("last_result", "")
                        info["rule"] = r.get("rule", "")
                        break

            # return raw info for the alert preview in UI
            return jsonify(info)

        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.post("/api/integrity/diff")
    def api_integrity_diff():
        """
        Privacy-preserving diff between baseline chunk hashes and the current file.

        We never return file contents, only:
        - which chunk ranges changed (by chunk-hash),
        - tiny 'after' previews (hex + ASCII) capped per region.

        Percent logic:
        - For ZIP-based Office files (docx/xlsx/pptx), estimate change from ZIP
            member deltas (added/removed = size, modified = abs(size diff), or a
            small cap when only CRC differs). Ignore the chunk-floor here to avoid
            100% spikes from container re-packing.
        - For non-ZIP files, fall back to chunk-region coverage as before.
        """
        try:
            body: dict[str, Any] = cast(dict[str, Any], request.get_json(force=True) or {})
            path = str(body.get("path") or "").strip()
            max_regions = int(body.get("max_regions") or 50)
            preview_cap = int(body.get("preview_bytes") or 64)

            if not path:
                return jsonify({"ok": False, "error": "missing path"}), 400

            # Find target + baseline chunks
            rows = _read_integrity_targets()
            target = next(
                (r for r in rows if str(r.get("path") or "").lower() == path.lower()), None
            )
            if target is None:
                return jsonify({"ok": False, "error": "not on watch list"}), 400

            baseline = target.get("chunks")
            if not baseline or not isinstance(baseline.get("hashes"), list):
                return jsonify({"ok": False, "error": "no baseline chunks available"}), 400

            # Current per-chunk hashes
            cur = _chunk_hashes(path)
            if "error" in cur:
                return jsonify({"ok": False, "error": cur["error"]}), 400

            base_hashes = list(baseline.get("hashes") or [])
            cur_hashes = list(cur.get("hashes") or [])
            chunk_size = int(cur.get("chunk_size") or baseline.get("chunk_size") or 4096)
            base_size = int(baseline.get("size") or 0)
            cur_size = int(cur.get("size") or 0)

            # ----- ZIP member-level comparison (for docx/xlsx/pptx) -----
            zip_before = target.get("zip_manifest") or {}
            zip_after = _zip_manifest(path)
            zip_changes: list[dict[str, Any]] = []

            if zip_after or zip_before:
                before_keys = set(zip_before.keys())
                after_keys = set(zip_after.keys())
                added = sorted(after_keys - before_keys)
                removed = sorted(before_keys - after_keys)
                common = sorted(before_keys & after_keys)

                for k in added:
                    z = zip_after[k]
                    zip_changes.append(
                        {"member": k, "change": "added", "size": z["size"], "crc": z["crc"]}
                    )
                for k in removed:
                    z = zip_before[k]
                    zip_changes.append(
                        {"member": k, "change": "removed", "size": z["size"], "crc": z["crc"]}
                    )
                for k in common:
                    a, b = zip_after[k], zip_before[k]
                    if a["size"] != b["size"] or a["crc"] != b["crc"]:
                        zip_changes.append(
                            {
                                "member": k,
                                "change": "modified",
                                "size_before": b["size"],
                                "size_after": a["size"],
                                "crc_before": b["crc"],
                                "crc_after": a["crc"],
                            }
                        )

            # ----- Identify changed chunk indices (for regions UI only) -----
            max_len = max(len(base_hashes), len(cur_hashes))
            changed_idxs: list[int] = []
            for i in range(max_len):
                old = base_hashes[i] if i < len(base_hashes) else None
                new = cur_hashes[i] if i < len(cur_hashes) else None
                if old != new:
                    changed_idxs.append(i)

            ranges = _merge_changed_chunks(changed_idxs)

            # Build regions with offsets and tiny 'after' previews
            regions_out: list[dict[str, Any]] = []
            chunk_floor_bytes = 0
            for start_idx, end_idx in ranges[:max_regions]:
                start_off = start_idx * chunk_size
                end_off = min(cur_size, (end_idx + 1) * chunk_size)
                length = max(0, end_off - start_off)

                old_list = (
                    base_hashes[start_idx : end_idx + 1] if start_idx < len(base_hashes) else []
                )
                new_list = (
                    cur_hashes[start_idx : end_idx + 1] if start_idx < len(cur_hashes) else []
                )

                raw = _read_region_preview(path, start_off, length, cap=preview_cap)
                hex_preview = raw.hex().upper()
                ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)

                regions_out.append(
                    {
                        "chunk_idx_start": start_idx,
                        "chunk_idx_end": end_idx,
                        "start_offset": start_off,
                        "end_offset": end_off,
                        "length": length,
                        "old_chunk_hashes": old_list,
                        "new_chunk_hashes": new_list,
                        "preview": {"bytes": len(raw), "hex": hex_preview, "ascii": ascii_preview},
                    }
                )
                chunk_floor_bytes += length

            # ----- Estimate % changed -----
            # Default: non-ZIP → chunk-floor estimate
            approx_bytes_changed = chunk_floor_bytes
            estimation_method = "chunks"

            if zip_changes:
                # For Office containers, use only ZIP delta for the %.
                # This avoids "100%" when the whole archive gets re-packed.
                changed_zip_bytes = 0
                for z in zip_changes:
                    ch = (z.get("change") or "").lower()
                    if ch == "added":
                        changed_zip_bytes += int(z.get("size", 0))
                    elif ch == "removed":
                        changed_zip_bytes += int(z.get("size", 0))
                    elif ch == "modified":
                        sb = int(z.get("size_before", 0))
                        sa = int(z.get("size_after", 0))
                        delta = abs(sa - sb)
                        if delta == 0 and z.get("crc_before") != z.get("crc_after"):
                            # Same size but different bytes → treat as a tiny content tweak.
                            delta = min(sa, 512)  # cap the tiny edit at 1 KiB
                        changed_zip_bytes += delta

                # In case everything is metadata-only and delta rounds to zero, give a small floor.
                if changed_zip_bytes == 0 and changed_idxs:
                    changed_zip_bytes = min(cur_size, 1024)

                approx_bytes_changed = min(int(changed_zip_bytes), cur_size)
                estimation_method = "zip-members-delta"

            # Percent is always relative to the outer file size users see on disk
            denom = float(max(1, cur_size))
            percent = round((approx_bytes_changed / denom) * 100.0, 2)

            nl = _nl_summary_for_diff(
                path=path,
                approx_bytes_changed=approx_bytes_changed,
                percent=percent,
                ranges=ranges,
                zip_changes=zip_changes,
                chunk_size=chunk_size,
                base_size=base_size,
                cur_size=cur_size,
            )

            out = {
                "ok": True,
                "summary": {
                    "file": path,
                    "changed_chunks": len(changed_idxs),
                    "regions_returned": len(regions_out),
                    "approx_changed_bytes": approx_bytes_changed,
                    "approx_percent_of_file": percent,
                    "chunk_size": chunk_size,
                    "baseline_size": base_size,
                    "current_size": cur_size,
                },
                "estimation_method": estimation_method,  # "zip-members-delta" or "chunks"
                "summary_text": {
                    "headline": nl.get("headline", ""),
                    "details": nl.get("details", ""),
                },
                "zip_changes": zip_changes,
                "regions": regions_out,
            }
            return jsonify(out)

        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.get("/api/integrity/baseline/download")
    def api_integrity_baseline_download():
        """
        Download the stored baseline blob for a given path, if present and valid.
        Query: ?path=<watch-list path>
        """
        try:
            path = (request.args.get("path") or "").strip()
            if not path:
                return jsonify({"ok": False, "error": "missing path"}), 400

            rows = _read_integrity_targets()
            target = next(
                (r for r in rows if str(r.get("path") or "").lower() == path.lower()), None
            )
            if not target:
                return jsonify({"ok": False, "error": "not on watch list"}), 404

            blob = target.get("baseline_blob")
            if not isinstance(blob, dict) or blob.get("error"):
                return jsonify({"ok": False, "error": "no baseline blob available"}), 404

            if not _validate_cas_blob(blob):
                return jsonify({"ok": False, "error": "baseline blob failed validation"}), 409

            p = blob.get("stored_path")
            fname = os.path.basename(p) if p else "baseline.bin"
            return send_file(p, as_attachment=True, download_name=fname)
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

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
