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
import re
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


def _update_live_events_for_path(path: str, acceptance_text: str) -> None:
    """
    Update existing Live Events entries for a given path when baseline is accepted.
    Appends acceptance text to the existing reason, keeping the level as CRITICAL.
    Only updates integrity events related to file changes (not verification events).
    """
    try:
        path_lower = path.lower() if path else ""
        if not path_lower:
            return

        # Update events in BUFFER
        for ev in BUFFER:
            ev_path = str(ev.get("path") or "").lower()
            ev_level = str(ev.get("level") or "").lower()
            ev_reason = str(ev.get("reason") or "")
            ev_reason_lower = ev_reason.lower()

            # Match integrity events for this path that are critical and related to changes
            # Skip if already accepted
            if (
                ev.get("source") == "integrity"
                and ev_path == path_lower
                and ev_level == "critical"
                and not ev.get("accepted", False)
                and (
                    "changed" in ev_reason_lower
                    or "mismatch" in ev_reason_lower
                    or "deleted" in ev_reason_lower
                    or "missing" in ev_reason_lower
                )
            ):
                # Append acceptance text to existing reason, keep level as CRITICAL
                ev["reason"] = ev_reason + " — " + acceptance_text
                # Preserve timestamp and level - don't change them
                # Mark as accepted/approved
                ev["accepted"] = True

        # Update events in RECENT_MAP
        for fp, rec in RECENT_MAP.items():
            ev_ref = rec.get("ref", {})
            ev_path = str(ev_ref.get("path") or "").lower()
            ev_level = str(ev_ref.get("level") or "").lower()
            ev_reason = str(ev_ref.get("reason") or "")
            ev_reason_lower = ev_reason.lower()

            # Match integrity events for this path that are critical and related to changes
            # Skip if already accepted
            if (
                ev_ref.get("source") == "integrity"
                and ev_path == path_lower
                and ev_level == "critical"
                and not ev_ref.get("accepted", False)
                and (
                    "changed" in ev_reason_lower
                    or "mismatch" in ev_reason_lower
                    or "deleted" in ev_reason_lower
                    or "missing" in ev_reason_lower
                )
            ):
                # Append acceptance text to existing reason, keep level as CRITICAL
                ev_ref["reason"] = ev_reason + " — " + acceptance_text
                ev_ref["accepted"] = True
    except Exception:
        # Don't break event processing on update errors
        pass


def _update_live_events_for_hash_verified(path: str) -> None:
    """
    Update existing Live Events entries for a given path when hash is verified.
    Replaces the reason with "✔ Hash verified", keeping the level as CRITICAL.
    Only updates integrity events related to file changes (not verification events).
    """
    try:
        path_lower = path.lower() if path else ""
        if not path_lower:
            return

        # Update events in BUFFER
        for ev in BUFFER:
            ev_path = str(ev.get("path") or "").lower()
            ev_level = str(ev.get("level") or "").lower()
            ev_reason = str(ev.get("reason") or "")
            ev_reason_lower = ev_reason.lower()

            # Match integrity events for this path that are critical and related to changes
            # Skip if already updated to "Hash verified"
            if (
                ev.get("source") == "integrity"
                and ev_path == path_lower
                and ev_level == "critical"
                and "hash verified" not in ev_reason_lower
                and (
                    "changed" in ev_reason_lower
                    or "mismatch" in ev_reason_lower
                    or "deleted" in ev_reason_lower
                    or "missing" in ev_reason_lower
                )
            ):
                # Replace reason with "✔ Hash verified", keep level as CRITICAL
                ev["reason"] = "✔ Hash verified"
                # Preserve timestamp and level - don't change them
                # Mark as accepted/verified
                ev["accepted"] = True

        # Update events in RECENT_MAP
        for fp, rec in RECENT_MAP.items():
            ev_ref = rec.get("ref", {})
            ev_path = str(ev_ref.get("path") or "").lower()
            ev_level = str(ev_ref.get("level") or "").lower()
            ev_reason = str(ev_ref.get("reason") or "")
            ev_reason_lower = ev_reason.lower()

            # Match integrity events for this path that are critical and related to changes
            # Skip if already updated to "Hash verified"
            if (
                ev_ref.get("source") == "integrity"
                and ev_path == path_lower
                and ev_level == "critical"
                and "hash verified" not in ev_reason_lower
                and (
                    "changed" in ev_reason_lower
                    or "mismatch" in ev_reason_lower
                    or "deleted" in ev_reason_lower
                    or "missing" in ev_reason_lower
                )
            ):
                # Replace reason with "✔ Hash verified", keep level as CRITICAL
                ev_ref["reason"] = "✔ Hash verified"
                ev_ref["accepted"] = True
    except Exception:
        # Don't break event processing on update errors
        pass


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


def _update_integrity_target_from_event(ev: dict[str, Any]) -> None:
    """
    Update integrity targets JSON when integrity events come in.
    Note: Last Result is now only updated when user clicks Retest, not automatically from events.
    This gives users intentional control over status updates.
    """
    try:
        path = ev.get("path", "")
        if not path:
            return

        rows = _read_integrity_targets()
        target = next((r for r in rows if str(r.get("path") or "").lower() == path.lower()), None)
        if target is None:
            return  # Not on watch list

        # Only update hash if provided, but don't update last_result automatically
        # Last Result will be updated only when user clicks Retest
        if ev.get("actual"):
            target["sha256"] = ev.get("actual")
        elif ev.get("expected"):
            target["sha256"] = ev.get("expected")

        # Only update status for OK/verified events (baseline accepted)
        reason = ev.get("reason", "").lower()

        # Check for OK/verified status (baseline updated/accepted)
        if "baseline updated" in reason or "deletion accepted" in reason:
            if "baseline updated" in reason:
                target["last_result"] = "OK (baseline updated)"
            elif "deletion accepted" in reason:
                target["last_result"] = "OK (deletion accepted)"
            else:
                target["last_result"] = "OK (verified)"
            _write_integrity_targets(rows)
    except Exception:
        # Don't break event processing on update errors
        pass


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


def _is_text_file(path: str) -> bool:
    """Determine if a file is likely a text file based on extension."""
    p = (path or "").lower()
    text_extensions = (
        ".txt",
        ".log",
        ".md",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".conf",
        ".py",
        ".js",
        ".ts",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".java",
        ".rb",
        ".rs",
        ".go",
        ".php",
        ".sh",
        ".bash",
        ".ps1",
        ".bat",
        ".cmd",
        ".r",
        ".m",
        ".scala",
        ".kt",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".sql",
        ".csv",
        ".tsv",
        ".properties",
        ".env",
        ".gitignore",
        ".dockerfile",
        ".dockerignore",
        ".gitattributes",
        ".config",
        ".toml",
        ".lock",
        ".patch",
        ".diff",
        ".txt",
    )
    return p.endswith(text_extensions)


def _is_pdf_file(path: str) -> bool:
    """Determine if a file is a PDF."""
    p = (path or "").lower()
    return p.endswith(".pdf")


def _is_config_file(path: str) -> bool:
    """Determine if a file is a config file."""
    p = (path or "").lower()
    config_extensions = (
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".conf",
        ".toml",
        ".properties",
        ".env",
    )
    return p.endswith(config_extensions)


def _read_text_file(path: str, max_size: int = 10 * 1024 * 1024) -> tuple[str | None, str]:
    """
    Attempt to read a file as text.
    Returns (content, error_message) where content is None on error.
    """
    try:
        p = _norm_user_path(path)
        st = os.stat(p)
        if st.st_size > max_size:
            return None, f"File too large ({st.st_size} bytes, max {max_size})"

        # Try UTF-8 first
        with open(p, encoding="utf-8", errors="replace") as f:
            content = f.read()
        return content, ""
    except UnicodeDecodeError:
        # Try other common encodings
        encodings = ["latin-1", "cp1252", "iso-8859-1"]
        for enc in encodings:
            try:
                with open(p, encoding=enc, errors="replace") as f:
                    content = f.read()
                return content, ""
            except Exception:
                continue
        return None, "Could not decode as text"
    except Exception as e:
        return None, f"Error reading file: {e}"


def _extract_text_from_pdf(path: str) -> tuple[str | None, str]:
    """
    Extract readable text from PDF files.
    Returns (content, error_message) where content is None on error.
    Uses simple text extraction - for better results, consider using PyPDF2 or pdfplumber.
    """
    try:
        p = _norm_user_path(path)

        # Simple PDF text extraction - look for readable text streams
        # This is a basic implementation; for production, consider using PyPDF2 or pdfplumber
        with open(p, "rb") as f:
            content = f.read()

        # Try to extract text from PDF streams (basic approach)
        # Look for text objects in PDF format
        import re

        # Extract text from PDF streams (basic regex approach)
        # This is a simple fallback - proper PDF parsing would be better
        text_parts: list[str] = []

        # Look for text in PDF streams
        stream_matches = re.findall(rb"stream\s+(.*?)\s+endstream", content, re.DOTALL)
        for stream in stream_matches[:20]:  # Limit to first 20 streams
            try:
                # Try to decode as text
                text = stream.decode("utf-8", errors="replace")
                # Extract printable text
                text = re.sub(r"[^\x20-\x7E\n\r\t]", "", text)
                if len(text.strip()) > 10:  # Only keep substantial text
                    text_parts.append(text.strip())
            except Exception:
                continue

        if text_parts:
            # Join with line breaks
            return "\n".join(text_parts), ""

        return None, "No readable text found in PDF (consider using PyPDF2 for better extraction)"

    except Exception as e:
        return None, f"Error extracting text from PDF: {e}"


def _extract_images_from_office_doc(path: str) -> list[dict[str, Any]]:
    """
    Extract image metadata from Office documents, including dimensions.
    Returns list of image info dicts with name, path, size, hash, width, height.
    """
    images: list[dict[str, Any]] = []
    try:
        p = _norm_user_path(path)
        p_lower = (path or "").lower()

        if not p_lower.endswith((".docx", ".xlsx", ".pptx")):
            return images

        with zipfile.ZipFile(p, "r") as zf:
            # Look for images in media folders
            if p_lower.endswith(".docx"):
                # Word: images in word/media/
                media_pattern = "word/media/"
                # Word stores image dimensions in document.xml relationships
                doc_xml = None
                try:
                    doc_xml = zf.read("word/document.xml").decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif p_lower.endswith(".xlsx"):
                # Excel: images in xl/media/
                media_pattern = "xl/media/"
                doc_xml = None
            elif p_lower.endswith(".pptx"):
                # PowerPoint: images in ppt/media/
                media_pattern = "ppt/media/"
                doc_xml = None
            else:
                return images

            for name in zf.namelist():
                if name.startswith(media_pattern) and name.lower().endswith(
                    (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".wmf", ".emf")
                ):
                    try:
                        info = zf.getinfo(name)
                        # Compute hash for the image
                        img_data = zf.read(name)
                        img_hash = hashlib.sha256(img_data).hexdigest()[
                            :16
                        ]  # Short hash for display

                        # Extract dimensions from document.xml for .docx
                        width = None
                        height = None

                        if p_lower.endswith(".docx") and doc_xml:
                            # Find image relationships and extract dimensions
                            # Word stores dimensions in EMU (English Metric Units): 1 inch = 914400 EMU
                            # Look for <wp:extent> or <a:ext> tags with cx/cy attributes
                            # Search for relationships to this image
                            rel_pattern = r'<a:blip[^>]*r:embed="[^"]*"[^>]*>.*?<wp:extent[^>]*cx="(\d+)"[^>]*cy="(\d+)"[^>]*>'
                            matches = re.findall(rel_pattern, doc_xml, re.DOTALL)
                            if matches:
                                # Use first match (most common case)
                                cx_emu, cy_emu = matches[0]
                                # Convert EMU to pixels (assuming 96 DPI: 1 inch = 96 pixels = 914400 EMU)
                                width = round(int(cx_emu) / 914400 * 96)
                                height = round(int(cy_emu) / 914400 * 96)
                            else:
                                # Try alternative pattern for inline images
                                alt_pattern = r'<a:blip[^>]*r:embed="[^"]*"[^>]*>.*?<a:ext[^>]*cx="(\d+)"[^>]*cy="(\d+)"[^>]*>'
                                alt_matches = re.findall(alt_pattern, doc_xml, re.DOTALL)
                                if alt_matches:
                                    cx_emu, cy_emu = alt_matches[0]
                                    width = round(int(cx_emu) / 914400 * 96)
                                    height = round(int(cy_emu) / 914400 * 96)

                        img_info = {
                            "name": os.path.basename(name),
                            "path": name,
                            "size": info.file_size,
                            "hash": img_hash,
                            "type": "image",
                        }

                        if width is not None and height is not None:
                            img_info["width"] = width
                            img_info["height"] = height

                        images.append(img_info)
                    except Exception:
                        continue

        return images
    except Exception:
        return images


def _extract_formatting_from_office_doc(path: str) -> dict[str, dict[str, Any]]:
    """
    Extract formatting information (color, bold, italic, etc.) from Office documents.
    Returns a dict mapping text content to effective styles (after inheritance).
    This avoids false positives from run re-segmentation.
    """
    formatting_map: dict[str, dict[str, Any]] = {}
    try:
        p = _norm_user_path(path)
        p_lower = (path or "").lower()

        if not p_lower.endswith(".docx"):
            return formatting_map

        with zipfile.ZipFile(p, "r") as zf:
            try:
                doc_xml = zf.read("word/document.xml").decode("utf-8", errors="replace")

                # Find all paragraphs first to get paragraph-level styles
                paragraph_pattern = r"<w:p[^>]*>(.*?)</w:p>"
                paragraphs = re.findall(paragraph_pattern, doc_xml, re.DOTALL)

                for para in paragraphs:
                    # Get paragraph-level default styles (if any)
                    para_color = re.search(
                        r'<w:pPr[^>]*>.*?<w:color[^>]*w:val="([^"]+)"', para, re.DOTALL
                    )
                    para_bold = re.search(r"<w:pPr[^>]*>.*?<w:b[^>]*/>", para, re.DOTALL)
                    para_italic = re.search(r"<w:pPr[^>]*>.*?<w:i[^>]*/>", para, re.DOTALL)

                    # Find all runs within this paragraph
                    run_pattern = r"<w:r[^>]*>(.*?)</w:r>"
                    runs = re.findall(run_pattern, para, re.DOTALL)

                    for run in runs:
                        # Extract text - handle multi-codepoint graphemes (emojis) as single units
                        text_match = re.search(r"<w:t[^>]*>([^<]+)</w:t>", run)
                        if not text_match:
                            continue

                        text = text_match.group(1)
                        if not text.strip():
                            continue

                        # Get run-level styles (override paragraph defaults)
                        run_color = re.search(r'<w:color[^>]*w:val="([^"]+)"', run)
                        run_bold = re.search(r"<w:b[^>]*/>", run)
                        run_italic = re.search(r"<w:i[^>]*/>", run)
                        run_underline = re.search(r'<w:u[^>]*w:val="([^"]+)"', run)

                        # Determine effective styles (run overrides paragraph)
                        effective_styles: dict[str, str] = {}

                        # Color: run overrides paragraph
                        if run_color:
                            effective_styles["color"] = run_color.group(1)
                        elif para_color:
                            effective_styles["color"] = para_color.group(1)

                        # Bold: run overrides paragraph
                        if run_bold:
                            effective_styles["bold"] = "true"
                        elif para_bold:
                            effective_styles["bold"] = "true"

                        # Italic: run overrides paragraph
                        if run_italic:
                            effective_styles["italic"] = "true"
                        elif para_italic:
                            effective_styles["italic"] = "true"

                        # Underline: run-level only
                        if run_underline:
                            effective_styles["underline"] = run_underline.group(1)

                        # Store by text content (normalize whitespace for comparison)
                        # Use the text as-is for matching, but handle emojis as single units
                        text_key = text

                        # If this text already exists, merge styles (only if they're identical)
                        if text_key in formatting_map:
                            existing = formatting_map[text_key]
                            existing_styles = existing.get("styles", {})
                            # Merge - only keep styles that are consistent
                            merged_styles = {}
                            for key, val in effective_styles.items():
                                if key in existing_styles and existing_styles[key] == val:
                                    merged_styles[key] = val
                                elif key not in existing_styles:
                                    merged_styles[key] = val
                            formatting_map[text_key] = {
                                "text": text_key,
                                "styles": merged_styles if merged_styles else effective_styles,
                                "type": "formatting",
                            }
                        else:
                            formatting_map[text_key] = {
                                "text": text_key,
                                "styles": effective_styles,
                                "type": "formatting",
                            }
            except Exception:
                pass

        return formatting_map
    except Exception:
        return formatting_map


def _extract_text_from_office_doc(path: str) -> tuple[str | None, str]:
    """
    Extract readable text from Office documents (.docx, .xlsx, .pptx).
    Returns (content, error_message) where content is None on error.
    Office documents are ZIP files containing XML.
    Also preserves whitespace (Tab/Enter) for proper diffing.
    """
    try:
        p = _norm_user_path(path)
        p_lower = (path or "").lower()

        if not p_lower.endswith((".docx", ".xlsx", ".pptx")):
            return None, "Not an Office document"

        text_parts: list[str] = []

        with zipfile.ZipFile(p, "r") as zf:
            if p_lower.endswith(".docx"):
                # Word: text is in word/document.xml
                try:
                    doc_xml = zf.read("word/document.xml").decode("utf-8", errors="replace")

                    # Better approach: extract paragraphs and their text runs
                    # Find all paragraphs first
                    paragraph_pattern = r"<w:p[^>]*>(.*?)</w:p>"
                    paragraphs = re.findall(paragraph_pattern, doc_xml, re.DOTALL)

                    if paragraphs:
                        para_texts = []
                        for para in paragraphs:
                            # Extract all text runs within this paragraph
                            # Preserve whitespace (Tab, Enter) by checking for <w:br/> and <w:tab/>
                            text_runs = re.findall(r"<w:t[^>]*>([^<]+)</w:t>", para)
                            # Check for line breaks and tabs
                            has_break = re.search(r"<w:br[^>]*/>", para)
                            has_tab = re.search(r"<w:tab[^>]*/>", para)

                            if text_runs:
                                # Join text runs within a paragraph (preserves formatting within para)
                                para_text = "".join(text_runs)
                                # Decode XML entities
                                para_text = (
                                    para_text.replace("&lt;", "<")
                                    .replace("&gt;", ">")
                                    .replace("&amp;", "&")
                                )
                                # Preserve tabs and line breaks
                                if has_tab:
                                    para_text = "\t" + para_text  # Add tab at start if present
                                if has_break:
                                    para_text = para_text + "\n"  # Add line break if present
                                if para_text.strip() or has_tab or has_break:
                                    para_texts.append(para_text)

                        if para_texts:
                            # Join paragraphs with newlines to preserve structure
                            # Don't strip to preserve whitespace
                            text = "\n".join(para_texts)
                            text_parts.append(f"[Word Document Text]\n{text}\n")
                    else:
                        # Fallback: extract all text from <w:t> tags
                        text_matches = re.findall(r"<w:t[^>]*>([^<]+)</w:t>", doc_xml)
                        if text_matches:
                            # Decode XML entities
                            text = "".join(text_matches)
                            text = (
                                text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
                            )
                            # Add newlines at paragraph boundaries (approximate)
                            text = re.sub(r"</w:p>", "\n", text)
                            text = re.sub(r"\n\s*\n", "\n", text)  # Clean up multiple newlines
                            if text.strip():
                                text_parts.append(f"[Word Document Text]\n{text.strip()}\n")
                except Exception as e:
                    text_parts.append(f"[Word Document - Error extracting text: {e}]\n")

            elif p_lower.endswith(".xlsx"):
                # Excel: text is in xl/sharedStrings.xml and sheet data
                try:
                    # Get shared strings
                    try:
                        shared_strings_xml = zf.read("xl/sharedStrings.xml").decode(
                            "utf-8", errors="replace"
                        )
                        # Extract text from <t> tags (Excel text elements)
                        text_matches = re.findall(r"<t[^>]*>([^<]+)</t>", shared_strings_xml)
                        if text_matches:
                            text_parts.append(
                                "[Excel Shared Strings]\n" + "\n".join(text_matches) + "\n"
                            )
                    except Exception:
                        pass

                    # Get sheet data (first sheet)
                    try:
                        sheet_list = [
                            name
                            for name in zf.namelist()
                            if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")
                        ]
                        if sheet_list:
                            # Read first sheet
                            sheet_xml = zf.read(sheet_list[0]).decode("utf-8", errors="replace")
                            # Extract cell values with references
                            cell_matches = re.findall(
                                r'<c r="([^"]+)"[^>]*><v>([^<]+)</v></c>', sheet_xml
                            )
                            if cell_matches:
                                cell_data = [
                                    f"{ref}: {val}" for ref, val in cell_matches[:50]
                                ]  # Limit to 50 cells
                                text_parts.append(
                                    "[Excel Sheet Data (first 50 cells)]\n"
                                    + "\n".join(cell_data)
                                    + "\n"
                                )
                    except Exception:
                        pass
                except Exception as e:
                    text_parts.append(f"[Excel Document - Error extracting text: {e}]\n")

            elif p_lower.endswith(".pptx"):
                # PowerPoint: text is in ppt/slides/*.xml
                try:
                    slide_files = [
                        name
                        for name in zf.namelist()
                        if name.startswith("ppt/slides/slide") and name.endswith(".xml")
                    ]
                    slide_files.sort()

                    for slide_file in slide_files[:10]:  # Limit to first 10 slides
                        try:
                            slide_xml = zf.read(slide_file).decode("utf-8", errors="replace")
                            # Extract text from <a:t> tags (text in PowerPoint)
                            text_matches = re.findall(r"<a:t[^>]*>([^<]+)</a:t>", slide_xml)
                            if text_matches:
                                slide_num = slide_file.split("/")[-1].replace(".xml", "")
                                text_parts.append(
                                    f"[Slide {slide_num}]\n" + "\n".join(text_matches) + "\n"
                                )
                        except Exception:
                            continue
                except Exception as e:
                    text_parts.append(f"[PowerPoint Document - Error extracting text: {e}]\n")

        if text_parts:
            return "\n".join(text_parts), ""
        return None, "No text content found in Office document"

    except zipfile.BadZipFile:
        return None, "Not a valid ZIP file (Office document)"
    except Exception as e:
        return None, f"Error extracting text from Office document: {e}"


def _split_into_words(text: str) -> list[tuple[str, int, int]]:
    """
    Split text into words, preserving whitespace.
    Returns list of (word, start_pos, end_pos) tuples.
    """
    import re

    words: list[tuple[str, int, int]] = []
    for match in re.finditer(r"\S+|\s+", text):
        words.append((match.group(0), match.start(), match.end()))
    return words


def _compute_char_diff(
    old_line: str, new_line: str, word_level: bool = True
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Compute word-level or character-level diff for a single line pair.
    Returns (old_parts, new_parts) where each part is {'type': 'equal'|'removed'|'added', 'text': str}

    When word_level=True, groups changes by words for better readability.
    """
    from difflib import SequenceMatcher

    # Initialize result lists
    old_parts: list[dict[str, Any]] = []
    new_parts: list[dict[str, Any]] = []

    if word_level:
        # Word-level diffing: split into words and diff at word level
        old_words = _split_into_words(old_line)
        new_words = _split_into_words(new_line)

        old_word_texts = [w[0] for w in old_words]
        new_word_texts = [w[0] for w in new_words]

        matcher = SequenceMatcher(None, old_word_texts, new_word_texts)

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                # Join equal words
                text = "".join(old_word_texts[i1:i2])
                old_parts.append({"type": "equal", "text": text})
                new_parts.append({"type": "equal", "text": "".join(new_word_texts[j1:j2])})
            elif tag == "delete":
                # Join deleted words
                text = "".join(old_word_texts[i1:i2])
                old_parts.append({"type": "removed", "text": text})
            elif tag == "insert":
                # Join inserted words
                text = "".join(new_word_texts[j1:j2])
                new_parts.append({"type": "added", "text": text})
            elif tag == "replace":
                # Join replaced words
                old_parts.append({"type": "removed", "text": "".join(old_word_texts[i1:i2])})
                new_parts.append({"type": "added", "text": "".join(new_word_texts[j1:j2])})
    else:
        # Character-level diffing (fallback)
        matcher = SequenceMatcher(None, old_line, new_line)

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                old_parts.append({"type": "equal", "text": old_line[i1:i2]})
                new_parts.append({"type": "equal", "text": new_line[j1:j2]})
            elif tag == "delete":
                old_parts.append({"type": "removed", "text": old_line[i1:i2]})
            elif tag == "insert":
                new_parts.append({"type": "added", "text": new_line[j1:j2]})
            elif tag == "replace":
                old_parts.append({"type": "removed", "text": old_line[i1:i2]})
                new_parts.append({"type": "added", "text": new_line[j1:j2]})

    return old_parts, new_parts


def _compute_line_diff(old_lines: list[str], new_lines: list[str]) -> list[dict[str, Any]]:
    """
    Compute a line-by-line diff with character-level highlighting for modified lines.
    Returns a list of diff segments with type: 'equal', 'added', 'removed', 'modified'
    For modified lines, includes character-level differences.
    """
    from difflib import SequenceMatcher

    matcher = SequenceMatcher(None, old_lines, new_lines)
    diff_segments: list[dict[str, Any]] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            # Include equal lines
            diff_segments.append(
                {
                    "type": "equal",
                    "old_start": i1 + 1,  # 1-indexed for display
                    "old_end": i2,
                    "new_start": j1 + 1,
                    "new_end": j2,
                    "old_lines": old_lines[i1:i2],
                    "new_lines": new_lines[j1:j2],
                }
            )
        elif tag == "delete":
            diff_segments.append(
                {
                    "type": "removed",
                    "old_start": i1 + 1,
                    "old_end": i2,
                    "old_lines": old_lines[i1:i2],
                    "new_lines": [],
                }
            )
        elif tag == "insert":
            diff_segments.append(
                {
                    "type": "added",
                    "new_start": j1 + 1,
                    "new_end": j2,
                    "old_lines": [],
                    "new_lines": new_lines[j1:j2],
                }
            )
        elif tag == "replace":
            # For modified lines, compute character-level differences
            old_section = old_lines[i1:i2]
            new_section = new_lines[j1:j2]

            # If same number of lines, do character-level diff for each pair
            if len(old_section) == len(new_section):
                old_char_diffs: list[list[dict[str, Any]]] = []
                new_char_diffs: list[list[dict[str, Any]]] = []

                for old_line, new_line in zip(old_section, new_section):
                    # Use word-level diffing for better readability
                    old_parts, new_parts = _compute_char_diff(old_line, new_line, word_level=True)
                    old_char_diffs.append(old_parts)
                    new_char_diffs.append(new_parts)

                diff_segments.append(
                    {
                        "type": "modified",
                        "old_start": i1 + 1,
                        "old_end": i2,
                        "new_start": j1 + 1,
                        "new_end": j2,
                        "old_lines": old_section,
                        "new_lines": new_section,
                        "old_char_diffs": old_char_diffs,
                        "new_char_diffs": new_char_diffs,
                    }
                )
            else:
                # Different number of lines - treat as delete + insert
                diff_segments.append(
                    {
                        "type": "modified",
                        "old_start": i1 + 1,
                        "old_end": i2,
                        "new_start": j1 + 1,
                        "new_end": j2,
                        "old_lines": old_section,
                        "new_lines": new_section,
                    }
                )

    return diff_segments


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
        Skips emitting events for OK statuses (baseline updated/deletion accepted)
        since we update the existing CRITICAL entry instead.
        """
        s = (status or "").upper()
        # Skip emitting new events for OK statuses - we update existing CRITICAL entries instead
        if s.startswith("OK") and (
            "baseline updated" in status.lower() or "deletion accepted" in status.lower()
        ):
            return

        lvl = "info"
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

                if ev.get("source") == "integrity":
                    # Update integrity targets when integrity events come in
                    _update_integrity_target_from_event(ev)

                    # Check if this is a "Hash verified" event that should update existing CRITICAL entry
                    if ev.get("update_existing") and ev.get("reason") == "Hash verified":
                        # Update existing CRITICAL entry instead of creating new one
                        path = ev.get("path", "")
                        if path:
                            _update_live_events_for_hash_verified(path)
                            # Don't add this event to buffer - we updated the existing entry
                            continue
                else:
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
        Re-hash: Manually compute SHA-256 and update baseline if needed.
        This is for manually generating a new trusted hash, NOT for detection.
        Does NOT emit events to avoid duplicate alerts - the integrity checker handles detection.
        """
        try:
            body: dict[str, Any] = cast(
                dict[str, Any], request.get_json(force=True) or {}
            )  # parse JSON body
            path = str(body.get("path") or "").strip()  # normalize to a simple string
            if not path:
                return jsonify({"error": "missing path"}), 400  # hard fail if no path

            # Check if file exists first - handle deletion gracefully
            if not os.path.exists(_norm_user_path(path)):
                # File is deleted - update status gracefully
                rows = _read_integrity_targets()
                for r in rows:
                    if str(r.get("path") or "").lower() == path.lower():
                        r["last_result"] = "CHANGED: File deleted or path changed"
                        _write_integrity_targets(rows)
                        return jsonify(
                            {
                                "error": "File deleted or missing",
                                "last_result": "CHANGED: File deleted or path changed",
                                "file_deleted": True,
                            }
                        )

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
                        # DO NOT emit event - this is manual Re-hash, not detection
                    else:
                        new_hash = info.get("sha256", "")  # current SHA-256 hex
                        if rule == "sha256":
                            if not baseline:
                                # first time, promote to baseline
                                r["sha256"] = new_hash
                                r["last_result"] = "OK (baseline set)"
                                changed = True
                                # DO NOT emit event - this is manual Re-hash, not detection
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
                                # DO NOT emit event - this is manual Re-hash, not detection
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
                                    # DO NOT emit event - this is manual Re-hash, not detection
                            except Exception as e:
                                r["last_result"] = f"ERR: {e}"
                                # DO NOT emit event - this is manual Re-hash, not detection
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

            # Check if file exists
            if not os.path.exists(_norm_user_path(path)):
                return (
                    jsonify(
                        {"ok": False, "error": "File deleted or path changed", "file_deleted": True}
                    ),
                    400,
                )

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

            # Initial byte-based percentage (will be refined if text_diff is available)
            denom = float(max(1, cur_size))
            percent = round((approx_bytes_changed / denom) * 100.0, 2)

            # ----- Try to extract text-based diff for readable files -----
            text_diff: dict[str, Any] | None = None
            file_type = "binary"

            # Check if this is a text file, Office document, or PDF
            is_text = _is_text_file(path)
            is_office = (path or "").lower().endswith((".docx", ".xlsx", ".pptx"))
            is_pdf = _is_pdf_file(path)

            if is_text or is_office or is_pdf:
                # Check if we have a baseline blob stored
                baseline_blob = target.get("baseline_blob")
                baseline_text = None
                current_text = None

                if (
                    baseline_blob
                    and isinstance(baseline_blob, dict)
                    and not baseline_blob.get("error")
                ):
                    # Read baseline from stored blob
                    stored_path = baseline_blob.get("stored_path")
                    if stored_path and os.path.exists(stored_path):
                        if is_office:
                            # Extract text from Office document baseline
                            baseline_text, _ = _extract_text_from_office_doc(stored_path)
                        elif is_pdf:
                            # Extract text from PDF baseline
                            baseline_text, _ = _extract_text_from_pdf(stored_path)
                        else:
                            # Read as regular text file
                            baseline_text, _ = _read_text_file(stored_path)

                # Read current file
                if is_office:
                    # Extract text from Office document
                    current_text, text_error = _extract_text_from_office_doc(path)
                elif is_pdf:
                    # Extract text from PDF
                    current_text, text_error = _extract_text_from_pdf(path)
                else:
                    # Read as regular text file
                    current_text, text_error = _read_text_file(path)

                if baseline_text is not None and current_text is not None:
                    # Both files readable - compute line diff
                    old_lines = baseline_text.splitlines(keepends=False)
                    new_lines = current_text.splitlines(keepends=False)
                    diff_segments = _compute_line_diff(old_lines, new_lines)

                    # Extract images and formatting for Office documents
                    images_baseline: list[dict[str, Any]] = []
                    images_current: list[dict[str, Any]] = []
                    image_changes: list[dict[str, Any]] = []
                    formatting_changes: list[dict[str, Any]] = []

                    if is_office:
                        # Extract images from both versions
                        images_baseline = (
                            _extract_images_from_office_doc(stored_path)
                            if stored_path and os.path.exists(stored_path)
                            else []
                        )
                        images_current = _extract_images_from_office_doc(path)

                        # Compare images to detect add/remove/replace/resize
                        # Create maps by hash for quick lookup
                        baseline_img_map = {img["hash"]: img for img in images_baseline}
                        current_img_map = {img["hash"]: img for img in images_current}

                        # Also create maps by name for resize detection (when hash might be same but dimensions differ)
                        baseline_img_by_name = {img["name"]: img for img in images_baseline}
                        current_img_by_name = {img["name"]: img for img in images_current}

                        baseline_hashes = set(baseline_img_map.keys())
                        current_hashes = set(current_img_map.keys())

                        # Added images (new hash)
                        for img_hash in current_hashes - baseline_hashes:
                            image_changes.append(
                                {
                                    "change": "added",
                                    "image": current_img_map[img_hash],
                                    "type": "image",
                                }
                            )

                        # Removed images (hash no longer exists)
                        for img_hash in baseline_hashes - current_hashes:
                            image_changes.append(
                                {
                                    "change": "removed",
                                    "image": baseline_img_map[img_hash],
                                    "type": "image",
                                }
                            )

                        # Check for resized images (same name/hash but different dimensions)
                        common_names = set(baseline_img_by_name.keys()) & set(
                            current_img_by_name.keys()
                        )
                        for img_name in common_names:
                            baseline_img = baseline_img_by_name[img_name]
                            current_img = current_img_by_name[img_name]

                            baseline_width = baseline_img.get("width")
                            baseline_height = baseline_img.get("height")
                            current_width = current_img.get("width")
                            current_height = current_img.get("height")

                            # Check if dimensions changed
                            if (
                                baseline_width is not None
                                and baseline_height is not None
                                and current_width is not None
                                and current_height is not None
                            ):
                                if (
                                    baseline_width != current_width
                                    or baseline_height != current_height
                                ):
                                    # Image was resized
                                    image_changes.append(
                                        {
                                            "change": "resized",
                                            "image": current_img,
                                            "old_width": baseline_width,
                                            "old_height": baseline_height,
                                            "new_width": current_width,
                                            "new_height": current_height,
                                            "type": "image",
                                        }
                                    )
                            # Also check if hash is same but dimensions are missing in one version
                            elif baseline_img.get("hash") == current_img.get("hash"):
                                # Same hash means same image file, but dimensions might have changed
                                # This is a resize case where we detected the same file but dimensions differ
                                if (baseline_width is not None or baseline_height is not None) and (
                                    current_width is not None or current_height is not None
                                ):
                                    if (
                                        baseline_width != current_width
                                        or baseline_height != current_height
                                    ):
                                        image_changes.append(
                                            {
                                                "change": "resized",
                                                "image": current_img,
                                                "old_width": baseline_width,
                                                "old_height": baseline_height,
                                                "new_width": current_width,
                                                "new_height": current_height,
                                                "type": "image",
                                            }
                                        )

                        # Extract and compare formatting - use dict-based approach to avoid false positives
                        formatting_baseline_map = (
                            _extract_formatting_from_office_doc(stored_path)
                            if stored_path and os.path.exists(stored_path)
                            else {}
                        )
                        formatting_current_map = _extract_formatting_from_office_doc(path)

                        # Compare formatting - only report actual style changes on matching text
                        # Text that exists in both versions
                        common_texts = set(formatting_baseline_map.keys()) & set(
                            formatting_current_map.keys()
                        )

                        for text in common_texts:
                            old_fmt = formatting_baseline_map[text]
                            new_fmt = formatting_current_map[text]

                            old_styles = old_fmt.get("styles", {})
                            new_styles = new_fmt.get("styles", {})

                            # Only report if styles actually changed
                            if old_styles != new_styles:
                                # Calculate what actually changed (only report changed attributes)
                                changed_attrs = []
                                removed_attrs = []
                                added_attrs = []

                                # Check each attribute
                                all_keys = set(old_styles.keys()) | set(new_styles.keys())
                                for key in all_keys:
                                    old_val = old_styles.get(key)
                                    new_val = new_styles.get(key)

                                    if old_val != new_val:
                                        if old_val is not None and new_val is not None:
                                            # Attribute changed
                                            changed_attrs.append(f"{key}: {old_val} → {new_val}")
                                        elif old_val is not None:
                                            # Attribute removed
                                            removed_attrs.append(f"{key}={old_val}")
                                        else:
                                            # Attribute added
                                            added_attrs.append(f"{key}={new_val}")

                                # Only report if there are actual changes
                                if changed_attrs or removed_attrs or added_attrs:
                                    # Convert to list format for display
                                    old_style_list = [f"{k}={v}" for k, v in old_styles.items()]
                                    new_style_list = [f"{k}={v}" for k, v in new_styles.items()]

                                    formatting_changes.append(
                                        {
                                            "change": "modified",
                                            "text": text,
                                            "old_styles": old_style_list,
                                            "new_styles": new_style_list,
                                            "changed_attrs": changed_attrs,
                                            "removed_attrs": removed_attrs,
                                            "added_attrs": added_attrs,
                                            "type": "formatting",
                                        }
                                    )

                    # Show entire file - no truncation
                    # The UI will handle scrolling for large files

                    text_diff = {
                        "type": "text",
                        "file_type": _nl_file_kind(path),
                        "is_config": _is_config_file(path),
                        "is_office": is_office,
                        "is_pdf": is_pdf,
                        "old_line_count": len(old_lines),
                        "new_line_count": len(new_lines),
                        "diff_segments": diff_segments,
                        "show_full_file": True,  # Flag to show entire file
                        "images_baseline": images_baseline,
                        "images_current": images_current,
                        "image_changes": image_changes,
                        "formatting_changes": formatting_changes,
                    }
                    file_type = "text"

                    # Recalculate percentage based on actual changed lines (more accurate for text files)
                    total_lines = max(len(old_lines), len(new_lines))
                    changed_lines = 0
                    changed_chars = 0
                    total_chars = 0

                    for seg in diff_segments:
                        seg_type = seg.get("type", "")
                        if seg_type == "added":
                            changed_lines += len(seg.get("new_lines", []))
                            for line in seg.get("new_lines", []):
                                changed_chars += len(line)
                        elif seg_type == "removed":
                            changed_lines += len(seg.get("old_lines", []))
                            for line in seg.get("old_lines", []):
                                changed_chars += len(line)
                        elif seg_type == "modified":
                            # For modified lines, count actual character changes
                            old_char_diffs = seg.get("old_char_diffs", [])
                            new_char_diffs = seg.get("new_char_diffs", [])
                            old_lines_seg = seg.get("old_lines", [])
                            new_lines_seg = seg.get("new_lines", [])

                            if old_char_diffs or new_char_diffs:
                                # Count actual changed characters from character-level diffs
                                for i in range(max(len(old_lines_seg), len(new_lines_seg))):
                                    if i < len(old_char_diffs) and old_char_diffs[i]:
                                        for part in old_char_diffs[i]:
                                            if part.get("type") == "removed":
                                                changed_chars += len(part.get("text", ""))
                                    if i < len(new_char_diffs) and new_char_diffs[i]:
                                        for part in new_char_diffs[i]:
                                            if part.get("type") == "added":
                                                changed_chars += len(part.get("text", ""))
                                    changed_lines += 0.5  # Partial line (weighted)
                            else:
                                # Fallback: count all modified lines
                                changed_lines += max(len(old_lines_seg), len(new_lines_seg))
                                # Estimate character changes
                                for line in old_lines_seg + new_lines_seg:
                                    changed_chars += len(line) // 2  # Estimate 50% changed

                    # Count total characters for percentage calculation
                    for line in old_lines + new_lines:
                        total_chars += len(line)

                    if total_lines > 0 and total_chars > 0:
                        # Use character-based percentage for more accuracy (weighted 60%)
                        char_percent = (changed_chars / total_chars) * 100.0
                        # Use line-based percentage (weighted 40%)
                        line_percent = (changed_lines / total_lines) * 100.0
                        # Blend both
                        percent = round((char_percent * 0.6) + (line_percent * 0.4), 2)
                    elif total_lines > 0:
                        # Fallback to line-based only
                        line_percent = (changed_lines / total_lines) * 100.0
                        byte_percent = (approx_bytes_changed / float(max(1, cur_size))) * 100.0
                        percent = round((line_percent * 0.7) + (byte_percent * 0.3), 2)

                    # Cap at 100% and ensure non-negative
                    percent = min(100.0, max(0.0, percent))
                elif current_text is not None:
                    # Only current file readable - baseline might be missing or binary
                    text_diff = {
                        "type": "text",
                        "file_type": _nl_file_kind(path),
                        "is_config": _is_config_file(path),
                        "is_office": is_office,
                        "old_line_count": 0,
                        "new_line_count": len(current_text.splitlines(keepends=False)),
                        "diff_segments": [],
                        "note": "Baseline file not available for comparison",
                    }
                    file_type = "text"
            elif zip_changes:
                file_type = "office"

            # Generate summary text with accurate percentage
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
                "file_type": file_type,
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
                "text_diff": text_diff,  # New: text-based diff for readable files
            }
            return jsonify(out)

        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 500

    @app.post("/api/integrity/baseline/accept")
    def api_integrity_baseline_accept():
        """
        Accept current file state as the new baseline.
        This updates the baseline hash/mtime+size and creates a new baseline blob.
        For deleted files, marks the deletion as intentional and removes from watch list.
        """
        try:
            body: dict[str, Any] = cast(dict[str, Any], request.get_json(force=True) or {})
            path = str(body.get("path") or "").strip()
            if not path:
                return jsonify({"ok": False, "error": "missing path"}), 400

            rows = _read_integrity_targets()
            target = next(
                (r for r in rows if str(r.get("path") or "").lower() == path.lower()), None
            )
            if target is None:
                return jsonify({"ok": False, "error": "not on watch list"}), 400

            # Check if file is deleted
            if not os.path.exists(_norm_user_path(path)):
                # File is deleted - mark as intentionally deleted and remove from watch list
                rule = str(target.get("rule") or "sha256").lower()

                # Update existing Live Events entries for this path to reflect acceptance
                # Append acceptance text to existing CRITICAL entry instead of creating new event
                _update_live_events_for_path(path, "✔ Change accepted (deletion accepted)")

                # Note: We don't emit a new event for OK statuses - we update the existing CRITICAL entry instead
                # The file is removed from the watch list, so no integrity target update is needed

                # Remove from watch list
                rows = [r for r in rows if str(r.get("path") or "").lower() != path.lower()]
                _write_integrity_targets(rows)
                return jsonify(
                    {
                        "ok": True,
                        "message": "File deletion accepted - removed from watch list",
                        "file_deleted": True,
                    }
                )

            rule = str(target.get("rule") or "sha256").lower()

            # Update baseline based on rule
            if rule == "sha256":
                info = _sha256_file(path)
                if info.get("sha256"):
                    target["sha256"] = info["sha256"]
                    target["last_result"] = "OK (baseline updated)"

                    # Update baseline blob
                    if ALLOW_MTIME_SNAPSHOTS:
                        try:
                            target["baseline_blob"] = _snapshot_file_to_cas(path)
                            _maybe_prune_baselines()
                        except Exception as e:
                            target["baseline_blob"] = {"error": str(e)}
                else:
                    return jsonify({"ok": False, "error": info.get("error", "hash failed")}), 400
            else:
                # mtime+size rule
                try:
                    st = os.stat(_norm_user_path(path))
                    target["mtime"] = int(st.st_mtime)
                    target["size"] = int(st.st_size)
                    target["last_result"] = "OK (baseline updated)"

                    # Update baseline blob
                    if ALLOW_MTIME_SNAPSHOTS:
                        try:
                            target["baseline_blob"] = _snapshot_file_to_cas(path)
                            _maybe_prune_baselines()
                        except Exception as e:
                            target["baseline_blob"] = {"error": str(e)}
                except Exception as e:
                    return jsonify({"ok": False, "error": str(e)}), 400

            # Update chunk baseline
            info_chunks = _chunk_hashes(path)
            if "error" not in info_chunks:
                target["chunks"] = info_chunks

            # Update ZIP manifest if applicable
            zman = _zip_manifest(path)
            if zman:
                target["zip_manifest"] = zman
            else:
                target.pop("zip_manifest", None)

            _write_integrity_targets(rows)

            # Update existing Live Events entries for this path to reflect acceptance
            # Append acceptance text to existing CRITICAL entry instead of creating new event
            _update_live_events_for_path(path, "✔ Marked Safe")

            # Note: We don't emit a new event for OK statuses - we update the existing CRITICAL entry instead
            # The integrity target status is already updated above with target["last_result"] = "OK (baseline updated)"

            return jsonify(
                {
                    "ok": True,
                    "message": "Baseline updated successfully",
                    "last_result": target.get("last_result", "OK (baseline updated)"),
                }
            )

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
