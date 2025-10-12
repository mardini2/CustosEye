"""
goal: compute a simple, explainable trust score (0-100) for process events.

it keeps the same public surface but adds a bunch of smart, defensive heuristics:
- Prevalence with time-decay (per-hash & per-exe basename) to reward "seen often here" and avoid
  trusting something just because it ran once.
- File origin context (system dir vs. user/temp/downloads), elevation, service/session hints.
- Network posture (listening vs outbound, risky vs common ports, volume of connections).
- Parent/launcher context (script shells & LOLBIN-ish patterns).
- Name/path signals (entropy, “looks hex/packed”, suspicious tokens, misspellings).
- Safe clamping and soft caps so one bad signal doesn’t nuke trust alone.
- Tiny local DB (JSON) with version + time-decay to avoid stale trust forever.

Inputs (all optional; we only use what is present):
    name, exe, sha256, ppid, parent_name, parent_exe, username, integrity_level,
    is_service, elevation (bool), file_ctime, file_mtime, file_size_mb,
    listening_ports (list[int]), remote_addrs / remote_endpoints (list[str|dict]),
    signer_valid (bool), signer_subject (str)

weights live in data/csc_weights.json; missing keys fall back to sane defaults.
"""

from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any


def _now() -> float:
    return time.time()


def _safe_lower(x: Any) -> str:
    return str(x).lower() if x is not None else ""


def _basename(p: str) -> str:
    try:
        return os.path.basename(p)
    except Exception:
        return p


def _to_float(x: Any) -> float | None:
    if isinstance(x, int | float):
        return float(x)
    if isinstance(x, str):
        try:
            return float(x)
        except ValueError:
            return None
    return None


def _shannon_entropy(s: str) -> float:
    # tiny helper: higher entropy -> more "random-looking"
    if not s:
        return 0.0
    from collections import Counter

    counts = Counter(s)
    n = float(len(s))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log(p, 2.0)
    return ent


def _looks_hexish(s: str) -> bool:
    # “deadbeef-like” token detector (very rough; good enough for names)
    if not s or len(s) < 8:
        return False
    hex_chars = set("0123456789abcdef")
    s2 = s.lower()
    # long segments of mostly hex and few separators
    alnum = [ch for ch in s2 if ch.isalnum()]
    if len(alnum) < 8:
        return False
    return sum(1 for ch in alnum if ch in hex_chars) / len(alnum) >= 0.9


class CSCTrustEngine:
    def __init__(self, weights_path: str, db_path: str) -> None:
        self.weights_path = weights_path
        self.db_path = db_path
        self.weights = self._load_weights()
        self.db = self._load_db()

    # ---------- config / db ----------
    def _load_weights(self) -> dict[str, Any]:
        # defaults: designed so nothing explodes if the JSON is missing/incomplete
        defaults: dict[str, Any] = {
            # base & thresholds
            "base": 70,
            "trust_low_threshold": 40,
            "trust_high_threshold": 75,
            # directory context
            "bonus_system_dir": 12,
            "bonus_program_files": 5,
            "deduct_temp_path": 18,
            "deduct_downloads_path": 12,
            "system_paths": ["\\windows\\system32", "/windows/system32"],
            "program_files_paths": ["\\program files", "\\program files (x86)"],
            "temp_paths": [
                "\\appdata\\local\\temp",
                "/appdata/local/temp",
                "\\temp\\",
                "/tmp/",
                "\\users\\public\\",
            ],
            "downloads_paths": ["\\downloads\\", "/downloads/"],
            # name signals
            "deduct_susp_name": 10,
            "susp_name_tokens": [
                "svhost",
                "svch0st",
                "updater",
                "update",
                "patch",
                "fix",
                "agent",
                "service",
                "driver",
                "protect",
                "defender",
                "winlogin",
                "security",
            ],
            "misspell_tokens": [
                ("svchost", "svhost"),  # canonical -> often-misspelled
                ("explorer", "exploer"),
                ("chrome", "chr0me"),
                ("system", "syst3m"),
                ("microsoft", "micros0ft"),
            ],
            "entropy_name_thresh": 3.8,  # > this is a little random-looking
            "deduct_entropy_name": 6,
            "hexish_name_len": 14,
            "deduct_hexish_name": 8,
            # signing
            "bonus_valid_signature": 12,
            "deduct_unsigned_in_system": 10,
            # file time/size context (soft hints)
            "file_age_days_fresh": 3,  # very recent file can be risky if in odd place
            "deduct_very_fresh_non_system": 5,
            "file_size_mb_tiny": 0.15,  # suspiciously tiny binaries (stagers, droppers)
            "deduct_tiny_binary": 6,
            # network posture
            "deduct_listening": 10,
            "deduct_risky_port": 25,
            "deduct_many_listen": 6,  # extra if multiple listening ports
            "risky_ports": [22, 3389, 4444, 5900, 135, 139, 445],
            "common_ports": [80, 443, 53, 123, 587, 993],
            "deduct_remote": 8,
            "deduct_many_remote": 10,  # extra if many distinct remotes
            "remote_many_count": 10,
            # launcher/parent context
            "deduct_susp_launcher": 10,
            "susp_launchers": [
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "regsvr32.exe",
                "rundll32.exe",
                "wmic.exe",
            ],
            # elevation/Session context
            "deduct_elevated_from_user_dir": 12,
            "deduct_service_from_user_dir": 14,
            # prevalence with time-decay
            "bonus_prevalence_hash": 12,
            "bonus_prevalence_exe": 6,
            "penalize_unknown_hash": 6,
            "prevalence_seen_thresh_hash": 4,
            "prevalence_seen_thresh_exe": 8,
            "prevalence_halflife_days": 14,  # older sightings count less
            # soft caps so a single category doesn't dominate excessively
            "max_network_deduction": 35,
            "max_path_deduction": 28,
            "max_name_deduction": 20,
            # label floors/ceilings (we clamp to 0..100 anyway)
            "min_score": 0,
            "max_score": 100,
        }
        try:
            with open(self.weights_path, encoding="utf-8") as f:
                overrides = json.load(f) or {}
            if isinstance(overrides, dict):
                defaults.update(overrides)
        except Exception:
            pass
        return defaults

    def _load_db(self) -> dict[str, Any]:
        # Schema:
        # {
        #   "version": 1,
        #   "hash_stats": { sha256: {"seen": int, "last_seen": ts} },
        #   "exe_stats":  { basename: {"seen": int, "last_seen": ts} }
        # }
        empty = {"version": 1, "hash_stats": {}, "exe_stats": {}}
        if not os.path.exists(self.db_path):
            return empty
        try:
            with open(self.db_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    data.setdefault("version", 1)
                    data.setdefault("hash_stats", {})
                    data.setdefault("exe_stats", {})
                    return data
        except Exception:
            pass
        return empty

    def _save_db(self) -> None:
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.db, f, indent=2)
        except Exception:
            # DB issues are not fatal; we just skip persistence.
            pass

    # ---------- helpers ----------
    def _days_since(self, ts: float) -> float:
        if not ts:
            return 1e9
        return max(0.0, (_now() - float(ts)) / 86400.0)

    def _decayed_seen(self, seen: int, last_seen: float, halflife_days: float) -> float:
        # exponential decay: effective_seen = seen * 0.5^(days_since / halflife)
        if seen <= 0:
            return 0.0
        days = self._days_since(last_seen)
        if halflife_days <= 0:
            return float(seen)
        return float(seen) * (0.5 ** (days / float(halflife_days)))

    # ---------- scoring ----------
    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        if event.get("source") != "process":
            return {"trust": 70, "label": "medium", "reasons": ["not a process event"]}

        w = self.weights
        score = float(w["base"])
        reasons: list[str] = []

        # --- normalize inputs (best-effort; everything optional) ---
        name = _safe_lower(event.get("name"))
        exe = _safe_lower(event.get("exe"))
        sha256 = _safe_lower(event.get("sha256"))
        base = _basename(exe)
        parent_name = _safe_lower(event.get("parent_name") or event.get("parent"))
        parent_exe = _safe_lower(event.get("parent_exe"))
        is_service = bool(event.get("is_service"))
        elevation = bool(event.get("elevation"))  # true if elevated/admin
        # integrity_level currently unused; add when we wire IL heuristics
        # _integrity_level = _safe_lower(event.get("integrity_level"))

        signer_valid = bool(event.get("signer_valid"))
        # signer_subject = event.get("signer_subject")  #not used for now but available for future vendor allowlists

        ports = event.get("listening_ports") or []
        remotes = event.get("remote_addrs") or event.get("remote_endpoints") or []
        if isinstance(remotes, dict):
            # some agents send a dict keyed by proto; flatten
            remotes = sum(remotes.values(), [])  # type: ignore[arg-type]

        file_ctime = float(event.get("file_ctime") or 0.0)  # epoch seconds (if provided)
        file_size_mb = _to_float(event.get("file_size_mb"))  # -> float | None

        # --- prevalence memory (hash + exe basename) ---
        # hash memory
        if sha256:
            h = self.db["hash_stats"].setdefault(sha256, {"seen": 0, "last_seen": 0.0})
            h["seen"] = int(h.get("seen", 0)) + 1
            h["last_seen"] = _now()
        # exe memory
        if base:
            e = self.db["exe_stats"].setdefault(base.lower(), {"seen": 0, "last_seen": 0.0})
            e["seen"] = int(e.get("seen", 0)) + 1
            e["last_seen"] = _now()

        # --- directory / path context ---
        path_deduction = 0.0
        if exe:
            if any(seg in exe for seg in w["system_paths"]):
                score += w["bonus_system_dir"]
                reasons.append("executable under system directory")
            elif any(seg in exe for seg in w["program_files_paths"]):
                score += w["bonus_program_files"]
                reasons.append("executable under Program Files")
            if any(seg in exe for seg in w["temp_paths"]):
                path_deduction += w["deduct_temp_path"]
                reasons.append("executable under temp/public directory")
            if any(seg in exe for seg in w["downloads_paths"]):
                path_deduction += w["deduct_downloads_path"]
                reasons.append("executable under downloads directory")
        # cap path signal so it does not dominate by itself
        if path_deduction > w["max_path_deduction"]:
            path_deduction = float(w["max_path_deduction"])
        score -= path_deduction

        # --- signing signal ---
        if signer_valid:
            score += w["bonus_valid_signature"]
            reasons.append("valid code signature")
        else:
            # unsigned binary in system32 is sus
            if exe and any(seg in exe for seg in w["system_paths"]):
                score -= w["deduct_unsigned_in_system"]
                reasons.append("unsigned binary located in system directory")

        # --- name signals ---
        name_deduction = 0.0
        if name:
            if any(tok in name for tok in w["susp_name_tokens"]):
                name_deduction += w["deduct_susp_name"]
                reasons.append("suspicious name token")
            for canonical, miss in w["misspell_tokens"]:
                if miss in name and canonical not in name:
                    name_deduction += 6  # modest penalty
                    reasons.append(f"name looks like misspelling of '{canonical}'")
            ent = _shannon_entropy(name)
            if ent >= float(w["entropy_name_thresh"]):
                name_deduction += w["deduct_entropy_name"]
                reasons.append("name has high entropy")
            if len(name) >= int(w["hexish_name_len"]) and _looks_hexish(name):
                name_deduction += w["deduct_hexish_name"]
                reasons.append("name looks hex/packed-like")
        if name_deduction > w["max_name_deduction"]:
            name_deduction = float(w["max_name_deduction"])
        score -= name_deduction

        # --- file age / size hints (soft) ---
        if file_ctime and exe:
            age_days = self._days_since(file_ctime)
            # recent binaries outside system dirs are a tad risky
            if age_days <= float(w["file_age_days_fresh"]) and not any(
                seg in exe for seg in w["system_paths"]
            ):
                score -= w["deduct_very_fresh_non_system"]
                reasons.append("very new binary outside system directory")
        if file_size_mb is not None and file_size_mb <= float(w["file_size_mb_tiny"]):
            score -= w["deduct_tiny_binary"]
            reasons.append("binary size is unusually small")

        # --- network posture ---
        net_deduction = 0.0
        risky = set(int(p) for p in w["risky_ports"])
        # common ports reserved for future heuristics
        # _common = set(int(p) for p in w.get("common_ports", []))

        if ports:
            net_deduction += w["deduct_listening"]
            reasons.append("process is listening on a port")
            # risky listen?
            if any(self._safe_int(p) in risky for p in ports):
                net_deduction += w["deduct_risky_port"]
                reasons.append("listening on a risky port")
            # many listening ports → additional penalty
            if len(ports) >= 3:
                net_deduction += w["deduct_many_listen"]
                reasons.append("listening on multiple ports")
        # outbound
        remote_count = 0
        try:
            remote_count = len(remotes)
        except Exception:
            remote_count = 0
        if remote_count > 0:
            # light penalty for outbound in general; if only common ports, stay gentle
            net_deduction += w["deduct_remote"]
            reasons.append("has remote connections")
            if remote_count >= int(w["remote_many_count"]):
                net_deduction += w["deduct_many_remote"]
                reasons.append("many remote connections")

        if net_deduction > w["max_network_deduction"]:
            net_deduction = float(w["max_network_deduction"])
        score -= net_deduction

        # --- parent / launcher context ---
        # if launched by a “scripting/LOLBIN” tool AND binary is in user-ish dir → more suspicious
        if parent_name or parent_exe:
            parent_base = _basename(parent_exe) if parent_exe else parent_name
            if parent_base and parent_base in w["susp_launchers"]:
                score -= w["deduct_susp_launcher"]
                reasons.append(f"launched by suspicious tool ({parent_base})")

        # --- elevation/service context ---
        userish = exe and any(seg in exe for seg in (w["temp_paths"] + w["downloads_paths"]))
        if elevation and userish:
            score -= w["deduct_elevated_from_user_dir"]
            reasons.append("elevated binary from user/temp path")
        if is_service and userish:
            score -= w["deduct_service_from_user_dir"]
            reasons.append("service binary resides in user/temp path")

        # --- prevalence with time-decay ---
        halflife = float(w["prevalence_halflife_days"])

        if sha256:
            hs: dict[str, Any] = self.db["hash_stats"].get(sha256, {"seen": 0, "last_seen": 0.0})
            seen_h = int(hs.get("seen", 0) or 0)
            last_seen_h = _to_float(hs.get("last_seen")) or 0.0
            eff = self._decayed_seen(seen_h, last_seen_h, halflife)
            if eff >= float(w["prevalence_seen_thresh_hash"]):
                score += w["bonus_prevalence_hash"]
                reasons.append("hash is common on this machine (time-decayed)")
            else:
                score -= w["penalize_unknown_hash"]
                reasons.append("hash is rare/unknown on this machine")

        if base:
            es: dict[str, Any] = self.db["exe_stats"].get(
                base.lower(), {"seen": 0, "last_seen": 0.0}
            )
            seen_e = int(es.get("seen", 0) or 0)
            last_seen_e = _to_float(es.get("last_seen")) or 0.0
            eff2 = self._decayed_seen(seen_e, last_seen_e, halflife)
            if eff2 >= float(w["prevalence_seen_thresh_exe"]):
                score += w["bonus_prevalence_exe"]
                reasons.append("executable name seen often here (time-decayed)")

        # --- final clamp & labeling ---
        score = max(float(w["min_score"]), min(float(w["max_score"]), score))
        if score < float(w["trust_low_threshold"]):
            label = "low"
        elif score >= float(w["trust_high_threshold"]):
            label = "high"
        else:
            label = "medium"

        # persist DB (best-effort)
        self._save_db()

        return {"trust": int(round(score)), "label": label, "reasons": reasons}

    # tiny safe-int helper for port parsing
    def _safe_int(self, v: Any) -> int:
        try:
            return int(v)
        except Exception:
            return -1
