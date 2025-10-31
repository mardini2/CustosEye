# ruff: noqa: E501
"""
goal: Trust engine for processes with a clear verdict, class, and confidence. Small, fast, local.

What this file does
• Scores a single process event and returns a categorical verdict:
  malicious | suspicious | caution | trusted | unknown.
• Adds a coarse class tag (system, popular_app, game, dev_tool, service, script, utility, embedded, unknown).
• Produces a confidence number and short human reasons, plus a signals blob for debugging and UI.

How it thinks
• Uses a simple internal score S and a few cut points to map S → verdict.
• Looks at path context (system, Program Files, temp/downloads).
• Gives credit for a valid code signature and recognizes common publishers.
• Heuristics for sketchy names: entropy, hexy strings, misspell tokens.
• Flags risky network posture (listening ports, especially the spicy ones).
• Watches parent launcher hints (powershell, cmd, wscript, etc.).
• Notes elevation and service status, with extra caution if they live in user paths.
• Learns local prevalence over time using a tiny decayed DB:
  per-hash and per-basename sightings with a half-life. Common things earn trust.
• Classifies with simple rules first-hit-wins. Falls back to service/dev_tool/utility/unknown.

Inputs it expects (event dict)
• source="process" or not (non-process returns unknown quickly)
• name, exe, sha256
• parent_name/parent_exe
• signer_valid, signer_subject
• is_service, elevation
• listening_ports, remote_addrs|remote_endpoints
• file_ctime, file_size_mb

Outputs you get (always)
{
  "version": "csc-v2",
  "verdict": "...",
  "cls": "...",
  "confidence": float 0..1,
  "reasons": [str, ...],   # short, readable
  "signals": { ... }       # raw flags and numbers for UI and tests
}

Config and data
• Weights JSON is optional. Every knob has a sane default so the engine runs out of the box.
• Tiny JSON DB tracks decayed sightings. Writes are best-effort so the pipeline never breaks.

Notes for future
• Cut points and bonuses are easy to tune in weights.json.
• Prevalence half-life controls how quickly the engine forgets.
• Reasons are intentionally short. Keep them punchy so the UI stays clean.
"""

from __future__ import annotations

import json  # we load weights and a small local prevalence DB
import math  # entropy calc and a couple small helpers
import os  # path checks for context (system dirs, temp, downloads)
import time  # time-decay and "last seen" tracking
from numbers import Real  # for isinstance() without tuples (ruff UP038)
from pathlib import Path  # safe, cross-platform filesystem ops
from typing import Any  # type hints for readability

# tiny utilities


def _now() -> float:
    # return "now" as epoch seconds; used for decay and last_seen
    return time.time()


def _safe_lower(x: Any) -> str:
    # best-effort to lower a value safely; empty string for None
    return str(x).lower() if x is not None else ""


def _basename(p: str) -> str:
    # robust basename that never throws; falls back to original on odd inputs
    try:
        return os.path.basename(p)
    except Exception:
        return p


def _to_float(x: Any) -> float | None:
    # try to coerce to float; if it fails just return None
    if isinstance(x, Real):
        return float(x)
    if isinstance(x, str):
        try:
            return float(x)
        except ValueError:
            return None
    return None


def _shannon_entropy(s: str) -> float:
    # quick-n-dirty entropy (higher means "more random-looking")
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
    # detect long, almost-hexish tokens (very rough, works fine for names)
    if not s or len(s) < 8:
        return False
    hex_chars = set("0123456789abcdef")
    s2 = s.lower()
    alnum = [ch for ch in s2 if ch.isalnum()]
    if len(alnum) < 8:
        return False
    return sum(1 for ch in alnum if ch in hex_chars) / len(alnum) >= 0.9


def _safe_int(v: Any) -> int:
    # convert to int; on failure return sentinel -1
    try:
        return int(v)
    except Exception:
        return -1


# CSC v2 core


class CSCTrustEngine:
    """
    CSC v2 (categorical): returns a verdict, class, and confidence instead of a 0–100 score.

    Output schema (always present):
        {
          "version": "csc-v2",
          "verdict": "trusted" | "caution" | "suspicious" | "malicious" | "unknown",
          "cls":     "system"  | "popular_app" | "game" | "dev_tool" | "service" |
                     "script"  | "utility" | "embedded" | "unknown",
          "confidence": float in [0.0, 1.0],
          "reasons": [str, ...],       # short human messages
          "signals": { str: Any, ... } # raw helpful flags/values for UI/debug
        }

    Notes:
    - We still keep a tiny local DB to model prevalence with time decay (per-hash, per-basename).
    - We use weight config for knobs, risky/common ports, path hints, and allow/deny vendor cues.
    """

    def __init__(self, weights_path: str, db_path: str) -> None:
        # remember where weights and DB live so we can reload/persist
        self.weights_path = weights_path
        self.db_path = db_path
        # load weights with safe defaults so missing JSON never breaks anything
        self.weights = self._load_weights()
        # load the tiny DB (hash/exe sightings with decay)
        self.db = self._load_db()

    # config / db

    def _load_weights(self) -> dict[str, Any]:
        # defaults: every knob has a sane fallback so you can ship without a file
        defaults: dict[str, Any] = {
            # categorical thresholds live as logit-like cut points on an internal score S
            # we map S -> verdict using these boundaries (ordered low->high)
            "cut_malicious": -2.0,  # S <  -2.0 → malicious
            "cut_suspicious": -0.5,  # -2.0 ≤ S < -0.5 → suspicious
            "cut_caution": 0.5,  # -0.5 ≤ S < 0.5 → caution
            "cut_trusted": 1.6,  # 0.5 ≤ S < 1.6 → trusted; S ≥ 1.6 gets "trusted (high)"
            # path groups (lower-cased substring checks)
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
            # name heuristics
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
                ["svchost", "svhost"],
                ["explorer", "exploer"],
                ["chrome", "chr0me"],
                ["system", "syst3m"],
                ["microsoft", "micros0ft"],
            ],
            "entropy_name_thresh": 3.8,
            "hexish_name_len": 14,
            # signing and vendor hints
            "prefer_signed_bonus": 0.8,  # bump on valid signature
            "unsigned_system_penalty": 0.9,  # unsigned in system dir is sketchy
            "publisher_buckets": {  # quick vendor cues for classification
                "microsoft": "system",
                "google": "popular_app",
                "mozilla": "popular_app",
                "valve": "game",
                "epic": "game",
                "unity": "game",
                "adobe": "popular_app",
                "jetbrains": "dev_tool",
                "oracle": "popular_app",
                "nvidia": "driver",
                "amd": "driver",
            },
            # file age/size
            "file_age_days_fresh": 3.0,
            "tiny_binary_mb": 0.15,
            # network posture
            "risky_ports": [22, 3389, 4444, 5900, 135, 139, 445],
            "common_ports": [80, 443, 53, 123, 587, 993],
            "listen_penalty": 0.6,
            "risky_listen_extra": 1.1,
            "many_listens_extra": 0.4,
            "remote_bump": 0.2,
            "remote_many_extra": 0.5,
            "remote_many_count": 10,
            # parent/launcher context
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
            "susp_launcher_penalty": 0.7,
            # elevation/service context
            "elev_from_user_penalty": 0.9,
            "service_userdir_penalty": 0.9,
            # prevalence with time-decay
            "prevalence_halflife_days": 14.0,
            "hash_seen_thresh": 4.0,
            "exe_seen_thresh": 8.0,
            "prevalence_hash_bonus": 0.8,
            "prevalence_exe_bonus": 0.4,
            "unknown_hash_penalty": 0.4,
            # class mapping thresholds (soft rules to pick a "cls" label)
            "class_rules": {
                # these are evaluated in order; first hit wins
                "system": {"if_system_dir": True, "if_signed": True},
                "service": {"if_service": True},
                "dev_tool": {"if_parent_is_dev_shell": True},
                "game": {"if_publisher_any": ["valve", "epic", "unity"]},
                "popular_app": {"if_publisher_any": ["google", "mozilla", "adobe", "oracle"]},
            },
        }
        try:
            with open(self.weights_path, encoding="utf-8") as f:
                overrides = json.load(f) or {}
            if isinstance(overrides, dict):
                # merge simple dicts; nested dicts use a shallow update for simplicity
                for k, v in overrides.items():
                    if isinstance(v, dict) and isinstance(defaults.get(k), dict):
                        defaults[k].update(v)  # shallow override for nested dicts
                    else:
                        defaults[k] = v
        except Exception:
            # if anything goes wrong we just stick with defaults
            pass
        return defaults

    def _load_db(self) -> dict[str, Any]:
        # schema stays tiny and straightforward to avoid migrations
        # {
        #   "version": 2,
        #   "hash_stats": { sha256: {"seen": int, "last_seen": ts} },
        #   "exe_stats":  { basename: {"seen": int, "last_seen": ts} }
        # }
        empty = {"version": 2, "hash_stats": {}, "exe_stats": {}}
        if not os.path.exists(self.db_path):
            return empty
        try:
            with open(self.db_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    data.setdefault("version", 2)
                    data.setdefault("hash_stats", {})
                    data.setdefault("exe_stats", {})
                    return data
        except Exception:
            # corrupt or unreadable DB → start clean
            pass
        return empty

    def _save_db(self) -> None:
        # persistence is best-effort; failures must never break the pipeline
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.db, f, indent=2)
        except Exception:
            pass

    # small helpers

    def _days_since(self, ts: float) -> float:
        # convert epoch to days ago; big number if 0/None
        if not ts:
            return 1e9
        return max(0.0, (_now() - float(ts)) / 86400.0)

    def _decayed_seen(self, seen: int, last_seen: float, halflife_days: float) -> float:
        # standard exponential decay so old sightings fade out naturally
        if seen <= 0:
            return 0.0
        days = self._days_since(last_seen)
        if halflife_days <= 0:
            return float(seen)
        return float(seen) * (0.5 ** (days / float(halflife_days)))

    # main API

    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        # non-process events get a neutral "unknown" verdict right away
        if event.get("source") != "process":
            return {
                "version": "csc-v2",
                "verdict": "unknown",
                "cls": "unknown",
                "confidence": 0.35,
                "reasons": ["not a process event"],
                "signals": {},
            }

        w = self.weights  # keep the alias short for readability
        reasons: list[str] = []  # human messages we bubble up for the UI
        signals: dict[str, Any] = {}  # raw flags we expose for debugging/exports

        # normalize inputs we care about
        name = _safe_lower(event.get("name"))
        exe = _safe_lower(event.get("exe"))
        sha256 = _safe_lower(event.get("sha256"))
        base = _basename(exe)
        parent_name = _safe_lower(event.get("parent_name") or event.get("parent"))
        parent_exe = _safe_lower(event.get("parent_exe"))
        is_service = bool(event.get("is_service"))
        elevation = bool(event.get("elevation"))
        signer_valid = bool(event.get("signer_valid"))
        signer_subject = _safe_lower(event.get("signer_subject") or "")
        ports = event.get("listening_ports") or []
        remotes = event.get("remote_addrs") or event.get("remote_endpoints") or []
        if isinstance(remotes, dict):
            # flatten proto-keyed dicts into a single list
            try:
                flat = []
                for v in remotes.values():
                    flat.extend(v)
                remotes = flat
            except Exception:
                remotes = []

        file_ctime = float(event.get("file_ctime") or 0.0)
        file_size_mb = _to_float(event.get("file_size_mb"))

        # compute an internal score S (unbounded real)
        # we start near zero, then push up/down with small additive bumps
        S = 0.0

        # 1) path context (system vs program files vs temp/downloads)
        in_system = bool(exe and any(seg in exe for seg in w["system_paths"]))
        in_pf = bool(exe and any(seg in exe for seg in w["program_files_paths"]))
        in_userish = bool(
            exe and any(seg in exe for seg in (w["temp_paths"] + w["downloads_paths"]))
        )

        signals["in_system_dir"] = in_system
        signals["in_program_files"] = in_pf
        signals["in_user_or_downloads"] = in_userish

        if in_system:
            S += 0.9  # system path usually good (not absolute, but a solid push)
            reasons.append("executable under system directory")
        elif in_pf:
            S += 0.4  # program files is decent signal for installed software
            reasons.append("executable under Program Files")
        if in_userish:
            S -= 1.0  # user/temp/downloads is generally risky to run from
            reasons.append("executable under user/temp/downloads path")

        # 2) code signing (strong safety cue when valid, especially with known publishers)
        if signer_valid:
            S += float(w["prefer_signed_bonus"])
            reasons.append("valid code signature")
            signals["publisher"] = signer_subject
            # light class cue: vendor buckets map to rough families (games, dev, popular)
            for vendor, bucket in w["publisher_buckets"].items():
                if vendor in signer_subject:
                    signals.setdefault("publisher_bucket_hits", []).append(bucket)
        else:
            if in_system:
                S -= float(w["unsigned_system_penalty"])
                reasons.append("unsigned binary located in system directory")

        # 3) name-based oddities (entropy / hexish / misspells / suspicious tokens)
        if name:
            ent = _shannon_entropy(name)
            if ent >= float(w["entropy_name_thresh"]):
                S -= 0.4
                reasons.append("name has high entropy")
            if len(name) >= int(w["hexish_name_len"]) and _looks_hexish(name):
                S -= 0.5
                reasons.append("name looks hex/packed-like")
            if any(tok in name for tok in w["susp_name_tokens"]):
                S -= 0.5
                reasons.append("suspicious name token")
            for canonical, miss in w["misspell_tokens"]:
                if miss in name and canonical not in name:
                    S -= 0.3
                    reasons.append(f"name looks like a misspelling of '{canonical}'")

        # 4) file age/size (fresh and tiny outside system dirs tends to be risky)
        if file_ctime and exe:
            age_days = self._days_since(file_ctime)
            signals["file_age_days"] = age_days
            if age_days <= float(w["file_age_days_fresh"]) and not in_system:
                S -= 0.5
                reasons.append("very new binary outside system directory")
        if file_size_mb is not None:
            signals["file_size_mb"] = file_size_mb
            if file_size_mb <= float(w["tiny_binary_mb"]):
                S -= 0.5
                reasons.append("binary size is unusually small")

        # 5) network posture (listening and especially on risky ports is a red flag)
        risky = set(int(p) for p in w["risky_ports"])
        listen_ports = [p for p in ports if _safe_int(p) >= 0]
        if listen_ports:
            S -= float(w["listen_penalty"])
            reasons.append("process is listening on a port")
            if any(_safe_int(p) in risky for p in listen_ports):
                S -= float(w["risky_listen_extra"])
                reasons.append("listening on a risky port")
            if len(listen_ports) >= 3:
                S -= float(w["many_listens_extra"])
                reasons.append("listening on multiple ports")

        remote_count = 0
        try:
            remote_count = len(remotes)
        except Exception:
            remote_count = 0
        if remote_count > 0:
            S += float(w["remote_bump"])  # outbound isn’t evil; modern apps talk a lot
            reasons.append("has remote connections")
            if remote_count >= int(w["remote_many_count"]):
                S += float(w["remote_many_extra"])
                reasons.append("many remote connections")
        signals["listening_ports"] = listen_ports
        signals["remote_count"] = remote_count

        # 6) parent / launcher context (script shells / LOLBINs reduce trust a notch)
        if parent_name or parent_exe:
            parent_base = _basename(parent_exe) if parent_exe else parent_name
            if parent_base and parent_base in w["susp_launchers"]:
                S -= float(w["susp_launcher_penalty"])
                reasons.append(f"launched by suspicious tool ({parent_base})")
                signals["parent"] = parent_base

        # 7) elevation/service in user locations (classic "service from user dir" smell)
        if elevation and in_userish:
            S -= float(w["elev_from_user_penalty"])
            reasons.append("elevated binary from user/temp path")
        if is_service and in_userish:
            S -= float(w["service_userdir_penalty"])
            reasons.append("service binary resides in user/temp path")

        # 8) prevalence with time-decay (things seen often here earn trust gradually)
        halflife = float(w["prevalence_halflife_days"])

        if sha256:
            hs = self.db["hash_stats"].get(sha256, {"seen": 0, "last_seen": 0.0})
            seen_prev = int(hs.get("seen", 0) or 0)
            last_seen = _to_float(hs.get("last_seen")) or 0.0
            # exclude current sighting from effective-seen
            eff = self._decayed_seen(max(seen_prev - 1, 0), last_seen, halflife)
            signals["hash_eff_seen"] = eff
            if eff >= float(w["hash_seen_thresh"]):
                S += float(w["prevalence_hash_bonus"])
                reasons.append("hash is common on this machine (time-decayed)")
            else:
                S -= float(w["unknown_hash_penalty"])
                reasons.append("hash is rare/unknown on this machine")

        if base:
            es = self.db["exe_stats"].get(base.lower(), {"seen": 0, "last_seen": 0.0})
            seen_prev2 = int(es.get("seen", 0) or 0)
            last_seen2 = _to_float(es.get("last_seen")) or 0.0
            # exclude current sighting from effective-seen
            eff2 = self._decayed_seen(max(seen_prev2 - 1, 0), last_seen2, halflife)
            signals["exe_eff_seen"] = eff2
            if eff2 >= float(w["exe_seen_thresh"]):
                S += float(w["prevalence_exe_bonus"])
                reasons.append("executable name seen often here (time-decayed)")

        # classify "cls" (family) before we choose verdict, because reasons may reference it
        cls = self._classify(signals, signer_subject, is_service, parent_exe or parent_name)

        # convert internal S into a categorical verdict and a confidence
        verdict, confidence = self._to_verdict_and_confidence(S, w)

        # record the sighting *after* scoring so decay uses pre-update stats
        try:
            now_ts = _now()
            if sha256:
                h2 = self.db["hash_stats"].setdefault(sha256, {"seen": 0, "last_seen": 0.0})
                h2["seen"] = int(h2.get("seen", 0)) + 1
                h2["last_seen"] = now_ts
            if base:
                e2 = self.db["exe_stats"].setdefault(base.lower(), {"seen": 0, "last_seen": 0.0})
                e2["seen"] = int(e2.get("seen", 0)) + 1
                e2["last_seen"] = now_ts
        except Exception:
            # never fail scoring on telemetry bookkeeping
            pass

        # persist DB at the end; never fail the flow if this throws
        self._save_db()

        # return the v2 shape expected by the updated dashboard
        return {
            "version": "csc-v2",
            "verdict": verdict,
            "cls": cls,
            "confidence": confidence,
            "reasons": reasons,
            "signals": signals,
        }

    # helpers: class + verdict mapping

    def _classify(
        self, signals: dict[str, Any], publisher: str, is_service: bool, parent_path: str
    ) -> str:
        # this maps to a coarse "family" label that the UI can badge nicely
        w = self.weights

        # quick booleans for readability
        in_system = bool(signals.get("in_system_dir"))
        parent_base = _basename(_safe_lower(parent_path)) if parent_path else ""
        parent_is_dev_shell = parent_base in {"powershell.exe", "pwsh.exe", "cmd.exe"}

        # evaluate rule buckets in order; first match wins
        rules: dict[str, dict[str, Any]] = dict(w.get("class_rules", {}))
        for label, rule in rules.items():
            # simple checks; each key is optional and treated as AND within the rule
            if rule.get("if_system_dir") and not in_system:
                continue
            if rule.get("if_signed") and not publisher:
                continue
            vend_list = [v for v in rule.get("if_publisher_any", [])]
            if vend_list and not any(v in publisher for v in vend_list):
                continue
            if rule.get("if_service") and not is_service:
                continue
            if rule.get("if_parent_is_dev_shell") and not parent_is_dev_shell:
                continue
            return label  # first matching bucket wins

        # fallbacks if no rule matched
        if is_service:
            return "service"
        if parent_is_dev_shell:
            return "dev_tool"
        if signals.get("in_program_files"):
            return "utility"
        return "unknown"

    def _to_verdict_and_confidence(self, S: float, w: dict[str, Any]) -> tuple[str, float]:
        # map internal score S to categorical verdict using cut points
        # confidence uses a smooth logistic curve around the chosen region
        if S < float(w["cut_malicious"]):
            verdict = "malicious"
            # farther below the cut → higher confidence
            confidence = min(1.0, 0.6 + (float(w["cut_malicious"]) - S) / 4.0)
        elif S < float(w["cut_suspicious"]):
            verdict = "suspicious"
            confidence = 0.55 + (float(w["cut_suspicious"]) - S) / 6.0
        elif S < float(w["cut_caution"]):
            verdict = "caution"
            confidence = 0.45 + (S - float(w["cut_suspicious"])) / 6.0
        elif S < float(w["cut_trusted"]):
            verdict = "trusted"
            confidence = 0.55 + (S - float(w["cut_caution"])) / 6.0
        else:
            verdict = "trusted"
            confidence = min(1.0, 0.8 + (S - float(w["cut_trusted"])) / 4.0)

        # clamp confidence strictly to [0,1] to keep UI sane
        confidence = max(0.0, min(1.0, float(confidence)))
        return verdict, confidence
