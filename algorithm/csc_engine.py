"""
Goal: Compute a simple, explainable trust score (0-100) for process events.

Design:
- Stateless scoring per event + tiny persistence in a local trust DB (JSON) for "known hash" boosts.
- Inputs expected on "process" events (from agent.monitor): name, exe, sha256, listening_ports, remote_addrs, etc.
- Weights are loaded from data/csc_weights.json with safe defaults if file is missing.
- Output dict:
    {
      "trust": 0..100,
      "label": "high" | "medium" | "low",
      "reasons": ["why the score changed", ...]
    }
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


class CSCTrustEngine:
    def __init__(self, weights_path: str, db_path: str) -> None:
        self.weights_path = weights_path
        self.db_path = db_path
        self.weights = self._load_weights()
        self.db = self._load_db()

    # ---------- config / db ----------
    def _load_weights(self) -> dict[str, Any]:
        defaults = {
            "base": 70,
            "deduct_listening": 10,
            "deduct_risky_port": 25,
            "deduct_remote": 10,
            "deduct_temp_path": 15,
            "deduct_susp_name": 10,
            "bonus_known_hash": 15,
            "bonus_system_dir": 10,
            "risky_ports": [22, 3389, 4444, 5900],
            "susp_name_tokens": [
                "tmp",
                "temp",
                "svhost",
                "update",
                "patch",
                "fix",
                "agent",
                "service",
            ],
            "system_paths": ["\\windows\\system32", "/windows/system32"],
            "temp_paths": ["\\appdata\\local\\temp", "/appdata/local/temp", "\\temp\\", "/tmp/"],
            "trust_low_threshold": 40,
            "trust_high_threshold": 75,
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
        if not os.path.exists(self.db_path):
            return {"hash_stats": {}}  # sha256 -> {"seen": int, "last_seen": ts}
        try:
            with open(self.db_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    data.setdefault("hash_stats", {})
                    return data
        except Exception:
            pass
        return {"hash_stats": {}}

    def _save_db(self) -> None:
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.db, f, indent=2)
        except Exception:
            # Non-fatal in Phase 2
            pass

    # ---------- scoring ----------
    def evaluate(self, event: dict[str, Any]) -> dict[str, Any]:
        if event.get("source") != "process":
            return {"trust": 70, "label": "medium", "reasons": ["not a process event"]}

        w = self.weights
        score = float(w["base"])
        reasons: list[str] = []

        name = (event.get("name") or "").lower()
        exe = (event.get("exe") or "").lower()
        sha256 = (event.get("sha256") or "").lower()
        ports = event.get("listening_ports") or []
        remotes = event.get("remote_addrs") or event.get("remote_endpoints") or []

        # memory: track hash frequency
        if sha256:
            stats = self.db["hash_stats"].setdefault(sha256, {"seen": 0, "last_seen": 0.0})
            stats["seen"] += 1
            stats["last_seen"] = time.time()

        # listeners
        if ports:
            score -= w["deduct_listening"]
            reasons.append("process is listening on a port")
            # risky ports
            risky = set(int(p) for p in w["risky_ports"])
            if any(int(p) in risky for p in ports):
                score -= w["deduct_risky_port"]
                reasons.append("listening on a risky port")

        # outbound
        if remotes:
            score -= w["deduct_remote"]
            reasons.append("has remote connections")

        # path heuristics
        if exe:
            if any(seg in exe for seg in w["system_paths"]):
                score += w["bonus_system_dir"]
                reasons.append("executable under system directory")
            if any(seg in exe for seg in w["temp_paths"]):
                score -= w["deduct_temp_path"]
                reasons.append("executable under temp/appdata directory")

        # name heuristics
        if name and any(tok in name for tok in w["susp_name_tokens"]):
            score -= w["deduct_susp_name"]
            reasons.append("suspicious name token")

        # known/unknown hash bonus (very naive in Phase 2)
        if sha256 and self.db["hash_stats"].get(sha256, {}).get("seen", 0) > 3:
            score += w["bonus_known_hash"]
            reasons.append("known hash on this machine")

        # clamp and label
        score = max(0.0, min(100.0, score))
        if score < w["trust_low_threshold"]:
            label = "low"
        elif score >= w["trust_high_threshold"]:
            label = "high"
        else:
            label = "medium"

        self._save_db()
        return {"trust": int(round(score)), "label": label, "reasons": reasons}
