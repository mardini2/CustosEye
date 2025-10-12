"""
goal: apply JSON-defined rules to events and return a decision with "level" and "reason".

it adds targeted match fields so you can reduce noise:
- when.source: "process" | "network" | "integrity"
- when.listening_port: true/false      # any listening port on the event
- when.name_contains: str | [str,...]  # match process name substring(s)
- when.exe_contains: str | [str,...]   # match executable path substring(s)
- when.port_in: [int,...]              # match if any listed port is present
- when.port_not_in: [int,...]          # match if none of these ports are present
- when.any_remote: true/false          # any remote endpoints present

rules are evaluated top-to-bottom; the first match wins. keep rules ordered from most specific to most general.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from typing import Any

StrOrList = str | Sequence[str]


def _ensure_list(x: StrOrList | None) -> list[str]:
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    return [str(v) for v in x]


class RulesEngine:
    def __init__(self, path: str) -> None:
        self.path = path
        self.rules: list[dict[str, Any]] = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []

    def _match(self, when: dict[str, Any], event: dict[str, Any]) -> bool:
        # source match
        src = when.get("source")
        if src and event.get("source") != src:
            return False

        # listening port presence (for process events we expect list on event["listening_ports"])
        if "listening_port" in when:
            need = bool(when["listening_port"])
            has = bool(event.get("listening_ports"))
            if need and not has:
                return False
            if not need and has:
                return False

        # name_contains
        names = _ensure_list(when.get("name_contains"))
        if names:
            evname = (event.get("name") or "").lower()
            if not any(s.lower() in evname for s in names):
                return False

        # exe_contains
        exes = _ensure_list(when.get("exe_contains"))
        if exes:
            evexe = (event.get("exe") or "").lower()
            if not any(s.lower() in evexe for s in exes):
                return False

        # port_in (any matching port)
        port_in = when.get("port_in")
        if port_in:
            ev_ports = set(event.get("listening_ports") or [])
            if not ev_ports.intersection(set(port_in)):
                return False

        # port_not_in (no matching ports)
        port_not_in = when.get("port_not_in")
        if port_not_in:
            ev_ports = set(event.get("listening_ports") or [])
            if ev_ports.intersection(set(port_not_in)):
                return False

        # any_remote (for outbound connections)
        if "any_remote" in when:
            need_remote = bool(when["any_remote"])
            has_remote = bool(event.get("remote_addrs") or event.get("remote_endpoints"))
            if need_remote and not has_remote:
                return False
            if not need_remote and has_remote:
                return False

        return True

    def evaluate(self, event: dict[str, Any]) -> dict[str, str]:
        decision = {"level": "info", "reason": "no rule matched"}
        for rule in self.rules:
            when = rule.get("when", {})
            if self._match(when, event):
                then = rule.get("then", {})
                decision = {
                    "level": then.get("level", "info"),
                    "reason": then.get("reason", rule.get("name", "rule triggered")),
                }
                break
        return decision
