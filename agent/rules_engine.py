"""
goal: evaluates JSON-defined rules against events to determine alert level and reason. loads rules from
a JSON file and matches events based on various criteria like source type, process names, executable
paths, listening ports, and remote connections. rules are evaluated in order and the first match wins,
so they should be ordered from most specific to most general.
"""

from __future__ import annotations  # lets us use string annotations before classes are defined

import json  # for loading rules from JSON files
import os  # for checking if the rules file exists
from collections.abc import Sequence  # type hint for sequences (lists, tuples, etc)
from typing import Any  # type hint for flexible dictionary values

# type alias for things that can be either a string or a list/sequence of strings
StrOrList = str | Sequence[str]


def _ensure_list(x: StrOrList | None) -> list[str]:
    if x is None:  # if it is None, return empty list
        return []
    if isinstance(x, str):  # if it is a single string, wrap it in a list
        return [x]
    return [
        str(v) for v in x
    ]  # if it is already a sequence, convert each item to string and return as list


class RulesEngine:
    def __init__(self, path: str) -> None:
        self.path = path  # path to the JSON file containing the rules
        self.rules: list[dict[str, Any]] = self._load_rules()  # load the rules when we're created

    def _load_rules(self) -> list[dict[str, Any]]:
        if not os.path.exists(self.path):  # if the rules file doesn't exist
            return []  # return empty list, no rules to apply
        with open(self.path, encoding="utf-8") as f:  # open the JSON file as UTF-8 text
            data = json.load(f)  # parse the JSON
            return (
                data if isinstance(data, list) else []
            )  # make sure it is a list, otherwise return empty list

    def _match(self, when: dict[str, Any], event: dict[str, Any]) -> bool:
        # source match
        src = when.get("source")  # get the required source type from the rule
        if (
            src and event.get("source") != src
        ):  # if rule specifies a source and event does not match
            return False  # this rule doesn't match

        # listening port presence (for process events we expect list on event["listening_ports"])
        if "listening_port" in when:  # if the rule checks for listening ports
            need = bool(
                when["listening_port"]
            )  # what the rule wants (True = must have, False = must not have)
            has = bool(
                event.get("listening_ports")
            )  # whether the event actually has listening ports
            if need and not has:  # rule wants ports but event doesn't have any
                return False  # doesn't match
            if not need and has:  # rule doesn't want ports but event has some
                return False  # doesn't match

        # name_contains
        names = _ensure_list(
            when.get("name_contains")
        )  # get list of strings to search for in process name
        if names:  # if there are names to check
            evname = (
                event.get("name") or ""
            ).lower()  # get the event's process name (lowercase, empty string if missing)
            if not any(
                s.lower() in evname for s in names
            ):  # check if any of the search strings are in the name
                return False  # none of them matched, so rule doesn't match

        # exe_contains
        exes = _ensure_list(
            when.get("exe_contains")
        )  # get list of strings to search for in executable path
        if exes:  # if there are paths to check
            evexe = (
                event.get("exe") or ""
            ).lower()  # get the event's executable path (lowercase, empty string if missing)
            if not any(
                s.lower() in evexe for s in exes
            ):  # check if any of the search strings are in the path
                return False  # none of them matched, so rule doesn't match

        # port_in (any matching port)
        port_in = when.get("port_in")  # get list of ports that should be present
        if port_in:  # if the rule specifies ports that must be in the event
            ev_ports = set(
                event.get("listening_ports") or []
            )  # get the event's listening ports as a set
            if not ev_ports.intersection(
                set(port_in)
            ):  # check if any of the required ports are in the event
                return False  # no matching ports, so rule doesn't match

        # port_not_in (no matching ports)
        port_not_in = when.get("port_not_in")  # get list of ports that should NOT be present
        if port_not_in:  # if the rule specifies ports that must not be in the event
            ev_ports = set(
                event.get("listening_ports") or []
            )  # get the event's listening ports as a set
            if ev_ports.intersection(
                set(port_not_in)
            ):  # check if any of the forbidden ports are in the event
                return False  # found a forbidden port, so rule doesn't match

        # any_remote (for outbound connections)
        if "any_remote" in when:  # if the rule checks for remote connections
            need_remote = bool(
                when["any_remote"]
            )  # what the rule wants (True = must have, False = must not have)
            has_remote = bool(
                event.get("remote_addrs") or event.get("remote_endpoints")
            )  # check both possible field names for remote addresses
            if (
                need_remote and not has_remote
            ):  # rule wants remote connections but event doesn't have any
                return False  # doesn't match
            if (
                not need_remote and has_remote
            ):  # rule doesn't want remote connections but event has some
                return False  # doesn't match

        return True  # all checks passed, this rule matches the event

    def evaluate(self, event: dict[str, Any]) -> dict[str, str]:
        decision = {
            "level": "info",
            "reason": "no rule matched",
        }  # default decision if no rules match
        for rule in self.rules:  # loop through rules in order (first match wins)
            when = rule.get("when", {})  # get the conditions that must be met
            if self._match(when, event):  # check if this rule matches the event
                then = rule.get("then", {})  # get the action/result for when this rule matches
                decision = {
                    "level": then.get("level", "info"),  # get the alert level, default to "info"
                    "reason": then.get(
                        "reason", rule.get("name", "rule triggered")
                    ),  # get the reason, fall back to rule name or generic message
                }
                break  # stop checking more rules since we found a match
        return decision  # return the decision (level and reason)
