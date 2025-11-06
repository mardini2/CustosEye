"""
goal: verify the integrity of configured files by recomputing SHA256 and comparing to known-good values,
      but only emit events when a file's status changes (quiet output).

design:
- targets are listed in data/integrity_targets.json:
  [
    {"path": "%WINDIR%/System32/notepad.exe", "sha256": "..."},
    {"path": "data/fixtures/ok.txt", "sha256": "..."}
  ]
- paths can be relative, absolute, with %ENVVARS%, or with ~.
- status transitions that trigger a print:
    missing  -> ok | mismatch | noaccess | error
    ok       -> missing | mismatch | noaccess | error
    mismatch -> ok | missing | noaccess | error
    noaccess -> ok | missing | mismatch | error
    error    -> ok | missing | mismatch | noaccess
- interval defaults to 30s; you can set a faster interval from app/console.py when constructing IntegrityChecker.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
from collections.abc import Callable
from typing import Any

PublishFn = Callable[[dict[str, Any]], None]


class IntegrityChecker:
    """Continuously verifies file integrity against expected SHA256 hashes and emits only on state changes."""

    def __init__(self, targets_path: str, publish: PublishFn, interval_sec: float = 30.0) -> None:
        """
        :param targets_path: Path to integrity_targets.json
        :param publish: Callback for publishing alert events
        :param interval_sec: How often to recheck files (seconds)
        """
        self.targets_path = targets_path
        self.publish = publish
        self.interval = interval_sec
        self.targets: list[dict[str, str]] = []
        # path -> "ok" | "mismatch" | "missing" | "noaccess" | "error"
        self._last_status: dict[str, str] = {}
        self._load_targets()

    def _load_targets(self) -> None:
        """Load integrity targets from JSON file."""
        if not os.path.exists(self.targets_path):
            self.targets = []
            return
        try:
            with open(self.targets_path, encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    # Empty file - treat as empty list
                    self.targets = []
                    return
                data = json.loads(content)
            self.targets = data if isinstance(data, list) else []
        except (json.JSONDecodeError, ValueError):
            # Invalid JSON - treat as empty list
            self.targets = []
        except Exception:
            # Any other error - treat as empty list
            self.targets = []

    @staticmethod
    def _sha256(path: str) -> str:
        """Compute SHA256 of a file (1 MB buffer for efficiency)."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _normalize_path(self, raw: str) -> str:
        """
        Normalize and expand paths so they work on any Windows system.
        Handles %ENVVARS%, ~, and mixed slashes.
        """
        expanded = os.path.expandvars(os.path.expanduser(raw))
        normalized = str(pathlib.Path(expanded))
        return normalized

    def _emit_if_changed(self, path: str, status: str, payload: dict[str, Any]) -> None:
        """
        Publish the event only if the status for this path changed since the last check.
        """
        prev = self._last_status.get(path)
        if prev != status:
            self._last_status[path] = status
            self.publish(payload)

    def run(self) -> None:
        """Main loop: check each file's integrity at regular intervals and emit only on change."""
        while True:
            # Reload targets on each iteration to pick up changes
            self._load_targets()
            for entry in self.targets:
                raw_path = entry.get("path", "")
                expected = entry.get("sha256", "").lower()

                if not raw_path or not expected:
                    continue

                path = self._normalize_path(raw_path)

                # missing file
                if not os.path.exists(path):
                    self._emit_if_changed(
                        path,
                        "missing",
                        {
                            "source": "integrity",
                            "level": "critical",  # Changed to critical for deletion
                            "reason": f"File deleted or missing: {path}",
                            "path": path,
                        },
                    )
                    continue

                try:
                    actual = self._sha256(path).lower()
                    if actual != expected:
                        # Emit single combined event message
                        self._emit_if_changed(
                            path,
                            "mismatch",
                            {
                                "source": "integrity",
                                "level": "critical",
                                "reason": "File content changed (Hash changed)",
                                "path": path,
                                "expected": expected,
                                "actual": actual,
                            },
                        )
                    else:
                        # When hash matches, update existing CRITICAL entry instead of creating new INFO event
                        # This happens after user marks change as safe (baseline updated, causing mismatch->ok transition)
                        prev_status = self._last_status.get(path)
                        if prev_status == "mismatch":
                            # Transitioning from mismatch to ok - update existing CRITICAL entry
                            # Emit CRITICAL event with "Hash verified" reason (will be updated in-place by backend)
                            self._emit_if_changed(
                                path,
                                "ok",
                                {
                                    "source": "integrity",
                                    "level": "critical",  # Keep as CRITICAL, not INFO
                                    "reason": "Hash verified",  # Will be updated to "✔ Hash verified" in green
                                    "path": path,
                                    "update_existing": True,  # Flag to update existing CRITICAL entry
                                },
                            )
                        else:
                            # Transitioning from missing/noaccess/error to ok - emit normal event
                            self._emit_if_changed(
                                path,
                                "ok",
                                {
                                    "source": "integrity",
                                    "level": "info",
                                    "reason": "Hash verified",
                                    "path": path,
                                },
                            )
                except PermissionError:
                    self._emit_if_changed(
                        path,
                        "noaccess",
                        {
                            "source": "integrity",
                            "level": "warning",
                            "reason": f"No permission to read: {path}",
                            "path": path,
                        },
                    )
                except Exception as e:
                    self._emit_if_changed(
                        path,
                        "error",
                        {
                            "source": "integrity",
                            "level": "warning",
                            "reason": f"Integrity check error: {e}",
                            "path": path,
                        },
                    )

            time.sleep(self.interval)
