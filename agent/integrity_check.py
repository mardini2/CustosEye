"""
goal: continuously monitors file integrity by checking SHA256 hashes against expected values.
only emits events when a file's status changes (missing -> ok, ok -> mismatch, etc).
reloads the target list from JSON on each check loop so changes take effect immediately.
handles various file states: ok, missing, mismatch, noaccess, and error.
"""

from __future__ import (
    annotations,
)  # lets us use string annotations like "IntegrityChecker" before the class is defined

import hashlib  # for computing SHA256 hashes of files
import json  # for reading the targets JSON file
import os  # for checking if files exist and expanding environment variables
import pathlib  # for normalizing file paths
import time  # for sleeping between check intervals
from collections.abc import Callable  # type hint for function callbacks
from typing import Any  # type hint for flexible dictionary values

# type alias for the publish callback, takes a dictionary and returns nothing
PublishFn = Callable[[dict[str, Any]], None]


class IntegrityChecker:
    """Continuously verifies file integrity against expected SHA256 hashes and emits only on state changes."""

    def __init__(self, targets_path: str, publish: PublishFn, interval_sec: float = 30.0) -> None:
        """
        :param targets_path: Path to integrity_targets.json
        :param publish: Callback for publishing alert events
        :param interval_sec: How often to recheck files (seconds)
        """
        self.targets_path = (
            targets_path  # where to find the JSON file with file paths and expected hashes
        )
        self.publish = publish  # callback function to send events/alerts to
        self.interval = interval_sec  # how many seconds to wait between check cycles
        self.targets: list[dict[str, str]] = []  # list of target files to check, loaded from JSON
        # tracks the last known status for each file path so we only emit on changes
        # path -> "ok" | "mismatch" | "missing" | "noaccess" | "error"
        self._last_status: dict[str, str] = {}
        self._load_targets()  # load the initial list of files to monitor

    def _load_targets(self) -> None:
        """Load integrity targets from JSON file."""
        if not os.path.exists(self.targets_path):  # check if the targets file exists
            self.targets = []  # no file means no targets to check
            return
        try:
            with open(self.targets_path, encoding="utf-8") as f:  # open the JSON file as UTF-8 text
                content = f.read().strip()  # read everything and strip whitespace
                if not content:  # if the file is empty after stripping
                    # empty file, so treat as empty list
                    self.targets = []  # no targets to monitor
                    return
                data = json.loads(content)  # parse the JSON string into Python objects
            self.targets = (
                data if isinstance(data, list) else []
            )  # make sure we got a list, otherwise use empty list
        except (json.JSONDecodeError, ValueError):  # if the JSON is malformed
            # invalid JSON, so treat as empty list
            self.targets = []  # can't parse it, so no targets
        except Exception:  # catch any other weird errors (permissions, etc)
            # any other error, so treat as empty list
            self.targets = []  # safer to just have no targets than crash

    @staticmethod
    def _sha256(path: str) -> str:
        """Compute SHA256 of a file (1 MB buffer for efficiency)."""
        h = hashlib.sha256()  # create a new SHA256 hash object
        with open(path, "rb") as f:  # open the file in binary read mode
            for chunk in iter(
                lambda: f.read(1024 * 1024), b""
            ):  # read 1MB chunks at a time until empty (more efficient for large files)
                h.update(chunk)  # feed each chunk into the hash
        return h.hexdigest()  # return the final hash as a hex string

    def _normalize_path(self, raw: str) -> str:
        """
        Normalize and expand paths so they work on any Windows system.
        Handles %ENVVARS%, ~, and mixed slashes.
        """
        expanded = os.path.expandvars(
            os.path.expanduser(raw)
        )  # expand ~ to home dir, then expand %ENVVARS% like %WINDIR%
        normalized = str(
            pathlib.Path(expanded)
        )  # convert to Path object then back to string to normalize slashes and resolve relative paths
        return normalized  # return the final normalized absolute path

    def _emit_if_changed(self, path: str, status: str, payload: dict[str, Any]) -> None:
        """
        Publish the event only if the status for this path changed since the last check.
        """
        prev = self._last_status.get(
            path
        )  # get the previous status for this file (None if first time checking)
        if prev != status:  # only do something if the status actually changed
            self._last_status[path] = status  # update our record of the status
            self.publish(payload)  # send the event/alert to the callback

    def run(self) -> None:
        """Main loop: check each file's integrity at regular intervals and emit only on change."""
        while True:  # run forever until the process is killed
            # reload targets on each iteration to pick up changes
            self._load_targets()  # reload the JSON file so we can add/remove targets without restarting
            for entry in self.targets:  # loop through each file we're supposed to monitor
                raw_path = entry.get("path", "")  # get the file path from the JSON entry

                if not raw_path:  # skip if no path
                    continue

                path = self._normalize_path(raw_path)  # expand env vars and normalize the path

                # missing file - emit immediately when file is deleted or missing
                # Check for missing files BEFORE checking for hash requirement
                # This ensures deletion events are always emitted, even for files without hashes
                file_exists = os.path.exists(path)
                if not file_exists:  # check if the file actually exists
                    # File is missing - check if we need to emit a deletion event
                    # We emit if the file was previously existing (status was not "missing")
                    # or if this is the first time we're checking this file (prev_status is None)
                    prev_status = self._last_status.get(path)
                    should_emit_deletion = prev_status != "missing"

                    if should_emit_deletion:
                        # Update status to missing and emit deletion event
                        self._last_status[path] = "missing"
                        self.publish(
                            {
                                "source": "integrity",
                                "level": "critical",
                                "reason": f"File deleted or missing: {path}",
                                "path": path,
                                "ts": time.time(),  # include timestamp for immediate event visibility
                            }
                        )
                    continue  # skip to next file since this one doesn't exist

                # File exists - if it was previously missing, clear that status
                # This ensures we can detect deletion again if the file is deleted later
                if self._last_status.get(path) == "missing":
                    # File was missing but now exists - clear missing status
                    # We don't emit an event here, just update status for future deletion detection
                    self._last_status[path] = "ok"  # will be updated by hash check below

                expected = entry.get(
                    "sha256", ""
                ).lower()  # get the expected hash (lowercase for comparison)

                if (
                    not expected
                ):  # skip this entry if hash is missing (but we already checked for missing files above)
                    # File exists but has no hash - set status to "ok" so we can detect deletion later
                    # This ensures files without hashes can still trigger deletion events
                    if self._last_status.get(path) != "ok":
                        self._last_status[path] = "ok"
                    continue

                try:
                    actual = self._sha256(path).lower()  # compute the actual hash of the file
                    if actual != expected:  # hash doesn't match - file has been modified
                        # Emit single combined event message
                        self._emit_if_changed(
                            path,
                            "mismatch",  # file content changed
                            {
                                "source": "integrity",
                                "level": "critical",
                                "reason": "File content changed (Hash changed)",
                                "path": path,
                                "expected": expected,  # what the hash should be
                                "actual": actual,  # what the hash actually is
                            },
                        )
                    else:  # hash matches - file is good
                        # when hash matches, update existing CRITICAL entry instead of creating new INFO event
                        # this happens after user marks change as safe (baseline updated, causing mismatch->ok transition)
                        prev_status = self._last_status.get(
                            path
                        )  # check what the previous status was
                        if prev_status == "mismatch":  # if it was a mismatch before, now it's fixed
                            # transitioning from mismatch to ok - update existing CRITICAL entry
                            # emit CRITICAL event with "Hash verified" reason (will be updated in-place by backend)
                            self._emit_if_changed(
                                path,
                                "ok",  # file is now verified as correct
                                {
                                    "source": "integrity",
                                    "level": "critical",  # keep as CRITICAL, not INFO
                                    "reason": "Hash verified",  # will be updated to "✔ Hash verified" in green
                                    "path": path,
                                    "update_existing": True,  # flag to update existing CRITICAL entry
                                },
                            )
                        else:  # transitioning from missing/noaccess/error back to ok
                            # transitioning from missing/noaccess/error to ok - emit normal event
                            self._emit_if_changed(
                                path,
                                "ok",  # file is verified and good
                                {
                                    "source": "integrity",
                                    "level": "info",
                                    "reason": "Hash verified",
                                    "path": path,
                                },
                            )
                except PermissionError:  # can not read the file due to permissions
                    self._emit_if_changed(
                        path,
                        "noaccess",  # no permission to access this file
                        {
                            "source": "integrity",
                            "level": "warning",
                            "reason": f"No permission to read: {path}",
                            "path": path,
                        },
                    )
                except (
                    FileNotFoundError,
                    OSError,
                ):  # file was deleted or became unavailable during processing
                    # File was deleted or storage became unavailable - emit deletion event immediately
                    prev_status = self._last_status.get(path)
                    if prev_status != "missing":  # only emit if not already in missing state
                        self._last_status[path] = "missing"  # update status to missing
                        self.publish(
                            {
                                "source": "integrity",
                                "level": "critical",
                                "reason": f"File deleted or missing: {path}",
                                "path": path,
                                "ts": time.time(),  # include timestamp for immediate event visibility
                            }
                        )
                except Exception as e:  # catch any other errors (file locked, disk error, etc)
                    self._emit_if_changed(
                        path,
                        "error",  # something went wrong checking this file
                        {
                            "source": "integrity",
                            "level": "warning",
                            "reason": f"Integrity check error: {e}",
                            "path": path,
                        },
                    )

            time.sleep(self.interval)  # wait before checking again
