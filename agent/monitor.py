"""
goal: continuously monitors Windows processes and collects telemetry: PID, name, executable path, SHA256 hash,
memory usage, parent PID, and open TCP/UDP ports. Polls at regular intervals and publishes events for
new processes. Caches file hashes based on path and modification time to avoid recomputing the same files.
also extracts Windows code signature information when available.
"""

from __future__ import annotations  # lets us use string annotations before classes are defined

import hashlib  # for computing SHA256 hashes of executables
import os  # for getting file stats and checking if files exist
import sys  # for checking the platform (Windows vs other)
import time  # for tracking when we last saw processes
from collections.abc import Callable  # type hint for function callbacks
from dataclasses import dataclass  # for the hash cache key dataclass
from typing import Any, cast  # type hints for flexible dict values and type casting

import psutil  # library for getting process and system information

# type alias for the signature checker function, takes a path and returns signature info or None
GetSigFn = Callable[[str], dict[str, Any] | None]
try:
    from agent.win_sign import (
        get_signature_info as _get_signature_info,  # type: ignore  # try to import Windows signature checker
    )

    get_signature_info: GetSigFn | None = _get_signature_info  # if it worked, use it
except Exception:  # if the import failed (probably not Windows or module missing)
    get_signature_info = None  # type: ignore[assignment]  # set to None so we can check if it exists later

# type alias for the publish callback, takes an event dict and returns nothing
PublishFn = Callable[[dict[str, Any]], None]


@dataclass
class _HashCacheKey:
    path: str  # file path for the cache key
    mtime: float  # modification time for the cache key


class _Hasher:
    """small SHA256 hasher with naive cache keyed by (path, mtime)."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, float], str] = (
            {}
        )  # cache mapping (path, mtime) tuples to hash strings

    def sha256_file(self, path: str) -> str | None:
        try:
            st = os.stat(path)  # get file stats including modification time
            key = (path, st.st_mtime)  # create cache key from path and modification time
            if key in self._cache:  # check if we've hashed this exact version before
                return self._cache[key]  # return the cached hash
            h = hashlib.sha256()  # create a new SHA256 hash object
            with open(
                path, "rb", buffering=1024 * 1024
            ) as f:  # open file in binary mode with 1MB buffer
                for chunk in iter(lambda: f.read(1024 * 1024), b""):  # read 1MB chunks until empty
                    h.update(chunk)  # feed each chunk into the hash
            digest = h.hexdigest()  # get the final hash as a hex string
            self._cache[key] = digest  # store it in the cache for next time
            return digest
        except Exception:  # if anything goes wrong (file gone, permissions, etc)
            return None  # return None instead of crashing


class ProcessMonitor:
    """polls Windows processes and publishes normalized events"""

    def __init__(self, publish: PublishFn, interval_sec: float = 3.0) -> None:
        self.publish = publish  # callback function to send events to
        self.interval = interval_sec  # how many seconds to wait between polling cycles
        self._hasher = _Hasher()  # hasher instance with caching for file hashes
        self._seen: dict[int, float] = {}  # track which PIDs we've seen and when (pid -> timestamp)
        self._sig_cache: dict[tuple[str, float], tuple[bool, str | None]] = (
            {}
        )  # cache for signature info (unused but kept for future)

    def _proc_event(self, p: psutil.Process) -> dict[str, Any]:
        # gather fields with resilience to disappearing processes
        info: dict[str, Any] = {
            "source": "process"
        }  # start building the event dict with source type
        try:
            info["pid"] = p.pid  # process ID
            info["name"] = p.name()  # process name (like "notepad.exe")
            info["ppid"] = p.ppid()  # parent process ID
            info["exe"] = (
                p.exe() if p.exe() else None
            )  # full path to executable, or None if we can't get it
            info["cmdline"] = " ".join(p.cmdline())  # full command line as a single string
            info["username"] = p.username()  # user who owns the process
            info["create_time"] = p.create_time()  # when the process was created
            mem = p.memory_info()  # get memory usage info
            info["rss"] = getattr(
                mem, "rss", None
            )  # resident set size (physical memory), None if not available
            info["vms"] = getattr(mem, "vms", None)  # virtual memory size, None if not available
            conns = p.connections(kind="inet")  # TCP/UDP connections for this process
            info["listening_ports"] = [
                c.laddr.port
                for c in conns
                if c.status == psutil.CONN_LISTEN  # extract ports that are listening
            ]
            info["remote_addrs"] = [
                f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr
            ]  # format remote addresses as "ip:port"

            # hash if we have an exe
            if info.get("exe"):  # if we have an executable path
                digest = self._hasher.sha256_file(info["exe"])  # compute or get cached hash
                info["sha256"] = digest  # add hash to the event

            # signer (Windows only), mypy-safe optional callable
            exe = info.get("exe")  # get the exe path again for signature checking
            if (
                sys.platform == "win32"  # only check signatures on Windows
                and exe  # make sure we have an exe path
                and os.path.exists(exe)  # and the file actually exists
                and get_signature_info is not None  # and we have the signature checker available
            ):
                try:
                    sig = cast(GetSigFn, get_signature_info)(
                        exe
                    )  # get code signature info for the executable
                    if sig:  # if we got signature data back
                        info["signer_valid"] = bool(
                            sig.get("valid", False)
                        )  # whether the signature is valid
                        subj = sig.get("subject")  # get the certificate subject
                        if subj:  # if there's a subject
                            info["signer_subject"] = subj  # add it to the event
                except Exception:  # if signature checking fails for any reason
                    pass  # never break polling, just skip signature info
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):  # process disappeared or we can't access it
            info["status"] = "gone"  # mark that the process is gone
        return info

    def run(self) -> None:
        while True:  # run forever until the process is killed
            for p in psutil.process_iter(attrs=[]):  # iterate through all running processes
                pid = p.pid  # get the process ID
                # detect new processes (basic delta)
                if pid not in self._seen:  # if we haven't seen this PID before
                    ev = self._proc_event(p)  # gather all the process information
                    self.publish(ev)  # publish the event for this new process
                self._seen[pid] = time.time()  # update when we last saw this PID (or add it if new)
            # remove old pids
            now = time.time()  # get current time
            to_forget = [
                pid for pid, ts in self._seen.items() if now - ts > 60
            ]  # find PIDs we haven't seen in over 60 seconds
            for pid in to_forget:  # loop through PIDs to remove
                self._seen.pop(pid, None)  # remove them from our tracking dict
            time.sleep(self.interval)  # wait before checking again
