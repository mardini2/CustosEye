"""
goal: collect process-level telemetry on Windows: PID, name, exe path, SHA256, memory, parent, and open TCP/UDP ports.

design:
- polls at a fixed interval (default 3s) using psutil.
- publishes structured events for each observed process and deltas for new ones.
- hashing is cached per (pid, exe_path, mtime) to avoid heavy recompute.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import psutil

# signer helper (typed shim; safe if missing)
GetSigFn = Callable[[str], dict[str, Any] | None]
try:
    from agent.win_sign import get_signature_info as _get_signature_info  # type: ignore

    get_signature_info: GetSigFn | None = _get_signature_info
except Exception:
    get_signature_info = None  # type: ignore[assignment]

PublishFn = Callable[[dict[str, Any]], None]


@dataclass
class _HashCacheKey:
    path: str
    mtime: float


class _Hasher:
    """small SHA256 hasher with naive cache keyed by (path, mtime)."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, float], str] = {}

    def sha256_file(self, path: str) -> str | None:
        try:
            st = os.stat(path)
            key = (path, st.st_mtime)
            if key in self._cache:
                return self._cache[key]
            h = hashlib.sha256()
            with open(path, "rb", buffering=1024 * 1024) as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            digest = h.hexdigest()
            self._cache[key] = digest
            return digest
        except Exception:
            return None


class ProcessMonitor:
    """polls Windows processes and publishes normalized events"""

    def __init__(self, publish: PublishFn, interval_sec: float = 3.0) -> None:
        self.publish = publish
        self.interval = interval_sec
        self._hasher = _Hasher()
        self._seen: dict[int, float] = {}
        self._sig_cache: dict[tuple[str, float], tuple[bool, str | None]] = {}

    def _proc_event(self, p: psutil.Process) -> dict[str, Any]:
        # gather fields with resilience to disappearing processes
        info: dict[str, Any] = {"source": "process"}
        try:
            info["pid"] = p.pid
            info["name"] = p.name()
            info["ppid"] = p.ppid()
            info["exe"] = p.exe() if p.exe() else None
            info["cmdline"] = " ".join(p.cmdline())
            info["username"] = p.username()
            info["create_time"] = p.create_time()
            mem = p.memory_info()
            info["rss"] = getattr(mem, "rss", None)
            info["vms"] = getattr(mem, "vms", None)
            conns = p.connections(kind="inet")  # TCP/UDP
            info["listening_ports"] = [
                c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN
            ]
            info["remote_addrs"] = [f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr]

            # hash if we have an exe
            if info.get("exe"):
                digest = self._hasher.sha256_file(info["exe"])
                info["sha256"] = digest

            # signer (Windows only), mypy-safe optional callable
            exe = info.get("exe")
            if (
                sys.platform == "win32"
                and exe
                and os.path.exists(exe)
                and get_signature_info is not None
            ):
                try:
                    sig = cast(GetSigFn, get_signature_info)(exe)
                    if sig:
                        info["signer_valid"] = bool(sig.get("valid", False))
                        subj = sig.get("subject")
                        if subj:
                            info["signer_subject"] = subj
                except Exception:
                    pass  # never break polling
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            info["status"] = "gone"
        return info

    def run(self) -> None:
        while True:
            for p in psutil.process_iter(attrs=[]):
                pid = p.pid
                # detect new processes (basic delta)
                if pid not in self._seen:
                    ev = self._proc_event(p)
                    self.publish(ev)
                self._seen[pid] = time.time()
            # remove old pids
            now = time.time()
            to_forget = [pid for pid, ts in self._seen.items() if now - ts > 60]
            for pid in to_forget:
                self._seen.pop(pid, None)
            time.sleep(self.interval)
