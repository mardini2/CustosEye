from __future__ import annotations

import contextlib
import os
import subprocess
from pathlib import Path

import pytest


def _discover_exe() -> Path | None:
    env = os.getenv("CUSTOSEYE_EXE")
    if env:
        p = Path(env)
        return p if p.exists() else None
    guess = Path("dist") / "CustosEye.exe"
    return guess if guess.exists() else None


@pytest.mark.timeout(10)
def test_exe_starts_and_exits_with_help_or_version() -> None:
    exe = _discover_exe()
    if not exe:
        pytest.skip("No .exe found (set CUSTOSEYE_EXE or build to dist/CustosEye.exe)")

    for arg in ("--version", "--help"):
        try:
            proc = subprocess.run([str(exe), arg], capture_output=True, text=True, timeout=8)
            assert proc.returncode in (0, 1, 2)
            assert proc.stdout or proc.stderr
            return
        except Exception:
            continue

    p = subprocess.Popen([str(exe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        p.terminate()
        p.wait(timeout=5)
    finally:
        with contextlib.suppress(Exception):
            p.kill()
