"""
Goal: Write a simple version file with current git sha for traceability.
"""
from __future__ import annotations

import os
import subprocess

sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
os.makedirs("dist", exist_ok=True)
with open("dist/VERSION.txt", "w", encoding="utf-8") as f:
    f.write(f"version: {sha}\n")