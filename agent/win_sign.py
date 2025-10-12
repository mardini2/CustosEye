# agent/win_sign.py for Windows Authenticode signature checking
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any


def get_signature_info(path: str) -> dict[str, Any]:
    """
    Windows-only: returns {"valid": bool, "subject": str} using PowerShell Get-AuthenticodeSignature.
    Best-effort; returns {} on failure or non-Windows.
    """
    try:
        if sys.platform != "win32":
            return {}
        p = (path or "").strip().strip('"')
        if not p or not os.path.exists(p):
            return {}

        ps = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$s=Get-AuthenticodeSignature -FilePath '{}' ; "
            "$o=@{{ valid=($s.Status -eq 'Valid'); subject=($s.SignerCertificate.Subject) }} ; "
            "ConvertTo-Json -Compress -InputObject $o".format(p.replace("'", "''")),
        ]
        proc = subprocess.run(ps, capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            return {}
        out = proc.stdout.strip()
        if not out:
            return {}
        data = json.loads(out)
        if not isinstance(data, dict):
            return {}
        return {
            "valid": bool(data.get("valid", False)),
            "subject": str(data.get("subject") or "")[:512],
        }
    except Exception:
        return {}
