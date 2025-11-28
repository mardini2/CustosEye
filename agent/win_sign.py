# SPDX-License-Identifier: GPL-3.0-or-later
"""
goal: checks Windows Authenticode signatures for executable files using PowerShell.
returns whether the signature is valid and the certificate subject. only works on Windows,
returns empty dict on other platforms or if anything goes wrong.
"""

from __future__ import annotations  # lets us use string annotations before functions are defined

import json  # for parsing JSON output from PowerShell
import os  # for checking if the file path exists
import subprocess  # for running PowerShell commands
import sys  # for checking if we are on Windows
from typing import Any  # type hint for flexible dictionary values


def get_signature_info(path: str) -> dict[str, Any]:
    """
    Windows-only: returns {"valid": bool, "subject": str} using PowerShell Get-AuthenticodeSignature.
    Best-effort; returns {} on failure or non-Windows.
    """
    try:
        if sys.platform != "win32":  # if we are not on Windows
            return {}  # can not check signatures, return empty dict
        p = (path or "").strip().strip('"')  # clean up the path, remove whitespace and quotes
        if not p or not os.path.exists(p):  # if path is empty or file doesn't exist
            return {}  # can not check a non-existent file, return empty dict

        ps = [
            "powershell",  # run PowerShell
            "-NoProfile",  # do not load user profile (faster startup)
            "-ExecutionPolicy",  # set execution policy
            "Bypass",  # bypass any execution policy restrictions
            "-Command",  # run a command instead of a script
            "$s=Get-AuthenticodeSignature -FilePath '{}' ; "
            "$o=@{{ valid=($s.Status -eq 'Valid'); subject=($s.SignerCertificate.Subject) }} ; "
            "ConvertTo-Json -Compress -InputObject $o".format(
                p.replace("'", "''")
            ),  # PowerShell command that gets signature, checks if valid, extracts subject, and converts to JSON (escape single quotes in path)
        ]
        proc = subprocess.run(
            ps, capture_output=True, text=True, timeout=5
        )  # run PowerShell command, capture output, wait max 5 seconds
        if proc.returncode != 0:  # if the command failed
            return {}  # return empty dict
        out = proc.stdout.strip()  # get the output and remove whitespace
        if not out:  # if there's no output
            return {}  # return empty dict
        data = json.loads(out)  # parse the JSON output from PowerShell
        if not isinstance(data, dict):  # make sure we got a dictionary
            return {}  # if not, return empty dict
        return {
            "valid": bool(data.get("valid", False)),  # convert to boolean, default to False
            "subject": str(data.get("subject") or "")[
                :512
            ],  # get subject string, limit to 512 characters to avoid huge values
        }
    except Exception:  # if anything goes wrong (timeout, JSON parse error, etc)
        return {}  # return empty dict instead of crashing
