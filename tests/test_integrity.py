"""
Goal: Validate integrity checker behavior on missing files and bad hashes.
"""
from __future__ import annotations

import json
import os
from typing import List, Dict

from agent.integrity_check import IntegrityChecker


def test_integrity_missing(tmp_path):
    targets = [{"path": str(tmp_path / "nope.bin"), "sha256": "deadbeef"}]
    tpath = tmp_path / "targets.json"
    tpath.write_text(json.dumps(targets), encoding="utf-8")

    events: List[Dict[str, str]] = []
    ic = IntegrityChecker(targets_path=str(tpath), publish=lambda e: events.append(e), interval_sec=0.01)

    import threading, time
    t = threading.Thread(target=ic.run, daemon=True)
    t.start()
    time.sleep(0.05)

    assert any(e.get("reason", "").startswith("File missing") for e in events)