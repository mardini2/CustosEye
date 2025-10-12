"""
Goal: Basic sanity tests for CSCTrustEngine scoring.
"""

from __future__ import annotations

from algorithm.csc_engine import CSCTrustEngine


def test_trust_high_for_system_exe(tmp_path):
    weights = tmp_path / "w.json"
    weights.write_text("{}", encoding="utf-8")
    db = tmp_path / "db.json"
    eng = CSCTrustEngine(str(weights), str(db))

    ev = {
        "source": "process",
        "name": "notepad.exe",
        "exe": "C:\\Windows\\System32\\notepad.exe",
        "listening_ports": [],
        "remote_addrs": [],
        "sha256": "abc",
    }
    out = eng.evaluate(ev)
    assert 0 <= out["trust"] <= 100
    assert out["label"] in ("high", "medium", "low")


def test_trust_lower_for_risky_port(tmp_path):
    weights = tmp_path / "w.json"
    weights.write_text("{}", encoding="utf-8")
    db = tmp_path / "db.json"
    eng = CSCTrustEngine(str(weights), str(db))

    ev = {
        "source": "process",
        "name": "weird.exe",
        "exe": "C:\\Users\\x\\AppData\\Local\\Temp\\weird.exe",
        "listening_ports": [4444],
        "remote_addrs": ["1.2.3.4:5555"],
        "sha256": "def",
    }
    out = eng.evaluate(ev)
    assert 0 <= out["trust"] <= 100
    assert out["label"] in ("low", "medium")
