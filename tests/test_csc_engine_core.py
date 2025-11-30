from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from algorithm.csc_engine import CSCTrustEngine

# ------------ Fixtures ------------


@pytest.fixture()
def tmp_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Fresh engine per test with a temp weights.json and db.json.

    Time is frozen so prevalence math is deterministic.
    """
    weights_path = tmp_path / "weights.json"
    db_path = tmp_path / "db.json"

    # Minimal overrides to make boundaries crisp
    weights = {
        "cut_malicious": -2.0,
        "cut_suspicious": -0.5,
        "cut_caution": 0.5,
        "cut_trusted": 1.6,
        "prefer_signed_bonus": 1.0,
        "unsigned_system_penalty": 1.0,
        "listen_penalty": 0.8,
        "risky_listen_extra": 1.1,
        "many_listens_extra": 0.5,
        "remote_bump": 0.25,
        "remote_many_extra": 0.6,
        "remote_many_count": 5,
        "susp_launcher_penalty": 0.9,
        "elev_from_user_penalty": 1.1,
        "service_userdir_penalty": 1.1,
        "file_age_days_fresh": 3.0,
        "tiny_binary_mb": 0.15,
        "prevalence_halflife_days": 14.0,
        "hash_seen_thresh": 2.0,
        "exe_seen_thresh": 4.0,
        "prevalence_hash_bonus": 1.0,
        "prevalence_exe_bonus": 0.6,
    }
    weights_path.write_text(json.dumps(weights), encoding="utf-8")

    # Freeze time
    import algorithm.csc_engine as mod

    monkeypatch.setattr(mod.time, "time", lambda: 1_000_000_000.0)

    eng = CSCTrustEngine(str(weights_path), str(db_path))

    # Return a simple, typed “ctx” that Pylance is happy with
    ctx = SimpleNamespace(
        engine=eng,
        weights_path=weights_path,
        db_path=db_path,
        tmp=tmp_path,
        mod=mod,
        monkeypatch=monkeypatch,
    )
    return ctx


# ------------ Helpers ------------


def _base_event(**kw: dict[str, Any]) -> dict[str, Any]:
    e: dict[str, Any] = {
        "source": "process",
        "name": "app.exe",
        "exe": r"C:\Program Files\App\app.exe",
        "sha256": "aa11" * 16,
        "parent_name": "explorer.exe",
        "parent_exe": r"C:\Windows\explorer.exe",
        "is_service": False,
        "elevation": False,
        "signer_valid": False,
        "signer_subject": "",
        "listening_ports": [],
        "remote_addrs": [],
        "file_ctime": 1_000_000_000.0 - 90 * 86400,  # ~90 days old
        "file_size_mb": 5.0,
    }
    e.update(kw)
    return e


# ------------ Tests ------------


def test_non_process_events_return_unknown(tmp_engine: SimpleNamespace) -> None:
    res = tmp_engine.engine.evaluate({"source": "integrity"})
    assert res["verdict"] == "unknown"
    assert res["cls"] == "unknown"
    assert 0.0 <= res["confidence"] <= 1.0
    assert "not a process event" in res["reasons"]


def test_system_and_signed_moves_to_trusted(tmp_engine: SimpleNamespace) -> None:
    ev = _base_event(
        exe=r"C:\Windows\System32\calc.exe",
        signer_valid=True,
        signer_subject="Microsoft Corporation",
    )
    res = tmp_engine.engine.evaluate(ev)
    assert res["verdict"] == "trusted"
    assert res["confidence"] >= 0.55


def test_user_temp_unsigned_with_listen_on_risky_ports_is_suspicious_or_worse(
    tmp_engine: SimpleNamespace,
) -> None:
    ev = _base_event(
        exe=r"C:\Users\Bob\AppData\Local\Temp\x\evil.exe",
        file_ctime=tmp_engine.mod.time.time(),  # very new
        signer_valid=False,
        listening_ports=[4444, 3389],  # risky defaults
        file_size_mb=0.05,
    )
    res = tmp_engine.engine.evaluate(ev)
    assert res["verdict"] in {"suspicious", "malicious"}
    assert res["signals"]["in_user_or_downloads"] is True
    assert res["signals"]["listening_ports"]


def test_parent_lolbin_penalizes(tmp_engine: SimpleNamespace) -> None:
    ev = _base_event(parent_exe=r"C:\Windows\System32\powershell.exe")
    res = tmp_engine.engine.evaluate(ev)
    assert res["verdict"] in {"caution", "suspicious"}


def test_elevated_from_user_dir_penalty(tmp_engine: SimpleNamespace) -> None:
    ev = _base_event(
        exe=r"C:\Users\Bob\Downloads\setup.exe",
        elevation=True,
    )
    res = tmp_engine.engine.evaluate(ev)
    assert res["signals"]["in_user_or_downloads"] is True
    assert res["verdict"] in {"suspicious", "malicious"}


def test_prevalence_hash_and_exe_bonus_with_decay(tmp_engine: SimpleNamespace) -> None:
    base_sha = "bb22" * 16
    base_exe = r"C:\Program Files\CoolApp\cool.exe"
    ev = _base_event(exe=base_exe, sha256=base_sha)

    # First sighting: unknown hash penalty
    res1 = tmp_engine.engine.evaluate(ev)
    assert "hash is rare/unknown on this machine" in res1["reasons"]
    first_eff = res1["signals"]["hash_eff_seen"]

    # Two more sightings to cross the hash threshold
    tmp_engine.engine.evaluate(ev)
    res3 = tmp_engine.engine.evaluate(ev)
    eff_after = res3["signals"]["hash_eff_seen"]
    assert eff_after >= first_eff

    # Advance time by 30 days and observe decay
    now_plus_30 = 1_000_000_000.0 + 30 * 86400
    tmp_engine.monkeypatch.setattr(tmp_engine.mod.time, "time", lambda: now_plus_30)
    res_decay = tmp_engine.engine.evaluate(ev)
    assert res_decay["signals"]["hash_eff_seen"] <= eff_after


def test_class_rules_order_and_fallbacks(tmp_engine: SimpleNamespace) -> None:
    ev_sys = _base_event(
        exe=r"C:\Windows\System32\thing.exe",
        signer_valid=True,
        signer_subject="Google LLC",
    )
    res_sys = tmp_engine.engine.evaluate(ev_sys)
    assert res_sys["cls"] in {"system", "popular_app"}

    ev_dev = _base_event(
        parent_exe=r"C:\Windows\System32\cmd.exe",
        signer_valid=False,
    )
    res_dev = tmp_engine.engine.evaluate(ev_dev)
    assert res_dev["cls"] in {"dev_tool", "unknown", "utility"}  # rule or fallback

    ev_util = _base_event()
    res_util = tmp_engine.engine.evaluate(ev_util)
    assert res_util["cls"] in {"utility", "unknown"}


def test_confidence_is_clamped_and_verdict_valid(tmp_engine: SimpleNamespace) -> None:
    verdict, conf = tmp_engine.engine._to_verdict_and_confidence(10.0, tmp_engine.engine.weights)
    assert verdict == "trusted"
    assert 0.0 <= conf <= 1.0

    verdict2, conf2 = tmp_engine.engine._to_verdict_and_confidence(-10.0, tmp_engine.engine.weights)
    assert verdict2 in {"malicious", "suspicious"}
    assert 0.0 <= conf2 <= 1.0