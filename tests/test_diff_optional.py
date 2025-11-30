from __future__ import annotations

import pytest


def test_diff_modal_when_changed(server_up, base_url, http):
    """If a target is reported as CHANGED, /api/integrity/diff should return a well-formed JSON.

    This test is opportunistic: it only runs when a target reports CHANGED.
    """
    r = http.get(f"{base_url}/api/integrity/targets")
    assert r.status_code == 200
    targets = r.json()

    changed = []
    for t in targets:
        last = (t.get("last_result") or "").upper()
        if last.startswith("CHANGED"):
            changed.append(t)

    if not changed:
        pytest.skip("No CHANGED targets at the moment")

    path = changed[0]["path"]
    r2 = http.post(f"{base_url}/api/integrity/diff", json={"path": path, "max_regions": 10})
    assert r2.status_code == 200
    data = r2.json()
    assert isinstance(data, dict)
    # Expected top-level flags from your modal renderer
    assert "ok" in data
    assert "summary" in data
    assert "regions" in data