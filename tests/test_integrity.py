from __future__ import annotations

import pytest


def test_targets_list(server_up, base_url, http):
    r = http.get(f"{base_url}/api/integrity/targets")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    # Entries, if any, have expected shape
    for row in data:
        assert isinstance(row, dict)
        assert "path" in row
        assert "rule" in row
        assert row["rule"] in ("sha256", "mtime+size")


@pytest.mark.parametrize("limit", [1])
def test_hash_preview_non_destructive(server_up, base_url, http, limit):
    # If there are integrity targets, request a hash for the first one.
    r = http.get(f"{base_url}/api/integrity/targets")
    assert r.status_code == 200
    targets = r.json()

    if not targets:
        pytest.skip("No integrity targets configured to hash")

    for row in targets[:limit]:
        path = row.get("path")
        if not path:
            continue
        r2 = http.post(f"{base_url}/api/integrity/hash", json={"path": path})
        assert r2.status_code == 200
        data = r2.json()
        # Either sha256 for exact rule, or mtime/size payload for attr rule
        assert any(k in data for k in ("sha256", "mtime", "size"))
        # Don’t assert exact values to keep this portable
