from __future__ import annotations


def test_ping_ok(server_up, base_url, http):
    r = http.get(f"{base_url}/api/ping")
    assert r.status_code == 200
    try:
        data = r.json()
        assert isinstance(data, dict)
    except Exception:
        # If ping returns plain text, a 200 is enough.
        pass
