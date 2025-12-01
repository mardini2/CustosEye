from __future__ import annotations

from conftest import assert_has_keys


def test_about_shape(server_up, base_url, http):
    r = http.get(f"{base_url}/api/about")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, dict)
    # Expected fields, allow extra keys
    assert_has_keys(data, ("version", "build", "buffer_max"))
    v = data.get("version")
    b = data.get("build")
    assert v is None or isinstance(v, str)
    assert b is None or isinstance(b, str)
    assert isinstance(data["buffer_max"], int)
