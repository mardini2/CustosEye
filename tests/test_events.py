from __future__ import annotations

import pytest


def test_events_list(server_up, base_url, http):
    r = http.get(f"{base_url}/api/events?include_info=1")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)

    # If there are events, validate a couple of common fields
    if data:
        ev = data[0]
        assert isinstance(ev, dict)
        # Soft schema, your fields can include more than these
        for key in ("level", "reason", "source"):
            assert key in ev
        # Types
        if "level" in ev:
            assert isinstance(ev["level"], str)
        if "reason" in ev:
            assert isinstance(ev["reason"], str)
        if "source" in ev:
            assert isinstance(ev["source"], str)


@pytest.mark.parametrize(
    "fmt,ctype_part",
    [
        ("csv", "text/csv"),
        ("json", "application/json"),
    ],
)
def test_export_formats(server_up, base_url, http, fmt, ctype_part):
    # This should succeed even with zero events; the server can return an empty file
    r = http.get(
        f"{base_url}/api/export?format={fmt}&include_info=1&levels=info,warning,critical&q="
    )
    assert r.status_code == 200
    ct = r.headers.get("Content-Type", "")
    assert ctype_part in ct.lower()
    assert r.content is not None
