from __future__ import annotations

import os
from typing import Any

import pytest
import requests


def _env_url() -> str:
    return os.getenv("CUSTOSEYE_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


@pytest.fixture(scope="session")
def base_url() -> str:
    return _env_url()


@pytest.fixture(scope="session")
def http():
    """Simple requests wrapper with a short timeout."""

    class _HTTP:
        def get(self, url: str, **kw):
            kw.setdefault("timeout", 5)
            return requests.get(url, **kw)

        def post(self, url: str, json: dict[str, Any] | None = None, **kw):
            kw.setdefault("timeout", 8)
            return requests.post(url, json=json, **kw)

    return _HTTP()


@pytest.fixture(scope="session")
def server_up(base_url: str, http):
    """Skip the test session if the API isn’t reachable."""
    try:
        r = http.get(f"{base_url}/api/ping")
        # Allow either JSON ok or a bare 200 if your ping is simple.
        if r.status_code != 200:
            pytest.skip(f"Server reachable but non-200 from /api/ping: {r.status_code}")
        try:
            data = r.json()
            if isinstance(data, dict) and "ok" in data and not data["ok"]:
                pytest.skip("Ping responded but ok=false")
        except Exception:
            # non-JSON is fine as long as it’s 200
            pass
    except Exception as exc:
        pytest.skip(f"Server not reachable at {base_url} ({exc})")


def assert_has_keys(obj: dict[str, Any], required: tuple[str, ...]) -> None:
    missing = [k for k in required if k not in obj]
    assert not missing, f"Missing keys: {missing} in {obj}"
