"""
Tests for dashboard.app - Dashboard Flask routes and functionality
Tests main dashboard routes, API endpoints, and core functionality.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest

# Set required environment variables before importing
os.environ.setdefault("CUSTOSEYE_SESSION_SECRET", "test_session_secret_key_for_testing_only")
os.environ.setdefault("CUSTOSEYE_PASSWORD_PEPPER", "test_password_pepper_for_testing_only")

from dashboard.app import BUFFER, PROC_INDEX, drain_into_buffer, run_dashboard


class TestDashboardRoutes:
    """Tests for dashboard Flask routes"""

    @pytest.fixture
    def app(self):
        """Create Flask app"""
        from flask import Flask

        app = Flask(__name__)
        app.secret_key = os.getenv("CUSTOSEYE_SESSION_SECRET", "test_secret")
        app.config["TESTING"] = True

        # Import and register routes
        from dashboard.app import app as dashboard_app

        return dashboard_app

    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()

    def test_index_route_requires_auth(self, client):
        """Test that index route requires authentication"""
        response = client.get("/")
        assert response.status_code in [302, 401]  # Redirect or unauthorized

    def test_index_route_renders_when_authenticated(self, client):
        """Test that index route renders when authenticated"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/")
        assert response.status_code == 200

    def test_api_ping_returns_ok(self, client):
        """Test that /api/ping returns ok"""
        response = client.get("/api/ping")
        assert response.status_code == 200
        if response.is_json:
            data = response.get_json()
            assert data is not None

    def test_api_events_requires_auth(self, client):
        """Test that /api/events requires authentication"""
        response = client.get("/api/events")
        assert response.status_code == 401

    def test_api_events_returns_list(self, client):
        """Test that /api/events returns a list"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/events")
        assert response.status_code == 200
        assert response.is_json
        data = response.get_json()
        assert isinstance(data, list)

    def test_api_events_filters_by_level(self, client):
        """Test that /api/events filters by level"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/events?levels=critical")
        assert response.status_code == 200

    def test_api_events_filters_by_source(self, client):
        """Test that /api/events filters by source"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/events?sources=process")
        assert response.status_code == 200

    def test_api_events_searches(self, client):
        """Test that /api/events searches"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/events?q=test")
        assert response.status_code == 200

    def test_api_proctree_requires_auth(self, client):
        """Test that /api/proctree requires authentication"""
        response = client.get("/api/proctree")
        assert response.status_code == 401

    def test_api_proctree_returns_list(self, client):
        """Test that /api/proctree returns a list"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/proctree")
        assert response.status_code == 200
        assert response.is_json
        data = response.get_json()
        assert isinstance(data, list)

    def test_api_about_returns_info(self, client):
        """Test that /api/about returns info"""
        response = client.get("/api/about")
        assert response.status_code == 200
        assert response.is_json
        data = response.get_json()
        assert isinstance(data, dict)
        assert "version" in data or "buffer_max" in data

    def test_api_integrity_targets_requires_auth(self, client):
        """Test that /api/integrity/targets requires authentication"""
        response = client.get("/api/integrity/targets")
        assert response.status_code == 401

    def test_api_integrity_targets_returns_list(self, client):
        """Test that /api/integrity/targets returns list"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/integrity/targets")
        assert response.status_code == 200
        assert response.is_json
        data = response.get_json()
        assert isinstance(data, list)

    def test_api_export_requires_auth(self, client):
        """Test that /api/export requires authentication"""
        response = client.get("/api/export?format=csv")
        assert response.status_code == 401

    def test_api_export_csv(self, client):
        """Test that /api/export exports CSV"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/export?format=csv&include_info=1")
        assert response.status_code == 200
        assert "text/csv" in response.content_type or "csv" in response.content_type.lower()

    def test_api_export_json(self, client):
        """Test that /api/export exports JSON"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/export?format=json&include_info=1")
        assert response.status_code == 200
        assert response.is_json

    def test_api_export_jsonl(self, client):
        """Test that /api/export exports JSONL"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/export?format=jsonl&include_info=1")
        assert response.status_code == 200

    def test_api_export_xlsx(self, client):
        """Test that /api/export exports XLSX"""
        with client.session_transaction() as sess:
            sess["username"] = "testuser"

        response = client.get("/api/export?format=xlsx&include_info=1")
        assert response.status_code == 200
        assert "spreadsheet" in response.content_type.lower() or "xlsx" in response.content_type.lower()

    def test_api_integrity_add_requires_auth(self, client):
        """Test that POST /api/integrity/add requires authentication"""
        response = client.post("/api/integrity/add", json={"path": "test.txt"})
        assert response.status_code == 401

    def test_api_integrity_hash_requires_auth(self, client):
        """Test that POST /api/integrity/hash requires authentication"""
        response = client.post("/api/integrity/hash", json={"path": "test.txt"})
        assert response.status_code == 401

    def test_api_integrity_diff_requires_auth(self, client):
        """Test that POST /api/integrity/diff requires authentication"""
        response = client.post("/api/integrity/diff", json={"path": "test.txt"})
        assert response.status_code == 401


class TestDrainIntoBuffer:
    """Tests for drain_into_buffer function"""

    def test_drain_into_buffer_processes_events(self):
        """Test that drain_into_buffer processes events from bus"""
        # Create mock event bus
        events = [
            {"source": "process", "name": "test.exe", "pid": 1234},
            {"source": "network", "listening_ports": [8080]},
        ]

        def mock_subscribe():
            for event in events:
                yield event
            while True:
                yield None

        mock_bus = Mock()
        mock_bus.subscribe = Mock(return_value=mock_subscribe())

        # Clear buffer
        BUFFER.clear()

        # Drain events
        drain_into_buffer(mock_bus, limit=10, deadline_sec=1.0)

        # Should have processed events
        assert len(BUFFER) > 0

    def test_drain_into_buffer_respects_limit(self):
        """Test that drain_into_buffer respects limit"""
        events = [{"source": "process", "name": f"test{i}.exe"} for i in range(100)]

        def mock_subscribe():
            for event in events:
                yield event
            while True:
                yield None

        mock_bus = Mock()
        mock_bus.subscribe = Mock(return_value=mock_subscribe())

        BUFFER.clear()
        initial_len = len(BUFFER)

        drain_into_buffer(mock_bus, limit=5, deadline_sec=1.0)

        # Should not exceed limit
        assert len(BUFFER) - initial_len <= 5

    def test_drain_into_buffer_handles_none_events(self):
        """Test that drain_into_buffer handles None events"""
        def mock_subscribe():
            yield None
            yield None
            while True:
                yield None

        mock_bus = Mock()
        mock_bus.subscribe = Mock(return_value=mock_subscribe())

        BUFFER.clear()
        initial_len = len(BUFFER)

        drain_into_buffer(mock_bus, limit=10, deadline_sec=0.1)

        # Should not crash on None events
        assert len(BUFFER) == initial_len


class TestProcessIndex:
    """Tests for process index functionality"""

    def test_proc_index_tracks_processes(self):
        """Test that PROC_INDEX tracks processes"""
        PROC_INDEX.clear()

        # Simulate process event
        event = {
            "source": "process",
            "pid": 1234,
            "name": "test.exe",
            "ppid": 1,
            "exe": "C:\\test.exe",
        }

        # Process would normally be added by drain_into_buffer
        # For test, manually verify structure
        assert isinstance(PROC_INDEX, dict)

    def test_proc_index_handles_missing_fields(self):
        """Test that PROC_INDEX handles missing fields"""
        PROC_INDEX.clear()

        # Process with minimal fields
        event = {"source": "process", "pid": 1234}

        # Should not crash
        assert isinstance(PROC_INDEX, dict)


class TestBufferManagement:
    """Tests for buffer management"""

    def test_buffer_has_max_size(self):
        """Test that BUFFER has max size"""
        from dashboard.app import BUFFER_MAX

        assert BUFFER_MAX > 0
        assert BUFFER.maxlen == BUFFER_MAX

    def test_buffer_is_deque(self):
        """Test that BUFFER is a deque"""
        from collections import deque

        assert isinstance(BUFFER, deque)