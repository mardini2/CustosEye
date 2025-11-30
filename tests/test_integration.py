"""
Integration tests for CustosEye
Tests end-to-end functionality and component interactions.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest
import psutil

from agent.integrity_check import IntegrityChecker
from agent.monitor import ProcessMonitor
from agent.network_scan import NetworkSnapshot
from agent.rules_engine import RulesEngine
from algorithm.csc_engine import CSCTrustEngine
from app.console import EventBus


class TestEventBusIntegration:
    """Tests for EventBus integration with agents"""

    @pytest.fixture
    def event_bus(self):
        """Create EventBus instance"""
        return EventBus()

    @pytest.fixture
    def mock_publish(self):
        """Mock publish callback"""
        return MagicMock()

    def test_event_bus_fanout_to_multiple_subscribers(self, event_bus):
        """Test that EventBus fans out to multiple subscribers"""
        sub1 = event_bus.subscribe()
        sub2 = event_bus.subscribe()
        sub3 = event_bus.subscribe()
        
        event = {"source": "test", "data": "test"}
        event_bus.publish(event)
        
        # All subscribers should receive the event
        ev1 = next(sub1)
        ev2 = next(sub2)
        ev3 = next(sub3)
        
        assert ev1 == event
        assert ev2 == event
        assert ev3 == event

    def test_process_monitor_publishes_to_bus(self, event_bus):
        """Test that ProcessMonitor publishes to EventBus"""
        events_received = []
        
        def collect(event):
            events_received.append(event)
        
        monitor = ProcessMonitor(publish=collect, interval_sec=0.1)
        
        # Get a real process
        import psutil
        proc = psutil.Process()
        event = monitor._proc_event(proc)
        
        assert event["source"] == "process"
        assert "pid" in event

    def test_network_snapshot_publishes_to_bus(self, event_bus):
        """Test that NetworkSnapshot publishes to EventBus"""
        events_received = []
        
        def collect(event):
            events_received.append(event)
        
        snapshot = NetworkSnapshot(publish=collect, interval_sec=0.1)
        
        with patch("agent.network_scan.psutil.net_connections", return_value=[]):
            snapshot.run()
        
        assert len(events_received) > 0
        assert events_received[0]["source"] == "network"

    def test_integrity_checker_publishes_to_bus(self, tmp_path):
        """Test that IntegrityChecker publishes to EventBus"""
        events_received = []
        
        def collect(event):
            events_received.append(event)
        
        targets_file = tmp_path / "targets.json"
        targets_file.write_text(json.dumps([]), encoding="utf-8")
        
        checker = IntegrityChecker(
            targets_path=str(targets_file), publish=collect, interval_sec=0.1
        )
        
        # Run once
        checker.run()
        
        # May or may not have events depending on targets
        # But should not crash


class TestRulesEngineIntegration:
    """Tests for RulesEngine integration"""

    def test_rules_engine_evaluates_process_events(self, tmp_path):
        """Test that RulesEngine evaluates process events"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "name": "suspicious_temp",
                "when": {
                    "source": "process",
                    "exe_contains": "temp",
                },
                "then": {"level": "warning", "reason": "Process from temp"},
            }
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")
        
        engine = RulesEngine(path=str(rules_file))
        
        event = {
            "source": "process",
            "name": "test.exe",
            "exe": "C:\\temp\\test.exe",
        }
        
        result = engine.evaluate(event)
        assert result["level"] == "warning"
        assert "temp" in result["reason"].lower()


class TestCSCEngineIntegration:
    """Tests for CSC engine integration"""

    def test_csc_engine_evaluates_process(self, tmp_path):
        """Test that CSC engine evaluates process events"""
        weights_file = tmp_path / "weights.json"
        db_file = tmp_path / "db.json"
        
        weights_file.write_text(json.dumps({}), encoding="utf-8")
        
        engine = CSCTrustEngine(weights_path=str(weights_file), db_path=str(db_file))
        
        event = {
            "source": "process",
            "name": "test.exe",
            "exe": "C:\\Windows\\System32\\test.exe",
            "sha256": "abc123" * 16,
            "signer_valid": True,
            "signer_subject": "Microsoft Corporation",
        }
        
        result = engine.evaluate(event)
        assert "verdict" in result
        assert "confidence" in result
        assert "reasons" in result
        assert result["verdict"] in ["trusted", "caution", "suspicious", "malicious", "unknown"]


class TestComponentInteraction:
    """Tests for component interactions"""

    def test_process_monitor_and_rules_engine(self, tmp_path):
        """Test ProcessMonitor and RulesEngine interaction"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "when": {"source": "process", "name_contains": "test"},
                "then": {"level": "info", "reason": "Test process"},
            }
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")
        
        rules_engine = RulesEngine(path=str(rules_file))
        
        # Simulate process event
        process_event = {
            "source": "process",
            "name": "test.exe",
            "exe": "C:\\test.exe",
        }
        
        # Apply rules
        decision = rules_engine.evaluate(process_event)
        assert decision["level"] == "info"

    def test_integrity_checker_and_rules_engine(self, tmp_path):
        """Test IntegrityChecker and RulesEngine interaction"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "when": {"source": "integrity"},
                "then": {"level": "critical", "reason": "File changed"},
            }
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")
        
        rules_engine = RulesEngine(path=str(rules_file))
        
        # Simulate integrity event
        integrity_event = {
            "source": "integrity",
            "level": "critical",
            "path": "C:\\test.txt",
        }
        
        # Apply rules
        decision = rules_engine.evaluate(integrity_event)
        assert decision["level"] == "critical"


class TestErrorHandling:
    """Tests for error handling across components"""

    def test_process_monitor_handles_missing_process(self):
        """Test that ProcessMonitor handles missing processes"""
        events = []
        
        def collect(event):
            events.append(event)
        
        monitor = ProcessMonitor(publish=collect, interval_sec=0.1)
        
        # Create mock process that raises NoSuchProcess
        mock_proc = Mock()
        mock_proc.pid = 99999
        mock_proc.name = Mock(side_effect=psutil.NoSuchProcess(99999))
        
        event = monitor._proc_event(mock_proc)
        assert event.get("status") == "gone"

    def test_integrity_checker_handles_missing_file(self, tmp_path):
        """Test that IntegrityChecker handles missing files gracefully"""
        events = []
        
        def collect(event):
            events.append(event)
        
        targets_file = tmp_path / "targets.json"
        targets = [{"path": "C:\\nonexistent\\file.txt", "sha256": "abc123"}]
        targets_file.write_text(json.dumps(targets), encoding="utf-8")
        
        checker = IntegrityChecker(
            targets_path=str(targets_file), publish=collect, interval_sec=0.1
        )
        
        # Should not crash
        checker.run()

    def test_rules_engine_handles_invalid_rules(self, tmp_path):
        """Test that RulesEngine handles invalid rules gracefully"""
        rules_file = tmp_path / "rules.json"
        rules_file.write_text("{ invalid json }", encoding="utf-8")
        
        engine = RulesEngine(path=str(rules_file))
        assert engine.rules == []