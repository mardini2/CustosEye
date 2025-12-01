"""
Tests for agent.rules_engine - RulesEngine functionality
Tests rule loading, matching, and evaluation logic.
"""

from __future__ import annotations

import json

import pytest

from agent.rules_engine import RulesEngine, _ensure_list


class TestEnsureList:
    """Tests for _ensure_list helper function"""

    def test_ensure_list_with_none(self):
        """Test _ensure_list with None"""
        result = _ensure_list(None)
        assert result == []

    def test_ensure_list_with_string(self):
        """Test _ensure_list with string"""
        result = _ensure_list("test")
        assert result == ["test"]

    def test_ensure_list_with_list(self):
        """Test _ensure_list with list"""
        result = _ensure_list(["a", "b", "c"])
        assert result == ["a", "b", "c"]

    def test_ensure_list_with_tuple(self):
        """Test _ensure_list with tuple"""
        result = _ensure_list(("a", "b"))
        assert result == ["a", "b"]


class TestRulesEngine:
    """Tests for RulesEngine class"""

    @pytest.fixture
    def tmp_rules_file(self, tmp_path):
        """Create temporary rules JSON file"""
        rules_file = tmp_path / "rules.json"
        rules_file.write_text(json.dumps([]), encoding="utf-8")
        return str(rules_file)

    @pytest.fixture
    def rules_engine(self, tmp_rules_file):
        """Create RulesEngine instance"""
        return RulesEngine(path=tmp_rules_file)

    def test_rules_engine_initializes(self, rules_engine, tmp_rules_file):
        """Test that RulesEngine initializes correctly"""
        assert rules_engine.path == tmp_rules_file
        assert isinstance(rules_engine.rules, list)

    def test_load_rules_empty_file(self, tmp_path):
        """Test loading rules from empty file"""
        rules_file = tmp_path / "empty.json"
        rules_file.write_text("", encoding="utf-8")

        # Empty file causes JSONDecodeError, which the code doesn't handle
        # So we expect it to raise an exception
        with pytest.raises((json.JSONDecodeError, ValueError)):
            RulesEngine(path=str(rules_file))

    def test_load_rules_nonexistent_file(self, tmp_path):
        """Test loading rules when file doesn't exist"""
        rules_file = tmp_path / "nonexistent.json"

        engine = RulesEngine(path=str(rules_file))
        assert engine.rules == []

    def test_load_rules_valid_json(self, tmp_path):
        """Test loading rules from valid JSON"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "name": "test_rule",
                "when": {"source": "process", "name_contains": "test"},
                "then": {"level": "warning", "reason": "Test process detected"},
            }
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")

        engine = RulesEngine(path=str(rules_file))
        assert len(engine.rules) == 1

    def test_load_rules_invalid_json(self, tmp_path):
        """Test loading rules from invalid JSON"""
        rules_file = tmp_path / "invalid.json"
        rules_file.write_text("{ invalid json }", encoding="utf-8")

        # Invalid JSON causes JSONDecodeError, which the code doesn't handle
        # So we expect it to raise an exception
        with pytest.raises(json.JSONDecodeError):
            RulesEngine(path=str(rules_file))

    def test_load_rules_not_list(self, tmp_path):
        """Test loading rules when JSON is not a list"""
        rules_file = tmp_path / "not_list.json"
        rules_file.write_text('{"not": "a list"}', encoding="utf-8")

        engine = RulesEngine(path=str(rules_file))
        assert engine.rules == []

    def test_match_source_filter(self, rules_engine):
        """Test that _match filters by source"""
        rule_when = {"source": "process"}
        event_process = {"source": "process", "name": "test.exe"}
        event_network = {"source": "network"}

        assert rules_engine._match(rule_when, event_process) is True
        assert rules_engine._match(rule_when, event_network) is False

    def test_match_source_optional(self, rules_engine):
        """Test that source filter is optional"""
        rule_when = {}
        event = {"source": "process", "name": "test.exe"}

        assert rules_engine._match(rule_when, event) is True

    def test_match_listening_port_presence(self, rules_engine):
        """Test that _match checks listening port presence"""
        rule_when = {"listening_port": True}
        event_with_ports = {"source": "process", "listening_ports": [8080]}
        event_without_ports = {"source": "process", "listening_ports": []}

        assert rules_engine._match(rule_when, event_with_ports) is True
        assert rules_engine._match(rule_when, event_without_ports) is False

    def test_match_listening_port_absence(self, rules_engine):
        """Test that _match checks listening port absence"""
        rule_when = {"listening_port": False}
        event_with_ports = {"source": "process", "listening_ports": [8080]}
        event_without_ports = {"source": "process", "listening_ports": []}

        assert rules_engine._match(rule_when, event_with_ports) is False
        assert rules_engine._match(rule_when, event_without_ports) is True

    def test_match_name_contains_single(self, rules_engine):
        """Test that _match checks name_contains with single string"""
        rule_when = {"name_contains": "test"}
        event_match = {"source": "process", "name": "test.exe"}
        event_no_match = {"source": "process", "name": "other.exe"}

        assert rules_engine._match(rule_when, event_match) is True
        assert rules_engine._match(rule_when, event_no_match) is False

    def test_match_name_contains_list(self, rules_engine):
        """Test that _match checks name_contains with list"""
        rule_when = {"name_contains": ["test", "evil"]}
        event_match1 = {"source": "process", "name": "test.exe"}
        event_match2 = {"source": "process", "name": "evil.exe"}
        event_no_match = {"source": "process", "name": "other.exe"}

        assert rules_engine._match(rule_when, event_match1) is True
        assert rules_engine._match(rule_when, event_match2) is True
        assert rules_engine._match(rule_when, event_no_match) is False

    def test_match_name_contains_case_insensitive(self, rules_engine):
        """Test that name_contains is case-insensitive"""
        rule_when = {"name_contains": "TEST"}
        event_lower = {"source": "process", "name": "test.exe"}
        event_upper = {"source": "process", "name": "TEST.EXE"}

        assert rules_engine._match(rule_when, event_lower) is True
        assert rules_engine._match(rule_when, event_upper) is True

    def test_match_exe_contains(self, rules_engine):
        """Test that _match checks exe_contains"""
        rule_when = {"exe_contains": "temp"}
        event_match = {"source": "process", "exe": "C:\\temp\\evil.exe"}
        event_no_match = {"source": "process", "exe": "C:\\windows\\system32\\test.exe"}

        assert rules_engine._match(rule_when, event_match) is True
        assert rules_engine._match(rule_when, event_no_match) is False

    def test_match_port_in(self, rules_engine):
        """Test that _match checks port_in"""
        rule_when = {"port_in": [8080, 443]}
        event_match = {"source": "process", "listening_ports": [8080, 80]}
        event_no_match = {"source": "process", "listening_ports": [80, 22]}

        assert rules_engine._match(rule_when, event_match) is True
        assert rules_engine._match(rule_when, event_no_match) is False

    def test_match_port_not_in(self, rules_engine):
        """Test that _match checks port_not_in"""
        rule_when = {"port_not_in": [8080, 443]}
        event_match = {"source": "process", "listening_ports": [80, 22]}
        event_no_match = {"source": "process", "listening_ports": [8080, 80]}

        assert rules_engine._match(rule_when, event_match) is True
        assert rules_engine._match(rule_when, event_no_match) is False

    def test_match_any_remote_presence(self, rules_engine):
        """Test that _match checks any_remote presence"""
        rule_when = {"any_remote": True}
        event_with_remote = {"source": "process", "remote_addrs": ["192.168.1.1:80"]}
        event_without_remote = {"source": "process", "remote_addrs": []}

        assert rules_engine._match(rule_when, event_with_remote) is True
        assert rules_engine._match(rule_when, event_without_remote) is False

    def test_match_any_remote_absence(self, rules_engine):
        """Test that _match checks any_remote absence"""
        rule_when = {"any_remote": False}
        event_with_remote = {"source": "process", "remote_addrs": ["192.168.1.1:80"]}
        event_without_remote = {"source": "process", "remote_addrs": []}

        assert rules_engine._match(rule_when, event_with_remote) is False
        assert rules_engine._match(rule_when, event_without_remote) is True

    def test_match_any_remote_with_remote_endpoints(self, rules_engine):
        """Test that _match checks remote_endpoints field"""
        rule_when = {"any_remote": True}
        event = {"source": "process", "remote_endpoints": ["192.168.1.1:80"]}

        assert rules_engine._match(rule_when, event) is True

    def test_match_combines_conditions(self, rules_engine):
        """Test that _match combines multiple conditions with AND"""
        rule_when = {
            "source": "process",
            "name_contains": "test",
            "listening_port": True,
        }
        event_match = {
            "source": "process",
            "name": "test.exe",
            "listening_ports": [8080],
        }
        event_no_match1 = {
            "source": "network",  # Wrong source
            "name": "test.exe",
            "listening_ports": [8080],
        }
        event_no_match2 = {
            "source": "process",
            "name": "other.exe",  # Wrong name
            "listening_ports": [8080],
        }

        assert rules_engine._match(rule_when, event_match) is True
        assert rules_engine._match(rule_when, event_no_match1) is False
        assert rules_engine._match(rule_when, event_no_match2) is False

    def test_evaluate_no_rules(self, rules_engine):
        """Test that evaluate returns default when no rules match"""
        event = {"source": "process", "name": "test.exe"}
        result = rules_engine.evaluate(event)

        assert result["level"] == "info"
        assert result["reason"] == "no rule matched"

    def test_evaluate_first_match_wins(self, tmp_path):
        """Test that evaluate uses first matching rule"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "name": "rule1",
                "when": {"name_contains": "test"},
                "then": {"level": "warning", "reason": "Rule 1"},
            },
            {
                "name": "rule2",
                "when": {"name_contains": "test"},
                "then": {"level": "critical", "reason": "Rule 2"},
            },
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")

        engine = RulesEngine(path=str(rules_file))
        event = {"source": "process", "name": "test.exe"}
        result = engine.evaluate(event)

        assert result["level"] == "warning"
        assert result["reason"] == "Rule 1"

    def test_evaluate_uses_rule_name_as_fallback(self, tmp_path):
        """Test that evaluate uses rule name as reason fallback"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "name": "My Custom Rule",
                "when": {"name_contains": "test"},
                "then": {"level": "warning"},  # No reason field
            }
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")

        engine = RulesEngine(path=str(rules_file))
        event = {"source": "process", "name": "test.exe"}
        result = engine.evaluate(event)

        assert result["reason"] == "My Custom Rule"

    def test_evaluate_uses_generic_reason_when_no_name(self, tmp_path):
        """Test that evaluate uses generic reason when rule has no name"""
        rules_file = tmp_path / "rules.json"
        rules = [
            {
                "when": {"name_contains": "test"},
                "then": {"level": "warning"},  # No name, no reason
            }
        ]
        rules_file.write_text(json.dumps(rules), encoding="utf-8")

        engine = RulesEngine(path=str(rules_file))
        event = {"source": "process", "name": "test.exe"}
        result = engine.evaluate(event)

        assert result["reason"] == "rule triggered"
