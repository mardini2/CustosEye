"""
goal: make sure rule matches on a simple listening process event.
"""

from __future__ import annotations

from agent.rules_engine import RulesEngine


def test_rule_match(tmp_path):
    rules = [
        {
            "name": "Listening process",
            "when": {"source": "process", "listening_port": True},
            "then": {"level": "warning", "reason": "Process is listening"},
        }
    ]
    rpath = tmp_path / "rules.json"
    rpath.write_text(__import__("json").dumps(rules), encoding="utf-8")

    engine = RulesEngine(path=str(rpath))
    decision = engine.evaluate({"source": "process", "listening_ports": [80]})
    assert decision["level"] == "warning"
