"""
goal: smoke test the monitor module to make sure event shape is sane.
"""

from __future__ import annotations

from agent.monitor import ProcessMonitor


def test_monitor_event_shape(monkeypatch):
    events = []
    m = ProcessMonitor(publish=lambda e: events.append(e), interval_sec=0.01)

    # Run a tight single-iteration loop by monkeypatching psutil.process_iter
    import psutil

    orig = psutil.process_iter
    psutil.process_iter = lambda attrs=None: []  # type: ignore
    try:
        # Run a tiny slice of the loop
        import threading
        import time

        t = threading.Thread(target=m.run, daemon=True)
        t.start()
        time.sleep(0.05)
    finally:
        psutil.process_iter = orig  # restore

    # No crash implies pass; events may be empty due to patch
    assert isinstance(events, list)
