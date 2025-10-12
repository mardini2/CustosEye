"""
Goal: Wire up the CustosEye agent components and provide a minimal console runner
      (and optional Flask dashboard) with auto-refresh for rules and integrity targets.

What this file does:
- Starts the process monitor, network snapshotter, and integrity checker as background threads.
- Streams events to a tiny in-memory event bus.
- Prints integrity events directly (their severity comes from the checker).
- Applies the JSON rules engine to other events.
- Adds CSC trust scoring for process events and optionally escalates low-trust warnings to critical.
- Auto-reloads:
    - data/rules.json                -> refreshes rule set on change
    - data/integrity_targets.json    -> refreshes integrity targets on change
- Optional minimal dashboard at http://127.0.0.1:8765 if Flask is installed (no setup needed).

Run:
    Console only:
        python -m app.console --console
    Console + dashboard:
        python -m app.console

Noise control options (console-side, no code changes elsewhere):
    --suppress-repeats                # print each (pid, level, reason) only once
    --repeat-window SECONDS           # with --suppress-repeats, re-allow the same alert after SECONDS
"""

from __future__ import annotations

import argparse
import os
import queue
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent.integrity_check import IntegrityChecker
from agent.monitor import ProcessMonitor
from agent.network_scan import NetworkSnapshot
from agent.rules_engine import RulesEngine
from algorithm.csc_engine import CSCTrustEngine  # Phase 2: trust scoring

# Dashboard is optional; console works fine without it
try:
    from dashboard.app import run_dashboard

    HAVE_DASHBOARD = True
except Exception:
    HAVE_DASHBOARD = False


class EventBus:
    """
    Very small in-memory pub/sub queue for alerts and events.

    We keep it simple: a single Queue read by console and dashboard.
    """

    def __init__(self) -> None:
        self._q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1000)

    def publish(self, event: dict[str, Any]) -> None:
        # Non-blocking put with fallback drop-on-full to avoid agent stalls.
        try:
            self._q.put_nowait(event)
        except queue.Full:
            # In production, consider metrics; here we drop silently.
            pass

    def iter_events(self):
        """
        Generator that yields events as they arrive, or None if idle.
        """
        while True:
            try:
                yield self._q.get(timeout=0.5)
            except queue.Empty:
                yield None


def file_mtime(path: str) -> float | None:
    """
    Safe mtime getter. Returns None if file does not exist.
    """
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def watch_file(path: str, on_change: Callable[[], None], check_every: float = 2.0) -> None:
    """
    Background watcher that calls `on_change()` whenever `path` is modified.

    Notes:
    - Uses modification time checks; cheap and portable.
    - If the file is created after start, we still detect it.
    - Intended for small JSON configs (rules, integrity targets).
    """
    last_mtime = file_mtime(path)

    def _loop() -> None:
        nonlocal last_mtime
        while True:
            time.sleep(check_every)
            cur = file_mtime(path)
            if cur is None and last_mtime is None:
                continue
            if cur != last_mtime:
                last_mtime = cur
                try:
                    on_change()
                except Exception:
                    # Avoid crashing the watcher on bad edits; user can fix JSON and it will reload next change.
                    pass

    t = threading.Thread(target=_loop, name=f"watch:{os.path.basename(path)}", daemon=True)
    t.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="CustosEye runner")
    parser.add_argument("--console", action="store_true", help="run without Flask dashboard")

    # Noise control (console-side)
    parser.add_argument(
        "--suppress-repeats",
        action="store_true",
        help="print each (pid, level, reason) only once until it changes",
    )
    parser.add_argument(
        "--repeat-window",
        type=float,
        default=0.0,
        help="with --suppress-repeats, re-allow the same alert after N seconds (default: 0 = never)",
    )

    args = parser.parse_args()

    # Resolve a stable base directory whether running as script or frozen exe
    if getattr(sys, "frozen", False):
        # Running as PyInstaller onefile exe: use the exe's folder
        BASE_DIR = Path(sys.executable).parent
    else:
        # Running from source: repo root = this file's parent parent
        BASE_DIR = Path(__file__).resolve().parents[1]

    def data_path(rel: str) -> str:
        return str((BASE_DIR / rel).resolve())

    # Event bus wiring
    bus = EventBus()

    # Config paths (robust for source + exe)
    rules_path = data_path("data/rules.json")
    targets_path = data_path("data/integrity_targets.json")

    # Phase 2: CSC Trust scoring paths and engine
    csc_weights_path = data_path("data/csc_weights.json")
    csc_db_path = data_path("data/trust_db.json")
    csc = CSCTrustEngine(weights_path=csc_weights_path, db_path=csc_db_path)

    # Components
    rules = RulesEngine(path=rules_path)
    monitor = ProcessMonitor(publish=bus.publish)
    net = NetworkSnapshot(publish=bus.publish)
    # Faster integrity loop for interactive feedback (5s instead of 30s)
    integ = IntegrityChecker(targets_path=targets_path, publish=bus.publish, interval_sec=5.0)

    # Start background workers
    for target, name in (
        (monitor.run, "monitor"),
        (net.run, "network"),
        (integ.run, "integrity"),
    ):
        threading.Thread(target=target, name=name, daemon=True).start()

    # Auto-refresh integrity targets when the JSON file changes
    def _reload_integrity_targets() -> None:
        # Reuse the existing instance; just reload the targets list in place
        integ._load_targets()  # intentionally calling the loader to pick up changes

    watch_file(targets_path, _reload_integrity_targets, check_every=2.0)

    # Auto-refresh rules when the JSON file changes
    def _reload_rules() -> None:
        # Recreate the list so the engine sees fresh rules on next evaluate()
        rules.rules = rules._load_rules()

    watch_file(rules_path, _reload_rules, check_every=2.0)

    # Console consumer: integrity prints directly; everything else goes through rules
    def console_loop() -> None:
        # Optional de-dup cache: (pid, level, reason) -> last_print_ts
        seen: dict[tuple[Any, str, str], float] = {}

        for ev in bus.iter_events():
            if not ev:
                continue

            src = ev.get("source")

            # Integrity events already carry level/reason; show them directly
            if src == "integrity":
                level = (ev.get("level") or "info").upper()
                reason = ev.get("reason") or "integrity event"
                path = ev.get("path") or ""
                print(f"[{level}] {reason} | source=integrity | path={path}")
                continue

            # All other events use the rules engine
            decision = rules.evaluate(ev)
            if decision["level"] == "info":
                continue

            # Phase 2: compute trust for process events and optionally escalate
            trust_frag = ""
            if src == "process":
                t = csc.evaluate(ev)
                ev["trust"] = t["trust"]
                ev["trust_label"] = t["label"]
                ev["trust_reasons"] = t["reasons"]
                # Optional escalation: low-trust warnings -> critical
                if t["label"] == "low" and decision["level"] == "warning":
                    decision["level"] = "critical"
                    decision["reason"] = f"{decision['reason']} (low trust)"
                trust_frag = f" | trust={t['trust']}({t['label']})"

            # Optional: suppress repeats for the same (pid, level, reason)
            if args.suppress_repeats:
                key = (ev.get("pid"), decision["level"], decision["reason"])
                now = time.time()
                last = seen.get(key)
                # If repeat-window is 0 -> suppress forever until the tuple changes.
                # If > 0 -> allow reprint only after that many seconds.
                if last is not None and (
                    args.repeat_window <= 0.0 or (now - last) < args.repeat_window
                ):
                    continue
                seen[key] = now

            print(
                f"[{decision['level'].upper()}] {decision['reason']} "
                f"| source={src} | pid={ev.get('pid')} | name={ev.get('name')}{trust_frag}"
            )

    threading.Thread(target=console_loop, name="console", daemon=True).start()

    # Optional dashboard in a background thread
    if not args.console and HAVE_DASHBOARD:
        threading.Thread(target=run_dashboard, kwargs={"event_bus": bus}, daemon=True).start()

    # Keep main thread alive; Ctrl+C to quit
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        # If you want to change or remove this line, it's here.
        print("\nShutting down CustosEye...")


if __name__ == "__main__":
    main()
