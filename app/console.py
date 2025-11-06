"""
CustosEye launcher: starts agents + dashboard and opens the UI.

- uses a fan-out EventBus so the dashboard always receives events.
- terminal just shows a welcome.
- auto-opens http://127.0.0.1:8765/ (use --no-open to suppress).
- optional system tray (if pystray/Pillow available) via --tray.
"""

from __future__ import annotations

import argparse
import logging
import os
import queue
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Any

from agent.integrity_check import IntegrityChecker
from agent.monitor import ProcessMonitor
from agent.network_scan import NetworkSnapshot

# Set root level high enough so library WARNINGs don't spam the console
logging.basicConfig(level=logging.ERROR)

# Silence Waitress chatter decisively
logging.getLogger("waitress.queue").setLevel(logging.CRITICAL)
logging.getLogger("waitress").setLevel(logging.CRITICAL)
logging.getLogger("waitress.access").setLevel(logging.CRITICAL)


# --- ASCII banner (CustosEye logo like-alike) ---
def print_banner() -> None:
    # use ANSI color if available (Windows via colorama), otherwise plain text
    try:
        from colorama import init as _colorama_init

        _colorama_init()  # enables ANSI on Windows terminals
        cyan = "\x1b[36m"
        blue = "\x1b[34m"
        mag = "\x1b[35m"
        dim = "\x1b[2m"
        bold = "\x1b[1m"
        reset = "\x1b[0m"
        red = "\x1b[31m"
    except Exception:
        cyan = blue = mag = red = dim = bold = reset = ""

    eye = rf"""
{dim}┌────────────────────────────────────────────────────────────┐{reset}
{dim}│{reset}{cyan}{bold}                  C  u  s  t  o  s  E  y  e{reset}{dim}                 │{reset}
{dim}├────────────────────────────────────────────────────────────┤{reset}
{mag}                         ⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀                         {reset}
{mag}                    ⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⠀⠀⠀⠀⠀⠀                    {reset}
{mag}                 ⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⠟⠛⠉⠉⠛⠻⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀               {reset}
{mag}              ⠀⠀⠀⢀⣾⣿⣿⣿⡿⠋⠀⠀⠀⢀⣀⠀⠀⠀⠙⢿⣿⣿⣿⣷⡀⠀⠀            {reset}
{mag}            ⠀⠀⢀⣾⣿⣿⣿⠟⠀⢀⣠⣴⣿⣿⣿⣿⣿⣷⣦⣄⠀⠻⣿⣿⣿⣷⡀⠀          {reset}
{mag}           ⠀⠀⣾⣿⣿⣿⠃⠀⣴⣿⣿⣿⣿⣿{blue}██████████{mag}⣿⣿⣿⣿⣦⠀⠘⣿⣿⣿⣷⠀         {reset}
{mag}          ⠀⢠⣿⣿⣿⡏⠀⣼⣿⣿⣿⣿⣿{blue}████{cyan}██████{blue}████{mag}⣿⣿⣿⣿⣿⣧⠀⢹⣿⣿⣿⡄        {reset}
{mag}          ⠀⣾⣿⣿⣿⠁⢠⣿⣿⣿⣿⣿⣿{blue}███{cyan}████████{blue}███{mag}⣿⣿⣿⣿⣿⣿⡄⠈⣿⣿⣿⣷        {reset}
{mag}          ⢰⣿⣿⣿⡏⠀⣾⣿⣿⣿⣿⣿⣿{blue}██{cyan}█████{red}│{cyan}████{blue}██{mag}⣿⣿⣿⣿⣿⣿⣷⠀⢹⣿⣿⣿⡆       {reset}
{mag}          ⣾⣿⣿⣿⠁⠀⣿⣿⣿⣿⣿⣿⣿{blue}██{cyan}█████{red}│{cyan}████{blue}██{mag}⣿⣿⣿⣿⣿⣿⣿⠀⠈⣿⣿⣿⣷       {reset}
{mag}          ⣿⣿⣿⡟⠀⠀⣿⣿⣿⣿⣿⣿⣿{blue}██{cyan}█████{red}│{cyan}████{blue}██{mag}⣿⣿⣿⣿⣿⣿⣿⠀⠀⢻⣿⣿⣿       {reset}
{mag}          ⣿⣿⣿⡇⠀⠀⢿⣿⣿⣿⣿⣿⣿{blue}██{cyan}█████{red}│{cyan}████{blue}██{mag}⣿⣿⣿⣿⣿⣿⡿⠀⠀⢸⣿⣿⣿       {reset}
{mag}          ⢿⣿⣿⣧⠀⠀⠘⣿⣿⣿⣿⣿⣿{blue}███{cyan}████{red}│{cyan}███{blue}███{mag}⣿⣿⣿⣿⣿⣿⠃⠀⠀⣸⣿⣿⡿       {reset}
{mag}          ⠀⢻⣿⣿⣷⠀⠀⠘⢿⣿⣿⣿⣿{blue}████{cyan}██████{blue}████{mag}⣿⣿⣿⣿⡿⠃⠀⠀⣾⣿⣿⡟        {reset}
{mag}           ⠀⠙⢿⣿⣿⣧⠀⠀⠀⠙⠻⣿⣿⣿{blue}██████████{mag}⣿⠟⠋⠀⠀⠀ ⣸⣿⣿⡿⠋         {reset}
{mag}             ⠀⠀⠙⢿⣿⣿⣦⣀⠀⠀⠀⠉⠛⠿⣿⣿⠿⠛⠉⠀⠀⠀  ⣀⣴⣿⣿⠟⠀⠀           {reset}
{mag}                 ⠀⠀⠈⠛⠿⣿⣿⣶⣤⣄⣀⠀⠀⠀⠀⣀⣠⣤⣶⣿⣿⠿⠛⠁⠀⠀               {reset}
{mag}                        ⠀⠀⠀⠈⠉⠛⠛⠛⠛⠉⠁⠀⠀⠀⠀                         {reset}
{cyan}              Your Third Eye • Vigilant by Design                        {reset}
{dim}├────────────────────────────────────────────────────────────┤{reset}
{dim}│{reset}  Tip: press Ctrl+C to quit.                                {dim}│{reset}
{dim}└────────────────────────────────────────────────────────────┘{reset}
"""
    print(eye)


# --- end banner ---

# optional dashboard import
try:
    from dashboard.app import run_dashboard

    HAVE_DASHBOARD = True
except Exception:
    HAVE_DASHBOARD = False

# optional tray support
try:
    import pystray  # type: ignore
    from PIL import Image  # type: ignore

    HAVE_TRAY = True
except Exception:
    HAVE_TRAY = False


def _resolve_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parents[1]


# fan-out EventBus
class EventBus:
    """pub/sub fan-out: each subscriber gets every event."""

    def __init__(self) -> None:
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # drop on full to avoid backpressure

    def subscribe(self):
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subs.append(q)

        def _iter():
            while True:
                try:
                    yield q.get(timeout=0.5)
                except queue.Empty:
                    yield None

        return _iter()


def main() -> None:
    parser = argparse.ArgumentParser(description="CustosEye")
    parser.add_argument(
        "--no-open", action="store_true", help="do not open the dashboard in a browser"
    )
    parser.add_argument(
        "--tray", action="store_true", help="show a system tray icon (if available)"
    )
    args = parser.parse_args()

    BASE_DIR = _resolve_base_dir()

    def data_path(rel: str) -> str:
        return str((BASE_DIR / rel).resolve())

    # build the fan-out bus
    bus = EventBus()

    # start agents
    integ = IntegrityChecker(
        targets_path=data_path("data/integrity_targets.json"),
        publish=bus.publish,
        interval_sec=2.0,  # Check every 2 seconds for faster detection
    )
    mon = ProcessMonitor(publish=bus.publish)
    net = NetworkSnapshot(publish=bus.publish)

    for target in (mon.run, net.run, integ.run):
        threading.Thread(target=target, daemon=True).start()

    # dashboard
    if HAVE_DASHBOARD:
        threading.Thread(target=run_dashboard, kwargs={"event_bus": bus}, daemon=True).start()

        if not args.no_open:

            def _open_browser() -> None:
                # short delay so the server is listening
                time.sleep(0.8)
                try:
                    webbrowser.open("http://127.0.0.1:8765")
                except Exception:
                    pass

            threading.Thread(target=_open_browser, name="open-browser", daemon=True).start()

    # tray (optional)
    if args.tray and HAVE_TRAY:
        ico_path = BASE_DIR / "assets" / "custoseye.ico"
        img = None
        try:
            if ico_path.exists():
                img = Image.open(str(ico_path))
        except Exception:
            img = None

        def on_open(icon, item):  # type: ignore
            try:
                webbrowser.open("http://127.0.0.1:8765")
            except Exception:
                pass

        def on_quit(icon, item):  # type: ignore
            icon.stop()
            os._exit(0)

        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", on_open),
            pystray.MenuItem("Quit", on_quit),
        )
        icon = pystray.Icon("CustosEye", img, "CustosEye")
        icon.menu = menu
        threading.Thread(target=icon.run, name="tray", daemon=True).start()

    # minimal terminal output (no live stream)
    print_banner()
    print("Welcome to CustosEye!")
    print("Dashboard running at http://127.0.0.1:8765/ 𒆙")

    # keep main alive
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nShutting down CustosEye...")


if __name__ == "__main__":
    main()
