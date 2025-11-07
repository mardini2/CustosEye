"""
goal: main launcher for CustosEye: starts all monitoring agents, the web dashboard, and optionally opens the browser
or shows a system tray icon. uses an event bus to fan-out events from agents to all subscribers (like the dashboard).
the terminal shows a welcome banner and minimal output while agents run in background threads.
"""

from __future__ import annotations  # lets us use string annotations before classes are defined

import argparse  # for parsing command line arguments
import logging  # for suppressing library log messages
import os  # for system exit in tray quit handler
import queue  # for event bus message queues
import sys  # for checking if we are frozen (packaged) and getting executable path
import threading  # for running agents and dashboard in background threads
import time  # for delays and sleep
import webbrowser  # for opening the dashboard in the browser
from pathlib import Path  # for working with file paths
from typing import Any  # type hint for flexible dictionary values

from agent.integrity_check import IntegrityChecker  # agent that monitors file integrity
from agent.monitor import ProcessMonitor  # agent that monitors running processes
from agent.network_scan import NetworkSnapshot  # agent that scans network connections

# set root logging level high enough so library warnings do not spam the console
logging.basicConfig(level=logging.ERROR)  # only show errors, suppress warnings and info

# silence waitress web server log messages so the console stays clean
logging.getLogger("waitress.queue").setLevel(logging.CRITICAL)  # suppress waitress queue messages
logging.getLogger("waitress").setLevel(logging.CRITICAL)  # suppress all waitress messages
logging.getLogger("waitress.access").setLevel(logging.CRITICAL)  # suppress waitress access logs


# --- ASCII banner ---
def print_banner() -> None:
    # print a colorful ASCII art banner with the CustosEye logo
    # use ANSI color codes if available (Windows via colorama), otherwise plain text
    try:
        from colorama import init as _colorama_init  # try to import colorama for Windows ANSI support

        _colorama_init()  # enable ANSI color codes on Windows terminals
        cyan = "\x1b[36m"  # ANSI code for cyan color
        blue = "\x1b[34m"  # ANSI code for blue color
        mag = "\x1b[35m"  # ANSI code for magenta color
        dim = "\x1b[2m"  # ANSI code for dim/brightness
        bold = "\x1b[1m"  # ANSI code for bold text
        reset = "\x1b[0m"  # ANSI code to reset all formatting
        red = "\x1b[31m"  # ANSI code for red color
    except Exception:  # if colorama is not available or import fails
        cyan = blue = mag = red = dim = bold = reset = ""  # use empty strings so banner still works without colors

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
"""  # multi-line string containing the ASCII art banner with embedded color codes
    print(eye)  # print the banner to the console


# --- end banner ---

# optional dashboard import
try:
    from dashboard.app import run_dashboard  # try to import the dashboard function

    HAVE_DASHBOARD = True  # flag indicating dashboard is available
except Exception:  # if dashboard module cannot be imported
    HAVE_DASHBOARD = False  # flag indicating dashboard is not available

# optional tray support
try:
    import pystray  # type: ignore  # try to import pystray for system tray support
    from PIL import Image  # type: ignore  # try to import PIL for image handling

    HAVE_TRAY = True  # flag indicating system tray is available
except Exception:  # if pystray or PIL cannot be imported
    HAVE_TRAY = False  # flag indicating system tray is not available


def _resolve_base_dir() -> Path:
    # figure out the base directory of the application
    if getattr(sys, "frozen", False):  # if we are running as a packaged executable (like PyInstaller)
        return Path(sys.executable).parent  # return the directory where the executable is located
    return Path(__file__).resolve().parents[1]  # otherwise return the parent of the parent directory (project root)


# fan-out EventBus
class EventBus:
    """pub/sub fan-out: each subscriber gets every event."""

    def __init__(self) -> None:
        self._subs: list[queue.Queue] = []  # list of subscriber queues
        self._lock = threading.Lock()  # lock to protect the subscribers list from race conditions

    def publish(self, event: dict[str, Any]) -> None:
        # send an event to all subscribers (fan-out pattern)
        with self._lock:  # acquire lock to safely read the subscribers list
            subs = list(self._subs)  # create a copy of the list so we can iterate without holding the lock
        for q in subs:  # loop through each subscriber queue
            try:
                q.put_nowait(event)  # try to put the event in the queue without blocking
            except queue.Full:  # if the queue is full
                pass  # drop the event to avoid backpressure (better to lose events than block)

    def subscribe(self):
        # create a new subscription and return an iterator that yields events
        q: queue.Queue = queue.Queue(maxsize=1000)  # create a queue with max 1000 events
        with self._lock:  # acquire lock to safely add to subscribers list
            self._subs.append(q)  # add this queue to the list of subscribers

        def _iter():
            # generator function that yields events from the queue
            while True:  # loop forever
                try:
                    yield q.get(timeout=0.5)  # wait up to 0.5 seconds for an event, yield it if found
                except queue.Empty:  # if no event arrived within the timeout
                    yield None  # yield None to keep the iterator alive

        return _iter()  # return the generator iterator


def main() -> None:
    # main entry point that sets up and starts all components
    parser = argparse.ArgumentParser(description="CustosEye")  # create argument parser
    parser.add_argument(
        "--no-open", action="store_true", help="do not open the dashboard in a browser"  # flag to skip opening browser
    )
    parser.add_argument(
        "--tray", action="store_true", help="show a system tray icon (if available)"  # flag to enable system tray
    )
    args = parser.parse_args()  # parse command line arguments

    BASE_DIR = _resolve_base_dir()  # get the base directory of the application

    def data_path(rel: str) -> str:
        # helper function to resolve relative paths to absolute paths
        return str((BASE_DIR / rel).resolve())  # combine base dir with relative path and resolve to absolute

    # build the fan-out bus
    bus = EventBus()  # create the event bus that will distribute events to all subscribers

    # start agents
    integ = IntegrityChecker(
        targets_path=data_path("data/integrity_targets.json"),  # path to integrity targets file
        publish=bus.publish,  # callback to publish events to the bus
        interval_sec=2.0,  # check every 2 seconds for faster detection
    )
    mon = ProcessMonitor(publish=bus.publish)  # create process monitor that publishes to the bus
    net = NetworkSnapshot(publish=bus.publish)  # create network scanner that publishes to the bus

    for target in (mon.run, net.run, integ.run):  # loop through each agent's run method
        threading.Thread(target=target, daemon=True).start()  # start each agent in a separate daemon thread

    # dashboard
    if HAVE_DASHBOARD:  # if dashboard module is available
        threading.Thread(target=run_dashboard, kwargs={"event_bus": bus}, daemon=True).start()  # start dashboard in a daemon thread

        if not args.no_open:  # if user did not specify --no-open flag

            def _open_browser() -> None:
                # function to open the dashboard in the browser after a short delay
                # short delay so the server is listening before we try to open it
                time.sleep(0.8)  # wait 0.8 seconds for server to start
                try:
                    webbrowser.open("http://127.0.0.1:8765")  # open the dashboard URL in the default browser
                except Exception:  # if opening browser fails
                    pass  # silently fail, user can open manually

            threading.Thread(target=_open_browser, name="open-browser", daemon=True).start()  # start browser opener in a thread

    # tray (optional)
    if args.tray and HAVE_TRAY:  # if user requested tray and tray support is available
        ico_path = BASE_DIR / "assets" / "custoseye.ico"  # path to the tray icon file
        img = None  # initialize image variable
        try:
            if ico_path.exists():  # if the icon file exists
                img = Image.open(str(ico_path))  # open the image file
        except Exception:  # if opening image fails
            img = None  # leave it as None (tray will use default icon)

        def on_open(icon, item):  # type: ignore
            # callback when user clicks "Open Dashboard" in tray menu
            try:
                webbrowser.open("http://127.0.0.1:8765")  # open dashboard in browser
            except Exception:  # if opening browser fails
                pass  # silently fail

        def on_quit(icon, item):  # type: ignore
            # callback when user clicks "Quit" in tray menu
            icon.stop()  # stop the tray icon
            os._exit(0)  # exit the program immediately

        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", on_open),  # menu item to open dashboard
            pystray.MenuItem("Quit", on_quit),  # menu item to quit
        )
        icon = pystray.Icon("CustosEye", img, "CustosEye")  # create the tray icon
        icon.menu = menu  # attach the menu to the icon
        threading.Thread(target=icon.run, name="tray", daemon=True).start()  # start the tray icon in a thread

    # minimal terminal output (no live stream)
    print_banner()  # print the welcome banner
    print("Welcome to CustosEye!")  # print welcome message
    print("Dashboard running at http://127.0.0.1:8765/ 𒆙")  # print dashboard URL

    # keep main alive
    try:
        while True:  # loop forever to keep the main thread alive
            time.sleep(0.5)  # sleep for half a second (prevents busy-waiting)
    except KeyboardInterrupt:  # if user presses Ctrl+C
        print("\nShutting down CustosEye...")  # print shutdown message


if __name__ == "__main__":
    main()  # run main function if this script is executed directly