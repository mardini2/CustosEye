# SPDX-License-Identifier: GPL-3.0-or-later
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
import signal  # for handling Ctrl+C even while webview is running
import sys  # for checking if we are frozen (packaged) and getting executable path
import threading  # for running agents and dashboard in background threads
import time  # for delays and sleep
import webbrowser  # for opening the dashboard in the browser
from pathlib import Path  # for working with file paths
from typing import Any  # type hint for flexible dictionary values

# load environment variables from .env file before importing dashboard
try:
    from dotenv import load_dotenv

    load_dotenv()  # load .env file if it exists
except ImportError:
    pass  # python-dotenv is optional, but recommended

# Auto-generate .env file if it doesn't exist and secrets are missing (for end users)
# This makes sure first-time users do not need to manually run setup_env.py
if not os.getenv("CUSTOSEYE_SESSION_SECRET") or not os.getenv("CUSTOSEYE_PASSWORD_PEPPER"):
    import secrets

    # Resolve base directory (works for both dev and packaged exe)
    if getattr(sys, "frozen", False):
        base_dir = Path(sys.executable).parent
    else:
        base_dir = Path(__file__).resolve().parents[1]

    env_file = base_dir / ".env"
    if not env_file.exists():
        # Generate secrets like setup_env.py does
        session_secret = secrets.token_hex(32)  # 64-char hex string
        password_pepper = secrets.token_hex(32)  # 64-char hex string
        env_content = f"""# =========================================
# CustosEye Environment Variables
# =========================================
# auto-generated on first run - keep this file secure and never commit it!

# required: secret key for Flask sessions (auto-generated)
CUSTOSEYE_SESSION_SECRET={session_secret}

# required: additional secret for password hashing (auto-generated)
CUSTOSEYE_PASSWORD_PEPPER={password_pepper}

# optional: issuer name for TOTP QR codes (defaults to "CustosEye" if not set)
CUSTOSEYE_TOTP_ISSUER=CustosEye
"""
        try:
            env_file.write_text(env_content, encoding="utf-8")
            # Reload .env file now that we created it
            try:
                from dotenv import load_dotenv

                load_dotenv()
            except ImportError:
                pass
        except Exception:
            # If we ca not write .env, the import will fail with a clear error from auth.py
            pass

from agent.integrity_check import IntegrityChecker  # agent that monitors file integrity
from agent.monitor import ProcessMonitor  # agent that monitors running processes
from agent.network_scan import NetworkSnapshot  # agent that scans network connections

# Suppress Chrome/CEF error messages early (before any imports that might trigger them)
if sys.platform == "win32":
    import os

    # Set environment variable to suppress Chromium logging
    os.environ.setdefault("WEBVIEW_LOG", "0")

    # Also filter stderr to catch any remaining errors (like Chrome_WidgetWin_0 noise)
    try:
        original_stderr = sys.stderr

        class StderrFilter:
            def __init__(self, original):
                self.original = original

            def write(self, text):
                # Filter out known noisy Chrome/CEF errors that do not affect functionality
                if (
                    "Chrome_WidgetWin" in text
                    or "ERROR:ui\\gfx\\win\\window_impl.cc" in text
                    or "Failed to unregister class Chrome_WidgetWin" in text
                ):
                    return
                self.original.write(text)

            def flush(self):
                self.original.flush()

            def __getattr__(self, name):
                return getattr(self.original, name)

        sys.stderr = StderrFilter(original_stderr)
    except Exception:
        # If anything goes wrong, just leave stderr alone
        pass

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
        from colorama import (
            init as _colorama_init,
        )  # try to import colorama for Windows ANSI support

        _colorama_init()  # enable ANSI color codes on Windows terminals
        cyan = "\x1b[36m"  # ANSI code for cyan color
        blue = "\x1b[34m"  # ANSI code for blue color
        mag = "\x1b[35m"  # ANSI code for magenta color
        dim = "\x1b[2m"  # ANSI code for dim/brightness
        bold = "\x1b[1m"  # ANSI code for bold text
        reset = "\x1b[0m"  # ANSI code to reset all formatting
        red = "\x1b[31m"  # ANSI code for red color
    except Exception:  # if colorama is not available or import fails
        cyan = blue = mag = red = dim = bold = reset = (
            ""  # use empty strings so banner still works without colors
        )

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
{dim}│{reset}  Tip: if running in a terminal, press {cyan}Ctrl+C{reset} to quit.      {dim}│{reset}
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

# optional webview support for windowed dashboard
try:
    import webview  # type: ignore  # try to import webview for windowed application support

    HAVE_WEBVIEW = True  # flag indicating webview is available
except Exception:  # if webview cannot be imported
    HAVE_WEBVIEW = False  # flag indicating webview is not available


def _resolve_base_dir() -> Path:
    # figure out the base directory of the application
    if getattr(
        sys, "frozen", False
    ):  # if we are running as a packaged executable (like PyInstaller)
        return Path(sys.executable).parent  # return the directory where the executable is located
    return (
        Path(__file__).resolve().parents[1]
    )  # otherwise return the parent of the parent directory (project root)


# fan-out EventBus
class EventBus:
    """pub/sub fan-out: each subscriber gets every event."""

    def __init__(self) -> None:
        self._subs: list[queue.Queue] = []  # list of subscriber queues
        self._lock = threading.Lock()  # lock to protect the subscribers list from race conditions

    def publish(self, event: dict[str, Any]) -> None:
        # send an event to all subscribers (fan-out pattern)
        with self._lock:  # acquire lock to safely read the subscribers list
            subs = list(
                self._subs
            )  # create a copy of the list so we can iterate without holding the lock
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
                    yield q.get(
                        timeout=0.5
                    )  # wait up to 0.5 seconds for an event, yield it if found
                except queue.Empty:  # if no event arrived within the timeout
                    yield None  # yield None to keep the iterator alive

        return _iter()  # return the generator iterator


# global variable to track if windowed dashboard is already open
_window_open = False
_window_lock = threading.Lock()
# Queue to signal main thread to start webview (webview must run on main thread)
_webview_start_queue: queue.Queue = queue.Queue()
# Global shutdown flag for Ctrl+C handling
_shutdown_requested = False
_shutdown_lock = threading.Lock()


def _suppress_stderr_os_level():
    """Suppress stderr and stdout at the OS level using Windows API. This catches errors that bypass Python's stderr."""
    if sys.platform == "win32":
        try:
            import ctypes

            STD_ERROR_HANDLE = -12
            STD_OUTPUT_HANDLE = -11  # Also redirect stdout in case Chrome writes there
            GENERIC_WRITE = 0x40000000
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING = 3
            kernel32 = ctypes.windll.kernel32

            # Open NUL device
            null_handle = kernel32.CreateFileW(
                "NUL", GENERIC_WRITE, FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None
            )

            if null_handle != -1:
                # Redirect both stderr and stdout to catch Chrome errors
                kernel32.SetStdHandle(STD_ERROR_HANDLE, null_handle)
                kernel32.SetStdHandle(STD_OUTPUT_HANDLE, null_handle)
        except Exception:
            pass
    # Also suppress Python stderr and stdout
    try:
        devnull = open(os.devnull, "w")
        sys.stderr = devnull
        sys.stdout = devnull
        if hasattr(sys.stderr, "original"):
            sys.stderr.original = devnull
    except Exception:
        pass


def _set_window_icon_windows(icon_path: str) -> bool:
    """Set the window icon on Windows using the Windows API. Returns True if successful."""
    if sys.platform != "win32":
        return False

    try:
        import ctypes
        from ctypes import wintypes

        IMAGE_ICON = 1
        LR_LOADFROMFILE = 0x00000010
        WM_SETICON = 0x0080
        ICON_BIG = 0
        ICON_SMALL = 1

        # Ensure icon_path is absolute and exists
        icon_path_abs = str(Path(icon_path).resolve())
        if not Path(icon_path_abs).exists():
            return False

        # Load icon from file (must be .ico format for LoadImageW)
        hicon = ctypes.windll.user32.LoadImageW(
            None,
            icon_path_abs,
            IMAGE_ICON,
            0,
            0,
            LR_LOADFROMFILE,
        )

        if not hicon:
            return False

        # Try to find the main window in a few ways
        hwnd = None

        # 1) Exact title match first
        hwnd = ctypes.windll.user32.FindWindowW(None, "CustosEye")

        # 2) If not found, enumerate windows and look for our title and/or Chrome widget class
        if not hwnd:
            found_hwnd = None

            def enum_callback(hwnd_param, lParam):
                nonlocal found_hwnd
                # Check if window is visible
                if not ctypes.windll.user32.IsWindowVisible(hwnd_param):
                    return True

                title_buf = ctypes.create_unicode_buffer(512)
                class_buf = ctypes.create_unicode_buffer(256)

                ctypes.windll.user32.GetWindowTextW(hwnd_param, title_buf, 512)
                ctypes.windll.user32.GetClassNameW(hwnd_param, class_buf, 256)

                title = title_buf.value or ""
                cls = class_buf.value or ""

                # Prefer a window that both has our title and is a Chrome host window
                if "CustosEye" in title and "Chrome_WidgetWin" in cls:
                    found_hwnd = hwnd_param
                    return False

                # Fallback: any window whose title contains CustosEye
                if "CustosEye" in title and found_hwnd is None:
                    found_hwnd = hwnd_param

                return True

            EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
            ctypes.windll.user32.EnumWindows(EnumWindowsProc(enum_callback), 0)
            hwnd = found_hwnd

        # 3) As a last resort, try grabbing the first Chrome host window
        if not hwnd:
            hwnd = ctypes.windll.user32.FindWindowW("Chrome_WidgetWin_0", None)

        if not hwnd:
            return False

        # Set both large and small icons multiple times to ensure it sticks
        # Sometimes Windows needs multiple attempts to apply the icon
        for _ in range(3):
            ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon)
            ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, hicon)
            # Also try SetClassLongPtr for more persistent icon setting
            try:
                GCL_HICON = -14
                GCL_HICONSM = -34
                ctypes.windll.user32.SetClassLongPtrW(hwnd, GCL_HICON, hicon)
                ctypes.windll.user32.SetClassLongPtrW(hwnd, GCL_HICONSM, hicon)
            except Exception:
                pass
        return True
    except Exception:
        return False


def launch_windowed_dashboard() -> None:
    """Launch the dashboard in a native windowed application."""
    global _window_open

    if not HAVE_WEBVIEW:
        print("Windowed dashboard requires pywebview. Install it with: pip install pywebview")
        return

    with _window_lock:
        if _window_open:
            # Window already open, don't open another
            return
        _window_open = True

    def _prepare_window() -> None:
        # Wait for server to be ready
        time.sleep(1.0)  # wait 1 second for server to start

        try:
            # Get the dashboard URL from config, with fallback to default
            url = "http://127.0.0.1:8765"  # default URL
            try:
                from dashboard.config import load_config

                cfg = load_config()
                url = f"http://{cfg.host}:{cfg.port}"
            except Exception:
                # If config loading fails, use default URL
                pass

            # Get the base directory to find the icon
            BASE_DIR = _resolve_base_dir()
            icon_path = None
            # Prefer a dedicated CustosEye icon if present, otherwise fall back to favicon.ico
            # Only use .ico for Windows, as LoadImageW requires .ico format
            for icon_file in ["custoseye.ico", "favicon.ico"]:
                test_path = BASE_DIR / "assets" / icon_file
                if test_path.exists():
                    icon_path = str(test_path.resolve())  # Use absolute path
                    break

            # Create the window (this can be done from any thread)
            # Note: icon parameter is not supported in create_window, will be set via webview.start()
            # IMPORTANT: create_window must be called before start(), and the window object must exist
            window = webview.create_window(
                "CustosEye",  # window title
                url,  # URL to load
                width=1400,  # window width
                height=900,  # window height
                min_size=(800, 600),  # minimum window size
                resizable=True,  # allow resizing
            )

            # Verify window was created successfully
            if window is None:
                raise RuntimeError("Failed to create window")

            # Wait to ensure window is fully registered before signaling start
            # This is critical - webview.start() will fail if window isn't registered
            time.sleep(0.8)

            # Signal main thread to start webview with icon
            _webview_start_queue.put(("start", icon_path))
        except Exception as e:
            # If creating window fails, fall back to browser
            print(f"Failed to create windowed dashboard: {e}")
            print("Falling back to browser...")
            try:
                webbrowser.open("http://127.0.0.1:8765")
            except Exception:
                pass
            global _window_open
            with _window_lock:
                _window_open = False

    # Prepare window in background thread
    threading.Thread(target=_prepare_window, name="prepare-window", daemon=True).start()


def main() -> None:
    # main entry point that sets up and starts all components
    global _shutdown_requested  # declare global variable for shutdown flag
    parser = argparse.ArgumentParser(description="CustosEye")  # create argument parser
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="do not open the dashboard automatically",  # flag to skip opening dashboard
    )
    parser.add_argument(
        "--tray",
        action="store_true",
        help="show a system tray icon (if available)",  # flag to enable system tray
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="open dashboard in browser instead of windowed application",  # flag to use browser instead of window
    )
    args = parser.parse_args()  # parse command line arguments

    BASE_DIR = _resolve_base_dir()  # get the base directory of the application

    # Get color codes for messages (used in shutdown and welcome)
    try:
        from colorama import init as _colorama_init

        _colorama_init()
        purple = "\x1b[35m"
        cyan = "\x1b[36m"
        reset = "\x1b[0m"
    except Exception:
        purple = cyan = reset = ""

    # Install a Ctrl+C handler so the app quits cleanly even while webview is running
    def _handle_sigint(sig, frame):
        global _shutdown_requested
        # Set shutdown flag immediately
        with _shutdown_lock:
            _shutdown_requested = True

        # Suppress stderr at OS level (catches Chrome errors that bypass Python stderr)
        _suppress_stderr_os_level()

        # Suppress output BEFORE printing shutdown message (Chrome error happens during destroy)
        # Print shutdown message first, then suppress everything
        try:
            print(f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n")
            # Flush stdout to ensure message is printed before we suppress it
            sys.stdout.flush()
        except Exception:
            pass

        # Now suppress all output before destroying webview (this is when the error occurs)
        _suppress_stderr_os_level()

        # Don't call webview.destroy_window() - just exit and let OS clean up
        # This avoids triggering the Chrome error message
        # The window will be destroyed automatically when the process exits
        # Force immediate exit - os._exit() bypasses all cleanup and should work even when blocked
        # This is the most reliable way to exit on Ctrl+C, especially when webview is blocking
        os._exit(0)

    try:
        signal.signal(signal.SIGINT, _handle_sigint)
    except Exception:
        # On some platforms or environments, signal handling may not be available
        pass

    # On Windows, also register a console control handler for more reliable Ctrl+C handling
    # This works even when the main thread is blocked by webview
    if sys.platform == "win32":
        try:
            import ctypes

            # Define the console control handler type
            PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

            def _console_ctrl_handler(ctrl_type):
                """Windows console control handler for Ctrl+C and Ctrl+Break."""
                if ctrl_type in (0, 1):  # CTRL_C_EVENT (0) or CTRL_BREAK_EVENT (1)
                    global _shutdown_requested
                    with _shutdown_lock:
                        _shutdown_requested = True

                    # Print shutdown message first
                    try:
                        print(
                            f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n"
                        )
                        sys.stdout.flush()
                    except Exception:
                        pass

                    # Now suppress all output before exit (Chrome error happens during cleanup)
                    _suppress_stderr_os_level()

                    # Don't call webview.destroy_window() - just exit and let OS clean up
                    # This avoids triggering the Chrome error message
                    os._exit(0)
                return False  # Don't call next handler

            # Register the console control handler
            # This handler will be called by Windows when Ctrl+C or Ctrl+Break is pressed
            # even when the main thread is blocked by webview.start()
            handler = PHANDLER_ROUTINE(_console_ctrl_handler)
            result = ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)
            if not result:
                # Handler registration failed, but continue anyway
                pass
        except Exception:
            # If Windows-specific handling fails, fall back to signal handler only
            # This is expected on non-console environments or if ctypes fails
            pass

    def data_path(rel: str) -> str:
        # helper function to resolve relative paths to absolute paths
        return str(
            (BASE_DIR / rel).resolve()
        )  # combine base dir with relative path and resolve to absolute

    # Start a background thread to monitor for shutdown requests
    # This helps ensure Ctrl+C works even when webview is blocking
    def _shutdown_monitor():
        while True:
            time.sleep(0.2)  # Check every 200ms
            with _shutdown_lock:
                if _shutdown_requested:
                    # Give signal handler a moment, then force exit
                    time.sleep(0.1)
                    os._exit(0)

    threading.Thread(target=_shutdown_monitor, name="shutdown-monitor", daemon=True).start()

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
        threading.Thread(
            target=target, daemon=True
        ).start()  # start each agent in a separate daemon thread

    # dashboard
    if HAVE_DASHBOARD:  # if dashboard module is available
        threading.Thread(
            target=run_dashboard, kwargs={"event_bus": bus}, daemon=True
        ).start()  # start dashboard in a daemon thread

        if not args.no_open:  # if user did not specify --no-open flag
            if args.browser:  # if user requested browser
                # Open in browser
                def _open_browser() -> None:
                    # function to open the dashboard in the browser after a short delay
                    # short delay so the server is listening before we try to open it
                    time.sleep(0.8)  # wait 0.8 seconds for server to start
                    try:
                        webbrowser.open(
                            "http://127.0.0.1:8765"
                        )  # open the dashboard URL in the default browser
                    except Exception:  # if opening browser fails
                        pass  # silently fail, user can open manually

                threading.Thread(
                    target=_open_browser, name="open-browser", daemon=True
                ).start()  # start browser opener in a thread
            else:  # default: open windowed dashboard (if available)
                if HAVE_WEBVIEW:
                    launch_windowed_dashboard()  # launch windowed dashboard
                else:
                    # Fall back to browser if webview is not available
                    def _open_browser() -> None:
                        time.sleep(0.8)
                        try:
                            webbrowser.open("http://127.0.0.1:8765")
                        except Exception:
                            pass

                    threading.Thread(target=_open_browser, name="open-browser", daemon=True).start()

    # tray (optional)
    if args.tray and HAVE_TRAY:  # if user requested tray and tray support is available
        ico_path = BASE_DIR / "assets" / "custoseye.ico"  # path to the tray icon file
        img = None  # initialize image variable
        try:
            if ico_path.exists():  # if the icon file exists
                img = Image.open(str(ico_path))  # open the image file
        except Exception:  # if opening image fails
            img = None  # leave it as None (tray will use default icon)

        def on_open_browser(icon, item):  # type: ignore
            # callback when user clicks "Open Dashboard (Browser)" in tray menu
            try:
                webbrowser.open("http://127.0.0.1:8765")  # open dashboard in browser
            except Exception:  # if opening browser fails
                pass  # silently fail

        def on_open_window(icon, item):  # type: ignore
            # callback when user clicks "Open Dashboard (Window)" in tray menu
            launch_windowed_dashboard()  # launch windowed dashboard

        def on_quit(icon, item):  # type: ignore
            # callback when user clicks "Quit" in tray menu
            icon.stop()  # stop the tray icon
            os._exit(0)  # exit the program immediately

        # Build menu items
        menu_items = [
            pystray.MenuItem(
                "Open Dashboard (Browser)", on_open_browser
            ),  # menu item to open dashboard in browser
        ]
        if HAVE_WEBVIEW:
            menu_items.append(
                pystray.MenuItem(
                    "Open Dashboard (Window)", on_open_window
                )  # menu item to open windowed dashboard
            )
        menu_items.append(pystray.MenuItem("Quit", on_quit))  # menu item to quit

        menu = pystray.Menu(*menu_items)
        icon = pystray.Icon("CustosEye", img, "CustosEye")  # create the tray icon
        icon.menu = menu  # attach the menu to the icon
        threading.Thread(
            target=icon.run, name="tray", daemon=True
        ).start()  # start the tray icon in a thread

    # minimal terminal output (no live stream)
    print_banner()  # print the welcome banner
    print(
        f"{purple}⬩{reset}{cyan}➢ {reset} Welcome to {purple}CustosEye{reset}!\n"
    )  # print welcome message with colored CustosEye

    # keep main alive and handle webview startup (webview must run on main thread)
    global _window_open
    try:
        while True:  # loop forever to keep the main thread alive
            # Check for shutdown request
            with _shutdown_lock:
                if _shutdown_requested:
                    print(
                        f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n"
                    )
                    os._exit(0)

            # Check if webview needs to be started (non-blocking check)
            try:
                cmd, icon_path = _webview_start_queue.get_nowait()
                if cmd == "start":
                    # Start webview on main thread (this blocks until window is closed)
                    try:
                        # On Windows, start icon-setting thread BEFORE webview.start() blocks
                        if sys.platform == "win32" and icon_path:

                            def _set_icon_after_delay() -> None:
                                # Wait for window to appear, then set icon
                                # Try multiple times with increasing delays to ensure window is ready
                                max_attempts = 60  # Try for up to 6 seconds
                                for attempt in range(max_attempts):
                                    time.sleep(0.1)
                                    if _set_window_icon_windows(icon_path):
                                        # Set again after a moment to ensure it sticks
                                        time.sleep(0.2)
                                        _set_window_icon_windows(icon_path)
                                        # Set one more time after window is fully loaded
                                        time.sleep(0.5)
                                        _set_window_icon_windows(icon_path)
                                        break
                                    # After initial attempts, try with longer delays
                                    if attempt > 20:
                                        time.sleep(0.2)

                            threading.Thread(
                                target=_set_icon_after_delay,
                                name="set-window-icon",
                                daemon=True,
                            ).start()

                        # Check for shutdown before starting webview
                        with _shutdown_lock:
                            if _shutdown_requested:
                                print(
                                    f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n"
                                )
                                os._exit(0)

                        # Start webview (this blocks until window is closed)
                        # Note: webview.start() must be called after create_window() has been called
                        try:
                            if icon_path:
                                try:
                                    # Try GTK/QT icon parameter first
                                    webview.start(debug=False, icon=icon_path)  # type: ignore[call-arg]
                                except (TypeError, ValueError):
                                    # Icon parameter not supported, start without it
                                    webview.start(debug=False)
                            else:
                                webview.start(debug=False)
                        except RuntimeError as e:
                            if "create a window first" in str(e).lower():
                                # Window not ready yet, wait a bit more and try again
                                time.sleep(0.5)
                                try:
                                    webview.start(debug=False)
                                except KeyboardInterrupt:
                                    # Ctrl+C pressed while webview is running
                                    try:
                                        print(
                                            f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n"
                                        )
                                        sys.stdout.flush()
                                    except Exception:
                                        pass
                                    # Suppress all output before exit (Chrome error happens during cleanup)
                                    _suppress_stderr_os_level()
                                    os._exit(0)
                            else:
                                raise
                        except KeyboardInterrupt:
                            # Ctrl+C pressed while webview is running
                            try:
                                print(
                                    f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n"
                                )
                                sys.stdout.flush()
                            except Exception:
                                pass
                            # Suppress all output before exit (Chrome error happens during cleanup)
                            _suppress_stderr_os_level()
                            os._exit(0)

                        # Window was closed - shut down the application
                        print(
                            f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n"
                        )
                        os._exit(0)
                    except Exception as e:
                        print(f"Failed to start windowed dashboard: {e}")
                        print("Falling back to browser...")
                        try:
                            webbrowser.open("http://127.0.0.1:8765")
                        except Exception:
                            pass
                        with _window_lock:
                            _window_open = False
            except queue.Empty:
                # No webview start request, continue
                pass
            time.sleep(0.1)  # sleep for 0.1 seconds (allows more responsive shutdown checking)
    except KeyboardInterrupt:  # if user presses Ctrl+C
        # Make Ctrl+C behave exactly like the banner promises: clean shutdown from terminal
        with _shutdown_lock:
            _shutdown_requested = True
        try:
            print(f"\n{purple}⬩{reset}{cyan}➢ {reset} Shutting down {purple}CustosEye{reset}...\n")
            sys.stdout.flush()
        except Exception:
            pass
        # Suppress all output before exit (Chrome error happens during cleanup)
        _suppress_stderr_os_level()
        # Don't call webview.destroy_window() - just exit and let OS clean up
        os._exit(0)


if __name__ == "__main__":
    main()  # run main function if this script is executed directly
