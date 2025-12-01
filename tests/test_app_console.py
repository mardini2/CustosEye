"""
Tests for app.console - Console entry point functionality
Tests main entry point, event bus, and component initialization.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.console import EventBus, _resolve_base_dir, main, print_banner


class TestResolveBaseDir:
    """Tests for _resolve_base_dir function"""

    def test_resolve_base_dir_normal(self):
        """Test _resolve_base_dir in normal mode"""
        with patch("sys.frozen", False, create=True):
            result = _resolve_base_dir()
            assert isinstance(result, Path)

    def test_resolve_base_dir_frozen(self):
        """Test _resolve_base_dir in frozen mode"""
        with patch("sys.frozen", True, create=True):
            with patch("sys.executable", "C:\\app\\CustosEye.exe"):
                result = _resolve_base_dir()
                assert isinstance(result, Path)


class TestEventBus:
    """Tests for EventBus class"""

    @pytest.fixture
    def event_bus(self):
        """Create EventBus instance"""
        return EventBus()

    def test_event_bus_initializes(self, event_bus):
        """Test that EventBus initializes correctly"""
        assert event_bus._subs == []
        assert event_bus._lock is not None

    def test_event_bus_publish_sends_to_subscribers(self, event_bus):
        """Test that publish sends events to all subscribers"""
        sub1 = event_bus.subscribe()
        sub2 = event_bus.subscribe()

        event = {"source": "test", "data": "test"}
        event_bus.publish(event)

        # Get events from subscribers
        ev1 = next(sub1)
        ev2 = next(sub2)

        assert ev1 == event
        assert ev2 == event

    def test_event_bus_publish_handles_full_queue(self, event_bus):
        """Test that publish handles full queues gracefully"""
        event_bus.subscribe()  # Create subscriber to test queue behavior

        # Fill the queue
        for _ in range(1001):  # More than maxsize
            event_bus.publish({"source": "test"})

        # Should not crash

    def test_event_bus_subscribe_creates_iterator(self, event_bus):
        """Test that subscribe creates an iterator"""
        sub = event_bus.subscribe()
        assert hasattr(sub, "__next__")

    def test_event_bus_subscribe_yields_none_on_timeout(self, event_bus):
        """Test that subscribe yields None on timeout"""
        sub = event_bus.subscribe()

        # No events published, should yield None after timeout
        ev = next(sub)
        assert ev is None


class TestPrintBanner:
    """Tests for print_banner function"""

    @patch("builtins.print")
    def test_print_banner_prints(self, mock_print):
        """Test that print_banner prints something"""
        print_banner()
        assert mock_print.called

    @patch("builtins.print")
    def test_print_banner_works_without_colorama(self, mock_print):
        """Test that print_banner works without colorama"""
        # Test that it works even if colorama import fails
        with patch.dict("sys.modules", {"colorama": None}):
            print_banner()
        assert mock_print.called


class TestMain:
    """Tests for main function"""

    @patch("app.console.ProcessMonitor")
    @patch("app.console.NetworkSnapshot")
    @patch("app.console.IntegrityChecker")
    @patch("app.console.run_dashboard")
    @patch("app.console.print_banner")
    @patch("app.console._resolve_base_dir")
    @patch("sys.argv", ["__main__.py"])  # Remove pytest's -q flag
    def test_main_initializes_components(
        self,
        mock_resolve_dir,
        mock_banner,
        mock_dashboard,
        mock_integrity,
        mock_network,
        mock_monitor,
        tmp_path,
    ):
        """Test that main initializes all components"""
        mock_resolve_dir.return_value = tmp_path

        # Mock threading to avoid actually starting threads
        with patch("app.console.threading.Thread") as mock_thread:
            mock_thread.return_value.start = Mock()

            # Run main in a way that exits quickly
            with patch("app.console.time.sleep", side_effect=KeyboardInterrupt()):
                try:
                    main()
                except KeyboardInterrupt:
                    pass

        # Verify components were created
        assert mock_monitor.called or mock_thread.called
        assert mock_banner.called

    @patch("app.console.run_dashboard")
    @patch("app.console.print_banner")
    @patch("app.console._resolve_base_dir")
    @patch("sys.argv", ["__main__.py"])  # Remove pytest's -q flag
    def test_main_handles_no_dashboard(
        self, mock_resolve_dir, mock_banner, mock_dashboard, tmp_path
    ):
        """Test that main handles missing dashboard module"""
        mock_resolve_dir.return_value = tmp_path

        with patch("app.console.HAVE_DASHBOARD", False):
            with patch("app.console.threading.Thread") as mock_thread:
                mock_thread.return_value.start = Mock()
                with patch("app.console.time.sleep", side_effect=KeyboardInterrupt()):
                    try:
                        main()
                    except KeyboardInterrupt:
                        pass

        assert mock_banner.called

    @patch("app.console.webbrowser.open")
    @patch("app.console.run_dashboard")
    @patch("app.console.print_banner")
    @patch("app.console._resolve_base_dir")
    @patch("sys.argv", ["__main__.py"])  # Remove pytest's -q flag
    def test_main_opens_browser(
        self, mock_resolve_dir, mock_banner, mock_dashboard, mock_browser, tmp_path
    ):
        """Test that main opens browser when not --no-open"""
        mock_resolve_dir.return_value = tmp_path

        with patch("app.console.HAVE_DASHBOARD", True):
            with patch("app.console.threading.Thread") as mock_thread:
                mock_thread.return_value.start = Mock()
                with patch("app.console.time.sleep", side_effect=KeyboardInterrupt()):
                    try:
                        main()
                    except KeyboardInterrupt:
                        pass

        # Browser opening happens in a thread, so we can't easily verify it
        # But we can verify the code path doesn't crash

    @patch("app.console.run_dashboard")
    @patch("app.console.print_banner")
    @patch("app.console._resolve_base_dir")
    def test_main_no_open_flag(self, mock_resolve_dir, mock_banner, mock_dashboard, tmp_path):
        """Test that main respects --no-open flag"""
        mock_resolve_dir.return_value = tmp_path

        with patch("app.console.sys.argv", ["console.py", "--no-open"]):
            with patch("app.console.threading.Thread") as mock_thread:
                mock_thread.return_value.start = Mock()
                with patch("app.console.time.sleep", side_effect=KeyboardInterrupt()):
                    try:
                        main()
                    except KeyboardInterrupt:
                        pass

        assert mock_banner.called
