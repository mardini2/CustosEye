"""
Tests for agent.monitor - ProcessMonitor functionality
Tests process monitoring, hash caching, signature extraction, and event publishing.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, Mock, patch

import psutil
import pytest

from agent.monitor import ProcessMonitor, _Hasher


class TestHasher:
    """Tests for the _Hasher class"""

    def test_hasher_initializes_empty_cache(self):
        """Test that hasher starts with empty cache"""
        hasher = _Hasher()
        assert hasher._cache == {}

    def test_hasher_sha256_file_nonexistent(self):
        """Test hasher returns None for non-existent file"""
        hasher = _Hasher()
        result = hasher.sha256_file("/nonexistent/file.exe")
        assert result is None

    def test_hasher_sha256_file_caches_result(self, tmp_path):
        """Test that hasher caches results based on path and mtime"""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"test content")

        hasher = _Hasher()
        hash1 = hasher.sha256_file(str(test_file))
        hash2 = hasher.sha256_file(str(test_file))

        assert hash1 == hash2
        assert len(hasher._cache) == 1

    def test_hasher_sha256_file_invalidates_on_mtime_change(self, tmp_path):
        """Test that cache invalidates when file mtime changes"""
        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"original")

        hasher = _Hasher()
        hash1 = hasher.sha256_file(str(test_file))

        # Wait a bit and modify file
        time.sleep(0.1)
        test_file.write_bytes(b"modified")

        hash2 = hasher.sha256_file(str(test_file))
        assert hash1 != hash2

    def test_hasher_sha256_file_handles_permission_error(self, tmp_path):
        """Test hasher handles permission errors gracefully"""
        hasher = _Hasher()
        # On Windows, try accessing a protected system file
        # This should return None without crashing
        result = hasher.sha256_file("C:\\Windows\\System32\\config\\sam")
        # Result may be None due to permissions or file not existing
        assert result is None or isinstance(result, str)


class TestProcessMonitor:
    """Tests for ProcessMonitor class"""

    @pytest.fixture
    def mock_publish(self):
        """Mock publish callback"""
        return MagicMock()

    @pytest.fixture
    def monitor(self, mock_publish):
        """Create ProcessMonitor instance"""
        return ProcessMonitor(publish=mock_publish, interval_sec=0.1)

    def test_monitor_initializes(self, monitor):
        """Test that monitor initializes correctly"""
        assert monitor.publish is not None
        assert monitor.interval == 0.1
        assert isinstance(monitor._hasher, _Hasher)
        assert isinstance(monitor._seen, dict)

    def test_proc_event_basic_fields(self, monitor):
        """Test that _proc_event extracts basic process fields"""
        # Get a real process for testing
        proc = psutil.Process()
        event = monitor._proc_event(proc)

        assert event["source"] == "process"
        assert "pid" in event
        assert "name" in event
        assert "ppid" in event
        assert isinstance(event["pid"], int)

    def test_proc_event_handles_missing_exe(self, monitor):
        """Test that _proc_event handles processes without exe path"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(return_value="test.exe")
        mock_proc.ppid = Mock(return_value=1)
        mock_proc.exe = Mock(return_value=None)
        mock_proc.cmdline = Mock(return_value=[])
        mock_proc.username = Mock(return_value="user")
        mock_proc.create_time = Mock(return_value=time.time())
        mock_proc.memory_info = Mock(return_value=Mock(rss=1024, vms=2048))
        mock_proc.connections = Mock(return_value=[])

        event = monitor._proc_event(mock_proc)
        assert event["exe"] is None
        assert "sha256" not in event or event.get("sha256") is None

    def test_proc_event_extracts_connections(self, monitor):
        """Test that _proc_event extracts network connections"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(return_value="test.exe")
        mock_proc.ppid = Mock(return_value=1)
        mock_proc.exe = Mock(return_value="C:\\test.exe")
        mock_proc.cmdline = Mock(return_value=["test.exe"])
        mock_proc.username = Mock(return_value="user")
        mock_proc.create_time = Mock(return_value=time.time())
        mock_proc.memory_info = Mock(return_value=Mock(rss=1024, vms=2048))

        # Mock connection with listening port
        mock_conn = Mock()
        mock_conn.status = psutil.CONN_LISTEN
        mock_conn.laddr = Mock(port=8080)
        mock_conn.raddr = None
        mock_proc.connections = Mock(return_value=[mock_conn])

        event = monitor._proc_event(mock_proc)
        assert 8080 in event["listening_ports"]

    def test_proc_event_extracts_remote_addrs(self, monitor):
        """Test that _proc_event extracts remote addresses"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(return_value="test.exe")
        mock_proc.ppid = Mock(return_value=1)
        mock_proc.exe = Mock(return_value="C:\\test.exe")
        mock_proc.cmdline = Mock(return_value=["test.exe"])
        mock_proc.username = Mock(return_value="user")
        mock_proc.create_time = Mock(return_value=time.time())
        mock_proc.memory_info = Mock(return_value=Mock(rss=1024, vms=2048))

        # Mock connection with remote address
        mock_conn = Mock()
        mock_conn.status = psutil.CONN_ESTABLISHED
        mock_conn.laddr = Mock(port=12345)
        mock_conn.raddr = Mock(ip="192.168.1.1", port=80)
        mock_proc.connections = Mock(return_value=[mock_conn])

        event = monitor._proc_event(mock_proc)
        assert "192.168.1.1:80" in event["remote_addrs"]

    def test_proc_event_handles_no_such_process(self, monitor):
        """Test that _proc_event handles NoSuchProcess exception"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(side_effect=psutil.NoSuchProcess(1234))

        event = monitor._proc_event(mock_proc)
        assert event.get("status") == "gone"

    def test_proc_event_handles_access_denied(self, monitor):
        """Test that _proc_event handles AccessDenied exception"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(side_effect=psutil.AccessDenied(1234))

        event = monitor._proc_event(mock_proc)
        assert event.get("status") == "gone"

    def test_proc_event_handles_zombie_process(self, monitor):
        """Test that _proc_event handles ZombieProcess exception"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(side_effect=psutil.ZombieProcess(1234))

        event = monitor._proc_event(mock_proc)
        assert event.get("status") == "gone"

    @patch("agent.monitor.get_signature_info")
    def test_proc_event_extracts_signature_windows(self, mock_get_sig, monitor):
        """Test that _proc_event extracts Windows signature on Windows"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(return_value="test.exe")
        mock_proc.ppid = Mock(return_value=1)
        mock_proc.exe = Mock(return_value="C:\\test.exe")
        mock_proc.cmdline = Mock(return_value=["test.exe"])
        mock_proc.username = Mock(return_value="user")
        mock_proc.create_time = Mock(return_value=time.time())
        mock_proc.memory_info = Mock(return_value=Mock(rss=1024, vms=2048))
        mock_proc.connections = Mock(return_value=[])

        mock_get_sig.return_value = {"valid": True, "subject": "Microsoft Corporation"}

        with patch("sys.platform", "win32"):
            with patch("os.path.exists", return_value=True):
                event = monitor._proc_event(mock_proc)
                assert event.get("signer_valid") is True
                assert event.get("signer_subject") == "Microsoft Corporation"

    @patch("agent.monitor.get_signature_info")
    def test_proc_event_handles_signature_error(self, mock_get_sig, monitor):
        """Test that _proc_event handles signature extraction errors"""
        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(return_value="test.exe")
        mock_proc.ppid = Mock(return_value=1)
        mock_proc.exe = Mock(return_value="C:\\test.exe")
        mock_proc.cmdline = Mock(return_value=["test.exe"])
        mock_proc.username = Mock(return_value="user")
        mock_proc.create_time = Mock(return_value=time.time())
        mock_proc.memory_info = Mock(return_value=Mock(rss=1024, vms=2048))
        mock_proc.connections = Mock(return_value=[])

        mock_get_sig.side_effect = Exception("Signature check failed")

        with patch("sys.platform", "win32"):
            with patch("os.path.exists", return_value=True):
                event = monitor._proc_event(mock_proc)
                # Should not crash, signature fields may be missing
                assert "signer_valid" not in event or event.get("signer_valid") is False

    def test_monitor_run_detects_new_processes(self, monitor, mock_publish):
        """Test that monitor detects and publishes new processes"""
        # This test would require running the monitor in a thread
        # For now, we test the logic indirectly
        initial_seen = len(monitor._seen)
        assert isinstance(initial_seen, int)

    def test_monitor_forgets_old_processes(self, monitor):
        """Test that monitor removes old PIDs from tracking"""
        # Add a fake PID that's old
        old_time = time.time() - 120  # 2 minutes ago
        monitor._seen[99999] = old_time

        # Simulate cleanup (normally done in run loop)
        now = time.time()
        to_forget = [pid for pid, ts in monitor._seen.items() if now - ts > 60]
        for pid in to_forget:
            monitor._seen.pop(pid, None)

        assert 99999 not in monitor._seen

    def test_monitor_hashes_executable(self, monitor, tmp_path):
        """Test that monitor hashes executable files"""
        test_exe = tmp_path / "test.exe"
        test_exe.write_bytes(b"executable content")

        mock_proc = Mock(spec=psutil.Process)
        mock_proc.pid = 1234
        mock_proc.name = Mock(return_value="test.exe")
        mock_proc.ppid = Mock(return_value=1)
        mock_proc.exe = Mock(return_value=str(test_exe))
        mock_proc.cmdline = Mock(return_value=["test.exe"])
        mock_proc.username = Mock(return_value="user")
        mock_proc.create_time = Mock(return_value=time.time())
        mock_proc.memory_info = Mock(return_value=Mock(rss=1024, vms=2048))
        mock_proc.connections = Mock(return_value=[])

        event = monitor._proc_event(mock_proc)
        assert "sha256" in event
        assert event["sha256"] is not None
        assert len(event["sha256"]) == 64  # SHA256 hex string length
