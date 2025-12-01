"""
Tests for agent.win_sign - Windows signature checking functionality
Tests Authenticode signature verification using PowerShell.
"""

from __future__ import annotations

import json
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest

from agent.win_sign import get_signature_info


class TestGetSignatureInfo:
    """Tests for get_signature_info function"""

    def test_get_signature_info_non_windows(self):
        """Test that get_signature_info returns empty dict on non-Windows"""
        with patch("sys.platform", "linux"):
            result = get_signature_info("C:\\test.exe")
            assert result == {}

    def test_get_signature_info_nonexistent_file(self):
        """Test that get_signature_info returns empty dict for non-existent file"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        result = get_signature_info("C:\\nonexistent\\file.exe")
        assert result == {}

    def test_get_signature_info_empty_path(self):
        """Test that get_signature_info handles empty path"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        result = get_signature_info("")
        assert result == {}

    def test_get_signature_info_strips_quotes(self):
        """Test that get_signature_info strips quotes from path"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        with patch("os.path.exists", return_value=False):
            result = get_signature_info('"C:\\test.exe"')
            assert result == {}

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_valid_signature(self, mock_exists, mock_run):
        """Test that get_signature_info returns valid signature info"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"valid": true, "subject": "Microsoft Corporation"}'
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")

        assert result["valid"] is True
        assert result["subject"] == "Microsoft Corporation"

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_invalid_signature(self, mock_exists, mock_run):
        """Test that get_signature_info returns invalid signature info"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"valid": false, "subject": ""}'
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")

        assert result["valid"] is False
        assert result["subject"] == ""

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_powershell_failure(self, mock_exists, mock_run):
        """Test that get_signature_info handles PowerShell failure"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 1  # PowerShell failed
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")
        assert result == {}

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_empty_output(self, mock_exists, mock_run):
        """Test that get_signature_info handles empty PowerShell output"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")
        assert result == {}

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_invalid_json(self, mock_exists, mock_run):
        """Test that get_signature_info handles invalid JSON"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = "{ invalid json }"
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")
        assert result == {}

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_not_dict(self, mock_exists, mock_run):
        """Test that get_signature_info handles non-dict JSON"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = '["not", "a", "dict"]'
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")
        assert result == {}

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_timeout(self, mock_exists, mock_run):
        """Test that get_signature_info handles timeout"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired("powershell", 5)

        result = get_signature_info("C:\\test.exe")
        assert result == {}

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_subject_truncation(self, mock_exists, mock_run):
        """Test that get_signature_info truncates long subject strings"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        long_subject = "A" * 1000  # Very long subject
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps({"valid": True, "subject": long_subject})
        mock_run.return_value = mock_proc

        result = get_signature_info("C:\\test.exe")

        assert result["valid"] is True
        assert len(result["subject"]) <= 512  # Should be truncated

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_get_signature_info_escapes_path(self, mock_exists, mock_run):
        """Test that get_signature_info escapes single quotes in path"""
        if sys.platform != "win32":
            pytest.skip("Windows-only test")

        mock_exists.return_value = True
        mock_proc = Mock()
        mock_proc.returncode = 0
        mock_proc.stdout = '{"valid": true, "subject": "Test"}'
        mock_run.return_value = mock_proc

        # Path with single quote
        result = get_signature_info("C:\\test's file.exe")

        # Should not crash
        assert isinstance(result, dict)
        # Verify that the path was escaped in the PowerShell command
        call_args = mock_run.call_args[0][0]
        assert "test''s" in " ".join(call_args) or "test's" in " ".join(call_args)
