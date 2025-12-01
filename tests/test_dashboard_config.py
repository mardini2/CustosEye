"""
Tests for dashboard.config - Configuration loading functionality
Tests config loading from JSON and environment variables.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from dashboard.config import Config, _get, _resolve_base_dir, load_config


class TestResolveBaseDir:
    """Tests for _resolve_base_dir function"""

    def test_resolve_base_dir_normal(self):
        """Test _resolve_base_dir in normal (non-frozen) mode"""
        with patch("sys.frozen", False, create=True):
            result = _resolve_base_dir()
            assert isinstance(result, Path)

    def test_resolve_base_dir_frozen(self):
        """Test _resolve_base_dir in frozen (PyInstaller) mode"""
        with patch("sys.frozen", True, create=True):
            with patch("sys.executable", "C:\\app\\CustosEye.exe"):
                result = _resolve_base_dir()
                assert isinstance(result, Path)
                # In frozen mode, it returns the directory containing the executable
                # So it should be "C:\\app" not "C:\\app\\CustosEye.exe"
                assert str(result) == "C:\\app" or "app" in str(result)


class TestGet:
    """Tests for _get helper function"""

    def test_get_from_env_int(self):
        """Test _get retrieves integer from environment"""
        obj = {"key": 100}
        with patch.dict(os.environ, {"CUSTOSEYE_KEY": "200"}):
            result = _get(obj, "key", 50)
            assert result == 200

    def test_get_from_env_float(self):
        """Test _get retrieves float from environment"""
        obj = {"key": 1.5}
        with patch.dict(os.environ, {"CUSTOSEYE_KEY": "2.5"}):
            result = _get(obj, "key", 1.0)
            assert result == 2.5

    def test_get_from_env_string(self):
        """Test _get retrieves string from environment"""
        obj = {"key": "default"}
        with patch.dict(os.environ, {"CUSTOSEYE_KEY": "override"}):
            result = _get(obj, "key", "fallback")
            assert result == "override"

    def test_get_from_json_when_env_missing(self):
        """Test _get falls back to JSON when env var missing"""
        obj = {"key": "json_value"}
        with patch.dict(os.environ, {}, clear=True):
            result = _get(obj, "key", "default")
            assert result == "json_value"

    def test_get_from_default_when_both_missing(self):
        """Test _get uses default when both env and JSON missing"""
        obj = {}
        with patch.dict(os.environ, {}, clear=True):
            result = _get(obj, "key", "default")
            assert result == "default"

    def test_get_invalid_env_int(self):
        """Test _get handles invalid integer in env var"""
        obj = {"key": 100}
        with patch.dict(os.environ, {"CUSTOSEYE_KEY": "not_a_number"}):
            result = _get(obj, "key", 50)
            assert result == 50  # Falls back to default

    def test_get_invalid_env_float(self):
        """Test _get handles invalid float in env var"""
        obj = {"key": 1.5}
        with patch.dict(os.environ, {"CUSTOSEYE_KEY": "not_a_float"}):
            result = _get(obj, "key", 1.0)
            assert result == 1.0  # Falls back to default


class TestLoadConfig:
    """Tests for load_config function"""

    @pytest.fixture
    def tmp_base_dir(self, tmp_path):
        """Create temporary base directory with data folder"""
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        return tmp_path

    def test_load_config_creates_defaults(self, tmp_base_dir):
        """Test that load_config creates config with defaults"""
        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()

            assert isinstance(config, Config)
            assert config.base_dir == tmp_base_dir
            assert config.buffer_max == 1200
            assert config.host == "127.0.0.1"
            assert config.port == 8765

    def test_load_config_loads_from_json(self, tmp_base_dir):
        """Test that load_config loads values from JSON file"""
        config_file = tmp_base_dir / "data" / "config.json"
        config_data = {
            "buffer_max": 2000,
            "port": 9000,
            "host": "0.0.0.0",
        }
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()

            assert config.buffer_max == 2000
            assert config.port == 9000
            assert config.host == "0.0.0.0"

    def test_load_config_env_overrides_json(self, tmp_base_dir):
        """Test that environment variables override JSON values"""
        config_file = tmp_base_dir / "data" / "config.json"
        config_data = {"port": 9000}
        config_file.write_text(json.dumps(config_data), encoding="utf-8")

        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            with patch.dict(os.environ, {"CUSTOSEYE_PORT": "8000"}):
                config = load_config()
                assert config.port == 8000  # Env overrides JSON

    def test_load_config_handles_missing_json(self, tmp_base_dir):
        """Test that load_config handles missing JSON file"""
        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()
            # Should use defaults
            assert config.buffer_max == 1200

    def test_load_config_handles_invalid_json(self, tmp_base_dir):
        """Test that load_config handles invalid JSON"""
        config_file = tmp_base_dir / "data" / "config.json"
        config_file.write_text("{ invalid json }", encoding="utf-8")

        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()
            # Should use defaults
            assert config.buffer_max == 1200

    def test_load_config_handles_empty_json(self, tmp_base_dir):
        """Test that load_config handles empty JSON file"""
        config_file = tmp_base_dir / "data" / "config.json"
        config_file.write_text("", encoding="utf-8")

        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()
            # Should use defaults
            assert config.buffer_max == 1200

    def test_load_config_paths_relative_to_base(self, tmp_base_dir):
        """Test that config paths are relative to base_dir"""
        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()

            assert config.rules_path == tmp_base_dir / "data" / "rules.json"
            assert config.csc_weights_path == tmp_base_dir / "data" / "csc_weights.json"
            assert config.integrity_targets_path == tmp_base_dir / "data" / "integrity_targets.json"

    def test_load_config_env_base_dir(self, tmp_path):
        """Test that CUSTOSEYE_BASE_DIR env var is respected"""
        custom_base = tmp_path / "custom"
        custom_base.mkdir()
        (custom_base / "data").mkdir()

        with patch.dict(os.environ, {"CUSTOSEYE_BASE_DIR": str(custom_base)}):
            config = load_config()
            assert config.base_dir == custom_base

    def test_load_config_all_paths_set(self, tmp_base_dir):
        """Test that all config paths are set"""
        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()

            assert config.rules_path is not None
            assert config.csc_weights_path is not None
            assert config.csc_db_path is not None
            assert config.integrity_targets_path is not None
            assert config.self_suppress_path is not None

    def test_load_config_numeric_defaults(self, tmp_base_dir):
        """Test that numeric defaults are correct"""
        with patch("dashboard.config._resolve_base_dir", return_value=tmp_base_dir):
            config = load_config()

            assert isinstance(config.buffer_max, int)
            assert isinstance(config.port, int)
            assert isinstance(config.drain_limit_per_call, int)
            assert isinstance(config.drain_deadline_sec, float)
            assert isinstance(config.max_tree_roots, int)
            assert isinstance(config.max_tree_children, int)
