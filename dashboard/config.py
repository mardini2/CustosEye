"""
goal: configuration loader for the dashboard. loads settings from a JSON file and environment
      variables, with sensible defaults. handles PyInstaller frozen executables by detecting
      the base directory correctly. returns a frozen Config dataclass with all paths and settings
      needed by the dashboard app.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


# figure out where the app is running from (handles PyInstaller bundles)
def _resolve_base_dir() -> Path:
    import sys

    # if we are frozen (PyInstaller), use the executable's directory
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    # otherwise, go up one level from this file (dashboard/config.py -> project root)
    return Path(__file__).resolve().parents[1]


# frozen dataclass to hold all config values (immutable once created)
@dataclass(frozen=True)
class Config:
    base_dir: Path  # root directory of the project
    rules_path: Path  # path to rules JSON file
    csc_weights_path: Path  # path to CSC trust engine weights JSON
    csc_db_path: Path  # path to CSC trust database JSON
    integrity_targets_path: Path  # path to integrity watch list JSON
    self_suppress_path: Path  # path to self-suppression list JSON
    buffer_max: int  # max number of events in the ring buffer
    drain_limit_per_call: int  # max events to drain per API call
    drain_deadline_sec: float  # max seconds to spend draining per call
    host: str  # web server host address
    port: int  # web server port number
    max_tree_roots: int  # max root processes to show in process tree
    max_tree_children: int  # max child processes per parent in tree


# get a config value with priority: environment variable > JSON file > default
def _get(obj: dict, key: str, default):
    # check for environment variable first (CUSTOSEYE_* prefix)
    env = os.getenv(f"CUSTOSEYE_{key.upper()}")
    if env is not None:
        # try to coerce to int/float when default is numeric
        if isinstance(default, int):
            try:
                return int(env)
            except Exception:
                return default
        if isinstance(default, float):
            try:
                return float(env)
            except Exception:
                return default
        # for strings, just return the env var as-is
        return env
    # fall back to JSON file value, or default if not found
    return obj.get(key, default)


# load configuration from JSON file and environment variables
def load_config() -> Config:
    # base directory can be overridden by env var, otherwise auto-detect
    base = Path(os.getenv("CUSTOSEYE_BASE_DIR") or _resolve_base_dir())
    # config file lives in data/config.json
    cfg_file = base / "data" / "config.json"
    obj = {}
    # try to load the JSON config file if it exists
    if cfg_file.exists():
        try:
            obj = json.loads(cfg_file.read_text(encoding="utf-8") or "{}")
        except Exception:
            # if JSON is broken, just use empty dict (all defaults)
            obj = {}

    # build the Config object with all paths and settings
    # each value checks: env var > JSON file > default
    return Config(
        base_dir=base,
        rules_path=base / _get(obj, "rules_path", "data/rules.json"),
        csc_weights_path=base / _get(obj, "csc_weights_path", "data/csc_weights.json"),
        csc_db_path=base / _get(obj, "csc_db_path", "data/trust_db.json"),
        integrity_targets_path=base
        / _get(obj, "integrity_targets_path", "data/integrity_targets.json"),
        self_suppress_path=base / _get(obj, "self_suppress_path", "data/self_suppress.json"),
        buffer_max=_get(obj, "buffer_max", 1200),
        drain_limit_per_call=_get(obj, "drain_limit_per_call", 300),
        drain_deadline_sec=_get(obj, "drain_deadline_sec", 0.25),
        host=_get(obj, "host", "127.0.0.1"),
        port=_get(obj, "port", 8765),
        max_tree_roots=_get(obj, "max_tree_roots", 100),
        max_tree_children=_get(obj, "max_tree_children", 100),
    )
