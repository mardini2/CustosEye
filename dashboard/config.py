from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json, os

def _resolve_base_dir() -> Path:
    import sys
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    # adjust to match your current layout (../ from this file → repo root)
    return Path(__file__).resolve().parents[1]

@dataclass(frozen=True)
class Config:
    base_dir: Path
    rules_path: Path
    csc_weights_path: Path
    csc_db_path: Path
    integrity_targets_path: Path
    self_suppress_path: Path
    buffer_max: int
    drain_limit_per_call: int
    drain_deadline_sec: float
    host: str
    port: int
    max_tree_roots: int
    max_tree_children: int

def _get(obj: dict, key: str, default):
    env = os.getenv(f"CUSTOSEYE_{key.upper()}")
    if env is not None:
        # try to coerce to int/float when default is numeric
        if isinstance(default, int):
            try: return int(env)
            except: return default
        if isinstance(default, float):
            try: return float(env)
            except: return default
        return env
    return obj.get(key, default)

def load_config() -> Config:
    base = Path(os.getenv("CUSTOSEYE_BASE_DIR") or _resolve_base_dir())
    cfg_file = base / "data" / "config.json"
    obj = {}
    if cfg_file.exists():
        try:
            obj = json.loads(cfg_file.read_text(encoding="utf-8") or "{}")
        except Exception:
            obj = {}

    return Config(
        base_dir=base,
        rules_path=base / _get(obj, "rules_path", "data/rules.json"),
        csc_weights_path=base / _get(obj, "csc_weights_path", "data/csc_weights.json"),
        csc_db_path=base / _get(obj, "csc_db_path", "data/trust_db.json"),
        integrity_targets_path=base / _get(obj, "integrity_targets_path", "data/integrity_targets.json"),
        self_suppress_path=base / _get(obj, "self_suppress_path", "data/self_suppress.json"),
        buffer_max=_get(obj, "buffer_max", 1200),
        drain_limit_per_call=_get(obj, "drain_limit_per_call", 300),
        drain_deadline_sec=_get(obj, "drain_deadline_sec", 0.25),
        host=_get(obj, "host", "127.0.0.1"),
        port=_get(obj, "port", 8765),
        max_tree_roots=_get(obj, "max_tree_roots", 100),
        max_tree_children=_get(obj, "max_tree_children", 100),
    )