"""
Goal: Publish a coarse network state snapshot so rules can react to listening ports, connections, etc.

Design:
- Uses psutil.net_connections for system-wide view every N seconds.
- Normalizes into a compact event for the rules engine.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Callable

import psutil

PublishFn = Callable[[Dict[str, Any]], None]


class NetworkSnapshot:
    def __init__(self, publish: PublishFn, interval_sec: float = 5.0) -> None:
        self.publish = publish
        self.interval = interval_sec

    def run(self) -> None:
        while True:
            conns = psutil.net_connections(kind="inet")
            listening: List[int] = sorted({c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN})
            outbound: List[str] = [f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr]
            self.publish({
                "source": "network",
                "listening_ports": listening,
                "remote_endpoints": outbound,
            })
            time.sleep(self.interval)