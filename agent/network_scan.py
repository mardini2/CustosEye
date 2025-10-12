"""
goal: publish a coarse network state snapshot so rules can react to listening ports, connections, etc.

design:
- uses psutil.net_connections for system-wide view every N seconds.
- normalizes into a compact event for the rules engine.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import psutil

PublishFn = Callable[[dict[str, Any]], None]


class NetworkSnapshot:
    def __init__(self, publish: PublishFn, interval_sec: float = 5.0) -> None:
        self.publish = publish
        self.interval = interval_sec

    def run(self) -> None:
        while True:
            conns = psutil.net_connections(kind="inet")
            listening: list[int] = sorted(
                {c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN}
            )
            outbound: list[str] = [f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr]
            self.publish(
                {
                    "source": "network",
                    "listening_ports": listening,
                    "remote_endpoints": outbound,
                }
            )
            time.sleep(self.interval)
