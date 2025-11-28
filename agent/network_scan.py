# SPDX-License-Identifier: GPL-3.0-or-later
"""
goal: periodically scans network connections on the system and publishes snapshots of listening ports
and remote endpoints. Uses psutil to get system-wide network state and publishes compact events
that the rules engine can use to make decisions.
"""

from __future__ import annotations  # lets us use string annotations before classes are defined

import time  # for sleeping between scan intervals
from collections.abc import Callable  # type hint for function callbacks
from typing import Any  # type hint for flexible dictionary values

import psutil  # library for getting network connection information

# type alias for the publish callback, takes an event dict and returns nothing
PublishFn = Callable[[dict[str, Any]], None]


class NetworkSnapshot:
    def __init__(self, publish: PublishFn, interval_sec: float = 5.0) -> None:
        self.publish = publish  # callback function to send events to
        self.interval = interval_sec  # how many seconds to wait between scans

    def run(self) -> None:
        while True:  # run forever until the process is killed
            conns = psutil.net_connections(kind="inet")  # get all TCP/UDP connections on the system
            listening: list[int] = sorted(
                {
                    c.laddr.port for c in conns if c.status == psutil.CONN_LISTEN
                }  # extract unique listening ports and sort them
            )
            outbound: list[str] = [
                f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr
            ]  # format remote addresses as "ip:port" for connections that have a remote address
            self.publish(
                {
                    "source": "network",  # mark this as a network event
                    "listening_ports": listening,  # list of ports that are listening for connections
                    "remote_endpoints": outbound,  # list of remote endpoints we're connected to
                }
            )
            time.sleep(self.interval)  # wait before scanning again
