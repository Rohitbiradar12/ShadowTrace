import os
import socket
import sys

import pytest

from shadowtrace_agent.collectors.common.network import NetworkCollector, classify_ip


class Capture:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def __call__(self, category, action, data=None, user=None, ts=None) -> None:
        self.events.append({"action": action, **(data or {})})


def test_classify_ip():
    assert classify_ip("127.0.0.1") == (True, False)
    assert classify_ip("192.168.1.20") == (False, True)
    assert classify_ip("8.8.8.8") == (False, False)
    assert classify_ip("::ffff:10.0.0.5") == (False, True)
    assert classify_ip("not-an-ip") == (False, False)


@pytest.mark.skipif(sys.platform == "darwin", reason="listing sockets needs root on macOS")
def test_new_listening_port_is_reported_once():
    capture = Capture()
    collector = NetworkCollector(NetworkCollector.Options(), capture)
    collector.poll(report=False)

    server = socket.socket()
    server.bind(("0.0.0.0", 0))
    server.listen()
    port = server.getsockname()[1]
    try:
        collector.poll()
        collector.poll()
    finally:
        server.close()

    mine = [
        e for e in capture.events if e["action"] == "port_listening" and e["local_port"] == port
    ]
    assert len(mine) == 1
    assert mine[0]["pid"] == os.getpid()
