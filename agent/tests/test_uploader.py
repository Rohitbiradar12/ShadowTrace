import json

import httpx
import pytest

from shadowtrace_agent.config import UploadConfig
from shadowtrace_agent.schema import Category, new_event
from shadowtrace_agent.transport.buffer import EventBuffer
from shadowtrace_agent.transport.client import AuthError, ServerClient, ServerError
from shadowtrace_agent.transport.loops import Uploader


def make_uploader(tmp_path, handler, batch_size=2):
    buffer = EventBuffer(tmp_path / "b.db", max_events=1000)
    client = ServerClient(
        "http://server", api_key="stk_test", transport=httpx.MockTransport(handler)
    )
    return buffer, Uploader(buffer, client, UploadConfig(batch_size=batch_size))


def test_successful_upload_acks_batch(tmp_path):
    received = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Device-Key"] == "stk_test"
        assert request.url.path == "/api/v1/events/batch"
        received.extend(json.loads(request.content)["events"])
        return httpx.Response(200, json={"accepted": 2, "duplicates": 0})

    buffer, uploader = make_uploader(tmp_path, handler)
    for _ in range(3):
        buffer.put(new_event(Category.PROCESS, "process_started"))

    assert uploader.flush_once() == 2
    assert [e["seq"] for e in received] == [1, 2]
    assert len(buffer) == 1


def test_failed_upload_keeps_events_buffered(tmp_path):
    buffer, uploader = make_uploader(tmp_path, lambda r: httpx.Response(503))
    buffer.put(new_event(Category.PROCESS, "process_started"))

    with pytest.raises(ServerError):
        uploader.flush_once()
    assert len(buffer) == 1


def test_network_error_is_a_server_error(tmp_path):
    def handler(request):
        raise httpx.ConnectError("connection refused")

    buffer, uploader = make_uploader(tmp_path, handler)
    buffer.put(new_event(Category.PROCESS, "process_started"))

    with pytest.raises(ServerError):
        uploader.flush_once()


def test_rejected_key_is_an_auth_error(tmp_path):
    buffer, uploader = make_uploader(tmp_path, lambda r: httpx.Response(401))
    buffer.put(new_event(Category.PROCESS, "process_started"))

    with pytest.raises(AuthError):
        uploader.flush_once()
