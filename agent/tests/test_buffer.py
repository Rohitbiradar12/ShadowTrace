from shadowtrace_agent.schema import Category, new_event
from shadowtrace_agent.transport.buffer import EventBuffer


def event(n: int) -> dict:
    return new_event(Category.PROCESS, "process_started", {"n": n})


def test_peek_returns_oldest_first_with_seq(tmp_path):
    buffer = EventBuffer(tmp_path / "b.db", max_events=1000)
    for n in range(3):
        buffer.put(event(n))

    batch = buffer.peek(2)

    assert [e["data"]["n"] for e in batch] == [0, 1]
    assert [e["seq"] for e in batch] == [1, 2]


def test_ack_removes_uploaded_events(tmp_path):
    buffer = EventBuffer(tmp_path / "b.db", max_events=1000)
    for n in range(5):
        buffer.put(event(n))

    buffer.ack(buffer.peek(3)[-1]["seq"])

    assert len(buffer) == 2
    assert [e["data"]["n"] for e in buffer.peek(10)] == [3, 4]


def test_events_survive_restart_and_seq_keeps_growing(tmp_path):
    path = tmp_path / "b.db"
    buffer = EventBuffer(path, max_events=1000)
    buffer.put(event(0))
    buffer.ack(1)
    buffer.put(event(1))
    buffer.close()

    reopened = EventBuffer(path, max_events=1000)
    seq = reopened.put(event(2))

    assert len(reopened) == 2
    assert seq == 3  # AUTOINCREMENT never reuses a seq, so the server can detect gaps


def test_full_buffer_drops_oldest(tmp_path):
    buffer = EventBuffer(tmp_path / "b.db", max_events=1000)
    for n in range(1005):
        buffer.put(event(n))

    assert len(buffer) == 1000
    assert buffer.dropped == 5
    assert buffer.peek(1)[0]["data"]["n"] == 5
