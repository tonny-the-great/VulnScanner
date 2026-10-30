"""Server-Sent Events stream of scan progress.

TestClient buffers a whole response, so streams that must be observed while
they are still open are driven through a minimal ASGI client below.
"""

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import update

from app.database import SessionLocal, engine
from app.main import app
from app.models.scan import Scan, ScanEvent, ScanStatus
from app.routers import events as events_router


def _parse(body: bytes) -> list[tuple[str, dict | None]]:
    """Split an SSE body into (event name, data) pairs; comment frames give (':', None)."""
    frames = []
    for block in body.decode().split("\n\n"):
        if not block:
            continue
        if block.startswith(":"):
            frames.append((":", None))
            continue
        lines = dict(line.split(": ", 1) for line in block.split("\n"))
        frames.append((lines["event"], json.loads(lines["data"])))
    return frames


def _set_status(scan_id, status):
    with SessionLocal() as s:
        s.execute(update(Scan).where(Scan.id == scan_id).values(status=status))
        s.commit()


def _add_events(db, scan_id, *specs):
    """specs: (event_type, created_at); returns the new event ids in order."""
    rows = [
        ScanEvent(scan_id=scan_id, event_type=t, payload={"n": i}, created_at=ts)
        for i, (t, ts) in enumerate(specs)
    ]
    db.add_all(rows)
    db.commit()
    return [row.id for row in rows]


class _StreamClient:
    """Drive one GET request through the ASGI app, receiving body chunks as they are sent."""

    def __init__(self, client, path):
        cookie = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
        self.scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": [
                (b"host", b"testserver"),
                (b"accept", b"text/event-stream"),
                (b"cookie", cookie.encode()),
            ],
            "client": ("127.0.0.1", 50000),
            "server": ("testserver", 80),
            "state": {},
        }
        self.messages: asyncio.Queue = asyncio.Queue()
        self.disconnected = asyncio.Event()
        self._request_sent = False
        self.task = None

    async def _receive(self):
        if not self._request_sent:
            self._request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await self.disconnected.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message):
        await self.messages.put(message)

    async def start(self) -> int:
        self.task = asyncio.create_task(app(self.scope, self._receive, self._send))
        message = await asyncio.wait_for(self.messages.get(), timeout=10)
        assert message["type"] == "http.response.start"
        return message["status"]

    async def next_chunk(self) -> bytes | None:
        """Next non-empty body chunk, or None once the response is complete."""
        while True:
            message = await asyncio.wait_for(self.messages.get(), timeout=10)
            assert message["type"] == "http.response.body"
            if message.get("body"):
                return message["body"]
            if not message.get("more_body", False):
                return None

    async def rest(self) -> bytes:
        body = b""
        while (chunk := await self.next_chunk()) is not None:
            body += chunk
        await asyncio.wait_for(self.task, timeout=10)
        return body


def test_completed_scan_replays_events_then_done(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    scan_id = launch_scan(workflow)
    base = datetime.now(UTC)
    ids = _add_events(
        db, scan_id, *((f"step_{i}", base + timedelta(milliseconds=i)) for i in range(3))
    )
    _set_status(scan_id, ScanStatus.COMPLETED)

    response = client.get(prefix + f"/scans/{scan_id}/events")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    frames = _parse(response.content)
    assert [name for name, _ in frames] == ["step_0", "step_1", "step_2", "done"]
    assert [data["id"] for _, data in frames[:3]] == [str(i) for i in ids]
    assert frames[0][1]["payload"] == {"n": 0}
    assert frames[0][1]["event_type"] == "step_0"
    assert frames[0][1]["created_at"]
    assert frames[-1][1] == {"event_type": "stream_closed", "final_status": "completed"}


def test_events_sharing_a_timestamp_are_all_delivered_once(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    scan_id = launch_scan(workflow)
    same = datetime.now(UTC)
    ids = _add_events(
        db, scan_id,
        ("early", same - timedelta(seconds=1)), ("tie", same), ("tie", same), ("tie", same),
    )
    _set_status(scan_id, ScanStatus.FAILED)

    frames = _parse(client.get(prefix + f"/scans/{scan_id}/events").content)
    delivered = [data["id"] for name, data in frames if name != "done"]
    assert sorted(delivered) == sorted(str(i) for i in ids)
    assert delivered[0] == str(ids[0])
    assert frames[-1] == ("done", {"event_type": "stream_closed", "final_status": "failed"})


def test_unknown_scan_is_not_found(workflow):
    client, prefix, _payload, _scanner = workflow
    assert client.get(prefix + f"/scans/{uuid.uuid4()}/events").status_code == 404


def test_running_stream_holds_no_connection_and_ends_on_completion(
    workflow, launch_scan, db, monkeypatch
):
    client, prefix, _payload, _scanner = workflow
    monkeypatch.setattr(events_router, "POLL_INTERVAL_SECONDS", 0.05)
    scan_id = launch_scan(workflow)
    _set_status(scan_id, ScanStatus.RUNNING)
    tied = datetime.now(UTC)
    first_ids = _add_events(
        db, scan_id, ("tool_started", tied - timedelta(seconds=1)), ("tool_finished", tied)
    )
    db.close()  # the test's own session must not hold a pooled connection

    async def scenario():
        stream = _StreamClient(client, prefix + f"/scans/{scan_id}/events")
        assert await stream.start() == 200
        first = await stream.next_chunk()
        # Neither the request's session nor a polling session is open while streaming.
        checked_out = engine.pool.checkedout()
        body = first + await stream.next_chunk()

        # A later event with the same timestamp as the last delivered one, committed
        # together with completion from another session.
        def finish():
            with SessionLocal() as other:
                late = ScanEvent(
                    scan_id=scan_id, event_type="scan_completed", payload={}, created_at=tied
                )
                other.add(late)
                other.execute(
                    update(Scan).where(Scan.id == scan_id).values(status=ScanStatus.COMPLETED)
                )
                other.commit()
                return late.id

        late_id = await asyncio.to_thread(finish)
        body += await stream.rest()
        return checked_out, body, late_id

    checked_out, body, late_id = asyncio.run(scenario())
    assert checked_out == 0
    frames = _parse(body)
    delivered = [data["id"] for name, data in frames if name not in ("done", ":")]
    assert delivered == [str(first_ids[0]), str(first_ids[1]), str(late_id)]
    assert frames[-1] == ("done", {"event_type": "stream_closed", "final_status": "completed"})


def test_idle_stream_sends_keepalive_comments(workflow, launch_scan, monkeypatch):
    client, prefix, _payload, _scanner = workflow
    monkeypatch.setattr(events_router, "POLL_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(events_router, "KEEPALIVE_INTERVAL_SECONDS", 0.05)
    scan_id = launch_scan(workflow)
    _set_status(scan_id, ScanStatus.RUNNING)

    async def scenario():
        stream = _StreamClient(client, prefix + f"/scans/{scan_id}/events")
        assert await stream.start() == 200
        ping = await stream.next_chunk()
        await asyncio.to_thread(_set_status, scan_id, ScanStatus.CANCELLED)
        return ping, await stream.rest()

    ping, rest = asyncio.run(scenario())
    assert ping == b": ping\n\n"
    assert _parse(rest)[-1] == (
        "done",
        {"event_type": "stream_closed", "final_status": "cancelled"},
    )
