"""Integration tests for StatusServer /incidents endpoint (closes #16)."""
import asyncio
import json
import sys
import os
import socket
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mock_aegis(incidents=None):
    mock = MagicMock()
    mock._reporter.get_index.return_value = incidents if incidents is not None else []
    mock.full_status.return_value = {"system": {}, "layers": {}}
    return mock


async def _fetch(port, path):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode())
    await writer.drain()
    raw = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            break
        raw += chunk
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    header_part, _, body_part = raw.partition(b"\r\n\r\n")
    header_lines = header_part.decode(errors="replace").splitlines()
    status_code = int(header_lines[0].split()[1]) if header_lines else 0
    headers = {}
    for line in header_lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    try:
        body = json.loads(body_part.decode(errors="replace"))
    except Exception:
        body = {}
    return status_code, headers, body


async def _with_server(aegis, coro_fn):
    from status_server import AegisStatusServer
    port = _free_port()
    srv = AegisStatusServer(aegis, port=port)
    await srv.start()
    try:
        return await coro_fn(port)
    finally:
        await srv.stop()


def test_incidents_returns_200_empty_list():
    async def run():
        async def check(port):
            status, _, body = await _fetch(port, "/incidents")
            assert status == 200, f"Expected 200, got {status}"
            assert isinstance(body, list), f"Expected list, got {type(body)}"
            assert body == [], f"Expected empty list, got {body}"
        await _with_server(_mock_aegis([]), check)
    asyncio.run(run())


def test_incidents_cors_header_present():
    async def run():
        async def check(port):
            _, headers, _ = await _fetch(port, "/incidents")
            assert "access-control-allow-origin" in headers, "CORS header missing"
            assert headers["access-control-allow-origin"] == "*"
        await _with_server(_mock_aegis([]), check)
    asyncio.run(run())


def test_incidents_returns_data():
    sample = [
        {"id": "INC-001", "timestamp": "2026-07-04T00:00:00Z", "threat_level": "HIGH"},
        {"id": "INC-002", "timestamp": "2026-07-04T01:00:00Z", "threat_level": "LOW"},
    ]

    async def run():
        async def check(port):
            status, _, body = await _fetch(port, "/incidents")
            assert status == 200
            assert len(body) == 2
            assert body[0]["id"] == "INC-001"
            assert body[1]["threat_level"] == "LOW"
        await _with_server(_mock_aegis(sample), check)
    asyncio.run(run())


def test_incidents_n_param_passed_to_reporter():
    async def run():
        aegis = _mock_aegis([])

        async def check(port):
            await _fetch(port, "/incidents?n=5")
            aegis._reporter.get_index.assert_called_with(last_n=5)
        await _with_server(aegis, check)
    asyncio.run(run())


def test_incidents_default_n_is_10():
    async def run():
        aegis = _mock_aegis([])

        async def check(port):
            await _fetch(port, "/incidents")
            aegis._reporter.get_index.assert_called_with(last_n=10)
        await _with_server(aegis, check)
    asyncio.run(run())


def test_incidents_content_type_json():
    async def run():
        async def check(port):
            _, headers, _ = await _fetch(port, "/incidents")
            ct = headers.get("content-type", "")
            assert "application/json" in ct, f"Expected JSON content-type, got: {ct}"
        await _with_server(_mock_aegis([]), check)
    asyncio.run(run())


if __name__ == "__main__":
    import pytest as _pytest
    sys.exit(_pytest.main([__file__, "-v"]))
