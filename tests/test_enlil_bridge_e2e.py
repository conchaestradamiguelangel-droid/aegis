"""
AEGIS — E2E del bridge AEGIS→ENLIL con ENLIL simulado (mock HTTP local)
=======================================================================
Sin gasto real: el "ENLIL" es un servidor HTTP en 127.0.0.1 que solo graba
lo que recibe y responde lo que el test le ordena. Recorre el camino real:
detección → AegisSystem._on_detection_lockdown → EnlilConnector → HTTP →
mock ENLIL → respuesta → AEGIS la procesa (log) y SIGUE ejecutando el
lockdown pase lo que pase.

El bridge real sigue apagado (ENLIL_BRIDGE_ENABLED=false en aegis.env).
"""

import asyncio
import json
import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.aegis import AegisSystem
from integrations import enlil_connector as ec
from integrations.enlil_connector import EnlilConnector
from layers.detector import DetectionEvent, DetectionType, ThreatConfidence

API_KEY = "sk-test-SECRETO-no-debe-aparecer-en-logs"


# ───────────────────────── mock ENLIL ─────────────────────────

class _MockEnlil:
    def __init__(self):
        self.requests = []          # (path, headers, body)
        self.mode = "ok"            # ok | slow | http:<code> | raw:<texto> | json:<valor>
        self.delay = 0.0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silencio
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.requests.append((self.path, dict(self.headers), body))
                if outer.delay:
                    time.sleep(outer.delay)
                mode = outer.mode
                if mode.startswith("http:"):
                    code = int(mode.split(":", 1)[1])
                    data = json.dumps({"detail": "error simulado"}).encode()
                elif mode.startswith("raw:"):
                    code, data = 200, mode.split(":", 1)[1].encode()
                elif mode.startswith("json:"):
                    code, data = 200, mode.split(":", 1)[1].encode()
                else:
                    code = 200
                    data = json.dumps({
                        "decree_id": "abcdef12-0000-0000-0000-000000000000",
                        "synthesis": "Contramedida simulada",
                        "status": "completed", "total_tokens": 10,
                    }).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def mock():
    m = _MockEnlil()
    yield m
    m.close()


@pytest.fixture
def bridge_on(monkeypatch):
    monkeypatch.setenv("ENLIL_BRIDGE_ENABLED", "true")


@pytest.fixture
def bridge_off(monkeypatch):
    monkeypatch.delenv("ENLIL_BRIDGE_ENABLED", raising=False)


# ───────────────────────── helpers ─────────────────────────

def _det(ip="10.0.0.9", dtype=DetectionType.MINE_CONTACT, conf=ThreatConfidence.CONFIRMED, **kw):
    base = dict(
        detection_id="TESTID000001", timestamp=datetime.now(timezone.utc),
        detection_type=dtype, confidence=conf, source_ips=[ip],
        indicators=["indicador de prueba"], evidence={"requests_per_second": 999.0},
        action_required="LOCKDOWN", elapsed_ms=1.0,
    )
    base.update(kw)
    return DetectionEvent(**base)


class _Lock:
    def __init__(self):
        self.executed = 0

    def is_sealed(self):
        return False

    async def execute(self, **kw):
        self.executed += 1
        return None


def _aegis_stub(connector):
    """Sustituto mínimo de AegisSystem para ejercitar su manejador REAL."""
    timing = SimpleNamespace(record=lambda *_: None)
    return SimpleNamespace(
        _telegram=None, _enlil=connector, lockdown=_Lock(),
        _timing_lockdown=timing, _timing_detection=timing,
    )


async def _flow(connector, detections):
    """Pasa detecciones por el manejador real de AEGIS y espera a ENLIL."""
    stub = _aegis_stub(connector)
    for d in detections:
        await AegisSystem._on_detection_lockdown(stub, d)
    if connector._tasks:
        await asyncio.gather(*list(connector._tasks))
    return stub


def run(connector, detections):
    return asyncio.run(_flow(connector, detections))


def _conn(url):
    return EnlilConnector(enlil_url=url, api_key=API_KEY)


# ───────────────────────── casos ─────────────────────────

def test_exito_e2e_auth_payload_y_respuesta_procesada(mock, bridge_on, caplog):
    caplog.set_level(logging.INFO, logger="aegis.enlil")
    stub = run(_conn(mock.url), [_det()])
    assert len(mock.requests) == 1
    path, headers, body = mock.requests[0]
    assert path == "/query"
    assert headers.get("X-Api-Key") == API_KEY
    assert set(body) == {"query", "context", "budget_tier"}
    assert body["budget_tier"] == "full"
    assert "10.0.0.9" in body["query"]
    assert stub.lockdown.executed == 1
    assert "Decreto emitido" in caplog.text and "abcdef12" in caplog.text
    assert API_KEY not in caplog.text


@pytest.mark.parametrize("code", [400, 401, 403, 429, 500, 502, 503])
def test_enlil_4xx_5xx_aegis_sigue_sin_reintentos(mock, bridge_on, caplog, code):
    caplog.set_level(logging.INFO, logger="aegis.enlil")
    mock.mode = f"http:{code}"
    stub = run(_conn(mock.url), [_det()])
    assert len(mock.requests) == 1, "no debe haber reintentos"
    assert stub.lockdown.executed == 1
    assert "Sin respuesta válida" in caplog.text
    assert API_KEY not in caplog.text


def test_timeout_acotado_aegis_sigue(mock, bridge_on, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="aegis.enlil")
    monkeypatch.setattr(ec, "_TIMEOUT_S", 0.2)
    mock.delay = 1.0
    c = _conn(mock.url)
    t0 = time.monotonic()
    stub = run(c, [_det()])
    assert time.monotonic() - t0 < 0.9, "el timeout debe acotar la espera"
    assert len(mock.requests) == 1
    assert stub.lockdown.executed == 1
    assert c._inflight == 0
    assert "Sin respuesta válida" in caplog.text


def test_enlil_caido_conexion_rechazada(bridge_on, caplog):
    caplog.set_level(logging.INFO, logger="aegis.enlil")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]          # puerto libre, nadie escucha
    c = _conn(f"http://127.0.0.1:{port}")
    stub = run(c, [_det()])
    assert stub.lockdown.executed == 1
    assert c._inflight == 0
    assert "Sin respuesta válida" in caplog.text
    assert API_KEY not in caplog.text


def test_cost_guard_deny_decreto_fallido_se_registra_sin_romper(mock, bridge_on, caplog):
    """ENLIL responde 200 con decreto status=failed (Cost Guard DENY) o 503 de kill switch."""
    caplog.set_level(logging.INFO, logger="aegis.enlil")
    mock.mode = 'json:{"decree_id":"deadbeef-1","synthesis":"","status":"failed","accounting_state":"denied"}'
    stub = run(_conn(mock.url), [_det()])
    assert stub.lockdown.executed == 1
    assert "estado=failed" in caplog.text
    assert len(mock.requests) == 1


@pytest.mark.parametrize("mode", [
    "raw:esto no es json", "raw:", "json:[]", "json:null", "json:42",
    'json:{"decree_id":null,"synthesis":null,"status":null}',
    'json:{"decree_id":123,"synthesis":["x"]}',
])
def test_respuesta_invalida_no_rompe(mock, bridge_on, mode):
    mock.mode = mode
    c = _conn(mock.url)
    stub = run(c, [_det()])
    assert stub.lockdown.executed == 1
    assert c._inflight == 0
    assert len(mock.requests) == 1


def test_duplicado_misma_deteccion_no_reenvia(mock, bridge_on):
    run(_conn(mock.url), [_det(), _det()])
    assert len(mock.requests) == 1


def test_distinta_ip_si_envia(mock, bridge_on):
    run(_conn(mock.url), [_det(ip="10.0.0.1"), _det(ip="10.0.0.2")])
    assert len(mock.requests) == 2


def test_tope_de_simultaneas(mock, bridge_on):
    mock.delay = 0.4
    stub = run(_conn(mock.url), [_det(ip=f"10.0.1.{i}") for i in range(6)])
    assert len(mock.requests) == ec._MAX_INFLIGHT
    assert stub.lockdown.executed == 6, "AEGIS procesa TODAS las detecciones"


def test_tope_por_hora(mock, bridge_on, monkeypatch):
    monkeypatch.setattr(ec, "_MAX_PER_HOUR", 3)
    # una a una (sin solapar) para aislar el tope horario del de simultáneas
    c = _conn(mock.url)

    async def seq():
        s = _aegis_stub(c)
        for i in range(6):
            await AegisSystem._on_detection_lockdown(s, _det(ip=f"10.0.3.{i}"))
            await asyncio.gather(*list(c._tasks))
        return s

    s = asyncio.run(seq())
    assert len(mock.requests) == 3
    assert s.lockdown.executed == 6


def test_bridge_off_cero_llamadas(mock, bridge_off):
    c = _conn(mock.url)
    assert c._enabled is False
    stub = run(c, [_det(), _det(ip="10.9.9.9")])
    assert mock.requests == []
    assert stub.lockdown.executed == 2


def test_automated_nunca_se_envia(mock, bridge_on):
    run(_conn(mock.url), [_det(dtype=DetectionType.AUTOMATED, conf=ThreatConfidence.HIGH)])
    assert mock.requests == []


def test_fallo_interno_del_conector_no_llega_al_lockdown(mock, bridge_on, caplog):
    """Una detección malformada (evidence no iterable) hacía fallar on_threat_detected
    DENTRO del camino de lockdown. Ahora se absorbe y AEGIS sigue."""
    caplog.set_level(logging.INFO, logger="aegis.enlil")
    stub = run(_conn(mock.url), [_det(evidence=42)])
    assert stub.lockdown.executed == 1
    assert mock.requests == []
    assert "Bridge omitido por error interno" in caplog.text


def test_sin_bucle_una_deteccion_una_llamada(mock, bridge_on):
    """La respuesta de ENLIL solo se registra: no genera detecciones ni más llamadas."""
    c = _conn(mock.url)

    async def go():
        await _flow(c, [_det()])
        await asyncio.sleep(0.3)        # margen para detectar llamadas espurias

    asyncio.run(go())
    assert len(mock.requests) == 1
    assert c._inflight == 0 and not c._tasks
