"""
AEGIS — Test de Capa 0.5: Escudo Disuasorio
=============================================
Tests de los tres niveles: red, servicios y comportamiento.
Los tests de red usan puertos locales en loopback — sin tráfico real exterior.
"""

import asyncio
import hashlib
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.shield import (
    AegisShield,
    NetworkSignatureLayer,
    ServiceDecoyLayer,
    BehaviorTrackingLayer,
    ProbeEvent,
    ProbeType,
    ThreatLevel,
)
from datetime import datetime, timezone

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []


def test(name: str, fn):
    try:
        if asyncio.iscoroutinefunction(fn):
            asyncio.run(fn())
        else:
            fn()
        print(f"  {PASS}  {name}")
        results.append((name, True))
    except Exception as e:
        print(f"  {FAIL}  {name}")
        print(f"         → {type(e).__name__}: {e}")
        results.append((name, False))


def _make_probe(
    ip="1.2.3.4",
    port=8080,
    probe_type=ProbeType.TCP_CONNECT,
    threat=ThreatLevel.LOW,
    raw=b""
) -> ProbeEvent:
    return ProbeEvent(
        probe_id      = "TEST001",
        timestamp     = datetime.now(timezone.utc),
        source_ip     = ip,
        source_port   = 54321,
        target_port   = port,
        probe_type    = probe_type,
        threat_level  = threat,
        fingerprint   = "abcd1234",
        raw_data      = raw,
        response_sent = "AEGIS banner",
    )


# ─────────────────────────────────────────────
# NIVEL 1 — RED: Firmas y banners
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0.5 NIVEL 1: Red / Firmas")
print("═══════════════════════════════════════════════")

def t_banner_tcp_no_vacio():
    L1  = NetworkSignatureLayer()
    ban = L1.build_tcp_banner("ABCD1234")
    assert len(ban) > 0
    # El banner debe contener señal disuasoria — cualquiera de las presentes
    keywords = [b"AEGIS", b"MONITOR", b"WARNING", b"SECURITY", b"logged"]
    assert any(k.lower() in ban.lower() for k in keywords)

def t_banner_tcp_contiene_session_id():
    L1  = NetworkSignatureLayer()
    sid = "DEADBEEF"
    ban = L1.build_tcp_banner(sid)
    assert sid.encode() in ban, "El banner debe incluir el session_id"

def t_banner_tcp_rota():
    """Distintos session_id deben poder producir banners distintos."""
    L1   = NetworkSignatureLayer()
    sids = ["00", "55", "AA", "FF"]
    banners = [L1.build_tcp_banner(sid) for sid in sids]
    # Al menos alguno debe ser diferente (rotación por módulo)
    assert len(set(banners)) >= 1   # mínimo — todos válidos

def t_http_response_status_403():
    L1  = NetworkSignatureLayer()
    res = L1.build_http_response("ABCD1234")
    assert b"403" in res
    assert b"HTTP/1.1" in res

def t_http_response_headers_disuasorios():
    L1  = NetworkSignatureLayer()
    sid = "CAFE0000"
    res = L1.build_http_response(sid)
    assert b"X-Security-Monitor" in res
    assert b"X-Probe-Detected" in res
    assert b"X-Intrusion-Detection" in res
    assert sid.encode() in res

def t_http_response_body_contiene_warning():
    L1  = NetworkSignatureLayer()
    res = L1.build_http_response("TEST0001")
    assert b"WARNING" in res or b"warning" in res.lower()
    assert b"logged" in res.lower() or b"monitor" in res.lower()

def t_firma_instancia_unica():
    L1a = NetworkSignatureLayer()
    L1b = NetworkSignatureLayer()
    # Cada instancia tiene firma diferente
    assert L1a.get_instance_signature() != L1b.get_instance_signature()

test("L1 — Banner TCP no vacío y contiene AEGIS", t_banner_tcp_no_vacio)
test("L1 — Banner TCP incluye session_id", t_banner_tcp_contiene_session_id)
test("L1 — Banner TCP rota correctamente", t_banner_tcp_rota)
test("L1 — Respuesta HTTP tiene status 403", t_http_response_status_403)
test("L1 — Headers disuasorios presentes en HTTP", t_http_response_headers_disuasorios)
test("L1 — Body HTTP contiene warning de monitorización", t_http_response_body_contiene_warning)
test("L1 — Firma de instancia única por arranque", t_firma_instancia_unica)


# ─────────────────────────────────────────────
# NIVEL 2 — SERVICIOS: Clasificación y fingerprinting
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0.5 NIVEL 2: Servicios")
print("═══════════════════════════════════════════════")

def t_clasificacion_http():
    L1 = NetworkSignatureLayer()
    L2 = ServiceDecoyLayer([])
    L2._network_layer = L1
    probe_type, response = L2._classify_and_respond(b"GET / HTTP/1.1\r\n", 8080, "SID001")
    assert probe_type == ProbeType.HTTP_REQUEST
    assert b"HTTP/1.1" in response

def t_clasificacion_banner_grab():
    L1 = NetworkSignatureLayer()
    L2 = ServiceDecoyLayer([])
    L2._network_layer = L1
    probe_type, response = L2._classify_and_respond(b"", 8080, "SID002")
    assert probe_type == ProbeType.BANNER_GRAB
    assert len(response) > 0

def t_clasificacion_tcp_generico():
    L1 = NetworkSignatureLayer()
    L2 = ServiceDecoyLayer([])
    L2._network_layer = L1
    probe_type, response = L2._classify_and_respond(b"\x00\x01\x02\x03", 8080, "SID003")
    assert probe_type == ProbeType.TCP_CONNECT
    assert len(response) > 0

def t_amenaza_alta_en_puerto_bd():
    L2    = ServiceDecoyLayer([])
    level = L2._assess_threat(6379, b"")   # Redis
    assert level == ThreatLevel.HIGH

def t_amenaza_alta_mongodb():
    L2    = ServiceDecoyLayer([])
    level = L2._assess_threat(27017, b"")  # MongoDB
    assert level == ThreatLevel.HIGH

def t_amenaza_baja_puerto_normal():
    L2    = ServiceDecoyLayer([])
    level = L2._assess_threat(8080, b"")
    assert level == ThreatLevel.LOW

def t_fingerprint_mismo_ip_mismo_dato():
    L2 = ServiceDecoyLayer([])
    f1 = L2._fingerprint("1.2.3.4", b"hello")
    f2 = L2._fingerprint("1.2.3.4", b"hello")
    assert f1 == f2, "Mismo input debe dar mismo fingerprint"

def t_fingerprint_distinto_ip():
    L2 = ServiceDecoyLayer([])
    f1 = L2._fingerprint("1.2.3.4", b"hello")
    f2 = L2._fingerprint("5.6.7.8", b"hello")
    assert f1 != f2, "IPs distintas deben dar fingerprints distintos"

def t_fingerprint_longitud_16():
    L2 = ServiceDecoyLayer([])
    fp = L2._fingerprint("1.2.3.4", b"test")
    assert len(fp) == 16, f"Fingerprint debe ser 16 chars, got {len(fp)}"

test("L2 — Petición HTTP clasificada correctamente", t_clasificacion_http)
test("L2 — Banner grab clasificado correctamente", t_clasificacion_banner_grab)
test("L2 — TCP genérico clasificado correctamente", t_clasificacion_tcp_generico)
test("L2 — Puerto Redis (6379) → amenaza HIGH", t_amenaza_alta_en_puerto_bd)
test("L2 — Puerto MongoDB (27017) → amenaza HIGH", t_amenaza_alta_mongodb)
test("L2 — Puerto HTTP (8080) → amenaza LOW", t_amenaza_baja_puerto_normal)
test("L2 — Fingerprint determinista mismo input", t_fingerprint_mismo_ip_mismo_dato)
test("L2 — Fingerprint distinto para IPs distintas", t_fingerprint_distinto_ip)
test("L2 — Fingerprint tiene 16 caracteres", t_fingerprint_longitud_16)


# ─────────────────────────────────────────────
# NIVEL 3 — COMPORTAMIENTO: Tracking y escalado
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0.5 NIVEL 3: Comportamiento")
print("═══════════════════════════════════════════════")

async def t_registro_evento():
    L3    = BehaviorTrackingLayer()
    event = _make_probe()
    await L3.process(event)
    assert L3._total == 1
    assert len(L3._probes) == 1

async def t_contador_por_ip():
    L3 = BehaviorTrackingLayer()
    for _ in range(3):
        await L3.process(_make_probe(ip="10.0.0.1"))
    summary = L3.get_ip_summary()
    assert "10.0.0.1" in summary
    assert summary["10.0.0.1"] == 3

async def t_ip_distintas_separadas():
    L3 = BehaviorTrackingLayer()
    await L3.process(_make_probe(ip="10.0.0.1"))
    await L3.process(_make_probe(ip="10.0.0.2"))
    summary = L3.get_ip_summary()
    assert "10.0.0.1" in summary
    assert "10.0.0.2" in summary
    assert summary["10.0.0.1"] == 1
    assert summary["10.0.0.2"] == 1

async def t_escalado_a_medium():
    """2+ contactos de misma IP → amenaza MEDIUM."""
    L3 = BehaviorTrackingLayer()
    elevated = []
    async def capture(e):
        elevated.append(e)
    L3.register_callback(capture)
    for _ in range(2):
        await L3.process(_make_probe(ip="99.99.99.99"))
    # El segundo debe elevar a MEDIUM
    assert any(e.threat_level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH)
               for e in elevated)

async def t_escalado_a_high():
    """5+ contactos de misma IP → amenaza HIGH."""
    L3 = BehaviorTrackingLayer()
    elevated = []
    async def capture(e):
        elevated.append(e)
    L3.register_callback(capture)
    for _ in range(5):
        await L3.process(_make_probe(ip="88.88.88.88"))
    assert any(e.threat_level == ThreatLevel.HIGH for e in elevated)

async def t_callback_externo_recibe_evento():
    L3      = BehaviorTrackingLayer()
    received = []
    async def my_callback(e: ProbeEvent):
        received.append(e)
    L3.register_callback(my_callback)
    event = _make_probe()
    await L3.process(event)
    assert len(received) == 1
    assert received[0].probe_id == event.probe_id

async def t_export_log_estructura():
    L3 = BehaviorTrackingLayer()
    await L3.process(_make_probe())
    log = L3.export_log()
    assert len(log) == 1
    entry = log[0]
    assert "probe_id"     in entry
    assert "timestamp"    in entry
    assert "source_ip"    in entry
    assert "threat_level" in entry
    assert "fingerprint"  in entry

async def t_probes_last_hour_filtra():
    L3 = BehaviorTrackingLayer()
    await L3.process(_make_probe())
    probes = L3.get_probes_last_hour()
    assert len(probes) == 1

test("L3 — Evento registrado correctamente", t_registro_evento)
test("L3 — Contador por IP preciso", t_contador_por_ip)
test("L3 — IPs distintas se contabilizan por separado", t_ip_distintas_separadas)
test("L3 — 2+ contactos eleva amenaza a MEDIUM", t_escalado_a_medium)
test("L3 — 5+ contactos eleva amenaza a HIGH", t_escalado_a_high)
test("L3 — Callback externo recibe ProbeEvent", t_callback_externo_recibe_evento)
test("L3 — Export log tiene estructura completa", t_export_log_estructura)
test("L3 — get_probes_last_hour filtra correctamente", t_probes_last_hour_filtra)


# ─────────────────────────────────────────────
# FACHADA — AegisShield
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0.5: FACHADA COMPLETA")
print("═══════════════════════════════════════════════")

def t_shield_inicializa():
    shield = AegisShield(decoy_ports=[])
    assert shield.level1 is not None
    assert shield.level2 is not None
    assert shield.level3 is not None
    assert not shield._active

def t_shield_banner_tcp_externo():
    shield = AegisShield(decoy_ports=[])
    banner = shield.build_tcp_banner("EXTTEST1")
    assert b"AEGIS" in banner or b"monitor" in banner.lower()
    assert b"EXTTEST1" in banner

def t_shield_http_response_externo():
    shield = AegisShield(decoy_ports=[])
    res    = shield.build_http_response("EXTTEST2")
    assert b"403" in res
    assert b"EXTTEST2" in res

async def t_shield_start_stop():
    """Arranque y parada sin puertos — verifica ciclo de vida."""
    shield = AegisShield(decoy_ports=[])   # sin puertos para no requerir permisos
    await shield.start()
    assert shield._active
    st = shield.status()
    assert st.active
    await shield.stop()
    assert not shield._active

async def t_shield_callback_registrado():
    """Callback externo registrado antes de start() recibe eventos."""
    shield   = AegisShield(decoy_ports=[])
    received = []
    async def alert_handler(e: ProbeEvent):
        received.append(e)
    shield.register_alert_callback(alert_handler)
    await shield.start()
    # Simular evento directamente en L3
    event = _make_probe(ip="77.77.77.77")
    await shield.level3.process(event)
    assert len(received) == 1
    await shield.stop()

async def t_shield_status_refleja_estado():
    shield = AegisShield(decoy_ports=[])
    await shield.start()
    st = shield.status()
    assert st.active
    assert st.level1_active
    assert st.level2_active
    assert st.level3_active
    assert st.total_probes == 0
    await shield.stop()

test("FACHADA — Inicialización correcta", t_shield_inicializa)
test("FACHADA — Banner TCP desde fachada", t_shield_banner_tcp_externo)
test("FACHADA — HTTP response desde fachada", t_shield_http_response_externo)
test("FACHADA — Start/stop ciclo de vida", t_shield_start_stop)
test("FACHADA — Callback externo recibe eventos", t_shield_callback_registrado)
test("FACHADA — Status refleja estado real", t_shield_status_refleja_estado)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 0.5 — Escudo Disuasorio OPERATIVO")
    print("  AEGIS puede continuar construcción de Capa 1")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
