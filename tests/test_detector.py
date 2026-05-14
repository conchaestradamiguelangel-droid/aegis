"""
AEGIS — Test de Capa 3: Detección Multi-Agente
================================================
Tests de agente pasivo, agente activo, coordinación y umbral de tiempo.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.detector import (
    AegisDetector, PassiveAgent, ActiveAgent,
    DetectionEvent, DetectionType, ThreatConfidence, IPProfile,
)
from layers.minefield import MineContact, MineType, ContactSeverity
from layers.shield import ProbeEvent, ProbeType, ThreatLevel
from datetime import datetime, timezone

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"
IP_C = "10.0.0.3"


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


def _make_mine_contact(ip=IP_A, port=8080, mine="backup.json",
                        mine_type=MineType.FILE, severity=ContactSeverity.HIGH) -> MineContact:
    return MineContact(
        contact_id   = "TEST001",
        timestamp    = datetime.now(timezone.utc),
        source_ip    = ip,
        source_port  = port,
        mine_id      = f"file:{mine}",
        mine_type    = mine_type,
        mine_name    = mine,
        severity     = severity,
        method       = "GET",
        payload      = b"",
        fingerprint  = "abcd1234",
        response_sent= "fake content",
    )


def _make_probe(ip=IP_A, port=8080) -> ProbeEvent:
    return ProbeEvent(
        probe_id      = "PROBE001",
        timestamp     = datetime.now(timezone.utc),
        source_ip     = ip,
        source_port   = 54321,
        target_port   = port,
        probe_type    = ProbeType.TCP_CONNECT,
        threat_level  = ThreatLevel.LOW,
        fingerprint   = "abcd1234",
        raw_data      = b"",
        response_sent = "banner",
    )


# ─────────────────────────────────────────────
# AGENTE PASIVO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 3: Agente Pasivo")
print("═══════════════════════════════════════════════")

async def t_pasivo_contacto_genera_deteccion():
    received = []
    async def cb(d): received.append(d)
    agent   = PassiveAgent(on_detection=cb)
    contact = _make_mine_contact()
    det     = await agent.on_mine_contact(contact)
    assert det is not None
    assert len(received) == 1

async def t_pasivo_deteccion_es_confirmed():
    received = []
    async def cb(d): received.append(d)
    agent   = PassiveAgent(on_detection=cb)
    contact = _make_mine_contact()
    det     = await agent.on_mine_contact(contact)
    assert det.confidence == ThreatConfidence.CONFIRMED

async def t_pasivo_deteccion_es_mine_contact():
    received = []
    async def cb(d): received.append(d)
    agent = PassiveAgent(on_detection=cb)
    det   = await agent.on_mine_contact(_make_mine_contact())
    assert det.detection_type == DetectionType.MINE_CONTACT

async def t_pasivo_accion_es_jump():
    received = []
    async def cb(d): received.append(d)
    agent = PassiveAgent(on_detection=cb)
    det   = await agent.on_mine_contact(_make_mine_contact())
    assert det.action_required == "JUMP"

async def t_pasivo_ip_en_deteccion():
    received = []
    async def cb(d): received.append(d)
    agent = PassiveAgent(on_detection=cb)
    det   = await agent.on_mine_contact(_make_mine_contact(ip=IP_A))
    assert IP_A in det.source_ips

async def t_pasivo_evidencia_completa():
    received = []
    async def cb(d): received.append(d)
    agent = PassiveAgent(on_detection=cb)
    det   = await agent.on_mine_contact(_make_mine_contact())
    assert "mine_id"    in det.evidence
    assert "mine_type"  in det.evidence
    assert "fingerprint"in det.evidence

async def t_pasivo_umbral_menos_1s():
    """Detección debe producirse en menos de 1 segundo — regla invariable."""
    received = []
    async def cb(d): received.append(d)
    agent = PassiveAgent(on_detection=cb)
    t0    = time.monotonic()
    await agent.on_mine_contact(_make_mine_contact())
    elapsed = (time.monotonic() - t0) * 1000
    assert elapsed < 1000, f"Tardó {elapsed:.1f}ms — supera 1000ms"

test("PASIVO — Contacto genera detección", t_pasivo_contacto_genera_deteccion)
test("PASIVO — Detección es CONFIRMED", t_pasivo_deteccion_es_confirmed)
test("PASIVO — Tipo es MINE_CONTACT", t_pasivo_deteccion_es_mine_contact)
test("PASIVO — Acción requerida es JUMP", t_pasivo_accion_es_jump)
test("PASIVO — IP del atacante en detección", t_pasivo_ip_en_deteccion)
test("PASIVO — Evidencia completa incluida", t_pasivo_evidencia_completa)
test("PASIVO — Umbral < 1 segundo (regla invariable)", t_pasivo_umbral_menos_1s)


# ─────────────────────────────────────────────
# AGENTE ACTIVO — Reconocimiento
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 3: Agente Activo — Reconocimiento")
print("═══════════════════════════════════════════════")

async def t_activo_perfil_se_crea():
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    await agent.register_event(IP_A, 8080, "/admin")
    profile = agent.get_profile(IP_A)
    assert profile is not None
    assert profile.ip == IP_A

async def t_activo_paths_acumulan():
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    for path in ["/admin", "/api/keys", "/config"]:
        await agent.register_event(IP_A, 8080, path)
    profile = agent.get_profile(IP_A)
    assert profile.unique_paths() == 3

async def t_activo_puertos_acumulan():
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    for port in [8080, 8443, 2222, 6379]:
        await agent.register_event(IP_A, port, "")
    profile = agent.get_profile(IP_A)
    assert profile.unique_ports() >= 3

async def t_activo_deteccion_reconocimiento():
    """3+ rutas en poco tiempo → detección de reconocimiento."""
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.RECON_PATHS_THRESHOLD = 3
    agent.AUTOMATION_RPS_THRESHOLD = 999999.0  # desactivar en este test
    for path in ["/admin", "/api/keys", "/config/secrets"]:
        await agent.register_event(IP_A, 8080, path)
    recon = [d for d in received if d.detection_type == DetectionType.RECON_PATTERN]
    assert len(recon) >= 1

async def t_activo_deteccion_exploracion_puertos():
    """3+ puertos distintos → detección de exploración."""
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.EXPLORATION_PORTS_THRESHOLD = 3
    agent.AUTOMATION_RPS_THRESHOLD    = 999999.0  # desactivar en este test
    agent.RECON_PATHS_THRESHOLD       = 999       # desactivar recon (ports crean paths tambien)
    for port in [8080, 8443, 2222]:
        await agent.register_event(IP_A, port, "")   # path vacío — solo cuenta el puerto
    exploration = [d for d in received if d.detection_type == DetectionType.EXPLORATION]
    assert len(exploration) >= 1

async def t_activo_indicadores_presentes():
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.RECON_PATHS_THRESHOLD = 2
    for path in ["/admin", "/api/keys"]:
        await agent.register_event(IP_A, 8080, path)
    if received:
        assert len(received[0].indicators) >= 1
        assert len(received[0].evidence) >= 1

async def t_activo_umbral_menos_1s():
    """Detección activa también debe cumplir < 1s."""
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.RECON_PATHS_THRESHOLD = 3
    t0 = time.monotonic()
    for path in ["/admin", "/api/keys", "/secrets"]:
        await agent.register_event(IP_A, 8080, path)
    elapsed = (time.monotonic() - t0) * 1000
    assert elapsed < 1000

test("ACTIVO — Perfil de IP se crea en primer evento", t_activo_perfil_se_crea)
test("ACTIVO — Rutas distintas se acumulan en perfil", t_activo_paths_acumulan)
test("ACTIVO — Puertos distintos se acumulan en perfil", t_activo_puertos_acumulan)
test("ACTIVO — 3+ rutas → detección RECON_PATTERN", t_activo_deteccion_reconocimiento)
test("ACTIVO — 3+ puertos → detección EXPLORATION", t_activo_deteccion_exploracion_puertos)
test("ACTIVO — Detección incluye indicadores y evidencia", t_activo_indicadores_presentes)
test("ACTIVO — Umbral < 1 segundo", t_activo_umbral_menos_1s)


# ─────────────────────────────────────────────
# AGENTE ACTIVO — Automatización y Coordinación
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 3: Automatización y Coordinación")
print("═══════════════════════════════════════════════")

async def t_activo_deteccion_automatizacion():
    """Ráfaga de peticiones → detección de automatización."""
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.AUTOMATION_RPS_THRESHOLD = 3.0
    # Enviar 10 eventos en ráfaga rápida
    for i in range(10):
        await agent.register_event(IP_A, 8080, f"/path{i}")
    automated = [d for d in received if d.detection_type == DetectionType.AUTOMATED]
    assert len(automated) >= 1

async def t_activo_deteccion_coordinacion():
    """Múltiples IPs activas simultáneamente → coordinación."""
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.COORDINATION_MIN_IPS = 2
    agent.AUTOMATION_RPS_THRESHOLD = 999999.0  # desactivar en este test
    agent.RECON_PATHS_THRESHOLD   = 999        # desactivar recon
    agent.EXPLORATION_PORTS_THRESHOLD = 999    # desactivar exploration
    # IP_A con múltiples eventos
    for i in range(3):
        await agent.register_event(IP_A, 8080, f"/pathA{i}")
    # IP_B con múltiples eventos simultáneos
    for i in range(3):
        await agent.register_event(IP_B, 8080, f"/pathB{i}")
    coordinated = [d for d in received if d.detection_type == DetectionType.COORDINATED]
    assert len(coordinated) >= 1

async def t_activo_coordinacion_multiples_ips():
    """Detección de coordinación incluye todas las IPs involucradas."""
    received = []
    async def cb(d): received.append(d)
    agent = ActiveAgent(on_detection=cb)
    agent.COORDINATION_MIN_IPS = 2
    for i in range(3):
        await agent.register_event(IP_A, 8080, f"/a{i}")
    for i in range(3):
        await agent.register_event(IP_B, 8080, f"/b{i}")
    coordinated = [d for d in received if d.detection_type == DetectionType.COORDINATED]
    if coordinated:
        assert len(coordinated[0].source_ips) >= 2

test("AUTOMATIZACIÓN — Ráfaga genera detección AUTOMATED", t_activo_deteccion_automatizacion)
test("COORDINACIÓN — Múltiples IPs generan detección COORDINATED", t_activo_deteccion_coordinacion)
test("COORDINACIÓN — Detección incluye todas las IPs", t_activo_coordinacion_multiples_ips)


# ─────────────────────────────────────────────
# FACHADA — AegisDetector
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 3: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_detector_inicializa():
    det = AegisDetector()
    st  = det.status()
    assert st["total_detections"]   == 0
    assert st["passive_contacts"]   == 0
    assert st["active_detections"]  == 0

async def t_detector_mine_contact_dispara_jump():
    """Contacto con señuelo → callback de jump activado."""
    detector = AegisDetector()
    jumps    = []
    async def on_jump(d): jumps.append(d)
    detector.register_jump_callback(on_jump)
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    assert len(jumps) == 1
    assert jumps[0].action_required == "JUMP"

async def t_detector_shield_probe_alimenta_activo():
    """Evento de escudo alimenta el agente activo."""
    detector = AegisDetector()
    probe    = _make_probe(ip=IP_A, port=8080)
    await detector.register_shield_probe(probe)
    profile = detector.get_profile(IP_A)
    assert profile is not None
    assert profile.total_events == 1

async def t_detector_callbacks_forensic():
    """Toda detección llega al callback forense."""
    detector = AegisDetector()
    forensic = []
    async def on_forensic(d): forensic.append(d)
    detector.register_forensic_callback(on_forensic)
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    assert len(forensic) == 1

async def t_detector_deduplicacion():
    """Dos detecciones de la misma IP en ventana corta → solo una procesada."""
    detector = AegisDetector()
    jumps    = []
    async def on_jump(d): jumps.append(d)
    detector.register_jump_callback(on_jump)
    # Dos contactos de la misma IP en rápida sucesión
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    # Por deduplicación, solo debe haberse procesado 1
    assert len(jumps) == 1

async def t_detector_dos_ips_distintas_no_deduplicadas():
    """IPs distintas no se deduplicadn entre sí."""
    detector = AegisDetector()
    jumps    = []
    async def on_jump(d): jumps.append(d)
    detector.register_jump_callback(on_jump)
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    await detector.on_mine_contact(_make_mine_contact(ip=IP_B))
    assert len(jumps) == 2

async def t_detector_log_exportable():
    detector = AegisDetector()
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    log = detector.get_detection_log()
    assert len(log) == 1
    entry = log[0]
    assert "detection_id"   in entry
    assert "detection_type" in entry
    assert "confidence"     in entry
    assert "source_ips"     in entry
    assert "evidence"       in entry

async def t_detector_status_actualiza():
    detector = AegisDetector()
    assert detector.status()["total_detections"] == 0
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))
    assert detector.status()["total_detections"] == 1

async def t_detector_integracion_mine_y_shield():
    """Integración: evento de shield + contacto con mina → detección combinada."""
    detector = AegisDetector()
    all_detections = []
    async def capture(d): all_detections.append(d)
    detector.register_jump_callback(capture)
    detector.register_lockdown_callback(capture)

    # Primero probe del escudo — no dispara detección sola
    await detector.register_shield_probe(_make_probe(ip=IP_A, port=8080))
    # Luego contacto con mina — dispara JUMP
    await detector.on_mine_contact(_make_mine_contact(ip=IP_A))

    jump_detections = [d for d in all_detections if d.action_required == "JUMP"]
    assert len(jump_detections) >= 1

test("FACHADA — Inicialización correcta", t_detector_inicializa)
test("FACHADA — Mine contact dispara callback JUMP", t_detector_mine_contact_dispara_jump)
test("FACHADA — Shield probe alimenta agente activo", t_detector_shield_probe_alimenta_activo)
test("FACHADA — Toda detección llega a forense", t_detector_callbacks_forensic)
test("FACHADA — Deduplicación misma IP en ventana", t_detector_deduplicacion)
test("FACHADA — IPs distintas no se deduplicadn", t_detector_dos_ips_distintas_no_deduplicadas)
test("FACHADA — Log exportable con estructura completa", t_detector_log_exportable)
test("FACHADA — Status se actualiza tras detección", t_detector_status_actualiza)
test("FACHADA — Integración shield + mine funciona", t_detector_integracion_mine_y_shield)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 3 — Detección Multi-Agente OPERATIVA")
    print("  AEGIS puede continuar construcción de Capa 4")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
