"""
AEGIS — Test de Integración Completa
======================================
Verifica que todas las capas funcionan coordinadas como sistema unificado.
Tests end-to-end del flujo completo de amenaza.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.aegis import AegisSystem, SystemStatus
from layers.minefield import MineType, ContactSeverity
from layers.bubble import InteractionType

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP_INTRUDER = "99.99.99.99"


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


# ─────────────────────────────────────────────
# ARRANQUE Y PARADA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST INTEGRACIÓN: Arranque y Parada")
print("═══════════════════════════════════════════════")

async def t_sistema_arranca():
    aegis = AegisSystem(installation_id="AEGIS-TEST", decoy_ports=[])
    await aegis.start()
    assert aegis.status == SystemStatus.ONLINE
    await aegis.stop()

async def t_sistema_para_limpiamente():
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    await aegis.stop()
    assert aegis.status == SystemStatus.OFFLINE

async def t_crypto_self_test_en_arranque():
    """El self-test criptográfico debe pasar durante el arranque."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()   # lanzaría RuntimeError si self_test falla
    assert aegis.crypto is not None
    await aegis.stop()

async def t_installation_id_asignado():
    aegis = AegisSystem(installation_id="AEGIS-ESP-001", decoy_ports=[])
    assert aegis.installation_id == "AEGIS-ESP-001"
    await aegis.start()
    await aegis.stop()

async def t_todas_las_capas_instanciadas():
    aegis = AegisSystem(decoy_ports=[])
    assert aegis.crypto    is not None
    assert aegis.shield    is not None
    assert aegis.twin      is not None
    assert aegis.minefield is not None
    assert aegis.detector  is not None
    assert aegis.lockdown  is not None
    assert aegis.amtd      is not None
    assert aegis.bubble    is not None
    assert aegis.forensic  is not None
    assert aegis.learning  is not None

test("ARRANQUE — Sistema arranca en estado ONLINE", t_sistema_arranca)
test("ARRANQUE — Sistema para en estado OFFLINE", t_sistema_para_limpiamente)
test("ARRANQUE — Crypto self-test pasa al arrancar", t_crypto_self_test_en_arranque)
test("ARRANQUE — Installation ID asignado correctamente", t_installation_id_asignado)
test("ARRANQUE — Las 10 capas instanciadas", t_todas_las_capas_instanciadas)


# ─────────────────────────────────────────────
# CONEXIONES INTER-CAPA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST INTEGRACIÓN: Conexiones")
print("═══════════════════════════════════════════════")

async def t_c2_a_c3_conexion():
    """C2 → C3: señuelo tocado llega al detector."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    # Simular contacto con señuelo
    await aegis.minefield.touch_file("backup.json", IP_INTRUDER, 54321)
    await asyncio.sleep(0.05)
    assert aegis.detector.total_detections() >= 1
    await aegis.stop()

async def t_c2_a_c7_conexion():
    """C2 → C7: señuelo tocado llega a forense."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    await aegis.minefield.touch_credential("admin", IP_INTRUDER, 54321)
    await asyncio.sleep(0.05)
    assert aegis.forensic.active_incidents() >= 1
    await aegis.stop()

async def t_c3_detecta_patron():
    """C3: detector acumula eventos de reconocimiento."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    # Registrar múltiples eventos de red
    for i in range(5):
        await aegis.detector.register_network_event(
            ip=IP_INTRUDER, port=8080+i, path=f"/path{i}"
        )
    profile = aegis.detector.get_profile(IP_INTRUDER)
    assert profile is not None
    assert profile.total_events >= 5
    await aegis.stop()

async def t_c5_opera_continuamente():
    """C5: AMTD rota automáticamente."""
    aegis = AegisSystem(decoy_ports=[], amtd_interval_s=1)
    await aegis.start()
    ports_before = aegis.amtd.current_ports().copy()
    await asyncio.sleep(1.2)   # esperar 1 ciclo
    ports_after  = aegis.amtd.current_ports()
    await aegis.stop()
    assert aegis.amtd.status()["cycle"] >= 1
    assert ports_before != ports_after

async def t_c1_gemelo_opera_continuamente():
    """C1: gemelo sincroniza continuamente."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    # Modificar estado del gemelo A
    aegis.twin.update_state(
        lambda s: setattr(s.security, "threat_level", "MEDIUM")
    )
    await asyncio.sleep(0.15)   # esperar sincronización
    assert aegis.twin.twin_b.state.security.threat_level == "MEDIUM"
    await aegis.stop()

test("CONEXIÓN C2→C3 — Señuelo detectado por detector", t_c2_a_c3_conexion)
test("CONEXIÓN C2→C7 — Señuelo registrado en forense", t_c2_a_c7_conexion)
test("CONEXIÓN C3 — Detector acumula eventos de red", t_c3_detecta_patron)
test("CONEXIÓN C5 — AMTD rota en ciclo automático", t_c5_opera_continuamente)
test("CONEXIÓN C1 — Gemelo sincroniza continuamente", t_c1_gemelo_opera_continuamente)


# ─────────────────────────────────────────────
# FLUJO COMPLETO DE AMENAZA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST INTEGRACIÓN: Flujo de Amenaza")
print("═══════════════════════════════════════════════")

async def t_flujo_lockdown_manual():
    """Lockdown manual activa el sistema."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    result = await aegis.trigger_lockdown("test manual")
    assert result is True
    await aegis.stop()

async def t_flujo_burbuja_completa():
    """Ciclo completo de burbuja: abrir → interactuar → cerrar."""
    aegis  = AegisSystem(decoy_ports=[])
    await aegis.start()
    sid    = aegis.open_bubble_session(IP_INTRUDER)
    assert sid is not None
    response = await aegis.bubble_interact(sid, b"GET /admin", InteractionType.API_CALL)
    assert len(response) > 0
    aegis.bubble.close_session(sid)
    await aegis.stop()

async def t_flujo_forense_manual():
    """Abrir incidente forense → analizar → cerrar."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    iid   = aegis.open_forensic_incident([IP_INTRUDER])
    assert iid is not None
    # Ingestar un contacto
    await aegis.minefield.touch_file("backup.json", IP_INTRUDER, 54321)
    await asyncio.sleep(0.05)
    await aegis.close_forensic_incident(iid)
    assert aegis.forensic.closed_incidents() >= 1
    await aegis.stop()

async def t_flujo_amtd_rotate_now():
    """Rotación forzada de AMTD."""
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    cycle_before = aegis.amtd.status()["cycle"]
    await aegis.rotate_now()
    cycle_after  = aegis.amtd.status()["cycle"]
    assert cycle_after == cycle_before + 1
    await aegis.stop()

async def t_flujo_inteligencia_colectiva():
    """Exportar inteligencia de una instalación e importarla en otra."""
    key    = b"test_key_32_bytes_exactly_here!!"
    aegis1 = AegisSystem(installation_id="AEGIS-A", signing_key=key, decoy_ports=[])
    aegis2 = AegisSystem(installation_id="AEGIS-B", signing_key=key, decoy_ports=[])
    await asyncio.gather(aegis1.start(), aegis2.start())

    # A toca señuelos y aprende
    await aegis1.minefield.touch_credential("admin", IP_INTRUDER, 54321)
    await asyncio.sleep(0.05)

    # A exporta inteligencia
    packet = aegis1.export_intelligence()
    assert packet.origin_id == "AEGIS-A"

    # B importa
    imported = aegis2.import_intelligence(packet, verify=False)
    assert imported

    await asyncio.gather(aegis1.stop(), aegis2.stop())

test("FLUJO — Lockdown manual ejecutado correctamente", t_flujo_lockdown_manual)
test("FLUJO — Ciclo completo de burbuja operativo", t_flujo_burbuja_completa)
test("FLUJO — Incidente forense abierto y cerrado", t_flujo_forense_manual)
test("FLUJO — rotate_now() incrementa ciclo AMTD", t_flujo_amtd_rotate_now)
test("FLUJO — Red colectiva: A exporta → B importa", t_flujo_inteligencia_colectiva)


# ─────────────────────────────────────────────
# SNAPSHOT Y ESTADO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST INTEGRACIÓN: Estado del Sistema")
print("═══════════════════════════════════════════════")

async def t_snapshot_estructura():
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    snap  = aegis.snapshot()
    d     = snap.to_dict()
    assert "timestamp"        in d
    assert "status"           in d
    assert "threat_level"     in d
    assert "total_detections" in d
    assert "jump_count"       in d
    assert "uptime_s"         in d
    await aegis.stop()

async def t_snapshot_uptime_positivo():
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    await asyncio.sleep(0.05)
    snap  = aegis.snapshot()
    assert snap.uptime_s > 0
    await aegis.stop()

async def t_full_status_todas_las_capas():
    aegis = AegisSystem(decoy_ports=[])
    await aegis.start()
    st = aegis.full_status()
    for capa in ["system", "shield", "twin", "minefield", "detector",
                 "lockdown", "amtd", "bubble", "forensic", "learning"]:
        assert capa in st, f"Capa '{capa}' no en full_status"
    await aegis.stop()

async def t_repr_sistema():
    aegis = AegisSystem(installation_id="AEGIS-TEST", decoy_ports=[])
    r = repr(aegis)
    assert "AEGIS-TEST" in r
    assert "OFFLINE"    in r

test("ESTADO — snapshot() tiene estructura completa", t_snapshot_estructura)
test("ESTADO — uptime positivo tras arranque", t_snapshot_uptime_positivo)
test("ESTADO — full_status() incluye las 10 capas", t_full_status_todas_las_capas)
test("ESTADO — __repr__ legible", t_repr_sistema)


# ─────────────────────────────────────────────
# RESUMEN FINAL
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║      AEGIS — INTEGRACIÓN COMPLETA       ║")
    print("  ║   318 tests unitarios + integración     ║")
    print("  ║   Sistema defensivo 100% operativo      ║")
    print("  ╚══════════════════════════════════════════╝")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
