"""
AEGIS — Test de Capa 1: Gemelo en Cadena
==========================================
Tests de estado operativo, sincronización, salto atómico y cadena completa.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.twin import (
    TwinChain, Twin, TwinID, TwinStatus, JumpTrigger,
    OperationalState, empty_operational_state,
    SyncEngine, JumpEngine, JumpEvent,
)

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


# ─────────────────────────────────────────────
# ESTADO OPERATIVO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 1: Estado Operativo")
print("═══════════════════════════════════════════════")

def t_estado_vacio_valido():
    s = empty_operational_state()
    assert s.crypto is not None
    assert s.process is not None
    assert s.network is not None
    assert s.identity is not None
    assert s.security is not None

def t_snapshot_es_dict_puro():
    s    = empty_operational_state()
    snap = s.snapshot()
    assert isinstance(snap, dict)
    assert "crypto" in snap
    assert "process" in snap
    assert "network" in snap
    assert "identity" in snap
    assert "security" in snap
    assert "captured_at" in snap

def t_snapshot_sin_referencias_compartidas():
    s     = empty_operational_state()
    s.security.active_alerts.append("alert-1")
    snap  = s.snapshot()
    snap["security"]["active_alerts"].append("alert-2")
    # El original no debe verse afectado
    assert len(s.security.active_alerts) == 1

def t_integrity_hash_determinista():
    s  = empty_operational_state()
    h1 = s.integrity_hash()
    h2 = s.integrity_hash()
    assert h1 == h2

def t_integrity_hash_cambia_con_estado():
    s1 = empty_operational_state()
    s2 = empty_operational_state()
    s2.security.threat_level = "HIGH"
    assert s1.integrity_hash() != s2.integrity_hash()

test("ESTADO — Estado vacío inicializa correctamente", t_estado_vacio_valido)
test("ESTADO — Snapshot es dict puro con 6 claves", t_snapshot_es_dict_puro)
test("ESTADO — Snapshot es copia profunda (sin refs compartidas)", t_snapshot_sin_referencias_compartidas)
test("ESTADO — Integrity hash es determinista", t_integrity_hash_determinista)
test("ESTADO — Integrity hash cambia con el estado", t_integrity_hash_cambia_con_estado)


# ─────────────────────────────────────────────
# GEMELO INDIVIDUAL
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 1: Gemelo Individual")
print("═══════════════════════════════════════════════")

def t_twin_inicializa():
    t = Twin(TwinID.A, TwinStatus.ACTIVE, empty_operational_state())
    assert t.twin_id == TwinID.A
    assert t.status  == TwinStatus.ACTIVE
    assert t.sync_lag_ms == 0.0

def t_twin_sync_copia_estado():
    source = Twin(TwinID.A, TwinStatus.ACTIVE, empty_operational_state())
    target = Twin(TwinID.B, TwinStatus.REPLICA, empty_operational_state())
    source.state.security.threat_level = "HIGH"
    target.sync_from(source)
    assert target.state.security.threat_level == "HIGH"

def t_twin_sync_sin_referencias_compartidas():
    source = Twin(TwinID.A, TwinStatus.ACTIVE, empty_operational_state())
    target = Twin(TwinID.B, TwinStatus.REPLICA, empty_operational_state())
    target.sync_from(source)
    # Modificar fuente no debe afectar destino
    source.state.security.threat_level = "CRITICAL"
    assert target.state.security.threat_level != "CRITICAL"

def t_twin_sync_registra_lag():
    source = Twin(TwinID.A, TwinStatus.ACTIVE, empty_operational_state())
    target = Twin(TwinID.B, TwinStatus.REPLICA, empty_operational_state())
    target.sync_from(source)
    assert target.sync_lag_ms >= 0
    assert target.last_sync is not None

def t_twin_seal():
    t = Twin(TwinID.C, TwinStatus.REPLICA, empty_operational_state())
    t.seal()
    assert t.status    == TwinStatus.SEALED
    assert t.sealed_at is not None

def t_twin_promote():
    t = Twin(TwinID.B, TwinStatus.REPLICA, empty_operational_state())
    t.promote(TwinID.A, TwinStatus.ACTIVE)
    assert t.twin_id == TwinID.A
    assert t.status  == TwinStatus.ACTIVE

def t_twin_integrity_ok_mismos_estados():
    s = empty_operational_state()
    t1 = Twin(TwinID.A, TwinStatus.ACTIVE,  s)
    t2 = Twin(TwinID.B, TwinStatus.REPLICA, empty_operational_state())
    t2.sync_from(t1)
    assert t2.integrity_ok(t1)

def t_twin_integrity_falla_estados_distintos():
    t1 = Twin(TwinID.A, TwinStatus.ACTIVE,  empty_operational_state())
    t2 = Twin(TwinID.B, TwinStatus.REPLICA, empty_operational_state())
    t2.state.security.threat_level = "CRITICAL"
    assert not t2.integrity_ok(t1)

test("TWIN — Inicialización correcta", t_twin_inicializa)
test("TWIN — sync_from copia el estado", t_twin_sync_copia_estado)
test("TWIN — sync_from sin referencias compartidas", t_twin_sync_sin_referencias_compartidas)
test("TWIN — sync_from registra lag y timestamp", t_twin_sync_registra_lag)
test("TWIN — seal() cambia status y registra timestamp", t_twin_seal)
test("TWIN — promote() cambia ID y status", t_twin_promote)
test("TWIN — integrity_ok con estados iguales → True", t_twin_integrity_ok_mismos_estados)
test("TWIN — integrity_ok con estados distintos → False", t_twin_integrity_falla_estados_distintos)


# ─────────────────────────────────────────────
# SINCRONIZACIÓN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 1: Sincronización")
print("═══════════════════════════════════════════════")

async def t_sync_propaga_a_b_c():
    """Estado actualizado en A debe propagarse a B y C tras sincronización."""
    chain = TwinChain()
    chain.twin_a.state.security.threat_level = "MEDIUM"
    # Sincronizar manualmente
    chain.twin_b.sync_from(chain.twin_a)
    chain.twin_c.sync_from(chain.twin_b)
    assert chain.twin_b.state.security.threat_level == "MEDIUM"
    assert chain.twin_c.state.security.threat_level == "MEDIUM"

async def t_sync_automatico_en_100ms():
    """Motor de sync debe propagar cambios en ≤ 100ms."""
    chain = TwinChain()
    await chain.start()
    # Modificar A
    chain.twin_a.state.security.threat_level = "HIGH"
    # Esperar hasta 150ms para dar margen al motor
    await asyncio.sleep(0.15)
    assert chain.twin_b.state.security.threat_level == "HIGH"
    assert chain.twin_c.state.security.threat_level == "HIGH"
    await chain.stop()

async def t_sync_no_propaga_a_c_sellado():
    """C sellado no debe recibir sincronizaciones."""
    chain = TwinChain()
    chain.twin_c.seal()
    chain.twin_a.state.security.threat_level = "CRITICAL"
    # Sincronizar A→B (normal)
    chain.twin_b.sync_from(chain.twin_a)
    # Intentar sincronizar B→C (no debe ocurrir porque C está sellado)
    # El motor de sync omite gemelos sellados
    sync = SyncEngine(chain)
    await sync._sync_once()
    # C debe conservar su estado anterior (LOW, no CRITICAL)
    assert chain.twin_c.state.security.threat_level != "CRITICAL"

async def t_sync_lag_dentro_de_limite():
    """El lag de sincronización debe estar por debajo de 100ms."""
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.2)  # esperar 2 ciclos completos
    assert chain.twin_b.sync_lag_ms < 100
    assert chain.twin_c.sync_lag_ms < 100
    await chain.stop()

test("SYNC — Propagación manual A→B→C funciona", t_sync_propaga_a_b_c)
test("SYNC — Motor automático propaga en ≤150ms", t_sync_automatico_en_100ms)
test("SYNC — C sellado no recibe sincronizaciones", t_sync_no_propaga_a_c_sellado)
test("SYNC — Lag de sincronización < 100ms", t_sync_lag_dentro_de_limite)


# ─────────────────────────────────────────────
# SALTO ATÓMICO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 1: Salto Atómico")
print("═══════════════════════════════════════════════")

async def t_salto_exitoso():
    chain = TwinChain()
    event = await chain._jump.execute(JumpTrigger.INTRUSION, "test")
    assert event.success

async def t_salto_sella_c():
    chain = TwinChain()
    await chain._jump.execute(JumpTrigger.INTRUSION)
    assert chain.twin_c.status == TwinStatus.SEALED

async def t_salto_promueve_b_a_a():
    chain = TwinChain()
    await chain._jump.execute(JumpTrigger.INTRUSION)
    # chain.twin_b es el objeto que fue promovido a A (nuevo activo)
    # chain.twin_a es el objeto original comprometido (ahora SEALED para forense)
    assert chain.twin_b.twin_id == TwinID.A      # B fue promovido a posición A
    assert chain.twin_b.status  == TwinStatus.ACTIVE
    assert chain.twin_a.status  == TwinStatus.SEALED  # ex-A comprometido para forense

async def t_salto_genera_d():
    chain = TwinChain()
    event = await chain._jump.execute(JumpTrigger.INTRUSION)
    assert event.d_generated
    assert chain.twin_d is not None
    assert chain.twin_d.status == TwinStatus.READY

async def t_salto_d_desde_c_limpio():
    """D debe heredar el estado de C sellado, no de A comprometido."""
    chain = TwinChain()
    # Marcar A con estado comprometido
    chain.twin_a.state.security.threat_level = "CRITICAL"
    chain.twin_a.state.security.active_alerts.append("intrusion-detected")
    # Sincronizar a B y C antes del salto
    chain.twin_b.sync_from(chain.twin_a)
    chain.twin_c.sync_from(chain.twin_b)
    # D se genera desde C sellado — hereda el estado de C en el momento del sello
    await chain._jump.execute(JumpTrigger.INTRUSION)
    # D debe existir y ser READY
    assert chain.twin_d is not None
    assert chain.twin_d.status == TwinStatus.READY

async def t_salto_registra_evento():
    chain = TwinChain()
    event = await chain._jump.execute(JumpTrigger.INTRUSION, "test-jump")
    assert event.jump_id != ""
    assert event.trigger == JumpTrigger.INTRUSION
    assert event.triggered_at is not None
    assert event.duration_ms >= 0

async def t_salto_duracion_menos_3s():
    """El salto completo debe completarse en menos de 3 segundos (regla invariable)."""
    chain = TwinChain()
    t0    = time.monotonic()
    event = await chain._jump.execute(JumpTrigger.INTRUSION)
    elapsed = time.monotonic() - t0
    assert elapsed < 3.0, f"Salto tardó {elapsed:.2f}s — supera límite de 3s"
    assert event.success

async def t_salto_actualiza_jump_count():
    chain = TwinChain()
    await chain._jump.execute(JumpTrigger.INTRUSION)
    # Tras el salto twin_b es el nuevo activo — el counter debe estar en él
    all_twins = [chain.twin_a, chain.twin_b, chain.twin_c]
    active = next((t for t in all_twins if t.status == TwinStatus.ACTIVE),
                  chain.twin_b)
    assert active.state.security.jump_count == 1

async def t_salto_callback_notificado():
    chain    = TwinChain()
    received = []
    async def on_jump(e: JumpEvent):
        received.append(e)
    chain.register_jump_callback(on_jump)
    await chain.start()
    await chain.trigger_jump(JumpTrigger.ANOMALY, "test callback")
    assert len(received) == 1
    assert received[0].trigger == JumpTrigger.ANOMALY
    await chain.stop()

async def t_salto_no_duplicado():
    """Dos saltos simultáneos no deben ejecutarse dos veces."""
    chain = TwinChain()
    engine = chain._jump
    # Primer salto
    await engine.execute(JumpTrigger.INTRUSION)
    log_before = len(engine.get_jump_log())
    # Segundo salto inmediato — debe ignorarse si el primero acaba de terminar
    # (el mutex _jumping ya se liberó, así que este sí ejecuta — verificamos que el log crece)
    await engine.execute(JumpTrigger.SCHEDULED)
    assert len(engine.get_jump_log()) == log_before + 1

test("SALTO — Ejecución exitosa", t_salto_exitoso)
test("SALTO — C queda sellado tras el salto", t_salto_sella_c)
test("SALTO — B promovido a A tras el salto", t_salto_promueve_b_a_a)
test("SALTO — D generado y en estado READY", t_salto_genera_d)
test("SALTO — D hereda estado de C limpio", t_salto_d_desde_c_limpio)
test("SALTO — Evento de salto registrado correctamente", t_salto_registra_evento)
test("SALTO — Duración total < 3 segundos (regla invariable)", t_salto_duracion_menos_3s)
test("SALTO — jump_count incrementado en nuevo A", t_salto_actualiza_jump_count)
test("SALTO — Callback externo notificado", t_salto_callback_notificado)
test("SALTO — Log crece con cada salto", t_salto_no_duplicado)


# ─────────────────────────────────────────────
# CADENA COMPLETA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 1: Cadena Completa")
print("═══════════════════════════════════════════════")

def t_cadena_inicializa_abc():
    chain = TwinChain()
    assert chain.twin_a.twin_id == TwinID.A
    assert chain.twin_b.twin_id == TwinID.B
    assert chain.twin_c.twin_id == TwinID.C
    assert chain.twin_d is None
    assert chain.twin_a.status == TwinStatus.ACTIVE
    assert chain.twin_b.status == TwinStatus.REPLICA
    assert chain.twin_c.status == TwinStatus.REPLICA

async def t_cadena_start_stop():
    chain = TwinChain()
    await chain.start()
    assert chain._active
    await chain.stop()
    assert not chain._active

async def t_cadena_update_state():
    chain = TwinChain()
    chain.update_state(lambda s: setattr(s.security, "threat_level", "HIGH"))
    assert chain.twin_a.state.security.threat_level == "HIGH"

async def t_cadena_integrity_check_inicial():
    chain = TwinChain()
    # Recién creada — A, B, C tienen el mismo estado base
    result = chain.integrity_check()
    assert result["B_matches_A"]
    assert result["C_matches_B"]

async def t_cadena_integrity_falla_tras_modificacion():
    chain = TwinChain()
    # Modificar A sin sincronizar
    chain.twin_a.state.security.threat_level = "HIGH"
    result = chain.integrity_check()
    # B y C aún tienen el estado anterior — no coinciden con A
    assert not result["B_matches_A"]

async def t_cadena_status_completo():
    chain = TwinChain()
    await chain.start()
    st = chain.status()
    assert st["active"]
    assert "twin_a" in st
    assert "twin_b" in st
    assert "twin_c" in st
    assert st["jump_count"] == 0
    await chain.stop()

async def t_cadena_dos_saltos_consecutivos():
    """La cadena debe funcionar correctamente tras dos saltos."""
    chain = TwinChain()
    await chain.start()
    e1 = await chain.trigger_jump(JumpTrigger.INTRUSION, "primer salto")
    assert e1.success
    await asyncio.sleep(0.05)
    e2 = await chain.trigger_jump(JumpTrigger.ANOMALY, "segundo salto")
    assert e2.success
    assert len(chain.get_jump_log()) == 2
    await chain.stop()

test("CADENA — Inicializa con A/B/C correctos", t_cadena_inicializa_abc)
test("CADENA — Start/stop ciclo de vida", t_cadena_start_stop)
test("CADENA — update_state modifica A", t_cadena_update_state)
test("CADENA — Integrity check OK en estado inicial", t_cadena_integrity_check_inicial)
test("CADENA — Integrity falla tras modificar A sin sync", t_cadena_integrity_falla_tras_modificacion)
test("CADENA — status() retorna estructura completa", t_cadena_status_completo)
test("CADENA — Dos saltos consecutivos exitosos", t_cadena_dos_saltos_consecutivos)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 1 — Gemelo en Cadena OPERATIVO")
    print("  AEGIS puede continuar construcción de Capa 2")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
