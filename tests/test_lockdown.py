"""
AEGIS — Test de Capa 4: Cierre Atómico
========================================
Tests de atomicidad, simultaneidad, límites de tiempo y coordinación.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.lockdown import (
    AegisLockdown, LockdownResult, LockdownTrigger, LockdownStatus,
    TwinJumpOperation, SessionSealOperation,
    CredentialRotationOperation, SurfaceCloseOperation,
    ForensicSnapshotOperation,
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
# OPERACIÓN 1 — TWIN JUMP
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 4: Op1 Twin Jump")
print("═══════════════════════════════════════════════")

async def t_twin_jump_llama_callback():
    called = []
    async def cb(lockdown_id): called.append(lockdown_id)
    op = TwinJumpOperation()
    op.set_jump_callback(cb)
    await op.execute("TEST001")
    assert len(called) == 1

async def t_twin_jump_sin_callback_no_falla():
    op = TwinJumpOperation()
    ms = await op.execute("TEST001")
    assert ms >= 0

async def t_twin_jump_menos_100ms():
    called = []
    async def cb(lid): called.append(lid)
    op = TwinJumpOperation()
    op.set_jump_callback(cb)
    ms = await op.execute("TEST001")
    assert ms < 100, f"Twin jump tardó {ms:.1f}ms — supera 100ms"

test("TWIN JUMP — Callback activado", t_twin_jump_llama_callback)
test("TWIN JUMP — Sin callback no falla", t_twin_jump_sin_callback_no_falla)
test("TWIN JUMP — Tiempo < 100ms", t_twin_jump_menos_100ms)


# ─────────────────────────────────────────────
# OPERACIÓN 2 — SESIONES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 4: Op2 Sesiones")
print("═══════════════════════════════════════════════")

async def t_sesiones_selladas():
    op = SessionSealOperation()
    op.register_session("sess_001", {"user": "admin"})
    op.register_session("sess_002", {"user": "sysadmin"})
    ms, count = await op.execute("LOCK001")
    assert count == 2
    assert op.is_sealed("sess_001")
    assert op.is_sealed("sess_002")

async def t_sesiones_activas_vacias_tras_cierre():
    op = SessionSealOperation()
    op.register_session("sess_001", {"user": "admin"})
    assert op.active_count() == 1
    await op.execute("LOCK001")
    assert op.active_count() == 0

async def t_sesiones_sin_sesiones_no_falla():
    op = SessionSealOperation()
    ms, count = await op.execute("LOCK001")
    assert count == 0
    assert ms >= 0

async def t_sesiones_menos_100ms():
    op = SessionSealOperation()
    for i in range(100):
        op.register_session(f"sess_{i:03d}", {"user": f"user_{i}"})
    ms, count = await op.execute("LOCK001")
    assert count == 100
    assert ms < 100, f"Sellar 100 sesiones tardó {ms:.1f}ms"

test("SESIONES — Todas selladas correctamente", t_sesiones_selladas)
test("SESIONES — Activas vacías tras cierre", t_sesiones_activas_vacias_tras_cierre)
test("SESIONES — Sin sesiones no falla", t_sesiones_sin_sesiones_no_falla)
test("SESIONES — 100 sesiones < 100ms", t_sesiones_menos_100ms)


# ─────────────────────────────────────────────
# OPERACIÓN 3 — CREDENCIALES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 4: Op3 Credenciales")
print("═══════════════════════════════════════════════")

async def t_credenciales_rotadas():
    import hashlib
    op = CredentialRotationOperation()
    old_hash = hashlib.sha3_256(b"old_password").hexdigest()
    op.register_credential("db_password", old_hash)
    ms, count = await op.execute("LOCK001")
    assert count == 1
    assert op._credentials["db_password"] != old_hash

async def t_credenciales_log_generado():
    op = CredentialRotationOperation()
    op.register_credential("api_key", "hash_inicial")
    await op.execute("LOCK001")
    log = op.get_rotation_log()
    assert len(log) == 1
    assert "name" in log[0]
    assert "lockdown_id" in log[0]

async def t_credenciales_sin_creds_no_falla():
    op = CredentialRotationOperation()
    ms, count = await op.execute("LOCK001")
    assert count == 0

async def t_credenciales_menos_100ms():
    op = CredentialRotationOperation()
    for i in range(50):
        op.register_credential(f"cred_{i}", f"hash_{i}")
    ms, count = await op.execute("LOCK001")
    assert count == 50
    assert ms < 100, f"Rotar 50 credenciales tardó {ms:.1f}ms"

test("CREDENCIALES — Hash cambia tras rotación", t_credenciales_rotadas)
test("CREDENCIALES — Log de rotación generado", t_credenciales_log_generado)
test("CREDENCIALES — Sin credenciales no falla", t_credenciales_sin_creds_no_falla)
test("CREDENCIALES — 50 credenciales < 100ms", t_credenciales_menos_100ms)


# ─────────────────────────────────────────────
# OPERACIÓN 4 — SUPERFICIES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 4: Op4 Superficies")
print("═══════════════════════════════════════════════")

async def t_superficie_cerrada():
    op = SurfaceCloseOperation()
    op.register_surface("decoy_8080", "http_decoy")
    ms, count = await op.execute("LOCK001")
    assert count == 1
    assert op.is_closed("decoy_8080")

async def t_superficie_close_fn_llamada():
    called = []
    async def close_fn(): called.append(True)
    op = SurfaceCloseOperation()
    op.register_surface("api_endpoint", "rest_api", close_fn)
    await op.execute("LOCK001")
    assert len(called) == 1

async def t_superficie_callback_externo():
    called = []
    async def ext_cb(lockdown_id): called.append(lockdown_id)
    op = SurfaceCloseOperation()
    op.register_close_callback(ext_cb)
    await op.execute("LOCK001")
    assert len(called) == 1

async def t_superficie_multiples_simultaneous():
    """Múltiples superficies cerradas en paralelo — tiempo = max no suma."""
    delays  = []
    async def slow_close():
        await asyncio.sleep(0.01)   # 10ms cada una
        delays.append(True)

    op = SurfaceCloseOperation()
    for i in range(5):
        op.register_surface(f"surf_{i}", "decoy", slow_close)

    t0 = time.monotonic()
    ms, count = await op.execute("LOCK001")
    elapsed = (time.monotonic() - t0) * 1000

    assert count == 5
    assert len(delays) == 5
    # Simultáneas → debería ser ~10ms, no ~50ms
    assert elapsed < 50, f"5 superficies tardaron {elapsed:.1f}ms — deberían ser ~10ms en paralelo"

test("SUPERFICIE — Superficie marcada como cerrada", t_superficie_cerrada)
test("SUPERFICIE — close_fn ejecutada al cerrar", t_superficie_close_fn_llamada)
test("SUPERFICIE — Callback externo llamado", t_superficie_callback_externo)
test("SUPERFICIE — Múltiples cierres simultáneos (no suma)", t_superficie_multiples_simultaneous)


# ─────────────────────────────────────────────
# OPERACIÓN 5 — FORENSE
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 4: Op5 Forense")
print("═══════════════════════════════════════════════")

async def t_forense_snapshot_generado():
    op = ForensicSnapshotOperation()
    ms = await op.execute("LOCK001", {"threat": "intrusion"})
    snaps = op.get_snapshots()
    assert len(snaps) == 1
    assert snaps[0]["lockdown_id"] == "LOCK001"

async def t_forense_callback_recibe_snapshot():
    received = []
    async def cb(snap): received.append(snap)
    op = ForensicSnapshotOperation()
    op.register_forensic_callback(cb)
    await op.execute("LOCK001", {"context": "test"})
    assert len(received) == 1
    assert "lockdown_id" in received[0]
    assert "captured_at" in received[0]

async def t_forense_menos_100ms():
    op = ForensicSnapshotOperation()
    ms = await op.execute("LOCK001", {"data": "x" * 10000})
    assert ms < 100, f"Snapshot tardó {ms:.1f}ms"

test("FORENSE — Snapshot generado con contexto", t_forense_snapshot_generado)
test("FORENSE — Callback recibe snapshot completo", t_forense_callback_recibe_snapshot)
test("FORENSE — Snapshot < 100ms", t_forense_menos_100ms)


# ─────────────────────────────────────────────
# FACHADA — AegisLockdown
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 4: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_lockdown_inicializa():
    lk = AegisLockdown()
    assert lk.status == LockdownStatus.IDLE
    assert not lk.is_sealed()

async def t_lockdown_ejecuta_exitosamente():
    lk = AegisLockdown()
    result = await lk.execute(LockdownTrigger.DETECTION)
    assert result.success
    assert result.total_ms > 0

async def t_lockdown_sella_status():
    lk = AegisLockdown()
    await lk.execute(LockdownTrigger.DETECTION)
    assert lk.status == LockdownStatus.SEALED
    assert lk.is_sealed()

async def t_lockdown_tiempo_total_menos_3s():
    """El cierre completo debe completarse en menos de 3 segundos — regla invariable."""
    lk = AegisLockdown()
    lk.register_session("sess_001", {"user": "admin"})
    lk.register_credential("db_pass", "hash_001")
    lk.register_surface("decoy_8080", "http")

    t0 = time.monotonic()
    result = await lk.execute(LockdownTrigger.DETECTION)
    elapsed = time.monotonic() - t0

    assert elapsed < 3.0, f"Cierre tardó {elapsed:.2f}s — supera límite de 3s"
    assert result.success

async def t_lockdown_operaciones_dentro_de_100ms():
    """Cada operación individual debe estar por debajo de 100ms."""
    lk = AegisLockdown()
    result = await lk.execute(LockdownTrigger.DETECTION)
    assert result.within_limits(), (
        f"Operaciones fuera de límite — "
        f"twin={result.twin_jump_ms:.1f}ms "
        f"sessions={result.sessions_sealed_ms:.1f}ms "
        f"creds={result.credentials_rotated_ms:.1f}ms "
        f"surfaces={result.surfaces_closed_ms:.1f}ms "
        f"forensic={result.forensic_snapshot_ms:.1f}ms"
    )

async def t_lockdown_idempotente():
    """Activar dos veces no rompe nada — retorna último resultado."""
    lk     = AegisLockdown()
    result1 = await lk.execute(LockdownTrigger.DETECTION)
    result2 = await lk.execute(LockdownTrigger.DETECTION)   # debe ignorarse
    assert result1.lockdown_id == result2.lockdown_id
    assert len(lk._results) == 1

async def t_lockdown_reset_permite_nueva_activacion():
    lk = AegisLockdown()
    await lk.execute(LockdownTrigger.DETECTION)
    assert lk.is_sealed()
    await lk.reset()
    assert lk.status == LockdownStatus.IDLE
    result2 = await lk.execute(LockdownTrigger.MANUAL)
    assert result2.success

async def t_lockdown_callbacks_coordinados():
    """Twin jump + forense reciben el lockdown_id correcto."""
    lk       = AegisLockdown()
    jumps    = []
    forensic = []

    async def on_jump(lid):    jumps.append(lid)
    async def on_forensic(snap): forensic.append(snap)

    lk.set_twin_jump_callback(on_jump)
    lk.register_forensic_callback(on_forensic)

    result = await lk.execute(LockdownTrigger.DETECTION, context={"threat": "test"})

    assert len(jumps) == 1
    assert jumps[0] == result.lockdown_id
    assert len(forensic) == 1
    assert forensic[0]["lockdown_id"] == result.lockdown_id

async def t_lockdown_sesiones_y_credenciales():
    lk = AegisLockdown()
    lk.register_session("sess_001", {"user": "admin"})
    lk.register_session("sess_002", {"user": "sysadmin"})
    lk.register_credential("db_pass", "hash_001")

    result = await lk.execute(LockdownTrigger.DETECTION)

    assert result.sessions_invalidated  == 2
    assert result.credentials_rotated   == 1

async def t_lockdown_superficie_con_close_fn():
    lk     = AegisLockdown()
    closed = []
    async def close_fn(): closed.append(True)
    lk.register_surface("decoy_8080", "http_decoy", close_fn)

    result = await lk.execute(LockdownTrigger.DETECTION)

    assert result.surfaces_closed == 1
    assert len(closed) == 1

async def t_lockdown_log_exportable():
    lk = AegisLockdown()
    await lk.execute(LockdownTrigger.MANUAL, notes="test manual")
    log = lk.get_result_log()
    assert len(log) == 1
    entry = log[0]
    assert "lockdown_id"   in entry
    assert "trigger"       in entry
    assert "total_ms"      in entry
    assert "success"       in entry
    assert "triggered_at"  in entry

async def t_lockdown_atomico_tiempo_paralelo():
    """
    Cierre atómico: tiempo total ≈ operación más lenta, no suma de todas.
    Con 5 operaciones de 10ms cada una → debería ser ~10ms no ~50ms.
    """
    lk = AegisLockdown()

    # Registrar superficies con delay simulado de 10ms
    async def slow_close(): await asyncio.sleep(0.01)
    for i in range(3):
        lk.register_surface(f"surf_{i}", "decoy", slow_close)

    t0     = time.monotonic()
    result = await lk.execute(LockdownTrigger.DETECTION)
    elapsed = (time.monotonic() - t0) * 1000

    # Paralelo → ~10ms, no ~30ms
    assert elapsed < 80, f"Cierre con delays tardó {elapsed:.1f}ms — posible ejecución secuencial"
    assert result.success

test("FACHADA — Inicialización correcta", t_lockdown_inicializa)
test("FACHADA — Ejecución exitosa", t_lockdown_ejecuta_exitosamente)
test("FACHADA — Status SEALED tras cierre", t_lockdown_sella_status)
test("FACHADA — Tiempo total < 3 segundos (regla invariable)", t_lockdown_tiempo_total_menos_3s)
test("FACHADA — Cada operación < 100ms (límite absoluto)", t_lockdown_operaciones_dentro_de_100ms)
test("FACHADA — Idempotente: segunda activación ignorada", t_lockdown_idempotente)
test("FACHADA — Reset permite nueva activación", t_lockdown_reset_permite_nueva_activacion)
test("FACHADA — Twin + forense reciben lockdown_id correcto", t_lockdown_callbacks_coordinados)
test("FACHADA — Sesiones y credenciales procesadas", t_lockdown_sesiones_y_credenciales)
test("FACHADA — Superficie con close_fn ejecutada", t_lockdown_superficie_con_close_fn)
test("FACHADA — Log exportable con estructura completa", t_lockdown_log_exportable)
test("FACHADA — Cierre atómico: tiempo paralelo no suma", t_lockdown_atomico_tiempo_paralelo)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 4 — Cierre Atómico OPERATIVO")
    print("  AEGIS puede continuar construcción de Capa 5")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
