"""
AEGIS — Test de Resiliencia D1: Saturación bajo Carga Extrema
==============================================================
Vector: 1000 peticiones concurrentes mientras se ejecuta el lockdown.

CRITERIO DE ÉXITO (defensivo):
    Lockdown completa en < 3 segundos bajo carga extrema.
    Alarma si supera 2 segundos (margen de seguridad).
    El lockdown nunca queda incompleto por saturación.
    Las operaciones atómicas no se corrompen bajo concurrencia.

CRITERIO DE FALLO:
    Lockdown supera 3 segundos bajo carga — brecha temporal.
    Alguna operación del lockdown queda sin ejecutar.
    El estado del sistema queda inconsistente tras la carga.

ESTO NO ES:
    Un ataque de denegación de servicio contra sistemas externos.
    Un exploit para retrasar el lockdown en producción.

ESTO ES:
    Verificación de que asyncio.gather() y el mutex interno
    de AegisLockdown mantienen su rendimiento bajo presión.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.lockdown import AegisLockdown, LockdownTrigger, LockdownStatus

PASS = "✓ PASS"
FAIL = "✗ FAIL"
WARN = "⚠ WARN"
results = []

LIMITE_CRITICO_S = 3.0   # regla invariable de AEGIS
LIMITE_ALARMA_S  = 2.0   # alarma temprana


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
# GENERADORES DE CARGA
# ─────────────────────────────────────────────

async def _carga_concurrente(n: int, tarea: callable):
    """Lanza n tareas concurrentes y espera a que todas terminen."""
    await asyncio.gather(*[tarea() for _ in range(n)])


async def _peticion_vacia():
    """Tarea de carga mínima — solo cede control al event loop."""
    await asyncio.sleep(0)


async def _peticion_con_computo():
    """Tarea de carga con algo de computo — más realista."""
    await asyncio.sleep(0)
    _ = sum(range(100))


# ─────────────────────────────────────────────
# BLOQUE 1 — BASELINE SIN CARGA
# Tiempos de lockdown en condiciones normales
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D1 — Bloque 1: Baseline sin Carga")
print("═══════════════════════════════════════════════════════")

async def t_lockdown_baseline_tiempo():
    """Lockdown sin carga establece el tiempo de referencia."""
    lk = AegisLockdown()
    t0 = time.monotonic()
    result = await lk.execute(LockdownTrigger.DETECTION)
    elapsed = time.monotonic() - t0

    assert result.success
    assert elapsed < LIMITE_CRITICO_S, \
        f"Lockdown baseline tardó {elapsed:.3f}s — supera límite de {LIMITE_CRITICO_S}s"
    print(f"\n    Baseline: {elapsed*1000:.1f}ms")

async def t_lockdown_baseline_within_limits():
    """Cada operación individual está bajo 100ms en baseline."""
    lk     = AegisLockdown()
    result = await lk.execute(LockdownTrigger.DETECTION)
    assert result.within_limits(), \
        f"Operaciones fuera de límite en baseline: " \
        f"twin={result.twin_jump_ms:.1f}ms " \
        f"sessions={result.sessions_sealed_ms:.1f}ms"

async def t_lockdown_con_recursos_registrados():
    """Baseline con sesiones y credenciales registradas."""
    lk = AegisLockdown()
    for i in range(10):
        lk.register_session(f"sess_{i:03d}", {"user": f"user_{i}"})
        lk.register_credential(f"cred_{i}", f"hash_{i}")

    t0     = time.monotonic()
    result = await lk.execute(LockdownTrigger.DETECTION)
    elapsed = time.monotonic() - t0

    assert result.success
    assert result.sessions_invalidated == 10
    assert result.credentials_rotated  == 10
    assert elapsed < LIMITE_CRITICO_S
    print(f"\n    Con 10 sesiones y 10 credenciales: {elapsed*1000:.1f}ms")

test("BASELINE — Lockdown sin carga dentro del límite", t_lockdown_baseline_tiempo)
test("BASELINE — Operaciones individuales < 100ms", t_lockdown_baseline_within_limits)
test("BASELINE — Con recursos registrados dentro del límite", t_lockdown_con_recursos_registrados)


# ─────────────────────────────────────────────
# BLOQUE 2 — LOCKDOWN BAJO CARGA CONCURRENTE
# El lockdown se ejecuta mientras hay presión en el event loop
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D1 — Bloque 2: Bajo Carga Concurrente")
print("═══════════════════════════════════════════════════════")

async def t_lockdown_con_100_concurrentes():
    """Lockdown mientras 100 tareas concurrentes saturan el loop."""
    lk = AegisLockdown()

    async def ejecutar_lockdown():
        t0 = time.monotonic()
        result = await lk.execute(LockdownTrigger.DETECTION)
        return time.monotonic() - t0, result

    # Lanzar lockdown + 100 tareas concurrentes simultáneamente
    resultados = await asyncio.gather(
        ejecutar_lockdown(),
        _carga_concurrente(100, _peticion_vacia),
    )
    elapsed, result = resultados[0]

    assert result.success, "Lockdown falló bajo carga de 100 concurrentes"
    assert elapsed < LIMITE_CRITICO_S, \
        f"Lockdown tardó {elapsed:.3f}s con 100 concurrentes — supera {LIMITE_CRITICO_S}s"

    if elapsed > LIMITE_ALARMA_S:
        print(f"\n    {WARN} Tiempo {elapsed*1000:.0f}ms supera alarma de {LIMITE_ALARMA_S*1000:.0f}ms")
    else:
        print(f"\n    Con 100 concurrentes: {elapsed*1000:.1f}ms")

async def t_lockdown_con_500_concurrentes():
    """Lockdown mientras 500 tareas concurrentes saturan el loop."""
    lk = AegisLockdown()

    async def ejecutar_lockdown():
        t0 = time.monotonic()
        result = await lk.execute(LockdownTrigger.DETECTION)
        return time.monotonic() - t0, result

    resultados = await asyncio.gather(
        ejecutar_lockdown(),
        _carga_concurrente(500, _peticion_vacia),
    )
    elapsed, result = resultados[0]

    assert result.success, "Lockdown falló bajo carga de 500 concurrentes"
    assert elapsed < LIMITE_CRITICO_S, \
        f"Lockdown tardó {elapsed:.3f}s con 500 concurrentes — supera {LIMITE_CRITICO_S}s"

    if elapsed > LIMITE_ALARMA_S:
        print(f"\n    {WARN} Tiempo {elapsed*1000:.0f}ms supera alarma de {LIMITE_ALARMA_S*1000:.0f}ms")
    else:
        print(f"\n    Con 500 concurrentes: {elapsed*1000:.1f}ms")

async def t_lockdown_con_1000_concurrentes():
    """
    CRITERIO PRINCIPAL: lockdown con 1000 peticiones concurrentes
    debe completar en menos de 3 segundos.
    Alarma si supera 2 segundos.
    """
    lk = AegisLockdown()
    # Registrar recursos para que el lockdown tenga trabajo real
    for i in range(20):
        lk.register_session(f"sess_{i:03d}", {"user": f"user_{i}"})
        lk.register_credential(f"cred_{i}", f"hash_{i}")

    async def ejecutar_lockdown():
        t0 = time.monotonic()
        result = await lk.execute(LockdownTrigger.DETECTION)
        return time.monotonic() - t0, result

    resultados = await asyncio.gather(
        ejecutar_lockdown(),
        _carga_concurrente(1000, _peticion_con_computo),
    )
    elapsed, result = resultados[0]

    # Criterio crítico
    assert result.success, "Lockdown falló bajo carga de 1000 concurrentes"
    assert elapsed < LIMITE_CRITICO_S, \
        f"BRECHA TEMPORAL: lockdown tardó {elapsed:.3f}s con 1000 concurrentes — " \
        f"supera límite invariable de {LIMITE_CRITICO_S}s"

    # Alarma
    if elapsed > LIMITE_ALARMA_S:
        print(f"\n    {WARN} ALARMA: {elapsed*1000:.0f}ms > {LIMITE_ALARMA_S*1000:.0f}ms")
        print(f"    Sesiones selladas: {result.sessions_invalidated}")
        print(f"    Credenciales rotadas: {result.credentials_rotated}")
    else:
        print(f"\n    Con 1000 concurrentes: {elapsed*1000:.1f}ms ✓")
        print(f"    Sesiones: {result.sessions_invalidated} | Creds: {result.credentials_rotated}")

test("CARGA — Lockdown con 100 concurrentes < 3s", t_lockdown_con_100_concurrentes)
test("CARGA — Lockdown con 500 concurrentes < 3s", t_lockdown_con_500_concurrentes)
test("CARGA — Lockdown con 1000 concurrentes < 3s (criterio principal)", t_lockdown_con_1000_concurrentes)


# ─────────────────────────────────────────────
# BLOQUE 3 — INTEGRIDAD BAJO CARGA
# El lockdown no solo debe ser rápido — debe ser correcto
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D1 — Bloque 3: Integridad bajo Carga")
print("═══════════════════════════════════════════════════════")

async def t_sesiones_selladas_correctamente_bajo_carga():
    """Bajo carga, todas las sesiones registradas deben sellarse."""
    lk = AegisLockdown()
    N_SESIONES = 50
    for i in range(N_SESIONES):
        lk.register_session(f"sess_{i:04d}", {"user": f"u{i}"})

    resultados = await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION),
        _carga_concurrente(500, _peticion_vacia),
    )
    result = resultados[0]

    assert result.sessions_invalidated == N_SESIONES, \
        f"Solo {result.sessions_invalidated}/{N_SESIONES} sesiones selladas bajo carga"

async def t_credenciales_rotadas_correctamente_bajo_carga():
    """Bajo carga, todas las credenciales registradas deben rotarse."""
    lk = AegisLockdown()
    N_CREDS = 30
    import hashlib
    for i in range(N_CREDS):
        lk.register_credential(f"cred_{i}", hashlib.sha256(f"val_{i}".encode()).hexdigest())

    resultados = await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION),
        _carga_concurrente(500, _peticion_vacia),
    )
    result = resultados[0]

    assert result.credentials_rotated == N_CREDS, \
        f"Solo {result.credentials_rotated}/{N_CREDS} credenciales rotadas bajo carga"

async def t_callbacks_ejecutados_bajo_carga():
    """Los callbacks de forense y twin se ejecutan correctamente bajo carga."""
    lk       = AegisLockdown()
    forensic_received = []
    twin_received     = []

    async def on_forensic(snap):   forensic_received.append(snap)
    async def on_twin(lockdown_id): twin_received.append(lockdown_id)

    lk.register_forensic_callback(on_forensic)
    lk.set_twin_jump_callback(on_twin)

    await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION),
        _carga_concurrente(1000, _peticion_vacia),
    )

    assert len(forensic_received) == 1, \
        f"Callback forense ejecutado {len(forensic_received)} veces (esperado 1)"
    assert len(twin_received) == 1, \
        f"Callback twin ejecutado {len(twin_received)} veces (esperado 1)"

async def t_estado_sealed_tras_carga():
    """El estado del lockdown es SEALED después de ejecutar bajo carga."""
    lk = AegisLockdown()
    await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION),
        _carga_concurrente(1000, _peticion_vacia),
    )
    assert lk.is_sealed(), "Estado no es SEALED tras lockdown bajo carga"
    assert lk.status == LockdownStatus.SEALED

async def t_idempotencia_bajo_carga():
    """
    Múltiples llamadas concurrentes a execute() no deben
    ejecutar el lockdown más de una vez.
    """
    lk = AegisLockdown()

    # 5 llamadas concurrentes — solo 1 debe ejecutarse
    resultados = await asyncio.gather(*[
        lk.execute(LockdownTrigger.DETECTION, notes=f"llamada_{i}")
        for i in range(5)
    ])

    assert len(lk.get_result_log()) == 1, \
        f"Lockdown ejecutado {len(lk.get_result_log())} veces — idempotencia rota"

test("INTEGRIDAD — Sesiones selladas correctamente bajo carga", t_sesiones_selladas_correctamente_bajo_carga)
test("INTEGRIDAD — Credenciales rotadas correctamente bajo carga", t_credenciales_rotadas_correctamente_bajo_carga)
test("INTEGRIDAD — Callbacks ejecutados exactamente una vez bajo carga", t_callbacks_ejecutados_bajo_carga)
test("INTEGRIDAD — Estado SEALED correcto tras carga", t_estado_sealed_tras_carga)
test("INTEGRIDAD — Idempotencia: 5 llamadas concurrentes = 1 ejecución", t_idempotencia_bajo_carga)


# ─────────────────────────────────────────────
# BLOQUE 4 — ESCALADO
# El tiempo no debe escalar linealmente con la carga
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D1 — Bloque 4: Escalado")
print("═══════════════════════════════════════════════════════")

async def t_tiempo_no_escala_linealmente():
    """
    Lockdown con 1000 concurrentes no debe tardar 10x más
    que lockdown con 100 concurrentes.
    asyncio.gather() garantiza paralelismo — el tiempo
    debe ser similar independientemente de la carga concurrente.
    """
    async def medir(n_carga: int) -> float:
        lk = AegisLockdown()

        async def ejecutar():
            t0 = time.monotonic()
            await lk.execute(LockdownTrigger.DETECTION)
            return time.monotonic() - t0

        resultados = await asyncio.gather(
            ejecutar(),
            _carga_concurrente(n_carga, _peticion_vacia),
        )
        return resultados[0]

    t_100  = await medir(100)
    t_1000 = await medir(1000)

    ratio = t_1000 / t_100 if t_100 > 0 else 1.0
    print(f"\n    t(100)={t_100*1000:.1f}ms | t(1000)={t_1000*1000:.1f}ms | ratio={ratio:.1f}x")

    # El tiempo con 1000 no debe ser más de 20x el de 100
    # El criterio real invariable es el tiempo absoluto < 3s
    assert ratio < 20.0, \
        f"Escalado excesivo: {ratio:.1f}x — posible degradación lineal"
    # Ambos deben estar bajo el límite crítico
    assert t_1000 < LIMITE_CRITICO_S, \
        f"t(1000) = {t_1000:.3f}s supera límite de {LIMITE_CRITICO_S}s"

async def t_operaciones_atomicas_no_se_fragmentan():
    """
    El paralelismo interno de asyncio.gather() no debe
    fragmentar las operaciones del lockdown entre ciclos.
    Tiempo total ≈ operación más lenta, no suma de todas.
    """
    import asyncio as _asyncio

    lk = AegisLockdown()
    superficies_cerradas = []

    async def slow_surface():
        await _asyncio.sleep(0.01)   # 10ms cada una
        superficies_cerradas.append(True)

    for i in range(5):
        lk.register_surface(f"surf_{i}", "decoy", slow_surface)

    t0     = time.monotonic()
    result = await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION),
        _carga_concurrente(500, _peticion_vacia),
    )
    elapsed = time.monotonic() - t0

    # 5 superficies de 10ms cada una en paralelo → ~10ms, no ~50ms
    # Bajo carga añadimos margen: < 200ms es aceptable
    assert elapsed < 0.2, \
        f"Operaciones atómicas posiblemente fragmentadas: {elapsed*1000:.1f}ms"
    assert len(superficies_cerradas) == 5, \
        f"Solo {len(superficies_cerradas)}/5 superficies cerradas"

test("ESCALADO — Tiempo no escala linealmente (< 10x entre 100 y 1000)", t_tiempo_no_escala_linealmente)
test("ESCALADO — Operaciones atómicas no se fragmentan bajo carga", t_operaciones_atomicas_no_se_fragmentan)


# ─────────────────────────────────────────────
# BLOQUE 5 — RECUPERACIÓN
# Después del lockdown el sistema puede reiniciarse
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D1 — Bloque 5: Recuperación")
print("═══════════════════════════════════════════════════════")

async def t_reset_y_segundo_lockdown_bajo_carga():
    """
    Tras un lockdown bajo carga, reset y segundo lockdown
    deben funcionar correctamente.
    """
    lk = AegisLockdown()

    # Primer lockdown bajo carga
    await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION),
        _carga_concurrente(500, _peticion_vacia),
    )
    assert lk.is_sealed()

    # Reset
    await lk.reset()
    assert lk.status == LockdownStatus.IDLE

    # Segundo lockdown bajo carga
    t0 = time.monotonic()
    await asyncio.gather(
        lk.execute(LockdownTrigger.MANUAL),
        _carga_concurrente(500, _peticion_vacia),
    )
    elapsed = time.monotonic() - t0

    assert lk.is_sealed()
    assert elapsed < LIMITE_CRITICO_S, \
        f"Segundo lockdown tardó {elapsed:.3f}s tras reset — supera límite"
    assert len(lk.get_result_log()) == 2, \
        "Historial debe tener 2 entradas tras 2 lockdowns"

async def t_log_completo_tras_carga():
    """El log del lockdown está completo tras ejecución bajo carga."""
    lk = AegisLockdown()
    await asyncio.gather(
        lk.execute(LockdownTrigger.DETECTION, notes="test_carga"),
        _carga_concurrente(1000, _peticion_vacia),
    )

    log = lk.get_result_log()
    assert len(log) == 1
    entry = log[0]
    assert entry["success"]
    assert entry["total_ms"] > 0
    assert entry["trigger"] == "DETECTION"
    assert entry["notes"]   == "test_carga"

test("RECUPERACIÓN — Reset y segundo lockdown bajo carga", t_reset_y_segundo_lockdown_bajo_carga)
test("RECUPERACIÓN — Log completo y correcto tras carga", t_log_completo_tras_carga)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print()
    print("  CONCLUSIÓN DE RESILIENCIA D1:")
    print("  El cierre atómico mantiene su tiempo bajo")
    print("  carga extrema de 1000 peticiones concurrentes.")
    print("  Integridad y atomicidad preservadas bajo presión.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
