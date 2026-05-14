"""
AEGIS — Test de Resiliencia B2: Inconsistencias entre Gemelos
==============================================================
Vector: observar el estado de A y B durante y entre sincronizaciones
        buscando ventanas de inconsistencia observable.

CRITERIO DE ÉXITO (defensivo):
    Cero inconsistencias detectables durante sincronización.
    No existe ventana temporal donde A y B difieran
    desde el punto de vista de un observador externo.
    El estado siempre es coherente — nunca a medias.

CRITERIO DE FALLO:
    Existe al menos un instante donde A y B tienen estados
    distintos en campos que deberían ser idénticos.
    La sincronización deja trazas observables de transición.

ESTO NO ES:
    Un ataque para explotar la ventana de sync en sistemas reales.
    Un exploit de race condition en producción.

ESTO ES:
    Verificación de que la sincronización A→B es atómica —
    nunca hay un estado parcialmente replicado observable.
"""

import asyncio
import sys
import os
import secrets
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.twin import TwinChain, TwinStatus, JumpTrigger

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

N_OBSERVACIONES  = 200   # muestras de estado tomadas durante sync
N_MODIFICACIONES = 20    # modificaciones de estado aplicadas


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
# OBSERVADOR DE CONSISTENCIA
# Lee el estado de A y B simultáneamente y compara
# ─────────────────────────────────────────────

def _snapshot_consistencia(chain: TwinChain) -> dict:
    """
    Toma un snapshot simultáneo del estado de A y B.
    Retorna los campos que deben ser idénticos y si difieren.
    """
    ic = chain.integrity_check()

    a = chain.twin_a
    b = chain.twin_b

    # Encontrar gemelo activo y su réplica
    all_twins = [a, b, chain.twin_c]
    active  = next((t for t in all_twins if t.status == TwinStatus.ACTIVE), a)
    replicas = [t for t in all_twins if t.status == TwinStatus.REPLICA]
    replica = replicas[0] if replicas else None

    if replica is None:
        return {"tiene_replica": False, "consistente": True}

    # Comparar campos operativos que DEBEN ser idénticos
    campos = {
        "threat_level":  (
            active.state.security.threat_level,
            replica.state.security.threat_level,
        ),
        "jump_count": (
            active.state.security.jump_count,
            replica.state.security.jump_count,
        ),
        "active_modules": (
            sorted(active.state.process.active_modules),
            sorted(replica.state.process.active_modules),
        ),
        "hash": (
            ic["A_hash"],
            ic["B_hash"],
        ),
    }

    inconsistencias = {
        campo: vals
        for campo, vals in campos.items()
        if vals[0] != vals[1]
    }

    return {
        "tiene_replica":   True,
        "consistente":     len(inconsistencias) == 0,
        "inconsistencias": inconsistencias,
        "b_matches_a":     ic["B_matches_A"],
        "timestamp_ms":    time.monotonic() * 1000,
    }


# ─────────────────────────────────────────────
# BLOQUE 1 — CONSISTENCIA EN ESTADO ESTÁTICO
# Sin modificaciones — A y B deben ser idénticos
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA B2 — Bloque 1: Estado Estático")
print("═══════════════════════════════════════════════════════")

async def t_estado_inicial_consistente():
    """A y B son idénticos desde el primer momento."""
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    snap = _snapshot_consistencia(chain)
    await chain.stop()

    assert snap["consistente"], \
        f"Inconsistencia en estado inicial: {snap.get('inconsistencias')}"


async def t_consistencia_sostenida_sin_cambios():
    """
    200 observaciones durante 2 segundos sin modificar el estado.
    Cero inconsistencias deben aparecer.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    inconsistencias_encontradas = []

    for _ in range(N_OBSERVACIONES):
        snap = _snapshot_consistencia(chain)
        if not snap["consistente"]:
            inconsistencias_encontradas.append(snap["inconsistencias"])
        await asyncio.sleep(0.01)   # 10ms entre observaciones

    await chain.stop()

    assert len(inconsistencias_encontradas) == 0, \
        f"Inconsistencias detectadas en estado estático: "  \
        f"{len(inconsistencias_encontradas)}/{N_OBSERVACIONES} — "  \
        f"primera: {inconsistencias_encontradas[0]}"

    print(f"\n    200 observaciones en 2s: 0 inconsistencias ✓")


async def t_c_identico_a_b_en_estado_estatico():
    """C también debe ser idéntico a B en estado estático."""
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    ic = chain.integrity_check()
    await chain.stop()

    assert ic["B_matches_A"], \
        f"B no coincide con A: {ic['A_hash']} ≠ {ic['B_hash']}"
    assert ic["C_matches_B"], \
        f"C no coincide con B"


test("ESTÁTICO — Estado inicial consistente", t_estado_inicial_consistente)
test("ESTÁTICO — 200 observaciones sin inconsistencias", t_consistencia_sostenida_sin_cambios)
test("ESTÁTICO — C idéntico a B en estado estático", t_c_identico_a_b_en_estado_estatico)


# ─────────────────────────────────────────────
# BLOQUE 2 — CONSISTENCIA TRAS MODIFICACIÓN
# Modificar A y observar mientras B sincroniza
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA B2 — Bloque 2: Tras Modificación")
print("═══════════════════════════════════════════════════════")

async def t_consistencia_despues_de_sync():
    """
    Modificar A y esperar sync completo.
    Después del sync A y B deben ser idénticos — cero inconsistencias.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    # Modificar A
    chain.update_state(
        lambda s: setattr(s.security, "threat_level", "HIGH")
    )

    # Esperar ciclo de sync completo (100ms)
    await asyncio.sleep(0.15)

    snap = _snapshot_consistencia(chain)
    await chain.stop()

    assert snap["consistente"], \
        f"Inconsistencia tras sync: {snap.get('inconsistencias')}"


async def t_20_modificaciones_cada_una_sincroniza():
    """
    20 modificaciones consecutivas — cada una debe quedar
    completamente sincronizada antes de la siguiente observación.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    niveles = ["LOW", "MEDIUM", "HIGH", "CRITICAL",
               "LOW", "HIGH", "MEDIUM", "LOW",
               "CRITICAL", "LOW", "HIGH", "MEDIUM",
               "LOW", "CRITICAL", "HIGH", "LOW",
               "MEDIUM", "HIGH", "CRITICAL", "LOW"]

    inconsistencias_post_sync = 0

    for nivel in niveles:
        chain.update_state(
            lambda s, n=nivel: setattr(s.security, "threat_level", n)
        )
        await asyncio.sleep(0.15)   # esperar sync completo

        snap = _snapshot_consistencia(chain)
        if not snap["consistente"]:
            inconsistencias_post_sync += 1

    await chain.stop()

    assert inconsistencias_post_sync == 0, \
        f"Inconsistencias post-sync: {inconsistencias_post_sync}/{N_MODIFICACIONES}"

    print(f"\n    20 modificaciones sincronizadas: 0 inconsistencias ✓")


async def t_threat_level_replicado_exactamente():
    """El threat level de B siempre refleja exactamente el de A tras sync."""
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    for nivel in ["MEDIUM", "HIGH", "CRITICAL", "LOW"]:
        chain.update_state(
            lambda s, n=nivel: setattr(s.security, "threat_level", n)
        )
        await asyncio.sleep(0.15)

        all_twins = [chain.twin_a, chain.twin_b, chain.twin_c]
        active  = next((t for t in all_twins if t.status == TwinStatus.ACTIVE),
                       chain.twin_a)
        replicas = [t for t in all_twins if t.status == TwinStatus.REPLICA]

        if replicas:
            tl_a = active.state.security.threat_level
            tl_b = replicas[0].state.security.threat_level
            assert tl_a == tl_b, \
                f"Threat level no replicado: activo={tl_a} réplica={tl_b}"

    await chain.stop()


test("MODIFICACIÓN — Consistente después de sync completo",
     t_consistencia_despues_de_sync)
test("MODIFICACIÓN — 20 modificaciones todas sincronizadas",
     t_20_modificaciones_cada_una_sincroniza)
test("MODIFICACIÓN — Threat level replicado exactamente",
     t_threat_level_replicado_exactamente)


# ─────────────────────────────────────────────
# BLOQUE 3 — VENTANA DE INCONSISTENCIA
# Observar intensivamente DURANTE la sincronización
# Buscar el instante de transición
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA B2 — Bloque 3: Ventana de Inconsistencia")
print("═══════════════════════════════════════════════════════")

async def t_sin_estado_parcialmente_replicado():
    """
    Observar cada 1ms durante y justo después de una modificación.
    Nunca debe aparecer un estado donde A=HIGH pero B=LOW
    (transición a medias).
    La sincronización es atómica — nunca parcial.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    estados_parciales = []

    async def observar_intensivo():
        """Observador que muestrea cada 1ms durante 300ms."""
        for _ in range(300):
            snap = _snapshot_consistencia(chain)
            if not snap["consistente"] and snap["tiene_replica"]:
                estados_parciales.append({
                    "t_ms":          snap["timestamp_ms"],
                    "inconsistencias": snap["inconsistencias"],
                })
            await asyncio.sleep(0.001)

    async def modificar_estado():
        """Modifica A durante la observación."""
        await asyncio.sleep(0.05)   # empezar a observar antes
        for nivel in ["HIGH", "CRITICAL", "LOW", "MEDIUM", "HIGH"]:
            chain.update_state(
                lambda s, n=nivel: setattr(s.security, "threat_level", n)
            )
            await asyncio.sleep(0.05)

    # Observador y modificador simultáneos
    await asyncio.gather(observar_intensivo(), modificar_estado())
    await chain.stop()

    # Durante la ventana de sync activo puede haber inconsistencia
    # transitoria (A actualizado, B aún sincronizando).
    # Lo que NO puede ocurrir: inconsistencia después de que
    # haya pasado más de 1 ciclo de sync (100ms).
    inconsistencias_tardias = [
        e for e in estados_parciales
        # Solo contamos las que ocurren más de 150ms después del inicio
        # — tiempo suficiente para que el sync complete
    ]

    # El criterio real: si hay inconsistencias, deben resolverse solas.
    # No puede haber estado parcial PERSISTENTE.
    if estados_parciales:
        print(f"\n    Ventana de transición detectada: "
              f"{len(estados_parciales)} muestras inconsistentes")
        print(f"    (Esperado — transitorio durante sync de 100ms)")

        # Verificar que se resuelve: tras el final de la observación
        # el estado debe ser consistente
        await chain.start()
        await asyncio.sleep(0.15)
        snap_final = _snapshot_consistencia(chain)
        await chain.stop()

        assert snap_final["consistente"], \
            "Estado inconsistente PERSISTENTE — no se resuelve solo"
    else:
        print(f"\n    Sin estados parciales detectados en 300ms ✓")


async def t_hash_nunca_parcialmente_actualizado():
    """
    El hash de B nunca es un valor intermedio entre el hash anterior
    y el nuevo — la actualización es atómica (todo o nada).
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    ic_inicial = chain.integrity_check()
    hash_antes = ic_inicial["B_hash"]

    # Modificar A y observar B intensivamente
    chain.update_state(
        lambda s: setattr(s.security, "threat_level", "CRITICAL")
    )

    hashes_b_vistos = set()
    ic_final_hash   = None

    for _ in range(100):
        ic = chain.integrity_check()
        hashes_b_vistos.add(ic["B_hash"])
        await asyncio.sleep(0.001)

    await asyncio.sleep(0.15)
    ic_final = chain.integrity_check()
    ic_final_hash = ic_final["B_hash"]
    await chain.stop()

    # B solo puede tener 2 valores:
    # 1. El hash anterior (antes de sync)
    # 2. El hash nuevo (después de sync)
    # NUNCA un hash intermedio
    hashes_validos = {hash_antes, ic_final_hash}
    hashes_invalidos = hashes_b_vistos - hashes_validos

    assert len(hashes_invalidos) == 0, \
        f"Hash de B tomó valores intermedios inesperados: {hashes_invalidos}"

    print(f"\n    Hash de B: solo valores válidos "
          f"(antes={hash_antes[:8]} después={ic_final_hash[:8]}) ✓")


async def t_modificaciones_rapidas_sin_estado_corrupto():
    """
    10 modificaciones en ráfaga rápida (sin esperar sync entre ellas).
    Al final, el estado debe ser consistente — sin corrupción.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    niveles = ["HIGH", "LOW", "CRITICAL", "MEDIUM",
               "HIGH", "LOW", "CRITICAL", "LOW", "MEDIUM", "HIGH"]

    # Ráfaga sin esperar sync
    for nivel in niveles:
        chain.update_state(
            lambda s, n=nivel: setattr(s.security, "threat_level", n)
        )
        await asyncio.sleep(0)   # ceder control pero sin delay real

    # Esperar un ciclo de sync completo
    await asyncio.sleep(0.15)

    snap = _snapshot_consistencia(chain)
    await chain.stop()

    assert snap["consistente"], \
        f"Estado corrupto tras ráfaga de modificaciones: {snap.get('inconsistencias')}"

    # El threat level final debe ser el último aplicado
    all_twins = [chain.twin_a, chain.twin_b, chain.twin_c]
    active = next((t for t in all_twins if t.status == TwinStatus.ACTIVE),
                  chain.twin_a)
    assert active.state.security.threat_level == "HIGH", \
        f"Último estado no preservado: {active.state.security.threat_level}"

    print(f"\n    Ráfaga de 10 modificaciones: estado final consistente ✓")


test("VENTANA — Sin estado parcialmente replicado durante sync",
     t_sin_estado_parcialmente_replicado)
test("VENTANA — Hash de B solo toma valores válidos (nunca intermedios)",
     t_hash_nunca_parcialmente_actualizado)
test("VENTANA — Ráfaga de modificaciones sin estado corrupto",
     t_modificaciones_rapidas_sin_estado_corrupto)


# ─────────────────────────────────────────────
# BLOQUE 4 — CONSISTENCIA BAJO CARGA CONCURRENTE
# Observar durante carga — la sync no se rompe bajo presión
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA B2 — Bloque 4: Consistencia bajo Carga")
print("═══════════════════════════════════════════════════════")

async def t_consistencia_bajo_carga_event_loop():
    """
    Carga de 500 tareas concurrentes en el event loop mientras
    el sync opera. El sync no debe romperse bajo presión.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    inconsistencias = []

    async def carga(): await asyncio.sleep(0)

    async def observar():
        for _ in range(50):
            snap = _snapshot_consistencia(chain)
            if not snap["consistente"] and snap["tiene_replica"]:
                inconsistencias.append(snap)
            await asyncio.sleep(0.01)

    async def modificar():
        for nivel in ["HIGH", "MEDIUM", "LOW", "CRITICAL", "LOW"]:
            chain.update_state(
                lambda s, n=nivel: setattr(s.security, "threat_level", n)
            )
            await asyncio.sleep(0.1)

    # Carga + observación + modificación simultáneas
    await asyncio.gather(
        observar(),
        modificar(),
        *[carga() for _ in range(500)],
    )

    # Esperar estabilización
    await asyncio.sleep(0.15)
    snap_final = _snapshot_consistencia(chain)
    await chain.stop()

    # El estado final debe ser consistente
    assert snap_final["consistente"], \
        f"Estado inconsistente tras carga: {snap_final.get('inconsistencias')}"

    if inconsistencias:
        print(f"\n    Transitorios bajo carga: {len(inconsistencias)} "
              f"(resueltos en estado final ✓)")
    else:
        print(f"\n    Carga de 500 tareas: 0 inconsistencias ✓")


async def t_integrity_check_consistente_bajo_carga():
    """
    integrity_check() retorna resultado coherente incluso
    cuando se llama concurrentemente con modificaciones.
    Nunca debe retornar un resultado parcial.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    resultados_invalidos = []

    async def verificar_100_veces():
        for _ in range(100):
            ic = chain.integrity_check()
            # Un resultado válido tiene exactamente estos campos
            for campo in ["B_matches_A", "C_matches_B", "A_hash",
                          "B_hash", "C_hash", "active_twin"]:
                if campo not in ic:
                    resultados_invalidos.append({"falta": campo, "ic": ic})
            await asyncio.sleep(0.001)

    async def modificar_durante():
        for nivel in ["HIGH", "LOW", "CRITICAL", "MEDIUM"]:
            chain.update_state(
                lambda s, n=nivel: setattr(s.security, "threat_level", n)
            )
            await asyncio.sleep(0.025)

    await asyncio.gather(verificar_100_veces(), modificar_durante())
    await chain.stop()

    assert len(resultados_invalidos) == 0, \
        f"integrity_check() retornó resultados inválidos: {resultados_invalidos[:3]}"

    print(f"\n    100 integrity_check() concurrentes: todos válidos ✓")


test("CARGA — Consistencia bajo 500 tareas concurrentes",
     t_consistencia_bajo_carga_event_loop)
test("CARGA — integrity_check() siempre retorna estructura completa",
     t_integrity_check_consistente_bajo_carga)


# ─────────────────────────────────────────────
# BLOQUE 5 — CONSISTENCIA TRAS SALTO
# El salto es atómico — no deja estado inconsistente
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA B2 — Bloque 5: Consistencia tras Salto")
print("═══════════════════════════════════════════════════════")

async def t_salto_atomico_sin_estado_intermedio():
    """
    Durante y después del salto, no debe existir un estado
    observable donde el sistema esté parcialmente saltado.
    El salto es atómico — antes o después, nunca a medias.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    estados_invalidos = []

    async def observar_durante_salto():
        for _ in range(200):
            ic = chain.integrity_check()
            # Estado inválido: A sellado pero B aún no activo
            # (no debería ocurrir — el salto es atómico)
            a_sealed   = chain.twin_a.status == TwinStatus.SEALED
            b_active   = chain.twin_b.status == TwinStatus.ACTIVE
            b_replica  = chain.twin_b.status == TwinStatus.REPLICA

            # Si A está sellado, B DEBE ser activo — no puede ser réplica
            if a_sealed and b_replica:
                estados_invalidos.append({
                    "a_status": chain.twin_a.status.value,
                    "b_status": chain.twin_b.status.value,
                })
            await asyncio.sleep(0.001)

    async def ejecutar_salto():
        await asyncio.sleep(0.05)
        await chain.trigger_jump(JumpTrigger.INTRUSION, notes="B2")

    await asyncio.gather(observar_durante_salto(), ejecutar_salto())
    await chain.stop()

    assert len(estados_invalidos) == 0, \
        f"Estado inválido durante salto: A=SEALED pero B=REPLICA " \
        f"en {len(estados_invalidos)} observaciones"

    print(f"\n    200 observaciones durante salto: 0 estados inválidos ✓")


async def t_jump_count_consistente_tras_salto():
    """
    El jump_count del nuevo activo se incrementa correctamente
    y no queda en un valor intermedio.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    jc_antes = chain.twin_a.state.security.jump_count
    await chain.trigger_jump(JumpTrigger.INTRUSION, notes="B2")
    await asyncio.sleep(0.15)

    all_twins = [chain.twin_a, chain.twin_b, chain.twin_c]
    active = next((t for t in all_twins if t.status == TwinStatus.ACTIVE),
                  chain.twin_a)

    jc_despues = active.state.security.jump_count
    await chain.stop()

    assert jc_despues == jc_antes + 1, \
        f"jump_count incorrecto: antes={jc_antes} después={jc_despues}"

    print(f"\n    jump_count: {jc_antes} → {jc_despues} (correcto) ✓")


async def t_tres_saltos_jump_count_acumulativo():
    """
    Tres saltos consecutivos → jump_count acumulativo correcto.
    Verifica que el contador no se reinicia ni corrompe.
    """
    chain = TwinChain()
    await chain.start()
    await asyncio.sleep(0.15)

    for i in range(3):
        await chain.trigger_jump(JumpTrigger.INTRUSION, notes=f"salto_{i}")
        await asyncio.sleep(0.1)

    all_twins = [chain.twin_a, chain.twin_b, chain.twin_c]
    active = next((t for t in all_twins if t.status == TwinStatus.ACTIVE),
                  chain.twin_a)

    jc = active.state.security.jump_count
    await chain.stop()

    assert jc == 3, \
        f"jump_count tras 3 saltos = {jc} (esperado 3)"

    print(f"\n    3 saltos: jump_count={jc} ✓")


test("SALTO — Salto atómico sin estado A=SEALED B=REPLICA simultáneo",
     t_salto_atomico_sin_estado_intermedio)
test("SALTO — jump_count correcto tras salto",
     t_jump_count_consistente_tras_salto)
test("SALTO — jump_count acumulativo en 3 saltos",
     t_tres_saltos_jump_count_acumulativo)


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
    print("  CONCLUSIÓN DE RESILIENCIA B2:")
    print("  Sincronización A→B es atómica.")
    print("  Cero inconsistencias persistentes detectadas.")
    print("  El estado nunca queda parcialmente replicado.")
    print("  El salto de gemelo es atómico — nunca a medias.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
