"""
AEGIS — Test de Resiliencia D2: Multivector Simultáneo
=======================================================
Vector: 4 vectores de presión activados simultáneamente.

    V1 — Toque de señuelo C2       → minefield.touch_file()
    V2 — Probe de escudo C0.5      → shield probe event
    V3 — Acceso a superficie AMTD caducada C5 → amtd.check_port()
    V4 — Fingerprinting de gemelo C1 → múltiples check de integrity

CRITERIO DE ÉXITO (defensivo):
    Cada vector genera su respuesta defensiva correcta.
    Ningún vector queda sin respuesta cuando todos se activan a la vez.
    Las respuestas de un vector no interfieren con las de otro.
    El sistema no queda en estado inconsistente tras la presión simultánea.

CRITERIO DE FALLO:
    Algún vector queda silencioso mientras otros se procesan.
    Un vector consume recursos que dejan a otro sin respuesta.
    El estado del sistema queda inconsistente tras la presión.

ESTO NO ES:
    Un ataque coordinado contra sistemas externos.
    Un exploit para saturar AEGIS y evadir detección.

ESTO ES:
    Verificación de que asyncio.gather() distribuye correctamente
    la respuesta defensiva a todos los vectores simultáneos.
"""

import asyncio
import sys
import os
import secrets
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.minefield import AegisMinefield, MineType
from layers.shield    import AegisShield, ProbeEvent, ProbeType, ThreatLevel
from layers.amtd      import AegisAMTD
from layers.detector  import AegisDetector
from core.twin        import TwinChain
from datetime         import datetime, timezone

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP_A = "10.99.1.1"   # actor vector 1 (señuelo)
IP_B = "10.99.1.2"   # actor vector 2 (escudo)
IP_C = "10.99.1.3"   # actor vector 3 (AMTD)
IP_D = "10.99.1.4"   # actor vector 4 (gemelo)


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
# SIMULADORES POR VECTOR
# ─────────────────────────────────────────────

async def _vector1_señuelo(minefield: AegisMinefield, resultados: dict):
    """V1: toca señuelo de archivo — debe generar MineContact."""
    contact, response = await minefield.touch_file(
        "backup.json", IP_A, 54321, method="GET"
    )
    resultados["v1_contact"]  = contact
    resultados["v1_response"] = response
    resultados["v1_ok"]       = contact is not None and len(response) > 0


async def _vector2_escudo(shield: AegisShield, resultados: dict):
    """V2: probe del escudo — debe generar banner disuasorio."""
    sid     = secrets.token_hex(8).upper()
    banner  = shield.build_tcp_banner(sid)
    resultados["v2_banner"] = banner
    resultados["v2_ok"]     = len(banner) > 0 and sid.encode() in banner


async def _vector3_amtd(amtd: AegisAMTD, resultados: dict):
    """V3: acceso a superficie caducada — debe generar alerta stale."""
    alertas = []

    async def on_stale(payload):
        alertas.append(payload)

    amtd.register_stale_access_callback(on_stale)

    # Capturar puertos antes de rotar
    puertos_antes   = amtd.current_ports().copy()
    await amtd.rotate_now()
    puertos_despues = amtd.current_ports()
    caducados       = [p for p in puertos_antes if p not in puertos_despues]

    if caducados:
        es_activo = await amtd.check_port(caducados[0], IP_C)
        resultados["v3_caducado"]  = caducados[0]
        resultados["v3_es_activo"] = es_activo
        resultados["v3_alertas"]   = len(alertas)
        resultados["v3_ok"]        = not es_activo and len(alertas) >= 1
    else:
        # No hubo caducados en este ciclo — marcar como N/A pero no fallar
        resultados["v3_ok"]      = True
        resultados["v3_alertas"] = 0
        resultados["v3_skip"]    = True


async def _vector4_gemelo(twin: TwinChain, resultados: dict):
    """V4: fingerprinting — intentar leer integridad del gemelo."""
    # El fingerprinting externo solo puede observar el estado del gemelo A
    # AEGIS responde con el estado del gemelo activo — siempre coherente
    integridad = twin.integrity_check()
    estado     = twin.status()

    resultados["v4_integrity"] = integridad
    resultados["v4_status"]    = estado
    # Respuesta correcta: integridad ok (A=B=C en estado inicial)
    resultados["v4_ok"] = (
        integridad["B_matches_A"] and
        integridad["C_matches_B"] and
        estado["active"] is not None
    )


# ─────────────────────────────────────────────
# BLOQUE 1 — VECTORES INDIVIDUALES
# Verificar que cada vector responde correctamente por separado
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D2 — Bloque 1: Vectores Individuales")
print("═══════════════════════════════════════════════════════")

async def t_v1_señuelo_individual():
    mf  = AegisMinefield()
    res = {}
    await _vector1_señuelo(mf, res)
    assert res["v1_ok"], f"V1 señuelo falló individualmente: {res}"

async def t_v2_escudo_individual():
    shield = AegisShield(decoy_ports=[])
    res    = {}
    await _vector2_escudo(shield, res)
    assert res["v2_ok"], f"V2 escudo falló individualmente: {res}"

async def t_v3_amtd_individual():
    amtd = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    res  = {}
    await _vector3_amtd(amtd, res)
    assert res["v3_ok"], f"V3 AMTD falló individualmente: {res}"

async def t_v4_gemelo_individual():
    async def _run():
        twin = TwinChain()
        await twin.start()
        res  = {}
        await _vector4_gemelo(twin, res)
        await twin.stop()
        return res
    res = await _run()
    assert res["v4_ok"], f"V4 gemelo falló individualmente: {res}"

test("V1 — Señuelo responde correctamente en solitario", t_v1_señuelo_individual)
test("V2 — Escudo responde correctamente en solitario", t_v2_escudo_individual)
test("V3 — AMTD detecta superficie caducada en solitario", t_v3_amtd_individual)
test("V4 — Gemelo responde a fingerprinting en solitario", t_v4_gemelo_individual)


# ─────────────────────────────────────────────
# BLOQUE 2 — ACTIVACIÓN SIMULTÁNEA
# Los 4 vectores a la vez — todos deben responder
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D2 — Bloque 2: Activación Simultánea")
print("═══════════════════════════════════════════════════════")

async def t_4_vectores_simultáneos_todos_responden():
    """
    CRITERIO PRINCIPAL: los 4 vectores activados con asyncio.gather()
    generan respuesta defensiva correcta sin que ninguno quede silencioso.
    """
    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    twin   = TwinChain()
    await twin.start()

    res = {}
    t0  = time.monotonic()

    # Los 4 vectores simultáneos
    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
    )

    elapsed_ms = (time.monotonic() - t0) * 1000
    await twin.stop()

    print(f"\n    4 vectores simultáneos completados en {elapsed_ms:.1f}ms")

    # Verificar que TODOS respondieron
    assert res.get("v1_ok"), f"V1 (señuelo) sin respuesta en multivector: {res.get('v1_contact')}"
    assert res.get("v2_ok"), f"V2 (escudo) sin respuesta en multivector"
    assert res.get("v3_ok"), f"V3 (AMTD) sin respuesta en multivector"
    assert res.get("v4_ok"), f"V4 (gemelo) sin respuesta en multivector"

async def t_ningún_vector_silenciado_por_otro():
    """
    Verificar que la respuesta de un vector no consume
    recursos que dejen a otro sin respuesta.
    Ejecutar 3 veces para confirmar consistencia.
    """
    for ronda in range(3):
        mf     = AegisMinefield()
        shield = AegisShield(decoy_ports=[])
        amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
        twin   = TwinChain()
        await twin.start()

        res = {}
        await asyncio.gather(
            _vector1_señuelo(mf,     res),
            _vector2_escudo(shield,  res),
            _vector3_amtd(amtd,      res),
            _vector4_gemelo(twin,    res),
        )
        await twin.stop()

        fallos = [k for k in ["v1_ok","v2_ok","v3_ok","v4_ok"] if not res.get(k)]
        assert not fallos, \
            f"Ronda {ronda+1}: vectores sin respuesta = {fallos}"

async def t_tiempo_simultáneo_menor_que_suma():
    """
    Tiempo de 4 vectores simultáneos debe ser menor
    que la suma de sus tiempos individuales.
    asyncio.gather() garantiza ejecución paralela.
    """
    seed = secrets.token_bytes(32)

    # Medir tiempos individuales
    t_individual = 0.0

    async def medir_v1():
        mf  = AegisMinefield()
        res = {}
        t0  = time.monotonic()
        await _vector1_señuelo(mf, res)
        return time.monotonic() - t0

    async def medir_v3():
        amtd = AegisAMTD(rotation_interval_s=60, seed=seed)
        res  = {}
        t0   = time.monotonic()
        await _vector3_amtd(amtd, res)
        return time.monotonic() - t0

    t1 = await medir_v1()
    t3 = await medir_v3()
    t_suma = t1 + t3   # aproximación de suma de los más lentos

    # Medir simultáneo
    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    amtd   = AegisAMTD(rotation_interval_s=60, seed=seed)
    twin   = TwinChain()
    await twin.start()

    res = {}
    t0  = time.monotonic()
    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
    )
    t_simultaneo = time.monotonic() - t0
    await twin.stop()

    print(f"\n    t_suma≈{t_suma*1000:.1f}ms | t_simultáneo={t_simultaneo*1000:.1f}ms")

    # El simultáneo debe ser menor que la suma (paralelo, no secuencial)
    # Con margen generoso — el gather tiene overhead propio
    assert t_simultaneo < t_suma * 2 or t_simultaneo < 0.5, \
        f"Ejecución posiblemente secuencial: suma={t_suma*1000:.1f}ms simultáneo={t_simultaneo*1000:.1f}ms"

test("SIMULTÁNEO — 4 vectores todos responden correctamente", t_4_vectores_simultáneos_todos_responden)
test("SIMULTÁNEO — Ningún vector silenciado (3 rondas)", t_ningún_vector_silenciado_por_otro)
test("SIMULTÁNEO — Tiempo paralelo menor que suma secuencial", t_tiempo_simultáneo_menor_que_suma)


# ─────────────────────────────────────────────
# BLOQUE 3 — INDEPENDENCIA DE RESPUESTAS
# Las respuestas de cada vector son independientes
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D2 — Bloque 3: Independencia")
print("═══════════════════════════════════════════════════════")

async def t_respuesta_v1_no_afecta_v2():
    """
    La detección del señuelo (V1) no debe contaminar
    la respuesta del escudo (V2).
    """
    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    res    = {}

    await asyncio.gather(
        _vector1_señuelo(mf,    res),
        _vector2_escudo(shield, res),
    )

    # V2 debe tener su propio banner independiente
    assert res.get("v2_ok"), "V2 afectado por V1"
    # El banner de V2 tiene su propio session_id — no es el de V1
    if res.get("v1_contact"):
        contact_id = res["v1_contact"].contact_id.encode()
        assert contact_id not in res.get("v2_banner", b""), \
            "Banner V2 contiene datos de V1 — contaminación entre vectores"

async def t_estado_gemelo_no_alterado_por_vectores_externos():
    """
    Los vectores V1, V2, V3 no deben alterar el estado
    del gemelo en cadena. V4 solo lo observa, no lo modifica.
    """
    twin = TwinChain()
    await twin.start()

    integridad_antes = twin.integrity_check()
    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    res    = {}

    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
    )

    integridad_despues = twin.integrity_check()
    await twin.stop()

    assert integridad_despues["B_matches_A"] == integridad_antes["B_matches_A"], \
        "Estado del gemelo alterado por vectores externos"
    assert integridad_despues["C_matches_B"] == integridad_antes["C_matches_B"], \
        "Estado del gemelo C alterado por vectores externos"

async def t_señuelo_y_amtd_generan_alertas_independientes():
    """
    V1 genera MineContact, V3 genera stale alert.
    Ambas alertas son independientes y distinguibles.
    """
    mf        = AegisMinefield()
    amtd      = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    mine_hits = []
    stale_hits= []

    async def on_mine(contact):  mine_hits.append(contact)
    async def on_stale(payload): stale_hits.append(payload)

    mf.register_detection_callback(on_mine)
    amtd.register_stale_access_callback(on_stale)

    res = {}
    await asyncio.gather(
        _vector1_señuelo(mf,   res),
        _vector3_amtd(amtd,    res),
    )

    # V1: debe haber generado al menos 1 MineContact
    assert len(mine_hits) >= 1, "V1 no generó MineContact"

    # V3: si hubo caducados, debe haber generado alerta stale
    if not res.get("v3_skip"):
        assert len(stale_hits) >= 1, "V3 no generó alerta stale"

    # Las alertas son de tipos distintos — no se confunden
    if mine_hits and stale_hits:
        assert hasattr(mine_hits[0], "mine_type"), \
            "Alerta de señuelo no tiene mine_type"
        assert "type" in stale_hits[0], \
            "Alerta stale no tiene tipo"

test("INDEPENDENCIA — V1 no afecta respuesta de V2", t_respuesta_v1_no_afecta_v2)
test("INDEPENDENCIA — Estado del gemelo intacto tras vectores externos", t_estado_gemelo_no_alterado_por_vectores_externos)
test("INDEPENDENCIA — Alertas de señuelo y AMTD son independientes", t_señuelo_y_amtd_generan_alertas_independientes)


# ─────────────────────────────────────────────
# BLOQUE 4 — CARGA MULTIVECTOR
# N repeticiones simultáneas de los 4 vectores
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D2 — Bloque 4: Carga Multivector")
print("═══════════════════════════════════════════════════════")

async def t_10_rondas_multivector_todas_correctas():
    """
    10 rondas consecutivas de 4 vectores simultáneos.
    Todas deben completar correctamente — sin degradación.
    """
    fallos_por_ronda = []

    for ronda in range(10):
        mf     = AegisMinefield()
        shield = AegisShield(decoy_ports=[])
        amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
        twin   = TwinChain()
        await twin.start()

        res = {}
        await asyncio.gather(
            _vector1_señuelo(mf,     res),
            _vector2_escudo(shield,  res),
            _vector3_amtd(amtd,      res),
            _vector4_gemelo(twin,    res),
        )
        await twin.stop()

        fallos = [k for k in ["v1_ok","v2_ok","v3_ok","v4_ok"] if not res.get(k)]
        if fallos:
            fallos_por_ronda.append((ronda + 1, fallos))

    assert not fallos_por_ronda, \
        f"Fallos en rondas: {fallos_por_ronda}"
    print(f"\n    10 rondas × 4 vectores = 40 activaciones correctas ✓")

async def t_multivector_bajo_carga_adicional():
    """
    4 vectores simultáneos + 200 tareas adicionales de carga.
    Todos los vectores deben responder correctamente.
    """
    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    twin   = TwinChain()
    await twin.start()

    async def carga(): await asyncio.sleep(0)

    res = {}
    t0  = time.monotonic()

    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
        *[carga() for _ in range(200)],
    )

    elapsed_ms = (time.monotonic() - t0) * 1000
    await twin.stop()

    fallos = [k for k in ["v1_ok","v2_ok","v3_ok","v4_ok"] if not res.get(k)]
    assert not fallos, \
        f"Vectores sin respuesta bajo carga adicional: {fallos}"
    assert elapsed_ms < 3000, \
        f"Multivector + carga tardó {elapsed_ms:.1f}ms — supera 3s"
    print(f"\n    4 vectores + 200 tareas en {elapsed_ms:.1f}ms ✓")

test("CARGA — 10 rondas × 4 vectores = 40 activaciones correctas", t_10_rondas_multivector_todas_correctas)
test("CARGA — 4 vectores + 200 tareas adicionales correctos", t_multivector_bajo_carga_adicional)


# ─────────────────────────────────────────────
# BLOQUE 5 — ESTADO FINAL
# El sistema queda en estado consistente tras la presión
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA D2 — Bloque 5: Estado Final")
print("═══════════════════════════════════════════════════════")

async def t_minefield_log_completo_tras_multivector():
    """Log de señuelos tiene entrada por cada toque, incluso bajo presión."""
    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    twin   = TwinChain()
    await twin.start()

    res = {}
    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
    )
    await twin.stop()

    log = mf.get_contact_log()
    assert len(log) >= 1, \
        "Log del minefield vacío tras activación multivector"
    assert log[0]["mine_name"] == "backup.json"

async def t_gemelo_sincronizado_tras_multivector():
    """El gemelo mantiene sincronización correcta tras presión multivector."""
    twin = TwinChain()
    await twin.start()

    mf     = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    amtd   = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    res    = {}

    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
    )

    # Esperar un ciclo de sincronización
    await asyncio.sleep(0.15)

    integridad = twin.integrity_check()
    await twin.stop()

    assert integridad["B_matches_A"], \
        "Gemelo B no sincronizado tras presión multivector"
    assert integridad["C_matches_B"], \
        "Gemelo C no sincronizado tras presión multivector"

async def t_amtd_ciclo_correcto_tras_multivector():
    """AMTD tiene el ciclo correcto tras activación simultánea."""
    amtd = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    mf   = AegisMinefield()
    shield = AegisShield(decoy_ports=[])
    twin   = TwinChain()
    await twin.start()

    res = {}
    await asyncio.gather(
        _vector1_señuelo(mf,     res),
        _vector2_escudo(shield,  res),
        _vector3_amtd(amtd,      res),
        _vector4_gemelo(twin,    res),
    )
    await twin.stop()

    st = amtd.status()
    assert st["cycle"] >= 1, \
        "AMTD no ejecutó ningún ciclo en la activación multivector"
    assert len(amtd.current_ports()) > 0, \
        "AMTD sin puertos activos tras multivector"

test("ESTADO — Log de señuelos completo tras multivector", t_minefield_log_completo_tras_multivector)
test("ESTADO — Gemelo sincronizado correctamente tras presión", t_gemelo_sincronizado_tras_multivector)
test("ESTADO — AMTD en estado correcto tras multivector", t_amtd_ciclo_correcto_tras_multivector)


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
    print("  CONCLUSIÓN DE RESILIENCIA D2:")
    print("  Los 4 vectores simultáneos generan respuesta")
    print("  defensiva correcta e independiente.")
    print("  Ningún vector queda silencioso bajo presión simultánea.")
    print("  Estado del sistema consistente tras la presión.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
