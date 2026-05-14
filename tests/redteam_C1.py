"""
AEGIS — Test de Resiliencia C1: Predictibilidad AMTD
=====================================================
Vector: intentar predecir el próximo estado de superficie
        observando los ciclos anteriores de rotación.

CRITERIO DE ÉXITO (defensivo):
    El patrón de rotación no es predecible.
    No se puede predecir el próximo estado con más del 60% de acierto.
    60% es el umbral — por encima sería capacidad real de predicción.

CRITERIO DE FALLO:
    El patrón de rotación sigue una secuencia observable que
    permite al atacante predecir el siguiente puerto/ruta/token
    con > 60% de acierto.

ESTO NO ES:
    Un exploit para predecir superficies de sistemas reales.
    Un ataque de análisis criptográfico.

ESTO ES:
    Verificación de que la semilla secreta y la derivación HMAC
    producen una superficie suficientemente impredecible para
    un observador externo sin acceso a la semilla.
"""

import asyncio
import sys
import os
import secrets
import hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.amtd import (
    AegisAMTD,
    PortRotationEngine,
    RouteRotationEngine,
    TokenRotationEngine,
    StructureRotationEngine,
)

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

N_CICLOS       = 20    # ciclos de observación
N_PREDICCIONES = 20    # intentos de predicción
UMBRAL_ACIERTO = 0.60  # 60% — por encima sería predicción real


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
# ESTRATEGIAS DE PREDICCIÓN
# Lo que un atacante podría intentar observando
# los ciclos anteriores
# ─────────────────────────────────────────────

def _predecir_por_ultimo_visto(historico: list):
    """
    Estrategia 1: predecir que el próximo será el último visto.
    Funciona si hay repetición de estados.
    """
    if not historico:
        return None
    return historico[-1]


def _predecir_por_patron_ciclico(historico: list, periodo: int = 2):
    """
    Estrategia 2: predecir asumiendo ciclo fijo de longitud `periodo`.
    Funciona si la secuencia es periódica.
    """
    if len(historico) < periodo:
        return None
    return historico[-periodo]


def _predecir_por_delta(historico: list):
    """
    Estrategia 3: predecir asumiendo incremento constante.
    Si los puertos suben de 100 en 100, predecir +100.
    Funciona si hay aritmética regular.
    """
    if len(historico) < 2:
        return None
    try:
        delta = int(historico[-1]) - int(historico[-2])
        return str(int(historico[-1]) + delta)
    except (ValueError, TypeError):
        return historico[-1]


def _predecir_por_moda(historico: list):
    """
    Estrategia 4: predecir el valor más frecuente visto.
    Funciona si hay sesgo hacia ciertos valores.
    """
    if not historico:
        return None
    from collections import Counter
    return Counter(historico).most_common(1)[0][0]


def _predecir_aleatorio(opciones: list):
    """
    Baseline: predicción aleatoria entre las opciones conocidas.
    Debe dar ~1/N de acierto.
    """
    if not opciones:
        return None
    return secrets.choice(opciones)


# ─────────────────────────────────────────────
# BLOQUE 1 — PUERTOS: NO PREDECIBLES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C1 — Bloque 1: Puertos No Predecibles")
print("═══════════════════════════════════════════════════════")

async def t_puertos_no_predecibles_por_ultimo_visto():
    """
    Observar N ciclos de puertos y predecir el siguiente
    usando el último visto. No debe superar el 60%.
    """
    seed = secrets.token_bytes(32)
    eng  = PortRotationEngine(seed, num_ports=3)

    # Fase de observación
    historico = []
    for _ in range(N_CICLOS):
        eng.rotate()
        historico.append(eng.current_ports[0])   # observar sólo el primero

    # Fase de predicción
    aciertos = 0
    for _ in range(N_PREDICCIONES):
        prediccion  = _predecir_por_ultimo_visto(historico)
        eng.rotate()
        real        = eng.current_ports[0]
        if prediccion == real:
            aciertos += 1
        historico.append(real)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [último visto] Acierto: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Puertos predecibles por último visto: {tasa:.0%} — supera 60%"


async def t_puertos_no_predecibles_por_ciclo():
    """Observar N ciclos y predecir asumiendo periodicidad."""
    seed = secrets.token_bytes(32)
    eng  = PortRotationEngine(seed, num_ports=3)

    historico = []
    for _ in range(N_CICLOS):
        eng.rotate()
        historico.append(eng.current_ports[0])

    aciertos = 0
    for periodo in [2, 3, 4]:   # probar distintos periodos
        aciertos_periodo = 0
        hist_local = list(historico)
        for _ in range(N_PREDICCIONES):
            prediccion = _predecir_por_patron_ciclico(hist_local, periodo)
            eng.rotate()
            real = eng.current_ports[0]
            if prediccion == real:
                aciertos_periodo += 1
            hist_local.append(real)
        aciertos = max(aciertos, aciertos_periodo)   # peor caso

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [patrón cíclico] Acierto máx: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Puertos predecibles por ciclo: {tasa:.0%} — supera 60%"


async def t_puertos_no_predecibles_por_delta():
    """Observar N ciclos y predecir asumiendo incremento constante."""
    seed = secrets.token_bytes(32)
    eng  = PortRotationEngine(seed, num_ports=3)

    historico = []
    for _ in range(N_CICLOS):
        eng.rotate()
        historico.append(eng.current_ports[0])

    aciertos = 0
    for _ in range(N_PREDICCIONES):
        prediccion = _predecir_por_delta(historico)
        eng.rotate()
        real = eng.current_ports[0]
        if str(prediccion) == str(real):
            aciertos += 1
        historico.append(real)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [delta constante] Acierto: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Puertos predecibles por delta: {tasa:.0%} — supera 60%"


async def t_puertos_no_predecibles_por_moda():
    """Observar N ciclos y predecir siempre el valor más frecuente."""
    seed = secrets.token_bytes(32)
    eng  = PortRotationEngine(seed, num_ports=3)

    historico = []
    for _ in range(N_CICLOS):
        eng.rotate()
        historico.append(eng.current_ports[0])

    aciertos = 0
    for _ in range(N_PREDICCIONES):
        prediccion = _predecir_por_moda(historico)
        eng.rotate()
        real = eng.current_ports[0]
        if prediccion == real:
            aciertos += 1
        historico.append(real)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [moda] Acierto: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Puertos predecibles por moda: {tasa:.0%} — supera 60%"


async def t_puertos_distintos_semillas_distintos_patrones():
    """
    Dos instancias con semillas distintas producen patrones
    completamente distintos — no hay patrón global explotable.
    """
    seed_a = secrets.token_bytes(32)
    seed_b = secrets.token_bytes(32)
    eng_a  = PortRotationEngine(seed_a, num_ports=3)
    eng_b  = PortRotationEngine(seed_b, num_ports=3)

    coincidencias = 0
    for _ in range(N_CICLOS):
        eng_a.rotate()
        eng_b.rotate()
        if eng_a.current_ports[0] == eng_b.current_ports[0]:
            coincidencias += 1

    tasa_coincidencia = coincidencias / N_CICLOS
    print(f"\n    [semillas distintas] Coincidencia: {tasa_coincidencia:.0%}")

    # Dos semillas distintas no deben coincidir más del 20%
    # (probabilidad aleatoria de coincidir en 100 puertos posibles ≈ 1%)
    assert tasa_coincidencia <= 0.20, \
        f"Dos semillas distintas coinciden {tasa_coincidencia:.0%} — patrón global"


test("PUERTOS — Último visto no predice siguiente (≤60%)",
     t_puertos_no_predecibles_por_ultimo_visto)
test("PUERTOS — Patrón cíclico no funciona (≤60%)",
     t_puertos_no_predecibles_por_ciclo)
test("PUERTOS — Delta constante no funciona (≤60%)",
     t_puertos_no_predecibles_por_delta)
test("PUERTOS — Moda no predice siguiente (≤60%)",
     t_puertos_no_predecibles_por_moda)
test("PUERTOS — Semillas distintas producen patrones distintos",
     t_puertos_distintos_semillas_distintos_patrones)


# ─────────────────────────────────────────────
# BLOQUE 2 — RUTAS: NO PREDECIBLES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C1 — Bloque 2: Rutas No Predecibles")
print("═══════════════════════════════════════════════════════")

async def t_rutas_no_predecibles_por_ultimo_visto():
    """Las rutas no siguen un patrón observable."""
    seed = secrets.token_bytes(32)
    eng  = RouteRotationEngine(seed)
    tmpl = list(eng.ROUTE_TEMPLATES)[0]

    historico = []
    for _ in range(N_CICLOS):
        eng.rotate()
        ruta = eng.get_active_route(tmpl)
        historico.append(ruta)

    aciertos = 0
    for _ in range(N_PREDICCIONES):
        prediccion = _predecir_por_ultimo_visto(historico)
        eng.rotate()
        real = eng.get_active_route(tmpl)
        if prediccion == real:
            aciertos += 1
        historico.append(real)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [rutas último visto] Acierto: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Rutas predecibles: {tasa:.0%} — supera 60%"


async def t_tokens_ruta_no_repiten_patron():
    """
    El token de ruta (parte variable de /api/{token}/data)
    no sigue una secuencia predecible — no es contador ni hash simple.
    """
    seed = secrets.token_bytes(32)
    eng  = RouteRotationEngine(seed)
    tmpl = list(eng.ROUTE_TEMPLATES)[0]

    tokens = []
    for _ in range(N_CICLOS + N_PREDICCIONES):
        eng.rotate()
        ruta  = eng.get_active_route(tmpl)
        token = ruta.split("/")[-2] if "/" in ruta else ruta
        tokens.append(token)

    # Verificar que no hay repeticiones en los primeros 20
    primeros = tokens[:N_CICLOS]
    unicos   = len(set(primeros))
    assert unicos == N_CICLOS, \
        f"Tokens de ruta se repiten: {unicos} únicos en {N_CICLOS} ciclos"

    print(f"\n    [tokens ruta] {unicos}/{N_CICLOS} únicos — sin repetición ✓")


test("RUTAS — Último visto no predice siguiente (≤60%)",
     t_rutas_no_predecibles_por_ultimo_visto)
test("RUTAS — Tokens de ruta sin repetición en 20 ciclos",
     t_tokens_ruta_no_repiten_patron)


# ─────────────────────────────────────────────
# BLOQUE 3 — TOKENS: NO PREDECIBLES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C1 — Bloque 3: Tokens No Predecibles")
print("═══════════════════════════════════════════════════════")

async def t_tokens_sesion_no_predecibles():
    """
    Observar N tokens emitidos y predecir el siguiente.
    Los tokens deben ser impredecibles — generados con entropía segura.
    """
    seed = secrets.token_bytes(32)
    eng  = TokenRotationEngine(seed, token_lifetime_cycles=100)

    # Emitir y observar N tokens
    tokens_vistos = []
    for i in range(N_CICLOS):
        token = eng.issue_token(f"sess_{i}")
        tokens_vistos.append(token)

    # Intentar predecir el siguiente por moda (el más frecuente)
    # En tokens únicos la moda da cualquiera — estrategia de azar
    aciertos = 0
    for i in range(N_PREDICCIONES):
        prediccion = _predecir_por_moda(tokens_vistos)
        token_real = eng.issue_token(f"pred_{i}")
        if prediccion == token_real:
            aciertos += 1
        tokens_vistos.append(token_real)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [tokens sesión] Acierto: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Tokens predecibles: {tasa:.0%} — supera 60%"


async def t_tokens_todos_unicos():
    """
    N tokens emitidos consecutivamente deben ser todos únicos.
    Ningún token se repite — sin colisiones observables.
    """
    seed = secrets.token_bytes(32)
    eng  = TokenRotationEngine(seed, token_lifetime_cycles=100)

    emitidos = [eng.issue_token(f"sess_{i}") for i in range(40)]
    unicos   = len(set(emitidos))

    assert unicos == 40, \
        f"Tokens con colisiones: {unicos} únicos de 40 emitidos"
    print(f"\n    [unicidad] 40/40 tokens únicos ✓")


test("TOKENS — No predecibles por moda (≤60%)",
     t_tokens_sesion_no_predecibles)
test("TOKENS — 40 tokens consecutivos todos únicos",
     t_tokens_todos_unicos)


# ─────────────────────────────────────────────
# BLOQUE 4 — ESTRUCTURA: NO PREDECIBLE
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C1 — Bloque 4: Estructura No Predecible")
print("═══════════════════════════════════════════════════════")

async def t_estructura_server_no_predecible():
    """
    El header Server no sigue un patrón observable.
    Observar N ciclos y predecir el siguiente — no supera 60%.
    """
    seed = secrets.token_bytes(32)
    eng  = StructureRotationEngine(seed)

    historico = []
    for _ in range(N_CICLOS):
        eng.rotate()
        historico.append(eng.current_headers.get("Server", ""))

    aciertos = 0
    for _ in range(N_PREDICCIONES):
        prediccion = _predecir_por_moda(historico)
        eng.rotate()
        real = eng.current_headers.get("Server", "")
        if prediccion == real:
            aciertos += 1
        historico.append(real)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [Server header] Acierto: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Header Server predecible: {tasa:.0%} — supera 60%"


async def t_request_id_unico_por_ciclo():
    """
    El X-Request-ID cambia en cada ciclo y nunca se repite.
    """
    seed = secrets.token_bytes(32)
    eng  = StructureRotationEngine(seed)

    ids = []
    for _ in range(30):
        eng.rotate()
        ids.append(eng.current_headers.get("X-Request-ID", ""))

    unicos = len(set(ids))
    assert unicos == 30, \
        f"X-Request-ID con colisiones: {unicos} únicos de 30"
    print(f"\n    [X-Request-ID] 30/30 únicos ✓")


test("ESTRUCTURA — Header Server no predecible (≤60%)",
     t_estructura_server_no_predecible)
test("ESTRUCTURA — X-Request-ID único en 30 ciclos",
     t_request_id_unico_por_ciclo)


# ─────────────────────────────────────────────
# BLOQUE 5 — FACHADA AEGIS AMTD: IMPREDECIBILIDAD GLOBAL
# Predicción sobre la fachada completa con 4 motores
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C1 — Bloque 5: Impredecibilidad Global")
print("═══════════════════════════════════════════════════════")

async def t_fachada_puertos_no_predecibles():
    """
    Observar N rotaciones de la fachada completa y predecir
    el siguiente puerto. No debe superar el 60%.
    """
    amtd = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))

    historico = []
    for _ in range(N_CICLOS):
        await amtd.rotate_now()
        historico.append(amtd.current_ports()[0])

    aciertos = 0
    for estrategia in [_predecir_por_ultimo_visto,
                       _predecir_por_moda,
                       lambda h: _predecir_por_patron_ciclico(h, 2)]:
        aciertos_e = 0
        hist_local = list(historico)
        for _ in range(N_PREDICCIONES):
            pred = estrategia(hist_local)
            await amtd.rotate_now()
            real = amtd.current_ports()[0]
            if pred == real:
                aciertos_e += 1
            hist_local.append(real)
        aciertos = max(aciertos, aciertos_e)

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [fachada puertos] Acierto máx: {tasa:.0%} "
          f"({'≤60% ✓' if tasa <= UMBRAL_ACIERTO else '>60% ✗'})")

    assert tasa <= UMBRAL_ACIERTO, \
        f"Fachada AMTD predecible en puertos: {tasa:.0%}"


async def t_sin_semilla_sin_prediccion():
    """
    Dos instancias AMTD con semillas distintas producen superficies
    completamente distintas — no hay patrón global entre instalaciones.
    """
    amtd_a = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    amtd_b = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))

    coincidencias_puerto = 0
    coincidencias_ruta   = 0

    for _ in range(N_CICLOS):
        await amtd_a.rotate_now()
        await amtd_b.rotate_now()

        if amtd_a.current_ports()[0] == amtd_b.current_ports()[0]:
            coincidencias_puerto += 1

        ruta_a = list(amtd_a.current_routes().values())[0]
        ruta_b = list(amtd_b.current_routes().values())[0]
        if ruta_a == ruta_b:
            coincidencias_ruta += 1

    tasa_puerto = coincidencias_puerto / N_CICLOS
    tasa_ruta   = coincidencias_ruta   / N_CICLOS

    print(f"\n    [semillas distintas] Puerto coincide: {tasa_puerto:.0%} "
          f"Ruta coincide: {tasa_ruta:.0%}")

    assert tasa_puerto <= 0.20, \
        f"Puertos de distintas instalaciones coinciden {tasa_puerto:.0%} — patrón global"
    assert tasa_ruta <= 0.05, \
        f"Rutas de distintas instalaciones coinciden {tasa_ruta:.0%} — patrón global"


async def t_determinismo_con_misma_semilla():
    """
    Dos instancias con la MISMA semilla producen la MISMA secuencia.
    El sistema legítimo siempre puede recalcular — el atacante sin semilla no.
    Esto confirma que la impredecibilidad viene de la semilla secreta.
    """
    semilla = secrets.token_bytes(32)
    amtd_a  = AegisAMTD(rotation_interval_s=60, seed=semilla)
    amtd_b  = AegisAMTD(rotation_interval_s=60, seed=semilla)

    for _ in range(N_CICLOS):
        await amtd_a.rotate_now()
        await amtd_b.rotate_now()

        assert amtd_a.current_ports() == amtd_b.current_ports(), \
            "Misma semilla produjo puertos distintos — rotura del determinismo"

        rutas_a = amtd_a.current_routes()
        rutas_b = amtd_b.current_routes()
        assert rutas_a == rutas_b, \
            "Misma semilla produjo rutas distintas — rotura del determinismo"

    print(f"\n    [determinismo] Misma semilla = misma secuencia en {N_CICLOS} ciclos ✓")


test("GLOBAL — Fachada puertos no predecibles (≤60%)",
     t_fachada_puertos_no_predecibles)
test("GLOBAL — Semillas distintas producen superficies distintas",
     t_sin_semilla_sin_prediccion)
test("GLOBAL — Misma semilla produce secuencia determinista",
     t_determinismo_con_misma_semilla)


# ─────────────────────────────────────────────
# BLOQUE 6 — BASELINE ALEATORIO
# Confirmar que el umbral del 60% es razonable
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C1 — Bloque 6: Baseline")
print("═══════════════════════════════════════════════════════")

async def t_baseline_aleatorio_bajo_umbral():
    """
    Predicción completamente aleatoria entre los rangos de puerto.
    Debe dar << 60% — confirma que el umbral es razonable.
    """
    seed = secrets.token_bytes(32)
    eng  = PortRotationEngine(seed, num_ports=3)

    # Rango de puertos posibles: 8100-8199, 8200-8299, 9100-9199
    rangos = [(8100, 8199), (8200, 8299), (9100, 9199),
              (9200, 9299), (7100, 7199)]

    import random
    aciertos = 0
    for _ in range(N_PREDICCIONES):
        rango    = secrets.choice(rangos)
        pred     = random.randint(rango[0], rango[1])
        eng.rotate()
        real     = eng.current_ports[0]
        if pred == real:
            aciertos += 1

    tasa = aciertos / N_PREDICCIONES
    print(f"\n    [aleatorio] Acierto: {tasa:.0%} (esperado ~1%)")

    # Aleatorio puro debería dar << 60%
    assert tasa <= UMBRAL_ACIERTO, \
        f"Baseline aleatorio anómalo: {tasa:.0%}"


test("BASELINE — Predicción aleatoria << 60%",
     t_baseline_aleatorio_bajo_umbral)


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
    print("  CONCLUSIÓN DE RESILIENCIA C1:")
    print("  El patrón de rotación AMTD no es predecible.")
    print(f"  Ninguna estrategia supera el {UMBRAL_ACIERTO:.0%} de acierto.")
    print("  La impredecibilidad proviene de la semilla secreta HMAC.")
    print("  El sistema legítimo con semilla siempre puede recalcular.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
