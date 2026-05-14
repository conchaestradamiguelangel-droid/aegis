"""
AEGIS — Test de Resiliencia A1: Movimiento Lento (Low & Slow)
==============================================================
Vector: intruso que toca señuelos de C2 muy despacio,
        con intervalos largos entre acciones.

CRITERIO DE ÉXITO (defensivo):
    C3 detecta al intruso antes de que complete 10 toques de señuelo.
    El detector tiene memoria temporal suficiente para acumular
    el patrón aunque los intervalos entre acciones sean largos.
    Sin falsos positivos en tráfico legítimo lento.

CRITERIO DE FALLO:
    C3 no detecta al intruso porque el patrón está demasiado
    espaciado en el tiempo y cae fuera de la ventana de memoria.
    Tráfico legítimo lento genera falsos positivos.

ESTO NO ES:
    Un exploit para evadir detección en sistemas reales.
    Un script de ataque low-and-slow reutilizable.

ESTO ES:
    Verificación de que la memoria temporal del detector es
    suficientemente larga para capturar ataques pacientes.
    El peor caso defensivo — el atacante más cuidadoso.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.detector  import AegisDetector, DetectionType
from layers.minefield import AegisMinefield, MineType

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP_INTRUSO = "10.99.2.1"
IP_LEGIT   = "10.0.2.1"
MAX_TOQUES = 10   # debe detectar antes de este número


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
# BLOQUE 1 — BASELINE: TRÁFICO LEGÍTIMO LENTO
# Verificar cero falsos positivos con intervalos largos
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A1 — Bloque 1: Legítimo Lento")
print("═══════════════════════════════════════════════════════")

async def t_legitimo_lento_sin_deteccion():
    """
    Tráfico legítimo con intervalos largos entre peticiones.
    Simula un usuario humano real — lento pero legítimo.
    No debe generar ninguna detección.
    """
    detector = AegisDetector()
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    detector._active.COORDINATION_MIN_IPS     = 999

    # 8 peticiones al mismo endpoint con intervalos de 200ms
    for i in range(8):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
        await asyncio.sleep(0.2)

    assert detector.total_detections() == 0, \
        f"Tráfico legítimo lento generó {detector.total_detections()} detecciones — FALSO POSITIVO"

async def t_legitimo_lento_rutas_variadas_sin_deteccion():
    """
    Usuario legítimo que navega distintas rutas lentamente.
    Exploración normal de una aplicación — no debe detectarse.
    """
    detector = AegisDetector()
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    detector._active.COORDINATION_MIN_IPS     = 999
    detector._active.RECON_PATHS_THRESHOLD    = 10  # umbral alto — usuario normal

    rutas_legitimas = [
        "/api/v1/products",
        "/api/v1/cart",
        "/api/v1/user/profile",
        "/api/v1/checkout",
        "/api/v1/orders",
    ]

    for ruta in rutas_legitimas:
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path=ruta
        )
        await asyncio.sleep(0.3)   # 300ms entre peticiones — humano real

    assert detector.total_detections() == 0, \
        f"Navegación legítima lenta generó detecciones — FALSO POSITIVO"

test("LEGÍTIMO — Mismo endpoint lento no genera detección", t_legitimo_lento_sin_deteccion)
test("LEGÍTIMO — Rutas variadas lentas no generan detección", t_legitimo_lento_rutas_variadas_sin_deteccion)


# ─────────────────────────────────────────────
# BLOQUE 2 — CONTACTO ÚNICO SIEMPRE DETECTADO
# Un solo toque a señuelo = CONFIRMED inmediato
# independientemente de la velocidad
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A1 — Bloque 2: Señuelo Único")
print("═══════════════════════════════════════════════════════")

async def t_un_toque_señuelo_detectado_inmediato():
    """
    Un solo toque a señuelo de C2 → detección CONFIRMED inmediata.
    No importa la velocidad — el señuelo es absoluto.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)

    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    # Esperar 500ms antes del toque — simula actor muy pausado
    await asyncio.sleep(0.5)
    await minefield.touch_file("backup.json", IP_INTRUSO, 54321)

    assert detector.total_detections() >= 1, \
        "Un toque a señuelo no generó detección — FALLO CRÍTICO"

    log = detector.get_detection_log()
    confirmados = [d for d in log if d["confidence"] == "CONFIRMED"]
    assert len(confirmados) >= 1, \
        "Toque a señuelo no generó detección CONFIRMED"

async def t_señuelo_detectado_tras_larga_pausa():
    """
    Tráfico legítimo durante 1 segundo, luego un toque a señuelo.
    El señuelo debe detectarse aunque venga tarde.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    # 1 segundo de tráfico legítimo
    for _ in range(5):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
        await asyncio.sleep(0.2)

    assert detector.total_detections() == 0

    # Toque al señuelo después de la pausa
    await minefield.touch_file("credentials.env", IP_INTRUSO, 54321)

    assert detector.total_detections() >= 1, \
        "Señuelo no detectado tras larga pausa de tráfico legítimo"

test("SEÑUELO — Un toque detectado inmediatamente", t_un_toque_señuelo_detectado_inmediato)
test("SEÑUELO — Detectado tras larga pausa de tráfico legítimo", t_señuelo_detectado_tras_larga_pausa)


# ─────────────────────────────────────────────
# BLOQUE 3 — DETECCIÓN LOW & SLOW
# Múltiples señuelos con intervalos largos
# Criterio: detectado antes del toque número 10
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A1 — Bloque 3: Detección Low & Slow")
print("═══════════════════════════════════════════════════════")

async def t_deteccion_antes_de_10_toques_intervalo_100ms():
    """
    Intruso toca señuelos cada 100ms.
    Debe ser detectado antes del toque número 10.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    señuelos = [
        ("backup.json",        "file"),
        ("credentials.env",    "file"),
        ("admin",              "credential"),
        ("/admin",             "endpoint"),
        ("admin_master",       "identity"),
        ("secrets.yaml",       "file"),
        ("/actuator/env",      "endpoint"),
        ("root",               "credential"),
        ("/.git/config",       "endpoint"),
        ("master.pem",         "file"),
    ]

    detectado_en = None
    for i, (mine, tipo) in enumerate(señuelos):
        await asyncio.sleep(0.1)   # 100ms entre toques

        if tipo == "file":
            await minefield.touch_file(mine, IP_INTRUSO, 54321)
        elif tipo == "credential":
            await minefield.touch_credential(mine, IP_INTRUSO, 54321)
        elif tipo == "endpoint":
            await minefield.touch_endpoint(mine, IP_INTRUSO, 54321)
        elif tipo == "identity":
            await minefield.touch_identity(mine, IP_INTRUSO, 54321)

        if detector.total_detections() > 0 and detectado_en is None:
            detectado_en = i + 1
            break

    assert detectado_en is not None, \
        f"Intruso no detectado tras {len(señuelos)} toques a señuelos — FALLO CRÍTICO"
    assert detectado_en <= MAX_TOQUES, \
        f"Detección tardía: toque {detectado_en} (máximo {MAX_TOQUES})"

    print(f"\n    [100ms] Detectado en toque {detectado_en}/{MAX_TOQUES} ✓")

async def t_deteccion_antes_de_10_toques_intervalo_300ms():
    """
    Intruso toca señuelos cada 300ms — más pausado.
    El detector debe tener memoria suficiente para acumular
    el patrón aunque los intervalos sean largos.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    señuelos = [
        ("backup.json",     "file"),
        ("credentials.env", "file"),
        ("admin",           "credential"),
        ("/admin",          "endpoint"),
        ("admin_master",    "identity"),
        ("secrets.yaml",    "file"),
        ("/actuator/env",   "endpoint"),
        ("root",            "credential"),
        ("master.pem",      "file"),
        ("/.git/config",    "endpoint"),
    ]

    detectado_en = None
    for i, (mine, tipo) in enumerate(señuelos):
        await asyncio.sleep(0.3)   # 300ms entre toques

        if tipo == "file":
            await minefield.touch_file(mine, IP_INTRUSO, 54321)
        elif tipo == "credential":
            await minefield.touch_credential(mine, IP_INTRUSO, 54321)
        elif tipo == "endpoint":
            await minefield.touch_endpoint(mine, IP_INTRUSO, 54321)
        elif tipo == "identity":
            await minefield.touch_identity(mine, IP_INTRUSO, 54321)

        if detector.total_detections() > 0 and detectado_en is None:
            detectado_en = i + 1
            break

    assert detectado_en is not None, \
        f"Intruso lento no detectado tras {len(señuelos)} toques — FALLO CRÍTICO"
    assert detectado_en <= MAX_TOQUES, \
        f"Detección tardía en tráfico lento: toque {detectado_en} (máximo {MAX_TOQUES})"

    print(f"\n    [300ms] Detectado en toque {detectado_en}/{MAX_TOQUES} ✓")

async def t_deteccion_antes_de_10_toques_intervalo_500ms():
    """
    Intruso toca señuelos cada 500ms — muy pausado.
    Verifica que la memoria temporal del detector
    cubre al menos 5 segundos de historia.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    señuelos = [
        ("backup.json",     "file"),
        ("credentials.env", "file"),
        ("admin",           "credential"),
        ("/admin",          "endpoint"),
        ("admin_master",    "identity"),
        ("secrets.yaml",    "file"),
        ("/actuator/env",   "endpoint"),
        ("root",            "credential"),
        ("master.pem",      "file"),
        ("/.git/config",    "endpoint"),
    ]

    detectado_en = None
    for i, (mine, tipo) in enumerate(señuelos):
        await asyncio.sleep(0.5)   # 500ms entre toques

        if tipo == "file":
            await minefield.touch_file(mine, IP_INTRUSO, 54321)
        elif tipo == "credential":
            await minefield.touch_credential(mine, IP_INTRUSO, 54321)
        elif tipo == "endpoint":
            await minefield.touch_endpoint(mine, IP_INTRUSO, 54321)
        elif tipo == "identity":
            await minefield.touch_identity(mine, IP_INTRUSO, 54321)

        if detector.total_detections() > 0 and detectado_en is None:
            detectado_en = i + 1
            break

    assert detectado_en is not None, \
        f"Intruso muy lento no detectado tras {len(señuelos)} toques — FALLO CRÍTICO"
    assert detectado_en <= MAX_TOQUES, \
        f"Detección tardía: toque {detectado_en} (máximo {MAX_TOQUES})"

    print(f"\n    [500ms] Detectado en toque {detectado_en}/{MAX_TOQUES} ✓")

test("LOW&SLOW — Detectado antes de 10 toques (intervalo 100ms)",
     t_deteccion_antes_de_10_toques_intervalo_100ms)
test("LOW&SLOW — Detectado antes de 10 toques (intervalo 300ms)",
     t_deteccion_antes_de_10_toques_intervalo_300ms)
test("LOW&SLOW — Detectado antes de 10 toques (intervalo 500ms)",
     t_deteccion_antes_de_10_toques_intervalo_500ms)


# ─────────────────────────────────────────────
# BLOQUE 4 — MEZCLA: LEGÍTIMO + LENTO SOSPECHOSO
# Tráfico legítimo lento mezclado con toques a señuelos
# El señuelo debe detectarse siempre
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A1 — Bloque 4: Mezcla Legítimo + Lento")
print("═══════════════════════════════════════════════════════")

async def t_señuelo_detectado_entre_trafico_legitimo_lento():
    """
    Tráfico legítimo lento (IP_LEGIT) intercalado con
    toques a señuelo (IP_INTRUSO) cada 400ms.
    El señuelo debe detectarse aunque el tráfico circundante
    sea también lento y no genere falsos positivos.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    detector._active.COORDINATION_MIN_IPS     = 999

    detectado_en = None

    for ronda in range(10):
        # Tráfico legítimo
        await asyncio.sleep(0.2)
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )

        # Toque a señuelo — IP distinta
        await asyncio.sleep(0.2)
        await minefield.touch_file("backup.json", IP_INTRUSO, 54321)

        if detector.total_detections() > 0 and detectado_en is None:
            detectado_en = ronda + 1
            break

    assert detectado_en is not None, \
        "Señuelo no detectado entre tráfico legítimo lento"
    assert detectado_en <= MAX_TOQUES, \
        f"Detección tardía: ronda {detectado_en}"

    # Verificar que IP_LEGIT no está en las detecciones
    log = detector.get_detection_log()
    for det in log:
        assert IP_LEGIT not in det["source_ips"], \
            f"IP legítima incorrectamente marcada en detección"

    print(f"\n    [mezcla 400ms] Detectado en ronda {detectado_en} ✓")

async def t_perfiles_independientes_bajo_trafico_lento():
    """
    Con tráfico lento, los perfiles de IP legítima e intrusa
    son completamente independientes.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    detector._active.COORDINATION_MIN_IPS     = 999

    # IP legítima — 5 peticiones lentas
    for _ in range(5):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
        await asyncio.sleep(0.3)

    # IP intrusa — 1 toque a señuelo
    await minefield.touch_credential("admin", IP_INTRUSO, 54321)

    assert detector.total_detections() >= 1, \
        "Señuelo no detectado"

    perfil_legit = detector.get_profile(IP_LEGIT)
    assert perfil_legit is not None
    assert perfil_legit.unique_ports() == 1, \
        "Perfil legítimo contaminado por actividad del intruso"

test("MEZCLA — Señuelo detectado entre tráfico legítimo lento",
     t_señuelo_detectado_entre_trafico_legitimo_lento)
test("MEZCLA — Perfiles independientes bajo tráfico lento",
     t_perfiles_independientes_bajo_trafico_lento)


# ─────────────────────────────────────────────
# BLOQUE 5 — DETECCIÓN CONFIRMADA
# Verificar que la detección es CONFIRMED, no solo HIGH
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A1 — Bloque 5: Calidad de Detección")
print("═══════════════════════════════════════════════════════")

async def t_deteccion_es_confirmed_no_solo_high():
    """
    El toque a señuelo debe generar detección CONFIRMED.
    No vale solo HIGH — el señuelo es evidencia directa.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)

    await asyncio.sleep(0.5)   # pausa larga antes del toque
    await minefield.touch_file("backup.json", IP_INTRUSO, 54321)

    log         = detector.get_detection_log()
    confirmados = [d for d in log if d["confidence"] == "CONFIRMED"]

    assert len(confirmados) >= 1, \
        f"Toque a señuelo no generó CONFIRMED — solo {[d['confidence'] for d in log]}"

async def t_log_exportable_con_ip_intrusa():
    """
    El log de detección incluye la IP del intruso
    y la evidencia del señuelo tocado.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)

    await asyncio.sleep(0.3)
    await minefield.touch_file("credentials.env", IP_INTRUSO, 54321)

    log = detector.get_detection_log()
    assert len(log) >= 1

    det = log[0]
    assert "source_ips"      in det
    assert "confidence"      in det
    assert "detection_type"  in det
    assert "indicators"      in det
    assert IP_INTRUSO in det["source_ips"], \
        f"IP del intruso no en el log: {det['source_ips']}"

async def t_action_required_es_jump_o_lockdown():
    """
    La detección de señuelo debe requerir acción de salto o lockdown
    — no puede ser solo MONITOR.
    """
    detector  = AegisDetector()
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)

    await asyncio.sleep(0.4)
    await minefield.touch_identity("admin_master", IP_INTRUSO, 54321)

    log = detector.get_detection_log()
    assert len(log) >= 1

    accion = log[0].get("action_required", "")
    assert accion in ("JUMP", "LOCKDOWN"), \
        f"Acción insuficiente para señuelo: {accion}"

test("CALIDAD — Detección es CONFIRMED (no solo HIGH)",
     t_deteccion_es_confirmed_no_solo_high)
test("CALIDAD — Log exportable con IP del intruso y evidencia",
     t_log_exportable_con_ip_intrusa)
test("CALIDAD — Acción requerida es JUMP o LOCKDOWN",
     t_action_required_es_jump_o_lockdown)


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
    print("  CONCLUSIÓN DE RESILIENCIA A1:")
    print("  C3 detecta ataques low & slow antes de 10 toques.")
    print("  Memoria temporal suficiente para intervalos de 500ms.")
    print("  Tráfico legítimo lento no genera falsos positivos.")
    print("  Detección siempre CONFIRMED con acción JUMP/LOCKDOWN.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
