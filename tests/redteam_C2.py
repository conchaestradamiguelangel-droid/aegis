"""
AEGIS — Test de Resiliencia C2: Transición AMTD
=================================================
Vector: accesos a puertos/rutas durante la ventana de rotación de Capa 5.

CRITERIO DE ÉXITO (defensivo):
    AEGIS detecta correctamente accesos a superficie caducada.
    AEGIS registra el evento en detector y forense.
    AEGIS responde en tiempo — nunca silenciosamente.

CRITERIO DE FALLO:
    Un acceso a superficie caducada NO es detectado.
    Un acceso a superficie caducada NO es registrado.
    La ventana de transición produce silencio en el sistema.

ESTO NO ES:
    - Un exploit que mide tasa de éxito del atacante.
    - Un script reutilizable para atacar sistemas externos.
    - Un test que busca evadir la detección.

ESTO ES:
    Verificación de que AEGIS funciona correctamente
    durante la condición más exigente — la transición.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.amtd     import AegisAMTD
from layers.detector import AegisDetector, DetectionType
from layers.forensic import AegisForensic

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP_SIMULADO = "10.99.99.99"   # IP del acceso simulado — nunca real


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
# UTILIDADES
# ─────────────────────────────────────────────

async def _setup_amtd_con_detector():
    """Prepara AMTD + Detector conectados para los tests."""
    import secrets
    seed     = secrets.token_bytes(32)
    amtd     = AegisAMTD(rotation_interval_s=60, seed=seed)
    detector = AegisDetector()
    forensic = AegisForensic()

    # Conectar AMTD → Detector (superficie caducada → alerta)
    # CRÍTICO: debe ser async def — register_network_event es coroutine
    async def _on_stale(payload):
        await detector.register_network_event(
            ip   = IP_SIMULADO,
            port = payload.get("value", 0) if isinstance(payload.get("value"), int) else 0,
            path = f"stale_{payload.get('type', 'unknown')}",
        )
    amtd.register_stale_access_callback(_on_stale)

    # Conectar Detector → Forense
    detector.register_forensic_callback(forensic.on_detection_event)

    return amtd, detector, forensic


# ─────────────────────────────────────────────
# BLOQUE 1 — COMPORTAMIENTO BASE (sin transición)
# Establece el baseline: cómo responde AEGIS en condiciones normales
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C2 — Bloque 1: Comportamiento Base")
print("═══════════════════════════════════════════════════════")

async def t_puerto_activo_no_es_stale():
    """Puerto del ciclo actual NO debe marcarse como caducado."""
    amtd, detector, _ = await _setup_amtd_con_detector()
    puerto_activo = amtd.current_ports()[0]
    es_activo = await amtd.check_port(puerto_activo, IP_SIMULADO)
    assert es_activo, f"Puerto activo {puerto_activo} marcado erróneamente como caducado"

async def t_puerto_inexistente_no_genera_falso_positivo():
    """Puerto fuera de cualquier rango no debe disparar stale alert."""
    amtd, detector, _ = await _setup_amtd_con_detector()
    alertas_antes = detector.total_detections()
    # Puerto claramente fuera de rangos de AMTD
    es_activo = await amtd.check_port(80, IP_SIMULADO)
    # No debería ser ni activo ni stale — simplemente desconocido
    alertas_despues = detector.total_detections()
    assert alertas_despues == alertas_antes, \
        "Puerto desconocido generó falsa alerta"

async def t_ruta_activa_no_es_stale():
    """Ruta del ciclo actual NO debe marcarse como caducada."""
    amtd, _, _ = await _setup_amtd_con_detector()
    ruta_activa = list(amtd.current_routes().values())[0]
    es_activa = await amtd.check_route(ruta_activa, IP_SIMULADO)
    assert es_activa, f"Ruta activa '{ruta_activa}' marcada erróneamente como caducada"

async def t_baseline_sin_rotacion_sin_alertas():
    """Sin rotación ni accesos anómalos → detector silencioso."""
    amtd, detector, _ = await _setup_amtd_con_detector()
    assert detector.total_detections() == 0, \
        "Sistema arrancó con detecciones espurias"

test("BASE — Puerto activo no marcado como caducado", t_puerto_activo_no_es_stale)
test("BASE — Puerto desconocido no genera falso positivo", t_puerto_inexistente_no_genera_falso_positivo)
test("BASE — Ruta activa no marcada como caducada", t_ruta_activa_no_es_stale)
test("BASE — Sin accesos anómalos el detector permanece silencioso", t_baseline_sin_rotacion_sin_alertas)


# ─────────────────────────────────────────────
# BLOQUE 2 — DETECCIÓN DURANTE TRANSICIÓN
# Verifica que AEGIS detecta accesos a superficie recién caducada
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C2 — Bloque 2: Detección en Transición")
print("═══════════════════════════════════════════════════════")

async def t_acceso_a_puerto_caducado_detectado():
    """
    Después de una rotación, acceder al puerto anterior
    DEBE ser detectado como superficie caducada.
    """
    amtd, detector, _ = await _setup_amtd_con_detector()
    stale_callbacks   = []

    amtd.register_stale_access_callback(
        lambda p: stale_callbacks.append(p)
    )

    # Capturar puertos antes de rotar
    puertos_antes = amtd.current_ports().copy()

    # Ejecutar rotación
    await amtd.rotate_now()

    # Identificar puertos que quedaron caducados (estaban antes, no están ahora)
    puertos_despues = amtd.current_ports()
    caducados = [p for p in puertos_antes if p not in puertos_despues]

    assert caducados, "La rotación no produjo ningún puerto caducado — test no aplica"

    # Acceder al primer puerto caducado
    es_activo = await amtd.check_port(caducados[0], IP_SIMULADO)

    # CRITERIO DE ÉXITO DEFENSIVO:
    assert not es_activo, \
        f"Puerto caducado {caducados[0]} reportado como activo — FALLO DE SEGURIDAD"
    assert len(stale_callbacks) >= 1, \
        f"Acceso a puerto caducado {caducados[0]} NO generó alerta — FALLO DE DETECCIÓN"

async def t_acceso_a_ruta_caducada_detectado():
    """
    Después de rotación, acceder a ruta anterior
    DEBE generar alerta de superficie caducada.
    """
    amtd, _, _ = await _setup_amtd_con_detector()
    stale_callbacks = []
    amtd.register_stale_access_callback(lambda p: stale_callbacks.append(p))

    rutas_antes = list(amtd.current_routes().values()).copy()
    await amtd.rotate_now()
    rutas_despues = list(amtd.current_routes().values())

    caducadas = [r for r in rutas_antes if r not in rutas_despues]
    assert caducadas, "Rotación no produjo rutas caducadas — test no aplica"

    es_activa = await amtd.check_route(caducadas[0], IP_SIMULADO)

    assert not es_activa, \
        f"Ruta caducada '{caducadas[0]}' reportada como activa — FALLO DE SEGURIDAD"
    assert len(stale_callbacks) >= 1, \
        f"Acceso a ruta caducada NO generó alerta — FALLO DE DETECCIÓN"

async def t_alerta_stale_contiene_ip():
    """La alerta de superficie caducada debe incluir la IP del acceso."""
    amtd, _, _ = await _setup_amtd_con_detector()
    alertas = []
    amtd.register_stale_access_callback(lambda p: alertas.append(p))

    puertos_antes = amtd.current_ports().copy()
    await amtd.rotate_now()
    puertos_despues = amtd.current_ports()
    caducados = [p for p in puertos_antes if p not in puertos_despues]

    if caducados:
        await amtd.check_port(caducados[0], IP_SIMULADO)
        assert alertas, "Sin alertas generadas"
        assert alertas[0].get("source_ip") == IP_SIMULADO, \
            f"IP no registrada en alerta: {alertas[0]}"

async def t_alerta_stale_contiene_tipo_y_valor():
    """La alerta debe especificar qué tipo de superficie y qué valor."""
    amtd, _, _ = await _setup_amtd_con_detector()
    alertas = []
    amtd.register_stale_access_callback(lambda p: alertas.append(p))

    puertos_antes = amtd.current_ports().copy()
    await amtd.rotate_now()
    puertos_despues = amtd.current_ports()
    caducados = [p for p in puertos_antes if p not in puertos_despues]

    if caducados:
        await amtd.check_port(caducados[0], IP_SIMULADO)
        alerta = alertas[0]
        assert "type"  in alerta, "Alerta sin campo 'type'"
        assert "value" in alerta, "Alerta sin campo 'value'"
        assert alerta["type"] == "port"
        assert alerta["value"] == caducados[0]

test("TRANSICIÓN — Acceso a puerto caducado → detectado", t_acceso_a_puerto_caducado_detectado)
test("TRANSICIÓN — Acceso a ruta caducada → detectado", t_acceso_a_ruta_caducada_detectado)
test("TRANSICIÓN — Alerta incluye IP del acceso", t_alerta_stale_contiene_ip)
test("TRANSICIÓN — Alerta incluye tipo y valor de superficie", t_alerta_stale_contiene_tipo_y_valor)


# ─────────────────────────────────────────────
# BLOQUE 3 — MÚLTIPLES ROTACIONES
# Verifica que la detección es consistente a lo largo del tiempo
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C2 — Bloque 3: Múltiples Rotaciones")
print("═══════════════════════════════════════════════════════")

async def t_deteccion_consistente_en_multiples_ciclos():
    """
    Tras N rotaciones, cada acceso a superficie caducada
    debe ser detectado en todos los ciclos — sin degradación.
    Instancia fresca por ciclo — evita acumulación de callbacks.
    """
    import secrets as _sec
    N_CICLOS    = 5
    detecciones = 0
    intentos    = 0

    for _ in range(N_CICLOS):
        # Instancia fresca — el callback no se acumula entre ciclos
        amtd          = AegisAMTD(rotation_interval_s=60, seed=_sec.token_bytes(32))
        alertas_ciclo = []
        amtd.register_stale_access_callback(lambda p: alertas_ciclo.append(p))

        puertos_antes   = amtd.current_ports().copy()
        await amtd.rotate_now()
        puertos_despues = amtd.current_ports()
        caducados       = [p for p in puertos_antes if p not in puertos_despues]

        if not caducados:
            continue

        await amtd.check_port(caducados[0], IP_SIMULADO)
        intentos    += 1
        detecciones += 1 if alertas_ciclo else 0

    assert intentos > 0, "Ningún ciclo produjo puertos caducados"
    tasa = detecciones / intentos
    assert tasa == 1.0, \
        f"Detección no es consistente: {detecciones}/{intentos} = {tasa:.0%} — DEGRADACIÓN DETECTADA"

async def t_puertos_activos_no_afectados_por_rotacion():
    """
    Los puertos del ciclo ACTUAL no deben nunca marcarse como caducados,
    incluso habiendo rotado múltiples veces.
    """
    amtd, _, _ = await _setup_amtd_con_detector()
    for _ in range(3):
        await amtd.rotate_now()

    for puerto in amtd.current_ports():
        assert amtd.is_active_port(puerto), \
            f"Puerto activo {puerto} marcado como no activo tras múltiples rotaciones"
        assert not amtd.is_stale_port(puerto), \
            f"Puerto activo {puerto} marcado como caducado tras múltiples rotaciones"

async def t_log_rotaciones_completo():
    """Cada rotación genera 4 eventos en el log (PORT/ROUTE/TOKEN/STRUCT)."""
    import secrets
    amtd = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    N = 3
    for _ in range(N):
        await amtd.rotate_now()
    log = amtd.get_rotation_log()
    assert len(log) == N * 4, \
        f"Log incompleto: {len(log)} eventos para {N} rotaciones (esperado {N*4})"

test("MÚLTIPLES — Detección consistente en 5 ciclos consecutivos", t_deteccion_consistente_en_multiples_ciclos)
test("MÚLTIPLES — Puertos activos nunca marcados como caducados", t_puertos_activos_no_afectados_por_rotacion)
test("MÚLTIPLES — Log de rotaciones completo (4 eventos por ciclo)", t_log_rotaciones_completo)


# ─────────────────────────────────────────────
# BLOQUE 4 — TIEMPO DE RESPUESTA
# Verifica que la detección ocurre dentro de los límites temporales
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C2 — Bloque 4: Tiempo de Respuesta")
print("═══════════════════════════════════════════════════════")

async def t_deteccion_stale_en_menos_de_1s():
    """
    Desde el acceso a superficie caducada hasta la alerta:
    debe ocurrir en menos de 1 segundo — regla invariable de AEGIS.
    """
    import secrets
    amtd    = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    alertas = []

    async def cb(payload):
        alertas.append((payload, time.monotonic()))

    amtd.register_stale_access_callback(cb)

    puertos_antes = amtd.current_ports().copy()
    await amtd.rotate_now()
    puertos_despues = amtd.current_ports()
    caducados = [p for p in puertos_antes if p not in puertos_despues]

    if not caducados:
        return  # no hay caducados en este ciclo — skip

    t_inicio = time.monotonic()
    await amtd.check_port(caducados[0], IP_SIMULADO)
    t_alerta = alertas[0][1] if alertas else time.monotonic()

    elapsed_ms = (t_alerta - t_inicio) * 1000
    assert alertas, "No se generó alerta"
    assert elapsed_ms < 1000, \
        f"Alerta tardó {elapsed_ms:.1f}ms — supera límite de 1000ms"

async def t_rotacion_completa_en_menos_de_100ms():
    """
    La rotación de todos los motores simultáneos debe completarse
    en menos de 100ms — atomicidad de AMTD verificada.
    """
    import secrets
    amtd = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    t0   = time.monotonic()
    await amtd.rotate_now()
    elapsed_ms = (time.monotonic() - t0) * 1000
    assert elapsed_ms < 100, \
        f"Rotación tardó {elapsed_ms:.1f}ms — supera límite de 100ms"

test("TIEMPO — Detección de stale < 1 segundo (regla invariable)", t_deteccion_stale_en_menos_de_1s)
test("TIEMPO — Rotación completa < 100ms (atomicidad)", t_rotacion_completa_en_menos_de_100ms)


# ─────────────────────────────────────────────
# BLOQUE 5 — TOKEN LIFECYCLE
# Verifica que los tokens caducados son detectados correctamente
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA C2 — Bloque 5: Token Lifecycle")
print("═══════════════════════════════════════════════════════")

async def t_token_revocado_rechazado():
    """Token revocado por rotación no debe ser válido."""
    import secrets
    amtd  = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    token = amtd.issue_token("session_test")
    assert amtd.is_valid_token(token), "Token emitido no es válido"

    # Forzar caducidad
    amtd._token_engine._lifetime_cycles = 1
    amtd._token_engine.rotate()

    assert not amtd.is_valid_token(token), \
        "Token caducado sigue siendo válido — FALLO DE SEGURIDAD"
    assert amtd.is_revoked_token(token), \
        "Token caducado no está en lista de revocados"

async def t_token_renovado_invalida_anterior():
    """Renovar un token debe invalidar el anterior inmediatamente."""
    import secrets
    amtd      = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    token_old = amtd.issue_token("session_abc")
    token_new = amtd.renew_token(token_old)

    assert token_new is not None
    assert token_new != token_old
    assert amtd.is_valid_token(token_new), "Nuevo token no es válido"
    assert not amtd.is_valid_token(token_old), \
        "Token anterior sigue válido tras renovación — FALLO DE SEGURIDAD"
    assert amtd.is_revoked_token(token_old), \
        "Token anterior no revocado tras renovación"

async def t_token_inventado_rechazado():
    """Token fabricado que nunca fue emitido debe ser rechazado."""
    import secrets
    amtd         = AegisAMTD(rotation_interval_s=60, seed=secrets.token_bytes(32))
    token_falso  = secrets.token_hex(32)
    assert not amtd.is_valid_token(token_falso), \
        "Token inventado aceptado como válido — FALLO DE SEGURIDAD"

test("TOKEN — Revocado por rotación es rechazado", t_token_revocado_rechazado)
test("TOKEN — Renovación invalida token anterior", t_token_renovado_invalida_anterior)
test("TOKEN — Token inventado rechazado", t_token_inventado_rechazado)


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
    print("  CONCLUSIÓN DE RESILIENCIA:")
    print("  AEGIS detecta y responde correctamente a todos los")
    print("  accesos durante transiciones AMTD.")
    print("  La ventana de rotación NO produce silencio defensivo.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
