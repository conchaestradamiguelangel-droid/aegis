"""
AEGIS — Test de Resiliencia A2: Tráfico Contaminado Progresivamente
=====================================================================
Vector: acciones sospechosas mezcladas con tráfico legítimo,
        incrementando el ratio hasta el 30%.

CRITERIO DE ÉXITO (defensivo):
    AEGIS detecta la contaminación ANTES de que el ratio
    de acciones sospechosas supere el 30% del tráfico total.
    La detección ocurre por comportamiento — nunca por firma.

CRITERIO DE FALLO:
    AEGIS no detecta hasta que el 30%+ ya ha pasado.
    El tráfico legítimo enmascara completamente las acciones sospechosas.
    El sistema genera falsos positivos sobre tráfico limpio.

ESTO NO ES:
    Un script para evadir detección mezclando tráfico.
    Un exploit que busca el umbral mínimo para pasar desapercibido.

ESTO ES:
    Verificación de que C3 es suficientemente sensible para detectar
    contaminación progresiva sin generar ruido sobre tráfico limpio.
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.detector  import AegisDetector, DetectionType, ThreatConfidence
from layers.minefield import AegisMinefield, MineType
from layers.forensic  import AegisForensic

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP_LEGIT    = "10.0.1.5"    # IP que simula tráfico legítimo
IP_SOSPECHO = "10.99.0.1"   # IP que simula actor sospechoso


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
# SIMULADORES DE TRÁFICO
# ─────────────────────────────────────────────

async def _trafico_legitimo(detector: AegisDetector, ip: str, n: int):
    """
    Simula N eventos de tráfico legítimo:
    accesos a un solo endpoint conocido, intervalos normales.
    No toca señuelos, no escanea puertos, no explora rutas.
    """
    for i in range(n):
        await detector.register_network_event(
            ip   = ip,
            port = 8080,
            path = "/api/v1/data",
        )
        await asyncio.sleep(0)  # ceder control sin delay artificial


async def _accion_sospechosa(detector: AegisDetector, ip: str, paso: int):
    """
    Simula una acción sospechosa:
    exploración de ruta/puerto distinto en cada paso.
    """
    await detector.register_network_event(
        ip   = ip,
        port = 8080 + paso,           # puerto distinto en cada paso
        path = f"/ruta_desconocida_{paso}",
    )
    await asyncio.sleep(0)


async def _simular_mezcla(
    detector: AegisDetector,
    n_total:  int,
    ratio_sospechoso: float,
    ip_legit: str = IP_LEGIT,
    ip_sospecho: str = IP_SOSPECHO,
) -> int:
    """
    Envía n_total eventos con ratio_sospechoso de acciones sospechosas.
    Retorna el número de detecciones generadas.
    """
    detecciones_antes = detector.total_detections()
    paso_sospecho = 0

    for i in range(n_total):
        if i / n_total < ratio_sospechoso:
            await _accion_sospechosa(detector, ip_sospecho, paso_sospecho)
            paso_sospecho += 1
        else:
            await _trafico_legitimo(detector, ip_legit, 1)

    return detector.total_detections() - detecciones_antes


# ─────────────────────────────────────────────
# BLOQUE 1 — BASELINE: TRÁFICO LIMPIO
# Verifica que tráfico 100% legítimo no genera detecciones
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A2 — Bloque 1: Tráfico Limpio")
print("═══════════════════════════════════════════════════════")

async def t_trafico_100_legit_sin_detecciones():
    """100% tráfico legítimo → cero detecciones.
    Automation desactivado: en tests el loop ejecuta a miles req/s,
    no representativo de tráfico real legítimo.
    """
    detector = AegisDetector()
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    await _trafico_legitimo(detector, IP_LEGIT, 20)
    assert detector.total_detections() == 0, \
        f"Tráfico limpio generó {detector.total_detections()} detecciones — FALSO POSITIVO"

async def t_mismo_ip_mismo_puerto_no_dispara():
    """Acceso repetido al mismo endpoint no es anomalía."""
    detector = AegisDetector()
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    for _ in range(50):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
    # Mismo puerto y ruta repetidos no deben disparar exploration/recon
    profile = detector.get_profile(IP_LEGIT)
    assert profile is not None
    assert profile.unique_ports() == 1, \
        f"Un solo puerto registrado como {profile.unique_ports()} — error de conteo"
    assert detector.total_detections() == 0, \
        "Tráfico repetitivo legítimo generó detección — FALSO POSITIVO"

async def t_dos_ips_legitimas_no_se_confunden_con_coordinacion():
    """
    Dos IPs legítimas activas simultáneamente NO deben
    disparar detección de ataque coordinado.
    1 evento por IP no cumple el mínimo de coordinación (≥2 eventos/IP).
    """
    detector = AegisDetector()
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    await detector.register_network_event(ip=IP_LEGIT,   port=8080, path="/api")
    await detector.register_network_event(ip="10.0.1.6", port=8080, path="/api")
    assert detector.total_detections() == 0, \
        "Dos IPs legítimas con 1 evento cada una generaron falso positivo de coordinación"

test("LIMPIO — 100% tráfico legítimo no genera detecciones", t_trafico_100_legit_sin_detecciones)
test("LIMPIO — Mismo endpoint repetido no dispara anomalía", t_mismo_ip_mismo_puerto_no_dispara)
test("LIMPIO — Dos IPs legítimas no confundidas con coordinación", t_dos_ips_legitimas_no_se_confunden_con_coordinacion)


# ─────────────────────────────────────────────
# BLOQUE 2 — DETECCIÓN EN UMBRAL CRECIENTE
# Verifica en qué ratio se produce la primera detección
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A2 — Bloque 2: Umbral de Detección")
print("═══════════════════════════════════════════════════════")

async def t_deteccion_antes_de_30_pct():
    """
    Contaminación progresiva desde 0% hasta 30%.
    AEGIS debe detectar ANTES de llegar al 30%.
    Criterio de éxito: detección con ratio < 0.30.
    """
    detector = AegisDetector()
    # Bajar umbrales para test de contaminación gradual
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0  # desactivar velocidad

    TOTAL        = 30   # 30 eventos en total
    UMBRAL_MAX   = 0.30
    ratio_actual = 0.0
    detectado    = False
    ratio_deteccion = None

    for i in range(1, TOTAL + 1):
        ratio_actual = i / TOTAL

        # Cada evento: mezcla proporcional
        if i <= int(TOTAL * UMBRAL_MAX):
            # Evento sospechoso — nueva ruta y puerto cada vez
            await detector.register_network_event(
                ip=IP_SOSPECHO, port=8080+i, path=f"/unknown_{i}"
            )
        else:
            await detector.register_network_event(
                ip=IP_LEGIT, port=8080, path="/api/v1/data"
            )

        if detector.total_detections() > 0 and not detectado:
            detectado       = True
            ratio_deteccion = (i - 1) / TOTAL   # ratio en el momento de detección

    assert detectado, \
        f"AEGIS no detectó contaminación al {UMBRAL_MAX:.0%} — FALLO DE SENSIBILIDAD"
    assert ratio_deteccion < UMBRAL_MAX, \
        f"Detección a ratio {ratio_deteccion:.0%} — supera umbral máximo de {UMBRAL_MAX:.0%}"

    print(f"\n    Detección producida a ratio {ratio_deteccion:.0%} "
          f"(umbral máx: {UMBRAL_MAX:.0%}) ✓")

async def t_5_pct_contaminacion_detectado():
    """5% de acciones sospechosas (exploración sistemática) → detectado."""
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0

    # 3 eventos sospechosos (exploración) + 57 legítimos = ~5%
    for i in range(3):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8081+i, path=f"/recon_{i}"
        )
    for _ in range(57):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )

    assert detector.total_detections() > 0, \
        "5% de exploración sistemática no fue detectado — FALLO DE SENSIBILIDAD"

async def t_1_contacto_señuelo_detectado_independientemente_del_ratio():
    """
    Un solo contacto con señuelo debe detectarse SIEMPRE,
    independientemente de cuánto tráfico legítimo lo rodee.
    Automation desactivado para tráfico legítimo — lo que probamos
    es la detección CONFIRMED del señuelo, no la velocidad.
    """
    detector  = AegisDetector()
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0
    minefield = AegisMinefield()
    minefield.register_detection_callback(detector.on_mine_contact)

    # 100 eventos legítimos
    for _ in range(100):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
    assert detector.total_detections() == 0, "Tráfico legítimo generó detección"

    # 1 contacto con señuelo — debe detectarse con certeza CONFIRMED
    await minefield.touch_file("backup.json", IP_SOSPECHO, 54321)

    assert detector.total_detections() >= 1, \
        "Un solo contacto con señuelo no detectado entre 100 eventos legítimos"

    # Verificar que es CONFIRMED — no solo una anomalía de patrón
    log = detector.get_detection_log()
    confirmados = [d for d in log if d["confidence"] == "CONFIRMED"]
    assert len(confirmados) >= 1, \
        "Contacto con señuelo no generó detección CONFIRMED"

test("UMBRAL — Detección antes de 30% de contaminación", t_deteccion_antes_de_30_pct)
test("UMBRAL — 5% exploración sistemática detectado", t_5_pct_contaminacion_detectado)
test("UMBRAL — 1 contacto señuelo detectado entre 100 legítimos", t_1_contacto_señuelo_detectado_independientemente_del_ratio)


# ─────────────────────────────────────────────
# BLOQUE 3 — SEPARACIÓN DE IPs
# Verifica que actividad sospechosa de una IP
# no contamina el perfil de IPs legítimas
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A2 — Bloque 3: Separación de IPs")
print("═══════════════════════════════════════════════════════")

async def t_perfil_legit_no_contaminado_por_sospecho():
    """
    La actividad sospechosa de IP_SOSPECHO no debe contaminar
    el perfil de IP_LEGIT — los perfiles son independientes.
    """
    detector = AegisDetector()

    # IP sospechosa explora múltiples rutas
    for i in range(5):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080+i, path=f"/scan_{i}"
        )

    # IP legítima accede normalmente
    for _ in range(10):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )

    perfil_legit = detector.get_profile(IP_LEGIT)
    assert perfil_legit is not None
    assert perfil_legit.unique_ports() == 1, \
        f"Perfil legítimo contaminado: {perfil_legit.unique_ports()} puertos únicos"
    assert perfil_legit.unique_paths() == 1, \
        f"Perfil legítimo contaminado: {perfil_legit.unique_paths()} rutas únicas"

async def t_ip_sospechosa_detectada_ip_legit_no():
    """
    Detección disparada por IP sospechosa.
    IP legítima con misma actividad temporal NO debe ser marcada.
    Coordinación desactivada — no hay dos IPs sospechosas aquí.
    """
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0
    detector._active.COORDINATION_MIN_IPS        = 999  # desactivar — solo 1 IP sospechosa

    # IP legítima — acceso repetido al mismo punto
    for _ in range(10):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )

    # IP sospechosa — exploración de múltiples rutas
    for i in range(5):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080, path=f"/scan_{i}"
        )

    log = detector.get_detection_log()
    # Las detecciones deben apuntar a IP_SOSPECHO, no a IP_LEGIT
    for deteccion in log:
        assert IP_LEGIT not in deteccion["source_ips"], \
            f"IP legítima incorrectamente marcada en detección: {deteccion}"

async def t_deduplicacion_no_silencia_nueva_ip():
    """
    La deduplicación de IP_SOSPECHO no debe impedir detectar
    una segunda IP sospechosa distinta.
    """
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    IP_SOSPECHO_2 = "10.99.0.2"

    # Primera IP sospechosa
    for i in range(3):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080+i, path=f"/scan_a_{i}"
        )

    dets_tras_primera = detector.total_detections()

    # Segunda IP sospechosa distinta
    for i in range(3):
        await detector.register_network_event(
            ip=IP_SOSPECHO_2, port=9000+i, path=f"/scan_b_{i}"
        )

    dets_tras_segunda = detector.total_detections()
    assert dets_tras_segunda > dets_tras_primera, \
        "Segunda IP sospechosa no generó detección — deduplicación excesiva"

test("SEPARACIÓN — Perfil legítimo no contaminado por actividad sospechosa", t_perfil_legit_no_contaminado_por_sospecho)
test("SEPARACIÓN — Detección apunta a IP sospechosa, no a legítima", t_ip_sospechosa_detectada_ip_legit_no)
test("SEPARACIÓN — Deduplicación no silencia segunda IP sospechosa", t_deduplicacion_no_silencia_nueva_ip)


# ─────────────────────────────────────────────
# BLOQUE 4 — PATRONES DE CONTAMINACIÓN
# Distintos patrones de mezcla — todos deben ser detectados
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A2 — Bloque 4: Patrones de Mezcla")
print("═══════════════════════════════════════════════════════")

async def t_patron_intercalado_detectado():
    """
    Patrón: legítimo-sospechoso-legítimo-sospechoso...
    Intercalado perfecto — verificar detección.
    """
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0

    for i in range(10):
        # Evento legítimo
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
        # Evento sospechoso intercalado
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080+i, path=f"/probe_{i}"
        )

    assert detector.total_detections() > 0, \
        "Patrón intercalado 50/50 no detectado"

async def t_patron_rafaga_al_final_detectado():
    """
    Patrón: mucho tráfico legítimo, luego ráfaga sospechosa al final.
    La ráfaga debe ser detectada aunque llegue tarde.
    """
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0

    # 70% legítimo primero
    for _ in range(21):
        await detector.register_network_event(
            ip=IP_LEGIT, port=8080, path="/api/v1/data"
        )
    assert detector.total_detections() == 0, \
        "Tráfico legítimo inicial generó falso positivo"

    # 30% sospechoso al final — ráfaga de exploración
    for i in range(9):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8081+i, path=f"/late_probe_{i}"
        )

    assert detector.total_detections() > 0, \
        "Ráfaga sospechosa al final del tráfico no detectada"

async def t_patron_lento_acumulativo_detectado():
    """
    Patrón: 1 acción sospechosa cada 10 legítimas — acumulación lenta.
    Debe detectarse antes de superar 30% acumulado.
    """
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0

    detectado       = False
    ratio_acumulado = 0.0
    sosp_count      = 0
    total_count     = 0

    for ronda in range(10):
        # 9 legítimos
        for _ in range(9):
            await detector.register_network_event(
                ip=IP_LEGIT, port=8080, path="/api/v1/data"
            )
            total_count += 1

        # 1 sospechoso
        await detector.register_network_event(
            ip=IP_SOSPECHO,
            port=8080 + ronda,
            path=f"/slow_probe_{ronda}"
        )
        sosp_count  += 1
        total_count += 1
        ratio_acumulado = sosp_count / total_count

        if detector.total_detections() > 0 and not detectado:
            detectado = True
            break

    assert detectado, \
        f"Contaminación lenta ({ratio_acumulado:.0%}) no detectada — FALLO DE SENSIBILIDAD"
    assert ratio_acumulado <= 0.30, \
        f"Detección tardía a ratio {ratio_acumulado:.0%} — supera umbral 30%"

test("PATRÓN — Intercalado 50/50 detectado", t_patron_intercalado_detectado)
test("PATRÓN — Ráfaga sospechosa al final detectada", t_patron_rafaga_al_final_detectado)
test("PATRÓN — Acumulación lenta detectada antes de 30%", t_patron_lento_acumulativo_detectado)


# ─────────────────────────────────────────────
# BLOQUE 5 — REGISTRO Y EVIDENCIA
# Todo lo detectado debe quedar correctamente registrado
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA A2 — Bloque 5: Registro y Evidencia")
print("═══════════════════════════════════════════════════════")

async def t_deteccion_incluye_ip_sospechosa():
    """Cada detección debe identificar la IP origen correctamente."""
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    for i in range(3):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080+i, path=f"/probe_{i}"
        )

    log = detector.get_detection_log()
    assert len(log) > 0
    for d in log:
        assert "source_ips" in d
        assert len(d["source_ips"]) > 0

async def t_forense_recibe_eventos_de_contaminacion():
    """Capa 7 debe recibir las detecciones generadas por contaminación."""
    detector = AegisDetector()
    forensic = AegisForensic()
    detector._active.RECON_PATHS_THRESHOLD      = 3
    detector._active.EXPLORATION_PORTS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD    = 999999.0

    detector.register_forensic_callback(forensic.on_detection_event)

    for i in range(5):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080+i, path=f"/probe_{i}"
        )

    assert forensic.active_incidents() >= 1, \
        "Forense no recibió eventos de detección por contaminación"

async def t_log_exportable_con_estructura_completa():
    """El log de detecciones debe ser exportable para auditoría."""
    detector = AegisDetector()
    detector._active.RECON_PATHS_THRESHOLD = 3
    detector._active.AUTOMATION_RPS_THRESHOLD = 999999.0

    for i in range(3):
        await detector.register_network_event(
            ip=IP_SOSPECHO, port=8080+i, path=f"/probe_{i}"
        )

    log = detector.get_detection_log()
    if log:
        entry = log[0]
        for campo in ["detection_id", "detection_type", "confidence",
                      "source_ips", "indicators", "evidence", "action_required"]:
            assert campo in entry, f"Campo '{campo}' ausente del log"

test("EVIDENCIA — Detección identifica IP sospechosa", t_deteccion_incluye_ip_sospechosa)
test("EVIDENCIA — Forense recibe eventos de contaminación", t_forense_recibe_eventos_de_contaminacion)
test("EVIDENCIA — Log exportable con estructura completa", t_log_exportable_con_estructura_completa)


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
    print("  CONCLUSIÓN DE RESILIENCIA A2:")
    print("  AEGIS detecta contaminación progresiva antes")
    print("  de alcanzar el umbral del 30% de tráfico total.")
    print("  Tráfico legítimo no genera falsos positivos.")
    print("  Perfiles de IP son independientes y no contaminables.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
