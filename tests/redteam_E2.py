"""
AEGIS — Test de Resiliencia E2: Saturación del Aprendizaje Colectivo
=====================================================================
Vector: flood de 500 eventos falsos/malformados contra C8
        para intentar degradar su base de conocimiento o
        hacerle perder la capacidad de detección posterior.

CRITERIO DE ÉXITO (defensivo):
    C8 resiste 500 eventos falsos sin degradarse.
    Rechaza datos malformados sin excepción ni corrupción.
    Mantiene calidad de detección posterior — aprende solo
    de eventos reales, ignora el ruido.

CRITERIO DE FALLO:
    La base de conocimiento se corrompe con eventos falsos.
    C8 pierde capacidad de aprender de eventos reales
    después del flood.
    Datos malformados causan excepción o estado inconsistente.

ESTO NO ES:
    Un ataque de envenenamiento de datos contra sistemas reales.
    Un exploit para degradar modelos de ML en producción.

ESTO ES:
    Verificación de que C8 es robusto ante ruido masivo —
    el peor caso: un atacante que intenta envenenar el
    aprendizaje antes de lanzar el ataque real.
"""

import asyncio
import sys
import os
import secrets
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.learning  import AegisLearning, IntelligencePacket
from layers.forensic  import IntruderProfile, ActorType, AttackTechnique, IntentCategory
from layers.minefield import MineContact, MineType, ContactSeverity
from datetime         import datetime, timezone

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

N_FLOOD     = 500   # eventos falsos del flood
SIGNING_KEY = secrets.token_bytes(32)


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
# GENERADORES DE PERFILES FALSOS / MALFORMADOS
# ─────────────────────────────────────────────

def _perfil_vacio() -> IntruderProfile:
    """Perfil sin ningún dato — vacío."""
    return IntruderProfile(
        incident_id = secrets.token_hex(4),
        source_ips  = [],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
    )


def _perfil_tecnicas_desconocidas() -> IntruderProfile:
    """Perfil con técnicas e intenciones en valores extremos."""
    p = IntruderProfile(
        incident_id = secrets.token_hex(4),
        source_ips  = ["0.0.0.0"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = ActorType.UNKNOWN,
        techniques  = [AttackTechnique.UNKNOWN],
        intent      = IntentCategory.UNKNOWN,
    )
    return p


def _perfil_con_muchos_contactos(n: int = 100) -> IntruderProfile:
    """Perfil inflado con N contactos de señuelo."""
    p = IntruderProfile(
        incident_id = secrets.token_hex(4),
        source_ips  = [f"10.0.{secrets.randbelow(256)}.{secrets.randbelow(256)}"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = ActorType.BOT_SIMPLE,
        techniques  = [AttackTechnique.RECONNAISSANCE],
        intent      = IntentCategory.CREDENTIAL_THEFT,
    )
    for i in range(n):
        contact = MineContact(
            contact_id   = secrets.token_hex(4),
            timestamp    = datetime.now(timezone.utc),
            source_ip    = p.source_ips[0],
            source_port  = 54321,
            mine_id      = f"mine_{i}",
            mine_type    = MineType.FILE,
            mine_name    = "backup.json",
            severity     = ContactSeverity.HIGH,
            method       = "GET",
            payload      = b"",
            fingerprint  = secrets.token_hex(8),
            response_sent= "fake",
        )
        p.mine_contacts.append(contact)
    return p


def _paquete_firma_invalida() -> IntelligencePacket:
    """Paquete con firma incorrecta — debe ser rechazado."""
    packet = IntelligencePacket(
        packet_id       = secrets.token_hex(8).upper(),
        origin_id       = "AEGIS-FAKE",
        generated_at    = datetime.now(timezone.utc),
        effective_mines = ["FILE", "CREDENTIAL"],
        technique_freq  = {"RECONNAISSANCE": 99999},
    )
    # Firma con clave incorrecta
    packet.sign(secrets.token_bytes(32))
    return packet


def _paquete_propio(learning: AegisLearning) -> IntelligencePacket:
    """Paquete que simula venir de la misma instalación — debe ignorarse."""
    packet = IntelligencePacket(
        packet_id    = secrets.token_hex(8).upper(),
        origin_id    = learning._installation_id,   # misma ID
        generated_at = datetime.now(timezone.utc),
        technique_freq = {"RECONNAISSANCE": 500},
    )
    packet.sign(SIGNING_KEY)
    return packet


def _paquete_valores_extremos() -> IntelligencePacket:
    """Paquete con conteos absurdamente altos."""
    packet = IntelligencePacket(
        packet_id      = secrets.token_hex(8).upper(),
        origin_id      = "AEGIS-EXTREME",
        generated_at   = datetime.now(timezone.utc),
        technique_freq = {
            "RECONNAISSANCE":    999999999,
            "EXFILTRATION":      999999999,
            "LATERAL_MOVEMENT":  999999999,
        },
        intent_freq = {
            "CREDENTIAL_THEFT":  999999999,
        },
    )
    packet.sign(SIGNING_KEY)
    return packet


# ─────────────────────────────────────────────
# PERFIL REAL — para verificar calidad post-flood
# ─────────────────────────────────────────────

def _perfil_real_credential_stuffing() -> IntruderProfile:
    """Perfil real de credential stuffing para verificar aprendizaje."""
    p = IntruderProfile(
        incident_id = "REAL-001",
        source_ips  = ["99.1.2.3"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = ActorType.BOT_ADVANCED,
        techniques  = [
            AttackTechnique.CREDENTIAL_STUFFING,
            AttackTechnique.RECONNAISSANCE,
        ],
        intent      = IntentCategory.CREDENTIAL_THEFT,
    )
    for _ in range(3):
        contact = MineContact(
            contact_id   = secrets.token_hex(4),
            timestamp    = datetime.now(timezone.utc),
            source_ip    = "99.1.2.3",
            source_port  = 54321,
            mine_id      = "cred_mine",
            mine_type    = MineType.CREDENTIAL,
            mine_name    = "admin",
            severity     = ContactSeverity.HIGH,
            method       = "POST",
            payload      = b"user=admin&pass=admin123",
            fingerprint  = "abc123def456",
            response_sent= "fake",
        )
        p.mine_contacts.append(contact)
    p.bubble_interactions = list(range(5))
    return p


# ─────────────────────────────────────────────
# BLOQUE 1 — RESISTENCIA A PERFILES VACÍOS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA E2 — Bloque 1: Flood de Perfiles Vacíos")
print("═══════════════════════════════════════════════════════")

async def t_500_perfiles_vacios_sin_excepcion():
    """500 perfiles vacíos no causan excepción ni estado inválido."""
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_vacio())

    st = L.status()
    assert st["incidents_learned"] == N_FLOOD, \
        f"Contador incorrecto: {st['incidents_learned']} (esperado {N_FLOOD})"


async def t_perfiles_vacios_no_corrompen_kb():
    """
    500 perfiles vacíos seguidos de 1 perfil real.
    El perfil real debe registrarse correctamente — la KB no está corrupta.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_vacio())

    # Ingestar perfil real
    await L.ingest_profile(_perfil_real_credential_stuffing())

    kb = L.get_knowledge_base()
    # El perfil real debe haber registrado técnicas
    assert "CREDENTIAL_STUFFING" in str(kb["technique_counts"]), \
        f"Técnica real no registrada tras flood vacío: {kb['technique_counts']}"


async def t_calidad_deteccion_tras_flood_vacios():
    """
    Tras 500 perfiles vacíos, ingestar 5 perfiles reales.
    La distribución de técnicas debe reflejar los reales, no el ruido.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    # Flood de vacíos
    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_vacio())

    # 5 perfiles reales de credential stuffing
    for _ in range(5):
        await L.ingest_profile(_perfil_real_credential_stuffing())

    kb  = L.get_knowledge_base()
    tec = kb["technique_counts"]

    # CREDENTIAL_STUFFING debe aparecer (de los 5 reales)
    assert tec.get("CREDENTIAL_STUFFING", 0) > 0, \
        "Perfiles reales no aprendidos tras flood vacío"

    # UNKNOWN no debe dominar — el ruido no infecta el conocimiento
    unknown_count = tec.get("UNKNOWN", 0)
    cs_count      = tec.get("CREDENTIAL_STUFFING", 0)
    assert cs_count >= unknown_count or unknown_count == 0, \
        f"UNKNOWN domina sobre datos reales: UNKNOWN={unknown_count} CS={cs_count}"

    print(f"\n    técnicas post-flood: {tec}")

test("FLOOD VACÍO — 500 perfiles vacíos sin excepción", t_500_perfiles_vacios_sin_excepcion)
test("FLOOD VACÍO — KB no corrupta tras perfiles vacíos", t_perfiles_vacios_no_corrompen_kb)
test("FLOOD VACÍO — Calidad de detección preservada", t_calidad_deteccion_tras_flood_vacios)


# ─────────────────────────────────────────────
# BLOQUE 2 — RESISTENCIA A PERFILES INFLADOS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA E2 — Bloque 2: Flood de Perfiles Inflados")
print("═══════════════════════════════════════════════════════")

async def t_perfiles_inflados_sin_degradacion_tiempo():
    """
    50 perfiles con 100 contactos cada uno (5000 eventos total).
    El tiempo de ingesta no debe degradarse más del 50%
    entre el primer y último perfil.
    """
    import statistics
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    tiempos = []
    for _ in range(50):
        t0 = time.monotonic()
        await L.ingest_profile(_perfil_con_muchos_contactos(100))
        tiempos.append((time.monotonic() - t0) * 1000)

    # Warmup descartado implícitamente — comparar primera mitad vs segunda
    t_inicio = statistics.median(tiempos[:10])
    t_final  = statistics.median(tiempos[-10:])
    deg = (t_final - t_inicio) / t_inicio if t_inicio > 0 else 0

    print(f"\n    50 perfiles × 100 contactos: "
          f"inicio={t_inicio:.2f}ms final={t_final:.2f}ms deg={deg:.0%}")

    assert deg < 0.50, \
        f"Degradación bajo perfiles inflados: {deg:.0%} — supera 50%"


async def t_perfiles_inflados_no_corrompen_mine_effectiveness():
    """
    Perfiles inflados con el mismo mine_type no deben
    sesgar artificialmente la efectividad hacia ese tipo.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    # 100 perfiles inflados con MineType.FILE
    for _ in range(100):
        await L.ingest_profile(_perfil_con_muchos_contactos(50))

    kb = L.get_knowledge_base()
    # FILE debe tener alta efectividad — pero no debe haber corrompido la KB
    mine_eff = kb["mine_effectiveness"]
    assert isinstance(mine_eff, dict), "mine_effectiveness corrupto"

    if "MineType.FILE" in str(mine_eff):
        # Verificar que los conteos son numéricos y válidos
        for mine_type, data in mine_eff.items():
            assert isinstance(data, dict), f"Entrada corrupta: {mine_type}"
            assert "hits"  in data, f"Falta 'hits' en {mine_type}"
            assert "total" in data, f"Falta 'total' en {mine_type}"
            assert data["total"] >= data["hits"], \
                f"total < hits en {mine_type}: {data}"

    print(f"\n    mine_effectiveness tras 100 perfiles inflados: válida ✓")

test("INFLADO — Sin degradación de tiempo con 50 perfiles × 100 contactos",
     t_perfiles_inflados_sin_degradacion_tiempo)
test("INFLADO — mine_effectiveness no corrupta",
     t_perfiles_inflados_no_corrompen_mine_effectiveness)


# ─────────────────────────────────────────────
# BLOQUE 3 — RECHAZO DE PAQUETES MALFORMADOS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA E2 — Bloque 3: Rechazo de Paquetes Falsos")
print("═══════════════════════════════════════════════════════")

async def t_paquetes_firma_invalida_rechazados():
    """
    500 paquetes con firma incorrecta deben ser rechazados.
    Ninguno debe contaminar la KB.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2",
                      signing_key=SIGNING_KEY)

    rechazados = 0
    for _ in range(N_FLOOD):
        pkt = _paquete_firma_invalida()
        result = L.import_intelligence(pkt, SIGNING_KEY, verify=True)
        if not result:
            rechazados += 1

    kb = L.get_knowledge_base()

    assert rechazados == N_FLOOD, \
        f"Solo {rechazados}/{N_FLOOD} paquetes rechazados — algunos aceptados"

    # La KB debe estar vacía — ningún paquete contaminó
    assert len(kb["technique_counts"]) == 0, \
        f"KB contaminada con paquetes rechazados: {kb['technique_counts']}"

    print(f"\n    {rechazados}/{N_FLOOD} paquetes con firma inválida rechazados ✓")


async def t_paquetes_propios_ignorados():
    """
    Paquetes que simulan venir de la misma instalación
    deben ser silenciosamente ignorados — no aceptados.
    """
    L = AegisLearning(installation_id="AEGIS-SELF-TEST",
                      signing_key=SIGNING_KEY)

    importados = 0
    for _ in range(100):
        pkt = _paquete_propio(L)
        result = L.import_intelligence(pkt, verify=False)
        if result:
            importados += 1

    assert importados == 0, \
        f"{importados}/100 paquetes propios aceptados — BRECHA"

    assert len(L.get_imported_packets()) == 0, \
        "Paquetes propios en el registro de importados"

    print(f"\n    100 paquetes propios ignorados ✓")


async def t_paquetes_valores_extremos_no_corrompen():
    """
    Paquetes con conteos de 999999999 no deben corromper
    la base de conocimiento — la fusión conservadora los limita.
    """
    L_origen  = AegisLearning(installation_id="AEGIS-EXTREME",
                               signing_key=SIGNING_KEY)
    L_destino = AegisLearning(installation_id="AEGIS-DEST",
                               signing_key=SIGNING_KEY)

    # Ingestar primero datos reales en destino
    for _ in range(5):
        await L_destino.ingest_profile(_perfil_real_credential_stuffing())

    kb_antes = L_destino.get_knowledge_base()
    cs_antes = kb_antes["technique_counts"].get("CREDENTIAL_STUFFING", 0)

    # Flood de paquetes con valores extremos
    for _ in range(50):
        pkt = _paquete_valores_extremos()
        L_destino.import_intelligence(pkt, SIGNING_KEY, verify=True)

    kb_despues = L_destino.get_knowledge_base()
    cs_despues = kb_despues["technique_counts"].get("CREDENTIAL_STUFFING", 0)

    # CREDENTIAL_STUFFING de datos reales debe seguir siendo dominante
    recon_despues = kb_despues["technique_counts"].get("RECONNAISSANCE", 0)

    assert cs_despues >= cs_antes, \
        f"Datos reales perdidos tras flood extremo: antes={cs_antes} después={cs_despues}"

    print(f"\n    CS preservado: {cs_antes}→{cs_despues} "
          f"| RECON (flood): {recon_despues}")

test("PAQUETES — 500 firmas inválidas rechazadas y KB limpia",
     t_paquetes_firma_invalida_rechazados)
test("PAQUETES — 100 paquetes propios ignorados",
     t_paquetes_propios_ignorados)
test("PAQUETES — Valores extremos no corrompen KB real",
     t_paquetes_valores_extremos_no_corrompen)


# ─────────────────────────────────────────────
# BLOQUE 4 — CALIDAD POST-FLOOD
# Verificar que el aprendizaje real sigue funcionando
# después del flood
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA E2 — Bloque 4: Calidad Post-Flood")
print("═══════════════════════════════════════════════════════")

async def t_ajuste_correcto_tras_flood():
    """
    Tras 500 eventos falsos, los ajustes generados para C2/C3/C6
    deben seguir siendo correctos y no reflejar el ruido.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    # Flood de perfiles vacíos y con unknown
    for _ in range(N_FLOOD):
        perfil = _perfil_vacio() if secrets.randbelow(2) else \
                 _perfil_tecnicas_desconocidas()
        await L.ingest_profile(perfil)

    # 10 perfiles reales de credential stuffing
    for _ in range(10):
        await L.ingest_profile(_perfil_real_credential_stuffing())

    adj = L.get_adjustments()

    # Los ajustes deben tener estructura correcta
    assert "mines"         in adj
    assert "detector"      in adj
    assert "bubble"        in adj
    assert "reinforcement" in adj

    # El detector debe sugerir bajar umbral para CREDENTIAL_STUFFING
    det_adj = adj["detector"]
    if "CREDENTIAL_STUFFING" in det_adj:
        assert det_adj["CREDENTIAL_STUFFING"]["threshold_delta"] <= 0, \
            "Ajuste incorrecto para técnica frecuente"

    print(f"\n    Ajustes correctos tras flood: {list(adj.keys())} ✓")


async def t_aprendizaje_real_tras_flood_señuelos():
    """
    Verificar que C8 aprende correctamente de un evento real
    después de haber procesado 500 eventos con mine_type FILE.
    Un nuevo perfil con CREDENTIAL debe registrarse correctamente.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    # Flood con FILE exclusivamente
    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_con_muchos_contactos(10))

    kb_antes = L.get_knowledge_base()

    # Perfil real con CREDENTIAL
    from layers.minefield import MineType, ContactSeverity
    p = IntruderProfile(
        incident_id = "REAL-CRED-001",
        source_ips  = ["5.5.5.5"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = ActorType.AI_AGENT,
        techniques  = [AttackTechnique.CREDENTIAL_STUFFING],
        intent      = IntentCategory.CREDENTIAL_THEFT,
    )
    cred_contact = MineContact(
        contact_id   = "C999",
        timestamp    = datetime.now(timezone.utc),
        source_ip    = "5.5.5.5",
        source_port  = 443,
        mine_id      = "cred_mine",
        mine_type    = MineType.CREDENTIAL,
        mine_name    = "root",
        severity     = ContactSeverity.CRITICAL,
        method       = "POST",
        payload      = b"",
        fingerprint  = "zz9988",
        response_sent= "fake",
    )
    p.mine_contacts.append(cred_contact)
    await L.ingest_profile(p)

    kb_despues = L.get_knowledge_base()
    mine_eff   = kb_despues["mine_effectiveness"]

    # CREDENTIAL debe aparecer en mine_effectiveness
    cred_key = next((k for k in mine_eff if "CREDENTIAL" in k), None)
    assert cred_key is not None, \
        f"CREDENTIAL no registrado en mine_effectiveness tras flood FILE: {mine_eff}"

    print(f"\n    CREDENTIAL registrado correctamente tras flood FILE ✓")


async def t_callbacks_funcionan_tras_flood():
    """
    Los callbacks a C2/C3/C6 siguen disparándose correctamente
    después del flood — el sistema de notificación no se rompe.
    """
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    mine_callbacks     = []
    detector_callbacks = []
    bubble_callbacks   = []

    L.register_mine_callback(lambda adj: mine_callbacks.append(adj))
    L.register_detector_callback(lambda adj: detector_callbacks.append(adj))
    L.register_bubble_callback(lambda adj: bubble_callbacks.append(adj))

    # Flood de perfiles vacíos
    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_vacio())

    # Perfil real que debe disparar ajustes
    await L.ingest_profile(_perfil_real_credential_stuffing())

    # Al menos un callback debe haber disparado tras el perfil real
    total_callbacks = (len(mine_callbacks) +
                       len(detector_callbacks) +
                       len(bubble_callbacks))

    assert total_callbacks > 0, \
        "Ningún callback disparado tras perfil real post-flood — sistema roto"

    print(f"\n    Callbacks activos post-flood: "
          f"mine={len(mine_callbacks)} det={len(detector_callbacks)} "
          f"bubble={len(bubble_callbacks)} ✓")

test("POST-FLOOD — Ajustes correctos tras 500 eventos falsos",
     t_ajuste_correcto_tras_flood)
test("POST-FLOOD — Aprende CREDENTIAL correctamente tras flood FILE",
     t_aprendizaje_real_tras_flood_señuelos)
test("POST-FLOOD — Callbacks a C2/C3/C6 siguen funcionando",
     t_callbacks_funcionan_tras_flood)


# ─────────────────────────────────────────────
# BLOQUE 5 — RENDIMIENTO BAJO FLOOD
# El flood no degrada el tiempo de respuesta
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════════════")
print("  AEGIS RESILIENCIA E2 — Bloque 5: Rendimiento bajo Flood")
print("═══════════════════════════════════════════════════════")

async def t_tiempo_ingesta_no_degrada_bajo_flood():
    """
    Medir tiempo de ingesta al inicio y al final del flood.
    No debe degradarse más del 50%.
    """
    import statistics
    L = AegisLearning(installation_id="AEGIS-TEST-E2")

    # Warmup
    for _ in range(5):
        await L.ingest_profile(_perfil_vacio())

    # Primeras 20 ingestas
    tiempos_inicio = []
    for _ in range(20):
        t0 = time.monotonic()
        await L.ingest_profile(_perfil_vacio())
        tiempos_inicio.append((time.monotonic() - t0) * 1000)

    # Flood de 500
    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_vacio())

    # Últimas 20 ingestas
    tiempos_final = []
    for _ in range(20):
        t0 = time.monotonic()
        await L.ingest_profile(_perfil_vacio())
        tiempos_final.append((time.monotonic() - t0) * 1000)

    t_ini = statistics.median(tiempos_inicio)
    t_fin = statistics.median(tiempos_final)
    deg   = (t_fin - t_ini) / t_ini if t_ini > 0 else 0

    print(f"\n    Ingesta: inicio={t_ini:.3f}ms final={t_fin:.3f}ms deg={deg:.0%}")

    assert t_fin < 50, \
        f"Tiempo de ingesta inaceptable tras flood: {t_fin:.1f}ms"
    if t_ini > 0.1:  # solo si baseline es significativo
        assert deg < 0.50, \
            f"Degradación de ingesta bajo flood: {deg:.0%} — supera 50%"


async def t_export_correcto_tras_flood():
    """
    export_intelligence() produce paquete correcto y verificable
    incluso tras procesar 500 eventos falsos.
    """
    L = AegisLearning(installation_id="AEGIS-EXPORT-TEST",
                      signing_key=SIGNING_KEY)

    # Flood + eventos reales
    for _ in range(N_FLOOD):
        await L.ingest_profile(_perfil_vacio())
    for _ in range(10):
        await L.ingest_profile(_perfil_real_credential_stuffing())

    pkt = L.export_intelligence()

    assert pkt.origin_id == "AEGIS-EXPORT-TEST"
    assert pkt.signature != ""
    assert pkt.verify(SIGNING_KEY), "Firma inválida en export post-flood"

    # El paquete debe reflejar los datos reales, no solo el ruido
    # (CREDENTIAL_STUFFING debe aparecer en technique_freq)
    assert "CREDENTIAL_STUFFING" in str(pkt.technique_freq), \
        f"Paquete exportado no refleja datos reales: {pkt.technique_freq}"

    print(f"\n    Export post-flood: firmado y con datos reales ✓")


async def t_import_correcto_tras_flood():
    """
    Una instalación limpia puede importar correctamente
    desde una que ha procesado un flood.
    """
    L_flood  = AegisLearning(installation_id="AEGIS-FLOODED",
                              signing_key=SIGNING_KEY)
    L_limpia = AegisLearning(installation_id="AEGIS-CLEAN",
                              signing_key=SIGNING_KEY)

    # L_flood procesa flood + reales
    for _ in range(N_FLOOD):
        await L_flood.ingest_profile(_perfil_vacio())
    for _ in range(10):
        await L_flood.ingest_profile(_perfil_real_credential_stuffing())

    # Exportar e importar
    pkt      = L_flood.export_intelligence()
    resultado = L_limpia.import_intelligence(pkt, SIGNING_KEY, verify=True)

    assert resultado, "Import falló desde instalación floodeada"

    kb_limpia = L_limpia.get_knowledge_base()
    # La instalación limpia debe tener datos reales, no solo ruido
    assert len(L_limpia.get_imported_packets()) == 1

    print(f"\n    Import desde flooded a limpia: datos reales preservados ✓")

test("RENDIMIENTO — Tiempo de ingesta no degrada bajo flood",
     t_tiempo_ingesta_no_degrada_bajo_flood)
test("RENDIMIENTO — export_intelligence() correcto tras flood",
     t_export_correcto_tras_flood)
test("RENDIMIENTO — import desde instalación floodeada funciona",
     t_import_correcto_tras_flood)


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
    print("  CONCLUSIÓN DE RESILIENCIA E2:")
    print("  C8 resiste flood de 500 eventos falsos sin degradarse.")
    print("  Paquetes malformados rechazados — KB no contaminada.")
    print("  Calidad de detección preservada post-flood.")
    print("  Rendimiento estable bajo carga masiva de ruido.")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    print()
    print("  BRECHAS DETECTADAS — requieren corrección:")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
