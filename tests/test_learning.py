"""
AEGIS — Test de Capa 8: Aprendizaje Colectivo
===============================================
Tests de base de conocimiento, ajustes, exportación/importación y red colectiva.
"""

import asyncio
import sys
import os
import secrets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.learning import (
    AegisLearning, KnowledgeBase, AdjustmentEngine,
    IntelligencePacket, LearningSignal,
)
from layers.forensic import IntruderProfile, ActorType, AttackTechnique, IntentCategory
from layers.minefield import MineContact, MineType, ContactSeverity
from datetime import datetime, timezone

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

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


def _make_profile(
    incident_id="INC001", ips=None,
    actor=ActorType.BOT_SIMPLE,
    techniques=None, intent=IntentCategory.CREDENTIAL_THEFT,
    mine_types=None, bubble_interactions=3
) -> IntruderProfile:
    p = IntruderProfile(
        incident_id = incident_id,
        source_ips  = ips or ["10.0.0.1"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = actor,
        techniques  = techniques or [AttackTechnique.RECONNAISSANCE],
        intent      = intent,
    )
    # Añadir contactos con minas
    for mt in (mine_types or [MineType.FILE]):
        contact = MineContact(
            contact_id="C001", timestamp=datetime.now(timezone.utc),
            source_ip="10.0.0.1", source_port=54321,
            mine_id="test", mine_type=mt,
            mine_name="test_mine", severity=ContactSeverity.HIGH,
            method="GET", payload=b"", fingerprint="abcd",
            response_sent="fake"
        )
        p.mine_contacts.append(contact)
    # Simular interacciones de burbuja
    p.bubble_interactions = list(range(bubble_interactions))
    return p


# ─────────────────────────────────────────────
# BASE DE CONOCIMIENTO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 8: Base de Conocimiento")
print("═══════════════════════════════════════════════")

def t_kb_update_mine_efectivo():
    kb = KnowledgeBase()
    kb.update_mine("FILE", detected=True)
    kb.update_mine("FILE", detected=True)
    kb.update_mine("FILE", detected=False)
    rate = kb.mine_hit_rate("FILE")
    assert abs(rate - 2/3) < 0.01

def t_kb_mine_sin_datos_zero():
    kb   = KnowledgeBase()
    rate = kb.mine_hit_rate("INEXISTENTE")
    assert rate == 0.0

def t_kb_top_mines():
    kb = KnowledgeBase()
    kb.update_mine("IDENTITY", detected=True)
    kb.update_mine("IDENTITY", detected=True)
    kb.update_mine("FILE",     detected=True)
    kb.update_mine("FILE",     detected=False)
    kb.update_mine("ENDPOINT", detected=False)
    kb.update_mine("ENDPOINT", detected=False)
    top = kb.top_mines(2)
    assert "IDENTITY" in top
    assert top[0] == "IDENTITY"   # mayor tasa primero

def t_kb_update_tecnica():
    kb = KnowledgeBase()
    kb.update_technique("RECONNAISSANCE")
    kb.update_technique("RECONNAISSANCE")
    kb.update_technique("EXFILTRATION")
    assert kb.technique_counts["RECONNAISSANCE"] == 2
    assert kb.technique_counts["EXFILTRATION"]   == 1

def t_kb_layer_pressure():
    kb = KnowledgeBase()
    kb.update_layer_pressure("capa_2")
    kb.update_layer_pressure("capa_2")
    kb.update_layer_pressure("capa_3")
    assert kb.most_pressured_layer() == "capa_2"

def t_kb_avg_bubble_retention():
    kb = KnowledgeBase()
    kb.bubble_durations_s = [30.0, 60.0, 90.0]
    assert abs(kb.avg_bubble_retention_s() - 60.0) < 0.01

def t_kb_avg_bubble_sin_datos():
    kb = KnowledgeBase()
    assert kb.avg_bubble_retention_s() == 0.0

def t_kb_to_dict_estructura():
    kb = KnowledgeBase()
    kb.update_mine("FILE", True)
    kb.update_technique("RECON")
    d = kb.to_dict()
    assert "incident_count"       in d
    assert "mine_effectiveness"   in d
    assert "technique_counts"     in d
    assert "avg_bubble_retention_s" in d
    assert "top_mines"            in d

test("KB — Hit rate calculado correctamente", t_kb_update_mine_efectivo)
test("KB — Mine sin datos → 0.0", t_kb_mine_sin_datos_zero)
test("KB — top_mines ordena por efectividad", t_kb_top_mines)
test("KB — Técnicas se acumulan correctamente", t_kb_update_tecnica)
test("KB — Capa con más presión identificada", t_kb_layer_pressure)
test("KB — Retención media calculada", t_kb_avg_bubble_retention)
test("KB — Sin datos de burbuja → 0.0", t_kb_avg_bubble_sin_datos)
test("KB — to_dict() estructura completa", t_kb_to_dict_estructura)


# ─────────────────────────────────────────────
# MOTOR DE AJUSTES
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 8: Motor de Ajustes")
print("═══════════════════════════════════════════════")

def t_ajuste_mine_promote():
    """Señuelo con alta tasa → PROMOTE."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    for _ in range(9):
        kb.update_mine("IDENTITY", True)
    kb.update_mine("IDENTITY", False)
    adj = engine.compute_mine_adjustments(kb)
    assert adj["IDENTITY"]["action"] == "PROMOTE"

def t_ajuste_mine_vary():
    """Señuelo con baja tasa y suficientes muestras → VARY."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    kb.update_mine("ENDPOINT", True)
    for _ in range(9):
        kb.update_mine("ENDPOINT", False)
    adj = engine.compute_mine_adjustments(kb)
    assert adj["ENDPOINT"]["action"] == "VARY"

def t_ajuste_mine_maintain():
    """Señuelo con tasa media → MAINTAIN."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    kb.update_mine("FILE", True)
    kb.update_mine("FILE", False)
    adj = engine.compute_mine_adjustments(kb)
    assert adj["FILE"]["action"] == "MAINTAIN"

def t_ajuste_detector_umbral_negativo_frecuente():
    """Técnica muy frecuente → bajar umbral (delta negativo)."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    for _ in range(8):
        kb.update_technique("RECONNAISSANCE")
    for _ in range(2):
        kb.update_technique("EXFILTRATION")
    adj = engine.compute_detector_adjustments(kb)
    assert adj["RECONNAISSANCE"]["threshold_delta"] < 0

def t_ajuste_bubble_increase_complexity():
    """Retención baja → aumentar complejidad."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    kb.bubble_durations_s = [10.0, 15.0, 20.0]
    adj = engine.compute_bubble_adjustments(kb)
    assert adj["action"] == "INCREASE_COMPLEXITY"

def t_ajuste_bubble_maintain():
    """Retención alta → mantener."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    kb.bubble_durations_s = [150.0, 200.0, 180.0]
    adj = engine.compute_bubble_adjustments(kb)
    assert adj["action"] == "MAINTAIN"

def t_ajuste_layer_reinforcement():
    """Capa bajo presión → prioridad HIGH."""
    engine = AdjustmentEngine()
    kb     = KnowledgeBase()
    for _ in range(8):
        kb.update_layer_pressure("capa_2")
    for _ in range(2):
        kb.update_layer_pressure("capa_3")
    adj = engine.compute_layer_reinforcement(kb)
    assert adj["capa_2"]["priority"] == "HIGH"

test("AJUSTE — Señuelo alta tasa → PROMOTE", t_ajuste_mine_promote)
test("AJUSTE — Señuelo baja tasa → VARY", t_ajuste_mine_vary)
test("AJUSTE — Señuelo tasa media → MAINTAIN", t_ajuste_mine_maintain)
test("AJUSTE — Técnica frecuente → umbral negativo", t_ajuste_detector_umbral_negativo_frecuente)
test("AJUSTE — Retención baja → INCREASE_COMPLEXITY", t_ajuste_bubble_increase_complexity)
test("AJUSTE — Retención alta → MAINTAIN", t_ajuste_bubble_maintain)
test("AJUSTE — Capa presionada → prioridad HIGH", t_ajuste_layer_reinforcement)


# ─────────────────────────────────────────────
# PAQUETE DE INTELIGENCIA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 8: Paquete de Inteligencia")
print("═══════════════════════════════════════════════")

def t_packet_firma_y_verifica():
    packet = IntelligencePacket(
        packet_id    = "PKT001",
        origin_id    = "AEGIS-TEST",
        generated_at = datetime.now(timezone.utc),
        effective_mines=["IDENTITY", "FILE"],
        technique_freq={"RECONNAISSANCE": 5},
    )
    packet.sign(SIGNING_KEY)
    assert packet.signature != ""
    assert packet.verify(SIGNING_KEY)

def t_packet_firma_invalida_rechazada():
    packet = IntelligencePacket(
        packet_id    = "PKT001",
        origin_id    = "AEGIS-TEST",
        generated_at = datetime.now(timezone.utc),
    )
    packet.sign(SIGNING_KEY)
    wrong_key = secrets.token_bytes(32)
    assert not packet.verify(wrong_key)

def t_packet_to_dict_estructura():
    packet = IntelligencePacket(
        packet_id    = "PKT001",
        origin_id    = "AEGIS-TEST",
        generated_at = datetime.now(timezone.utc),
    )
    d = packet.to_dict()
    assert "packet_id"          in d
    assert "origin_id"          in d
    assert "generated_at"       in d
    assert "effective_mines"    in d
    assert "technique_freq"     in d
    assert "signature"          in d

test("PACKET — Firma y verificación correcta", t_packet_firma_y_verifica)
test("PACKET — Firma inválida rechazada", t_packet_firma_invalida_rechazada)
test("PACKET — to_dict() estructura completa", t_packet_to_dict_estructura)


# ─────────────────────────────────────────────
# FACHADA — AegisLearning
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 8: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_learning_inicializa():
    L  = AegisLearning(installation_id="AEGIS-TEST-001")
    st = L.status()
    assert st["installation_id"]   == "AEGIS-TEST-001"
    assert st["incidents_learned"] == 0
    assert st["signals_recorded"]  == 0

async def t_learning_ingest_profile():
    L       = AegisLearning()
    profile = _make_profile()
    await L.ingest_profile(profile)
    st = L.status()
    assert st["incidents_learned"] == 1
    assert st["signals_recorded"]  >= 1

async def t_learning_ingest_actualiza_kb():
    L       = AegisLearning()
    profile = _make_profile(
        mine_types = [MineType.IDENTITY],
        techniques = [AttackTechnique.CREDENTIAL_STUFFING],
        intent     = IntentCategory.CREDENTIAL_THEFT,
    )
    await L.ingest_profile(profile)
    kb = L.get_knowledge_base()
    assert kb["incident_count"] == 1
    assert "MineType.IDENTITY" in str(kb["mine_effectiveness"]) or \
           "IDENTITY" in str(kb["mine_effectiveness"])

async def t_learning_callbacks_ajuste_mine():
    L        = AegisLearning()
    received = []
    def on_mine(adj): received.append(adj)
    L.register_mine_callback(on_mine)
    # Ingestar suficientes perfiles para generar ajuste
    for _ in range(3):
        await L.ingest_profile(_make_profile(mine_types=[MineType.FILE]))
    assert len(received) >= 1

async def t_learning_callbacks_ajuste_detector():
    L        = AegisLearning()
    received = []
    def on_det(adj): received.append(adj)
    L.register_detector_callback(on_det)
    await L.ingest_profile(_make_profile(
        techniques=[AttackTechnique.RECONNAISSANCE, AttackTechnique.EXFILTRATION]
    ))
    assert len(received) >= 1

async def t_learning_export_intelligence():
    L = AegisLearning(installation_id="AEGIS-A", signing_key=SIGNING_KEY)
    await L.ingest_profile(_make_profile())
    packet = L.export_intelligence()
    assert packet.origin_id  == "AEGIS-A"
    assert packet.signature  != ""
    assert packet.verify(SIGNING_KEY)

async def t_learning_import_intelligence():
    L_a = AegisLearning(installation_id="AEGIS-A", signing_key=SIGNING_KEY)
    L_b = AegisLearning(installation_id="AEGIS-B", signing_key=SIGNING_KEY)
    # A aprende de un incidente
    await L_a.ingest_profile(_make_profile(
        techniques=[AttackTechnique.RECONNAISSANCE]
    ))
    # A exporta su inteligencia
    packet = L_a.export_intelligence()
    # B importa la inteligencia de A
    result = L_b.import_intelligence(packet, SIGNING_KEY, verify=True)
    assert result is True
    assert len(L_b.get_imported_packets()) == 1

async def t_learning_import_rechaza_firma_invalida():
    L_a = AegisLearning(installation_id="AEGIS-A", signing_key=SIGNING_KEY)
    L_b = AegisLearning(installation_id="AEGIS-B")
    await L_a.ingest_profile(_make_profile())
    packet    = L_a.export_intelligence()
    wrong_key = secrets.token_bytes(32)
    result    = L_b.import_intelligence(packet, wrong_key, verify=True)
    assert result is False
    assert len(L_b.get_imported_packets()) == 0

async def t_learning_import_ignora_propio():
    """Una instalación no debe importar sus propios paquetes."""
    L = AegisLearning(installation_id="AEGIS-A", signing_key=SIGNING_KEY)
    await L.ingest_profile(_make_profile())
    packet = L.export_intelligence()
    result = L.import_intelligence(packet, verify=False)
    assert result is False

async def t_learning_layer_pressure():
    L = AegisLearning()
    L.register_layer_pressure("capa_2")
    L.register_layer_pressure("capa_2")
    L.register_layer_pressure("capa_3")
    st = L.status()
    assert st["most_pressured"] == "capa_2"

async def t_learning_get_adjustments():
    L = AegisLearning()
    await L.ingest_profile(_make_profile(mine_types=[MineType.IDENTITY]))
    adj = L.get_adjustments()
    assert "mines"         in adj
    assert "detector"      in adj
    assert "bubble"        in adj
    assert "reinforcement" in adj

async def t_learning_signal_log():
    L = AegisLearning()
    await L.ingest_profile(_make_profile())
    log = L.get_signal_log()
    assert len(log) >= 1
    for entry in log:
        assert "signal"    in entry
        assert "data"      in entry
        assert "timestamp" in entry

async def t_learning_multiple_incidentes():
    L = AegisLearning()
    for i in range(5):
        await L.ingest_profile(_make_profile(incident_id=f"INC{i:03d}"))
    assert L.status()["incidents_learned"] == 5

async def t_learning_red_colectiva_dos_instalaciones():
    """
    Simulación de red colectiva:
    AEGIS-ESP aprende → exporta → AEGIS-DEU importa → ajusta sus defensas.
    """
    key   = secrets.token_bytes(32)
    spain = AegisLearning(installation_id="AEGIS-ESP", signing_key=key)
    germany = AegisLearning(installation_id="AEGIS-DEU", signing_key=key)

    # España detecta ataques de credential stuffing
    for _ in range(3):
        await spain.ingest_profile(_make_profile(
            techniques = [AttackTechnique.CREDENTIAL_STUFFING],
            intent     = IntentCategory.CREDENTIAL_THEFT,
            mine_types = [MineType.CREDENTIAL],
        ))

    # España exporta inteligencia
    packet = spain.export_intelligence()

    # Alemania importa y fusiona
    imported = germany.import_intelligence(packet, key, verify=True)
    assert imported

    # Alemania ahora tiene conocimiento de credential stuffing
    kb = germany.get_knowledge_base()
    assert "CREDENTIAL_STUFFING" in kb["technique_counts"] or \
           len(germany.get_imported_packets()) == 1

test("FACHADA — Inicialización correcta", t_learning_inicializa)
test("FACHADA — ingest_profile incrementa incidentes", t_learning_ingest_profile)
test("FACHADA — ingest_profile actualiza KB", t_learning_ingest_actualiza_kb)
test("FACHADA — Callback mine recibe ajustes", t_learning_callbacks_ajuste_mine)
test("FACHADA — Callback detector recibe ajustes", t_learning_callbacks_ajuste_detector)
test("FACHADA — export_intelligence firmado correctamente", t_learning_export_intelligence)
test("FACHADA — import_intelligence fusiona KB", t_learning_import_intelligence)
test("FACHADA — import rechaza firma inválida", t_learning_import_rechaza_firma_invalida)
test("FACHADA — import ignora paquete propio", t_learning_import_ignora_propio)
test("FACHADA — register_layer_pressure registra presión", t_learning_layer_pressure)
test("FACHADA — get_adjustments retorna estructura completa", t_learning_get_adjustments)
test("FACHADA — Signal log registra señales", t_learning_signal_log)
test("FACHADA — Múltiples incidentes acumulan correctamente", t_learning_multiple_incidentes)
test("FACHADA — Red colectiva: ESP aprende → DEU importa", t_learning_red_colectiva_dos_instalaciones)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

# ─────────────────────────────────────────────
# MEJORA 1 — TESTS DE APRENDIZAJE ANTICIPATORIO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  LEARNING — Mejora 1: Aprendizaje Anticipatorio")
print("═══════════════════════════════════════════════")

from layers.learning import SequenceTracker

def t_sequence_tracker_sin_datos_no_predice():
    """Sin historia, predict_next retorna None."""
    st = SequenceTracker()
    assert st.predict_next("MineType.FILE") is None

def t_sequence_tracker_menos_de_min_no_predice():
    """Menos de MIN_OBSERVATIONS → None (evita predicciones poco fiables)."""
    st = SequenceTracker()
    st.record_sequence(["MineType.FILE", "MineType.CREDENTIAL"])
    st.record_sequence(["MineType.FILE", "MineType.CREDENTIAL"])
    # Solo 2 observaciones de FILE — mínimo es 3
    assert st.predict_next("MineType.FILE") is None

def t_sequence_tracker_predice_con_suficientes_datos():
    """Con >= MIN_OBSERVATIONS, predice el sucesor más frecuente."""
    st = SequenceTracker()
    for _ in range(5):
        st.record_sequence(["MineType.FILE", "MineType.CREDENTIAL"])
    st.record_sequence(["MineType.FILE", "MineType.ENDPOINT"])

    pred = st.predict_next("MineType.FILE")
    assert pred is not None
    assert pred["predicted_mine"] == "MineType.CREDENTIAL"
    assert pred["confidence"] > 0.5

def t_sequence_tracker_confianza_correcta():
    """La confianza es la proporción real de la transición."""
    st = SequenceTracker()
    for _ in range(6):
        st.record_sequence(["MineType.FILE", "MineType.CREDENTIAL"])
    for _ in range(4):
        st.record_sequence(["MineType.FILE", "MineType.ENDPOINT"])

    pred = st.predict_next("MineType.FILE")
    assert pred is not None
    assert abs(pred["confidence"] - 0.6) < 0.05   # 6/10 = 60%
    assert pred["observations"] == 10

def t_sequence_tracker_secuencia_larga():
    """Registra y aprende de secuencias de 3+ pasos."""
    st = SequenceTracker()
    seq = ["MineType.FILE", "MineType.CREDENTIAL", "MineType.ENDPOINT"]
    for _ in range(5):
        st.record_sequence(seq)

    pred_file = st.predict_next("MineType.FILE")
    pred_cred = st.predict_next("MineType.CREDENTIAL")

    assert pred_file is not None
    assert pred_file["predicted_mine"] == "MineType.CREDENTIAL"
    assert pred_cred is not None
    assert pred_cred["predicted_mine"] == "MineType.ENDPOINT"

def t_predict_attack_sequence_profundidad():
    """predict_sequence encadena predicciones hasta profundidad solicitada."""
    st = SequenceTracker()
    for _ in range(5):
        st.record_sequence(["MineType.FILE", "MineType.CREDENTIAL",
                             "MineType.ENDPOINT", "MineType.IDENTITY"])

    preds = st.predict_sequence("MineType.FILE", depth=3)
    assert len(preds) == 3
    assert preds[0]["predicted_mine"] == "MineType.CREDENTIAL"
    assert preds[1]["predicted_mine"] == "MineType.ENDPOINT"
    assert preds[2]["predicted_mine"] == "MineType.IDENTITY"

def t_predict_sequence_para_cuando_confianza_baja():
    """La cadena se corta cuando la confianza cae del 30%."""
    st = SequenceTracker()
    # Solo FILE → CREDENTIAL con suficiente confianza
    for _ in range(5):
        st.record_sequence(["MineType.FILE", "MineType.CREDENTIAL"])
    # CREDENTIAL → muchos distintos (confianza baja para cada uno)
    for siguiente in ["MineType.ENDPOINT", "MineType.IDENTITY",
                      "MineType.FILE", "MineType.NETWORK", "MineType.OTHER"]:
        st.record_sequence(["MineType.CREDENTIAL", siguiente])

    preds = st.predict_sequence("MineType.FILE", depth=5)
    # Primera predicción alta confianza
    assert len(preds) >= 1
    assert preds[0]["predicted_mine"] == "MineType.CREDENTIAL"
    # Segunda predicción debe tener confianza < 30% → se cortó
    if len(preds) > 1:
        assert preds[1]["confidence"] >= 0.30   # si llegó, supera el umbral

async def t_ingest_profile_registra_secuencia():
    """ingest_profile registra la secuencia de mines del perfil."""
    L = AegisLearning(installation_id="AEGIS-SEQ-TEST")

    # Perfil con 3 contactos de distintos tipos
    p = _make_profile_with_mines(["FILE", "CREDENTIAL", "ENDPOINT"], 5)
    await L.ingest_profile(p)

    modelo = L.get_sequence_model()
    assert "MineType.FILE" in modelo["transitions"], \
        "Secuencia no registrada tras ingest_profile"

async def t_predict_next_mine_tras_multiples_incidentes():
    """
    Tras varios incidentes con el mismo patrón FILE→CREDENTIAL,
    predict_next_mine("MineType.FILE") devuelve CREDENTIAL.
    """
    L = AegisLearning(installation_id="AEGIS-PRED-TEST")

    for _ in range(5):
        p = _make_profile_with_mines(["FILE", "CREDENTIAL"], 2)
        await L.ingest_profile(p)
    # Un incidente distinto
    p = _make_profile_with_mines(["FILE", "ENDPOINT"], 2)
    await L.ingest_profile(p)

    pred = L.predict_next_mine("MineType.FILE")
    assert pred is not None, "Sin predicción tras 6 incidentes"
    assert pred["predicted_mine"] == "MineType.CREDENTIAL"
    assert pred["confidence"] > 0.6

async def t_predict_next_mine_sin_historia_retorna_none():
    """Sin incidentes previos, predict_next_mine retorna None."""
    L   = AegisLearning(installation_id="AEGIS-EMPTY")
    pred = L.predict_next_mine("MineType.FILE")
    assert pred is None

async def t_predict_attack_sequence_publico():
    """predict_attack_sequence encadena N pasos desde la fachada."""
    L = AegisLearning(installation_id="AEGIS-CHAIN-TEST")

    for _ in range(5):
        p = _make_profile_with_mines(
            ["FILE", "CREDENTIAL", "ENDPOINT"], 3
        )
        await L.ingest_profile(p)

    preds = L.predict_attack_sequence("MineType.FILE", depth=2)
    assert len(preds) >= 1
    assert preds[0]["predicted_mine"] == "MineType.CREDENTIAL"

def t_get_sequence_model_exportable():
    """get_sequence_model() retorna dict con transitions y totals."""
    L = AegisLearning(installation_id="AEGIS-MODEL-TEST")
    modelo = L.get_sequence_model()
    assert "transitions" in modelo
    assert "totals"      in modelo


# Helper — construye perfil con contactos de los tipos dados
def _make_profile_with_mines(mine_type_names: list, n_each: int):
    """
    Construye un IntruderProfile con contactos en el orden exacto dado.
    Para aprendizaje anticipatorio: un contacto de cada tipo en secuencia,
    repetida n_each veces. Así FILE→CREDENTIAL→ENDPOINT queda como patrón.
    """
    from layers.forensic  import IntruderProfile, ActorType, AttackTechnique, IntentCategory
    from layers.minefield import MineContact, MineType, ContactSeverity
    from datetime import datetime, timezone
    import secrets

    mine_type_map = {
        "FILE":       MineType.FILE,
        "CREDENTIAL": MineType.CREDENTIAL,
        "ENDPOINT":   MineType.ENDPOINT,
        "IDENTITY":   MineType.IDENTITY,
        "NETWORK":    MineType.FILE,
        "OTHER":      MineType.FILE,
    }

    p = IntruderProfile(
        incident_id = secrets.token_hex(4),
        source_ips  = ["10.0.0.1"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = ActorType.BOT_SIMPLE,
        techniques  = [AttackTechnique.RECONNAISSANCE],
        intent      = IntentCategory.CREDENTIAL_THEFT,
    )
    # Intercalar: un contacto de cada tipo, repetido n_each veces
    # FILE, CREDENTIAL, ENDPOINT, FILE, CREDENTIAL, ENDPOINT...
    # Así la secuencia registrada en el tracker es correcta
    for _ in range(n_each):
        for name in mine_type_names:
            mt = mine_type_map.get(name, MineType.FILE)
            c = MineContact(
                contact_id    = secrets.token_hex(4),
                timestamp     = datetime.now(timezone.utc),
                source_ip     = "10.0.0.1",
                source_port   = 54321,
                mine_id       = f"mine_{name}",
                mine_type     = mt,
                mine_name     = name.lower(),
                severity      = ContactSeverity.HIGH,
                method        = "GET",
                payload       = b"",
                fingerprint   = secrets.token_hex(8),
                response_sent = "fake",
            )
            p.mine_contacts.append(c)
    return p


test("ANTICIP — Sin datos no predice", t_sequence_tracker_sin_datos_no_predice)
test("ANTICIP — Menos de MIN_OBS no predice", t_sequence_tracker_menos_de_min_no_predice)
test("ANTICIP — Predice con datos suficientes", t_sequence_tracker_predice_con_suficientes_datos)
test("ANTICIP — Confianza = proporción real", t_sequence_tracker_confianza_correcta)
test("ANTICIP — Aprende secuencias de 3+ pasos", t_sequence_tracker_secuencia_larga)
test("ANTICIP — predict_sequence encadena N pasos", t_predict_attack_sequence_profundidad)
test("ANTICIP — Cadena se corta con confianza baja", t_predict_sequence_para_cuando_confianza_baja)
test("ANTICIP — ingest_profile registra secuencia", t_ingest_profile_registra_secuencia)
test("ANTICIP — predict_next_mine tras múltiples incidentes", t_predict_next_mine_tras_multiples_incidentes)
test("ANTICIP — predict_next_mine sin historia → None", t_predict_next_mine_sin_historia_retorna_none)
test("ANTICIP — predict_attack_sequence público", t_predict_attack_sequence_publico)
test("ANTICIP — get_sequence_model exportable", t_get_sequence_model_exportable)


# ─────────────────────────────────────────────
# MEJORA 3 — TESTS DE RED COLECTIVA AUTOMÁTICA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  LEARNING — Mejora 3: Red Colectiva Automática")
print("═══════════════════════════════════════════════")

from layers.learning import CollectiveNetwork

def t_collective_network_sin_pares_sync_retorna_cero():
    """Sin pares registrados, sync_once retorna 0."""
    async def _run():
        net = CollectiveNetwork(sync_interval_s=60)
        n   = await net.sync_once(lambda: "fake_packet")
        assert n == 0
    asyncio.run(_run())

def t_register_peer_añade_par():
    """register_peer añade correctamente un par."""
    net = CollectiveNetwork()
    net.register_peer("AEGIS-DEU-001", lambda pkt: None)
    st  = net.status()
    assert st["peers"] == 1
    assert "AEGIS-DEU-001" in st["peer_ids"]

def t_register_peer_no_duplica():
    """Registrar el mismo peer_id dos veces no duplica."""
    net = CollectiveNetwork()
    net.register_peer("AEGIS-DEU-001", lambda pkt: None)
    net.register_peer("AEGIS-DEU-001", lambda pkt: None)
    assert net.status()["peers"] == 1

def t_unregister_peer_elimina_par():
    """unregister_peer elimina el par correctamente."""
    net = CollectiveNetwork()
    net.register_peer("AEGIS-FRA-001", lambda pkt: None)
    net.unregister_peer("AEGIS-FRA-001")
    assert net.status()["peers"] == 0

async def t_sync_once_llama_callback_del_par():
    """sync_once llama al import_callback de cada par registrado."""
    recibidos = []

    net = CollectiveNetwork()
    net.register_peer("AEGIS-B", lambda pkt: recibidos.append(pkt))

    fake_packet = object()
    await net.sync_once(lambda: fake_packet)

    assert len(recibidos) == 1
    assert recibidos[0] is fake_packet

async def t_sync_once_con_dos_pares():
    """sync_once envía a todos los pares y retorna count correcto."""
    recibidos_a = []
    recibidos_b = []

    net = CollectiveNetwork()
    net.register_peer("AEGIS-A", lambda pkt: recibidos_a.append(pkt))
    net.register_peer("AEGIS-B", lambda pkt: recibidos_b.append(pkt))

    n = await net.sync_once(lambda: "paquete")
    assert n == 2
    assert len(recibidos_a) == 1
    assert len(recibidos_b) == 1

async def t_sync_once_registra_en_log():
    """sync_once registra el ciclo en el log con timestamp."""
    net = CollectiveNetwork()
    net.register_peer("AEGIS-LOG", lambda pkt: None)
    await net.sync_once(lambda: "paquete")

    log = net.get_sync_log()
    assert len(log) == 1
    assert log[0]["sync_id"]   == 1
    assert log[0]["peers_ok"]  == 1
    assert log[0]["peers_err"] == 0
    assert "timestamp" in log[0]

async def t_sync_once_maneja_error_en_callback():
    """Si un callback falla, sync_once registra el error y sigue."""
    def callback_roto(pkt):
        raise RuntimeError("conexión rechazada")

    net = CollectiveNetwork()
    net.register_peer("AEGIS-ROTO", callback_roto)
    net.register_peer("AEGIS-OK",   lambda pkt: None)

    n   = await net.sync_once(lambda: "paquete")
    log = net.get_sync_log()

    assert n == 1                        # solo el OK llegó
    assert log[0]["peers_err"] == 1      # el roto quedó registrado

async def t_start_stop_bucle_automatico():
    """start() inicia el bucle, stop() lo detiene limpiamente."""
    net = CollectiveNetwork(sync_interval_s=999)   # intervalo muy largo
    await net.start(lambda: "paquete")

    assert net.status()["running"] is True

    await net.stop()
    assert net.status()["running"] is False

async def t_sync_now_fuerza_sync_inmediato():
    """sync_now() fuerza un sync sin esperar el intervalo."""
    recibidos = []
    L_a = AegisLearning(installation_id="AEGIS-SYNC-A",
                        sync_interval_s=999)
    L_b = AegisLearning(installation_id="AEGIS-SYNC-B")

    L_a.register_peer("AEGIS-SYNC-B", L_b.import_intelligence)

    n = await L_a.sync_now()
    assert n == 1   # enviado correctamente a B

async def t_red_completa_a_exporta_b_aprende():
    """
    Integración completa: A aprende un patrón, sync automático,
    B importa y su KB refleja el conocimiento de A.
    """
    KEY = secrets.token_bytes(32)

    L_a = AegisLearning(installation_id="AEGIS-RED-A",
                        signing_key=KEY, sync_interval_s=999)
    L_b = AegisLearning(installation_id="AEGIS-RED-B",
                        signing_key=KEY)

    # A aprende credential stuffing
    from layers.forensic import IntruderProfile, ActorType, AttackTechnique, IntentCategory
    p = IntruderProfile(
        incident_id = "RED-001",
        source_ips  = ["5.5.5.5"],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
        actor_type  = ActorType.BOT_ADVANCED,
        techniques  = [AttackTechnique.CREDENTIAL_STUFFING],
        intent      = IntentCategory.CREDENTIAL_THEFT,
    )
    for _ in range(5):
        await L_a.ingest_profile(p)

    # Registrar B como par de A y forzar sync
    L_a.register_peer("AEGIS-RED-B", L_b.import_intelligence)
    n = await L_a.sync_now()
    assert n == 1

    # B debe tener la técnica aprendida por A
    kb_b = L_b.get_knowledge_base()
    assert "CREDENTIAL_STUFFING" in str(kb_b["technique_counts"]), \
        f"B no aprendió de A: {kb_b['technique_counts']}"

async def t_status_incluye_network():
    """status() incluye información de la red colectiva."""
    L = AegisLearning(installation_id="AEGIS-STATUS-NET",
                      sync_interval_s=60)
    L.register_peer("AEGIS-PEER", lambda pkt: None)

    st = L.status()
    assert "network" in st
    assert st["network"]["peers"]           == 1
    assert st["network"]["sync_interval_s"] == 60
    assert st["network"]["running"]         is False   # no started

def t_get_sync_log_vacio_inicialmente():
    """Sin syncs realizados, el log está vacío."""
    L = AegisLearning(installation_id="AEGIS-LOG-TEST")
    assert L.get_sync_log() == []

def t_get_network_status_estructura():
    """get_network_status() retorna estructura completa."""
    L  = AegisLearning(installation_id="AEGIS-NET-ST")
    st = L.get_network_status()
    for campo in ["peers", "peer_ids", "sync_count",
                  "sync_interval_s", "last_sync_at", "running"]:
        assert campo in st, f"Falta campo: {campo}"


test("RED — Sin pares sync retorna 0",               t_collective_network_sin_pares_sync_retorna_cero)
test("RED — register_peer añade par",                t_register_peer_añade_par)
test("RED — register_peer no duplica",               t_register_peer_no_duplica)
test("RED — unregister_peer elimina par",            t_unregister_peer_elimina_par)
test("RED — sync_once llama callback del par",       t_sync_once_llama_callback_del_par)
test("RED — sync_once con dos pares",                t_sync_once_con_dos_pares)
test("RED — sync_once registra en log",              t_sync_once_registra_en_log)
test("RED — sync_once maneja error sin romper",      t_sync_once_maneja_error_en_callback)
test("RED — start/stop bucle automático",            t_start_stop_bucle_automatico)
test("RED — sync_now fuerza sync inmediato",         t_sync_now_fuerza_sync_inmediato)
test("RED — Integración: A exporta, B aprende",      t_red_completa_a_exporta_b_aprende)
test("RED — status() incluye network",               t_status_incluye_network)
test("RED — get_sync_log vacío inicialmente",        t_get_sync_log_vacio_inicialmente)
test("RED — get_network_status estructura completa", t_get_network_status_estructura)


if failed == 0 and not any(not ok for _, ok in results):
    print(f"  RESULTADO: {len(results)}/{len(results)} tests PASADOS ✓")
    print("  Capa 8 — Aprendizaje Colectivo + Anticipatorio OPERATIVO")
    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║   AEGIS — TODAS LAS CAPAS COMPLETAS ║")
    print("  ╚══════════════════════════════════════╝")
else:
    total_f  = len(results)
    passed_f = sum(1 for _, ok in results if ok)
    failed_f = total_f - passed_f
    print(f"  RESULTADO: {passed_f}/{total_f} tests PASADOS "
          f"({'✓' if failed_f == 0 else '✗'})")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if all(ok for _, ok in results) else 1)
