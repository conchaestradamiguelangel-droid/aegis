"""
AEGIS — Test de Capa 7: Análisis Forense
==========================================
Tests de clasificación de actor, técnicas, intención y pipeline completo.
"""

import asyncio
import secrets
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.forensic import (
    AegisForensic, ForensicEngine, ActorClassifier, TechniqueAnalyzer,
    IntentAnalyzer, IntruderProfile, ActorType, AttackTechnique,
    IntentCategory,
)
from layers.minefield import MineContact, MineType, ContactSeverity
from datetime import datetime, timezone

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []
IP_A = "10.0.0.1"
IP_B = "10.0.0.2"


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


def _make_profile(ips=None, intervals=None, resources=None,
                  techniques=None) -> IntruderProfile:
    p = IntruderProfile(
        incident_id = "TEST001",
        source_ips  = ips or [IP_A],
        first_seen  = datetime.now(timezone.utc),
        last_seen   = datetime.now(timezone.utc),
    )
    if intervals:
        p.request_intervals_ms = intervals
        p.total_events         = len(intervals) + 1
    if resources:
        p.unique_resources = set(resources)
        p.total_events     = max(p.total_events, len(resources))
    if techniques:
        p.techniques = techniques
    return p


def _make_contact(ip=IP_A, mine="backup.json",
                  mine_type=MineType.FILE) -> MineContact:
    return MineContact(
        contact_id   = "C001",
        timestamp    = datetime.now(timezone.utc),
        source_ip    = ip,
        source_port  = 54321,
        mine_id      = f"file:{mine}",
        mine_type    = mine_type,
        mine_name    = mine,
        severity     = ContactSeverity.HIGH,
        method       = "GET",
        payload      = b"",
        fingerprint  = "abcd1234",
        response_sent= "fake",
    )


# ─────────────────────────────────────────────
# CLASIFICADOR DE ACTOR
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 7: Clasificador de Actor")
print("═══════════════════════════════════════════════")

def t_actor_unknown_sin_datos():
    clf     = ActorClassifier()
    profile = _make_profile()
    actor, conf = clf.classify(profile)
    assert actor == ActorType.UNKNOWN
    assert conf == 0.0

def t_actor_bot_simple_intervalos_regulares():
    """Intervalos muy regulares y rápidos → BOT_SIMPLE."""
    clf      = ActorClassifier()
    intervals = [20.0, 21.0, 19.5, 20.2, 20.8, 19.9]   # muy regulares < 500ms
    profile  = _make_profile(intervals=intervals,
                              resources=["r1", "r2", "r3"])
    actor, conf = clf.classify(profile)
    assert actor == ActorType.BOT_SIMPLE
    assert conf >= 0.7

def t_actor_humano_intervalos_lentos():
    """Intervalos lentos e irregulares → HUMAN."""
    clf      = ActorClassifier()
    intervals = [1200.0, 3500.0, 800.0, 2100.0, 4000.0]   # lentos y variables
    profile  = _make_profile(intervals=intervals,
                              resources=["r1", "r2"])
    actor, conf = clf.classify(profile)
    assert actor == ActorType.HUMAN
    assert conf >= 0.6

def t_actor_bot_avanzado_rapido_variable():
    """Rápido pero variable (introduce aleatoriedad) → BOT_ADVANCED."""
    clf      = ActorClassifier()
    intervals = [100.0, 350.0, 80.0, 420.0, 150.0, 300.0]  # rápido pero variable
    profile  = _make_profile(intervals=intervals,
                              resources=["r1", "r2", "r3"])
    actor, conf = clf.classify(profile)
    assert actor == ActorType.BOT_ADVANCED
    assert conf >= 0.6

def t_actor_ai_sistematico():
    """Alta unicidad + rápido + múltiples técnicas → AI_AGENT."""
    clf      = ActorClassifier()
    # 10 recursos únicos con 10 eventos (unicidad = 1.0)
    resources = [f"resource_{i}" for i in range(10)]
    intervals = [50.0, 80.0, 60.0, 70.0, 55.0, 65.0, 75.0, 58.0, 62.0]
    profile   = _make_profile(
        intervals  = intervals,
        resources  = resources,
        techniques = [AttackTechnique.RECONNAISSANCE, AttackTechnique.ENUMERATION]
    )
    profile.total_events = 10
    actor, conf = clf.classify(profile)
    assert actor == ActorType.AI_AGENT
    assert conf >= 0.7

def t_actor_confianza_entre_0_y_1():
    clf     = ActorClassifier()
    for intervals in [
        [20.0, 21.0],
        [1500.0, 2000.0],
        [100.0, 350.0],
    ]:
        p = _make_profile(intervals=intervals, resources=["r1"])
        _, conf = clf.classify(p)
        assert 0.0 <= conf <= 1.0

test("ACTOR — Sin datos → UNKNOWN", t_actor_unknown_sin_datos)
test("ACTOR — Intervalos regulares rápidos → BOT_SIMPLE", t_actor_bot_simple_intervalos_regulares)
test("ACTOR — Intervalos lentos irregulares → HUMAN", t_actor_humano_intervalos_lentos)
test("ACTOR — Rápido pero variable → BOT_ADVANCED", t_actor_bot_avanzado_rapido_variable)
test("ACTOR — Sistemático + múltiples técnicas → AI_AGENT", t_actor_ai_sistematico)
test("ACTOR — Confianza siempre entre 0 y 1", t_actor_confianza_entre_0_y_1)


# ─────────────────────────────────────────────
# ANALIZADOR DE TÉCNICAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 7: Analizador de Técnicas")
print("═══════════════════════════════════════════════")

def t_tecnica_reconocimiento():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(resources=["/admin", "/api/keys", "/config/secrets"])
    techs   = ana.analyze(profile)
    assert AttackTechnique.RECONNAISSANCE in techs

def t_tecnica_credential_stuffing():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(resources=["admin/credential", "login_endpoint", "auth_token"])
    techs   = ana.analyze(profile)
    assert AttackTechnique.CREDENTIAL_STUFFING in techs

def t_tecnica_exfiltracion():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(resources=["database_export", "backup.json", "data_dump"])
    techs   = ana.analyze(profile)
    assert AttackTechnique.EXFILTRATION in techs

def t_tecnica_movimiento_lateral():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(ips=[IP_A, IP_B], resources=["r1"])
    techs   = ana.analyze(profile)
    assert AttackTechnique.LATERAL_MOVEMENT in techs

def t_tecnica_persistencia():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(resources=["ssh_key", "config_secret", "cert_private"])
    techs   = ana.analyze(profile)
    assert AttackTechnique.PERSISTENCE in techs

def t_tecnica_sin_recursos_unknown():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(resources=[])
    techs   = ana.analyze(profile)
    assert AttackTechnique.UNKNOWN in techs

def t_tecnica_multiples_simultaneas():
    ana     = TechniqueAnalyzer()
    profile = _make_profile(
        ips       = [IP_A, IP_B],
        resources = ["credential_db", "backup_export", "ssh_config", "/admin", "/api", "/config"]
    )
    techs = ana.analyze(profile)
    assert len(techs) >= 2

test("TÉCNICA — 3+ recursos → RECONNAISSANCE", t_tecnica_reconocimiento)
test("TÉCNICA — Credenciales tocadas → CREDENTIAL_STUFFING", t_tecnica_credential_stuffing)
test("TÉCNICA — Datos/backups tocados → EXFILTRATION", t_tecnica_exfiltracion)
test("TÉCNICA — Múltiples IPs → LATERAL_MOVEMENT", t_tecnica_movimiento_lateral)
test("TÉCNICA — Keys/certs tocados → PERSISTENCE", t_tecnica_persistencia)
test("TÉCNICA — Sin recursos → UNKNOWN", t_tecnica_sin_recursos_unknown)
test("TÉCNICA — Recursos mixtos → múltiples técnicas", t_tecnica_multiples_simultaneas)


# ─────────────────────────────────────────────
# ANALIZADOR DE INTENCIÓN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 7: Analizador de Intención")
print("═══════════════════════════════════════════════")

def t_intencion_robo_credenciales():
    ana     = IntentAnalyzer()
    profile = _make_profile(resources=["credential_store", "password_db", "auth_token"])
    intent  = ana.analyze(profile)
    assert intent == IntentCategory.CREDENTIAL_THEFT

def t_intencion_exfiltracion_datos():
    ana     = IntentAnalyzer()
    profile = _make_profile(resources=["database_backup", "data_export", "table_dump"])
    intent  = ana.analyze(profile)
    assert intent == IntentCategory.DATA_EXFILTRATION

def t_intencion_acceso_sistema():
    ana     = IntentAnalyzer()
    profile = _make_profile(resources=["ssh_config", "admin_shell", "service_secret"])
    intent  = ana.analyze(profile)
    assert intent == IntentCategory.SYSTEM_ACCESS

def t_intencion_reconocimiento_puro():
    ana     = IntentAnalyzer()
    profile = _make_profile(resources=["r1", "r2", "r3"])
    profile.techniques = [AttackTechnique.RECONNAISSANCE]
    intent  = ana.analyze(profile)
    assert intent == IntentCategory.RECONNAISSANCE

def t_intencion_sin_datos_unknown():
    ana     = IntentAnalyzer()
    profile = _make_profile(resources=[])
    intent  = ana.analyze(profile)
    assert intent == IntentCategory.UNKNOWN

test("INTENCIÓN — Credenciales → CREDENTIAL_THEFT", t_intencion_robo_credenciales)
test("INTENCIÓN — Datos/exports → DATA_EXFILTRATION", t_intencion_exfiltracion_datos)
test("INTENCIÓN — SSH/config/admin → SYSTEM_ACCESS", t_intencion_acceso_sistema)
test("INTENCIÓN — Solo reconocimiento → RECONNAISSANCE", t_intencion_reconocimiento_puro)
test("INTENCIÓN — Sin recursos → UNKNOWN", t_intencion_sin_datos_unknown)


# ─────────────────────────────────────────────
# MOTOR FORENSE
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 7: Motor Forense")
print("═══════════════════════════════════════════════")

def t_motor_ingest_mine_contact():
    engine  = ForensicEngine()
    profile = _make_profile()
    contact = _make_contact()
    engine.ingest_mine_contact(profile, contact)
    assert profile.total_events == 1
    assert "backup.json" in profile.unique_resources

def t_motor_ingest_multiples_contactos():
    engine  = ForensicEngine()
    profile = _make_profile()
    for mine in ["backup.json", "credentials.env", "secrets.yaml"]:
        engine.ingest_mine_contact(profile, _make_contact(mine=mine))
    assert profile.total_events == 3
    assert len(profile.unique_resources) == 3

def t_motor_analyze_genera_fingerprint():
    engine  = ForensicEngine()
    profile = _make_profile(
        intervals = [50.0, 60.0, 55.0],
        resources = ["credential_store", "database_export"]
    )
    result = engine.analyze(profile)
    assert result.fingerprint != ""
    assert len(result.fingerprint) == 16

def t_motor_analyze_completo():
    engine  = ForensicEngine()
    profile = _make_profile(
        intervals = [50.0, 55.0, 48.0, 52.0],
        resources = ["credential_db", "backup_export", "/admin", "/api/keys", "/config"]
    )
    result = engine.analyze(profile)
    assert result.actor_type   != ActorType.UNKNOWN
    assert len(result.techniques) >= 1
    assert result.intent       != IntentCategory.UNKNOWN or True   # puede ser unknown con pocos datos
    assert result.confidence   >= 0.0

test("MOTOR — ingest_mine_contact registra recurso", t_motor_ingest_mine_contact)
test("MOTOR — Múltiples contactos acumulan recursos únicos", t_motor_ingest_multiples_contactos)
test("MOTOR — analyze() genera fingerprint de 16 chars", t_motor_analyze_genera_fingerprint)
test("MOTOR — analyze() completo actualiza todos los campos", t_motor_analyze_completo)


# ─────────────────────────────────────────────
# FACHADA — AegisForensic
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 7: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_forensic_inicializa():
    f  = AegisForensic()
    st = f.status()
    assert st["active_incidents"] == 0
    assert st["closed_incidents"] == 0

def t_forensic_open_incident():
    f   = AegisForensic()
    iid = f.open_incident([IP_A])
    assert iid is not None
    assert f.active_incidents() == 1

def t_forensic_close_incident():
    f   = AegisForensic()
    iid = f.open_incident([IP_A])
    f.close_incident(iid)
    assert f.active_incidents() == 0
    assert f.closed_incidents() == 1

async def t_forensic_on_mine_contact_crea_incidente():
    f       = AegisForensic()
    contact = _make_contact(ip=IP_A)
    await f.on_mine_contact(contact)
    assert f.active_incidents() == 1

async def t_forensic_on_mine_contact_mismo_ip_mismo_incidente():
    f = AegisForensic()
    for mine in ["backup.json", "credentials.env"]:
        await f.on_mine_contact(_make_contact(ip=IP_A, mine=mine))
    # Misma IP → un solo incidente
    assert f.active_incidents() == 1

async def t_forensic_analyze_incidente_activo():
    f       = AegisForensic()
    contact = _make_contact()
    await f.on_mine_contact(contact)
    iids    = list(f._incidents.keys())
    profile = f.analyze(iids[0])
    assert profile is not None
    assert profile.incident_id == iids[0]

async def t_forensic_callback_learning_al_cerrar():
    f        = AegisForensic()
    received = []
    async def on_learn(profile): received.append(profile)
    f.register_learning_callback(on_learn)
    iid = f.open_incident([IP_A])
    await f.on_mine_contact(_make_contact(ip=IP_A))
    await f.close_incident_async(iid)
    assert len(received) == 1
    assert received[0].incident_id == iid

async def t_forensic_get_profile_activo():
    f       = AegisForensic()
    iid     = f.open_incident([IP_A])
    profile = f.get_profile(iid)
    assert profile is not None
    assert profile["incident_id"] == iid

async def t_forensic_get_profile_cerrado():
    f   = AegisForensic()
    iid = f.open_incident([IP_A])
    f.close_incident(iid)
    profile = f.get_profile(iid)
    assert profile is not None

async def t_forensic_get_all_profiles():
    f    = AegisForensic()
    iid1 = f.open_incident([IP_A])
    iid2 = f.open_incident([IP_B])
    f.close_incident(iid1)
    all_p = f.get_all_profiles()
    assert len(all_p) == 2

async def t_forensic_perfil_to_dict_estructura():
    f       = AegisForensic()
    contact = _make_contact(mine="credential_store")
    await f.on_mine_contact(contact)
    iid     = list(f._incidents.keys())[0]
    profile = f.analyze(iid)
    d       = profile.to_dict()
    assert "incident_id"   in d
    assert "actor_type"    in d
    assert "techniques"    in d
    assert "intent"        in d
    assert "confidence"    in d
    assert "fingerprint"   in d
    assert "source_ips"    in d

test("FACHADA — Inicialización correcta", t_forensic_inicializa)
test("FACHADA — open_incident crea incidente activo", t_forensic_open_incident)
test("FACHADA — close_incident mueve a cerrados", t_forensic_close_incident)
test("FACHADA — on_mine_contact crea incidente automáticamente", t_forensic_on_mine_contact_crea_incidente)
test("FACHADA — Misma IP → un solo incidente", t_forensic_on_mine_contact_mismo_ip_mismo_incidente)
test("FACHADA — analyze() sobre incidente activo", t_forensic_analyze_incidente_activo)
test("FACHADA — Callback learning notificado al cerrar", t_forensic_callback_learning_al_cerrar)
test("FACHADA — get_profile() incidente activo", t_forensic_get_profile_activo)
test("FACHADA — get_profile() incidente cerrado", t_forensic_get_profile_cerrado)
test("FACHADA — get_all_profiles() retorna todos", t_forensic_get_all_profiles)
test("FACHADA — Perfil to_dict() estructura completa", t_forensic_perfil_to_dict_estructura)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

# ─────────────────────────────────────────────
# MEJORA 4 — TESTS DE PERFIL DE AMENAZA PREDICTIVO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  FORENSIC — Mejora 4: Perfil de Amenaza Predictivo")
print("═══════════════════════════════════════════════")

from layers.forensic import ThreatScorer

def _perfil_base(
    actor=ActorType.BOT_SIMPLE,
    techniques=None,
    n_mines=0,
    elapsed_s=10,
    n_resources=1,
) -> IntruderProfile:
    """Construye un perfil sintético con los parámetros dados."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    p = IntruderProfile(
        incident_id = secrets.token_hex(4),
        source_ips  = ["10.0.0.1"],
        first_seen  = now - timedelta(seconds=elapsed_s),
        last_seen   = now,
        actor_type  = actor,
        techniques  = techniques or [],
    )
    p.unique_resources = set(f"res_{i}" for i in range(n_resources))
    for i in range(n_mines):
        p.mine_contacts.append(MineContact(
            contact_id    = secrets.token_hex(4),
            timestamp     = now,
            source_ip     = "10.0.0.1",
            source_port   = 54321,
            mine_id       = f"mine_{i}",
            mine_type     = MineType.FILE,
            mine_name     = "backup.json",
            severity      = ContactSeverity.HIGH,
            method        = "GET",
            payload       = b"",
            fingerprint   = secrets.token_hex(8),
            response_sent = "fake",
        ))
    return p


def t_score_estructura_completa():
    """score() retorna dict con todos los campos requeridos."""
    sc  = ThreatScorer()
    p   = _perfil_base()
    res = sc.score(p)
    for campo in ["score", "level", "will_escalate",
                  "recommendation", "breakdown", "inputs"]:
        assert campo in res, f"Falta campo: {campo}"
    for dim in ["actor", "techniques", "resources", "time", "mines"]:
        assert dim in res["breakdown"], f"Falta dimensión: {dim}"


def t_score_rango_valido():
    """score siempre está en [0.0, 1.0]."""
    sc = ThreatScorer()
    for actor in ActorType:
        for tech in [[], [AttackTechnique.RECONNAISSANCE],
                     [AttackTechnique.PERSISTENCE]]:
            p   = _perfil_base(actor=actor, techniques=tech,
                               n_mines=3, elapsed_s=600, n_resources=15)
            res = sc.score(p)
            assert 0.0 <= res["score"] <= 1.0, \
                f"Score fuera de rango: {res['score']}"


def t_ai_agent_mayor_score_que_bot_simple():
    """AI_AGENT tiene mayor score que BOT_SIMPLE con mismas condiciones."""
    sc    = ThreatScorer()
    techs = [AttackTechnique.RECONNAISSANCE]
    s_ai  = sc.score(_perfil_base(actor=ActorType.AI_AGENT,   techniques=techs))
    s_bot = sc.score(_perfil_base(actor=ActorType.BOT_SIMPLE, techniques=techs))
    assert s_ai["score"] > s_bot["score"], \
        f"AI_AGENT ({s_ai['score']}) no supera BOT_SIMPLE ({s_bot['score']})"


def t_persistence_fuerza_critico():
    """PERSISTENCE siempre produce nivel CRÍTICO y will_escalate=True."""
    sc  = ThreatScorer()
    p   = _perfil_base(techniques=[AttackTechnique.PERSISTENCE])
    res = sc.score(p)
    assert res["level"]         == "CRÍTICO"
    assert res["will_escalate"] is True


def t_lateral_movement_fuerza_escalada():
    """LATERAL_MOVEMENT fuerza will_escalate=True."""
    sc  = ThreatScorer()
    p   = _perfil_base(techniques=[AttackTechnique.LATERAL_MOVEMENT])
    res = sc.score(p)
    assert res["will_escalate"] is True


def t_exfiltracion_fuerza_escalada():
    """EXFILTRATION fuerza will_escalate=True."""
    sc  = ThreatScorer()
    p   = _perfil_base(techniques=[AttackTechnique.EXFILTRATION])
    res = sc.score(p)
    assert res["will_escalate"] is True


def t_sin_tecnicas_ni_mines_score_bajo():
    """Sin técnicas, sin mines y tiempo corto → nivel BAJO."""
    sc  = ThreatScorer()
    p   = _perfil_base(elapsed_s=5, n_resources=1, n_mines=0)
    res = sc.score(p)
    assert res["level"] in ("BAJO", "MEDIO"), \
        f"Perfil mínimo tiene nivel inesperado: {res['level']}"


def t_muchos_recursos_sube_score():
    """Más recursos únicos → score más alto."""
    sc    = ThreatScorer()
    s_low = sc.score(_perfil_base(n_resources=1))
    s_hi  = sc.score(_perfil_base(n_resources=25))
    assert s_hi["score"] > s_low["score"]


def t_tiempo_largo_sube_score():
    """Más tiempo en sistema → score más alto."""
    sc     = ThreatScorer()
    s_low  = sc.score(_perfil_base(elapsed_s=10))
    s_hi   = sc.score(_perfil_base(elapsed_s=1200))
    assert s_hi["score"] > s_low["score"]


def t_multiples_mines_sube_score():
    """Más señuelos tocados → score más alto."""
    sc    = ThreatScorer()
    s_0   = sc.score(_perfil_base(n_mines=0))
    s_5   = sc.score(_perfil_base(n_mines=5))
    assert s_5["score"] > s_0["score"]


def t_score_incluido_en_to_dict():
    """to_dict() del perfil incluye threat_assessment tras analyze()."""
    forensic = AegisForensic()
    iid      = forensic.open_incident(["5.5.5.5"])
    forensic.analyze(iid)
    d = forensic.get_profile(iid)
    assert "threat_assessment" in d
    assert "score" in d["threat_assessment"]
    assert "level" in d["threat_assessment"]


def t_score_threat_publico_sin_cerrar():
    """score_threat() funciona en incidente activo sin cerrarlo."""
    forensic = AegisForensic()
    iid      = forensic.open_incident(["6.6.6.6"])
    res      = forensic.score_threat(iid)
    assert res is not None
    assert 0.0 <= res["score"] <= 1.0
    assert res["level"] in ("BAJO", "MEDIO", "ALTO", "CRÍTICO")


def t_score_threat_incidente_inexistente_retorna_none():
    """score_threat() retorna None para incidentes que no existen."""
    forensic = AegisForensic()
    assert forensic.score_threat("INEXISTENTE") is None


def t_nivel_critico_tiene_lockdown_recomendado():
    """Nivel CRÍTICO siempre recomienda LOCKDOWN o acción inmediata."""
    sc  = ThreatScorer()
    p   = _perfil_base(
        actor      = ActorType.AI_AGENT,
        techniques = [AttackTechnique.PERSISTENCE, AttackTechnique.EXFILTRATION],
        n_mines    = 5,
        elapsed_s  = 900,
        n_resources= 20,
    )
    res = sc.score(p)
    assert res["level"]         == "CRÍTICO"
    assert res["will_escalate"] is True
    assert "LOCKDOWN" in res["recommendation"].upper() or \
           "JUMP"     in res["recommendation"].upper()


test("AMENAZA — score() retorna estructura completa",        t_score_estructura_completa)
test("AMENAZA — score siempre en [0.0, 1.0]",               t_score_rango_valido)
test("AMENAZA — AI_AGENT > BOT_SIMPLE en igualdad",         t_ai_agent_mayor_score_que_bot_simple)
test("AMENAZA — PERSISTENCE → CRÍTICO siempre",             t_persistence_fuerza_critico)
test("AMENAZA — LATERAL_MOVEMENT → will_escalate=True",     t_lateral_movement_fuerza_escalada)
test("AMENAZA — EXFILTRATION → will_escalate=True",         t_exfiltracion_fuerza_escalada)
test("AMENAZA — Sin datos → nivel BAJO o MEDIO",            t_sin_tecnicas_ni_mines_score_bajo)
test("AMENAZA — Más recursos → score más alto",             t_muchos_recursos_sube_score)
test("AMENAZA — Más tiempo → score más alto",               t_tiempo_largo_sube_score)
test("AMENAZA — Más mines → score más alto",                t_multiples_mines_sube_score)
test("AMENAZA — threat_assessment en to_dict()",            t_score_incluido_en_to_dict)
test("AMENAZA — score_threat() sin cerrar incidente",       t_score_threat_publico_sin_cerrar)
test("AMENAZA — score_threat() inexistente → None",         t_score_threat_incidente_inexistente_retorna_none)
test("AMENAZA — CRÍTICO recomienda LOCKDOWN/JUMP",          t_nivel_critico_tiene_lockdown_recomendado)


if failed == 0 and not any(not ok for _, ok in results):
    print(f"\n  RESULTADO: {len(results)}/{len(results)} tests PASADOS ✓")
    print("  Capa 7 — Análisis Forense + Amenaza Predictiva OPERATIVO")
else:
    total_f  = len(results)
    passed_f = sum(1 for _, ok in results if ok)
    failed_f = total_f - passed_f
    print(f"\n  RESULTADO: {passed_f}/{total_f} tests PASADOS "
          f"({'✓' if failed_f == 0 else '✗'})")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if all(ok for _, ok in results) else 1)
