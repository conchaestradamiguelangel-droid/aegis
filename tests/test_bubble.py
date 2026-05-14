"""
AEGIS — Test de Capa 6: Burbuja Evolutiva de Engaño
=====================================================
Tests de latencia, respuestas, evolución, sesiones y conectores.
"""

import asyncio
import json
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.bubble import (
    AegisBubble, LatencyEngine, ResponseEngine, BubbleSession,
    BubbleInteraction, BubbleStatus, InteractionType,
)

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []
IP = "1.2.3.4"


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
# MOTOR DE LATENCIA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 6: Motor de Latencia")
print("═══════════════════════════════════════════════")

def t_latencia_siempre_positiva():
    eng = LatencyEngine()
    for _ in range(20):
        ms = eng.preview_next()
        assert ms >= 10, f"Latencia negativa o cero: {ms}ms"

def t_latencia_nunca_identica_consecutiva():
    """20 latencias consecutivas no deben ser todas iguales."""
    eng    = LatencyEngine()
    values = [eng.preview_next() for _ in range(20)]
    unique = len(set(round(v, 1) for v in values))
    assert unique > 5, f"Latencias demasiado repetitivas: {unique} distintas de 20"

def t_latencia_rango_razonable():
    """Todas las latencias deben estar entre 10ms y 3000ms."""
    eng = LatencyEngine()
    for _ in range(50):
        ms = eng.preview_next()
        assert 10 <= ms <= 3000, f"Latencia fuera de rango: {ms}ms"

async def t_latencia_apply_espera_real():
    """apply() debe esperar al menos algo de tiempo real."""
    eng = LatencyEngine()
    # Reducir latencia para test — mockear preview
    eng._interaction_count = 999   # forzar selector específico
    t0 = time.monotonic()
    ms = await asyncio.wait_for(eng.apply(), timeout=5.0)
    elapsed = (time.monotonic() - t0) * 1000
    assert elapsed >= 5, f"apply() no esperó nada real: {elapsed:.1f}ms"
    assert ms > 0

test("LATENCIA — Siempre ≥ 10ms", t_latencia_siempre_positiva)
test("LATENCIA — Valores variados (no repetitivos)", t_latencia_nunca_identica_consecutiva)
test("LATENCIA — Dentro de rango 10ms–3000ms", t_latencia_rango_razonable)
test("LATENCIA — apply() espera tiempo real", t_latencia_apply_espera_real)


# ─────────────────────────────────────────────
# MOTOR DE RESPUESTAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 6: Motor de Respuestas")
print("═══════════════════════════════════════════════")

def t_respuesta_file_read_es_json():
    eng = ResponseEngine()
    r   = eng.generate(InteractionType.FILE_READ, b"test")
    obj = json.loads(r)
    assert "file" in obj
    assert "owner" in obj
    assert "checksum" in obj

def t_respuesta_api_call_es_json():
    eng = ResponseEngine()
    r   = eng.generate(InteractionType.API_CALL, b"test")
    obj = json.loads(r)
    assert "status" in obj
    assert "version" in obj

def t_respuesta_auth_es_json():
    eng = ResponseEngine()
    r   = eng.generate(InteractionType.AUTH_ATTEMPT, b"admin:password")
    obj = json.loads(r)
    assert "authenticated" in obj

def t_respuesta_query_es_json():
    eng = ResponseEngine()
    r   = eng.generate(InteractionType.DATA_QUERY, b"SELECT *")
    obj = json.loads(r)
    assert "table" in obj
    assert "total_rows" in obj

def t_respuesta_command_es_json():
    eng = ResponseEngine()
    r   = eng.generate(InteractionType.COMMAND, b"ls -la")
    obj = json.loads(r)
    assert "exit_code" in obj
    assert "stdout" in obj

def t_respuesta_evoluciona_entre_ciclos():
    """Respuestas del mismo tipo deben cambiar entre ciclos."""
    eng  = ResponseEngine()
    r1   = eng.generate(InteractionType.API_CALL, b"test")
    r2   = eng.generate(InteractionType.API_CALL, b"test")
    # Al menos el timestamp o ID debe ser diferente
    assert r1 != r2

def t_respuesta_ciclo_incrementa():
    eng = ResponseEngine()
    assert eng._cycle == 0
    eng.generate(InteractionType.UNKNOWN, b"")
    assert eng._cycle == 1
    eng.generate(InteractionType.UNKNOWN, b"")
    assert eng._cycle == 2

def t_respuesta_todos_los_tipos():
    """Todos los tipos de interacción generan respuesta válida."""
    eng = ResponseEngine()
    for tipo in InteractionType:
        r = eng.generate(tipo, b"test_input")
        assert len(r) > 0
        try:
            json.loads(r)
        except json.JSONDecodeError:
            raise AssertionError(f"Respuesta no es JSON válido para {tipo}: {r[:50]}")

test("RESPUESTA — FILE_READ genera JSON con campos esperados", t_respuesta_file_read_es_json)
test("RESPUESTA — API_CALL genera JSON con campos esperados", t_respuesta_api_call_es_json)
test("RESPUESTA — AUTH_ATTEMPT genera JSON con authenticated", t_respuesta_auth_es_json)
test("RESPUESTA — DATA_QUERY genera JSON con tabla y filas", t_respuesta_query_es_json)
test("RESPUESTA — COMMAND genera JSON con exit_code", t_respuesta_command_es_json)
test("RESPUESTA — Evoluciona entre ciclos (nunca idéntica)", t_respuesta_evoluciona_entre_ciclos)
test("RESPUESTA — Ciclo incrementa en cada generate()", t_respuesta_ciclo_incrementa)
test("RESPUESTA — Todos los tipos generan JSON válido", t_respuesta_todos_los_tipos)


# ─────────────────────────────────────────────
# SESIÓN DE BURBUJA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 6: Sesión de Burbuja")
print("═══════════════════════════════════════════════")

def t_sesion_abierta_activa():
    from datetime import datetime, timezone
    s = BubbleSession(
        session_id="SID001", source_ip=IP,
        opened_at=datetime.now(timezone.utc)
    )
    assert s.is_active()
    assert s.closed_at is None

def t_sesion_cerrada_inactiva():
    from datetime import datetime, timezone
    s = BubbleSession(
        session_id="SID001", source_ip=IP,
        opened_at=datetime.now(timezone.utc)
    )
    s.closed_at = datetime.now(timezone.utc)
    assert not s.is_active()

def t_sesion_duracion_positiva():
    from datetime import datetime, timezone
    import time as t
    s = BubbleSession(
        session_id="SID001", source_ip=IP,
        opened_at=datetime.now(timezone.utc)
    )
    t.sleep(0.01)
    assert s.duration_s() > 0

def t_sesion_to_dict_estructura():
    from datetime import datetime, timezone
    s = BubbleSession(
        session_id="SID001", source_ip=IP,
        opened_at=datetime.now(timezone.utc)
    )
    d = s.to_dict()
    assert "session_id"        in d
    assert "source_ip"         in d
    assert "opened_at"         in d
    assert "interaction_count" in d
    assert "interactions"      in d

test("SESIÓN — Recién abierta está activa", t_sesion_abierta_activa)
test("SESIÓN — Cerrada está inactiva", t_sesion_cerrada_inactiva)
test("SESIÓN — Duración positiva mientras activa", t_sesion_duracion_positiva)
test("SESIÓN — to_dict() tiene estructura completa", t_sesion_to_dict_estructura)


# ─────────────────────────────────────────────
# FACHADA — AegisBubble
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 6: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_bubble_inicializa():
    b  = AegisBubble()
    st = b.status()
    assert st["status"]          == "INACTIVE"
    assert st["active_sessions"] == 0
    assert st["total_sessions"]  == 0

def t_bubble_open_session():
    b  = AegisBubble()
    sid = b.open_session(IP)
    assert sid is not None
    assert len(sid) > 0
    assert b.total_sessions() == 1
    assert len(b.active_sessions()) == 1

def t_bubble_session_ids_unicos():
    b    = AegisBubble()
    sid1 = b.open_session("1.1.1.1")
    sid2 = b.open_session("2.2.2.2")
    assert sid1 != sid2

def t_bubble_close_session():
    b   = AegisBubble()
    sid = b.open_session(IP)
    b.close_session(sid)
    s = b.get_session(sid)
    assert s is not None
    assert not s.is_active()
    assert len(b.active_sessions()) == 0

async def t_bubble_interact_retorna_json():
    b   = AegisBubble()
    sid = b.open_session(IP)
    r   = await b.interact(sid, b"test input", InteractionType.API_CALL)
    obj = json.loads(r)
    assert "status" in obj

async def t_bubble_interact_registra_interaccion():
    b   = AegisBubble()
    sid = b.open_session(IP)
    await b.interact(sid, b"test", InteractionType.FILE_READ)
    s = b.get_session(sid)
    assert s.interaction_count == 1
    assert len(s.interactions) == 1

async def t_bubble_interact_latencia_incluida():
    b   = AegisBubble()
    sid = b.open_session(IP)
    t0  = time.monotonic()
    await b.interact(sid, b"test", InteractionType.API_CALL)
    elapsed = (time.monotonic() - t0) * 1000
    # Debe haber aplicado latencia — al menos 10ms
    assert elapsed >= 10, f"Sin latencia detectada: {elapsed:.1f}ms"

async def t_bubble_interact_sesion_invalida():
    b = AegisBubble()
    r = await b.interact("SESION_INEXISTENTE", b"test", InteractionType.UNKNOWN)
    assert "error" in r or "session" in r.lower()

async def t_bubble_respuestas_distintas_consecutivas():
    """El mismo tipo de interacción produce respuestas distintas."""
    b   = AegisBubble()
    sid = b.open_session(IP)
    r1  = await b.interact(sid, b"test", InteractionType.DATA_QUERY)
    r2  = await b.interact(sid, b"test", InteractionType.DATA_QUERY)
    assert r1 != r2

async def t_bubble_callback_forensic():
    b        = AegisBubble()
    received = []
    async def on_forensic(interaction): received.append(interaction)
    b.register_forensic_callback(on_forensic)
    sid = b.open_session(IP)
    await b.interact(sid, b"test", InteractionType.COMMAND)
    assert len(received) == 1
    assert isinstance(received[0], BubbleInteraction)

async def t_bubble_callback_learning():
    b        = AegisBubble()
    received = []
    async def on_learn(interaction): received.append(interaction)
    b.register_learning_callback(on_learn)
    sid = b.open_session(IP)
    await b.interact(sid, b"test", InteractionType.AUTH_ATTEMPT)
    assert len(received) == 1

async def t_bubble_multiples_interacciones_registradas():
    b   = AegisBubble()
    sid = b.open_session(IP)
    for tipo in [InteractionType.FILE_READ, InteractionType.API_CALL,
                 InteractionType.DATA_QUERY]:
        await b.interact(sid, b"test", tipo)
    s = b.get_session(sid)
    assert s.interaction_count == 3
    assert len(s.interactions) == 3

async def t_bubble_evolution_cycle_avanza():
    b   = AegisBubble()
    sid = b.open_session(IP)
    c0  = b.status()["evolution_cycle"]
    await b.interact(sid, b"test", InteractionType.UNKNOWN)
    c1 = b.status()["evolution_cycle"]
    assert c1 > c0

async def t_bubble_log_completo():
    b   = AegisBubble()
    sid = b.open_session(IP)
    await b.interact(sid, b"test", InteractionType.FILE_READ)
    b.close_session(sid)
    log = b.get_full_log()
    assert len(log) == 1
    entry = log[0]
    assert "session_id"        in entry
    assert "interactions"      in entry
    assert "interaction_count" in entry

async def t_bubble_status_activo_con_sesion():
    b   = AegisBubble()
    sid = b.open_session(IP)
    st  = b.status()
    assert st["status"]          == "ACTIVE"
    assert st["active_sessions"] == 1
    b.close_session(sid)
    st2 = b.status()
    assert st2["status"]          == "INACTIVE"
    assert st2["active_sessions"] == 0

test("FACHADA — Inicialización correcta", t_bubble_inicializa)
test("FACHADA — open_session crea sesión activa", t_bubble_open_session)
test("FACHADA — Session IDs son únicos", t_bubble_session_ids_unicos)
test("FACHADA — close_session cierra correctamente", t_bubble_close_session)
test("FACHADA — interact retorna JSON válido", t_bubble_interact_retorna_json)
test("FACHADA — interact registra interacción en sesión", t_bubble_interact_registra_interaccion)
test("FACHADA — interact aplica latencia real", t_bubble_interact_latencia_incluida)
test("FACHADA — Sesión inválida retorna error", t_bubble_interact_sesion_invalida)
test("FACHADA — Respuestas distintas en interacciones consecutivas", t_bubble_respuestas_distintas_consecutivas)
test("FACHADA — Callback forense recibe BubbleInteraction", t_bubble_callback_forensic)
test("FACHADA — Callback learning recibe BubbleInteraction", t_bubble_callback_learning)
test("FACHADA — Múltiples interacciones todas registradas", t_bubble_multiples_interacciones_registradas)
test("FACHADA — Evolution cycle avanza con interacciones", t_bubble_evolution_cycle_avanza)
test("FACHADA — Log completo exportable", t_bubble_log_completo)
test("FACHADA — Status refleja sesiones activas", t_bubble_status_activo_con_sesion)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 6 — Burbuja Evolutiva OPERATIVA")
    print("  AEGIS puede continuar construcción de Capa 7")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
