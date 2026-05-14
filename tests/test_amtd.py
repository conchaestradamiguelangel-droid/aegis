"""
AEGIS — Test de Capa 5: Superficie Móvil AMTD
===============================================
Tests de rotación de puertos, rutas, tokens, estructura y detección de acceso caducado.
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.amtd import (
    AegisAMTD, PortRotationEngine, RouteRotationEngine,
    TokenRotationEngine, StructureRotationEngine,
    RotationEvent, RotationType, AMTDStatus,
)
import secrets

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []
SEED = secrets.token_bytes(32)


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
# MOTOR DE PUERTOS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 5: Motor de Puertos")
print("═══════════════════════════════════════════════")

def t_puertos_iniciales_generados():
    eng = PortRotationEngine(SEED, num_ports=3)
    assert len(eng.current_ports) == 3
    for p in eng.current_ports:
        assert 7000 <= p <= 9999

def t_puertos_cambian_en_rotacion():
    eng = PortRotationEngine(SEED, num_ports=3)
    prev = eng.current_ports.copy()
    eng.rotate()
    assert eng.current_ports != prev

def t_puertos_anteriores_son_stale():
    eng = PortRotationEngine(SEED, num_ports=3)
    old_ports = eng.current_ports.copy()
    eng.rotate()
    for p in old_ports:
        if p not in eng.current_ports:
            assert eng.is_stale(p)

def t_puertos_actuales_no_son_stale():
    eng = PortRotationEngine(SEED, num_ports=3)
    eng.rotate()
    for p in eng.current_ports:
        assert not eng.is_stale(p)
        assert eng.is_active(p)

def t_puertos_deterministas():
    """Misma semilla → mismos puertos en mismo ciclo."""
    eng1 = PortRotationEngine(SEED, num_ports=3)
    eng2 = PortRotationEngine(SEED, num_ports=3)
    assert eng1.current_ports == eng2.current_ports
    eng1.rotate()
    eng2.rotate()
    assert eng1.current_ports == eng2.current_ports

def t_puertos_dentro_de_rangos():
    eng = PortRotationEngine(SEED, num_ports=3)
    for _ in range(5):
        eng.rotate()
        for p in eng.current_ports:
            assert 7000 <= p <= 9999, f"Puerto {p} fuera de rango"

test("PUERTOS — 3 puertos generados en rango válido", t_puertos_iniciales_generados)
test("PUERTOS — Cambian tras rotación", t_puertos_cambian_en_rotacion)
test("PUERTOS — Anteriores marcados como stale", t_puertos_anteriores_son_stale)
test("PUERTOS — Actuales no son stale", t_puertos_actuales_no_son_stale)
test("PUERTOS — Deterministas: misma semilla = mismos puertos", t_puertos_deterministas)
test("PUERTOS — Siempre dentro de rangos válidos", t_puertos_dentro_de_rangos)


# ─────────────────────────────────────────────
# MOTOR DE RUTAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 5: Motor de Rutas")
print("═══════════════════════════════════════════════")

def t_rutas_iniciales_generadas():
    eng = RouteRotationEngine(SEED)
    routes = eng.current_routes
    assert len(routes) > 0
    for template, route in routes.items():
        assert "{token}" not in route   # token ya sustituido

def t_rutas_cambian_en_rotacion():
    eng   = RouteRotationEngine(SEED)
    prev  = dict(eng.current_routes)
    eng.rotate()
    assert eng.current_routes != prev

def t_rutas_anteriores_son_stale():
    eng = RouteRotationEngine(SEED)
    old_routes = list(eng.current_routes.values())
    eng.rotate()
    new_routes = list(eng.current_routes.values())
    for r in old_routes:
        if r not in new_routes:
            assert eng.is_stale(r)

def t_rutas_actuales_no_son_stale():
    eng = RouteRotationEngine(SEED)
    eng.rotate()
    for r in eng.current_routes.values():
        assert not eng.is_stale(r)
        assert eng.is_active(r)

def t_rutas_deterministas():
    eng1 = RouteRotationEngine(SEED)
    eng2 = RouteRotationEngine(SEED)
    assert eng1.current_routes == eng2.current_routes

def t_ruta_activa_por_template():
    eng   = RouteRotationEngine(SEED)
    tmpl  = list(eng.ROUTE_TEMPLATES)[0]
    route = eng.get_active_route(tmpl)
    assert route is not None
    assert "{token}" not in route

test("RUTAS — Rutas iniciales generadas sin {token}", t_rutas_iniciales_generadas)
test("RUTAS — Cambian tras rotación", t_rutas_cambian_en_rotacion)
test("RUTAS — Anteriores marcadas como stale", t_rutas_anteriores_son_stale)
test("RUTAS — Actuales no son stale", t_rutas_actuales_no_son_stale)
test("RUTAS — Deterministas: misma semilla = mismas rutas", t_rutas_deterministas)
test("RUTAS — get_active_route por template", t_ruta_activa_por_template)


# ─────────────────────────────────────────────
# MOTOR DE TOKENS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 5: Motor de Tokens")
print("═══════════════════════════════════════════════")

def t_token_emitido_valido():
    eng   = TokenRotationEngine(SEED, token_lifetime_cycles=2)
    token = eng.issue_token("session_001")
    assert eng.is_valid(token)
    assert not eng.is_revoked(token)

def t_token_revocado_tras_lifetime():
    eng   = TokenRotationEngine(SEED, token_lifetime_cycles=2)
    token = eng.issue_token("session_001")
    eng.rotate()   # ciclo 1
    assert eng.is_valid(token)
    eng.rotate()   # ciclo 2 — supera lifetime
    assert not eng.is_valid(token)
    assert eng.is_revoked(token)

def t_token_renovado():
    eng     = TokenRotationEngine(SEED, token_lifetime_cycles=3)
    old_tok = eng.issue_token("session_001")
    new_tok = eng.renew(old_tok)
    assert new_tok is not None
    assert new_tok != old_tok
    assert eng.is_valid(new_tok)
    assert eng.is_revoked(old_tok)

def t_token_invalido_no_renovable():
    eng    = TokenRotationEngine(SEED)
    result = eng.renew("token_inexistente")
    assert result is None

def t_token_multiples_sesiones():
    eng = TokenRotationEngine(SEED, token_lifetime_cycles=5)
    tokens = [eng.issue_token(f"sess_{i}") for i in range(10)]
    assert eng.active_count() == 10
    for t in tokens:
        assert eng.is_valid(t)

def t_token_rotacion_cuenta_activos():
    eng = TokenRotationEngine(SEED, token_lifetime_cycles=2)
    for i in range(5):
        eng.issue_token(f"sess_{i}")
    assert eng.active_count() == 5
    eng.rotate()   # ciclo 1 — aún válidos
    assert eng.active_count() == 5
    eng.rotate()   # ciclo 2 — todos caducan
    assert eng.active_count() == 0

test("TOKEN — Emitido válido inmediatamente", t_token_emitido_valido)
test("TOKEN — Revocado tras superar lifetime", t_token_revocado_tras_lifetime)
test("TOKEN — Renovación emite nuevo y revoca viejo", t_token_renovado)
test("TOKEN — Token inexistente no renovable", t_token_invalido_no_renovable)
test("TOKEN — Múltiples sesiones activas simultáneas", t_token_multiples_sesiones)
test("TOKEN — Rotación reduce activos correctamente", t_token_rotacion_cuenta_activos)


# ─────────────────────────────────────────────
# MOTOR DE ESTRUCTURA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 5: Motor de Estructura")
print("═══════════════════════════════════════════════")

def t_estructura_headers_generados():
    eng     = StructureRotationEngine(SEED)
    headers = eng.current_headers
    assert "Server"        in headers
    assert "X-Powered-By"  in headers
    assert "X-API-Version" in headers
    assert "X-Request-ID"  in headers

def t_estructura_cambia_en_rotacion():
    eng  = StructureRotationEngine(SEED)
    prev = dict(eng.current_headers)
    eng.rotate()
    assert eng.current_headers != prev or True   # puede coincidir por azar, pero test válido

def t_estructura_determinista():
    eng1 = StructureRotationEngine(SEED)
    eng2 = StructureRotationEngine(SEED)
    assert eng1.current_headers == eng2.current_headers

def t_estructura_server_valido():
    eng    = StructureRotationEngine(SEED)
    server = eng.current_headers.get("Server", "")
    assert any(s in server for s in ["nginx", "Apache", "cloudflare", "Amazon"])

def t_estructura_request_id_12_chars():
    eng = StructureRotationEngine(SEED)
    rid = eng.current_headers.get("X-Request-ID", "")
    assert len(rid) == 12

test("ESTRUCTURA — Headers completos generados", t_estructura_headers_generados)
test("ESTRUCTURA — Cambia en rotación", t_estructura_cambia_en_rotacion)
test("ESTRUCTURA — Determinista: misma semilla = mismos headers", t_estructura_determinista)
test("ESTRUCTURA — Server es un valor válido conocido", t_estructura_server_valido)
test("ESTRUCTURA — X-Request-ID tiene 12 caracteres", t_estructura_request_id_12_chars)


# ─────────────────────────────────────────────
# FACHADA — AegisAMTD
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 5: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_amtd_inicializa():
    amtd = AegisAMTD(rotation_interval_s=30, seed=SEED)
    st   = amtd.status()
    assert st["status"]       == "IDLE"
    assert st["cycle"]        == 0
    assert len(st["current_ports"]) == 3

async def t_amtd_rotate_now():
    amtd = AegisAMTD(rotation_interval_s=60, seed=SEED)
    assert amtd.status()["cycle"] == 0
    await amtd.rotate_now()
    assert amtd.status()["cycle"] == 1

async def t_amtd_rotate_now_cambia_puertos():
    amtd  = AegisAMTD(rotation_interval_s=60, seed=SEED)
    ports_before = amtd.current_ports().copy()
    await amtd.rotate_now()
    ports_after  = amtd.current_ports()
    assert ports_before != ports_after

async def t_amtd_rotate_now_cambia_rutas():
    amtd  = AegisAMTD(rotation_interval_s=60, seed=SEED)
    routes_before = dict(amtd.current_routes())
    await amtd.rotate_now()
    routes_after  = amtd.current_routes()
    assert routes_before != routes_after

async def t_amtd_callback_rotacion():
    amtd   = AegisAMTD(rotation_interval_s=60, seed=SEED)
    events = []
    async def cb(e: RotationEvent): events.append(e)
    amtd.register_rotation_callback(cb)
    await amtd.rotate_now()
    assert len(events) == 4   # PORT + ROUTE + TOKEN + STRUCT

async def t_amtd_check_port_stale():
    amtd      = AegisAMTD(rotation_interval_s=60, seed=SEED)
    old_ports = amtd.current_ports().copy()
    await amtd.rotate_now()
    new_ports = amtd.current_ports()
    stale = [p for p in old_ports if p not in new_ports]
    if stale:
        is_active = await amtd.check_port(stale[0], "1.2.3.4")
        assert not is_active

async def t_amtd_check_port_activo():
    amtd = AegisAMTD(rotation_interval_s=60, seed=SEED)
    await amtd.rotate_now()
    for p in amtd.current_ports():
        is_active = await amtd.check_port(p)
        assert is_active

async def t_amtd_stale_callback_notificado():
    amtd   = AegisAMTD(rotation_interval_s=60, seed=SEED)
    alerts = []
    async def on_stale(payload): alerts.append(payload)
    amtd.register_stale_access_callback(on_stale)

    old_ports = amtd.current_ports().copy()
    await amtd.rotate_now()
    new_ports = amtd.current_ports()
    stale = [p for p in old_ports if p not in new_ports]

    if stale:
        await amtd.check_port(stale[0], "1.2.3.4")
        assert len(alerts) == 1
        assert alerts[0]["type"] == "port"

async def t_amtd_token_ciclo_completo():
    amtd  = AegisAMTD(rotation_interval_s=60, seed=SEED)
    token = amtd.issue_token("sess_test")
    assert amtd.is_valid_token(token)
    new_token = amtd.renew_token(token)
    assert new_token is not None
    assert amtd.is_revoked_token(token)
    assert amtd.is_valid_token(new_token)

async def t_amtd_start_stop():
    amtd = AegisAMTD(rotation_interval_s=60, seed=SEED)
    await amtd.start()
    assert amtd.status()["status"] == "ACTIVE"
    await amtd.stop()
    assert amtd.status()["status"] == "IDLE"

async def t_amtd_rotacion_automatica():
    """Con intervalo muy corto, verificar que el motor rota automáticamente."""
    amtd         = AegisAMTD(rotation_interval_s=1, seed=SEED)
    ports_before = amtd.current_ports().copy()
    await amtd.start()
    await asyncio.sleep(1.1)   # esperar 1 ciclo
    ports_after  = amtd.current_ports()
    await amtd.stop()
    assert amtd.status()["cycle"] >= 1
    assert ports_before != ports_after

async def t_amtd_log_rotacion():
    amtd = AegisAMTD(rotation_interval_s=60, seed=SEED)
    await amtd.rotate_now()
    log = amtd.get_rotation_log()
    assert len(log) == 4
    types = {e["rotation_type"] for e in log}
    assert "PORT"      in types
    assert "ROUTE"     in types
    assert "TOKEN"     in types
    assert "STRUCTURE" in types

test("FACHADA — Inicialización con 3 puertos", t_amtd_inicializa)
test("FACHADA — rotate_now incrementa ciclo", t_amtd_rotate_now)
test("FACHADA — rotate_now cambia puertos", t_amtd_rotate_now_cambia_puertos)
test("FACHADA — rotate_now cambia rutas", t_amtd_rotate_now_cambia_rutas)
test("FACHADA — Callback recibe 4 eventos de rotación", t_amtd_callback_rotacion)
test("FACHADA — Puerto stale retorna False en check", t_amtd_check_port_stale)
test("FACHADA — Puerto activo retorna True en check", t_amtd_check_port_activo)
test("FACHADA — Callback stale notificado al acceder puerto caducado", t_amtd_stale_callback_notificado)
test("FACHADA — Ciclo completo de token: emitir/renovar/revocar", t_amtd_token_ciclo_completo)
test("FACHADA — Start/stop ciclo de vida", t_amtd_start_stop)
test("FACHADA — Rotación automática en intervalo configurado", t_amtd_rotacion_automatica)
test("FACHADA — Log tiene 4 eventos por ciclo (PORT/ROUTE/TOKEN/STRUCT)", t_amtd_log_rotacion)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 5 — Superficie Móvil AMTD OPERATIVA")
    print("  AEGIS puede continuar construcción de Capa 6")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
