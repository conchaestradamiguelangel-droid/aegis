"""
AEGIS — Tests de Integración MACE
===================================
Tests que verifican:
1. El proxy arranca y escucha en el puerto configurado
2. El proxy reenvía correctamente peticiones a MACE (simulado)
3. El proxy bloquea IPs detectadas y no las reenvía a MACE
4. El conector bloquea IPs al recibir callbacks de AEGIS
5. La integración completa con AegisSystem funciona
"""

import asyncio
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aiohttp
from aiohttp import web

from integrations.mace_proxy     import MaceProxy, Blocklist, ProxyStats
from integrations.mace_connector import MaceConnector

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []


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
# SERVIDOR MACE SIMULADO
# Para tests — escucha en un puerto libre y responde 200 OK
# ─────────────────────────────────────────────

async def _start_fake_mace(port: int) -> tuple:
    """Arranca un servidor HTTP mínimo que simula MACE."""
    hits = []

    async def handler(request):
        hits.append({
            "method": request.method,
            "path":   request.path,
            "ip":     request.headers.get("X-Forwarded-For", "?"),
        })
        return web.Response(
            text         = '{"status": "ok", "from": "MACE"}',
            content_type = "application/json",
        )

    app    = web.Application()
    app.router.add_route("*", "/{path_info:.*}", handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site   = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner, hits


# ─────────────────────────────────────────────
# BLOQUE 1 — BLOCKLIST
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 1: Blocklist")
print("═══════════════════════════════════════════════")

def t_blocklist_vacia_inicialmente():
    bl = Blocklist()
    assert bl.active_count() == 0
    assert bl.to_list() == []

def t_blocklist_bloquea_ip():
    bl = Blocklist()
    bl.block("1.2.3.4", ttl_s=60)
    assert bl.is_blocked("1.2.3.4")

def t_blocklist_no_bloquea_ip_no_registrada():
    bl = Blocklist()
    assert not bl.is_blocked("9.9.9.9")

def t_blocklist_desbloquea_ip():
    bl = Blocklist()
    bl.block("1.2.3.4", ttl_s=60)
    bl.unblock("1.2.3.4")
    assert not bl.is_blocked("1.2.3.4")

def t_blocklist_ttl_expirado():
    """IP con TTL=0 expira inmediatamente."""
    bl = Blocklist()
    bl.block("1.2.3.4", ttl_s=-1)
    assert not bl.is_blocked("1.2.3.4")

def t_blocklist_cuenta_activas():
    bl = Blocklist()
    bl.block("1.1.1.1", ttl_s=60)
    bl.block("2.2.2.2", ttl_s=60)
    bl.block("3.3.3.3", ttl_s=-1)  # ya expirado
    assert bl.active_count() == 2

def t_blocklist_to_list():
    bl = Blocklist()
    bl.block("10.0.0.1", ttl_s=60)
    bl.block("10.0.0.2", ttl_s=60)
    lst = bl.to_list()
    assert "10.0.0.1" in lst
    assert "10.0.0.2" in lst

test("BLOCKLIST — Vacía inicialmente",              t_blocklist_vacia_inicialmente)
test("BLOCKLIST — Bloquea IP",                      t_blocklist_bloquea_ip)
test("BLOCKLIST — No bloquea IP desconocida",       t_blocklist_no_bloquea_ip_no_registrada)
test("BLOCKLIST — Desbloquea IP",                   t_blocklist_desbloquea_ip)
test("BLOCKLIST — TTL expirado desbloquea",         t_blocklist_ttl_expirado)
test("BLOCKLIST — Cuenta solo activas",             t_blocklist_cuenta_activas)
test("BLOCKLIST — to_list retorna IPs activas",     t_blocklist_to_list)


# ─────────────────────────────────────────────
# BLOQUE 2 — PROXY: ARRANQUE Y ESTADO
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 2: Proxy Arranque")
print("═══════════════════════════════════════════════")

async def t_proxy_arranca_y_para():
    """El proxy arranca en el puerto configurado y para limpiamente."""
    proxy = MaceProxy(
        target_url  = "http://localhost:19001",
        listen_port = 18901,
    )
    await proxy.start()
    st = proxy.status()
    assert st["running"]     is True
    assert "18901"           in st["listen"]
    await proxy.stop()

async def t_proxy_status_estructura():
    """status() retorna todos los campos esperados."""
    proxy = MaceProxy(
        target_url  = "http://localhost:19002",
        listen_port = 18902,
    )
    await proxy.start()
    st = proxy.status()
    for campo in ["listen", "target", "running", "blocked_ips", "stats"]:
        assert campo in st, f"Falta campo: {campo}"
    await proxy.stop()

async def t_proxy_stats_iniciales_cero():
    """Estadísticas iniciales en cero."""
    proxy = MaceProxy(
        target_url  = "http://localhost:19003",
        listen_port = 18903,
    )
    await proxy.start()
    st = proxy.stats.to_dict()
    assert st["requests_total"]     == 0
    assert st["requests_blocked"]   == 0
    assert st["requests_forwarded"] == 0
    await proxy.stop()

test("PROXY — Arranca y para limpiamente",          t_proxy_arranca_y_para)
test("PROXY — status() estructura completa",        t_proxy_status_estructura)
test("PROXY — Stats iniciales en cero",             t_proxy_stats_iniciales_cero)


# ─────────────────────────────────────────────
# BLOQUE 3 — PROXY: REENVÍO A MACE
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 3: Reenvío a MACE")
print("═══════════════════════════════════════════════")

async def t_proxy_reenvía_a_mace():
    """El proxy reenvía peticiones al servidor MACE simulado."""
    fake_runner, hits = await _start_fake_mace(19010)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19010",
        listen_port = 18910,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:18910/api/test") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["from"] == "MACE"
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    assert hits[0]["path"] == "/api/test"


async def t_proxy_incrementa_contador_forwarded():
    """Cada reenvío exitoso incrementa requests_forwarded."""
    fake_runner, hits = await _start_fake_mace(19011)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19011",
        listen_port = 18911,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            for _ in range(3):
                await session.get("http://127.0.0.1:18911/ping")
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert proxy.stats.requests_forwarded == 3
    assert proxy.stats.requests_total     == 3


async def t_proxy_añade_header_x_forwarded():
    """El proxy añade X-Forwarded-By a las peticiones reenviadas."""
    fake_runner, hits = await _start_fake_mace(19012)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19012",
        listen_port = 18912,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            await session.get("http://127.0.0.1:18912/check")
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    # El proxy debe haber enviado X-Forwarded-For
    assert hits[0]["ip"] != "?"


async def t_proxy_retorna_502_si_mace_no_responde():
    """Si MACE no está disponible, el proxy retorna 502."""
    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19999",   # nadie escucha aquí
        listen_port = 18913,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://127.0.0.1:18913/test",
                timeout=aiohttp.ClientTimeout(total=3)
            ) as resp:
                assert resp.status == 502
    finally:
        await proxy.stop()

    assert proxy.stats.errors == 1


test("REENVÍO — Proxy reenvía a MACE simulado",    t_proxy_reenvía_a_mace)
test("REENVÍO — Contador forwarded incrementa",     t_proxy_incrementa_contador_forwarded)
test("REENVÍO — Añade X-Forwarded-For",            t_proxy_añade_header_x_forwarded)
test("REENVÍO — 502 si MACE no responde",          t_proxy_retorna_502_si_mace_no_responde)


# ─────────────────────────────────────────────
# BLOQUE 4 — PROXY: BLOQUEO DE IPs
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 4: Bloqueo de IPs")
print("═══════════════════════════════════════════════")

async def t_ip_bloqueada_no_llega_a_mace():
    """Una IP en la blocklist recibe 403 y MACE no recibe nada."""
    fake_runner, hits = await _start_fake_mace(19020)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19020",
        listen_port = 18920,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    # Bloquear la IP del cliente de test (127.0.0.1)
    proxy.blocklist.block("127.0.0.1", ttl_s=60)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:18920/secret") as resp:
                assert resp.status == 403
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 0, "MACE recibió petición de IP bloqueada"
    assert proxy.stats.requests_blocked == 1


async def t_ip_desbloqueada_vuelve_a_llegar():
    """Una IP desbloqueada vuelve a pasar a MACE."""
    fake_runner, hits = await _start_fake_mace(19021)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19021",
        listen_port = 18921,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    proxy.blocklist.block("127.0.0.1", ttl_s=60)
    proxy.blocklist.unblock("127.0.0.1")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:18921/ok") as resp:
                assert resp.status == 200
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1, "MACE no recibió petición tras desbloqueo"


async def t_ip_no_bloqueada_pasa_normalmente():
    """IPs no bloqueadas siempre llegan a MACE."""
    fake_runner, hits = await _start_fake_mace(19022)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19022",
        listen_port = 18922,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    proxy.blocklist.block("10.0.0.1", ttl_s=60)   # bloquear otra IP

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://127.0.0.1:18922/libre") as resp:
                assert resp.status == 200
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1


test("BLOQUEO — IP bloqueada → 403 y MACE no recibe", t_ip_bloqueada_no_llega_a_mace)
test("BLOQUEO — IP desbloqueada vuelve a pasar",       t_ip_desbloqueada_vuelve_a_llegar)
test("BLOQUEO — IP no bloqueada pasa normalmente",     t_ip_no_bloqueada_pasa_normalmente)


# ─────────────────────────────────────────────
# BLOQUE 5 — CONECTOR
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 5: Conector AEGIS → Proxy")
print("═══════════════════════════════════════════════")

def _make_detection_event(ips: list, det_type: str = "MINE_CONTACT"):
    """Crea un objeto mínimo que simula un DetectionEvent de C3."""
    class FakeType:
        value = det_type
    class FakeEvent:
        source_ips    = ips
        detection_type= FakeType()
    return FakeEvent()


def _make_mine_contact(ip: str, mine_name: str = "backup.json"):
    """Crea un objeto mínimo que simula un MineContact de C2."""
    class FakeMineType:
        value = "FILE"
    _ip        = ip
    _mine_name = mine_name
    class FakeContact:
        source_ip = _ip
        mine_name = _mine_name
        mine_type = FakeMineType()
    return FakeContact()


def t_connector_inicializa():
    proxy = MaceProxy(target_url="http://localhost:19030", listen_port=18930)
    conn  = MaceConnector(proxy)
    st    = conn.status()
    assert st["blocks_total"]  == 0
    assert st["active_blocks"] == 0
    assert st["events_logged"] == 0


async def t_connector_bloquea_ip_en_deteccion():
    """on_detection() bloquea todas las IPs del evento."""
    proxy = MaceProxy(target_url="http://localhost:19031", listen_port=18931)
    conn  = MaceConnector(proxy)
    event = _make_detection_event(["5.5.5.5", "6.6.6.6"])

    await conn.on_detection(event)

    assert proxy.blocklist.is_blocked("5.5.5.5")
    assert proxy.blocklist.is_blocked("6.6.6.6")
    assert conn.status()["blocks_total"] == 2


async def t_connector_bloquea_ip_en_mine_contact():
    """on_mine_contact() bloquea la IP del contacto con TTL mayor."""
    proxy   = MaceProxy(target_url="http://localhost:19032", listen_port=18932)
    conn    = MaceConnector(proxy)
    contact = _make_mine_contact("7.7.7.7", "credentials.env")

    await conn.on_mine_contact(contact)

    assert proxy.blocklist.is_blocked("7.7.7.7")
    assert conn.status()["blocks_total"] == 1


async def t_connector_registra_evento_en_log():
    """Cada bloqueo genera entrada en el log."""
    proxy = MaceProxy(target_url="http://localhost:19033", listen_port=18933)
    conn  = MaceConnector(proxy)
    event = _make_detection_event(["8.8.8.8"])

    await conn.on_detection(event)

    log = conn.get_event_log()
    assert len(log) == 1
    assert log[0]["event_type"] == "DETECTION"
    assert "8.8.8.8" in log[0]["source_ips"]


def t_connector_block_ip_manual():
    """block_ip() manual bloquea la IP en el proxy."""
    proxy = MaceProxy(target_url="http://localhost:19034", listen_port=18934)
    conn  = MaceConnector(proxy)
    conn.block_ip("9.9.9.9", ttl_s=300, reason="test")
    assert proxy.blocklist.is_blocked("9.9.9.9")


def t_connector_unblock_ip():
    """unblock_ip() desbloquea la IP del proxy."""
    proxy = MaceProxy(target_url="http://localhost:19035", listen_port=18935)
    conn  = MaceConnector(proxy)
    conn.block_ip("10.10.10.10")
    conn.unblock_ip("10.10.10.10")
    assert not proxy.blocklist.is_blocked("10.10.10.10")


test("CONECTOR — Inicializa correctamente",          t_connector_inicializa)
test("CONECTOR — on_detection bloquea IPs",          t_connector_bloquea_ip_en_deteccion)
test("CONECTOR — on_mine_contact bloquea IP",        t_connector_bloquea_ip_en_mine_contact)
test("CONECTOR — Registra evento en log",            t_connector_registra_evento_en_log)
test("CONECTOR — block_ip manual",                   t_connector_block_ip_manual)
test("CONECTOR — unblock_ip funciona",               t_connector_unblock_ip)


# ─────────────────────────────────────────────
# BLOQUE 6 — INTEGRACIÓN COMPLETA
# Proxy + Conector + flujo de extremo a extremo
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 6: Integración Extremo a Extremo")
print("═══════════════════════════════════════════════")

async def t_deteccion_bloquea_ip_que_ya_no_llega_a_mace():
    """
    Flujo completo:
    1. Petición normal → llega a MACE ✓
    2. Conector recibe detección para esa IP → la bloquea
    3. Siguiente petición de esa IP → 403, MACE no recibe nada
    """
    fake_runner, hits = await _start_fake_mace(19040)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19040",
        listen_port = 18940,
    )
    conn = MaceConnector(proxy)
    await proxy.start()
    await asyncio.sleep(0.1)

    # Bloquear ambos loopbacks para robustez ante IPv4/IPv6
    ip_atacante = "127.0.0.1"

    try:
        async with aiohttp.ClientSession() as session:
            # Petición 1 — antes del bloqueo → llega a MACE
            resp1 = await session.get("http://127.0.0.1:18940/antes")
            assert resp1.status == 200
            assert len(hits) == 1

            # Simular detección de AEGIS — bloquear ambos loopbacks
            event = _make_detection_event([ip_atacante, "::1"])
            await conn.on_detection(event)

            # Petición 2 — después del bloqueo → bloqueada
            resp2 = await session.get("http://127.0.0.1:18940/despues")
            assert resp2.status == 403
            assert len(hits) == 1   # MACE no recibió la segunda

    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert proxy.stats.requests_blocked   == 1
    assert proxy.stats.requests_forwarded == 1
    print(f"\n    E2E: 1 forwarded + 1 blocked ✓")


async def t_mine_contact_bloquea_y_protege_mace():
    """
    Toque de señuelo C2 → conector bloquea IP → MACE protegido.
    """
    fake_runner, hits = await _start_fake_mace(19041)

    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19041",
        listen_port = 18941,
    )
    conn = MaceConnector(proxy)
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        # Simular contacto con señuelo — bloquear ambos loopbacks
        contact = _make_mine_contact("127.0.0.1", "backup.json")
        await conn.on_mine_contact(contact)
        proxy.blocklist.block("::1", ttl_s=60)   # IPv6 loopback en Linux

        # Petición de esa IP → bloqueada
        async with aiohttp.ClientSession() as session:
            resp = await session.get("http://127.0.0.1:18941/after_mine")
            assert resp.status == 403, \
                f"Esperado 403, obtenido {resp.status}"

    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 0, \
        f"MACE recibió {len(hits)} peticiones — IP no fue bloqueada"
    print(f"\n    Mine → block → MACE protegido ✓")


async def t_aegissystem_start_mace_integration():
    """start_mace_integration() en AegisSystem arranca el proxy."""
    from core.aegis import AegisSystem

    fake_runner, hits = await _start_fake_mace(19042)
    aegis = AegisSystem(installation_id="AEGIS-MACE-TEST")

    try:
        await aegis.start()
        connector = await aegis.start_mace_integration(
            target_url  = "http://127.0.0.1:19042",
            listen_port = 18942,
        )
        await asyncio.sleep(0.1)

        # Verificar que el proxy responde
        async with aiohttp.ClientSession() as session:
            resp = await session.get("http://127.0.0.1:18942/health")
            assert resp.status == 200

        # Verificar que MACE recibió la petición
        assert len(hits) == 1

        # Verificar estado del conector
        st = connector.status()
        assert "proxy_stats" in st

    finally:
        await aegis.stop_mace_integration()
        await aegis.stop()
        await fake_runner.cleanup()

    print(f"\n    AegisSystem + MACE proxy: integración completa ✓")


test("E2E — Detección → bloqueo → MACE protegido",
     t_deteccion_bloquea_ip_que_ya_no_llega_a_mace)
test("E2E — Mine contact → bloqueo → MACE no recibe",
     t_mine_contact_bloquea_y_protege_mace)
test("E2E — AegisSystem.start_mace_integration funciona",
     t_aegissystem_start_mace_integration)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Integración MACE — Proxy + Conector OPERATIVOS")
    print("  MACE protegido sin modificar una sola línea de MACE")
else:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS "
          f"({'✓' if failed == 0 else '✗'})")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
