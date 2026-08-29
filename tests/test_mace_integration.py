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

# IP de prueba que simula al "atacante" -- loopback pero fuera del
# LOOPBACK_WHITELIST (que solo cubre 127.0.0.1 y ::1), para poder
# verificar bloqueo real sin chocar con la proteccion anti-self-lockout.
ATTACKER_IP = "127.0.0.2"

def _attacker_session() -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(local_addr=(ATTACKER_IP, 0))
    return aiohttp.ClientSession(connector=connector)

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
# BLOQUE 3.5 — PROXY: X-FORWARDED-FOR / TRUSTED PROXIES
# Regresión del hallazgo de seguridad P0 (auditoría 2026-08-29):
# un cliente arbitrario no debe poder suplantar su IP ni evadir un
# bloqueo fijando X-Forwarded-For, salvo que el peer TCP esté en
# AEGIS_TRUSTED_PROXIES.
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  MACE — Bloque 3.5: X-Forwarded-For / trusted proxies")
print("═══════════════════════════════════════════════")

import ipaddress

from integrations.mace_proxy import (
    _parse_trusted_proxies,
    _peer_is_trusted,
    _normalize_ip,
    _resolve_client_ip,
)


# ── Unitarios puros de _normalize_ip / _resolve_client_ip (sin red) ────────

def t_normalize_ip_rechaza_formatos_invalidos():
    """CIDR, IP con puerto, texto arbitrario, vacío y octeto con cero
    ambiguo (010.x, ataque de normalización clásico) se rechazan."""
    assert _normalize_ip("10.0.0.0/8") is None
    assert _normalize_ip("6.6.6.6:1234") is None
    assert _normalize_ip("[::1]:1234") is None
    assert _normalize_ip("not-an-ip") is None
    assert _normalize_ip("") is None
    assert _normalize_ip("   ") is None
    assert _normalize_ip("010.0.0.1") is None  # octeto ambiguo, Python lo rechaza


def t_normalize_ip_normaliza_ipv4_ipv6_validas():
    assert _normalize_ip(" 203.0.113.9 ") == "203.0.113.9"
    assert _normalize_ip("2001:db8::1") == "2001:db8::1"
    # forma expandida y comprimida deben normalizar a la misma identidad
    assert _normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def t_normalize_ip_desenvuelve_ipv4_mapped_loopback():
    """
    ::ffff:127.0.0.1 debe desenvolverse a 127.0.0.1 — verificado
    empíricamente que IPv6Address("::ffff:127.0.0.1").is_loopback da
    False en este runtime, así que sin desenvolver primero, esta
    forma se colaría como si no fuese loopback.
    """
    assert _normalize_ip("::ffff:127.0.0.1") == "127.0.0.1"


def t_normalize_ip_desenvuelve_ipv4_mapped_unspecified():
    """::ffff:0.0.0.0 debe desenvolverse a 0.0.0.0 (mismo motivo que arriba, con is_unspecified)."""
    assert _normalize_ip("::ffff:0.0.0.0") == "0.0.0.0"


def t_normalize_ip_desenvuelve_ipv4_mapped_publica():
    """Una IPv4 pública mapeada también se desenvuelve, no solo los casos especiales."""
    assert _normalize_ip("::ffff:8.8.8.8") == "8.8.8.8"


def t_normalize_ip_ipv4_mapped_y_ipv4_normal_misma_identidad():
    """
    El requisito central: una IPv4 normal y su equivalente
    IPv4-mapped IPv6 deben producir EXACTAMENTE la misma cadena — si
    no, "8.8.8.8" y "::ffff:8.8.8.8" serían dos identidades distintas
    para blocklist/whitelist (evasión de bloqueo por disfraz de
    protocolo).
    """
    assert _normalize_ip("8.8.8.8") == _normalize_ip("::ffff:8.8.8.8") == "8.8.8.8"


def t_resolve_client_ip_toma_el_ultimo_no_el_primero():
    """
    Regresión directa del hallazgo P0 (2026-08-29): con un proxy
    confiable delante, la IP del cliente es la que ese proxy AÑADIÓ al
    final de la cadena — no lo que el propio cliente pudo anteponer.
    """
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip           = "203.0.113.1",
        forwarded_header  = "6.6.6.6, 203.0.113.1, 198.51.100.7",
        trusted_networks  = trusted,
    )
    assert resolved == "198.51.100.7", (
        f"debía tomar el último valor no confiable, tomó: {resolved!r}"
    )


def t_resolve_client_ip_cadena_multisalto_confiable():
    """Con 2 proxies confiables encadenados, salta ambos y llega al cliente real."""
    hop_a  = ipaddress.ip_network("10.0.0.1/32")
    hop_b  = ipaddress.ip_network("10.0.0.2/32")
    trusted = frozenset({hop_a, hop_b})
    resolved = _resolve_client_ip(
        peer_ip          = "10.0.0.2",                 # hop_b es nuestro peer directo
        forwarded_header = "198.51.100.7, 10.0.0.1",    # cliente real, luego hop_a
        trusted_networks = trusted,
    )
    assert resolved == "198.51.100.7"


def t_resolve_client_ip_solo_proxies_confiables_cae_a_peer():
    """Si toda la cadena son proxies confiables (sin cliente real detrás), fallback seguro."""
    hop_a = ipaddress.ip_network("10.0.0.1/32")
    trusted = frozenset({hop_a})
    resolved = _resolve_client_ip(
        peer_ip          = "10.0.0.1",
        forwarded_header = "10.0.0.1",
        trusted_networks = trusted,
    )
    assert resolved == "10.0.0.1"


def t_resolve_client_ip_entrada_malformada_cae_a_peer():
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "6.6.6.6, not-an-ip",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1"


def t_resolve_client_ip_ip_con_puerto_rechazada():
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "6.6.6.6:1234",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1"


def t_resolve_client_ip_cidr_rechazado():
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "10.0.0.0/8",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1"


def t_resolve_client_ip_loopback_ipv4_inyectado_no_se_acepta():
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "127.0.0.1",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1", (
        f"127.0.0.1 inyectada no debe aceptarse como identidad del cliente: {resolved!r}"
    )


def t_resolve_client_ip_loopback_ipv6_inyectado_no_se_acepta():
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "::1",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1", (
        f"::1 inyectada no debe aceptarse como identidad del cliente: {resolved!r}"
    )


def t_resolve_client_ip_loopback_ipv4_mapped_inyectado_no_se_acepta():
    """::ffff:127.0.0.1 debe rechazarse igual que 127.0.0.1 (disfraz IPv4-mapped)."""
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "::ffff:127.0.0.1",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1", (
        f"::ffff:127.0.0.1 inyectada no debe aceptarse: {resolved!r}"
    )


def t_resolve_client_ip_unspecified_ipv4_mapped_inyectado_no_se_acepta():
    """::ffff:0.0.0.0 debe rechazarse igual que 0.0.0.0."""
    trusted = frozenset({ipaddress.ip_network("203.0.113.1/32")})
    resolved = _resolve_client_ip(
        peer_ip          = "203.0.113.1",
        forwarded_header = "::ffff:0.0.0.0",
        trusted_networks = trusted,
    )
    assert resolved == "203.0.113.1", (
        f"::ffff:0.0.0.0 inyectada no debe aceptarse: {resolved!r}"
    )


def t_parse_trusted_proxies_ignora_entradas_invalidas():
    """Entradas no-IP se descartan sin romper el arranque."""
    nets = _parse_trusted_proxies("not-an-ip, 10.0.0.0/8, , 192.168.1.5")
    assert len(nets) == 2
    assert _peer_is_trusted("10.1.2.3", nets) is True
    assert _peer_is_trusted("192.168.1.5", nets) is True
    assert _peer_is_trusted("11.1.2.3", nets) is False
    assert _peer_is_trusted("also-not-an-ip", nets) is False


def t_peer_is_trusted_sin_config_siempre_false():
    """Sin AEGIS_TRUSTED_PROXIES, ningún peer es confiable."""
    assert _peer_is_trusted("127.0.0.1", frozenset()) is False


async def t_xff_no_confiado_usa_ip_tcp_real():
    """
    Sin trusted_proxies configurado, un cliente normal que envía
    X-Forwarded-For no consigue que el proxy reenvíe esa IP falsa —
    debe usarse siempre la IP TCP real (peer).
    """
    fake_runner, hits = await _start_fake_mace(19014)
    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19014",
        listen_port = 18914,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            await session.get(
                "http://127.0.0.1:18914/check",
                headers={"X-Forwarded-For": "6.6.6.6"},
            )
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    assert hits[0]["ip"] == "127.0.0.1", (
        f"esperaba la IP TCP real, llegó la XFF falsa: {hits[0]['ip']!r}"
    )


async def t_xff_spoofing_no_suplanta_ip_del_atacante():
    """
    Un atacante conectado desde su propia IP no puede hacer que el
    proxy lo registre/reenvíe como otra IP fijando X-Forwarded-For.
    """
    fake_runner, hits = await _start_fake_mace(19015)
    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19015",
        listen_port = 18915,
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with _attacker_session() as session:
            await session.get(
                "http://127.0.0.1:18915/check",
                headers={"X-Forwarded-For": "8.8.8.8"},
            )
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    assert hits[0]["ip"] == ATTACKER_IP, (
        f"la IP suplantada 8.8.8.8 se coló en vez de {ATTACKER_IP}: {hits[0]['ip']!r}"
    )


async def t_xff_spoofing_no_evade_bloqueo():
    """
    Una IP bloqueada no puede reetiquetarse a sí misma vía
    X-Forwarded-For para colarse igualmente hasta MACE.
    """
    fake_runner, hits = await _start_fake_mace(19016)
    proxy = MaceProxy(
        target_url  = "http://127.0.0.1:19016",
        listen_port = 18916,
    )
    await proxy.start()
    await asyncio.sleep(0.1)
    proxy.blocklist.block(ATTACKER_IP, ttl_s=60)

    try:
        async with _attacker_session() as session:
            async with session.get(
                "http://127.0.0.1:18916/secret",
                headers={"X-Forwarded-For": "1.2.3.4"},  # IP no bloqueada
            ) as resp:
                assert resp.status == 403
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 0, "MACE recibió una petición que debía seguir bloqueada"


async def t_xff_confiado_solo_desde_proxy_configurado():
    """
    Con AEGIS_TRUSTED_PROXIES configurado y el peer dentro de esa
    lista, X-Forwarded-For sí se respeta (caso de uso legítimo: un
    reverse proxy propio delante de MaceProxy).
    """
    fake_runner, hits = await _start_fake_mace(19017)
    proxy = MaceProxy(
        target_url      = "http://127.0.0.1:19017",
        listen_port     = 18917,
        trusted_proxies = "127.0.0.1",  # el cliente de test conecta desde aquí
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            await session.get(
                "http://127.0.0.1:18917/check",
                headers={"X-Forwarded-For": "203.0.113.5"},
            )
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    assert hits[0]["ip"] == "203.0.113.5", (
        f"peer confiable pero XFF no respetado: {hits[0]['ip']!r}"
    )


async def t_xff_cadena_multiple_toma_ultimo_valor():
    """
    Extremo a extremo: con un proxy confiable delante y una cabecera
    de varios valores (cliente antepone un decoy, el proxy añade el
    suyo al final), MACE debe ver el ÚLTIMO valor — no el primero.
    """
    fake_runner, hits = await _start_fake_mace(19018)
    proxy = MaceProxy(
        target_url      = "http://127.0.0.1:19018",
        listen_port     = 18918,
        trusted_proxies = "127.0.0.1",
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            await session.get(
                "http://127.0.0.1:18918/check",
                headers={"X-Forwarded-For": "6.6.6.6, 203.0.113.9"},
            )
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    assert hits[0]["ip"] == "203.0.113.9", (
        f"debía tomar el último valor (203.0.113.9), tomó: {hits[0]['ip']!r}"
    )


async def t_xff_decoy_prefix_no_evade_bloqueo():
    """
    Un cliente detrás de un proxy confiable no puede anteponer una IP
    limpia a la cabecera para que la IP bloqueada de verdad (la que el
    proxy añadió) se cuele sin más como si fuera otra.
    """
    fake_runner, hits = await _start_fake_mace(19019)
    proxy = MaceProxy(
        target_url      = "http://127.0.0.1:19019",
        listen_port     = 18919,
        trusted_proxies = "127.0.0.1",
    )
    await proxy.start()
    await asyncio.sleep(0.1)
    proxy.blocklist.block("203.0.113.9", ttl_s=60)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "http://127.0.0.1:18919/secret",
                headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.9"},
            ) as resp:
                assert resp.status == 403
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 0, "el decoy en el prefijo evadió el bloqueo"


async def t_xff_ipv6_valido_se_reenvia():
    """Una IP cliente IPv6 legítima (aportada por el proxy confiable) se respeta."""
    fake_runner, hits = await _start_fake_mace(19020)
    proxy = MaceProxy(
        target_url      = "http://127.0.0.1:19020",
        listen_port     = 18920,
        trusted_proxies = "127.0.0.1",
    )
    await proxy.start()
    await asyncio.sleep(0.1)

    try:
        async with aiohttp.ClientSession() as session:
            await session.get(
                "http://127.0.0.1:18920/check",
                headers={"X-Forwarded-For": "2001:db8::1"},
            )
    finally:
        await proxy.stop()
        await fake_runner.cleanup()

    assert len(hits) == 1
    assert hits[0]["ip"] == "2001:db8::1"


test("XFF — Entradas inválidas en AEGIS_TRUSTED_PROXIES no rompen el arranque",
     t_parse_trusted_proxies_ignora_entradas_invalidas)
test("XFF — Sin configurar, ningún peer es confiable",
     t_peer_is_trusted_sin_config_siempre_false)
test("XFF — Sin trusted proxy, se usa la IP TCP real (no la XFF falsa)",
     t_xff_no_confiado_usa_ip_tcp_real)
test("XFF — Atacante no puede suplantar su IP vía X-Forwarded-For",
     t_xff_spoofing_no_suplanta_ip_del_atacante)
test("XFF — IP bloqueada no evade el bloqueo reetiquetándose vía XFF",
     t_xff_spoofing_no_evade_bloqueo)
test("XFF — Con proxy confiable configurado, XFF sí se respeta",
     t_xff_confiado_solo_desde_proxy_configurado)
test("XFF — _normalize_ip rechaza CIDR/puerto/texto/vacío/octeto ambiguo",
     t_normalize_ip_rechaza_formatos_invalidos)
test("XFF — _normalize_ip normaliza IPv4/IPv6 (incl. formas equivalentes)",
     t_normalize_ip_normaliza_ipv4_ipv6_validas)
test("XFF — _normalize_ip desenvuelve ::ffff:127.0.0.1 a 127.0.0.1",
     t_normalize_ip_desenvuelve_ipv4_mapped_loopback)
test("XFF — _normalize_ip desenvuelve ::ffff:0.0.0.0 a 0.0.0.0",
     t_normalize_ip_desenvuelve_ipv4_mapped_unspecified)
test("XFF — _normalize_ip desenvuelve IPv4 pública mapeada (::ffff:8.8.8.8)",
     t_normalize_ip_desenvuelve_ipv4_mapped_publica)
test("XFF — 8.8.8.8 y ::ffff:8.8.8.8 son la misma identidad",
     t_normalize_ip_ipv4_mapped_y_ipv4_normal_misma_identidad)
test("XFF — _resolve_client_ip toma el último valor, no el primero (P0)",
     t_resolve_client_ip_toma_el_ultimo_no_el_primero)
test("XFF — _resolve_client_ip soporta cadena de varios proxies confiables",
     t_resolve_client_ip_cadena_multisalto_confiable)
test("XFF — _resolve_client_ip cae al peer si toda la cadena es confiable",
     t_resolve_client_ip_solo_proxies_confiables_cae_a_peer)
test("XFF — _resolve_client_ip cae al peer ante entrada malformada",
     t_resolve_client_ip_entrada_malformada_cae_a_peer)
test("XFF — _resolve_client_ip rechaza IP con puerto",
     t_resolve_client_ip_ip_con_puerto_rechazada)
test("XFF — _resolve_client_ip rechaza CIDR",
     t_resolve_client_ip_cidr_rechazado)
test("XFF — _resolve_client_ip rechaza 127.0.0.1 inyectada",
     t_resolve_client_ip_loopback_ipv4_inyectado_no_se_acepta)
test("XFF — _resolve_client_ip rechaza ::1 inyectada",
     t_resolve_client_ip_loopback_ipv6_inyectado_no_se_acepta)
test("XFF — _resolve_client_ip rechaza ::ffff:127.0.0.1 inyectada",
     t_resolve_client_ip_loopback_ipv4_mapped_inyectado_no_se_acepta)
test("XFF — _resolve_client_ip rechaza ::ffff:0.0.0.0 inyectada",
     t_resolve_client_ip_unspecified_ipv4_mapped_inyectado_no_se_acepta)
test("XFF — Cadena con varios valores toma el último (E2E, P0)",
     t_xff_cadena_multiple_toma_ultimo_valor)
test("XFF — Decoy en el prefijo no evade un bloqueo existente (E2E)",
     t_xff_decoy_prefix_no_evade_bloqueo)
test("XFF — IPv6 válida aportada por proxy confiable se respeta (E2E)",
     t_xff_ipv6_valido_se_reenvia)


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

    # Bloquear la IP del cliente de test (atacante simulado)
    proxy.blocklist.block(ATTACKER_IP, ttl_s=60)

    try:
        async with _attacker_session() as session:
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

    # Atacante simulado: loopback fuera de la whitelist anti-self-lockout
    ip_atacante = ATTACKER_IP

    try:
        async with _attacker_session() as session:
            # Petición 1 — antes del bloqueo → llega a MACE
            resp1 = await session.get("http://127.0.0.1:18940/antes")
            assert resp1.status == 200
            assert len(hits) == 1

            # Simular detección de AEGIS — bloquear ambos loopbacks
            event = _make_detection_event([ip_atacante])
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
        contact = _make_mine_contact(ATTACKER_IP, "backup.json")
        await conn.on_mine_contact(contact)

        # Petición de esa IP → bloqueada
        async with _attacker_session() as session:
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
        # Loopback may be auto-blocked by minefield during startup; unblock for the health check
        connector.unblock_ip("127.0.0.1")

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
