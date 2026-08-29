"""
AEGIS — Integración MACE: Proxy HTTP
=====================================
Proxy inverso asyncio que se coloca delante de MACE (puerto 8000).
Todo el tráfico pasa por él. MACE no sabe que existe.

FLUJO NORMAL:
    cliente → MaceProxy:listen_port → localhost:8000 (MACE) → cliente

FLUJO CON AMENAZA:
    cliente → MaceProxy → IP en blocklist → respuesta burbuja C6
                                         → MACE no recibe nada

DISEÑO:
    - Fire-and-forget para inspección: C3 se alimenta sin añadir
      latencia al path crítico de MACE.
    - Blocklist en memoria: la IP bloqueada no vuelve a llegar a MACE.
    - No intrusivo: MACE corre en localhost:8000 sin modificar.
    - Integrado con el event loop de AEGIS — una sola tarea asyncio.
"""

import asyncio
import ipaddress
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional, Callable, Set

import aiohttp
from aiohttp import web

logger = logging.getLogger("aegis.mace.proxy")

# IPs que nunca se bloquean — el watchdog usa 127.0.0.1 para health checks
LOOPBACK_WHITELIST: frozenset[str] = frozenset({"127.0.0.1", "::1"})


# ─────────────────────────────────────────────
# PROXIES CONFIABLES — quién puede fijar X-Forwarded-For
# ─────────────────────────────────────────────
#
# Por defecto (sin AEGIS_TRUSTED_PROXIES configurado) NINGÚN peer es
# confiable: X-Forwarded-For se ignora siempre y se usa la IP TCP real
# de la conexión. Esto es deliberado — un cliente arbitrario no debe
# poder suplantar su IP ni forzar el bloqueo de una IP ajena solo
# fijando esa cabecera. Configurar AEGIS_TRUSTED_PROXIES únicamente si
# MaceProxy corre detrás de un reverse proxy propio (nginx, HAProxy...)
# que sobrescribe X-Forwarded-For con la IP real del cliente.

def _parse_trusted_proxies(raw: str) -> frozenset:
    """Convierte 'ip_o_cidr,ip_o_cidr,...' en un frozenset de redes IP."""
    networks = set()
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.add(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning(
                f"[PROXY] AEGIS_TRUSTED_PROXIES: entrada inválida ignorada: {item!r}"
            )
    return frozenset(networks)


def _peer_is_trusted(peer_ip: str, trusted_networks: frozenset) -> bool:
    if not trusted_networks:
        return False
    try:
        ip = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(ip in net for net in trusted_networks)


def _normalize_ip(raw: str) -> Optional[str]:
    """
    Valida una entrada de X-Forwarded-For como IPv4/IPv6 pura y la
    normaliza a su forma canónica (para que representaciones
    equivalentes, ej. "::1" y "0:0:0:0:0:0:0:1", resuelvan a la misma
    identidad). Devuelve None para cualquier cosa que no sea
    exactamente una IP: texto arbitrario, CIDR, IP con puerto, vacío.

    Las IPv6 "IPv4-mapped" (::ffff:a.b.c.d, rango ::ffff:0:0/96) se
    desenvuelven a su IPv4Address equivalente ANTES de canonicalizar
    y de cualquier comprobación de loopback/unspecified posterior en
    _resolve_client_ip. Verificado empíricamente en este runtime
    (Python 3.12.3): ni IPv6Address("::ffff:127.0.0.1").is_loopback
    ni IPv6Address("::ffff:0.0.0.0").is_unspecified detectan el caso
    mapeado (ambos dan False) — sin este desenvolvimiento, "8.8.8.8"
    y "::ffff:8.8.8.8" serían identidades distintas para
    blocklist/whitelist, y "::ffff:127.0.0.1"/"::ffff:0.0.0.0" se
    colarían como si no fuesen loopback/unspecified.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        ip_obj = ipaddress.ip_address(raw)
    except ValueError:
        return None
    mapped = getattr(ip_obj, "ipv4_mapped", None)
    if mapped is not None:
        ip_obj = mapped
    return str(ip_obj)


def _resolve_client_ip(
    peer_ip: str, forwarded_header: str, trusted_networks: frozenset
) -> str:
    """
    Deriva la IP real del cliente. Nunca "el primer valor de
    X-Forwarded-For, siempre" (hallazgo de seguimiento 2026-08-29):
    un proxy bien comportado (nginx `$proxy_add_x_forwarded_for`,
    HAProxy, etc.) AÑADE el peer que le conecta al FINAL de la
    cabecera — nunca lo antepone. Cualquier valor que el propio
    cliente haya podido meter de su mano en X-Forwarded-For queda
    siempre a la izquierda de lo que el proxy confiable añadió.

    Si el peer TCP directo no es un proxy en AEGIS_TRUSTED_PROXIES,
    X-Forwarded-For se ignora por completo.

    Si lo es, se recorre la cabecera de derecha a izquierda, saltando
    entradas que sean a su vez otros proxies confiables (soporta una
    cadena de varios saltos confiables), hasta la primera entrada que
    no lo sea — esa es la IP del cliente. Se rechaza todo el intento
    (fallback a la IP TCP real) ante:
      - una entrada malformada, con puerto o en formato CIDR en la
        posición evaluada (no hay forma segura de seguir confiando
        en el resto de la cadena);
      - que esa primera entrada no confiable resulte ser loopback o
        no especificada (127.0.0.1 / ::1 / 0.0.0.0 inyectada, para
        que nadie pueda reclamar la identidad exenta de bloqueo);
      - una cabecera vacía o compuesta solo por proxies confiables.
    """
    if not _peer_is_trusted(peer_ip, trusted_networks):
        return peer_ip

    raw_entries = (forwarded_header or "").split(",")
    for raw_entry in reversed(raw_entries):
        candidate = _normalize_ip(raw_entry)
        if candidate is None:
            return peer_ip
        if _peer_is_trusted(candidate, trusted_networks):
            continue
        ip_obj = ipaddress.ip_address(candidate)
        if ip_obj.is_loopback or ip_obj.is_unspecified:
            return peer_ip
        return candidate

    return peer_ip


# ─────────────────────────────────────────────
# BLOCKLIST — IPs bloqueadas temporalmente
# ─────────────────────────────────────────────

class Blocklist:
    DEFAULT_MAX_SIZE = 100_000

    def __init__(self, default_ttl_s: int = 3600, max_size: int = None):
        self._blocked: dict = {}
        self._default_ttl_s = default_ttl_s
        self._max_size = max_size or self.DEFAULT_MAX_SIZE
        self._total_blocked = 0
        self._order_counter = 0

    def block(self, ip: str, ttl_s: int = None):
        if ip in LOOPBACK_WHITELIST:
            return
        ttl = ttl_s if ttl_s is not None else self._default_ttl_s
        if ttl <= 0:
            self._blocked.pop(ip, None)
            return
        self._order_counter += 1
        self._blocked[ip] = (time.monotonic() + ttl, self._order_counter)
        self._evict_oldest_if_needed(exclude=ip)
        self._total_blocked += 1
        logger.warning(
            f"[PROXY.BLOCK] IP bloqueada: {ip} "
            f"(TTL={ttl}s | total={self._total_blocked} | activas={self.active_count()})"
        )

    def _evict_oldest_if_needed(self, exclude: str = None):
        if len(self._blocked) <= self._max_size:
            return
        now = time.monotonic()
        oldest_ip = None
        oldest_order = None
        for ip, (expires, order) in self._blocked.items():
            if ip == exclude:
                continue
            if expires and expires <= now:
                continue
            if oldest_order is None or order < oldest_order:
                oldest_ip = ip
                oldest_order = order
        if oldest_ip:
            del self._blocked[oldest_ip]

    def unblock(self, ip: str):
        self._blocked.pop(ip, None)

    def is_blocked(self, ip: str) -> bool:
        if ip in LOOPBACK_WHITELIST:
            return False
        entry = self._blocked.get(ip)
        if entry is None:
            return False
        expires, _ = entry
        if expires is None:
            return True
        if time.monotonic() > expires:
            del self._blocked[ip]
            return False
        return True

    def active_count(self) -> int:
        now = time.monotonic()
        return sum(1 for exp, _ in self._blocked.values() if exp is None or exp > now)

    def to_list(self) -> list:
        now = time.monotonic()
        return [ip for ip, (exp, _) in self._blocked.items() if exp is None or exp > now]

    def to_checkpoint(self) -> list:
        now = time.monotonic()
        wall = time.time()
        result = []
        for ip, (exp, order) in self._blocked.items():
            if exp is None or exp > now:
                remaining = None if exp is None else exp - now
                result.append({"ip": ip, "remaining_s": remaining, "wall_expire": None if remaining is None else wall + remaining})
        return result

    def restore_from_checkpoint(self, entries: list):
        wall_now = time.time()
        mono_now = time.monotonic()
        for e in entries:
            ip = e.get("ip")
            wall_exp = e.get("wall_expire")
            if not ip or ip in LOOPBACK_WHITELIST:
                continue
            if wall_exp is None:
                ttl = None
            else:
                remaining = wall_exp - wall_now
                if remaining <= 0:
                    continue
                ttl = remaining
            self.block(ip, ttl_s=int(ttl) if ttl is not None else None)


# ─────────────────────────────────────────────
# ESTADÍSTICAS DEL PROXY
# ─────────────────────────────────────────────

class ProxyStats:
    def __init__(self):
        self.started_at      = datetime.now(timezone.utc)
        self.requests_total  = 0
        self.requests_blocked= 0
        self.requests_forwarded = 0
        self.errors          = 0
        self.bytes_forwarded = 0

    def to_dict(self) -> dict:
        uptime = (datetime.now(timezone.utc) - self.started_at).total_seconds()
        return {
            "started_at":         self.started_at.isoformat(),
            "uptime_s":           round(uptime, 1),
            "requests_total":     self.requests_total,
            "requests_blocked":   self.requests_blocked,
            "requests_forwarded": self.requests_forwarded,
            "errors":             self.errors,
            "bytes_forwarded":    self.bytes_forwarded,
            "block_rate":         round(
                self.requests_blocked / self.requests_total, 3
            ) if self.requests_total else 0.0,
        }


# ─────────────────────────────────────────────
# PROXY PRINCIPAL
# ─────────────────────────────────────────────

class MaceProxy:
    """
    Proxy HTTP inverso para MACE.

    Uso:
        proxy = MaceProxy(
            target_url   = "http://localhost:8000",
            listen_port  = 8080,
            on_request   = aegis.detector.register_network_event,
            blocklist    = connector.blocklist,
        )
        await proxy.start()
        # ... corre hasta stop()
        await proxy.stop()
    """

    # Respuesta que recibe una IP bloqueada
    BLOCKED_RESPONSE = (
        b'{"error": "forbidden", "code": 403}',
        403,
        "application/json",
    )

    # Headers que no se reenvían al target
    HOP_BY_HOP = {
        "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers",
        "transfer-encoding", "upgrade",
    }

    def __init__(
        self,
        target_url:   str      = "http://localhost:8000",
        listen_host:  str      = "0.0.0.0",
        listen_port:  int      = 8080,
        on_request:   Optional[Callable] = None,
        blocklist:    Optional[Blocklist] = None,
        timeout_s:    float    = 30.0,
        trusted_proxies: Optional[str] = None,
    ):
        self._target      = target_url.rstrip("/")
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._on_request  = on_request     # callback → C3
        self._blocklist   = blocklist or Blocklist()
        self._timeout     = aiohttp.ClientTimeout(total=timeout_s)
        self._stats       = ProxyStats()

        # X-Forwarded-For solo se confía si el peer TCP está en esta lista.
        # trusted_proxies explícito > env AEGIS_TRUSTED_PROXIES > ninguno.
        raw_trusted = (
            trusted_proxies if trusted_proxies is not None
            else os.environ.get("AEGIS_TRUSTED_PROXIES", "")
        )
        self._trusted_proxies = _parse_trusted_proxies(raw_trusted)
        if self._trusted_proxies:
            logger.info(
                "[PROXY] X-Forwarded-For confiado solo desde: "
                + ", ".join(sorted(str(n) for n in self._trusted_proxies))
            )
        else:
            logger.info(
                "[PROXY] AEGIS_TRUSTED_PROXIES no configurado — "
                "X-Forwarded-For se ignora, se usa la IP TCP real del cliente"
            )
        self._session:    Optional[aiohttp.ClientSession] = None
        self._runner:     Optional[web.AppRunner]         = None
        self._site:       Optional[web.TCPSite]           = None
        self._is_healthy:    bool                       = True
        self._health_fails:  int                        = 0
        self._health_task:   Optional[asyncio.Task]     = None
        self._health_interval_s: float                  = 10.0

    # ── Arranque y parada ─────────────────────────────────────────────────────

    async def start(self):
        """Inicia el proxy. No bloquea — retorna tras el bind."""
        self._session = aiohttp.ClientSession(timeout=self._timeout)

        app = web.Application()
        app.router.add_route("*", "/{path_info:.*}", self._handle)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()

        self._site = web.TCPSite(
            self._runner, self._listen_host, self._listen_port
        )
        await self._site.start()

        self._health_task = asyncio.create_task(
            self._health_loop(), name="aegis.proxy.health"
        )
        logger.info(
            f"[PROXY] MaceProxy activo — "
            f"escucha={self._listen_host}:{self._listen_port} "
            f"target={self._target}"
        )

    async def stop(self):
        """Detiene el proxy limpiamente."""
        if self._health_task and not self._health_task.done():
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        if self._runner:
            await self._runner.cleanup()
        if self._session and not self._session.closed:
            await self._session.close()
        logger.info("[PROXY] MaceProxy detenido")

    # ── Health check ─────────────────────────────────────────────────────────

    async def _health_loop(self):
        """Prueba el upstream cada N segundos. Actualiza _is_healthy."""
        await asyncio.sleep(self._health_interval_s)  # espera inicial
        while True:
            try:
                async with self._session.get(
                    f"{self._target}/health",
                    timeout=aiohttp.ClientTimeout(total=5.0),
                    allow_redirects=False,
                ) as resp:
                    ok = resp.status < 500
                    if ok:
                        if not self._is_healthy:
                            logger.warning("[PROXY] Upstream MACE recuperado")
                        self._is_healthy = True
                        self._health_fails = 0
                    else:
                        self._health_fails += 1
                        was = self._is_healthy
                        self._is_healthy = self._health_fails < 3
                        if was and not self._is_healthy:
                            logger.error(
                                f"[PROXY] Upstream MACE degradado "
                                f"status={resp.status} fallos={self._health_fails}"
                            )
            except asyncio.CancelledError:
                break
            except Exception:
                self._health_fails += 1
                was = self._is_healthy
                self._is_healthy = self._health_fails < 3
                if was and not self._is_healthy:
                    logger.error(
                        f"[PROXY] Upstream MACE inaccesible "
                        f"(fallos={self._health_fails})"
                    )
            await asyncio.sleep(self._health_interval_s)

    # ── Handler principal ─────────────────────────────────────────────────────

    async def _handle(self, request: web.Request) -> web.Response:
        """Procesa cada petición entrante."""
        self._stats.requests_total += 1

        # IP real del cliente (X-Forwarded-For solo si el peer es confiable)
        client_ip = self._get_client_ip(request)
        path      = request.path
        method    = request.method

        # 1. Comprobar blocklist — si bloqueada, devolver respuesta de engaño
        if self._blocklist.is_blocked(client_ip):
            self._stats.requests_blocked += 1
            logger.info(
                f"[PROXY] Bloqueado — ip={client_ip} "
                f"path={path} (total_bloqueados={self._stats.requests_blocked})"
            )
            body, status, ctype = self.BLOCKED_RESPONSE
            return web.Response(
                body         = body,
                status       = status,
                content_type = ctype,
            )

        # 2. Inspección en background — fire-and-forget, sin latencia añadida
        if self._on_request:
            asyncio.create_task(
                self._inspect(client_ip, self._listen_port, path, method)
            )

        # 3. Reenviar a MACE
        return await self._forward(request, client_ip)

    async def _inspect(self, ip: str, port: int, path: str, method: str):
        """Alimenta C3 en background. Nunca propaga excepciones."""
        try:
            if asyncio.iscoroutinefunction(self._on_request):
                await self._on_request(ip=ip, port=port, path=path)
            else:
                self._on_request(ip=ip, port=port, path=path)
        except Exception as e:
            logger.debug(f"[PROXY] Error en inspección: {e}")

    async def _forward(
        self, request: web.Request, client_ip: str
    ) -> web.Response:
        """Reenvía la petición a MACE y devuelve su respuesta."""
        target_url = f"{self._target}{request.path}"
        if request.query_string:
            target_url += f"?{request.query_string}"

        # Filtrar hop-by-hop headers
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in self.HOP_BY_HOP
        }
        headers["X-Forwarded-For"]   = client_ip
        headers["X-Forwarded-Proto"] = "http"
        headers["X-Forwarded-By"]    = "AEGIS-MaceProxy"

        try:
            body = await request.read()
            async with self._session.request(
                method  = request.method,
                url     = target_url,
                headers = headers,
                data    = body,
                allow_redirects = False,
            ) as resp:
                resp_body = await resp.read()
                self._stats.requests_forwarded += 1
                self._stats.bytes_forwarded    += len(resp_body)

                # Filtrar hop-by-hop en la respuesta
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in self.HOP_BY_HOP
                }

                logger.debug(
                    f"[PROXY] → {request.method} {request.path} "
                    f"ip={client_ip} status={resp.status} "
                    f"bytes={len(resp_body)}"
                )
                return web.Response(
                    body    = resp_body,
                    status  = resp.status,
                    headers = resp_headers,
                )

        except aiohttp.ClientConnectorError:
            self._stats.errors += 1
            logger.error(
                f"[PROXY] MACE no responde en {self._target} — "
                f"¿está arrancado?"
            )
            return web.Response(
                body   = b'{"error": "upstream_unavailable"}',
                status = 502,
                content_type = "application/json",
            )
        except Exception as e:
            self._stats.errors += 1
            logger.error(f"[PROXY] Error reenviando: {e}")
            return web.Response(
                body   = b'{"error": "proxy_error"}',
                status = 500,
                content_type = "application/json",
            )

    # ── Utilidades ────────────────────────────────────────────────────────────

    def _get_client_ip(self, request: web.Request) -> str:
        """
        Extrae la IP real del cliente. Ver `_resolve_client_ip` para la
        política exacta (nunca "primer valor de X-Forwarded-For,
        siempre" — se toma el primer valor no confiable recorriendo
        la cadena de derecha a izquierda).
        """
        peer_ip = request.remote or "0.0.0.0"
        return _resolve_client_ip(
            peer_ip,
            request.headers.get("X-Forwarded-For", ""),
            self._trusted_proxies,
        )

    # ── Consultas ─────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "listen":           f"{self._listen_host}:{self._listen_port}",
            "target":           self._target,
            "running":          self._runner is not None,
            "upstream_healthy": self._is_healthy,
            "blocked_ips":      self._blocklist.active_count(),
            "stats":            self._stats.to_dict(),
        }

    @property
    def blocklist(self) -> Blocklist:
        return self._blocklist

    @property
    def stats(self) -> ProxyStats:
        return self._stats
