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
import logging
import time
from datetime import datetime, timezone
from typing import Optional, Callable, Set

import aiohttp
from aiohttp import web

logger = logging.getLogger("aegis.mace.proxy")


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
    ):
        self._target      = target_url.rstrip("/")
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._on_request  = on_request     # callback → C3
        self._blocklist   = blocklist or Blocklist()
        self._timeout     = aiohttp.ClientTimeout(total=timeout_s)
        self._stats       = ProxyStats()
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

        # IP real del cliente (respeta X-Forwarded-For si existe)
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

    @staticmethod
    def _get_client_ip(request: web.Request) -> str:
        """Extrae la IP real del cliente."""
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote or "0.0.0.0"

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
