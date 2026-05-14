import asyncio
"""AEGIS — Servidor de estado HTTP interno (puerto 8081)."""
import json
from datetime import datetime
from aiohttp import web

import logging
logger = logging.getLogger("aegis.status_server")


def _json_safe(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


class AegisStatusServer:
    def __init__(self, aegis_system, port: int = 8081):
        self._aegis   = aegis_system
        self._port    = port
        self._runner  = None

    async def start(self):
        app = web.Application()
        app.router.add_get("/status",    self._handle_status)
        app.router.add_get("/health",    self._handle_health)
        app.router.add_get("/incidents", self._handle_incidents)
        app.router.add_get("/stream",    self._handle_stream)

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self._port)
        await site.start()
        logger.info(f"[STATUS] Servidor de estado activo en 127.0.0.1:{self._port}")

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    async def _handle_status(self, request: web.Request) -> web.Response:
        data = self._aegis.full_status()
        text = json.dumps(data, default=_json_safe)
        return web.Response(
            text=text,
            content_type="application/json",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    async def _handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _handle_incidents(self, request: web.Request) -> web.Response:
        n = int(request.rel_url.query.get("n", 10))
        index = self._aegis._reporter.get_index(last_n=n)
        return web.Response(
            text=json.dumps(index, default=_json_safe),
            content_type="application/json",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    async def _handle_stream(self, request: web.Request) -> web.StreamResponse:
        """Server-Sent Events — envia status + incidents cada 2s."""
        response = web.StreamResponse()
        response.headers["Content-Type"]       = "text/event-stream"
        response.headers["Cache-Control"]      = "no-cache"
        response.headers["X-Accel-Buffering"]  = "no"
        response.headers["Access-Control-Allow-Origin"] = "*"
        await response.prepare(request)

        tick = 0
        while True:
            try:
                data = self._aegis.full_status()
                msg  = "data: " + json.dumps(data, default=_json_safe) + "\n\n"
                await response.write(msg.encode())

                if tick % 5 == 0:
                    try:
                        inc     = self._aegis._reporter.get_index(last_n=10)
                        inc_msg = "event: incidents\ndata: " + json.dumps(inc, default=_json_safe) + "\n\n"
                        await response.write(inc_msg.encode())
                    except Exception:
                        pass

                tick += 1
                await asyncio.sleep(2)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"[STATUS.SSE] Cliente desconectado: {e}")
                break

        return response
