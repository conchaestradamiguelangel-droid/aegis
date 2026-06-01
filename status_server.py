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
        app.router.add_get("/metrics",   self._handle_metrics)

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
    async def _handle_metrics(self, request):
        try:
            d  = self._aegis.full_status()
            sy = d.get("system", {})
            de = d.get("detector", {})
            lk = d.get("lockdown", {})
            fo = d.get("forensic", {})
            am = d.get("amtd", {})
            pe = d.get("persistence", {})
            ma = d.get("mace", {})
            threat_map = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            status_map = {"ONLINE": 1, "ALERT": 2, "LOCKDOWN": 3, "STOPPING": 0, "OFFLINE": 0}
            sep = chr(10)
            lines = [
                "# HELP aegis_up Sistema AEGIS operativo (1=online)",
                "# TYPE aegis_up gauge",
                "aegis_up {}".format(status_map.get(str(sy.get("status", "")), 0)),
                "# HELP aegis_uptime_seconds Tiempo activo en segundos",
                "# TYPE aegis_uptime_seconds counter",
                "aegis_uptime_seconds {}".format(sy.get("uptime_s", 0)),
                "# HELP aegis_threat_level Nivel de amenaza (0=NONE 4=CRITICAL)",
                "# TYPE aegis_threat_level gauge",
                "aegis_threat_level {}".format(threat_map.get(str(sy.get("threat_level", "")), 0)),
                "# HELP aegis_detections_total Detecciones acumuladas",
                "# TYPE aegis_detections_total counter",
                "aegis_detections_total {}".format(de.get("total_detections", 0)),
                "# HELP aegis_active_ips IPs bajo seguimiento activo",
                "# TYPE aegis_active_ips gauge",
                "aegis_active_ips {}".format(de.get("active_ips", 0)),
                "# HELP aegis_lockdowns_total Lockdowns ejecutados",
                "# TYPE aegis_lockdowns_total counter",
                "aegis_lockdowns_total {}".format(lk.get("total_lockdowns", 0)),
                "# HELP aegis_incidents_total Incidentes forenses totales",
                "# TYPE aegis_incidents_total counter",
                "aegis_incidents_total {}".format(fo.get("total_incidents", 0)),
                "# HELP aegis_incidents_open Incidentes forenses abiertos",
                "# TYPE aegis_incidents_open gauge",
                "aegis_incidents_open {}".format(fo.get("active_incidents", 0)),
                "# HELP aegis_amtd_cycle Ciclo AMTD actual",
                "# TYPE aegis_amtd_cycle counter",
                "aegis_amtd_cycle {}".format(am.get("cycle", 0)),
                "# HELP aegis_checkpoints_total Checkpoints escritos",
                "# TYPE aegis_checkpoints_total counter",
                "aegis_checkpoints_total {}".format(pe.get("checkpoints_created", 0)),
                "# HELP aegis_blocked_ips IPs bloqueadas activas en el proxy MACE",
                "# TYPE aegis_blocked_ips gauge",
                "aegis_blocked_ips {}".format(ma.get("blocked_ips", 0)),
            ]
            return web.Response(text=sep.join(lines) + sep, content_type="text/plain", charset="utf-8")
        except Exception as e:
            return web.Response(text="# ERROR " + str(e) + chr(10), status=500, content_type="text/plain")
