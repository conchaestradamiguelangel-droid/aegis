import asyncio
"""AEGIS — Servidor de estado HTTP interno (puerto 8081)."""
import json
import os
from datetime import datetime
from aiohttp import web

import logging
logger = logging.getLogger("aegis.status_server")

_API_KEY = os.environ.get("AEGIS_API_KEY", "")


def _json_safe(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


@web.middleware
async def _auth_middleware(request: web.Request, handler):
    if not _API_KEY or request.path == "/health":
        return await handler(request)
    if request.headers.get("X-Api-Key") != _API_KEY:
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


class AegisStatusServer:
    def __init__(self, aegis_system, port: int = 8081):
        self._aegis   = aegis_system
        self._port    = port
        self._runner  = None

    async def start(self):
        app = web.Application(middlewares=[_auth_middleware])
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
            sh = d.get("shield", {})
            tw = d.get("twin", {})
            mi = d.get("minefield", {})
            su = d.get("surface", {})
            ti = d.get("timings", {})
            ma_stats = ma.get("stats", {})
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
                "# HELP aegis_mace_requests_total Peticiones totales procesadas por MACE",
                "# TYPE aegis_mace_requests_total counter",
                "aegis_mace_requests_total {}".format(ma_stats.get("requests_total", 0)),
                "# HELP aegis_mace_requests_blocked Peticiones bloqueadas por MACE",
                "# TYPE aegis_mace_requests_blocked counter",
                "aegis_mace_requests_blocked {}".format(ma_stats.get("requests_blocked", 0)),
                "# HELP aegis_mace_bytes_forwarded Bytes reenviados por MACE",
                "# TYPE aegis_mace_bytes_forwarded counter",
                "aegis_mace_bytes_forwarded {}".format(ma_stats.get("bytes_forwarded", 0)),
            ]
            layer_active = {
                "shield":    int(bool(sh.get("active", False))),
                "twin":      int(bool(tw.get("active", False))),
                "minefield": int(bool(mi.get("files", 0) or mi.get("credentials", 0))),
                "detector":  int("total_detections" in de),
                "lockdown":  int(bool(lk.get("status", ""))),
                "amtd":      int(am.get("status", "") == "ACTIVE"),
                "surface":   int(bool(su.get("layers_monitored", 0))),
                "mace":      int(bool(ma.get("running", False))),
            }
            lines += [
                "# HELP aegis_layer_up Estado de cada capa de defensa (1=activa 0=inactiva)",
                "# TYPE aegis_layer_up gauge",
            ]
            for layer, val in layer_active.items():
                lines.append('aegis_layer_up{layer="' + layer + '"} ' + str(val))
            det_t = ti.get("detection_ms", {})
            lkd_t = ti.get("lockdown_ms", {})
            lines += [
                "# HELP aegis_detection_latency_ms Latencia de deteccion en milisegundos",
                "# TYPE aegis_detection_latency_ms gauge",
                'aegis_detection_latency_ms{quantile="0.5"} ' + str(det_t.get("p50") or 0),
                'aegis_detection_latency_ms{quantile="0.95"} ' + str(det_t.get("p95") or 0),
                'aegis_detection_latency_ms{quantile="0.99"} ' + str(det_t.get("p99") or 0),
                "# HELP aegis_lockdown_latency_ms Latencia de lockdown en milisegundos",
                "# TYPE aegis_lockdown_latency_ms gauge",
                'aegis_lockdown_latency_ms{quantile="0.5"} ' + str(lkd_t.get("p50") or 0),
                'aegis_lockdown_latency_ms{quantile="0.95"} ' + str(lkd_t.get("p95") or 0),
                'aegis_lockdown_latency_ms{quantile="0.99"} ' + str(lkd_t.get("p99") or 0),
            ]
            return web.Response(text=sep.join(lines) + sep, content_type="text/plain", charset="utf-8")
        except Exception as e:
            return web.Response(text="# ERROR " + str(e) + chr(10), status=500, content_type="text/plain")
