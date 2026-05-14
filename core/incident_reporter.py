"""
AEGIS -- Capa 7+: Post-Incident Report (PIR)
=============================================
Genera un informe estructurado al finalizar cada incidente de seguridad.

FILOSOFIA:
    El informe es evidencia forense -- persiste en disco, nunca se borra.
    Se genera fire-and-forget tras el lockdown -- nunca bloquea el path critico.

DESTINOS:
    -> /root/aegis/incidents/{INC-ID}.json   evidencia forense
    -> /root/aegis/incidents/{INC-ID}.html   lectura humana
    -> /root/aegis/incidents/index.json      indice de todos los incidentes
    -> Telegram: resumen conciso del incidente
"""

import asyncio
import json
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("aegis.reporter")

import os as _os
INCIDENTS_DIR = Path(_os.environ.get("AEGIS_INCIDENTS_DIR", "incidents"))


class IncidentReporter:
    """
    Genera Post-Incident Reports al completar cada lockdown.

    Uso:
        reporter = IncidentReporter()
        reporter.set_telegram(telegram_alerter)
        asyncio.create_task(reporter.generate(detection, result, twin, forensic))
    """

    def __init__(self):
        INCIDENTS_DIR.mkdir(exist_ok=True)
        self._telegram = None
        logger.info("[REPORTER] Inicializado -- dir=" + str(INCIDENTS_DIR) + " listo")

    def set_telegram(self, alerter):
        self._telegram = alerter

    # -----------------------------------------
    # GENERACION DEL PIR
    # -----------------------------------------

    async def generate(self, detection, lockdown_result, twin_chain=None, forensic=None) -> str:
        """
        Genera el PIR completo. Retorna el incident_id.
        Disenado para ejecutarse como fire-and-forget con asyncio.create_task().
        """
        now = datetime.now(timezone.utc)
        incident_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3).upper()}"

        report = self._build(incident_id, now, detection, lockdown_result, twin_chain, forensic)

        # Evidencia forense en JSON
        (INCIDENTS_DIR / f"{incident_id}.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        # Lectura humana en HTML
        (INCIDENTS_DIR / f"{incident_id}.html").write_text(
            self._html(report), encoding="utf-8"
        )

        # Actualizar indice global
        self._update_index(incident_id, report)

        # Telegram
        if self._telegram:
            try:
                await self._telegram.send_pir(report)
            except Exception as e:
                logger.warning(f"[REPORTER] Error enviando PIR a Telegram: {e}")

        logger.info(
            f"[REPORTER] PIR persistido -- "
            f"id={incident_id} "
            f"veredicto={report['verdict']} "
            f"amenaza={report['forensic']['threat_level']}"
        )
        return incident_id

    # -----------------------------------------
    # CONSTRUCCION DEL REPORT
    # -----------------------------------------

    def _build(self, incident_id, now, detection, result, twin_chain, forensic) -> dict:
        # Seccion amenaza
        threat = {
            "type":           self._attr(detection, "detection_type", "UNKNOWN"),
            "confidence":     self._attr(detection, "confidence", "UNKNOWN"),
            "source_ips":     list(getattr(detection, "source_ips", []) or []),
            "first_detected": str(getattr(detection, "timestamp", now.isoformat())),
            "detection_id":   self._attr(detection, "detection_id", ""),
            "elapsed_ms":     round(getattr(detection, "elapsed_ms", 0.0), 1),
        }

        # Seccion respuesta
        response = {}
        if result is not None:
            within = (result.within_limits() if callable(getattr(result, "within_limits", None))
                      else getattr(result, "_within_limits", True))
            response = {
                "lockdown_id":         getattr(result, "lockdown_id", ""),
                "total_ms":            round(getattr(result, "total_ms", 0.0), 1),
                "twin_jump_ms":        round(getattr(result, "twin_jump_ms", 0.0), 1),
                "sessions_sealed":     getattr(result, "sessions_invalidated", 0),
                "credentials_rotated": getattr(result, "credentials_rotated", 0),
                "surfaces_closed":     getattr(result, "surfaces_closed", 0),
                "within_limits":       within,
                "success":             getattr(result, "success", True),
            }

        # Seccion gemelo
        twin_data = {}
        if twin_chain is not None:
            jump_log = twin_chain.get_jump_log() if hasattr(twin_chain, "get_jump_log") else []
            if jump_log:
                lj = jump_log[-1]
                twin_data = {
                    "jump_count":   len(jump_log),
                    "last_jump_id": getattr(lj, "jump_id", ""),
                    "duration_ms":  round(getattr(lj, "duration_ms", 0.0), 1),
                    "trigger":      str(getattr(lj, "trigger", "")),
                }

        # Seccion forense
        forensic_data = {
            "threat_level": "DESCONOCIDO", "threat_score": 0.0,
            "will_escalate": False, "actor": "UNKNOWN",
            "techniques": [], "intent": "UNKNOWN",
            "total_events": 0, "mine_contacts": 0, "fingerprint": "",
        }
        if forensic is not None:
            pool = {**getattr(forensic, "_closed", {}), **getattr(forensic, "_incidents", {})}
            if pool:
                profile = list(pool.values())[-1]
                ta = getattr(profile, "threat_assessment", {})
                forensic_data = {
                    "threat_level":  ta.get("level", "DESCONOCIDO"),
                    "threat_score":  round(ta.get("score", 0.0), 3),
                    "will_escalate": ta.get("will_escalate", False),
                    "actor":         self._attr(profile, "actor_type", "UNKNOWN"),
                    "techniques":    [self._attr(t, None, str(t)) for t in getattr(profile, "techniques", [])],
                    "intent":        self._attr(profile, "intent", "UNKNOWN"),
                    "total_events":  getattr(profile, "total_events", 0),
                    "mine_contacts": len(getattr(profile, "mine_contacts", [])),
                    "fingerprint":   getattr(profile, "fingerprint", ""),
                }

        return {
            "incident_id":  incident_id,
            "generated_at": now.isoformat(),
            "threat":       threat,
            "response":     response,
            "twin":         twin_data,
            "forensic":     forensic_data,
            "verdict":      "NEUTRALIZADO" if response.get("success", True) else "DEGRADADO",
        }

    def _attr(self, obj, attr, default):
        val = getattr(obj, attr, None) if attr else obj
        if val is None:
            return default
        return val.value if hasattr(val, "value") else str(val)

    # -----------------------------------------
    # INDICE GLOBAL
    # -----------------------------------------

    def _update_index(self, incident_id: str, report: dict):
        index_path = INCIDENTS_DIR / "index.json"
        try:
            index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
        except Exception:
            index = []
        index.append({
            "incident_id":  incident_id,
            "generated_at": report["generated_at"],
            "verdict":      report["verdict"],
            "threat_type":  report["threat"]["type"],
            "source_ips":   report["threat"]["source_ips"],
            "threat_level": report["forensic"]["threat_level"],
            "threat_score": report["forensic"]["threat_score"],
        })
        index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")

    def get_index(self, last_n: int = 10) -> list:
        """Retorna los ultimos N incidentes del indice."""
        index_path = INCIDENTS_DIR / "index.json"
        try:
            index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
            return index[-last_n:]
        except Exception:
            return []

    # -----------------------------------------
    # RENDER HTML
    # -----------------------------------------

    def _html(self, r: dict) -> str:
        t   = r["threat"]
        res = r["response"]
        f   = r["forensic"]
        tw  = r["twin"]
        vc  = "#00cc44" if r["verdict"] == "NEUTRALIZADO" else "#ff4444"
        ips = ", ".join(t["source_ips"]) or "---"
        techs = "".join(
            f'<span style="background:#1a2a1a;color:#4f8;border:1px solid #2a4a2a;'
            f'padding:2px 8px;margin:2px;display:inline-block;font-size:11px">{x}</span>'
            for x in f["techniques"]
        ) or '<span style="color:#556">---</span>'

        twin_rows = ""
        if tw:
            twin_rows = (
                f"<tr><td>Saltos totales</td><td>{tw.get('jump_count', 0)}</td></tr>"
                f"<tr><td>Duracion ultimo salto</td><td>{tw.get('duration_ms', 0)}ms</td></tr>"
                f"<tr><td>Trigger</td><td>{tw.get('trigger', '---')}</td></tr>"
            )
        else:
            twin_rows = '<tr><td colspan="2" style="color:#445">Sin datos de gemelo</td></tr>'

        within_txt = "OK" if res.get("within_limits", True) else "SUPERADOS"
        escalada   = "SI" if f.get("will_escalate") else "NO"

        return (
            "<!DOCTYPE html>\n<html lang='es'><head><meta charset='UTF-8'>\n"
            f"<title>PIR -- {r['incident_id']}</title>\n"
            "<style>\n"
            "*{margin:0;padding:0;box-sizing:border-box}\n"
            "body{font-family:'Courier New',monospace;background:#0a0f1e;color:#c8d8e8;font-size:12px;padding:24px}\n"
            "h1{color:#00ff88;font-size:17px;margin-bottom:3px}\n"
            ".meta{color:#445;font-size:10px;margin-bottom:16px}\n"
            f".verdict{{display:inline-block;padding:5px 14px;border:2px solid {vc};color:{vc};font-weight:bold;font-size:15px;margin-bottom:18px}}\n"
            ".sec{border:1px solid #1a2a3a;padding:10px 14px;margin-bottom:12px}\n"
            ".sec-title{color:#4af;font-size:10px;font-weight:bold;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px}\n"
            "table{width:100%;border-collapse:collapse}\n"
            "td{padding:3px 6px;color:#aac;font-size:11px}\n"
            "td:first-child{color:#556;width:45%}\n"
            "</style></head><body>\n"
            "<h1>AEGIS -- Post-Incident Report</h1>\n"
            f"<div class='meta'>{r['incident_id']} &nbsp;·&nbsp; {r['generated_at']}</div>\n"
            f"<div class='verdict'>{r['verdict']}</div>\n\n"
            "<div class='sec'><div class='sec-title'>Amenaza</div><table>\n"
            f"<tr><td>Tipo</td><td>{t['type']}</td></tr>\n"
            f"<tr><td>Confianza</td><td>{t['confidence']}</td></tr>\n"
            f"<tr><td>IPs origen</td><td style='color:#0f8'>{ips}</td></tr>\n"
            f"<tr><td>Elapsed deteccion</td><td>{t['elapsed_ms']}ms</td></tr>\n"
            f"<tr><td>Detection ID</td><td style='color:#0f8'>{t['detection_id']}</td></tr>\n"
            "</table></div>\n\n"
            "<div class='sec'><div class='sec-title'>Respuesta del sistema</div><table>\n"
            f"<tr><td>Tiempo total lockdown</td><td>{res.get('total_ms', 0):.0f}ms</td></tr>\n"
            f"<tr><td>Salto de gemelo</td><td>{res.get('twin_jump_ms', 0):.0f}ms</td></tr>\n"
            f"<tr><td>Sesiones selladas</td><td>{res.get('sessions_sealed', 0)}</td></tr>\n"
            f"<tr><td>Credenciales rotadas</td><td>{res.get('credentials_rotated', 0)}</td></tr>\n"
            f"<tr><td>Superficies cerradas</td><td>{res.get('surfaces_closed', 0)}</td></tr>\n"
            f"<tr><td>Dentro de limites</td><td>{within_txt}</td></tr>\n"
            f"<tr><td>Lockdown ID</td><td style='color:#0f8'>{res.get('lockdown_id', '---')}</td></tr>\n"
            "</table></div>\n\n"
            "<div class='sec'><div class='sec-title'>Analisis forense (C7)</div><table>\n"
            f"<tr><td>Nivel de amenaza</td><td>{f['threat_level']}</td></tr>\n"
            f"<tr><td>Score predictivo</td><td>{f['threat_score']}</td></tr>\n"
            f"<tr><td>Tipo de actor</td><td>{f['actor']}</td></tr>\n"
            f"<tr><td>Intencion inferida</td><td>{f['intent']}</td></tr>\n"
            f"<tr><td>Escalada predicha</td><td>{escalada}</td></tr>\n"
            f"<tr><td>Eventos totales</td><td>{f['total_events']}</td></tr>\n"
            f"<tr><td>Senuelos tocados</td><td>{f['mine_contacts']}</td></tr>\n"
            f"<tr><td>Fingerprint</td><td style='color:#0f8'>{f.get('fingerprint', '---')}</td></tr>\n"
            "</table>\n"
            "<div style='margin-top:8px;color:#556;font-size:10px'>Tecnicas:</div>\n"
            f"<div style='margin-top:4px'>{techs}</div>\n"
            "</div>\n\n"
            "<div class='sec'><div class='sec-title'>Gemelo digital (C1)</div><table>\n"
            f"{twin_rows}\n"
            "</table></div>\n"
            "</body></html>"
        )
