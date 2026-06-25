"""
AEGIS -- AbuseIPDB enrichment (Capa 7+ / PIR)
=============================================
Enriquece IPs detectadas con datos de reputacion de AbuseIPDB v2.
Lee ABUSEIPDB_API_KEY desde entorno. Sin clave, devuelve datos vacios -- nunca rompe el pipeline.
Limite free tier: 1.000 req/dia -- suficiente para un IDS que bloquea antes de floods.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("aegis.abuseipdb")

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT_S = 5


async def enrich_ips(ips: list) -> list:
    """
    Enriquece una lista de IPs con datos de AbuseIPDB.
    Devuelve lista de resultados (uno por IP, mismo orden).
    Nunca lanza excepciones.
    """
    if not ips:
        return []

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        logger.debug("[ABUSEIPDB] Sin API key -- enriquecimiento omitido")
        return [_empty(ip, "no_api_key") for ip in ips]

    results = await asyncio.gather(
        *[_check_ip(ip, api_key) for ip in ips],
        return_exceptions=True,
    )

    output = []
    for ip, res in zip(ips, results):
        if isinstance(res, Exception):
            logger.warning(f"[ABUSEIPDB] Error enriqueciendo {ip}: {res}")
            output.append(_empty(ip, "error"))
        else:
            output.append(res)
    return output


async def _check_ip(ip: str, api_key: str) -> dict:
    import aiohttp

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    async with aiohttp.ClientSession() as session:
        async with session.get(
            _API_URL,
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=_TIMEOUT_S),
        ) as resp:
            if resp.status == 429:
                logger.warning("[ABUSEIPDB] Rate limit (429) -- saltando enriquecimiento")
                return _empty(ip, "rate_limit")
            if resp.status != 200:
                return _empty(ip, f"http_{resp.status}")

            data = (await resp.json()).get("data", {})
            return {
                "ip":                     ip,
                "enriched":               True,
                "abuse_confidence_score":  data.get("abuseConfidenceScore", 0),
                "total_reports":           data.get("totalReports", 0),
                "distinct_users":          data.get("numDistinctUsers", 0),
                "country_code":            data.get("countryCode", ""),
                "domain":                  data.get("domain", ""),
                "isp":                     data.get("isp", ""),
                "is_tor":                  data.get("isTor", False),
                "last_reported_at":        data.get("lastReportedAt", ""),
                "usage_type":              data.get("usageType", ""),
                "checked_at":              datetime.now(timezone.utc).isoformat(),
            }


def _empty(ip: str, reason: str) -> dict:
    return {"ip": ip, "enriched": False, "reason": reason}
