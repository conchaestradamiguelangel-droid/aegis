"""
AEGIS — Test del conector ENLIL
================================
Verifica que las detecciones de ruido rutinario (AUTOMATED) no consultan
al Consejo de ENLIL, y que las detecciones reales sí lo siguen haciendo.
"""

import asyncio
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from integrations.enlil_connector import EnlilConnector
from layers.detector import DetectionEvent, DetectionType, ThreatConfidence

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


def _make_detection(dtype: DetectionType, confidence: ThreatConfidence) -> DetectionEvent:
    return DetectionEvent(
        detection_id="TESTID000001",
        timestamp=datetime.now(timezone.utc),
        detection_type=dtype,
        confidence=confidence,
        source_ips=["10.0.0.9"],
        indicators=["indicador de prueba"],
        evidence={"requests_per_second": 999.0},
        action_required="LOCKDOWN",
        elapsed_ms=1.0,
    )


async def t_automated_no_llama_a_enlil():
    """AUTOMATED nunca debe consultar al Consejo — ruido rutinario, AEGIS ya actúa solo."""
    calls = []
    connector = EnlilConnector(enlil_url="http://127.0.0.1:9999", api_key="x")
    connector._post_sync = lambda payload: calls.append(payload) or None

    detection = _make_detection(DetectionType.AUTOMATED, ThreatConfidence.HIGH)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)  # deja correr la task en background si existiera

    assert calls == [], f"AUTOMATED no debería llamar a ENLIL, pero se registraron {len(calls)} llamadas"


async def t_confirmed_si_llama_a_enlil():
    """CONFIRMED (señuelo tocado) debe seguir consultando al Consejo con normalidad."""
    calls = []
    connector = EnlilConnector(enlil_url="http://127.0.0.1:9999", api_key="x")
    connector._post_sync = lambda payload: calls.append(payload) or {"decree_id": "abc", "synthesis": "ok"}

    detection = _make_detection(DetectionType.MINE_CONTACT, ThreatConfidence.CONFIRMED)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert len(calls) == 1, f"CONFIRMED debería llamar a ENLIL exactamente 1 vez, llamó {len(calls)}"
    assert calls[0]["budget_tier"] == "full"


async def t_coordinated_si_llama_a_enlil():
    """COORDINATED (campaña multi-IP) debe seguir consultando al Consejo con normalidad."""
    calls = []
    connector = EnlilConnector(enlil_url="http://127.0.0.1:9999", api_key="x")
    connector._post_sync = lambda payload: calls.append(payload) or {"decree_id": "abc", "synthesis": "ok"}

    detection = _make_detection(DetectionType.COORDINATED, ThreatConfidence.HIGH)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert len(calls) == 1, f"COORDINATED debería llamar a ENLIL exactamente 1 vez, llamó {len(calls)}"


test("ENLIL — AUTOMATED no consulta al Consejo", t_automated_no_llama_a_enlil)
test("ENLIL — CONFIRMED sí consulta al Consejo (tier full)", t_confirmed_si_llama_a_enlil)
test("ENLIL — COORDINATED sí consulta al Consejo", t_coordinated_si_llama_a_enlil)


print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
