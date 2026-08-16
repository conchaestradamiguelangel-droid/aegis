"""
AEGIS — Test del conector ENLIL
================================
Verifica el interruptor manual del bridge (ENLIL_BRIDGE_ENABLED, apagado
por defecto — decisión 16/08/2026) y que, con el bridge encendido, el
ruido rutinario (AUTOMATED) sigue sin consultar al Consejo mientras las
detecciones reales (CONFIRMED, COORDINATED) sí lo hacen.
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


def _connector(bridge_enabled: bool) -> EnlilConnector:
    """Construye un connector forzando el estado del interruptor, sin
    depender de lo que haya (o no) en el entorno real del proceso."""
    if bridge_enabled:
        os.environ["ENLIL_BRIDGE_ENABLED"] = "true"
    else:
        os.environ.pop("ENLIL_BRIDGE_ENABLED", None)
    try:
        return EnlilConnector(enlil_url="http://127.0.0.1:9999", api_key="x")
    finally:
        os.environ.pop("ENLIL_BRIDGE_ENABLED", None)


async def t_bridge_apagado_por_defecto_ni_confirmed_llama():
    """Sin ENLIL_BRIDGE_ENABLED en el entorno, NINGÚN tipo consulta al
    Consejo — ni siquiera CONFIRMED (señuelo tocado, la más grave)."""
    calls = []
    connector = _connector(bridge_enabled=False)
    connector._post_sync = lambda payload: calls.append(payload) or None

    detection = _make_detection(DetectionType.MINE_CONTACT, ThreatConfidence.CONFIRMED)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert calls == [], f"Con el bridge apagado, CONFIRMED no debería llamar a ENLIL, pero llamó {len(calls)} veces"


async def t_bridge_apagado_coordinated_tampoco_llama():
    """Igual que arriba, para COORDINATED (campaña multi-IP)."""
    calls = []
    connector = _connector(bridge_enabled=False)
    connector._post_sync = lambda payload: calls.append(payload) or None

    detection = _make_detection(DetectionType.COORDINATED, ThreatConfidence.HIGH)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert calls == [], f"Con el bridge apagado, COORDINATED no debería llamar a ENLIL, pero llamó {len(calls)} veces"


async def t_bridge_encendido_automated_sigue_bloqueado():
    """Con ENLIL_BRIDGE_ENABLED=true, AUTOMATED sigue sin llamar — es
    ruido rutinario independientemente del interruptor manual."""
    calls = []
    connector = _connector(bridge_enabled=True)
    connector._post_sync = lambda payload: calls.append(payload) or None

    detection = _make_detection(DetectionType.AUTOMATED, ThreatConfidence.HIGH)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert calls == [], f"AUTOMATED no debería llamar a ENLIL ni con el bridge encendido, llamó {len(calls)} veces"


async def t_bridge_encendido_confirmed_si_llama():
    """Con ENLIL_BRIDGE_ENABLED=true, CONFIRMED sí consulta al Consejo con normalidad."""
    calls = []
    connector = _connector(bridge_enabled=True)
    connector._post_sync = lambda payload: calls.append(payload) or {"decree_id": "abc", "synthesis": "ok"}

    detection = _make_detection(DetectionType.MINE_CONTACT, ThreatConfidence.CONFIRMED)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert len(calls) == 1, f"Con el bridge encendido, CONFIRMED debería llamar a ENLIL exactamente 1 vez, llamó {len(calls)}"
    assert calls[0]["budget_tier"] == "full"


async def t_bridge_encendido_coordinated_si_llama():
    """Con ENLIL_BRIDGE_ENABLED=true, COORDINATED sí consulta al Consejo con normalidad."""
    calls = []
    connector = _connector(bridge_enabled=True)
    connector._post_sync = lambda payload: calls.append(payload) or {"decree_id": "abc", "synthesis": "ok"}

    detection = _make_detection(DetectionType.COORDINATED, ThreatConfidence.HIGH)
    await connector.on_threat_detected(detection)
    await asyncio.sleep(0.05)

    assert len(calls) == 1, f"Con el bridge encendido, COORDINATED debería llamar a ENLIL exactamente 1 vez, llamó {len(calls)}"


test("ENLIL — bridge apagado por defecto: CONFIRMED NO consulta al Consejo", t_bridge_apagado_por_defecto_ni_confirmed_llama)
test("ENLIL — bridge apagado por defecto: COORDINATED NO consulta al Consejo", t_bridge_apagado_coordinated_tampoco_llama)
test("ENLIL — bridge encendido: AUTOMATED sigue bloqueado", t_bridge_encendido_automated_sigue_bloqueado)
test("ENLIL — bridge encendido: CONFIRMED sí consulta al Consejo (tier full)", t_bridge_encendido_confirmed_si_llama)
test("ENLIL — bridge encendido: COORDINATED sí consulta al Consejo", t_bridge_encendido_coordinated_si_llama)


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
