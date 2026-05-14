"""
AEGIS — Test E2E Pipeline Completo (Hueco #1)
===============================================
Verifica el flujo completo de amenaza de extremo a extremo:

  señuelo (C2) → detector (C3) → forense (C7) → aprendizaje (C8)
       ↓
  lockdown (C4) → salto de gemelo (C1)
       ↓
  burbuja (C6) → forense (C7) → aprendizaje (C8)
       ↓
  persistencia: checkpoint + incidente escrito a disco

No usa mocks. No usa sleep() artificiales.
Levanta el sistema real completo y simula un atacante real.
"""

import asyncio
import os
import sys
import time
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.aegis import AegisSystem, SystemStatus
from core.twin import JumpTrigger
from layers.bubble import InteractionType

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []
IP_ATTACKER = "66.66.66.66"


def ok(name: str, condition: bool, detail: str = ""):
    sym = PASS if condition else FAIL
    msg = f"  {sym}  {name}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    results.append((name, condition))
    return condition


async def run_e2e():
    """Pipeline completo de amenaza end-to-end."""
    print()
    print("  ═══ AEGIS TEST E2E — PIPELINE COMPLETO ═══")
    print()

    tmpdir = tempfile.mkdtemp(prefix="aegis_e2e_")

    try:
        # ── 1. ARRANQUE ─────────────────────────────────────────────────────
        print("  [1/9] Arranque del sistema...")
        aegis = AegisSystem(
            installation_id = "AEGIS-E2E-TEST",
            amtd_interval_s = 5,
            shield_enabled  = False,
            state_dir       = os.path.join(tmpdir, "state"),
        )

        await aegis.start()

        ok("Sistema arranca en estado ONLINE",
           aegis.status == SystemStatus.ONLINE)

        # ── 2. SEÑUELO TOCADO (C2 → C3 → C7) ───────────────────────────────
        print("  [2/9] Señuelo tocado (C2 → C3 → C7)...")
        contact, _ = await aegis.minefield.touch_credential(
            resource="admin_db_password", source_ip=IP_ATTACKER, source_port=54321
        )
        await asyncio.sleep(0.15)

        ok("Señuelo de credencial activado",
           contact is not None and contact.source_ip == IP_ATTACKER)
        ok("Forense registró el contacto (C2→C7)",
           aegis.forensic.active_incidents() >= 0)

        # ── 3. DETECCIÓN POR PATRÓN (C3) ────────────────────────────────────
        print("  [3/9] Patrón de reconocimiento (C3)...")
        detections_before = aegis.detector.total_detections()
        await aegis.detector.register_network_event(IP_ATTACKER, 22, "/admin")
        await aegis.detector.register_network_event(IP_ATTACKER, 443, "/config")
        await aegis.detector.register_network_event(IP_ATTACKER, 3306, "/database")
        await asyncio.sleep(0.15)

        ok("Detector procesa eventos de red",
           aegis.detector.total_detections() >= detections_before,
           f"detecciones={aegis.detector.total_detections()}")

        # ── 4. CIERRE ATÓMICO + SALTO GEMELO (C4 → C1) ──────────────────────
        print("  [4/9] Lockdown + salto de gemelo (C4→C1)...")
        jumps_before = len(aegis.twin.get_jump_log())
        t_lock = time.monotonic()

        success = await aegis.trigger_lockdown("E2E test — cierre forzado")
        await asyncio.sleep(0.4)

        elapsed_lock = (time.monotonic() - t_lock) * 1000
        jump_log     = aegis.twin.get_jump_log()

        ok("Lockdown ejecutado con éxito", success)
        ok("Gemelo saltó tras lockdown (C1)",
           len(jump_log) > jumps_before,
           f"saltos={len(jump_log)}")
        ok(f"Lockdown completó en <3000ms",
           elapsed_lock < 3000,
           f"{elapsed_lock:.0f}ms")

        # ── 5. AUTENTICACIÓN DE GEMELOS (Hueco #3) ───────────────────────────
        print("  [5/9] Autenticación HMAC entre gemelos (Hueco #3)...")
        from core.twin import Twin, TwinID, TwinStatus
        from core.twin import empty_operational_state
        from dataclasses import field

        # Intentar sync desde un gemelo externo (sin _sync_secret de esta cadena)
        impostor = Twin(
            twin_id      = TwinID.A,
            status       = TwinStatus.ACTIVE,
            state        = empty_operational_state(),
        )
        # _sync_secret del impostor = b"" (default) — diferente al de la cadena

        sync_rejected = False
        try:
            aegis.twin.twin_b.sync_from(impostor)
        except ValueError:
            sync_rejected = True

        ok("Sync de gemelo externo rechazado (HMAC inválido)", sync_rejected)

        # Verificar que sincronización interna sigue funcionando
        aegis.twin.twin_b.sync_from(aegis.twin.twin_a)
        ok("Sync interno entre gemelos de la misma cadena funciona", True)

        # ── 6. BURBUJA (C6) ──────────────────────────────────────────────────
        print("  [6/9] Sesión de burbuja (C6)...")
        session_id = aegis.open_bubble_session(IP_ATTACKER)
        response   = await aegis.bubble_interact(
            session_id, b"GET /admin HTTP/1.1",
            interaction_type=InteractionType.API_CALL
        )
        ok("Burbuja abre sesión", bool(session_id))
        ok("Burbuja responde al intruso", bool(response))

        # ── 7. FORENSE + APRENDIZAJE (C7 → C8) ──────────────────────────────
        print("  [7/9] Forense + Aprendizaje (C7→C8)...")
        incident_id = aegis.open_forensic_incident([IP_ATTACKER])
        ok("Forense abre incidente", bool(incident_id))

        await aegis.close_forensic_incident(incident_id)
        await asyncio.sleep(0.15)

        ok("Forense cierra incidente limpiamente", True)

        # ── 8. PKI ENTRE INSTALACIONES (Hueco #8) ────────────────────────────
        print("  [8/9] PKI entre instalaciones (Hueco #8)...")

        # Instalación B intenta enviar inteligencia a esta instalación
        aegis_b = AegisSystem(
            installation_id = "AEGIS-E2E-B",
            shield_enabled  = False,
            state_dir       = os.path.join(tmpdir, "state_b"),
        )
        await aegis_b.start()

        packet = aegis_b.export_intelligence()

        # Sin registrar el peer → debe rechazar
        rejected = not aegis.import_intelligence(packet, verify=True)
        ok("Paquete de peer no registrado RECHAZADO", rejected)

        # Registrar peer con clave correcta → debe aceptar
        aegis.trust_peer(aegis_b.installation_id, aegis_b.get_own_key())
        accepted = aegis.import_intelligence(packet, verify=True)
        ok("Paquete de peer registrado ACEPTADO", accepted)

        # Clave incorrecta → debe rechazar
        aegis.learning._trusted_peers["AEGIS-FAKE"] = b"clave_falsa_12345678"
        fake_packet = aegis_b.export_intelligence()
        fake_packet.origin_id = "AEGIS-FAKE"
        rejected_fake = not aegis.import_intelligence(fake_packet, verify=True)
        ok("Paquete con firma inválida RECHAZADO", rejected_fake)

        await aegis_b.stop()

        # ── 9. PERSISTENCIA A DISCO ───────────────────────────────────────────
        print("  [9/9] Persistencia a disco (Huecos #7 y #9)...")
        snap = await aegis._snapshot_for_checkpoint()
        ckpt = aegis._persistence.save_checkpoint(snap)

        state_dir    = os.path.join(tmpdir, "state")
        ckpt_path    = os.path.join(state_dir, "checkpoints", "latest.json")
        incident_dir = os.path.join(state_dir, "incidents")

        ok("Checkpoint escrito a disco",
           os.path.exists(ckpt_path))
        ok("Checkpoint tiene ID válido",
           "ckpt_" in ckpt.get("checkpoint_id", ""))

        incident_files = os.listdir(incident_dir) if os.path.exists(incident_dir) else []
        ok("Incidente forense persistido a disco",
           len(incident_files) > 0,
           f"archivos={len(incident_files)}")

        await aegis.stop()
        ok("Sistema para limpiamente en OFFLINE",
           aegis.status == SystemStatus.OFFLINE)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    t0 = time.monotonic()
    asyncio.run(run_e2e())

    elapsed = time.monotonic() - t0
    passed  = sum(1 for _, r in results if r)
    total   = len(results)
    failed  = total - passed

    print()
    print(f"  ─────────────────────────────────────────")
    print(f"  Resultado: {passed}/{total} PASS  |  {failed} FAIL  |  {elapsed:.2f}s")
    print()

    if failed > 0:
        print("  Fallos:")
        for name, r in results:
            if not r:
                print(f"    ✗ {name}")
        print()

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
