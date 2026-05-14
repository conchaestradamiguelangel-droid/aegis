"""
AEGIS — Test de Carga Real (Hueco #11)
========================================
Mide RPS y latencias p50/p95/p99 bajo carga concurrente.
"""

import asyncio
import os
import sys
import time
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.aegis import AegisSystem

PASS = "OK"
FAIL = "XX"
results = []


def ok(name, condition, detail=""):
    sym = PASS if condition else FAIL
    msg = f"  [{sym}]  {name}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    results.append((name, condition))


async def run_load():
    print()
    print("  === AEGIS LOAD TEST ===")
    print()

    tmpdir = tempfile.mkdtemp(prefix="aegis_load_")
    try:
        aegis = AegisSystem(
            installation_id="AEGIS-LOAD-TEST",
            shield_enabled=False,
            state_dir=os.path.join(tmpdir, "state"),
        )
        await aegis.start()

        # 1. 500 eventos concurrentes al detector
        print("  [1/3] 500 network events concurrentes...")
        N = 500
        ips = [f"10.0.{i // 256}.{i % 256}" for i in range(N)]
        t0 = time.monotonic()
        await asyncio.gather(*[
            aegis.detector.register_network_event(ip, 80, "/probe")
            for ip in ips
        ])
        elapsed = time.monotonic() - t0
        rps = N / elapsed
        ok(f"500 eventos en <5s", elapsed < 5.0, f"{elapsed:.2f}s")
        ok(f"RPS > 100", rps > 100, f"{rps:.0f} RPS")

        # 2. Lockdown x10 — p50 y p95
        print("  [2/3] Lockdown x10...")
        times_ms = []
        for _ in range(10):
            if aegis.lockdown.is_sealed():
                await aegis.lockdown.reset()
            t0 = time.monotonic()
            await aegis.trigger_lockdown("load test")
            times_ms.append((time.monotonic() - t0) * 1000)
        times_ms.sort()
        p50 = times_ms[len(times_ms) // 2]
        p95 = times_ms[int(len(times_ms) * 0.95)]
        ok("Lockdown p50 < 1000ms", p50 < 1000, f"p50={p50:.0f}ms")
        ok("Lockdown p95 < 3000ms", p95 < 3000, f"p95={p95:.0f}ms")

        # 3. 50 sesiones burbuja paralelas
        print("  [3/3] 50 sesiones burbuja paralelas...")
        from layers.bubble import InteractionType
        sids = [
            aegis.open_bubble_session(f"192.168.{i // 256}.{i % 256}")
            for i in range(50)
        ]
        t0 = time.monotonic()
        await asyncio.gather(*[
            aegis.bubble_interact(sid, b"GET /admin HTTP/1.1",
                                  InteractionType.API_CALL)
            for sid in sids
        ])
        elapsed_b = time.monotonic() - t0
        ok("50 sesiones burbuja en <10s", elapsed_b < 10.0, f"{elapsed_b:.2f}s")
        ok("Todas las sesiones activas", len(aegis.bubble.active_sessions()) == 50)

        await aegis.stop()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main():
    t0 = time.monotonic()
    asyncio.run(run_load())
    elapsed = time.monotonic() - t0
    passed = sum(1 for _, r in results if r)
    total = len(results)
    print()
    print(f"  Resultado: {passed}/{total} PASS  |  {elapsed:.2f}s")
    if passed < total:
        for name, r in results:
            if not r:
                print(f"    XX {name}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
