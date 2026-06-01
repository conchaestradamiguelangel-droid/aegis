"""
AEGIS — Test de resiliencia SIGKILL
Verifica que los bloqueos sobreviven un kill -9 del proceso.

Flujo:
1. Arrancar AEGIS en puertos de test (estado dir temporal)
2. Sembrar entradas WAL (simula bloques ocurridos entre checkpoints)
3. Enviar SIGKILL al proceso
4. Verificar que los archivos WAL persisten
5. Reiniciar AEGIS con mismo state dir
6. Verificar que las IPs estan bloqueadas via /status
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.wal import WALManager

PASS = "OK"
FAIL = "FAIL"
TEST_PORT  = 19081   # status server
TEST_MACE  = 19080   # proxy port (no hay MACE real detras — no importa)
ATTACKED_IPS = ["10.66.0.1", "10.66.0.2", "10.66.0.3"]

def log(msg):
    print(f"  {msg}", flush=True)


async def wait_health(port, timeout=15):
    """Espera a que /health responda 200."""
    import aiohttp
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"http://127.0.0.1:{port}/health", timeout=aiohttp.ClientTimeout(total=2)) as r:
                    if r.status == 200:
                        return True
        except Exception:
            pass
        await asyncio.sleep(0.5)
    return False


def seed_wal(wal_dir: Path, ips: list):
    """Siembra entradas WAL sin hacer commit (simula bloques entre checkpoints)."""
    wal = WALManager(wal_dir)
    for ip in ips:
        wal.write("block_ip", {"ip": ip, "ttl_s": 7200})
    return wal.pending_count()


async def get_blocked_ips(port) -> list:
    """Lee las IPs bloqueadas desde /status (campo blocked_ips_list del connector)."""
    import aiohttp
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"http://127.0.0.1:{port}/status", timeout=aiohttp.ClientTimeout(total=5)) as r:
                data = await r.json()
                mace = data.get("mace", {})
                return mace.get("blocked_ips_list", [])
    except Exception as e:
        return []


async def run_test():
    results = []

    with tempfile.TemporaryDirectory() as state_dir:
        wal_dir = Path(state_dir) / "wal"
        wal_dir.mkdir(parents=True, exist_ok=True)

        log(f"State dir: {state_dir}")

        cmd = [
            "python3", "main.py", "--daemon", "--mace",
            "--mace-port", str(TEST_MACE),
            "--mace-target", "http://127.0.0.1:18999",  # target inexistente
            "--status-port", str(TEST_PORT),
            "--state-dir", state_dir,
        ]

        # ── FASE 1: Arrancar AEGIS ───────────────────────────────────────────
        log("Fase 1: Arrancando AEGIS en puertos de test...")
        proc1 = subprocess.Popen(cmd, cwd="/root/aegis", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        healthy = await wait_health(TEST_PORT, timeout=20)
        if not healthy:
            proc1.kill()
            print(f"  {FAIL} AEGIS no arranco a tiempo")
            results.append((FAIL, "AEGIS arranca en puertos de test"))
            return results

        log(f"  AEGIS arrancado (PID={proc1.pid})")
        results.append((PASS, "AEGIS arranca en puertos de test"))

        # ── FASE 2: Sembrar WAL (simular bloques entre checkpoints) ─────────
        log("Fase 2: Sembrando entradas WAL (simulando bloques sin checkpoint)...")
        n = seed_wal(wal_dir, ATTACKED_IPS)
        log(f"  {n} entradas WAL sembradas")
        if n == len(ATTACKED_IPS):
            results.append((PASS, f"WAL sembrado con {n} IPs"))
        else:
            results.append((FAIL, f"WAL sembrado: esperado {len(ATTACKED_IPS)}, encontrado {n}"))

        # ── FASE 3: SIGKILL ─────────────────────────────────────────────────
        log("Fase 3: Enviando SIGKILL al proceso...")
        os.kill(proc1.pid, signal.SIGKILL)
        proc1.wait(timeout=5)
        log(f"  Proceso {proc1.pid} terminado")

        # Verificar que los archivos WAL persisten tras el kill
        surviving = list(wal_dir.glob("op_*.json"))
        log(f"  Archivos WAL sobrevivientes: {len(surviving)}")
        if len(surviving) == len(ATTACKED_IPS):
            results.append((PASS, f"WAL persiste tras SIGKILL ({len(surviving)} archivos)"))
        else:
            results.append((FAIL, f"WAL perdido tras SIGKILL: {len(surviving)}/{len(ATTACKED_IPS)}"))

        # ── FASE 4: Reiniciar AEGIS con mismo state dir ─────────────────────
        log("Fase 4: Reiniciando AEGIS con el mismo state dir...")
        proc2 = subprocess.Popen(cmd, cwd="/root/aegis", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        healthy2 = await wait_health(TEST_PORT, timeout=20)
        if not healthy2:
            proc2.kill()
            results.append((FAIL, "AEGIS no arranco tras SIGKILL"))
            return results

        log(f"  AEGIS reiniciado (PID={proc2.pid})")
        results.append((PASS, "AEGIS reinicia tras SIGKILL"))

        # Pequeña espera para que recovery complete
        await asyncio.sleep(2)

        # ── FASE 5: Verificar IPs bloqueadas ────────────────────────────────
        log("Fase 5: Verificando IPs bloqueadas via /status...")
        blocked = await get_blocked_ips(TEST_PORT)
        log(f"  IPs bloqueadas en /status: {blocked}")

        for ip in ATTACKED_IPS:
            if ip in blocked:
                results.append((PASS, f"IP {ip} bloqueada tras recovery"))
                log(f"  {PASS} {ip} esta bloqueada")
            else:
                results.append((FAIL, f"IP {ip} NO bloqueada tras recovery"))
                log(f"  {FAIL} {ip} no encontrada en blocklist")

        # Verificar WAL limpio tras recovery
        await asyncio.sleep(1)
        remaining_wal = list(wal_dir.glob("op_*.json"))
        log(f"  Archivos WAL tras recovery: {len(remaining_wal)}")
        if len(remaining_wal) == 0:
            results.append((PASS, "WAL limpio tras recovery"))
        else:
            results.append((FAIL, f"WAL no limpio: {len(remaining_wal)} archivos"))

        # Cleanup
        proc2.terminate()
        try:
            proc2.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc2.kill()

    return results


async def main():
    print("\n== TEST SIGKILL — AEGIS WAL Resilience ==")
    print("Simula: bloques ocurren entre checkpoints → SIGKILL → recovery")
    print()

    results = await run_test()

    print()
    passed = sum(1 for r, _ in results if r == PASS)
    failed = sum(1 for r, _ in results if r == FAIL)
    for r, name in results:
        print(f"  [{r}] {name}")
    print()
    print(f"Resultado: {passed}/{len(results)} tests pasados")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
