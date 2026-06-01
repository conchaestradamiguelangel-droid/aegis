"""
AEGIS — Tests del WAL (Write-Ahead Log)
=========================================
Tests que verifican:
1. WALManager escribe entrada y la recupera si no hay commit
2. WALManager elimina entrada tras commit
3. Entradas corruptas se ignoran sin romper recovery
4. WAL integrado con MaceConnector registra block/unblock
5. Recovery replay aplica bloqueos a la blocklist
"""

import sys
import os
import json
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.wal import WALManager
from integrations.mace_proxy import Blocklist, MaceProxy
from integrations.mace_connector import MaceConnector

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []


def test(name, fn):
    try:
        fn()
        results.append((PASS, name))
        print(f"{PASS} {name}")
    except Exception as e:
        results.append((FAIL, name))
        print(f"{FAIL} {name}: {e}")
        import traceback; traceback.print_exc()


def test_write_and_recover():
    with tempfile.TemporaryDirectory() as tmp:
        wal = WALManager(Path(tmp))
        wal_path = wal.write("block_ip", {"ip": "10.0.0.1", "ttl_s": 3600})
        assert wal_path.exists(), "WAL file debe existir"
        assert wal.pending_count() == 1
        pending = wal.recover()
        assert len(pending) == 1
        p, entry = pending[0]
        assert entry["op"] == "block_ip"
        assert entry["params"]["ip"] == "10.0.0.1"

test("WAL: write crea fichero recuperable", test_write_and_recover)


def test_commit_removes_file():
    with tempfile.TemporaryDirectory() as tmp:
        wal = WALManager(Path(tmp))
        wal_path = wal.write("block_ip", {"ip": "10.0.0.2", "ttl_s": 60})
        wal.commit(wal_path)
        assert wal.pending_count() == 0
        assert not wal_path.exists()

test("WAL: commit elimina fichero", test_commit_removes_file)


def test_corrupt_entry_ignored():
    with tempfile.TemporaryDirectory() as tmp:
        wal = WALManager(Path(tmp))
        corrupt = Path(tmp) / "op_bad.json"
        corrupt.write_text("not valid json")
        wal.write("block_ip", {"ip": "10.0.0.3", "ttl_s": 60})
        pending = wal.recover()
        assert len(pending) == 1, f"Solo la entrada valida — got {len(pending)}"

test("WAL: entradas corruptas ignoradas", test_corrupt_entry_ignored)


def test_multiple_ops_ordered():
    with tempfile.TemporaryDirectory() as tmp:
        wal = WALManager(Path(tmp))
        for i in range(5):
            wal.write("block_ip", {"ip": f"10.0.{i}.1", "ttl_s": 60})
        assert wal.pending_count() == 5
        pending = wal.recover()
        assert len(pending) == 5
        for p, e in pending:
            wal.commit(p)
        assert wal.pending_count() == 0

test("WAL: multiples ops y recovery completo", test_multiple_ops_ordered)


def test_connector_writes_wal_on_block():
    """WAL entry persiste despues de block_ip — se limpia en checkpoint, no en commit."""
    with tempfile.TemporaryDirectory() as tmp:
        wal = WALManager(Path(tmp))
        import types
        proxy = types.SimpleNamespace(
            blocklist=types.SimpleNamespace(
                block=lambda ip, ttl_s=None: None,
                unblock=lambda ip: None,
                active_count=lambda: 0,
                to_list=lambda: [],
                is_blocked=lambda ip: False,
            ),
            stats=types.SimpleNamespace(to_dict=lambda: {}),
        )
        proxy._blocklist = proxy.blocklist

        connector = MaceConnector(proxy=proxy, wal=wal)
        connector.block_ip("192.168.1.1", ttl_s=300, reason="test")
        # WAL persiste hasta el proximo checkpoint (no se commitea en block_ip)
        assert wal.pending_count() == 1, "WAL debe tener 1 entrada pendiente"
        # Simular checkpoint exitoso -> flush
        wal.flush()
        assert wal.pending_count() == 0, "Flush limpia el WAL"

test("WAL: connector escribe WAL y checkpoint lo limpia", test_connector_writes_wal_on_block)


def test_recovery_replays_block():
    """Simula crash mid-block: WAL existe sin commit — recovery debe bloquear la IP."""
    with tempfile.TemporaryDirectory() as tmp:
        wal = WALManager(Path(tmp))
        # Escribir WAL pero no hacer commit (simula SIGKILL entre write y commit)
        wal.write("block_ip", {"ip": "5.5.5.5", "ttl_s": 3600})
        
        # Recovery: leer WAL y aplicar a una blocklist limpia
        bl = Blocklist()
        assert not bl.is_blocked("5.5.5.5")
        
        pending = wal.recover()
        for wal_path, entry in pending:
            op = entry["op"]
            params = entry["params"]
            if op == "block_ip":
                bl.block(params["ip"], ttl_s=params["ttl_s"])
            elif op == "unblock_ip":
                bl.unblock(params["ip"])
            wal.commit(wal_path)
        
        assert bl.is_blocked("5.5.5.5"), "IP debe estar bloqueada tras recovery"
        assert wal.pending_count() == 0

test("WAL: recovery replay bloquea IP perdida por crash", test_recovery_replays_block)


print()
passed = sum(1 for r, _ in results if r == PASS)
failed = sum(1 for r, _ in results if r == FAIL)
print(f"Resultado: {passed}/{len(results)} tests pasados")
sys.exit(0 if failed == 0 else 1)
