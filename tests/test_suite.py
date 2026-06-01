"""
AEGIS — Suite pytest principal.
Corre cada script de test como subproceso y reporta pass/fail.
Uso: pytest tests/test_suite.py -v
"""
import subprocess
import sys
import pytest
from pathlib import Path

_TESTS_DIR = Path(__file__).parent

# Scripts incluidos en la suite principal (sin servidor live, sin cargas extremas)
_CORE_SCRIPTS = [
    "test_crypto.py",
    "test_amtd.py",
    "test_bubble.py",
    "test_detector.py",
    "test_forensic.py",
    "test_learning.py",
    "test_lockdown.py",
    "test_mace_integration.py",
    "test_minefield.py",
    "test_shield.py",
    "test_twin.py",
    "test_wal.py",
]

# test_aegis.py es el test principal de integracion (más lento)
_INTEGRATION_SCRIPTS = [
    "test_aegis.py",
]


@pytest.mark.parametrize("script", _CORE_SCRIPTS)
def test_core(script):
    """Tests unitarios y de capa — rápidos, sin servidor."""
    _run_script(script)


@pytest.mark.parametrize("script", _INTEGRATION_SCRIPTS)
@pytest.mark.slow
def test_integration(script):
    """Tests de integración completa — más lentos."""
    _run_script(script)


def _run_script(script: str):
    result = subprocess.run(
        [sys.executable, str(_TESTS_DIR / script)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(_TESTS_DIR.parent),
    )
    if result.returncode != 0:
        out = (result.stdout or "")[-3000:]
        err = (result.stderr or "")[-500:]
        pytest.fail(f"{script} exited with code {result.returncode}\n\n{out}\n{err}")
