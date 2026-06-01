"""
Excluye los scripts de test custom-framework de la colección de pytest.
Los tests se ejecutan a través de test_suite.py como subprocesos.
"""
collect_ignore_glob = [
    "test_aegis.py",
    "test_amtd.py",
    "test_bubble.py",
    "test_crypto.py",
    "test_detector.py",
    "test_e2e_pipeline.py",
    "test_forensic.py",
    "test_learning.py",
    "test_load.py",
    "test_lockdown.py",
    "test_mace_integration.py",
    "test_minefield.py",
    "test_shield.py",
    "test_sigkill.py",
    "test_twin.py",
    "test_wal.py",
    "redteam_*.py",
]
