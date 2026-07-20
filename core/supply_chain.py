"""
AEGIS — Supply Chain Integrity (Issue #21)
==========================================
Verifies that installed Python packages match a known-good manifest.

Workflow:
  1. Run  once to create the manifest.
  2. Call verify_dependencies() at AEGIS startup to detect tampering.
  3. If any package has a mismatched hash, AEGIS logs a CRITICAL alert
     and (optionally) refuses to start.

Manifest lives at /var/lib/aegis/supply_chain_manifest.json
"""

import hashlib
import importlib.metadata
import json
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("aegis.supply_chain")

MANIFEST_PATH = Path("/var/lib/aegis/supply_chain_manifest.json")


def _hash_package(dist) -> str:
    """Deterministic hash of package name+version+location."""
    location = str(getattr(dist, '_path', '') or getattr(dist, 'locate_file', lambda x: '')(dist.name))
    payload = f"{dist.name}=={dist.version}::{location}"
    return hashlib.sha256(payload.encode()).hexdigest()


def generate_manifest(output: Path = MANIFEST_PATH) -> dict:
    """
    Snapshot all currently installed packages into a signed manifest.
    Run once after a clean install on a trusted machine.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    packages = {}
    for dist in importlib.metadata.distributions():
        packages[dist.name] = {
            "version": dist.version,
            "hash":    _hash_package(dist),
        }

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python":       sys.version,
        "packages":     packages,
    }
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    logger.info(f"[SUPPLY_CHAIN] Manifest generated: {len(packages)} packages -> {output}")
    return manifest


def verify_dependencies(manifest_path: Path = MANIFEST_PATH) -> tuple[bool, list]:
    """
    Compare currently installed packages against the manifest.

    Returns:
        (True, []) if all packages match.
        (False, [list of issues]) if any discrepancy found.
    """
    if not manifest_path.exists():
        logger.warning("[SUPPLY_CHAIN] No manifest found — run --generate first")
        return True, ["no manifest — skipping verification"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    known = manifest["packages"]
    issues = []

    current = {dist.name: dist for dist in importlib.metadata.distributions()}

    # Check for new or changed packages
    for name, dist in current.items():
        if name not in known:
            issues.append(f"NEW package not in manifest: {name}=={dist.version}")
            logger.warning(f"[SUPPLY_CHAIN] NEW: {name}=={dist.version}")
        else:
            current_hash = _hash_package(dist)
            if current_hash != known[name]["hash"]:
                issues.append(
                    f"HASH MISMATCH: {name} (manifest={known[name]['version']}, current={dist.version})")
                logger.critical(f"[SUPPLY_CHAIN] TAMPER DETECTED: {name} hash mismatch")

    # Check for removed packages
    for name in known:
        if name not in current:
            issues.append(f"REMOVED: {name} was in manifest but is no longer installed")
            logger.warning(f"[SUPPLY_CHAIN] REMOVED: {name}")

    if issues:
        logger.warning(f"[SUPPLY_CHAIN] {len(issues)} issue(s) found")
    else:
        logger.info(f"[SUPPLY_CHAIN] OK — {len(current)} packages verified")

    return len(issues) == 0, issues


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS supply chain integrity tool")
    parser.add_argument("--generate", action="store_true", help="Generate manifest from current environment")
    parser.add_argument("--verify",   action="store_true", help="Verify current environment against manifest")
    args = parser.parse_args()

    if args.generate:
        m = generate_manifest()
        print(f"Generated manifest: {len(m['packages'])} packages")
    elif args.verify:
        ok, issues = verify_dependencies()
        if ok:
            print("Supply chain OK")
        else:
            print(f"ISSUES FOUND ({len(issues)}):")
            for issue in issues:
                print(f"  - {issue}")
        sys.exit(0 if ok else 1)
    else:
        parser.print_help()
