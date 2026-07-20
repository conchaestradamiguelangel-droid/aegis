"""
AEGIS — Forensic Log Integrity (Issue #22)
==========================================
Append-only, tamper-evident log chain for the C7 Forensic layer.

Each log entry is linked to the previous via SHA-256 hash chain.
Any deletion or modification of a past entry breaks the chain —
detectable by verify_chain().
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger("aegis.log_chain")

CHAIN_FILE = Path("/var/lib/aegis/forensic_chain.jsonl")


def _hash_entry(entry: dict) -> str:
    """SHA-256 of canonical JSON (no signature field)."""
    payload = {k: v for k, v in entry.items() if k != "sig"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()


def append_entry(data: dict, chain_file: Path = CHAIN_FILE) -> str:
    """
    Append a tamper-evident entry to the log chain.

    Each entry contains:
        seq      — monotonic sequence number
        ts       — UTC ISO timestamp
        prev_sig — SHA-256 of previous entry (genesis = 64 zeros)
        data     — caller-supplied payload
        sig      — SHA-256 of this entry (excluding sig field itself)

    Returns the sig of the appended entry.
    """
    chain_file.parent.mkdir(parents=True, exist_ok=True)

    prev_sig = "0" * 64
    seq = 0

    if chain_file.exists():
        lines = chain_file.read_text(encoding="utf-8").splitlines()
        for raw in reversed(lines):
            raw = raw.strip()
            if raw:
                try:
                    last = json.loads(raw)
                    prev_sig = last["sig"]
                    seq = last["seq"] + 1
                except (json.JSONDecodeError, KeyError):
                    pass
                break

    entry = {
        "seq":      seq,
        "ts":       datetime.now(timezone.utc).isoformat(),
        "prev_sig": prev_sig,
        "data":     data,
    }
    entry["sig"] = _hash_entry(entry)

    with open(chain_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())

    logger.debug(f"[LOG_CHAIN] seq={seq} sig={entry['sig'][:12]}...")
    return entry["sig"]


def verify_chain(chain_file: Path = CHAIN_FILE) -> tuple[bool, str]:
    """
    Verify the integrity of the entire log chain.

    Returns:
        (True, "ok") if chain is intact.
        (False, reason) if any tampering is detected.
    """
    if not chain_file.exists():
        return True, "ok (empty chain)"

    lines = [l.strip() for l in chain_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        return True, "ok (empty chain)"

    prev_sig = "0" * 64
    for i, raw in enumerate(lines):
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            return False, f"entry {i}: invalid JSON"

        if entry.get("seq") != i:
            return False, f"entry {i}: sequence mismatch (got {entry.get('seq')}; expected {i})"

        if entry.get("prev_sig") != prev_sig:
            return False, f"entry {i}: prev_sig mismatch — chain broken at seq {i}"

        expected_sig = _hash_entry(entry)
        if entry.get("sig") != expected_sig:
            return False, f"entry {i}: content hash mismatch — entry tampered"

        prev_sig = entry["sig"]

    return True, f"ok ({len(lines)} entries verified)"
