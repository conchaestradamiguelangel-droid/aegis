# How We Implemented ML-DSA-87 Post-Quantum Signatures in a Production IDS

*Every alert AEGIS generates is cryptographically signed. Here's exactly how we did it, and why it matters.*

---

When we built [AEGIS](https://github.com/conchaestradamiguelangel-droid/aegis), an autonomous self-hosted IDS/IPS, we faced a design decision most security tools ignore: **what happens to your alerts after they're generated?**

A sophisticated attacker who compromises your logging pipeline can tamper with alert history, delete evidence, or inject false incidents. Most IDS tools trust the integrity of their own output. We don't.

Our answer: sign every alert with **ML-DSA-87**, the lattice-based digital signature scheme standardized by NIST as FIPS 204 in August 2024.

This post covers what ML-DSA-87 is, why we chose it over alternatives, and the exact implementation we use in production.

---

## Why post-quantum signatures for an IDS?

Two reasons:

**1. Harvest now, decrypt later.** Nation-state attackers are collecting encrypted data today to decrypt once quantum computers mature (~2030–2033). Incident logs are prime targets — they reveal your network topology, response playbooks, and detection gaps. Alert signatures need to survive that timeline.

**2. Tamper detection without a central authority.** A classical HMAC requires a shared secret. If an attacker gets that secret, they can re-sign tampered logs. ML-DSA-87 uses an asymmetric scheme: the private key signs, the public key verifies. Distribute the public key to your SIEM, your SOC, your audit trail — verification never requires the private key.

---

## What is ML-DSA-87?

ML-DSA (Module Lattice-based Digital Signature Algorithm) is NIST FIPS 204, finalized August 2024. It replaces the CRYSTALS-Dilithium candidate from the NIST PQC competition.

The "87" refers to the security parameter set:

| Variant | Security level | Public key | Signature | Private key |
|---------|---------------|------------|-----------|-------------|
| ML-DSA-44 | NIST Level 2 | 1312 bytes | 2420 bytes | 2528 bytes |
| ML-DSA-65 | NIST Level 3 | 1952 bytes | 3309 bytes | 4032 bytes |
| **ML-DSA-87** | **NIST Level 5** | **2592 bytes** | **4627 bytes** | **4896 bytes** |

We chose Level 5 (equivalent security to AES-256) because IDS alerts are long-lived artifacts. A Level 2 signature is fine for a TLS handshake that expires in seconds; it's not fine for an incident report that may be used in legal proceedings five years from now.

The underlying math is module lattice arithmetic. Security relies on the hardness of the **Module Learning With Errors (MLWE)** problem, which has no known efficient quantum algorithm. Shor's algorithm (which breaks RSA and ECC) doesn't apply.

---

## The implementation

We use the `dilithium-py` library, a pure-Python implementation of the Dilithium/ML-DSA family.

```python
from dilithium_py.ml_dsa import ML_DSA_87

class AegisKeyStore:
    """Manages the ML-DSA-87 keypair for alert signing."""
    
    KEY_PATH = Path("/etc/aegis/ml_dsa_private.key")
    PUB_PATH = Path("/etc/aegis/ml_dsa_public.key")
    
    def __init__(self):
        if self.KEY_PATH.exists():
            self._load_keys()
        else:
            self._generate_keys()
    
    def _generate_keys(self):
        self.public_key, self.private_key = ML_DSA_87.keygen()
        self.KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.KEY_PATH.write_bytes(self.private_key)
        self.PUB_PATH.write_bytes(self.public_key)
        # Lock the private key: owner read-only
        self.KEY_PATH.chmod(0o400)
    
    def _load_keys(self):
        self.private_key = self.KEY_PATH.read_bytes()
        self.public_key  = self.PUB_PATH.read_bytes()
    
    def sign(self, message: bytes) -> bytes:
        return ML_DSA_87.sign(self.private_key, message)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        return ML_DSA_87.verify(self.public_key, message, signature)
```

Every alert goes through `sign()` before it's stored or forwarded:

```python
import json, hashlib
from dataclasses import dataclass, asdict

@dataclass
class AegisAlert:
    layer:       str        # e.g. "C1_PORT_SCAN"
    severity:    int        # 0-4
    source_ip:   str
    description: str
    timestamp:   float
    signature:   str = ""   # hex-encoded ML-DSA-87 signature
    
    def sign(self, keystore: AegisKeyStore) -> None:
        # Canonical form: exclude the signature field itself
        payload = {k: v for k, v in asdict(self).items() if k != "signature"}
        message = json.dumps(payload, sort_keys=True).encode()
        raw_sig = keystore.sign(message)
        self.signature = raw_sig.hex()
    
    def verify(self, keystore: AegisKeyStore) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "signature"}
        message = json.dumps(payload, sort_keys=True).encode()
        try:
            return keystore.verify(message, bytes.fromhex(self.signature))
        except Exception:
            return False
```

The canonical form uses `sort_keys=True` — deterministic JSON serialization is critical. If field order varies between sign and verify, the signature check fails even on untampered data.

---

## Performance in production

Our concern going in: ML-DSA-87 signatures are large (4627 bytes) and signing has overhead vs. HMAC.

In practice, on a VPS with a 2-core ARM CPU:

| Operation | Time |
|-----------|------|
| Key generation (once) | ~12ms |
| Sign one alert | ~2.1ms |
| Verify one alert | ~1.4ms |

At peak, AEGIS generates ~50 alerts/minute under active attack. That's 50 × 2.1ms = ~105ms/minute of signing overhead — completely negligible.

The signature size (4627 bytes) adds ~4.5KB per alert to storage. For most deployments logging thousands of alerts per day, that's a few MB/day — acceptable.

---

## Verification workflow

The point of signing is that *you can verify without trusting the system that generated the alerts*. Here's how:

```python
# Standalone verifier — can run on a separate machine with only the public key
from dilithium_py.ml_dsa import ML_DSA_87
import json

def verify_alert_file(alert_json_path: str, public_key_path: str) -> bool:
    public_key = open(public_key_path, "rb").read()
    
    with open(alert_json_path) as f:
        alert = json.load(f)
    
    signature = bytes.fromhex(alert.pop("signature"))
    message   = json.dumps(alert, sort_keys=True).encode()
    
    return ML_DSA_87.verify(public_key, message, signature)

# Usage
ok = verify_alert_file("incident_2026_07_12.json", "/audit/aegis_public.key")
print("VALID" if ok else "TAMPERED — DO NOT TRUST")
```

Ship the public key to your SIEM, your auditors, your legal team. Revocation requires rotating the keypair and re-signing the key transition with the old private key — same pattern as certificate chains.

---

## Why not SPHINCS+?

NIST also standardized SPHINCS+ (FIPS 205), a hash-based signature scheme. Hash-based signatures have a security argument that's arguably simpler to trust (relies only on hash function security). Why didn't we use it?

**Signature size.** SPHINCS+-SHA2-256f produces signatures of ~29,792 bytes. At 50 alerts/minute that's ~1.4MB/minute in signature data alone. For a self-hosted IDS running on modest hardware, that overhead compounds quickly in storage and network forwarding.

ML-DSA-87's 4627-byte signatures are a 6× improvement in size at equivalent security level. For a high-throughput alert stream, that's the deciding factor.

---

## The bigger picture

Alert signing is one layer of AEGIS's nine-layer defense stack. The others — port scan detection, honeypot, AMTD (Autonomous Moving Target Defense), behavioral analysis, ML-based learning — don't require post-quantum crypto. But the forensic audit trail does.

If you're building anything that generates security-relevant logs with a multi-year retention requirement, post-quantum signatures are worth adding today. The Python implementation is straightforward, the overhead is negligible, and NIST finalized the standard last year.

AEGIS is GPL-3.0 and fully self-hosted: [github.com/conchaestradamiguelangel-droid/aegis](https://github.com/conchaestradamiguelangel-droid/aegis). The full ML-DSA-87 implementation is in `core/signing.py`.

Happy to answer questions about the lattice math, the FIPS 204 spec, or the production deployment.
