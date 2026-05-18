# AEGIS — Autonomous Post-Quantum Cyber-Defense System

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Tests](https://github.com/conchaestradamiguelangel-droid/aegis/actions/workflows/tests.yml/badge.svg)](https://github.com/conchaestradamiguelangel-droid/aegis/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Live](https://img.shields.io/badge/live-aegis--pq.com-green.svg)](https://aegis-pq.com)
[![Paper](https://img.shields.io/badge/paper-Zenodo-blue.svg)](https://doi.org/10.5281/zenodo.20274935)

**AEGIS** is an autonomous, nine-layer post-quantum cyber-defense system deployed in production. It protects network services against modern and quantum-era threats using NIST-standardized post-quantum cryptography, without human intervention.

> *"We do not wait for Q-Day. We defend against it today."*

---

## Why AEGIS

The cryptographic infrastructure of the internet (RSA, ECC, Diffie-Hellman) is mathematically broken by quantum computers running Shor's algorithm. The Q-Day, estimated 2030-2033, is not a theory: it is an active geopolitical race between the US, China, and the EU.

AEGIS implements the NIST post-quantum standards (FIPS 203, 204, 205) in a fully autonomous defense stack that adapts, detects, isolates, and learns without requiring a security team.

---

## Architecture: Nine Defensive Layers

```
Incoming traffic
       |
  [C0]   Crypto Foundation   -- ML-KEM-1024, ML-DSA-87, SPHINCS+
  [C0.5] Shield              -- Decoy ports, disuasion layer
  [C1]   Digital Twin        -- Immutable forensic chain, signed jump log
  [C2]   Minefield           -- Honeypots, canary tokens
  [C3]   Detector            -- Anomaly detection (fire-and-forget)
         | threat detected
  [C4]   Lockdown            -- Atomic isolation, session sealing
  [C5]   AMTD                -- Adaptive Moving Target Defense
  [C6]   Bubble              -- Attacker containment, interaction recording
  [C7]   Forensic            -- Automated post-incident analysis
  [C8]   Learning            -- Collective intelligence, pattern update
       |
  Protected service (proxy :8080 -> :8000)
```

Threat flow: Detection (C3) -> Atomic lockdown (C4) -> Twin jump (C1) -> Forensic (C7) -> Learning (C8)

---

## Post-Quantum Cryptography

| Algorithm   | Standard      | Role                      |
|-------------|---------------|---------------------------|
| ML-KEM-1024 | NIST FIPS 203 | Key encapsulation (Kyber) |
| ML-DSA-87   | NIST FIPS 204 | Digital signatures        |
| SPHINCS+    | NIST FIPS 205 | Hash-based signatures     |

---

## Key Properties

- **100% defensive** -- no active reconnaissance, no counterattacks
- **Single process** -- pure Python asyncio, no threading, no microservices
- **Stateless restart** -- clean systemd restart with no undesired persistent state
- **Minimal surface** -- status API bound to 127.0.0.1 only, never 0.0.0.0
- **Immutable forensics** -- digital twin jumps are signed and immutable after registration

---

## Evaluation Results

| Metric             | Result               |
|--------------------|----------------------|
| Unit tests         | 611 passing (100%)   |
| Red team scenarios | 946 / 1,000 (94.6%)  |
| Security breaches  | **0**                |
| Known limit (E1)   | Latency >50% at >250 RPS sustained |

The 54 E1 failures are latency degradation under extreme load, not security failures. Detection remains functional at any load. This is a documented architectural limit of a single Python async process on a general-purpose VPS.

---

## Live Demo

- Production: https://aegis-pq.com
- Dashboard: https://aegis-pq.com/dashboard (auto-refresh 5s)
- Quantum demo: https://aegis-pq.com/quantum-demo (Shor N=15, Qiskit Aer, ~155ms)

---

## Quick Start

### Requirements

```bash
python3.11+
pip install aiohttp pqcrypto liboqs-python
```

### Run

```bash
# Protect a local service on port 8000
python main.py --daemon --mace --mace-port 8080 --mace-target http://localhost:8000

# With Telegram alerts
AEGIS_TG_TOKEN=your_bot_token AEGIS_TG_CHAT=your_chat_id \
python main.py --daemon --mace
```

### Environment Variables

| Variable            | Description              | Required |
|---------------------|--------------------------|----------|
| AEGIS_TG_TOKEN      | Telegram bot token       | No       |
| AEGIS_TG_CHAT       | Telegram chat ID         | No       |
| AEGIS_ENLIL_TOKEN   | ENLIL orchestrator token | No       |
| AEGIS_INCIDENTS_DIR | Path to incident reports | No       |

### systemd (production)

```ini
[Service]
WorkingDirectory=/path/to/aegis
Environment="AEGIS_TG_TOKEN=your_token"
Environment="AEGIS_TG_CHAT=your_chat_id"
ExecStart=/usr/bin/python3 main.py --daemon --mace --mace-port 8080 --mace-target http://localhost:8000
Restart=always
RestartSec=5
```

---

## Run Tests

```bash
pytest tests/ -v
```

611 tests covering all nine layers, forensic chain integrity, cryptographic primitives, and lockdown mechanics.

---

## Intellectual Property

Registered with the Spanish Intellectual Property Registry.

- Expediente: 8NT20260502456 (admitted 27 April 2026)
- Author: Miguel Angel Concha Estrada
- Name: AEGIS -- Sistema Autonomo de Ciberdefensa Post-Cuantica

GPL v3: free to use, study, modify, and distribute. Derivative works must remain open source under the same license.

---

## Contact

- Web: https://aegis-pq.com
- Email: contacto@aegis-pq.com

---

## Contributing

AEGIS is open to contributions. Priority areas:

- New detection vectors for C3 (Detector layer)
- Additional honeypot types for C2 (Minefield)
- Adapters for different deployment environments
- Performance improvements for the E1 known limit
- Translations and documentation

Two architectural constraints are non-negotiable: fire-and-forget on C3 (never block the proxy path), and immutability on C1 (twin jumps are forensic evidence).
