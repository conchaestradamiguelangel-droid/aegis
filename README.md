# AEGIS — Autonomous Post-Quantum Cyber-Defense System

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![CI](https://github.com/conchaestradamiguelangel-droid/aegis/actions/workflows/aegis_tests.yml/badge.svg)](https://github.com/conchaestradamiguelangel-droid/aegis/actions/workflows/aegis_tests.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Live](https://img.shields.io/badge/live-aegis--pq.com-green.svg)](https://aegis-pq.com)
[![Paper](https://img.shields.io/badge/paper-Zenodo-blue.svg)](https://doi.org/10.5281/zenodo.20274935)
[![Hacker News](https://img.shields.io/badge/Hacker%20News-Show%20HN-orange)](https://news.ycombinator.com/item?id=48883787)

**AEGIS** is a nine-layer defense system for a single HTTP service, deployed as a public demo. It watches request patterns (IP, path, port, rate) and temporarily blocks abusive IPs without human intervention. It implements NIST-standardized post-quantum cryptography (ML-KEM-1024, ML-DSA-87, SPHINCS+), verified at startup — see [Post-Quantum Cryptography](#post-quantum-cryptography) below for exactly what that does and does not protect today.

> *"We do not wait for Q-Day. We defend against it today."*

---

![AEGIS dashboard](https://raw.githubusercontent.com/conchaestradamiguelangel-droid/aegis/main/docs/screenshot.png)

### 🌐 Ekurhive — join our agent network
We're opening Ekurhive, our trust network between AI agents, to outside nodes.
Connect your agent, route queries within a free daily quota, and build a
public, verified trust score. More info: **[ekurhive.macefullmarket.com](https://ekurhive.macefullmarket.com)**

Update (Aug 2026): we found a real production bug in our own test suite, fixed it at the database engine level, and wrote up the whole thing — **[read the postmortem](https://dev.to/conchaestradamiguelangeldroid/we-found-a-bug-that-let-our-test-suite-write-to-production-heres-what-we-did-about-it-c60)**.

---

## Why AEGIS

The cryptographic infrastructure of the internet (RSA, ECC, Diffie-Hellman) is mathematically broken by quantum computers running Shor's algorithm. The Q-Day, estimated 2030-2033, is not a theory: it is an active geopolitical race between the US, China, and the EU.

AEGIS implements the NIST post-quantum standards (FIPS 203, 204, 205) and runs a threshold-based detection stack that adapts, detects, isolates, and learns without human intervention in the detection loop. Initial threshold tuning and reviewing blocked traffic is still an operator task, not something AEGIS does for you.

---

## When to Choose AEGIS

| Situation | AEGIS | Wazuh | Suricata | Falco |
|-----------|-------|-------|----------|-------|
| No human in the detection loop | ✅ automatic detect+block | ❌ requires SIEM ops | ❌ requires rule maintenance | ❌ |
| Post-quantum primitives implemented | ✅ ML-KEM/ML-DSA/SPHINCS+ | ❌ | ❌ | ❌ |
| Single service protection | ✅ one Python process | ❌ multi-component | ❌ | ❌ |
| Moving target defense (AMTD) | ✅ C5 built-in | ❌ | ❌ | ❌ |
| Cryptographic forensic evidence | ⚠️ C1 SHA-256 hash chain (not yet ML-DSA signed) | partial | ❌ | ❌ |
| Threshold-based anomaly detection + heuristic learning | ✅ C3+C8 | partial | ❌ | ❌ |
| Open source, self-hosted | ✅ GPL v3 | ✅ GPL | ✅ GPL | ✅ Apache |
| SIEM integration (ELK, Splunk) | ❌ planned | ✅ best-in-class | ✅ | ✅ |
| Large-scale network (>1 Gbps) | ❌ single process | ✅ | ✅ | ✅ |
| Kubernetes / cloud-native | ❌ | partial | ❌ | ✅ |

**Choose AEGIS when** you protect a specific service, have no dedicated security team, need quantum-safe cryptography, or want a zero-configuration autonomous system.

**Choose Wazuh/Suricata** when you need SIEM integration, large-scale network analysis, or cloud-native deployments.

---

## Architecture: Nine Defensive Layers

```
Incoming traffic
       |
  [C0]   Crypto Foundation   -- ML-KEM-1024, ML-DSA-87, SPHINCS+
  [C0.5] Shield              -- Decoy ports, disuasion layer
  [C1]   Digital Twin        -- In-process state replica, SHA-256 hash-chained jump log
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

> **What these layer names actually mean today:** "Digital Twin" (C1) is an in-process state replica (A/B/C/D), not a separate machine or a real quantum simulation. "Atomic isolation" (C4) means the 5 lockdown actions run concurrently via `asyncio.gather()` inside the same process — it does not reconfigure your firewall, Nginx, DNS, or Kubernetes. "Anomaly detection" (C3) is deterministic thresholds (request rate, path/port diversity), not a trained ML model. These are accurate descriptions of internal mechanisms with ambitious names, not infrastructure-level capabilities.

---

## Post-Quantum Cryptography

| Algorithm   | Standard      | Role                      |
|-------------|---------------|---------------------------|
| ML-KEM-1024 | NIST FIPS 203 | Key encapsulation (Kyber) |
| ML-DSA-87   | NIST FIPS 204 | Digital signatures        |
| SPHINCS+    | NIST FIPS 205 | Hash-based signatures (SHA-2 variant: `sphincs_sha2_256s`, not SHA-3) |

**What this protects today, and what it doesn't:** all three primitives are implemented via `pqcrypto` and pass a self-test on startup — key generation, encapsulation, signing, and verification are real and correct. What they do **not** currently do: ML-KEM is not used to protect proxy sessions (the proxy speaks plain HTTP to its upstream); ML-DSA-87 does not sign incidents, forensic reports, or per-event data — the only code path that calls it is the startup self-test. The forensic/incident chain integrity today comes from a SHA-256 hash chain (`core/log_chain.py`), not from ML-DSA signatures. Wiring PQC into the request/forensic path is on the roadmap, not shipped.

Need standalone ML-DSA-87 signing for your own Python project? We spun the signing layer out into [pqsign](https://github.com/pqsign/pqsign) — key rotation and FastAPI/Flask integration included.

---

## Key Properties

- **100% defensive** -- no active reconnaissance, no counterattacks
- **Single process** -- pure Python asyncio, no threading, no microservices
- **Stateless restart** -- clean systemd restart with no undesired persistent state
- **Minimal surface** -- status API bound to 127.0.0.1 only, never 0.0.0.0
- **Tamper-evident forensics** -- digital twin jumps are recorded in a SHA-256 hash chain; any later alteration is detectable (this is hash-chain integrity, not a cryptographic signature)

---

## Evaluation Results

| Metric             | Result               |
|--------------------|----------------------|
| Unit tests         | 611 passing (100%) — pytest wrappers, several run a full internal script per test, not 611 isolated unit cases |
| Internal scenario tests | 946 / 1,000 (94.6%)  |
| Security breaches in those scenarios | **0**                |
| Known limit (E1)   | latency degrades under sustained high load; exact RPS threshold not currently re-verified against the live proxy |

The "1,000 scenarios" are internal component-level simulations (`tests/redteam_*.py` instantiate AEGIS classes directly) — not an external red-team engagement or a pentest against the deployed proxy, and they don't open real network connections. The 54 failures are latency degradation under extreme load, not exploitable security issues. We have not re-run a live-traffic RPS benchmark against the proxy recently, so the specific ">250 RPS" figure from earlier testing is not being restated as current.

---

## Live Demo

- Production: https://aegis-pq.com
- Dashboard: https://aegis-pq.com/dashboard (auto-refresh 5s)
- Quantum demo: https://aegis-pq.com/quantum-demo (Shor N=15, Qiskit Aer, ~155ms)

---

## Quick Start

### Requirements

```bash
python3.12+
pip install -r requirements.txt
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
| WEBHOOK_URL         | Push incident events (JSON POST) to Discord/Slack/generic webhook | No |
| SYSLOG_HOST         | syslog-ng/rsyslog collector host (RFC 5424, UDP) for incident export | No |
| SYSLOG_PORT         | syslog collector port (default 514) | No |

### Docker
```bash
git clone https://github.com/conchaestradamiguelangel-droid/aegis && cd aegis
cp .env.example .env          # optional: add AEGIS_API_KEY and ABUSEIPDB_API_KEY
docker compose up -d
curl http://localhost:8081/health
```

AEGIS starts in daemon mode, exposes the status API on port `8081`, and the MACE proxy on `8080`.


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
pytest tests/test_suite.py -v
```

611 tests covering all nine layers, forensic chain integrity, cryptographic primitives, and lockdown mechanics.

---

## Use Cases

- **API protection**: proxy any HTTP service behind AEGIS; once an IP is flagged, its *future* requests are blocked — detection runs fire-and-forget in the background, so the specific request that triggers a detection is still forwarded upstream
- **Incident evidence**: every incident generates a JSON/HTML forensic report chained with SHA-256 hashes — a tamper-evident record of what happened, useful as one input into a NIS2/DORA/ISO 27001 evidence trail, not a compliance certification by itself
- **Quantum-safe cryptography, self-tested**: ML-KEM-1024/ML-DSA-87/SPHINCS+ are implemented and verified at startup, ready to build on ahead of Q-Day — see [Post-Quantum Cryptography](#post-quantum-cryptography) for what's wired into the live path today
- **SOC augmentation**: deploy AEGIS alongside existing tools; use [ENLIL](https://github.com/conchaestradamiguelangel-droid/enlil) for strategic AI-assisted incident analysis

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


## Technical Writing

- [How We Implemented ML-DSA-87 Post-Quantum Signatures in a Production IDS](https://dev.to/conchaestradamiguelangeldroid/how-we-implemented-ml-dsa-87-post-quantum-signatures-in-a-production-ids-fn3) — published on Dev.to — Deep dive into the NIST FIPS 204 implementation: signing pipeline, performance benchmarks, and verification workflow.

## Contributing

AEGIS is open to contributions. Priority areas:

- New detection vectors for C3 (Detector layer)
- Additional honeypot types for C2 (Minefield)
- Adapters for different deployment environments
- Performance improvements for the E1 known limit
- Translations and documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and non-negotiable constraints.

Two architectural constraints are non-negotiable: fire-and-forget on C3 (never block the proxy path), and immutability on C1 (twin jumps are forensic evidence).

Good first issues: see [ROADMAP.md](ROADMAP.md) for current open tasks.

---

## Companion Project: ENLIL

AEGIS detects threats. **ENLIL decides what to do about them.**

[ENLIL](https://github.com/conchaestradamiguelangel-droid/enlil) is an open source multi-model AI council: 9 specialized models deliberate in parallel on any query and emit a cryptographically signed Decree (ML-DSA-87). When AEGIS detects a high-severity incident, ENLIL provides the strategic judgment — documented, signed, auditable.

- Self-hosted, BYOK (bring your own OpenRouter API key)
- GPL v3 — same license as AEGIS
- Live demo: https://enlil-council.com
