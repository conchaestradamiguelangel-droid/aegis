# Contributing to AEGIS

AEGIS is a post-quantum cyber-defense system in active production. Contributions are welcome and held to a high standard — every change must preserve the autonomous, traceable, and defensive nature of the system.

## Before you start

Read the architecture overview below and in the README before proposing changes.

## Architecture overview

AEGIS runs as a single asyncio process with 9 defense layers:

| Layer | Module | Description |
|---|---|---|
| C0 | `core/crypto.py` | ML-DSA-87 post-quantum signing (NIST FIPS 204) |
| C0.5 | `layers/shield.py` | Decoy port honeypots |
| C1 | `core/twin.py` | Digital twin — tracks attack surface state |
| C2 | `layers/minefield.py` | Tarpit and rate limiting |
| C3 | `layers/detector.py` | ML-based anomaly detection |
| C4 | `core/lockdown.py` | Atomic lockdown on critical threat |
| C5 | `layers/amtd.py` | Autonomous Moving Target Defense |
| C6 | `layers/bubble.py` | Network isolation |
| C7 | `layers/forensic.py` | Evidence collection and chain-of-custody |
| C8 | `layers/learning.py` | Incident learning and pattern storage |

## Development setup

**Requirements:** Python 3.11+, Linux or WSL (asyncio signal handling requires Unix)

```bash
git clone https://github.com/conchaestradamiguelangel-droid/aegis
cd aegis
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the test suite:

```bash
cd aegis
pytest tests/ -v
```

All tests must pass before submitting a PR.

## How to contribute

1. **Fork** the repository and create a branch: `git checkout -b fix/your-description`
2. **Run tests** before and after your change
3. **Add a test** for any new behavior. If you touch a layer, add a test case in the corresponding `tests/test_<layer>.py`
4. **Open a PR** — describe what you changed, why, and what the test result was

## Good first issues

Look for issues labeled [`good-first-issue`](../../issues?q=label%3Agood-first-issue). These are well-scoped and don't require deep knowledge of the full stack.

## Non-negotiable constraints

- **100% defensive** — no active reconnaissance, no counterattacks, no data exfiltration from attackers
- **No threading/multiprocessing** — asyncio only, single process
- **No breaking the proxy path** — changes to `_handle()` in `integrations/mace_proxy.py` have direct latency impact on MACE
- **C1 Twin immutability** — jump logs are forensic evidence; `get_jump_log()` entries are immutable once written
- **Status server stays local** — `:8081` must stay bound to `127.0.0.1` only

If your contribution touches any of these, explain the justification explicitly in your PR.

## What we are looking for

- Type annotations and docstrings (Google style) on core modules and layers
- New detection patterns in `layers/detector.py`
- Performance improvements in the detection pipeline (without hiding E1 degradation)
- Cryptographic improvements aligned with NIST PQC standards
- Documentation, tutorials, deployment guides
- Integrations with SIEM/logging platforms

## What we will not merge

- Changes that reduce detection coverage to improve latency numbers
- Dependencies on external services that break offline deployability
- Features that require persistent state outside of the documented checkpoint system
- Anything that adds offensive capabilities

## Running specific layer tests

```bash
# All tests
pytest tests/ -v

# A specific layer
pytest tests/test_detector.py -v
pytest tests/test_crypto.py -v
```

## Questions

Open an issue or reach out at contacto@aegis-pq.com.
