# Contributing to AEGIS

AEGIS is a post-quantum cyber-defense system in active production. Contributions are welcome and held to a high standard — every change must preserve the autonomous, traceable, and defensive nature of the system.

## Before you start

Read the architecture overview in the README, especially the 9-layer stack. Understand what the system does before proposing changes to it.

## How to contribute

1. **Fork** the repository and create a branch: `git checkout -b fix/your-description`
2. **Run tests** before and after your change:
   ```bash
   pip install -r requirements.txt -r requirements-test.txt
   pytest tests/test_suite.py -v
   ```
3. **Add a test** for any new behavior. If you touch a layer, add a test case in the corresponding `tests/test_<layer>.py`.
4. **Open a PR** — describe what you changed, why, and what the test result was.

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

- Performance improvements in the detection pipeline (without hiding E1 degradation)
- New detection patterns in `layers/detector.py`
- Cryptographic improvements aligned with NIST PQC standards
- Documentation, tutorials, deployment guides
- Integrations with SIEM/logging platforms

## What we will not merge

- Changes that reduce detection coverage to improve latency numbers
- Dependencies on external services that break offline deployability
- Features that require persistent state outside of the documented checkpoint system

## Running specific layer tests

```bash
# All core tests
pytest tests/test_suite.py -v

# Integration test (slower)
pytest tests/test_suite.py -v -m slow

# A specific layer directly
python3 tests/test_detector.py
python3 tests/test_crypto.py
```

## Questions

Open an issue or reach out at contacto@aegis-pq.com.
