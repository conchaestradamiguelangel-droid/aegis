# Changelog

All notable changes to AEGIS are documented here.

---

## [Unreleased]

- ROADMAP added
- Issues #19-#23 opened with technical guidance for contributors

---

## [1.0.5] — 2026-07-03

### Added
- Technical contribution guides on open issues #19-#23 (baseline drift, poisoning detection, supply chain, forensic integrity, LOtL detection)
- PR submitted to [awesome-security](https://github.com/sbilly/awesome-security/pull/629) list

---

## [1.0.4] — 2026-06-27

### Added
- PULL_REQUEST_TEMPLATE.md with contributor checklist
- `good-first-issue` labels on #15-#18
- AEGIS metadata: English description, homepage, Discussions enabled

### Fixed
- LICENSE file was truncated (24 lines). Replaced with full GPL-3.0 text (674 lines) — commit `c341734`

---

## [1.0.3] — 2026-06-26

### Added
- AbuseIPDB enrichment in forensic reports: confidence score, country, ISP, TOR flag — commit `e96157a`
- 10 tests for AbuseIPDB integration (graceful no-op when key not provided)

---

## [1.0.2] — 2026-06-22

### Added
- `/version` endpoint: returns version, commit hash, layers, crypto algorithm — commit `3006a15`
- `aegis_prune.sh`: automated monthly incident archiving — commit `8921d56`
- `uptime_monitor.yml`: GitHub Actions external monitoring, opens issue on downtime — commit `af7dcab`

---

## [1.0.1] — 2026-06-16

### Added
- Security: `/status`, `/incidents`, `/stream`, `/metrics` endpoints protected with `X-Api-Key`
- Loopback whitelist in `mace_proxy.py` to prevent blocking 127.0.0.1 (watchdog false positive fix) — commit `b1d77b9`
- Docker Compose setup with healthcheck and volume for state persistence

### Fixed
- CI: 3 red-team tests used 127.0.0.1 (same as loopback whitelist) — fixed via `local_addr=127.0.0.2` — commit `500e71f`

---

## [1.0.0] — 2026-04-27

### Added
- Production launch at https://aegis-pq.com
- 9-layer autonomous defense stack (C0 through C8)
- ML-DSA-87 post-quantum signing (NIST FIPS 204)
- ML-KEM-1024 key encapsulation (NIST FIPS 203)
- SPHINCS+ hash-based signatures (NIST FIPS 205)
- 611 unit tests, 946/1000 red team scenarios passed
- MACE proxy: transparent protection of any HTTP service
- Digital twin with immutable signed jump log (C1)
- Adaptive Moving Target Defense — AMTD (C5)
- Collective learning across incidents (C8)
- Intellectual property registered: Expediente 8NT20260502456
