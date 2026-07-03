# AEGIS Roadmap

This roadmap reflects the current direction of AEGIS. Priorities are set by production feedback and contributor interest. Open an issue to propose changes or pick up a task.

---

## v1.1 — Observability (Q3 2026)

Planned issues — all open for contributors:

- [ ] Grafana dashboard JSON for Prometheus `/metrics` ([#17](../../issues/17))
- [ ] X-Request-ID tracing header across all status server responses ([#18](../../issues/18)) — *assigned*
- [ ] Integration test suite for `/incidents` endpoint ([#16](../../issues/16))
- [ ] README translated to English for non-Spanish contributors ([#15](../../issues/15)) — *assigned*

---

## v1.2 — Intelligence Layer (Q4 2026)

Research and implementation — all open for contributors:

- [ ] Low-and-slow / LOtL (Living-off-the-Land) detection in C8 ([#23](../../issues/23))
- [ ] Forensic log integrity — append-only tamper detection in C7 ([#22](../../issues/22))
- [ ] Supply chain integrity verification for AEGIS dependencies ([#21](../../issues/21))
- [ ] Adversarial baseline poisoning detection in C8 Learning layer ([#20](../../issues/20))
- [ ] Low-and-slow baseline drift alerting in C3 Detector ([#19](../../issues/19))

---

## v1.3 — Integrations (Q4 2026)

- [ ] Elasticsearch native export for SIEM platforms
- [ ] Syslog-ng / rsyslog adapter
- [ ] MISP threat intelligence feed integration
- [ ] Webhook push for incident events

---

## v2.0 — Distributed (2027)

- [ ] Multi-node coordination
- [ ] ENLIL strategic integration (AI council for threat response)
- [ ] Kubernetes deployment manifest
- [ ] REST API for external SIEM push

---

## Architectural constraints (non-negotiable)

- **Single asyncio process** — no threading, no multiprocessing
- **Fire-and-forget on C3** — never block the proxy path on detection
- **C1 Twin immutability** — jump logs are forensic evidence, never modified
- **Status server stays local** — port 8081 must remain bound to 127.0.0.1
- **100% defensive** — no active reconnaissance, no counterattacks
