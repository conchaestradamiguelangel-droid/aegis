\# Security Policy



AEGIS is an autonomous post-quantum cyber-defense system deployed in production.

This document outlines how to report security vulnerabilities and what to expect.



\## Supported Versions



| Version | Supported          |

| ------- | ------------------ |

| 0.1.x   | :white\_check\_mark: |



\## Reporting a Vulnerability



\*\*Do not open a public issue.\*\* AEGIS is a security project — publicly disclosing

a vulnerability before a fix is available could harm users relying on it for

defense.



Instead, report vulnerabilities privately:



\- \*\*Email:\*\* \[contacto@aegis-pq.com](mailto:contacto@aegis-pq.com)

\- \*\*GitHub:\*\* Use the \["Report a vulnerability"](https://github.com/conchaestradamiguelangel-droid/aegis/security/advisories/new) private advisory form



Please include:



\- A description of the vulnerability

\- Steps to reproduce

\- Affected component / layer (C0–C8)

\- Any suggested fix (optional)



\## What to Expect



| Timeline | Action |

| -------- | ------ |

| 48 hours | Acknowledgment of receipt |

| 5 business days | Initial assessment and severity classification |

| 30 days | Patch released (sooner for critical issues) |

| After patch | Public disclosure coordinated with reporter |



\### Severity Classifications



| Severity | Examples |

| -------- | -------- |

| \*\*Critical\*\* | Bypasses lockdown (C4), breaks forensic chain (C1), escapes bubble (C6) |

| \*\*High\*\* | Degrades detection coverage (C3), weakens crypto (C0) |

| \*\*Medium\*\* | Impacts honeypots (C2), AMTD rotation (C5) |

| \*\*Low\*\* | Documentation errors, non-security bugs |



We follow a 90-day disclosure timeline for non-critical issues. Critical fixes

are released as soon as they are verified.



\## Scope



The following are in scope:



\- All nine defense layers (C0–C8)

\- The MACE proxy integration

\- Cryptographic implementations (ML-KEM-1024, ML-DSA-87, SPHINCS+)

\- The status server (`:8081` bound to `127.0.0.1`)



Out of scope:



\- Denial-of-service via resource exhaustion (see E1 known limit at >250 RPS)

\- Attacks requiring physical access to the host

\- Vulnerabilities in third-party dependencies (report those upstream)



\## Architecture Constraints



When evaluating a vulnerability, note these non-negotiable constraints:



\- \*\*Fire-and-forget on C3\*\* — the detection path must never block the proxy

\- \*\*C1 immutability\*\* — jump logs are forensic evidence and immutable once written

\- \*\*Status server stays local\*\* — `:8081` is bound to `127.0.0.1` only

\- \*\*100% defensive\*\* — no active reconnaissance, no counterattacks

