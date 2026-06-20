# Security Policy

AEGIS is an autonomous post-quantum cyber-defense system deployed in production.
This document outlines how to report security vulnerabilities and what to expect.

## Supported Versions

Only the latest `main` branch is actively maintained. Pinned or forked versions
are not supported.

| Version           | Supported          |
| ----------------- | ------------------ |
| `main` (latest)   | :white_check_mark: |
| Pinned / forked   | :x:                |

## Reporting a Vulnerability

**Do not open a public issue.** AEGIS processes real network traffic and uses
post-quantum cryptography — publicly disclosing a vulnerability before a fix
could harm users relying on it for defense.

Use GitHub's private security advisory system:

1. Go to **Security → Advisories → [Report a vulnerability](https://github.com/conchaestradamiguelangel-droid/aegis/security/advisories/new)**
2. Describe the vulnerability, affected layer (C0–C8), steps to reproduce, and
   any suggested fix.

## What to Expect

| Timeline     | Action                                              |
| ------------ | --------------------------------------------------- |
| 72 hours     | Acknowledgment of receipt and initial triage        |
| 14 days      | Fix or workaround for confirmed vulnerabilities     |
| After patch  | Coordinated public disclosure with reporter         |

## Priority Classification

Reports touching these areas are **highest priority**:

| Priority     | Area                                                 |
| ------------ | ---------------------------------------------------- |
| **Critical** | Post-quantum cryptography (ML-DSA-87, ML-KEM-1024)   |
| **Critical** | MACE proxy blocklist / bypass                        |
| **High**     | AI decision pipeline (ENLIL integration)              |
| **High**     | Lockdown escape (C4) or forensic chain break (C1)    |
| **Medium**   | Detection degradation (C3), honeypot bypass (C2)     |
| **Low**      | Documentation errors, non-security bugs              |

## Scope

In scope:
- All nine defense layers (C0–C8)
- The MACE proxy integration
- Cryptographic implementations (ML-KEM-1024, ML-DSA-87, SPHINCS+)
- The status server (`:8081` bound to `127.0.0.1`)

Out of scope:
- Denial-of-service via resource exhaustion (see E1 known limit at >250 RPS)
- Attacks requiring physical access to the host
- Vulnerabilities in third-party dependencies (report those upstream)

## Architecture Constraints

When evaluating a vulnerability, note these non-negotiable constraints:

- **Fire-and-forget on C3** — the detection path must never block the proxy
- **C1 immutability** — jump logs are forensic evidence and immutable once written
- **Status server stays local** — `:8081` is bound to `127.0.0.1` only
- **100% defensive** — no active reconnaissance, no counterattacks