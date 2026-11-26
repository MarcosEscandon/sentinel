# Security Hardening & Compliance — Sentinel

> **Status:** Baseline / gap assessment (living document)
> **Last reviewed:** 2026-11-26
> **Owner:** TBD
> **Frameworks:** SOC 2 Trust Services Criteria, ISO/IEC 27001:2022, ISO/IEC 27701, AR PSI (DA 641/2021)

This document maps Sentinel's controls to the four requested frameworks and
lists the work required to close the gaps. It is a control mapping and gap
assessment, **not** a certification, audit report, or attestation. The existing
[threat model](./docs/THREAT_MODEL.md), [external audit scope](./docs/EXTERNAL_AUDIT_SCOPE.md)
and [EV/OV handoff](./docs/EV_OV_HANDOFF.md) are separate, more detailed
documents; `EXTERNAL_AUDIT_SCOPE.md` explicitly excludes formal certification.

---

## 1. Scope and data inventory

**System:** Local Windows security scanner (Python 3.10+, CLI/GUI/Windows
service, optional YARA and real-time monitoring). It reads files, applies
signatures/heuristics/Office/VBA/container analysis, records findings in a
local SQLite history, writes a JSONL audit log and optional JSON reports, and
can move detections to a local quarantine. Network activity is limited to IOC
feed imports and signed signature updates; there is no account system, server
component or telemetry upload.

```
Local user / service ──> Sentinel process
                          ├──reads──> scanned files + signature database
                          ├──reads──> signed updates / IOC feeds (HTTPS)
                          └──writes──> audit.jsonl, history.db, reports.json,
                                       quarantine/, signing keys (manual)
```

| Data | Classification | Where |
|---|---|---|
| Scanned paths, filenames, hashes | System metadata (can identify individuals) | Audit log, history DB, reports |
| Detection details and severities | Security metadata | Audit log, history DB, reports, console/GUI |
| Quarantined files | **Live malware samples** | `<home>/quarantine/files/*.qtn` |
| Quarantine HMAC key / Ed25519 private keys | Secrets | `<home>/quarantine.key`, user-supplied paths |
| Signature database + detached Ed25519 signature | Integrity-controlled input | `<home>` / `sentinel/data/` |
| Feed configuration, service config | Low sensitivity, but reveals monitored paths | `<home>/service.json`, feed cache |

**Data subjects / legal:** the local user and anyone whose files are scanned on
a shared machine. Under Argentine Ley 25.326, filenames and paths can be
personal data; obtain authorization before scanning devices you do not own and
redact reports before sharing. No PII inventory, lawful-basis register or ARC
registration assessment exists yet (SN-12).

---

## 2. Framework applicability

| Framework | Applies? | How it is used here |
|---|---|---|
| **SOC 2 (TSC)** | Only if Sentinel is delivered as part of a service requiring attestation. | The code contributes CC6 (access), CC7 (operations), CC8 (change) and PI1 (processing integrity); most controls are inherited from the operator. |
| **ISO/IEC 27001:2022** | Recommended reference for an ISMS. | A.5.24–A.5.28 (incident), A.8.8 (vulnerabilities), A.8.12 (data leakage), A.8.13/A.8.15–A.8.16 (backup/logging), A.8.20–A.8.21 (network), A.8.26–A.8.28 (application/security testing), A.8.32 (change). |
| **ISO/IEC 27701** | Applies where paths/hashes can identify people. | Minimize, restrict and retain log/report data; define privacy notice and data-subject handling (SN-12). |
| **Argentina — DA 641/2021 + PSI Modelo (DNC 1/2022)** | **Not mandatory** for this private tool. | Argentine public-sector baseline: DA 641/2021, Modelo Referencial PSI (DNC 1/2022), Ley 25.326, Ley 26.388 (cybercrime), Ley 25.506 (digital signatures) and Res. 44/2023 (national cybersecurity strategy). Used as a hygiene reference. |

> **Note on SISP:** SISP/PPSI 2.0 is Brazil's federal IT-resource framework and
> does not apply to an organization based in Argentina. The Argentine baseline
> above is used instead. If "SISP" referred to another local framework, identify
> it so this mapping can be updated.

---

## 3. Controls already implemented (evidence)

| Control | Evidence |
|---|---|
| Fail-closed signature verification | `sentinel/trust.py` requires a valid signature by default; unsigned or modified databases are rejected. CLI/GUI/service/monitor all call it; CI asserts exit code 2 for an unsigned database. |
| Signed updates + anti-rollback | `sentinel/updates.py` enforces scheme/host allowlist, 10 MiB/4 KiB size limits, public key + detached signature, revision rollback checks and atomic install with `.bak`. |
| Tamper-evident quarantine | `sentinel/core/quarantine.py` stores SHA-256 + size per entry and an HMAC-SHA256 of the canonical index with the key outside the store; `restore()` rejects modified entries. |
| Hostile-input limits | Container depth/ratio/entry limits, OLE and VBA decompression caps, regex/YARA timeouts, symlink/reparse rejection and per-file error isolation. |
| Allowlist / self-exclusion | `sentinel/core/allowlist.py` plus automatic exclusion of Sentinel's own files, report registry and JSON reports. |
| Safe persistence | Static bound SQL in `sentinel/core/database.py`; atomic writes for index, feed database and signature updates. |
| Self-assessment | `sentinel audit` runs 10 checks including logging, signature length, IOC count and allowlist validation. |
| Static analysis | `ruff`, `bandit` and `pip-audit` run in CI; latest local results are clean (one documented `# nosec B310` for the checked URL scheme). |
| Hash-locked dependencies | `requirements.lock` pins every declared extra with SHA-256 hashes; CI installs with `--require-hashes` and audits that same lockfile. |
| Output ACLs / retention | `sentinel/security_fs.py` restricts audit logs, quarantine store/index/key/samples, history DB, reports, generated keys, signatures and manifests; audit and registered report files older than 30 days are removed on startup; `Quarantine.prune()` and `ScanDatabase.prune()` provide explicit 30-day retention. `.gitignore` excludes generated state so it cannot be committed by accident. |
| Disclosure process | `SECURITY.md` defines private reporting, scope, sample handling and coordinated disclosure. |

---

## 4. Control mapping

| Control area | SOC 2 | ISO 27001 | ISO 27701 | AR PSI / law | Status |
|---|---|---|---|---|---|
| Access to local outputs | CC6.1, CC6.6, CC6.8 | A.5.15, A.8.2, A.8.18 | PII access restriction | DA 641/2021 access control; Ley 25.326 art. 10 | Met (ACL helper + tests, SN-04) |
| Malware/sample handling | CC7.1, PI1.1 | A.8.7, A.8.26 | Minimization | PSI incident/malware hygiene | Partial (quarantine + HMAC; no sandbox, SN-09) |
| Integrity / change control | CC8.1, PI1.2 | A.8.28, A.8.32, A.8.9 | Processing integrity | Ley 25.506 (signatures) | Partial (signed DB/manifest; unsigned release, SN-01) |
| Logging and monitoring | CC7.2–CC7.4 | A.8.15, A.8.16 | Privacy notice + retention | PSI logging; Ley 25.326 | Partial (structured log + ACL/retention; no immutability, SN-03) |
| Vulnerability management | CC7.1, CC9.2 | A.8.8, A.8.29 | — | PSI vulnerability management | Met (ruff/bandit/pip-audit + locked deps, SN-05) |
| Backup / recovery | A1.2, A1.3 | A.8.13, A.8.14 | PII availability | PSI continuity | Partial (`.bak` on update/manifest; no disaster recovery plan) |
| Incident response | CC7.3–CC7.5 | A.5.24–A.5.28 | Breach notification | Ley 25.326 art. 23-25; Res. 44/2023 | Partial (`SECURITY.md` disclosure; no internal IR runbook) |
| Data retention / deletion | P4, P5 | A.5.34, A.8.10 | Retention & deletion | Ley 25.326 art. 9, 27 | Partial (30-day audit/report/quarantine/history helpers; no registry of erasure requests) |
| Third parties / supply chain | CC9.2 | A.5.19, A.8.30 | Processor controls | PSI supply chain | Partial (feed terms review pending, SN-07; unsigned signtool download, SN-11) |

---

## 5. Gap register

| ID | Priority | Gap | Target |
|---|---|---|---|
| SN-01 | P0 | Code signing: procedure and thumbprint/subject selection exist in `packaging/build.ps1` and `docs/EV_OV_HANDOFF.md`, but no EV/OV certificate is provisioned. | Signed release + published SHA-256 checksums. |
| SN-02 | P0 | Signing private key is a disk file with no HSM, rotation, pinning or transparency log. | HSM/cloud key and documented rotation. |
| SN-03 | P0 | Audit log, history DB and reports are private and time-bounded but not signed or immutable. | Tamper-evident log, or documented compensating control. |
| SN-04 | P1 | Output ACLs and 30-day retention across generated state. | **Done** — `security_fs.py`, wired into logging, quarantine, DB, reports, keys, signatures and manifests. |
| SN-05 | P1 | Unpinned dependencies and generated audit requirements in CI. | **Done** — `requirements.lock` with hashes, `--require-hashes` install, `pip-audit` on the lock. |
| SN-06 | P1 | No vulnerability disclosure policy. | **Done** — `SECURITY.md`. |
| SN-07 | P1 | IOC feed terms/licenses and redistribution rights not reviewed. | Human/legal sign-off before redistributing feeds. |
| SN-08 | P1 | Real-time pending queue is unbounded under sustained events. | Bounded buffer or backpressure. |
| SN-09 | P2 | No kernel filter, sandbox or execution prevention for macros. | Track `docs/KERNEL_FILTER_DESIGN.md`; treat as a design limitation. |
| SN-10 | P2 | `EXTERNAL_AUDIT_SCOPE.md` cites stale evidence counts (127 tests, 6026 LOC). | Refresh evidence before any external audit. |
| SN-11 | P2 | `packaging/get-signtool.ps1` downloads signtool without verifying a hash/signature. | Pin and verify the downloaded package. |
| SN-12 | P2 | No PII inventory, privacy notice, data-subject process or ARC registration assessment. | Privacy review under Ley 25.326 before production deployment. |

---

## 6. Verification

```powershell
# Install exactly the locked dependency set
python -m pip install --require-hashes -r requirements.lock
python -m pip install -e . --no-deps

# Checks
python -m ruff check .
python -m bandit -q -r sentinel -x tests
python -m pytest -q
sentinel selftest
sentinel audit
python -m pip_audit -r requirements.lock

# Effective ACLs on Windows (must not grant other users)
icacls "$env:USERPROFILE\.sentinel"

# Confirm generated state is not tracked by git
git status --short
```

Expected: all checks pass, no generated `audit.jsonl`, `history.db`,
`reports.json`, `quarantine/` or signing key appears as a tracked file, and a
release is never described as signed without a certificate and verified
signature.

---

## 7. Remediation log

| Date | Change | Evidence |
|---|---|---|
| 2026-11-26 | Hash-locked all declared extras; CI installs with `--require-hashes` and audits the lockfile | `requirements.lock`, `.github/workflows/ci.yml` |
| 2026-11-26 | Added `SECURITY.md` with disclosure, sample handling and scope | `SECURITY.md` |
| 2026-11-26 | Added user-only ACLs and 30-day retention to audit logs, quarantine, history, reports, keys and manifests | `sentinel/security_fs.py`, `core/logging.py`, `core/quarantine.py`, `core/database.py`, `cli.py`, `service.py`, `integrity.py` |
| 2026-11-26 | Fixed YARA 4.5 `StringMatch` compatibility exposed by the locked dependency set | `sentinel/engine/yara.py`, `tests/test_yara_compat.py` |
| 2026-11-26 | Added framework mapping and gap register; updated threat model ACL note | `HARDENING.md`, `docs/THREAT_MODEL.md` |

---

## 8. Change log

| Date | Change | Author |
|---|---|---|
| 2026-11-26 | Initial hardening baseline and framework mapping for Sentinel | — |
