# Proposed scope for an external security audit

**Status: proposal.** No independent audit has been commissioned or performed.
`sentinel audit` is a self-assessment and does not replace this.

## 1. Objective

Obtain an independent opinion on whether Sentinel delivers what its
documentation claims and whether an attacker with user privileges can bypass it,
tamper with its persistent state or turn it into an attack vector.

Questions the audit should answer:

1. Can the signatures, allowlist and quarantine be tampered with by a process
   running with the privileges of the user executing the scanner?
2. Is container, OLE and VBA analysis resilient against hostile files (bombs,
   nesting, entropy, ReDoS and paths)?
3. Is the Ed25519 update chain and anti-rollback correct, or is there a path to
   install an older or unsigned database?
4. Do the Windows service and real-time monitor expand the attack surface
   beyond what is documented?
5. Are the claims in `README.md`, `THREAT_MODEL.md` and
   `KERNEL_FILTER_DESIGN.md` accurate, or are there controls that do not exist?

## 2. Scope inclusions

| Component | What is delivered | Emphasis |
| --- | --- | --- |
| `sentinel/engine/` | `signatures.py`, `scanner.py`, `heuristics.py`, `containers.py`, `ole.py`, `vba.py`, `yara.py` | Hostile parsing, anti-bomb limits, regex timeout, evasion |
| `sentinel/core/` | `allowlist.py`, `quarantine.py`, `logging.py`, `database.py`, `models.py` | HMAC, ACL, SQL injection, self-exclusion |
| `sentinel/` root | `crypto.py`, `updates.py`, `integrity.py`, `audit.py`, `realtime.py`, `service.py`, `cli.py`, `gui.py`, `feeds.py`, `notify.py` | Trust chain, rollback, tampering and service control |
| `packaging/` | `build.ps1`, `sentinel.spec` | Manifest, included signature, secrets in the bundle |
| `tests/` | Full suite and results | Coverage of security controls |
| Documentation | README, THREAT_MODEL, PERFORMANCE and the two handoffs | Correspondence with the code |

## 3. Out of scope

- Real malware: only EICAR, synthetic markers and public IOCs.
- Production infrastructure: there is no signature server, EV/OV CA, kernel
  filter or large-scale deployment to audit.
- Formal certification (ISO 27001, SOC 2, Common Criteria).
- Penetration testing of a corporate network or of the auditor's systems.
- Review of third-party dependencies: `pip-audit` and `bandit` have already been
  delivered, but the auditor may replicate them.

## 4. Expected methodology

1. **Documentation and code review** (1–2 days): compare `THREAT_MODEL.md`
   with the implementation, looking for claims without a corresponding control.
2. **Static testing** (0.5 days): reproduce `ruff`, `bandit`, `pip-audit` and
   search the Git history for secrets.
3. **Dynamic testing in an isolated VM** (2–3 days): synthetic corpus of nested
   containers, OLE/VBA, tampered PE, long paths, extremely high-ratio compressed
   files and aggressive regular expressions.
4. **User-privilege threat** (1–2 days): attempt to modify `quarantine.key`,
   `index.json`, `audit.jsonl`, `signatures.json`, the allowlist or terminate the
   monitor; check what is detected and what is not.
5. **Update chain** (1 day): valid signature, corrupt signature, rollback,
   `file://`, URL without a host, size limit and atomic replacement.
6. **Service and monitor** (1 day): installation, persisted home, `StopEvent`,
   reconnection and behavior when the user process is killed.

## 5. Audit deliverable

- Report with findings classified by severity, CWE and proof of concept.
- Clear map of **documented claim → actual control → evidence**.
- List of controls the auditor considers missing or insufficient.
- Prioritized recommendations, distinguishing code fixes from infrastructure
  changes (certificate, kernel, outsourcing).
- Retest letter after the fixes.

## 6. Evidence package to deliver

- Clean repository with an effective `.gitignore`.
- `python -m pytest -q` → 127 tests passing.
- `python -m ruff check .` → no warnings.
- `python -m bandit -r sentinel -x tests` → 0 warnings; `docs/bandit-results.json`.
- `pip-audit` over the extras → 0 vulnerabilities;
  `docs/pip-audit-results.json`.
- `sentinel selftest` and `sentinel audit` → 100/100.
- Recorded E2E run: EICAR → hash and content → quarantine → `verify` →
  `restore` with an identical SHA-256, and exit codes 0/1/2.
- `docs/EV_OV_HANDOFF.md` and `docs/KERNEL_FILTER_DESIGN.md` as explicit pending
  items, not implemented controls.
- `git ls-files` without private keys, `packaging/tools/`, `dist/` or `build/`.

## 7. Constraints and rules of engagement

- The auditor receives the code and a VM; they do not need access to this
  machine.
- The distribution Ed25519 private key is not provided; a disposable pair is
  generated for the update tests.
- Any finding requiring real malware is replaced with an equivalent synthetic
  marker.
- The audit must explicitly declare what it could not verify; a report that
  merely repeats `sentinel audit` does not meet the objective.

## 8. How the result is used

Confirmed findings are turned into issues with a proof of concept and a
regression test before being closed. `README.md` and `THREAT_MODEL.md` are
updated with the outcome, including the limitations the audit confirms.
**An external audit does not turn the prototype into a certified product
either**: the EV/OV certificate, the kernel filter and a commercial signature
database remain outstanding.
