# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

Security fixes are applied to the latest released version.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

- **Contact:** `security@example.com`
  > Replace this address with the maintainer's real mailbox before publishing
  > the repository or distributing binaries.
- Include the affected version, operating system, Python version, reproduction
  steps, impact, and any proof of concept.
- **Never attach quarantined samples or raw audit logs to a public report.**
  Redact local paths, hostnames, usernames and hashes first.
- Best-effort response targets: acknowledgement within **3 business days** and a
  remediation plan within **10 business days**. This is a community-project
  commitment, not a contractual SLA.

## Scope

**In scope:** the Python scanner engine (signatures, heuristics, container and
Office/VBA unpacking), CLI/GUI/service entry points, quarantine handling, audit
logging, update/feed verification, integrity tooling, packaging scripts and the
published release artifacts.

**Out of scope:** the operating system and kernel, Python itself, third-party
dependencies, the systems being scanned, and social engineering. Reports about
a malicious file that Sentinel failed to detect are welcome, but the sample
must be shared privately and handled as live malware.

## Sensitive data and sample handling

- Quarantined files are **live malware samples**. Do not execute or open them;
  restore only after verifying the entry through `sentinel quarantine verify`.
  The quarantine index is MAC-protected with a key stored outside the
  quarantine directory, and `restore()` rejects tampered entries.
- `audit.jsonl` can contain scanned paths, detection details and hashes. Its
  directory and file are restricted to the current OS user, and audit files
  older than 30 days are removed on startup.
- IOC feeds and signature packages may contain third-party data; respect the
  providers' terms and licenses when redistributing them.
- Sentinel is a local scanner: it does not require an account and does not send
  scan results to a server. Feed downloads and signed updates are the only
  expected network activity.

## Security practices

- Runtime/tooling dependencies are hash-locked in `requirements.lock`, installed
  with `--require-hashes` and audited with `pip-audit` in CI.
- Signature databases and updates are verified **fail-closed**: an unsigned or
  untrusted database is rejected instead of silently accepted.
- Audit outputs are restricted to the current user and retained for at most
  30 days by default; quarantine entries can be pruned with the CLI.
- Release binaries should be signed with an EV/OV code-signing certificate and
  published with SHA-256 checksums. The procedure is in
  [docs/EV_OV_HANDOFF.md](./docs/EV_OV_HANDOFF.md); unsigned builds must be
  labelled as such.
- Run Sentinel with the least privilege that still allows access to the paths
  being scanned. Avoid running the GUI or service as Administrator unless a
  specific monitoring task requires it.

## Coordinated disclosure

We follow coordinated disclosure: a fix is prepared before details are made
public, normally within 90 days. Reporters are credited unless they request
otherwise.

## Disclaimer

This policy and the linked hardening documents are a **gap assessment and
reference baseline**. They do not constitute a certification, attestation, or
legal opinion.
