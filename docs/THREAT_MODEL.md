# Sentinel threat model (prototype)

This document describes what Sentinel protects today, what it does not protect
and what remains outstanding. It is based on the repository code, not on a
certified product. **There is no kernel control and no executable trust
verification**: the scanner is a user process that reads files and applies
rules.

## Scope

- Python 3.10, Windows target; the pure modules also work on other OSes.
- On-demand analysis (`scan`), real-time monitoring (`monitor` / optional
  Windows service) and reversible quarantine.
- JSON signature database (`sentinel/data/signatures.json`, revision 3) with 11
  hashes (EICAR and ten public IOCs) and 2 content rules, one of them synthetic
  (`SENTINEL_TEST_MARKER`), with a `.sig` signature and a `.pub` public key.
- `sentinel/audit.py` self-assessment, integrated as the `sentinel audit`
  subcommand (ten checks).

Out of scope: protection against an attacker who is already an administrator,
execution prevention, sandboxing, cloud reputation and automated incident
response.

## Assets

| Asset | Location / form | Why it matters |
| --- | --- | --- |
| Signature database | `signatures.json`, revision, hashes and rules | Defines what is detected; tampering with it creates false negatives |
| Signature and trust anchor | `<base>.sig`, PEM public key | Trust chain for updates |
| Quarantine key | `<home>/quarantine.key` (HMAC-SHA256) | Detects tampering with the quarantine index |
| Quarantine | `<home>/quarantine/index.json`, `files/*.qtn` | Contains real malware; its integrity determines whether a restore is safe |
| Audit log | `<home>/audit.jsonl` | Evidence of scans, findings and actions |
| History | `<home>/history.db` (SQLite) | Past results and metrics |
| Exclusions | `allowlist.json` and `AllowList.for_self()` | Prevent false positives and self-detection; they can also hide malware |
| Scanner configuration | `--config-file` / `ScanConfig` | Anti-bomb limits; wrong values allow resource abuse |
| Installed code and dependencies | `sentinel` package, optional extras | Supply chain surface |
| Service and monitor | `RealtimeMonitor`, Windows service | Process with continuous access to the watched paths |

## Actors

- **Local user**: runs scans, can configure exclusions and restore files from
  quarantine if they have access to the home.
- **Malicious process with user privileges**: can write to the home, delete
  logs, modify the allowlist or terminate the monitor process.
- **Local administrator**: can install the service, change ACLs and stop
  protection; assuming otherwise would be self-deception.
- **File-delivery attacker** (downloads, email, USB): controls the analyzed
  content, not the machine.
- **Network / update-server attacker**: can serve a modified JSON or an older
  revision if the trust chain fails.
- **Operator/auditor**: consumes reports and decides whether the machine can
  operate.

## Attack surface

1. **Analyzed data**: PE (`engine/heuristics.py`), OLE2/CFB (`engine/ole.py`),
   ZIP/TAR/GZ/BZ2/XZ (`engine/containers.py`), OLE, content regular expressions,
   optional YARA rules and entropy calculation.
2. **Paths**: symlinks, junctions and reparse points; relative paths, long names
   and excluded directories.
3. **Configuration files**: signature JSON, imported feeds (`feeds.py`),
   allowlist, `ScanConfig` and `config.example.json`.
4. **Update channel**: HTTP/HTTPS and separate signature (`updates.py`).
5. **Persistent state**: quarantine index and key, `audit.jsonl`, `history.db`,
   JSON reports.
6. **Interface and service**: tkinter GUI, notifications and Windows service.

## Mitigated threats (controls that actually exist)

| Threat | Implemented control | Where | Honest limit |
| --- | --- | --- | --- |
| Malware known by hash/content/name | SHA-256 matching, regex over bytes and names | `engine/signatures.py` | Only covers what the database contains; no cloud detection |
| EICAR/synthetic IOC test file | Included hash and content rule | `data/signatures.json` | It is a functional test, not real malware coverage |
| Container obfuscation | Unpacking with entry, size, ratio and depth limits | `engine/containers.py`, `ScanConfig` | Does not analyze nested formats beyond `container_max_depth` |
| ReDoS in content rules | `regex` with a per-rule `timeout` and `RULE-TIMEOUT` reporting | `engine/signatures.py` | Without the `hardening` extra, `re` is used with no timeout |
| Loops and link-based evasion | `follow_symlinks=False` and rejection of reparse points in the native monitor | `config.py`, `realtime.py` | The decision depends on the available Windows APIs |
| Self-detection of the product | `AllowList.for_self([home, package root])` | `core/allowlist.py`, CLI | A badly edited allowlist can exempt malicious paths |
| Quarantine index modification | HMAC-SHA256 with a key outside the directory and `verify_all()` | `core/quarantine.py` | The key is stored in plaintext; an attacker with home access can read it and recompute the MAC |
| Restore of an altered file | `verify_entry()` compares the stored size and SHA-256 | `core/quarantine.py` | Does not encrypt content; `delete()`/`prune()` still work even if alteration is detected |
| Signature rollback | `check_rollback()` and increasing revision on updates | `engine/signatures.py`, `updates.py` | `SignatureDatabase.load()` by itself still does not require a signature; callers must use `trust.load_database()` |
| Unsigned or corrupt update | Mandatory Ed25519 signature with public key, optional hash, atomic replacement with `.bak`, and installed `.sig`/`.pub` | `updates.py`, `trust.py` | The public key is distributed manually; no rotation, build pinning or Transparency Log |
| Unsigned database at scan time | Fail-closed `trust.load_database()` in the CLI, GUI, monitor and service | `trust.py`, `cli.py`, `gui.py`, `service.py` | `--allow-unsigned-signatures` deliberately disables the check for local development |
| Parse errors in a hostile file | Per-file error capture and size limits | `engine/scanner.py`, `ScanConfig` | An error is recorded as `errors`, it does not kill the scan |
| Loss of visibility | JSONL events for scans, findings, quarantine and commands | `core/logging.py` | No signature, encryption, rotation or immutable retention |
| Insecure configuration detected late | `audit.py` validates the database, signature, quarantine, logs, exclusions, backend and limits | `sentinel/audit.py` | It is a point-in-time check, not a runtime control |

## Pending or unmitigated threats

- **Kernel filter**: does not exist. `RealtimeMonitor` uses
  `ReadDirectoryChangesW`, `watchdog` or polling from user space. An attacker
  with the same privilege can terminate the process, flood the watcher with
  events (excess paths are now dropped by `max_pending` backpressure, but
  detection can still be delayed) or act before the *grace period* expires.
  There is no execution prevention. The minifilter proposal is in
  `docs/KERNEL_FILTER_DESIGN.md`.
- **Authenticode**: PE signatures are not checked. A binary signed by a
  legitimate or stolen entity is analyzed like any other file; there are no
  trusted publisher lists or reputation.
- **Macro deobfuscation**: `engine/ole.py` extracts OLE streams and
  `engine/vba.py` decompresses the MS-OVBA project to apply `VBA-*` rules, but
  it does not interpret macros, deobfuscate arbitrary strategies and there is
  no sandbox. A document with obfuscated code may evade the rules.
- **Signature supply chain**: the private key is generated on disk
  (`crypto.generate_keypair`) with no encryption or HSM. The public key is
  delivered manually with `--public-key`, `SENTINEL_PUBLIC_KEY`,
  `<home>/signing.pub` or `<signatures>.pub`; there is no pinning, certificate
  chain, rotation or signing of the tool itself. The included database carries
  `signatures.json.sig` and `signatures.json.pub`, and all runtime entry points
  verify them before scanning. `SignatureDatabase.load()` is still a low-level
  helper that does not verify signatures, and
  `--allow-unsigned-signatures` bypasses the runtime check for development.
- **False positives**: the `SENTINEL_TEST_MARKER` rules and entropy heuristics
  are synthetic. Self-exclusion covers entire directories, so a badly placed
  exclusion creates a blind spot. There is no *sandbox*, reputation or vendor
  confirmation.
- **Windows permissions**: `os.stat` does not expose ACLs and usually shows
  mode `0666` even with a restrictive ACL. `security_fs.restrict_permissions()`
  now applies an `icacls` ACE granting only the current user on Windows (and
  `chmod` 0600/0700 on POSIX) to audit logs, quarantine, history, reports and
  generated keys. Verify the effective ACL with `icacls`; POSIX modes are
  covered by tests.
- **Attacker persistence**: `audit.jsonl`, `history.db` and reports are not
  signed or immutable; a user with home access can still delete or edit them.
  Retention is bounded (30 days) and the files are private to the current user,
  which reduces but does not eliminate this risk.
- **Quarantine**: files are renamed to UUIDs, not encrypted. ACLs restrict them
  to the current user, but a process running as that same user can still read
  them; encryption remains an open item.

## Using the self-assessment

The minimal workflow is:

```powershell
# 1. Generate keys (the private key must be kept off the scanned machine).
sentinel keys generate --private C:\secure\private.pem --public C:\secure\public.pem

# 2. Sign the installed database (the global --signatures option goes before the subcommand).
sentinel --signatures C:\ProgramData\Sentinel\signatures.json signatures sign `
  --key C:\secure\private.pem `
  --output C:\ProgramData\Sentinel\signatures.json.sig

# 3. Install the trust anchor (also used by every runtime scan).
Copy-Item C:\secure\public.pem C:\ProgramData\Sentinel\signing.pub
$env:SENTINEL_PUBLIC_KEY = 'C:\ProgramData\Sentinel\signing.pub'

# 4. Run the self-assessment: exit 0 if all pass, 2 on failures.
sentinel audit
```

`run_security_audit(home, signatures)` returns `SecurityAudit` with ten checks:

| Check | What it checks |
| --- | --- |
| `signatures.valid` | Database load/validation and integer revision > 0 |
| `signatures.signed` | Ed25519 `.sig` signature with the configured public key |
| `quarantine.integrity` | MAC and hashes of all entries; "no entries" if there is no index |
| `quarantine.key_permissions` | Read bits of `quarantine.key`; documented ACL limitation on Windows |
| `logging.enabled` | Writing and then reading an `audit.check` event in valid JSONL |
| `allowlist.self` | Non-empty self-exclusion applicable to the home |
| `realtime.backend` | Non-polling backend on Windows; `polling` on other OSes |
| `config.sane` | Anti-bomb limits > 0 and `container_max_depth >= 1` |
| `home.location` | Home outside `Windows` / `Program Files`; `ProgramData` allowed |
| `iocs.minimum` | At least one hash and one content rule |

Exceptions are converted to failures with the message in `detail`; the score is
the percentage of checks passed. **A 100/100 does not imply that the machine is
malware-free**: it only says that these controls are present and consistent.
The scope of an independent review is in `docs/EXTERNAL_AUDIT_SCOPE.md`.

## Static code analysis

In addition to the runtime self-assessment, the following were run:

* `python -m ruff check .`: no warnings.
* `python -m bandit -r sentinel -x tests`: **0 warnings** over 7472 lines
  (`docs/bandit-results.json`). Bandit flagged three points that were fixed
  rather than silenced: the SQL query with dynamic placeholders in
  `database.mark_quarantined()` was replaced with static SQL using bound
  parameters; an `assert` in the native backend was changed to an explicit
  check; and `updates._download()` now validates the `http`/`https` scheme before
  calling `urlopen`; the residual Bandit warning on that call was documented
  with `# nosec B310` because the scheme is already restricted. The update tests
  simulate HTTPS with a mocked `urlopen` instead of using `file://`.
* `git ls-files`: neither the private key (`packaging/keys/private.pem`), nor
  `packaging/tools/`, `dist/`, `build/` or the test home are versioned.
* Dependency analysis (SCA) with `pip-audit` over the extras declared in
  `pyproject.toml` (24 resolved packages): **0 vulnerabilities**
  (`docs/pip-audit-results.json`). The main environment ended up with 44
  packages and 0 vulnerabilities after removing the audit tool. `setuptools`
  was updated to 84.2.1. The SCA tool was run in an isolated venv with Python
  3.14: on Python 3.10 its transitive dependency `filelock` has no fixed version
  (the fix requires ≥3.11), so `pip-audit` was not added to the `dev` extras.

This does not replace an external review: `bandit` detects insecure patterns
and `pip-audit` compares versions against vulnerability databases; neither
finds logical flaws nor guarantees product security.

## Deployment checklist

- [ ] Install the home in `%ProgramData%\Sentinel` (or a user folder with a
      restrictive ACL), never under `C:\Windows` or `C:\Program Files`.
- [ ] Apply the ACL manually with `icacls` to the home, `quarantine.key` and
      `quarantine/`; verify who can read and write.
- [ ] Store the private key off the machine (or in a protected store) and
      distribute the public key through a verified channel.
- [ ] Sign `signatures.json` and check that `<base>.sig` exists with 64 bytes.
- [ ] Install `signatures.json.pub` and/or configure `SENTINEL_PUBLIC_KEY` before
      scanning or auditing; confirm a scan fails closed when the `.sig` is removed.
- [ ] Never pass `--allow-unsigned-signatures` on a production endpoint.
- [ ] Update only via `sentinel signatures update --public-key ...` over HTTPS
      and, if possible, with `--sha256`; review revisions and `.bak`.
- [ ] Run `sentinel audit` and require exit 0, a score of 100 and zero
      `failures`; investigate each `remediation` before accepting exceptions.
- [ ] Verify `sentinel quarantine verify` and the integrity of `audit.jsonl`.
- [ ] Review `allowlist.json` and document each exclusion with an owner and an
      expiration date.
- [ ] Confirm that a non-polling backend is available on Windows and that the
      service runs with the minimum necessary account.
- [ ] Test EICAR in an isolated environment, including restore from quarantine,
      and check that no unacceptable false positives are generated.
- [ ] Follow `docs/EV_OV_HANDOFF.md` to obtain the EV/OV certificate, sign the
      release and coordinate the AppLocker/WDAC rule; attach the evidence.
- [ ] Commission the external audit using `docs/EXTERNAL_AUDIT_SCOPE.md` and
      close findings with a regression test before accepting the report.
- [ ] Record the kernel filter, arbitrary macro deobfuscation and signature key
      rotation as outstanding items.
