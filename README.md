# Sentinel

Modular malware scanning engine for Windows, written in Python. It covers the
core of a Malwarebytes-like product: **SHA-256 signatures**, name and content
rules, **heuristics** (entropy, double extension, PE imports), **VBA macro
analysis** (MS-OVBA), **optional YARA**, **reversible quarantine**,
**SQLite history**, **JSON reports**, **real-time protection**, **Windows
service**, **GUI**, **security auditing** and **manifest anti-tamper**.

> This is not a replacement for a commercial antivirus. The included database
> contains a **real, harmless IOC** (EICAR), ten real hashes from public
> campaigns (Dark Caracal, Sofacy and Tick, curated from `Neo23x0/signature-base`)
> and synthetic markers to test the full workflow without handling malware.

## Try it with a real IOC

EICAR is the industry-standard test file: every antivirus must detect it and it
is completely harmless.

```powershell
sentinel scan sentinel\data\iocs\eicar.com
```

`EICAR-HASH` and `EICAR-CONTENT` should appear. The same indicator is in
`sentinel/data/iocs/eicar.csv`, ready for the feed converter.
`sentinel/data/iocs/curated.csv` contains the real hashes with their source
campaign; both can be imported with `sentinel feeds import`.

## Installation

```powershell
cd C:\Users\marco\Mine\sentinel
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev,hardening,realtime]"  # tests, regex, watchdog
pip install -e ".[signing]"                 # optional: preferred Ed25519 backend
pip install -e ".[yara]"                    # optional: YARA rules
pip install -e ".[service]"                 # optional: Windows service
```

Ed25519 verification works with the standard library alone; the optional
`signing` extra (`cryptography`) is the preferred, faster backend. `hardening`
adds a timeout to content rules. Without `regex`, content rules work but have
no timeout. Without `watchdog`, monitoring uses the native Windows backend
(`ReadDirectoryChangesW` via `ctypes`) and, if that is also unavailable,
dependency-free polling.

## Quick start

```powershell
# Verify that the detectors work
sentinel selftest

# Scan a folder (human-readable report + saved as JSON)
sentinel scan C:\Users\marco\Downloads --json report.json

# Parallel scan without unpacking containers
sentinel scan D:\data --jobs 8 --no-containers

# Only suspicious files go to quarantine, without prompting
sentinel scan C:\Users\marco\Downloads --quarantine-found --yes

# Additional allowlist (the product's own files are excluded automatically)
sentinel scan C:\Users\marco\Downloads --allowlist allowlist.json

# Manage quarantine (verify detects tampering)
sentinel quarantine list
sentinel quarantine verify
sentinel quarantine restore <id>
sentinel quarantine delete <id>

# History and signatures
sentinel history --limit 10
sentinel signatures info
sentinel signatures validate

# Security self-assessment and supply chain
sentinel audit                          # 10 checks; 0 OK, 2 on failures
sentinel integrity build . --output build/manifest.json
sentinel integrity verify . --manifest build/manifest.json --public-key public.pem

# Macro analysis (in addition to OFFICE-MACRO, VBA-* rules on the code)
sentinel scan C:\Downloads\report.docm
```

### Signed updates

```powershell
# 1. Generate keys once (the private key is NOT distributed)
sentinel keys generate --private C:\secure\private.pem --public public.pem

# 2. Sign the published signature package
sentinel signatures --signatures signatures.json sign --key C:\secure\private.pem --output signatures.json.sig

# 3. On each client: download, verify the signature, validate the schema and reject rollback
sentinel signatures update --url https://example.local/signatures.json --public-key public.pem
```

The `--sha256` option is additional; the Ed25519 signature and public key are
mandatory. The client rejects any revision lower than or equal to the installed
one. The JSON must include `"revision": <integer>`. An update installs the JSON
together with its `.sig` and the trusted `.pub`, so subsequent scans keep
verifying it.

Every production entry point (CLI `scan`, GUI, monitor and Windows service) now
loads the database through `sentinel.trust.load_database()` and **fails closed**
if the signature is missing or invalid. The trusted key is resolved in this
order: explicit `--public-key`, `SENTINEL_PUBLIC_KEY`, `<home>/signing.pub`,
`<signatures>.pub`. `--allow-unsigned-signatures` is an unsafe development-only
escape hatch; it must never be used in production.

### Containers, feeds and auditing

```powershell
# ZIP/TAR/GZ/BZ2/XZ are unpacked with anti-bomb limits (3 levels by default)
# Office/OOXML (docx, xlsx, ...) and OLE2 (doc, xls, ppt, msi, msg) are also analyzed
sentinel scan C:\Downloads

# An embedded VBA project is reported as OFFICE-MACRO (MEDIUM); the unpacked code
# is analyzed with VBA-* rules (AutoOpen, Shell, PowerShell, etc.)
sentinel scan C:\Downloads\report.docm

# Import IOCs from a CSV, JSON, MISP or hash list
sentinel --signatures C:\ProgramData\sentinel\signatures.json feeds import C:\feeds\vendor.csv --source vendor
sentinel --signatures C:\ProgramData\sentinel\signatures.json feeds import C:\feeds\misp.json --format misp --dry-run

# JSONL audit log (by default <home>/audit.jsonl)
sentinel --log-file C:\logs\sentinel.jsonl scan C:\Downloads
sentinel --no-log scan C:\Downloads
```

The importer increments `revision` and creates a `.bak` copy of the previous
database. The Ed25519 signature must be regenerated after importing IOCs.

### Real-time protection and graphical interface

```powershell
# Foreground monitor: prefers native (Windows), then watchdog, then polling
sentinel monitor C:\Downloads --poll-interval 2 --grace-period 0.5

# Desktop notifications: auto (toast if winotify is available, otherwise a native dialog), none for service
sentinel monitor C:\Downloads --notify auto

# Graphical interface (tkinter, included with Python for Windows)
sentinel gui
# or: sentinel-gui
```

The `realtime.detection`, `realtime.quarantine` and `realtime.error` events are
written to the JSONL audit log. A finding's action can be `quarantined`,
`detected` or `error` (`clean` if there are no findings). The monitor accepts
`--backend native|watchdog|polling` to force the monitoring mechanism (if not
specified, it is selected automatically). The native backend does not FOLLOW
reparse points: it watches directories with `ReadDirectoryChangesW` and, if
given specific files, watches them by polling. Notifications run in a daemon
thread so that they do not block the scan; `--notify none` is the recommended
option when running as a service. `--max-pending N` caps the number of paths
waiting for analysis (default 4096): once the cap is reached, new events are
dropped and a `realtime.error` event is written instead of growing memory
without limit. The Windows service accepts the same value as `max_pending` in
`service.json`.

To install the Windows service (requires administrator):

```powershell
sentinel --home C:\ProgramData\sentinel service install --paths C:\Downloads --startup auto
sentinel service status
sentinel service start
sentinel service stop
sentinel service remove
```

The service configuration is saved in `<home>/service.json` and the chosen home
is persisted in `%ProgramData%\sentinel\service_home.txt` so that `LocalSystem`
can read it. The monitored directory **must not be inside** the home, because
self-exclusion would ignore it. To debug without installing anything:
`sentinel service run`.

Exit codes: `0` clean, `1` findings present, `2` operational error. Useful for
integration into scripts or scheduled tasks. The global options (`--home`,
`--signatures`, `--config-file`, `--log-file`, `--no-log`) are accepted before or
after the subcommand.

To adjust thresholds and exclusions, copy `config.example.json` and pass it with
`--config-file`.

## Structure

```
sentinel/
├── sentinel/
│   ├── cli.py               # subcommands and presentation
│   ├── config.py            # ScanConfig
│   ├── crypto.py            # Ed25519 keys and verification (backend selector)
│   ├── _ed25519.py          # stdlib RFC 8032 fallback with PEM support
│   ├── trust.py             # fail-closed database loading and key resolution
│   ├── feeds.py             # IOC converter (CSV/JSON/MISP/hashes)
│   ├── realtime.py          # native/watchdog/polling monitor
│   ├── notify.py            # toast/native dialog notifications
│   ├── audit.py             # security self-assessment (10 checks)
│   ├── integrity.py         # SHA-256 manifests and package signing
│   ├── service.py           # Windows service
│   ├── gui.py               # tkinter interface
│   ├── updates.py           # verified, atomic signature updates
│   ├── data/
│   │   ├── signatures.json
│   │   ├── signatures.json.sig   # Ed25519 signature of the database
│   │   ├── signatures.json.pub   # distribution public key
│   │   ├── yara/sample.yar
│   │   └── iocs/                 # eicar.{com,csv} and curated.csv
│   ├── core/
│   │   ├── allowlist.py     # exclusions and self-exclusion
│   │   ├── logging.py       # JSONL audit logging
│   │   ├── models.py        # Finding, ScanResult, RuleHit, Severity
│   │   ├── quarantine.py    # quarantine with hash + MAC
│   │   └── database.py      # SQLite history
│   └── engine/
│       ├── signatures.py    # signature validation and matching
│       ├── heuristics.py    # entropy, double extension, PE parser
│       ├── containers.py    # ZIP/TAR/GZ/BZ2/XZ/OOXML with limits
│       ├── ole.py           # CFB/OLE2 parser for doc/xls/ppt/msi/msg
│       ├── vba.py           # MS-OVBA decompression and VBA-* rules
│       ├── scanner.py       # traversal, hashing, parallelism and orchestration
│       └── yara.py          # optional yara-python integration
├── packaging/               # PyInstaller spec, build.ps1 and get-signtool.ps1
├── tools/benchmark.py       # files/s and MB/s benchmarks with --jobs
├── docs/                    # THREAT_MODEL.md, PERFORMANCE.md and results
└── tests/
```

## Extending the signatures

`signatures.json` supports three blocks:

```json
{
  "schema": 1,
  "version": "2026-11-23",
  "revision": 3,
  "hashes": {
    "<sha256>": {"id": "IOC-0001", "severity": "high", "description": "..."}
  },
  "filenames": [
    {"id": "FN-0001", "pattern": "\\.js\\.vbs$", "severity": "medium", "description": "..."}
  ],
  "content": [
    {"id": "CT-0001", "pattern": "marker", "severity": "low", "description": "...", "max_size": 1048576}
  ]
}
```

The `filenames` and `content` patterns are regular expressions over bytes and
are compiled with `IGNORECASE`. `max_size` avoids evaluating large files. With
`hardening` installed, each rule has a 100 ms limit; a rule that exceeds it is
skipped and reported as `RULE-TIMEOUT`.

## Extension points

* **New detectors**: add a module in `engine/` that returns `RuleHit` and call
  it from `Scanner._detect`.
* **Other IOC sources**: add a parser in `feeds.py` and register it in
  `PARSERS`. Copy `allowlist.example.json` to exclude known-good binaries.
* **Graphical interface**: `sentinel gui` uses `SentinelGUI`; it can also be
  integrated from code with `SentinelGUI(headless=True)` to use `scan_path()`,
  `format_summary()` and `refresh_quarantine()` without a window.
* **Real-time protection**: `RealtimeMonitor` exposes `process_path()` and
  `on_finding`; the Windows service reuses that same implementation. Before
  deploying it, test the exclusions thoroughly in an isolated environment.

## Security and limits

* Heuristics **prioritize, they do not convict**: a `HEUR-*` finding must be
  reviewed before deleting anything. Exact signatures are the only
  deterministic signal.
* `--quarantine-found` moves files; the original path is recorded and can be
  restored with `sentinel quarantine restore <id>`.
* Reparse points/junctions are not analyzed by default to avoid loops.
* Maximum size per file: 128 MiB (configurable with `--max-size`).
* Quarantine stores the real SHA-256 and an HMAC of the index with a key outside
  the quarantine directory; `restore` rejects tampered entries.
* For production: use signed updates with `--public-key`, also sign the
  imported IOC package, run as an unprivileged user and review the allowlist
  before deployment.
* The executable's Authenticode signature (see `packaging/README.md`) **does
  not** replace Ed25519 verification of the signatures.
* The included database contains EICAR and ten real hashes from public sources;
  it is not a commercial signature database. Extend it with trusted sources and
  sign every revision.
* Office/MSI analysis extracts streams, detects VBA projects and decompresses
  MS-OVBA code to apply `VBA-*` rules. It does not evaluate code or deobfuscate
  arbitrary strategies: findings are signals for review.
* A kernel-level file system filter is still out of scope: the current monitor
  runs in user mode and may lose events if the 64 KiB buffer overflows
  (`realtime.error` is logged).

## Auditing, anti-tamper and performance

`sentinel audit` runs 10 real checks (database signature and rollback,
quarantine integrity, logging, allowlist, real-time backend, configuration
limits, `home` location and minimum IOCs). It returns `0` if all pass and `2` if
there are failures; with the included, signed database and its public key, the
result is **100/100**. Details and remediations are in `docs/THREAT_MODEL.md`;
the scope for an independent review is in `docs/EXTERNAL_AUDIT_SCOPE.md`.

`sentinel integrity build/verify` generates and checks a SHA-256 manifest.
`verify` distinguishes `missing`, `modified` and `added`, and with `--public-key`
it also validates the manifest's Ed25519 signature. Static analysis with
`python -m bandit -r sentinel -x tests` finished with **0 warnings** (6615 lines
analyzed; details in `docs/bandit-results.json`) and dependency analysis with
`pip-audit -r requirements.lock` found **0 vulnerabilities** in 27 locked packages
(`docs/pip-audit-results.json`). These figures are regenerated whenever the
locked dependency set changes. The PyInstaller build generates and packages
`manifest.json` (and its signature if `SENTINEL_PRIVATE_KEY` is set) inside
`sentinel/data`. In an onedir build (`-OneFile:$false`) it can be verified with:

```powershell
sentinel integrity verify _internal\sentinel\data --manifest _internal\sentinel\data\manifest.json --public-key _internal\sentinel\data\signatures.json.pub
```

In the default onefile build there is no `_internal`: data is extracted to a
temporary `_MEIxxxxx` folder while the process is alive. To verify the onefile
bundle, use the `sentinel/data` copy from the source tree.

Performance measured on this machine (Python 3.10.11, Windows 10, 2000 files,
63 MiB, `python tools/benchmark.py --files 2000`):

| `--jobs` | Time (s) | MB/s | Files/s |
| -------: | ---------: | ---: | ---------: |
|        1 |      2,386 | 26,4 |        838 |
|        2 |      2,243 | 28,1 |        892 |
|        4 |      2,204 | 28,6 |        908 |
|        8 |      2,215 | 28,5 |        903 |

The measured optimum is **4 threads**; at 8 threads the GIL cancels out the
gain. The 1948 findings are heuristic false positives on random data, not
malware; parallelism does not change the result. Full data in
`docs/PERFORMANCE.md` and `docs/benchmark-results.json`.

## Production status

This is a **functional prototype, packaged and validated locally**, not a
complete production-ready product. The following are out of scope or require
external infrastructure:

* Kernel-level file system filter: the monitor runs in user mode and may lose
  events if the 64 KiB buffer overflows. The proposed architecture is in
  `docs/KERNEL_FILTER_DESIGN.md`; it includes no driver code.
* Independent external audit: `sentinel audit` is a self-assessment. The
  proposed scope is in `docs/EXTERNAL_AUDIT_SCOPE.md`.
* EV/OV Authenticode certificate: only a self-signed certificate was used here
  to validate the process. Temporarily trusting it for the current user alone
  achieved `signtool verify /pa` with 0 errors; it was removed immediately
  afterwards. Without that trust the status is `UnknownError` and SmartScreen
  requires reputation. On this machine, in addition, **Device Guard blocked the
  freshly built exe** because it did not come from a trusted CA; the build and
  its internal smoke test passed, but final validation was done with the Python
  CLI. A real EV/OV certificate should resolve this block; the issuance, signing
  and trust procedure is in `docs/EV_OV_HANDOFF.md`.
* Windows service installation: requires administrator (opens UAC). `service
  run` in the foreground was validated and, with the persisted home and the
  pywin32 312 `StopEvent` now fixed, the installed service reaches `Running`.
* Signature database: EICAR, 10 public hashes and synthetic markers; it does not
  replace an up-to-date commercial database.

## Security and compliance

The hardening baseline and control mapping against **SOC 2**, **ISO/IEC
27001:2022**, **ISO/IEC 27701** and the Argentine **DA 641/2021 / PSI Modelo
(DNC 1/2022)** baseline is in [HARDENING.md](./HARDENING.md). Private
vulnerability reporting, sample handling and coordinated disclosure are in
[SECURITY.md](./SECURITY.md). Generated state (`audit.jsonl`, `history.db`,
`reports.json`, `quarantine/`, keys) is restricted to the current user, retained
for at most 30 days where applicable, and excluded from git; dependencies are
hash-locked in `requirements.lock`.

These documents are a **gap assessment**, not a certification, audit report or
attestation.

## Building (Windows x64)

```powershell
python -m pip install --require-hashes -r requirements.lock
python -m pip install -e . --no-deps
.\packaging\get-signtool.ps1          # optional: portable signtool, hash-verified, no admin required
.\packaging\build.ps1 -Console        # dist\sentinel.exe
.\packaging\build.ps1 -Sign           # sign with signtool + timestamp
```

With `SENTINEL_PRIVATE_KEY=<path.pem>` the build also signs the data manifest
with Ed25519. See `packaging/README.md` for certificates, onedir/onefile options
and smoke tests. Diagnostic tools: `python -m pytest`, `python -m ruff check .`,
`python -m bandit -r sentinel -x tests`, `sentinel selftest`, `sentinel audit`
and `python tools/benchmark.py`. In `.github/workflows/ci.yml` these checks run
on Windows, with a separate SCA job on Python 3.11.
