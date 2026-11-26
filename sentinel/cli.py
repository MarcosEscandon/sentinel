"""Sentinel command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__, crypto, trust
from . import service as windows_service
from .config import ScanConfig
from .core.allowlist import AllowList
from .core.database import ScanDatabase
from .core.logging import AuditLogger
from .core.models import ScanResult, Severity
from .core.quarantine import Quarantine, QuarantineIntegrityError
from .engine.scanner import Scanner, summarize
from .engine.signatures import SignatureDatabase
from .engine.yara import YaraEngine, YaraUnavailable
from .feeds import import_feed
from .integrity import build_manifest, verify_manifest, verify_signatures_bundle
from .security_fs import DEFAULT_RETENTION_DAYS, restrict_permissions, secure_write_text
from .updates import update_signatures

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_SIGNATURES = DATA_DIR / "signatures.json"
DEFAULT_YARA_DIR = DATA_DIR / "yara"
DEFAULT_HOME = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")))

# Exit codes: 0 clean, 1 findings, 2 operational error.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _enable_ansi() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError, ValueError):
        return False


class Colors:
    """ANSI colors with graceful degradation when unavailable."""

    def __init__(self, enabled: bool | None = None) -> None:
        self.enabled = _enable_ansi() if enabled is None else enabled
        self.reset = "\033[0m" if self.enabled else ""
        self.bold = "\033[1m" if self.enabled else ""
        self.dim = "\033[2m" if self.enabled else ""
        self.red = "\033[91m" if self.enabled else ""
        self.yellow = "\033[93m" if self.enabled else ""
        self.green = "\033[92m" if self.enabled else ""
        self.cyan = "\033[96m" if self.enabled else ""

    def severity(self, severity: Severity | None) -> str:
        if severity is None:
            return self.green
        return {
            Severity.INFO: self.cyan,
            Severity.LOW: self.cyan,
            Severity.MEDIUM: self.yellow,
            Severity.HIGH: self.red,
            Severity.CRITICAL: self.red + self.bold,
        }[severity]


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Modular malware scanner (signatures + heuristics + optional YARA).",
    )
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    parser.add_argument(
        "--home",
        default=str(DEFAULT_HOME),
        help="Data directory (default ~/.sentinel or $SENTINEL_HOME).",
    )
    parser.add_argument(
        "--signatures",
        default=str(DEFAULT_SIGNATURES),
        help="Path to signatures.json.",
    )
    parser.add_argument("--config-file", help="Path to a scanner configuration JSON file.")
    parser.add_argument("--log-file", help="Audit JSONL file.")
    parser.add_argument("--no-log", action="store_true", help="Disable audit logging.")
    parser.add_argument(
        "--allow-unsigned-signatures",
        action="store_true",
        help="Load an unsigned or untrusted signature database (unsafe; development only).",
    )

    # Global options are also accepted after the subcommand. SUPPRESS prevents
    # subparser defaults from overriding the global values.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", default=argparse.SUPPRESS)
    common.add_argument("--signatures", default=argparse.SUPPRESS)
    common.add_argument("--config-file", default=argparse.SUPPRESS)
    common.add_argument("--log-file", default=argparse.SUPPRESS)
    common.add_argument("--no-log", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--allow-unsigned-signatures", action="store_true", default=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan files or directories.", parents=[common])
    scan.add_argument(
        "--public-key", help="Trusted Ed25519 PEM key for the signature database."
    )
    scan.add_argument("paths", nargs="+", help="Files or directories to scan.")
    scan.add_argument("--no-heuristics", action="store_true", help="Disable heuristics.")
    scan.add_argument("--no-yara", action="store_true", help="Disable YARA rules.")
    scan.add_argument("--max-size", type=int, metavar="MB", help="Maximum size per file.")
    scan.add_argument("--jobs", type=int, metavar="N", help="Scanning threads (1 by default).")
    scan.add_argument(
        "--no-containers", action="store_true", help="Do not unpack ZIP/TAR/GZ/BZ2/XZ."
    )
    scan.add_argument("--exclude", action="append", default=[], metavar="NAME", help="Exclude a directory.")
    scan.add_argument("--json", dest="json_path", metavar="FILE", help="Write the JSON report.")
    scan.add_argument("--quiet", action="store_true", help="Only show the final summary.")
    scan.add_argument("--verbose", action="store_true", help="Show each file scanned.")
    scan.add_argument(
        "--quarantine-found",
        action="store_true",
        help="Quarantine detected files (will ask for confirmation).",
    )
    scan.add_argument("--yes", action="store_true", help="Confirm actions without prompting.")
    scan.add_argument(
        "--allowlist",
        metavar="FILE",
        help="Additional allowlist JSON (added to the self-exclusion rules).",
    )

    quarantine = sub.add_parser("quarantine", help="Manage quarantine.", parents=[common])
    qsub = quarantine.add_subparsers(dest="action", required=True)
    qsub.add_parser("list", help="List entries.")
    qsub.add_parser("verify", help="Verify hashes and MACs of all entries.")
    restore = qsub.add_parser("restore", help="Restore an entry.")
    restore.add_argument("id")
    restore.add_argument("--overwrite", action="store_true", help="Overwrite if the path exists.")
    delete = qsub.add_parser("delete", help="Permanently delete an entry.")
    delete.add_argument("id")
    prune = qsub.add_parser("prune", help="Remove old entries.")
    prune.add_argument("--days", type=int, default=30)

    signatures = sub.add_parser("signatures", help="Manage the signature database.", parents=[common])
    ssub = signatures.add_subparsers(dest="action", required=True)
    ssub.add_parser("info", help="Show statistics.")
    ssub.add_parser("validate", help="Validate the signature file.")
    sign = ssub.add_parser("sign", help="Sign the signature JSON with an Ed25519 private key.")
    sign.add_argument("--key", required=True, help="PEM private key.")
    sign.add_argument("--output", required=True, help="Output .sig file.")
    update = ssub.add_parser("update", help="Download and verify a signature database.")
    update.add_argument("--url", required=True)
    update.add_argument(
        "--public-key", required=True, help="Trusted PEM public key (required)."
    )
    update.add_argument(
        "--signature-url", help="Signature URL (default: <url>.sig)."
    )
    update.add_argument("--sha256", help="Expected SHA-256 hash of the download.")

    feeds = sub.add_parser("feeds", help="Import external IOCs.", parents=[common])
    fs = feeds.add_subparsers(dest="action", required=True)
    feed_import = fs.add_parser("import", help="Convert a feed to signatures.json.")
    feed_import.add_argument("file", help="CSV/JSON/MISP/hash-list file.")
    feed_import.add_argument("--source", default="feed", help="Source name (used for IDs).")
    feed_import.add_argument(
        "--format", choices=["auto", "csv", "json", "misp", "hashes"], default="auto"
    )
    feed_import.add_argument("--revision", type=int, help="Force a specific revision.")
    feed_import.add_argument("--dry-run", action="store_true", help="Do not modify the database.")

    keys = sub.add_parser("keys", help="Manage Ed25519 keys.", parents=[common])
    ksub = keys.add_subparsers(dest="action", required=True)
    generate = ksub.add_parser("generate", help="Generate a key pair.")
    generate.add_argument("--private", required=True, help="Path to the PEM private key.")
    generate.add_argument("--public", required=True, help="Path to the PEM public key.")

    service = sub.add_parser("service", help="Real-time protection (Windows service).", parents=[common])
    svc = service.add_subparsers(dest="action", required=True)
    svc_install = svc.add_parser("install", help="Install the service (requires administrator privileges).")
    svc_install.add_argument("--paths", nargs="+", required=True, help="Paths to monitor.")
    svc_install.add_argument(
        "--startup", choices=windows_service.STARTUP_MODES, default="auto"
    )
    svc_install.add_argument("--poll-interval", type=float, default=2.0)
    svc_install.add_argument(
        "--public-key",
        help="Trusted Ed25519 PEM key stored in the service configuration.",
    )
    svc.add_parser("remove", help="Uninstall the service.")
    svc_start = svc.add_parser("start", help="Start the service.")
    svc_start.add_argument("--wait", type=int, default=15)
    svc_stop = svc.add_parser("stop", help="Stop the service.")
    svc_stop.add_argument("--wait", type=int, default=15)
    svc.add_parser("status", help="Show the service status.")
    svc.add_parser("run", help="Run the monitor in the foreground (debugging).")

    monitor = sub.add_parser("monitor", help="Monitor paths in real time.", parents=[common])
    monitor.add_argument(
        "--public-key", help="Trusted Ed25519 PEM key for the signature database."
    )
    monitor.add_argument("paths", nargs="+", help="Paths to monitor.")
    monitor.add_argument("--poll-interval", type=float, default=2.0)
    monitor.add_argument("--grace-period", type=float, default=0.5)
    monitor.add_argument(
        "--max-pending",
        type=int,
        default=None,
        help="Maximum paths waiting for analysis (default: 4096).",
    )
    monitor.add_argument(
        "--backend",
        choices=("native", "watchdog", "polling"),
        default=None,
        help="Force the monitoring backend (default: best available).",
    )
    monitor.add_argument(
        "--notify",
        choices=("auto", "toast", "messagebox", "none"),
        default="auto",
        help="Desktop notifications on detection (default: automatic).",
    )

    gui = sub.add_parser("gui", help="Open the graphical interface (tkinter).", parents=[common])
    gui.add_argument("--public-key", help="Trusted Ed25519 PEM key for the signature database.")

    history = sub.add_parser("history", help="View scan history.", parents=[common])
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--findings", action="store_true", help="Show recent findings.")

    selftest = sub.add_parser(
        "selftest", help="Test the detectors with synthetic files.", parents=[common]
    )
    selftest.add_argument("--keep", action="store_true", help="Keep the generated files.")

    integrity = sub.add_parser(
        "integrity", help="Generate and verify integrity manifests.", parents=[common]
    )
    isub = integrity.add_subparsers(dest="action", required=True)
    build_cmd = isub.add_parser("build", help="Generate a SHA-256 manifest.")
    build_cmd.add_argument("root", nargs="?", default=".", help="Directory to record.")
    build_cmd.add_argument("--output", required=True, help="Path to the manifest JSON.")
    build_cmd.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Additional pattern to exclude (can be repeated).",
    )
    verify_cmd = isub.add_parser("verify", help="Compare a directory with its manifest.")
    verify_cmd.add_argument("root", nargs="?", default=".", help="Directory to verify.")
    verify_cmd.add_argument("--manifest", required=True, help="Manifest JSON.")
    verify_cmd.add_argument(
        "--public-key",
        help="Ed25519 public key; if provided, also verify <manifest>.sig.",
    )

    audit = sub.add_parser("audit", help="Security self-assessment.", parents=[common])
    audit.add_argument(
        "--public-key",
        help="PEM public key for verifying <signatures>.sig "
        "(equivalent to SENTINEL_PUBLIC_KEY).",
    )

    return parser


def _load_config(args: argparse.Namespace) -> ScanConfig:
    config = ScanConfig.from_file(args.config_file) if args.config_file else ScanConfig()
    command = getattr(args, "command", None)
    if command == "scan":
        if args.max_size is not None:
            config.max_file_size = args.max_size * 1024 * 1024
        if args.exclude:
            config.exclude_dirs = frozenset(set(config.exclude_dirs) | {n.lower() for n in args.exclude})
        if args.no_heuristics:
            config.use_heuristics = False
        if args.no_yara:
            config.use_yara = False
        if args.jobs is not None:
            config.jobs = args.jobs
        if args.no_containers:
            config.scan_containers = False
    config.validate()
    return config


def _report_registry(home: Path) -> Path:
    return home / "reports.json"


def _known_reports(home: Path) -> list[str]:
    path = _report_registry(home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, str)]


def _remember_report(home: Path, path: str) -> None:
    home.mkdir(parents=True, exist_ok=True)
    restrict_permissions(home)
    resolved = str(Path(path).resolve())

    # Only files Sentinel registered in reports.json are eligible for cleanup;
    # arbitrary paths chosen by the user are never deleted by a glob.
    cutoff = time.time() - DEFAULT_RETENTION_DAYS * 86400
    known: list[str] = []
    for item in _known_reports(home):
        candidate = Path(item)
        try:
            if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                candidate.unlink()
                continue
        except OSError:
            pass
        known.append(item)

    if resolved not in known:
        known.append(resolved)
    secure_write_text(
        _report_registry(home),
        json.dumps(known[-200:], indent=2, ensure_ascii=False),
    )


def _load_yara(config: ScanConfig) -> object | None:
    if not config.use_yara or not YaraEngine.available():
        return None
    rules = sorted(str(path) for path in DEFAULT_YARA_DIR.glob("*.yar"))
    try:
        return YaraEngine(rules)
    except (OSError, ValueError, YaraUnavailable) as exc:
        print(f"[warning] YARA disabled: {exc}", file=sys.stderr)
        return None


def _load_signatures(args: argparse.Namespace) -> SignatureDatabase:
    """Load the database with fail-closed signature verification by default."""
    return trust.load_database(
        args.signatures,
        home=args.home,
        public_key=getattr(args, "public_key", None),
        require_signature=not getattr(args, "allow_unsigned_signatures", False),
    )


def print_report(result: ScanResult, colors: Colors, *, quiet: bool = False) -> None:
    findings = result.sorted_findings()
    print(f"\n{colors.bold}SCAN REPORT{colors.reset}")
    print(f"  Started    : {result.started_at}")
    print(f"  Duration   : {result.duration_seconds:.2f} s")
    print(f"  Files      : {result.files_scanned}  ({human_size(result.bytes_scanned)})")
    print(f"  Skipped    : {result.skipped}")
    print(f"  Allowed    : {result.allowed}")
    print(f"  Container  : {result.container_entries} entries")
    print(f"  Errors     : {len(result.errors)}")

    if not findings:
        print(f"\n{colors.green}No threats found.{colors.reset}")
    else:
        print(f"\n{colors.red}{colors.bold}{len(findings)} finding(s):{colors.reset}")
        for finding in findings:
            tone = colors.severity(finding.severity)
            print(f"  {tone}[{finding.severity.value.upper()}]{colors.reset} {finding.rule_id} "
                  f"({finding.detection.value})")
            print(f"      {finding.path}")
            print(f"      {finding.description}")
            if finding.indicators:
                print(f"      {colors.dim}indicators: {', '.join(finding.indicators[:6])}{colors.reset}")
            if finding.sha256:
                print(f"      {colors.dim}sha256: {finding.sha256}{colors.reset}")
            if finding.quarantined:
                print(f"      {colors.yellow}quarantined ({finding.quarantine_id}){colors.reset}")
    for error in result.errors[:10]:
        print(f"  {colors.yellow}! {error['path']}: {error['error']}{colors.reset}", file=sys.stderr)


def cmd_scan(args: argparse.Namespace, colors: Colors, logger: AuditLogger) -> int:
    config = _load_config(args)
    signatures = _load_signatures(args)
    yara_engine = _load_yara(config)
    home = Path(args.home)
    database = ScanDatabase(home / "history.db")
    quarantine = Quarantine(home / "quarantine")

    rules = [
        AllowList.for_self([home, DATA_DIR.parent]),
        AllowList.for_files(_known_reports(home)),
    ]
    if args.json_path and args.json_path != "-":
        rules.append(AllowList.for_files([args.json_path]))
    if args.allowlist:
        rules.append(AllowList.load(args.allowlist, required=True))
    allowlist = AllowList.combine(*rules)
    scanner = Scanner(signatures, config, yara=yara_engine, allowlist=allowlist)
    logger.scan_start(
        args.paths,
        jobs=config.jobs,
        signatures_version=signatures.version,
        revision=signatures.revision,
    )

    stats = signatures.stats()
    if not args.quiet:
        print(f"{colors.bold}Sentinel {__version__}{colors.reset}")
        print(f"  Signatures: v{stats['version']} · {stats['hashes']} hashes · "
              f"{stats['filename_rules']} names · {stats['content_rules']} content")
        print(f"  Targets: {len(args.paths)}")
        print(f"  Exclusions: {allowlist.stats()['directories']} dirs, "
              f"{allowlist.stats()['paths']} files, {allowlist.stats()['globs']} globs")

    def progress(event: str, path: str, count: int) -> None:
        if args.quiet:
            return
        if args.verbose:
            mark = {"file": "·", "skip": "-", "error": "!", "finding": "*"}.get(event, "?")
            print(f"  {mark} {path}")
        elif event == "file" and count % 100 == 0:
            print(f"  ... {count} files", file=sys.stderr)

    result = scanner.scan(args.paths, progress)
    quarantine_ids: list[str] = []
    moved_paths: list[str] = []

    if args.quarantine_found and result.findings:
        targets: dict[str, list[Any]] = {}
        for finding in result.findings:
            targets.setdefault(finding.path, []).append(finding)
        if not args.yes:
            answer = input(f"Quarantine {len(targets)} file(s)? [y/N] ")
            if answer.strip().lower() not in {"y", "yes"}:
                print("Operation canceled; files were not moved.")
        else:
            answer = "y"
        if answer.strip().lower() in {"y", "yes"}:
            for path, items in targets.items():
                if not Path(path).is_file():
                    continue
                try:
                    entry_id = quarantine.add(path, items[0].rule_id, items[0].sha256)
                except (OSError, FileNotFoundError, QuarantineIntegrityError) as exc:
                    result.errors.append({"path": path, "error": str(exc)})
                    continue
                logger.emit("quarantine.add", id=entry_id, path=path, reason=items[0].rule_id)
                quarantine_ids.append(entry_id)
                moved_paths.append(path)
                for item in items:
                    item.quarantined = True
                    item.quarantine_id = entry_id

    scan_id = database.save_scan(result)
    if moved_paths:
        database.mark_quarantined(moved_paths, scan_id)
    for finding in result.findings:
        logger.finding(finding)
    logger.scan_finish({"scan_id": scan_id, **summarize(result)})

    print_report(result, colors, quiet=args.quiet)
    print(f"\n  Scan ID: {scan_id}")

    if args.json_path:
        payload = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
        if args.json_path == "-":
            print(payload)
        else:
            secure_write_text(Path(args.json_path), payload)
            _remember_report(home, args.json_path)
            print(f"  JSON report: {args.json_path}")

    if result.errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if result.findings else EXIT_CLEAN


def cmd_quarantine(args: argparse.Namespace, colors: Colors, logger: AuditLogger) -> int:
    store = Quarantine(Path(args.home) / "quarantine")
    if args.action == "list":
        entries = store.list()
        if not entries:
            print("Quarantine is empty.")
            return EXIT_CLEAN
        integrity = {entry.id: error for entry, error in store.verify_all()}
        for entry in entries:
            exists = Path(entry.stored_path).is_file()
            state = colors.green if exists else colors.red
            print(f"  {state}{entry.id}{colors.reset}  {entry.original_name}")
            print(f"      origin : {entry.original_path}")
            print(f"      reason : {entry.reason}  ·  {entry.quarantined_at}")
            if integrity[entry.id]:
                print(f"      {colors.red}INTEGRITY: {integrity[entry.id]}{colors.reset}")
        return EXIT_ERROR if any(integrity.values()) else EXIT_CLEAN

    if args.action == "verify":
        checked = store.verify_all()
        if not checked:
            print("Quarantine is empty.")
        for entry, error in checked:
            state = f"{colors.red}ALTERED: {error}" if error else f"{colors.green}OK"
            print(f"  {entry.id}  {state}{colors.reset}")
        logger.emit("quarantine.verify", altered=sum(bool(error) for _, error in checked))
        return EXIT_ERROR if any(error for _, error in checked) else EXIT_CLEAN

    try:
        if args.action == "restore":
            path = store.restore(args.id, overwrite=args.overwrite)
            logger.emit("quarantine.restore", id=args.id, path=str(path))
            print(f"Restored: {path}")
        elif args.action == "delete":
            store.delete(args.id)
            logger.emit("quarantine.delete", id=args.id)
            print("Entry permanently deleted.")
        elif args.action == "prune":
            count = store.prune(args.days)
            logger.emit("quarantine.prune", days=args.days, removed=count)
            print(f"Entries removed: {count}")
    except (KeyError, ValueError, OSError, QuarantineIntegrityError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


def cmd_signatures(args: argparse.Namespace, logger: AuditLogger) -> int:
    path = Path(args.signatures)
    if args.action == "sign":
        try:
            signature = crypto.sign_payload(path.read_bytes(), args.key)
            output = Path(args.output)
            output.write_bytes(signature)
            restrict_permissions(output)
        except (OSError, ValueError, TypeError, crypto.SigningUnavailable) as exc:
            print(f"Signing failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Signature saved to {args.output} ({len(signature)} bytes)")
        return EXIT_CLEAN

    if args.action == "update":
        try:
            info = update_signatures(
                args.url,
                path,
                args.public_key,
                signature_url=args.signature_url,
                expected_sha256=args.sha256,
            )
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            crypto.SigningUnavailable,
        ) as exc:  # network, signature, hash, format
            print(f"Update failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"Database updated and verified: {info['destination']}")
        print(f"  revision: {info['revision']}")
        logger.emit(
            "signatures.update",
            revision=info["revision"],
            sha256=info["sha256"],
            url=args.url,
        )
        print(f"  sha256: {info['sha256']}")
        print(f"  signatures: {info['stats']['hashes']} hashes")
        return EXIT_CLEAN
    try:
        database = _load_signatures(args)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print(f"Invalid signature database: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.action == "validate":
        print(f"{path}: OK")
    for key, value in database.stats().items():
        print(f"  {key}: {value}")
    return EXIT_CLEAN


def cmd_history(args: argparse.Namespace) -> int:
    database = ScanDatabase(Path(args.home) / "history.db")
    if args.findings:
        rows = database.recent_findings(args.limit)
        for row in rows:
            print(f"  [{row['severity']}] {row['rule_id']}  {row['path']}")
    else:
        rows = database.list_scans(args.limit)
        if not rows:
            print("No scans recorded.")
        for row in rows:
            print(
                f"  #{row['id']}  {row['started_at']}  "
                f"{row['files_scanned']} files  max={row['max_severity'] or '-'}"
            )
    return EXIT_CLEAN


def cmd_selftest(args: argparse.Namespace, colors: Colors) -> int:
    directory = Path(tempfile.mkdtemp(prefix="sentinel-selftest-"))
    print(f"Test directory: {directory}")
    (directory / "report.pdf.exe").write_bytes(b"synthetic sample\n")
    (directory / "marker.txt").write_bytes(b"SENTINEL_TEST_MARKER test payload\n")
    (directory / "random.bin").write_bytes(os.urandom(8192))

    signatures = _load_signatures(args)
    config = ScanConfig(entropy_threshold=7.0, entropy_min_size=1024)
    result = Scanner(signatures, config, yara=None).scan([directory])
    rules = {finding.rule_id for finding in result.findings}

    checks = {
        "content rule": "TEST-CONTENT-MARKER" in rules,
        "double extension": "HEUR-DOUBLE-EXT" in rules,
        "high entropy": "HEUR-ENTROPY" in rules,
    }
    for name, passed in checks.items():
        print(f"  {colors.green if passed else colors.red}{'OK' if passed else 'FAIL'}{colors.reset}  {name}")

    if not args.keep:
        shutil.rmtree(directory, ignore_errors=True)
        print("Temporary directory removed.")
    return EXIT_CLEAN if all(checks.values()) else EXIT_ERROR


def cmd_feeds(args: argparse.Namespace, logger: AuditLogger) -> int:
    try:
        report = import_feed(
            args.file,
            args.signatures,
            source=args.source,
            fmt=args.format,
            revision=args.revision,
            dry_run=args.dry_run,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"Feed import failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Feed imported ({report.fmt}): {report.parsed} records read")
    print(f"  hashes: {report.added_hashes} · names: {report.added_filenames} "
          f"· content: {report.added_content}")
    print(f"  duplicates: {report.duplicates} · errors: {len(report.errors)}")
    print(f"  revision: {report.revision}{' (dry run)' if report.dry_run else ''}")
    for error in report.errors[:10]:
        print(f"  ! {error}", file=sys.stderr)
    logger.emit(
        "feeds.import",
        source=report.source,
        format=report.fmt,
        revision=report.revision,
        added=report.added_hashes + report.added_filenames + report.added_content,
        dry_run=report.dry_run,
    )
    return EXIT_CLEAN if not report.errors else EXIT_ERROR


def cmd_keys(args: argparse.Namespace) -> int:
    try:
        crypto.generate_keypair(args.private, args.public)
    except (OSError, ValueError, crypto.SigningUnavailable) as exc:
        print(f"Key generation failed: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Private key: {args.private} (store it outside the scanned machine)")
    print(f"Public key  : {args.public} (distribute it with the client)")
    return EXIT_CLEAN


def cmd_monitor(args: argparse.Namespace, colors: Colors, logger: AuditLogger) -> int:
    from .notify import Notifier
    from .realtime import RealtimeMonitor, available_backends

    config = _load_config(args)
    signatures = _load_signatures(args)
    home = Path(args.home)
    try:
        notifier = Notifier(args.notify)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.backend and args.backend not in available_backends():
        print(
            f"Error: backend '{args.backend}' is not available. "
            f"Available: {', '.join(available_backends())}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    def on_finding(finding: Any, action: str) -> None:
        print(
            f"{colors.red}[{finding.severity.value.upper()}]{colors.reset} "
            f"{finding.rule_id} · {finding.path} · {action}"
        )
        notifier.notify_finding(finding, action)

    rules = AllowList.combine(
        AllowList.for_self([home, DATA_DIR.parent]),
        AllowList.for_files(_known_reports(home)),
    )
    monitor = RealtimeMonitor(
        paths=args.paths,
        signatures=signatures,
        config=config,
        quarantine=Quarantine(home / "quarantine"),
        logger=logger,
        allowlist=rules,
        on_finding=on_finding,
        poll_interval=args.poll_interval,
        grace_period=args.grace_period,
        backend=args.backend,
        max_pending=args.max_pending,
    )
    logger.emit(
        "realtime.start",
        paths=args.paths,
        backend=monitor.backend,
        notify=notifier.backend,
    )
    print(
        f"Monitoring {len(args.paths)} path(s) with backend '{monitor.backend}' "
        f"and notifications '{notifier.backend}'. Press Ctrl+C to exit."
    )
    monitor.start()
    try:
        while monitor.is_alive:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
    finally:
        monitor.stop()
    return EXIT_CLEAN


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from .gui import SentinelGUI

        config = ScanConfig.from_file(args.config_file) if args.config_file else ScanConfig()
        SentinelGUI(
            args.home,
            args.signatures,
            config=config,
            public_key=getattr(args, "public_key", None),
            require_signature=not getattr(args, "allow_unsigned_signatures", False),
        ).run()
    except (ImportError, OSError, ValueError, TypeError) as exc:
        print(f"Could not open the graphical interface: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


def cmd_integrity(args: argparse.Namespace, logger: AuditLogger) -> int:
    """Generate or verify a file integrity manifest."""
    if args.action == "build":
        manifest = build_manifest(args.root, args.output, args.exclude)
        total = len(manifest["files"])
        logger.emit("integrity.build", output=args.output, files=total)
        print(f"Manifest generated: {args.output} ({total} files).")
        return EXIT_CLEAN

    report = verify_manifest(args.root, args.manifest)
    signature_ok: bool | None = None
    if args.public_key:
        signature_ok = verify_signatures_bundle(args.manifest, args.public_key)
        status = "valid" if signature_ok else "invalid or missing"
        print(f"Manifest signature: {status}.")

    status = "OK" if report.ok else "FAILED"
    print(
        f"Integrity: {status} | expected={report.expected} "
        f"missing={report.missing} modified={report.modified} "
        f"added={report.added}"
    )
    for item in report.details:
        print(f"  {item['status']}: {item['path']}")

    logger.emit(
        "integrity.verify",
        ok=report.ok,
        signature_ok=signature_ok,
        expected=report.expected,
        missing=report.missing,
        modified=report.modified,
        added=report.added,
    )
    if report.ok and (signature_ok is None or signature_ok):
        return EXIT_CLEAN
    return EXIT_ERROR


def cmd_audit(args: argparse.Namespace, logger: AuditLogger) -> int:
    """Run the security self-assessment of the deployment."""
    from .audit import run_security_audit

    if getattr(args, "public_key", None):
        os.environ["SENTINEL_PUBLIC_KEY"] = args.public_key
    report = run_security_audit(args.home, args.signatures)

    print(f"\nSECURITY AUDIT  {report.score}/100")
    for check in report.checks:
        state = "OK" if check.passed else "FAIL"
        print(f"  [{state}] {check.name}: {check.detail}")
        if not check.passed and check.remediation:
            print(f"         -> {check.remediation}")
    print(f"  Result: {len(report.failures)} failure(s) out of {len(report.checks)} checks")
    logger.emit(
        "audit.result",
        passed=report.passed,
        score=report.score,
        failures=[check.name for check in report.failures],
    )
    return EXIT_CLEAN if report.passed else EXIT_ERROR


def cmd_service(args: argparse.Namespace, logger: AuditLogger) -> int:
    try:
        if args.action == "install":
            destination = windows_service.save_config(
                args.home,
                paths=args.paths,
                signatures=args.signatures,
                config_file=args.config_file,
                poll_interval=args.poll_interval,
                public_key=getattr(args, "public_key", None),
            )
            windows_service.install(args.home, startup=args.startup)
            logger.emit("service.install", config=str(destination), startup=args.startup)
            print(f"Service {windows_service.SERVICE_NAME} installed ({args.startup}).")
            print(f"Configuration: {destination}")
        elif args.action == "remove":
            windows_service.remove()
            logger.emit("service.remove")
            print("Service uninstalled.")
        elif args.action == "start":
            windows_service.start(args.wait)
            logger.emit("service.start")
            print("Service running.")
        elif args.action == "stop":
            windows_service.stop(args.wait)
            logger.emit("service.stop")
            print("Service stopped.")
        elif args.action == "status":
            print(f"Service {windows_service.SERVICE_NAME}: {windows_service.status()}")
        elif args.action == "run":
            return windows_service.run_foreground(args.home)
    except (
        windows_service.ServiceUnavailable,
        ValueError,
        TypeError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"Service error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - pywintypes.error does not derive from OSError
        print(f"Service error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_CLEAN


def _build_logger(args: argparse.Namespace) -> AuditLogger:
    if getattr(args, "no_log", False):
        return AuditLogger(None)
    if getattr(args, "log_file", None):
        return AuditLogger(args.log_file)
    return AuditLogger(Path(args.home) / "audit.jsonl")


def main(argv: Sequence[str] | None = None) -> int:
    if windows_service.dispatch_frozen():
        return EXIT_CLEAN
    parser = build_parser()
    args = parser.parse_args(argv)
    colors = Colors()
    logger = _build_logger(args)

    handlers = {
        "scan": lambda: cmd_scan(args, colors, logger),
        "quarantine": lambda: cmd_quarantine(args, colors, logger),
        "signatures": lambda: cmd_signatures(args, logger),
        "feeds": lambda: cmd_feeds(args, logger),
        "integrity": lambda: cmd_integrity(args, logger),
        "audit": lambda: cmd_audit(args, logger),
        "service": lambda: cmd_service(args, logger),
        "monitor": lambda: cmd_monitor(args, colors, logger),
        "gui": lambda: cmd_gui(args),
        "keys": lambda: cmd_keys(args),
        "history": lambda: cmd_history(args),
        "selftest": lambda: cmd_selftest(args, colors),
    }
    try:
        logger.emit("command", name=args.command)
        return handlers[args.command]()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR
    except (
        OSError,
        ValueError,
        TypeError,
        FileNotFoundError,
        crypto.SigningUnavailable,
        QuarantineIntegrityError,
    ) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
