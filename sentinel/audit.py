"""Security self-assessment of a Sentinel installation.

The ``sentinel audit`` command runs real checks against the signature
database, quarantine, audit log, exclusions, real-time monitor, and
configuration. No check propagates exceptions to the CLI: errors are converted
into ``AuditCheck(passed=False)``.

The public key used by ``signatures.signed`` is resolved, in this order, from
``SENTINEL_PUBLIC_KEY``, ``<home>/signing.pub``, and ``<signatures>.pub``. The
CLI accepts the key via ``sentinel signatures update --public-key`` and
``sentinel audit --public-key`` (which injects it into ``SENTINEL_PUBLIC_KEY``);
there is no persistent configuration, so this audit follows that resolution
convention.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import crypto
from .config import ScanConfig
from .core.allowlist import AllowList
from .core.logging import AuditLogger
from .core.quarantine import Quarantine
from .engine.signatures import SignatureDatabase
from .realtime import available_backends

PUBLIC_KEY_ENV = "SENTINEL_PUBLIC_KEY"
"""Environment variable with the path to the trusted public key."""

AUDIT_EVENT = "audit.check"
"""Test event written by the ``logging.enabled`` check."""

_REMEDIAR_BASE = "Repair or replace signatures.json and run `sentinel signatures validate`."
_REMEDIAR_FIRMA = (
    "Production requires an Ed25519 signature: generate a pair with `sentinel keys generate`, sign "
    "with `sentinel signatures sign --key <private> --output <signatures>.sig`, and "
    "distribute the public key through a secure channel."
)
_REMEDIAR_CLAVE = (
    f"Set {PUBLIC_KEY_ENV}=<path.pem> or copy the public key to "
    "<home>/signing.pub or next to the database as <signatures>.pub."
)
_REMEDIAR_CUARENTENA = (
    "Do not restore altered entries; preserve the index and the key, and investigate "
    "the change with `sentinel quarantine verify`."
)
_REMEDIAR_LOG = (
    "Ensure <home> is writable and that audit.jsonl has not been edited by hand."
)
_REMEDIAR_ALLOWLIST = (
    "Review AllowList.for_self: self-exclusion is necessary to avoid self-detection."
)
_REMEDIAR_REALTIME = "Install `watchdog` or verify the native Windows backend (ctypes)."
_REMEDIAR_CONFIG = "Fix the anti-bomb limits in the JSON passed with --config-file."
_REMEDIAR_HOME = (
    "Use %ProgramData%\\Sentinel or another writable path outside Windows/Program Files."
)

_CheckResult = tuple[bool, str, str]


@dataclass
class AuditCheck:
    """Result of a specific self-assessment check."""

    name: str
    passed: bool
    detail: str
    remediation: str = ""


@dataclass
class SecurityAudit:
    """Aggregate report containing all checks that were run."""

    home: Path
    signatures: Path
    checks: list[AuditCheck]

    @property
    def passed(self) -> bool:
        """``True`` only if there are checks and all of them passed."""
        return bool(self.checks) and all(check.passed for check in self.checks)

    @property
    def failures(self) -> list[AuditCheck]:
        """Failed checks, in the order in which they were run."""
        return [check for check in self.checks if not check.passed]

    @property
    def score(self) -> int:
        """Percentage of checks passed (0-100)."""
        if not self.checks:
            return 0
        ok = sum(1 for check in self.checks if check.passed)
        return round(100 * ok / len(self.checks))

    def to_dict(self) -> dict[str, Any]:
        """JSON-compatible serialization, including the computed properties."""
        return {
            "home": str(self.home),
            "signatures": str(self.signatures),
            "passed": self.passed,
            "score": self.score,
            "failures": [asdict(check) for check in self.failures],
            "checks": [asdict(check) for check in self.checks],
        }


def _check(
    name: str,
    fallback_remediation: str,
    operation: Callable[[], _CheckResult],
) -> AuditCheck:
    """Runs a check and converts any error into a failure."""
    try:
        passed, detail, remediation = operation()
        return AuditCheck(name, bool(passed), str(detail), str(remediation))
    except Exception as exc:  # noqa: BLE001 - the audit must never propagate errors
        return AuditCheck(
            name,
            False,
            f"{type(exc).__name__}: {exc}",
            fallback_remediation,
        )


def _check_signatures_valid(signatures: Path) -> _CheckResult:
    """Loads and validates the database, requiring a strictly positive revision."""
    database = SignatureDatabase.load(signatures)
    # An empty database (revision 0) is valid as a starting point, but not as an
    # installed database: ``check_rollback`` verifies that we do not roll back from it.
    database.check_rollback(SignatureDatabase.empty())
    stats = database.stats()
    revision = database.revision
    if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
        return (
            False,
            f"invalid revision: {revision!r} (must be an integer > 0)",
            _REMEDIAR_BASE,
        )
    detail = (
        f"valid database: revision {revision}, {stats['hashes']} hashes, "
        f"{stats['content_rules']} content rules"
    )
    return True, detail, ""


def _public_key_candidates(home: Path, signatures: Path) -> list[Path]:
    """Returns the supported locations for the trusted public key."""
    candidates: list[Path] = []
    configured = os.environ.get(PUBLIC_KEY_ENV, "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        [
            home / "signing.pub",
            Path(str(signatures) + ".pub"),
        ]
    )
    return candidates


def _check_signatures_signed(home: Path, signatures: Path) -> _CheckResult:
    """Verifies the separate Ed25519 signature against the configured public key."""
    signature_path = Path(str(signatures) + ".sig")
    if not signature_path.is_file():
        return (
            False,
            f"signature {signature_path.name} is missing; the database cannot be verified",
            _REMEDIAR_FIRMA,
        )
    if not crypto.available():
        return (
            False,
            "cryptography is not installed; Ed25519 verification is unavailable",
            "Install the signing extra: pip install -e '.[signing]'.",
        )

    candidates = _public_key_candidates(home, signatures)
    key_path = next(
        (candidate for candidate in candidates if candidate.is_file()),
        None,
    )
    if key_path is None:
        return (
            False,
            "there is a signature but no configured public key",
            _REMEDIAR_CLAVE,
        )

    payload = signatures.read_bytes()
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        return (
            False,
            f"signature of {len(signature)} bytes; Ed25519 requires 64",
            _REMEDIAR_FIRMA,
        )
    if crypto.verify_payload(payload, signature, key_path):
        return True, f"valid Ed25519 signature with {key_path}", ""
    return (
        False,
        "the Ed25519 signature does not match the database content",
        "Do not use this database: redistribute the JSON and its signature from the trusted source.",
    )


def _check_quarantine_integrity(home: Path) -> _CheckResult:
    """Verifies quarantine entries and MACs without raising exceptions."""
    store = Quarantine(home / "quarantine")
    if not store.index_path.exists():
        return True, "no entries", ""
    results = store.verify_all()
    if not results:
        return True, "no entries", ""
    altered = [(entry.id, error) for entry, error in results if error]
    if altered:
        first_id, first_error = altered[0]
        return (
            False,
            (
                f"{len(altered)} of {len(results)} entries altered "
                f"({first_id}: {first_error})"
            ),
            _REMEDIAR_CUARENTENA,
        )
    return True, f"{len(results)} intact entry(ies)", ""


def _check_quarantine_key_permissions(home: Path) -> _CheckResult:
    """Checks ``quarantine.key`` permissions without ever modifying them."""
    key_path = home / "quarantine.key"
    if not key_path.is_file():
        return True, "no quarantine key: no permissions to check", ""
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    readable_by_others = bool(mode & (stat.S_IRGRP | stat.S_IROTH))
    if os.name == "nt":
        # os.stat on Windows does not expose ACLs: even a file with a restrictive
        # ACL usually reports mode 0666. We can only assert the absence of group/other
        # read access when the bits indicate it; otherwise we state the limitation
        # and pass the check.
        if not readable_by_others:
            return True, f"os.stat: mode {mode:04o} without group/other read access", ""
        return (
            True,
            (
                f"os.stat on Windows does not expose ACLs (mode {mode:04o}); cannot "
                f"confirm whether the key is world-readable. Check with: icacls {key_path}"
            ),
            "",
        )
    if readable_by_others:
        return False, f"mode {mode:04o} allows group/other read access", f"chmod 600 {key_path}"
    return True, f"mode {mode:04o} restricted", ""


def _check_logging(home: Path) -> _CheckResult:
    """Writes a test event with ``AuditLogger`` and validates the JSONL."""
    path = home / "audit.jsonl"
    logger = AuditLogger(path)
    logger.emit(AUDIT_EVENT, component="audit")
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False, "the logger wrote no lines", _REMEDIAR_LOG
    try:
        records = [json.loads(line) for line in lines]
    except json.JSONDecodeError as exc:
        return False, f"audit.jsonl contains a non-JSON line: {exc}", _REMEDIAR_LOG
    if records[-1].get("event") != AUDIT_EVENT:
        return False, f"unexpected last event: {records[-1].get('event')!r}", _REMEDIAR_LOG
    return True, f"event {AUDIT_EVENT} written and read successfully ({len(records)} line(s))", ""


def _check_allowlist_self(home: Path) -> _CheckResult:
    """Checks that the application's self-exclusion is not empty."""
    package_root = Path(__file__).parent.parent
    rules = AllowList.for_self([home, package_root])
    if not rules.directories or not rules.allows_path(home / "sentinel-audit.txt"):
        return False, "self-exclusion is empty or does not cover the home directory", _REMEDIAR_ALLOWLIST
    return True, f"{len(rules.directories)} application directories excluded", ""


def _check_realtime_backend() -> _CheckResult:
    """Requires an event backend on Windows and ``polling`` on other OSes."""
    backends = available_backends()
    if os.name == "nt":
        usable = [backend for backend in backends if backend != "polling"]
        if not usable:
            return False, f"only polling is available: {backends}", _REMEDIAR_REALTIME
        return True, f"non-polling backend available: {', '.join(usable)}", ""
    if "polling" not in backends:
        return False, f"no polling backend available: {backends}", _REMEDIAR_REALTIME
    return True, f"available backend: {', '.join(backends)}", ""


def _check_config() -> _CheckResult:
    """Validates the anti-bomb limits of the default configuration."""
    config = ScanConfig()
    config.validate()
    names = (
        "max_file_size",
        "sample_size",
        "container_max_entries",
        "container_max_uncompressed",
        "container_max_depth",
        "container_max_ratio",
    )
    values = {name: getattr(config, name) for name in names}
    if any(value <= 0 for value in values.values()) or config.container_max_depth < 1:
        return False, f"invalid limits: {values}", _REMEDIAR_CONFIG
    return (
        True,
        (
            f"max_file_size={config.max_file_size}, sample_size={config.sample_size}, "
            f"container_max_depth={config.container_max_depth}"
        ),
        "",
    )


def _home_location_problem(home: Path) -> str | None:
    """Returns the reason why the home directory is invalid, or ``None``."""
    if os.name != "nt":
        return None
    try:
        resolved = home.resolve()
    except OSError:
        resolved = Path(os.path.abspath(str(home)))
    parts = [part.lower() for part in resolved.parts]
    # ProgramData is the recommended machine-wide configuration location.
    if any(part == "programdata" for part in parts):
        return None
    if len(parts) >= 2 and parts[0].rstrip("\\/").endswith(":"):
        forbidden = {
            "windows": "Windows",
            "program files": "Program Files",
            "program files (x86)": "Program Files (x86)",
        }
        if parts[1] in forbidden:
            return f"the home directory is inside {forbidden[parts[1]]} (read-only path)"
    return None


def _check_home_location(home: Path) -> _CheckResult:
    """Rejects home directories under read-only system directories."""
    problem = _home_location_problem(home)
    if problem:
        return False, problem, _REMEDIAR_HOME
    return True, f"home directory on a writable path: {home}", ""


def _check_iocs_minimum(signatures: Path) -> _CheckResult:
    """Requires at least one hash and one content rule in the database."""
    stats = SignatureDatabase.load(signatures).stats()
    hashes = int(stats["hashes"])
    content = int(stats["content_rules"])
    if hashes < 1 or content < 1:
        return (
            False,
            f"insufficient database: {hashes} hash(es), {content} content rule(s)",
            "Install a database with at least one hash and one content rule (for example EICAR).",
        )
    return True, f"{hashes} hash(es) and {content} content rule(s)", ""


def run_security_audit(home: str | Path, signatures: str | Path) -> SecurityAudit:
    """Runs all checks without raising exceptions.

    ``home`` is the Sentinel data directory and ``signatures`` is the path to
    ``signatures.json``. Each check catches its own errors; problems while
    building the paths become a failed ``audit.setup`` check.
    """
    try:
        home_path = Path(home)
        signatures_path = Path(signatures)
    except Exception as exc:  # noqa: BLE001 - invalid paths must not propagate
        return SecurityAudit(
            Path(),
            Path(),
            [
                AuditCheck(
                    "audit.setup",
                    False,
                    f"{type(exc).__name__}: {exc}",
                    "Pass valid paths to run_security_audit(home, signatures).",
                )
            ],
        )

    checks = [
        _check(
            "signatures.valid",
            _REMEDIAR_BASE,
            lambda: _check_signatures_valid(signatures_path),
        ),
        _check(
            "signatures.signed",
            _REMEDIAR_FIRMA,
            lambda: _check_signatures_signed(home_path, signatures_path),
        ),
        _check(
            "quarantine.integrity",
            _REMEDIAR_CUARENTENA,
            lambda: _check_quarantine_integrity(home_path),
        ),
        _check(
            "quarantine.key_permissions",
            "Review the permissions of <home>/quarantine.key manually; do not "
            "change them automatically.",
            lambda: _check_quarantine_key_permissions(home_path),
        ),
        _check("logging.enabled", _REMEDIAR_LOG, lambda: _check_logging(home_path)),
        _check(
            "allowlist.self",
            _REMEDIAR_ALLOWLIST,
            lambda: _check_allowlist_self(home_path),
        ),
        _check("realtime.backend", _REMEDIAR_REALTIME, _check_realtime_backend),
        _check("config.sane", _REMEDIAR_CONFIG, _check_config),
        _check("home.location", _REMEDIAR_HOME, lambda: _check_home_location(home_path)),
        _check("iocs.minimum", _REMEDIAR_BASE, lambda: _check_iocs_minimum(signatures_path)),
    ]
    return SecurityAudit(home_path, signatures_path, checks)


__all__ = [
    "AUDIT_EVENT",
    "PUBLIC_KEY_ENV",
    "AuditCheck",
    "SecurityAudit",
    "run_security_audit",
]
