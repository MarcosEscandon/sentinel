"""Core: models, quarantine, and persistence."""

from .allowlist import AllowList, normalize_path
from .database import ScanDatabase
from .logging import AuditLogger
from .models import Detection, Finding, RuleHit, ScanResult, Severity
from .quarantine import Quarantine, QuarantineEntry, QuarantineIntegrityError

__all__ = [
    "AllowList",
    "AuditLogger",
    "Detection",
    "Finding",
    "Quarantine",
    "QuarantineEntry",
    "QuarantineIntegrityError",
    "RuleHit",
    "ScanDatabase",
    "ScanResult",
    "Severity",
    "normalize_path",
]
