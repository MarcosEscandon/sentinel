"""Modelos de datos compartidos por todas las capas."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now() -> str:
    """Devuelve la hora actual en ISO 8601 con zona UTC."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Severity(str, Enum):
    """Niveles de severidad, ordenados de menor a mayor."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError as exc:
            valid = ", ".join(item.value for item in cls)
            raise ValueError(f"Severidad desconocida {value!r}. Válidas: {valid}") from exc


class Detection(str, Enum):
    """Origen de una detección."""

    HASH = "hash"
    FILENAME = "filename"
    CONTENT = "content"
    HEURISTIC = "heuristic"
    YARA = "yara"


@dataclass(frozen=True)
class RuleHit:
    """Resultado crudo de un módulo de detección, antes de asociarlo a un archivo."""

    rule_id: str
    detection: Detection
    severity: Severity
    description: str
    indicators: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "detection": self.detection.value,
            "severity": self.severity.value,
            "description": self.description,
            "indicators": list(self.indicators),
        }


@dataclass
class Finding:
    """Un archivo detectado como sospechoso o malicioso."""

    path: str
    rule_id: str
    detection: Detection
    severity: Severity
    description: str
    sha256: str = ""
    size: int = 0
    score: float = 0.0
    indicators: list[str] = field(default_factory=list)
    quarantined: bool = False
    quarantine_id: str = ""
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["detection"] = self.detection.value
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanResult:
    """Informe completo de una ejecución de escaneo."""

    roots: list[str]
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped: int = 0
    allowed: int = 0
    container_entries: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if not self.finished_at:
            return 0.0
        start = datetime.fromisoformat(self.started_at)
        end = datetime.fromisoformat(self.finished_at)
        return max(0.0, (end - start).total_seconds())

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((item.severity for item in self.findings), key=lambda item: item.rank)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (-item.severity.rank, item.path, item.rule_id),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "roots": list(self.roots),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "skipped": self.skipped,
            "allowed": self.allowed,
            "container_entries": self.container_entries,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [item.to_dict() for item in self.sorted_findings()],
            "errors": list(self.errors),
        }


def highest(findings: Iterable[Finding]) -> Severity | None:
    """Devuelve la severidad más alta de una colección de hallazgos."""
    items = list(findings)
    return max((item.severity for item in items), key=lambda item: item.rank, default=None)
