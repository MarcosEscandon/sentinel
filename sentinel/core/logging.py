"""Registro de auditoría en formato JSON Lines."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from .models import utc_now


class AuditLogger:
    """Escribe eventos como una línea JSON por evento.

    Es seguro usarlo desde los hilos del escáner: las escrituras están
    protegidas por un cerrojo. Si ``path`` es ``None`` no hace nada.
    """

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, **fields: Any) -> None:
        if self.path is None:
            return
        record: dict[str, Any] = {"ts": utc_now(), "event": event}
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")

    def scan_start(self, roots: list[str], **fields: Any) -> None:
        self.emit("scan.start", roots=roots, **fields)

    def scan_finish(self, summary: dict[str, Any]) -> None:
        self.emit("scan.finish", **summary)

    def finding(self, finding: Any) -> None:
        self.emit(
            "finding",
            path=finding.path,
            rule_id=finding.rule_id,
            detection=finding.detection.value,
            severity=finding.severity.value,
            sha256=finding.sha256,
        )


__all__ = ["AuditLogger"]
