"""Audit log in JSON Lines format."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ..security_fs import DEFAULT_RETENTION_DAYS, cleanup_old_files, restrict_permissions
from .models import utc_now


class AuditLogger:
    """Writes events as one JSON line per event.

    It is safe to use from scanner threads: writes are protected by a lock. If
    ``path`` is ``None``, it does nothing. The log directory and file are
    restricted to the current user, and stale audit files are removed on
    startup (30 days by default).
    """

    def __init__(self, path: str | Path | None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._restricted = False
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            restrict_permissions(self.path.parent)
            cleanup_old_files(
                self.path.parent,
                days=DEFAULT_RETENTION_DAYS,
                pattern="audit*.jsonl",
            )

    def emit(self, event: str, **fields: Any) -> None:
        if self.path is None:
            return
        record: dict[str, Any] = {"ts": utc_now(), "event": event}
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        if not self._restricted:
            restrict_permissions(self.path)
            self._restricted = True

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
