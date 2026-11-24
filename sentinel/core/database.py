"""Historial de escaneos en SQLite."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    bytes_scanned INTEGER NOT NULL DEFAULT 0,
    max_severity TEXT,
    summary TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    detection TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    quarantined INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);
"""


class ScanDatabase:
    """Persistencia ligera de informes; usa SQLite sin servicios externos."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save_scan(self, result: ScanResult) -> int:
        summary = {
            "roots": result.roots,
            "skipped": result.skipped,
            "errors": len(result.errors),
            "duration_seconds": round(result.duration_seconds, 3),
        }
        with self._connect() as connection:
            cursor = connection.execute(
                """INSERT INTO scans
                   (started_at, finished_at, files_scanned, bytes_scanned, max_severity, summary)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    result.started_at,
                    result.finished_at,
                    result.files_scanned,
                    result.bytes_scanned,
                    result.max_severity.value if result.max_severity else None,
                    json.dumps(summary, ensure_ascii=False),
                ),
            )
            scan_id = int(cursor.lastrowid)
            connection.executemany(
                """INSERT INTO findings
                   (scan_id, path, rule_id, detection, severity, description, sha256, quarantined)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        scan_id,
                        finding.path,
                        finding.rule_id,
                        finding.detection.value,
                        finding.severity.value,
                        finding.description,
                        finding.sha256,
                        int(finding.quarantined),
                    )
                    for finding in result.findings
                ],
            )
        return scan_id

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            findings = connection.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
            ).fetchall()
        data = dict(row)
        data["summary"] = json.loads(data.get("summary") or "{}")
        data["findings"] = [dict(item) for item in findings]
        return data

    def recent_findings(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT f.*, s.started_at AS scan_started_at
                   FROM findings f JOIN scans s ON s.id = f.scan_id
                   ORDER BY f.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            scans = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            quarantined = connection.execute(
                "SELECT COUNT(*) FROM findings WHERE quarantined = 1"
            ).fetchone()[0]
        return {"scans": scans, "findings": findings, "quarantined": quarantined}

    def mark_quarantined(self, paths: list[str], scan_id: int | None = None) -> int:
        """Marca los hallazgos cuyo archivo se envió a cuarentena."""
        if not paths:
            return 0
        placeholders = ",".join("?" for _ in paths)
        query = f"UPDATE findings SET quarantined = 1 WHERE path IN ({placeholders})"
        params: list[Any] = list(paths)
        if scan_id is not None:
            query += " AND scan_id = ?"
            params.append(scan_id)
        with self._connect() as connection:
            return connection.execute(query, params).rowcount


__all__ = ["Finding", "ScanDatabase", "ScanResult"]
