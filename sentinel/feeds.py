"""Conversión de feeds externos de IOCs a ``signatures.json``.

Formatos admitidos: CSV, JSON (lista de indicadores), MISP JSON y listas
planas de hashes SHA-256 (un hash por línea).
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core.models import Severity, utc_now

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"[^A-Z0-9_-]+")

TYPE_ALIASES = {
    "sha256": "hash",
    "hash": "hash",
    "hash_sha256": "hash",
    "filename": "filename",
    "file_name": "filename",
    "content": "content",
    "pattern": "content",
    "regexp": "content",
    "regexp_content": "content",
    "yara": "content",
}


@dataclass(frozen=True)
class IocRecord:
    kind: str
    value: str
    severity: str = "high"
    description: str = ""
    rule_id: str = ""


@dataclass
class ImportReport:
    source: str
    fmt: str
    parsed: int
    added_hashes: int = 0
    added_filenames: int = 0
    added_content: int = 0
    duplicates: int = 0
    errors: list[str] = field(default_factory=list)
    revision: int = 0
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "format": self.fmt,
            "parsed": self.parsed,
            "added_hashes": self.added_hashes,
            "added_filenames": self.added_filenames,
            "added_content": self.added_content,
            "duplicates": self.duplicates,
            "errors": self.errors,
            "revision": self.revision,
            "dry_run": self.dry_run,
        }


def _first(item: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = item.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _record(item: dict[str, Any]) -> IocRecord | None:
    kind = _first(item, "type", "kind", "ioc_type").lower().replace("-", "_")
    kind = TYPE_ALIASES.get(kind, kind)
    if kind not in {"hash", "filename", "content"}:
        return None
    value = _first(item, "value", "pattern", "sha256", "ioc", "indicator")
    if not value:
        return None
    severity = _first(item, "severity", "risk", default="high")
    try:
        Severity.parse(severity)
    except ValueError:
        severity = "high"
    return IocRecord(
        kind=kind,
        value=value,
        severity=severity.lower(),
        description=_first(item, "description", "comment", "category", "name"),
        rule_id=_first(item, "id", "uuid", "rule_id"),
    )


def parse_csv(text: str) -> list[IocRecord]:
    reader = csv.DictReader(io.StringIO(text))
    return [record for row in reader if (record := _record(row)) is not None]


def parse_json(text: str) -> list[IocRecord]:
    payload = json.loads(text)
    if isinstance(payload, dict):
        payload = next(
            (
                payload[key]
                for key in ("indicators", "iocs", "data", "values")
                if isinstance(payload.get(key), list)
            ),
            [payload],
        )
    if not isinstance(payload, list):
        raise TypeError("El JSON debe contener una lista de indicadores")
    return [record for item in payload if isinstance(item, dict) if (record := _record(item))]


def parse_misp(text: str) -> list[IocRecord]:
    payload = json.loads(text)
    event = payload.get("Event", payload) if isinstance(payload, dict) else {}
    attributes = event.get("Attribute", []) if isinstance(event, dict) else []
    records: list[IocRecord] = []
    for attribute in attributes:
        if not isinstance(attribute, dict):
            continue
        item = dict(attribute)
        item["type"] = str(attribute.get("type", "")).replace("|", "_")
        record = _record(item)
        if record is not None:
            records.append(record)
    return records


def parse_hashes(text: str) -> list[IocRecord]:
    records: list[IocRecord] = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if _HASH_RE.match(value.lower()):
            records.append(IocRecord(kind="hash", value=value.lower()))
    return records


PARSERS: dict[str, Callable[[str], list[IocRecord]]] = {
    "csv": parse_csv,
    "json": parse_json,
    "misp": parse_misp,
    "hashes": parse_hashes,
}


def detect_format(path: str | Path, text: str, requested: str = "auto") -> str:
    if requested != "auto":
        if requested not in PARSERS:
            raise ValueError(f"Formato desconocido: {requested}")
        return requested
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return "csv"
    if suffix in {".json", ".misp"}:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return "hashes"
        if isinstance(payload, dict) and "Event" in payload:
            return "misp"
        return "json"
    return "hashes"


def _new_database() -> dict[str, Any]:
    return {
        "schema": 1,
        "version": datetime.now(timezone.utc).date().isoformat(),
        "revision": 0,
        "updated_at": utc_now(),
        "hashes": {},
        "filenames": [],
        "content": [],
    }


def import_feed(
    source_path: str | Path,
    target_path: str | Path,
    *,
    source: str = "feed",
    fmt: str = "auto",
    revision: int | None = None,
    dry_run: bool = False,
) -> ImportReport:
    """Importa un feed a la base de firmas y devuelve un informe."""
    source_file = Path(source_path)
    target = Path(target_path)
    text = source_file.read_text(encoding="utf-8-sig", errors="replace")
    kind = detect_format(source_file, text, fmt)
    records = PARSERS[kind](text)
    report = ImportReport(source=source, fmt=kind, parsed=len(records), dry_run=dry_run)

    if target.is_file():
        database = json.loads(target.read_text(encoding="utf-8"))
    else:
        database = _new_database()
    if not isinstance(database, dict):
        raise TypeError("La base de firmas destino debe ser un objeto JSON")
    for key in ("hashes", "filenames", "content"):
        database.setdefault(key, {} if key == "hashes" else [])

    existing_ids = {
        str(item.get("id", ""))
        for item in [*database["filenames"], *database["content"], *database["hashes"].values()]
        if isinstance(item, dict)
    }
    existing_hashes = {str(item).lower() for item in database["hashes"]}
    prefix = _SAFE_ID.sub("-", source.upper()).strip("-") or "FEED"

    for index, record in enumerate(records, start=1):
        rule_id = record.rule_id or f"IOC-{prefix}-{index:04d}"
        rule_id = _SAFE_ID.sub("-", rule_id.upper()).strip("-") or f"IOC-{index:04d}"
        if rule_id in existing_ids:
            report.duplicates += 1
            continue
        try:
            severity = Severity.parse(record.severity).value
        except ValueError:
            severity = "high"
        description = record.description or f"IOC importado desde {source}"

        if record.kind == "hash":
            value = record.value.lower().strip()
            if not _HASH_RE.match(value):
                report.errors.append(f"SHA-256 inválido en el registro {index}")
                continue
            if value in existing_hashes:
                report.duplicates += 1
                continue
            database["hashes"][value] = {
                "id": rule_id,
                "severity": severity,
                "description": description,
            }
            existing_hashes.add(value)
            report.added_hashes += 1
        else:
            if len(record.value) > 4096:
                report.errors.append(f"Patrón demasiado largo en el registro {index}")
                continue
            try:
                re.compile(record.value.encode("utf-8"), re.IGNORECASE)
            except re.error as exc:
                report.errors.append(f"Patrón inválido en el registro {index}: {exc}")
                continue
            rule = {
                "id": rule_id,
                "pattern": record.value,
                "severity": severity,
                "description": description,
            }
            database["filenames" if record.kind == "filename" else "content"].append(rule)
            if record.kind == "filename":
                report.added_filenames += 1
            else:
                report.added_content += 1
        existing_ids.add(rule_id)

    current_revision = database.get("revision", 0)
    if not isinstance(current_revision, int) or current_revision < 0:
        current_revision = 0
    report.revision = revision if revision is not None else current_revision + 1
    database["revision"] = report.revision
    database["updated_at"] = utc_now()
    database["version"] = str(database.get("version", "imported"))

    if not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temp_name = tempfile.mkstemp(
            prefix="sentinel-feed-", suffix=".json", dir=str(target.parent)
        )
        temp = Path(temp_name)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                json.dump(database, stream, indent=2, ensure_ascii=False)
            if target.exists():
                shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
            temp.replace(target)
        finally:
            if temp.exists():
                temp.unlink()
    return report


__all__ = [
    "PARSERS",
    "ImportReport",
    "IocRecord",
    "detect_format",
    "import_feed",
    "parse_csv",
    "parse_json",
    "parse_misp",
]
