"""Quarantine management with integrity verification.

Files are renamed to a UUID inside ``<dir>/files`` and recorded in
``index.json``. Nothing is deleted until ``delete`` is explicitly requested.

Integrity:

* each entry stores the file's actual SHA-256 in ``stored_sha256``;
* the index carries an HMAC-SHA256 computed with a key located outside the
  quarantine directory (``<home>/quarantine.key``);
* ``restore()`` rejects modified entries. ``delete()`` and ``prune()`` still
  work so that damaged entries can be cleaned up.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import utc_now

_UUID_RE = re.compile(r"^[0-9a-f]{32}$")


class QuarantineIntegrityError(Exception):
    """The quarantine or one of its files was modified without authorization."""


def _file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    original_name: str
    stored_path: str
    sha256: str
    size: int
    reason: str
    quarantined_at: str = field(default_factory=utc_now)
    stored_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QuarantineEntry:
        return cls(
            id=str(data["id"]),
            original_path=str(data["original_path"]),
            original_name=str(data["original_name"]),
            stored_path=str(data["stored_path"]),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size", 0)),
            reason=str(data.get("reason", "")),
            quarantined_at=str(data.get("quarantined_at", utc_now())),
            stored_sha256=str(data.get("stored_sha256", "")),
        )


class Quarantine:
    """Reversible, tamper-evident store for detected files."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.files_dir = self.directory / "files"
        self.index_path = self.directory / "index.json"
        self.key_path = self.directory.parent / "quarantine.key"
        self.index_tampered = False

    def _ensure(self) -> None:
        self.files_dir.mkdir(parents=True, exist_ok=True)

    def _load_key(self) -> bytes:
        try:
            data = self.key_path.read_bytes()
            if len(data) < 32:
                raise QuarantineIntegrityError(f"Invalid quarantine key: {self.key_path}")
            return data
        except FileNotFoundError:
            pass
        data = secrets.token_bytes(32)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(str(self.key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self._load_key()
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        return data

    @staticmethod
    def _canonical(entries: list[QuarantineEntry]) -> bytes:
        payload = {
            "version": 2,
            "entries": sorted((item.to_dict() for item in entries), key=lambda item: item["id"]),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )

    def _read_index(self) -> list[QuarantineEntry]:
        self.index_tampered = False
        if not self.index_path.exists():
            return []
        try:
            payload = json.loads(self.index_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError("the index must be an object")
            entries = payload.get("entries", [])
            if not isinstance(entries, list):
                raise TypeError("'entries' must be a list")
        except (OSError, json.JSONDecodeError, TypeError, AttributeError):
            self.index_tampered = True
            return []

        result: list[QuarantineEntry] = []
        for item in entries:
            try:
                result.append(QuarantineEntry.from_dict(item))
            except (KeyError, TypeError, ValueError):
                self.index_tampered = True

        mac = payload.get("mac")
        expected = hmac.new(self._load_key(), self._canonical(result), hashlib.sha256).hexdigest()
        if not isinstance(mac, str) or not hmac.compare_digest(mac, expected):
            self.index_tampered = True
        return result

    def _write_index(self, entries: list[QuarantineEntry]) -> None:
        self._ensure()
        temporary = self.index_path.with_suffix(".json.tmp")
        payload = {
            "version": 2,
            "entries": [item.to_dict() for item in entries],
            "mac": hmac.new(self._load_key(), self._canonical(entries), hashlib.sha256).hexdigest(),
        }
        temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.index_path)

    def add(self, path: str | Path, reason: str = "", sha256: str = "") -> str:
        """Moves a file to quarantine and returns its identifier."""
        source = Path(path)
        if not source.is_file():
            raise FileNotFoundError(f"File does not exist: {source}")
        self._ensure()
        actual_sha256 = _file_sha256(source)
        entry_id = uuid.uuid4().hex
        stored = self.files_dir / f"{entry_id}.qtn"
        size = source.stat().st_size
        shutil.move(str(source), str(stored))
        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(source.resolve()),
            original_name=source.name,
            stored_path=str(stored),
            sha256=sha256 or actual_sha256,
            size=size,
            reason=reason,
            stored_sha256=actual_sha256,
        )
        entries = self._read_index()
        entries.append(entry)
        self._write_index(entries)
        return entry_id

    def list(self) -> list[QuarantineEntry]:
        return sorted(self._read_index(), key=lambda item: item.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> QuarantineEntry:
        self._validate_id(entry_id)
        for entry in self._read_index():
            if entry.id == entry_id:
                return entry
        raise KeyError(f"Quarantine entry not found: {entry_id}")

    def verify_entry(self, entry_id: str) -> bool:
        """Checks the index MAC and the hash/size of the stored file."""
        entry = self.get(entry_id)
        if self.index_tampered:
            raise QuarantineIntegrityError("The quarantine index was modified")
        stored = Path(entry.stored_path)
        if not stored.is_file():
            raise QuarantineIntegrityError(f"Missing quarantined file: {stored}")
        if entry.size and stored.stat().st_size != entry.size:
            raise QuarantineIntegrityError(f"Modified size in entry {entry_id}")
        actual = _file_sha256(stored)
        expected = entry.stored_sha256 or entry.sha256
        if expected and actual.lower() != expected.lower():
            raise QuarantineIntegrityError(f"Modified hash in entry {entry_id}")
        return True

    def verify_all(self) -> list[tuple[QuarantineEntry, str]]:
        """Returns ``(entry, error)`` for each item; the error is empty if valid."""
        checked: list[tuple[QuarantineEntry, str]] = []
        for entry in self.list():
            try:
                self.verify_entry(entry.id)
                error = ""
            except QuarantineIntegrityError as exc:
                error = str(exc)
            checked.append((entry, error))
        return checked

    def restore(self, entry_id: str, overwrite: bool = False) -> Path:
        """Returns the file to its original path if it passes verification."""
        self.verify_entry(entry_id)
        entry = self.get(entry_id)
        stored = Path(entry.stored_path)
        destination = Path(entry.original_path)
        if destination.exists() and not overwrite:
            raise FileExistsError(
                f"Original path is already occupied: {destination}. Use --overwrite."
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination.unlink()
        shutil.move(str(stored), str(destination))
        self._remove_entry(entry_id)
        return destination

    def delete(self, entry_id: str) -> None:
        """Permanently deletes an entry and its file."""
        entry = self.get(entry_id)
        stored = Path(entry.stored_path)
        if stored.is_file():
            stored.unlink()
        self._remove_entry(entry_id)

    def prune(self, days: int = 30) -> int:
        """Deletes entries older than ``days`` days. Returns the number removed."""
        if days < 0:
            raise ValueError("days must be >= 0")
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        removed = 0
        for entry in list(self._read_index()):
            try:
                timestamp = datetime.fromisoformat(entry.quarantined_at)
            except ValueError:
                continue
            if timestamp < cutoff:
                self.delete(entry.id)
                removed += 1
        return removed

    def _remove_entry(self, entry_id: str) -> None:
        self._write_index([item for item in self._read_index() if item.id != entry_id])

    @staticmethod
    def _validate_id(entry_id: str) -> None:
        if not _UUID_RE.match(entry_id):
            raise ValueError(f"Invalid quarantine ID: {entry_id!r}")


__all__ = ["Quarantine", "QuarantineEntry", "QuarantineIntegrityError"]
