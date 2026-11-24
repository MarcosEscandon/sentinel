"""Integrity verification of Sentinel files and signatures.

The manifest stores POSIX relative paths, SHA-256 hashes, and sizes. It can be
generated for the source tree or for an installation directory and makes it
possible to detect deleted, modified, or added files.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from . import crypto
from .core.models import utc_now

ALGORITHM = "sha256"
_READ_CHUNK = 1024 * 1024
_EXCLUDED_DIRS = frozenset(
    {"__pycache__", ".pytest_cache", ".ruff_cache", "build", "dist", ".venv"}
)
# Only the manifest's own signature is excluded (if generated); all other .sig
# signatures in the package ARE verified to detect tampering.
_EXCLUDED_FILE_GLOBS = (
    "*.pyc",
    "*.key",
    "manifest.json.sig",
    "audit.jsonl",
    "*.db",
    "*.jsonl",
)


@dataclass(frozen=True)
class FileRecord:
    """A record for a file in the manifest."""

    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        """Returns the record as a serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        """Rebuilds a record from a ``files`` element of the JSON."""
        return cls(str(data["path"]), str(data["sha256"]), int(data["size"]))


@dataclass(frozen=True)
class IntegrityReport:
    """Result of comparing a tree with its manifest.

    ``expected``, ``missing``, ``modified``, and ``added`` are counts; the
    per-file detail (with status and hashes) is in ``details``.
    """

    ok: bool
    expected: int
    missing: int
    modified: int
    added: int
    details: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Returns the full report as a serializable dictionary."""
        return asdict(self)


def _relative(root: Path, target: Path) -> str | None:
    """Returns the POSIX relative path, or ``None`` if it is outside ``root``."""
    try:
        return target.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _matches_extra(relative: str, extra: tuple[str, ...]) -> bool:
    """Checks additional patterns against the path, the name, and their parts."""
    lowered = relative.lower()
    name = PurePosixPath(relative).name.lower()
    for raw in extra:
        pattern = raw.replace("\\", "/").lower()
        if not pattern:
            continue
        if pattern.endswith("/"):
            if lowered.startswith(pattern) or f"/{pattern}" in f"/{lowered}":
                return True
            pattern = pattern.rstrip("/")
        if not pattern:
            continue
        if fnmatch.fnmatch(lowered, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        if any(fnmatch.fnmatch(part, pattern) for part in lowered.split("/")):
            return True
    return False


def _is_excluded(relative: str, *, is_dir: bool, extra: tuple[str, ...]) -> bool:
    """Applies the default exclusions and those provided by the caller."""
    parts = relative.lower().split("/")
    # ``quarantine*`` refers to the quarantine store (directories), not to
    # modules such as ``sentinel/core/quarantine.py``.
    ancestors = parts if is_dir else parts[:-1]
    if any(
        part in _EXCLUDED_DIRS or part.startswith("quarantine") for part in ancestors
    ):
        return True
    if not is_dir and any(
        fnmatch.fnmatch(parts[-1], pattern) for pattern in _EXCLUDED_FILE_GLOBS
    ):
        return True
    return _matches_extra(relative, extra)


def _iter_files(root: Path, extra: tuple[str, ...] = ()) -> list[tuple[str, Path]]:
    """Lists non-excluded files as ``(relative_path, path)`` pairs."""
    found: list[tuple[str, Path]] = []
    for current, dirs, files in os.walk(root, topdown=True):
        base = Path(current)
        kept: list[str] = []
        for name in dirs:
            relative = _relative(root, base / name) or name
            if not _is_excluded(relative, is_dir=True, extra=extra):
                kept.append(name)
        dirs[:] = kept

        for name in files:
            path = base / name
            relative = _relative(root, path)
            if relative is None or _is_excluded(relative, is_dir=False, extra=extra):
                continue
            found.append((relative, path))
    return sorted(found, key=lambda item: item[0])


def _sha256(path: Path) -> str:
    """Computes the SHA-256 of a file by reading it in 1 MiB chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    root: str | Path, output: str | Path, exclude: Iterable[str] = ()
) -> dict[str, Any]:
    """Generates and writes a SHA-256 manifest of the ``root`` tree.

    The manifest itself is always excluded so that regenerating it does not add
    it as a new file. ``exclude`` accepts ``fnmatch`` patterns over the relative
    path, the name, or each component of the path.
    """
    root_path = Path(root)
    output_path = Path(output)
    extra = tuple(str(item) for item in exclude)
    output_relative = _relative(root_path, output_path)
    if output_relative is not None:
        extra += (output_relative,)

    records: list[dict[str, Any]] = []
    for relative, path in _iter_files(root_path, extra):
        try:
            size = path.stat().st_size
            digest = _sha256(path)
        except OSError:
            # The file may have disappeared while the tree was being walked.
            continue
        records.append(FileRecord(relative, digest, size).to_dict())

    manifest = {
        "generated_at": utc_now(),
        "algorithm": ALGORITHM,
        "files": records,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest


def _detail(
    status: str,
    path: str,
    expected: FileRecord | None,
    actual: FileRecord | None,
) -> dict[str, Any]:
    """Builds a uniform entry for ``IntegrityReport.details``."""
    return {
        "status": status,
        "path": path,
        "expected_sha256": expected.sha256 if expected is not None else None,
        "actual_sha256": actual.sha256 if actual is not None else None,
        "expected_size": expected.size if expected is not None else None,
        "actual_size": actual.size if actual is not None else None,
    }


def verify_manifest(root: str | Path, manifest: str | Path) -> IntegrityReport:
    """Compares the tree with a manifest and detects deletions, changes, and additions.

    Monitored files that no longer exist are counted as ``missing``; no exception
    is raised because of them. ``ValueError``/``TypeError`` is raised only if the
    manifest itself is missing or invalid.
    """
    root_path = Path(root)
    manifest_path = Path(manifest)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("The manifest must be a JSON object")
    if payload.get("algorithm") != ALGORITHM:
        raise ValueError(f"Unsupported algorithm: {payload.get('algorithm')!r}")
    raw_files = payload.get("files")
    if not isinstance(raw_files, list):
        raise TypeError("'files' must be a list")

    expected: dict[str, FileRecord] = {}
    for item in raw_files:
        record = FileRecord.from_dict(item)
        if record.path in expected:
            raise ValueError(f"Duplicate path in the manifest: {record.path}")
        expected[record.path] = record

    extra: tuple[str, ...] = ()
    manifest_relative = _relative(root_path, manifest_path)
    if manifest_relative is not None:
        extra = (manifest_relative,)
    current = dict(_iter_files(root_path, extra))

    details: list[dict[str, Any]] = []
    missing = 0
    modified = 0
    for relative, record in sorted(expected.items()):
        path = current.get(relative)
        if path is None or not path.is_file():
            missing += 1
            details.append(_detail("missing", relative, record, None))
            continue
        try:
            actual = FileRecord(relative, _sha256(path), path.stat().st_size)
        except OSError:
            missing += 1
            details.append(_detail("missing", relative, record, None))
            continue
        if actual.sha256 != record.sha256 or actual.size != record.size:
            modified += 1
            details.append(_detail("modified", relative, record, actual))

    added_paths = sorted(set(current) - set(expected))
    for relative in added_paths:
        path = current[relative]
        try:
            actual = FileRecord(relative, _sha256(path), path.stat().st_size)
        except OSError:
            actual = FileRecord(relative, "", 0)
        details.append(_detail("added", relative, None, actual))

    added = len(added_paths)
    return IntegrityReport(
        ok=missing == 0 and modified == 0 and added == 0,
        expected=len(expected),
        missing=missing,
        modified=modified,
        added=added,
        details=details,
    )


def verify_signatures_bundle(path: str | Path, public_key_path: str | Path) -> bool:
    """Verifies the separate Ed25519 signature of a signature package.

    It first looks for ``<path>.sig`` (the ``sentinel.updates`` convention) and,
    as an alternative, ``path.with_suffix('.sig')``. Returns ``False`` if the
    package, the signature, or the key is missing, or if the signature does not
    match.
    """
    bundle = Path(path)
    key = Path(public_key_path)
    if not bundle.is_file() or not key.is_file():
        return False

    candidates = [Path(f"{bundle}.sig"), bundle.with_suffix(".sig")]
    signature = next((candidate for candidate in candidates if candidate.is_file()), None)
    if signature is None:
        return False

    try:
        if not crypto.available():
            return False
        return crypto.verify_payload(bundle.read_bytes(), signature.read_bytes(), key)
    except (OSError, ValueError, TypeError, RuntimeError):
        # Includes SigningUnavailable (RuntimeError) and corrupt keys or signatures.
        return False


__all__ = [
    "ALGORITHM",
    "FileRecord",
    "IntegrityReport",
    "build_manifest",
    "verify_manifest",
    "verify_signatures_bundle",
]
