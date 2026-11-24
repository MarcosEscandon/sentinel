"""Verificación de integridad de archivos y de firmas de Sentinel.

El manifiesto guarda rutas relativas POSIX, SHA-256 y tamaño. Puede generarse
para el árbol de fuentes o para el directorio de una instalación y permite
detectar archivos borrados, modificados o añadidos.
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
# Solo se excluye la firma del propio manifiesto (si se genera); el resto de
# firmas .sig del paquete SÍ se verifican para detectar manipulaciones.
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
    """Registro de un archivo dentro del manifiesto."""

    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        """Devuelve el registro como diccionario serializable."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        """Reconstruye un registro desde un elemento de ``files`` del JSON."""
        return cls(str(data["path"]), str(data["sha256"]), int(data["size"]))


@dataclass(frozen=True)
class IntegrityReport:
    """Resultado de comparar un árbol con su manifiesto.

    ``expected``, ``missing``, ``modified`` y ``added`` son recuentos; el
    detalle por archivo (con estado y hashes) está en ``details``.
    """

    ok: bool
    expected: int
    missing: int
    modified: int
    added: int
    details: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Devuelve el informe completo como diccionario serializable."""
        return asdict(self)


def _relative(root: Path, target: Path) -> str | None:
    """Devuelve la ruta relativa POSIX, o ``None`` si queda fuera de ``root``."""
    try:
        return target.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _matches_extra(relative: str, extra: tuple[str, ...]) -> bool:
    """Comprueba patrones adicionales contra la ruta, el nombre y sus partes."""
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
    """Aplica las exclusiones por defecto y las proporcionadas por el caller."""
    parts = relative.lower().split("/")
    # ``quarantine*`` se refiere al almacén de cuarentena (directorios), no a
    # módulos como ``sentinel/core/quarantine.py``.
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
    """Lista archivos no excluidos como pares ``(ruta_relativa, ruta)``."""
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
    """Calcula el SHA-256 de un archivo leyendo en bloques de 1 MiB."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    root: str | Path, output: str | Path, exclude: Iterable[str] = ()
) -> dict[str, Any]:
    """Genera y escribe un manifiesto SHA-256 del árbol ``root``.

    El propio manifiesto se excluye siempre para que regenerarlo no lo añada
    como archivo nuevo. ``exclude`` admite patrones ``fnmatch`` sobre la ruta
    relativa, el nombre o cada componente del camino.
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
            # El archivo pudo desaparecer mientras se recorría el árbol.
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
    """Construye una entrada uniforme para ``IntegrityReport.details``."""
    return {
        "status": status,
        "path": path,
        "expected_sha256": expected.sha256 if expected is not None else None,
        "actual_sha256": actual.sha256 if actual is not None else None,
        "expected_size": expected.size if expected is not None else None,
        "actual_size": actual.size if actual is not None else None,
    }


def verify_manifest(root: str | Path, manifest: str | Path) -> IntegrityReport:
    """Compara el árbol con un manifiesto y detecta borrados, cambios y altas.

    Los archivos supervisados que ya no existen se contabilizan como
    ``missing``; nunca se lanza una excepción por ellos. Sí se lanza
    ``ValueError``/``TypeError`` si el propio manifiesto no existe o es inválido.
    """
    root_path = Path(root)
    manifest_path = Path(manifest)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("El manifiesto debe ser un objeto JSON")
    if payload.get("algorithm") != ALGORITHM:
        raise ValueError(f"Algoritmo no soportado: {payload.get('algorithm')!r}")
    raw_files = payload.get("files")
    if not isinstance(raw_files, list):
        raise TypeError("'files' debe ser una lista")

    expected: dict[str, FileRecord] = {}
    for item in raw_files:
        record = FileRecord.from_dict(item)
        if record.path in expected:
            raise ValueError(f"Ruta duplicada en el manifiesto: {record.path}")
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
    """Verifica la firma Ed25519 separada de un paquete de firmas.

    Se busca primero ``<path>.sig`` (convención de ``sentinel.updates``) y,
    como alternativa, ``path.with_suffix('.sig')``. Devuelve ``False`` si
    faltan el paquete, la firma o la clave, o si la firma no coincide.
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
        # Incluye SigningUnavailable (RuntimeError) y claves o firmas corruptas.
        return False


__all__ = [
    "ALGORITHM",
    "FileRecord",
    "IntegrityReport",
    "build_manifest",
    "verify_manifest",
    "verify_signatures_bundle",
]
