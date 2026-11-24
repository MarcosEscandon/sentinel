"""Lista de exclusión para evitar falsos positivos y auto-detección.

Formato de ``allowlist.json``::

    {
      "version": 1,
      "paths": ["C:\\\\Tools\\\\known-good.exe"],
      "directories": ["C:\\\\Program Files\\\\MiApp"],
      "globs": ["C:\\\\Users\\\\*\\\\AppData\\\\Local\\\\Temp\\\\sentinel-*\\\\**"],
      "hashes": ["<sha256>"]
    }
"""

from __future__ import annotations

import fnmatch
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def normalize_path(path: str | Path) -> str:
    """Normaliza una ruta para comparaciones insensibles a mayúsculas."""
    candidate = Path(path)
    try:
        candidate = candidate.resolve()
    except OSError:
        pass
    return os.path.normcase(os.path.normpath(str(candidate)))


@dataclass(frozen=True)
class AllowList:
    """Conjunto de reglas que eximen a un archivo del análisis."""

    paths: frozenset[str] = frozenset()
    directories: frozenset[str] = frozenset()
    globs: frozenset[str] = frozenset()
    hashes: frozenset[str] = frozenset()
    sources: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, payload: Any, source: str = "") -> AllowList:
        if not isinstance(payload, dict):
            raise TypeError("La allowlist debe ser un objeto JSON")
        version = payload.get("version", 1)
        if version != 1:
            raise ValueError(f"Versión de allowlist no soportada: {version!r}")

        def strings(key: str) -> frozenset[str]:
            values = payload.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise ValueError(f"'{key}' debe ser una lista de cadenas")
            return frozenset(item for item in values if item.strip())

        hashes = frozenset(item.lower().strip() for item in strings("hashes"))
        return cls(
            paths=frozenset(normalize_path(item) for item in strings("paths")),
            directories=frozenset(normalize_path(item) for item in strings("directories")),
            globs=strings("globs"),
            hashes=hashes,
            sources=(source,) if source else (),
        )

    @classmethod
    def load(cls, path: str | Path, *, required: bool = False) -> AllowList:
        candidate = Path(path)
        if not candidate.is_file():
            if required:
                raise FileNotFoundError(f"Allowlist no encontrada: {candidate}")
            return cls()
        return cls.from_dict(
            json.loads(candidate.read_text(encoding="utf-8")), source=str(candidate)
        )

    @classmethod
    def combine(cls, *lists: AllowList) -> AllowList:
        sources: list[str] = []
        for item in lists:
            sources.extend(item.sources)
        return cls(
            paths=frozenset().union(*(item.paths for item in lists)),
            directories=frozenset().union(*(item.directories for item in lists)),
            globs=frozenset().union(*(item.globs for item in lists)),
            hashes=frozenset().union(*(item.hashes for item in lists)),
            sources=tuple(dict.fromkeys(sources)),
        )

    @classmethod
    def for_self(cls, directories: Iterable[str | Path]) -> AllowList:
        """Excluye los directorios propios de la aplicación."""
        return cls(
            directories=frozenset(normalize_path(item) for item in directories),
            sources=("auto:self-exclusion",),
        )

    @classmethod
    def for_files(cls, paths: Iterable[str | Path]) -> AllowList:
        """Excluye archivos concretos (por ejemplo, el informe JSON)."""
        return cls(
            paths=frozenset(normalize_path(item) for item in paths),
            sources=("auto:files",),
        )

    def allows_path(self, path: str | Path) -> bool:
        candidate = normalize_path(path)
        if candidate in self.paths:
            return True
        if any(
            candidate == directory or candidate.startswith(directory + os.sep)
            for directory in self.directories
        ):
            return True
        return any(fnmatch.fnmatchcase(candidate, pattern) for pattern in self.globs)

    def allows_hash(self, digest: str) -> bool:
        return bool(digest) and digest.lower() in self.hashes

    def stats(self) -> dict[str, Any]:
        return {
            "paths": len(self.paths),
            "directories": len(self.directories),
            "globs": len(self.globs),
            "hashes": len(self.hashes),
            "sources": list(self.sources),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "paths": sorted(self.paths),
            "directories": sorted(self.directories),
            "globs": sorted(self.globs),
            "hashes": sorted(self.hashes),
        }


__all__ = ["AllowList", "normalize_path"]
