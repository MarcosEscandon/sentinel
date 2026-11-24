"""Configuración del escáner."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_EXCLUDES = frozenset(
    {
        "$recycle.bin",
        "system volume information",
        "$windows.~ws",
        "$windows.~bt",
        "node_modules",
        ".git",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
    }
)


@dataclass
class ScanConfig:
    """Parámetros ajustables del análisis.

    Los valores por defecto están pensados para un escaneo de usuario: rápido,
    con límites de tamaño y sin seguir enlaces que puedan generar bucles.
    """

    max_file_size: int = 128 * 1024 * 1024
    """Tamaño máximo de archivo a analizar (bytes)."""

    sample_size: int = 1024 * 1024
    """Bytes leídos para heurística y reglas de contenido."""

    hash_all: bool = True
    """Calcular SHA-256 de todos los archivos, no solo de los candidatos."""

    follow_symlinks: bool = False
    exclude_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_EXCLUDES)
    include_extensions: frozenset[str] | None = None
    """Si se define, solo se analizan estos extensiones (con punto, en minúsculas)."""

    entropy_threshold: float = 7.4
    entropy_min_size: int = 4096
    suspicion_threshold: float = 5.0
    use_heuristics: bool = True
    use_yara: bool = True
    jobs: int = 1
    """Número de hilos de escaneo (1 = secuencial)."""

    scan_containers: bool = True
    """Descomprime ZIP/TAR/GZ/BZ2/XZ y analiza su contenido."""

    container_max_entries: int = 500
    container_max_uncompressed: int = 64 * 1024 * 1024
    container_max_depth: int = 3
    container_max_ratio: int = 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_file_size": self.max_file_size,
            "sample_size": self.sample_size,
            "hash_all": self.hash_all,
            "follow_symlinks": self.follow_symlinks,
            "exclude_dirs": sorted(self.exclude_dirs),
            "include_extensions": (
                sorted(self.include_extensions) if self.include_extensions is not None else None
            ),
            "entropy_threshold": self.entropy_threshold,
            "entropy_min_size": self.entropy_min_size,
            "suspicion_threshold": self.suspicion_threshold,
            "use_heuristics": self.use_heuristics,
            "use_yara": self.use_yara,
            "jobs": self.jobs,
            "scan_containers": self.scan_containers,
            "container_max_entries": self.container_max_entries,
            "container_max_uncompressed": self.container_max_uncompressed,
            "container_max_depth": self.container_max_depth,
            "container_max_ratio": self.container_max_ratio,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanConfig:
        known = {item for item in cls().to_dict()}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Claves de configuración desconocidas: {sorted(unknown)}")
        cfg = cls()
        for key, value in data.items():
            if key == "exclude_dirs":
                value = frozenset(str(item).lower() for item in value)
            elif key == "include_extensions":
                value = (
                    frozenset(str(item).lower() for item in value)
                    if value is not None
                    else None
                )
            setattr(cfg, key, value)
        cfg.validate()
        return cfg

    @classmethod
    def from_file(cls, path: str | Path) -> ScanConfig:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("El archivo de configuración debe contener un objeto JSON")
        return cls.from_dict(payload)

    def validate(self) -> None:
        if self.max_file_size <= 0:
            raise ValueError("max_file_size debe ser positivo")
        if not 0 < self.sample_size <= self.max_file_size:
            raise ValueError("sample_size debe estar entre 1 y max_file_size")
        if not 0.0 <= self.entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold debe estar entre 0 y 8")
        if self.suspicion_threshold < 0:
            raise ValueError("suspicion_threshold no puede ser negativo")
        if not 1 <= self.jobs <= 64:
            raise ValueError("jobs debe estar entre 1 y 64")
        for name in (
            "container_max_entries",
            "container_max_uncompressed",
            "container_max_depth",
            "container_max_ratio",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} debe ser positivo")
