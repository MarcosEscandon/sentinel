"""Scanner configuration."""

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
    """Adjustable analysis parameters.

    The defaults are designed for a user scan: fast, with size limits, and
    without following links that could create loops.
    """

    max_file_size: int = 128 * 1024 * 1024
    """Maximum file size to analyze (bytes)."""

    sample_size: int = 1024 * 1024
    """Bytes read for heuristics and content rules."""

    hash_all: bool = True
    """Calculate SHA-256 for all files, not just candidates."""

    follow_symlinks: bool = False
    exclude_dirs: frozenset[str] = field(default_factory=lambda: DEFAULT_EXCLUDES)
    include_extensions: frozenset[str] | None = None
    """If set, only these extensions are analyzed (with a dot, lowercase)."""

    entropy_threshold: float = 7.4
    entropy_min_size: int = 4096
    suspicion_threshold: float = 5.0
    use_heuristics: bool = True
    use_yara: bool = True
    jobs: int = 1
    """Number of scan threads (1 = sequential)."""

    scan_containers: bool = True
    """Unpack ZIP/TAR/GZ/BZ2/XZ archives and analyze their content."""

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
            raise ValueError(f"Unknown configuration keys: {sorted(unknown)}")
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
            raise TypeError("The configuration file must contain a JSON object")
        return cls.from_dict(payload)

    def validate(self) -> None:
        if self.max_file_size <= 0:
            raise ValueError("max_file_size must be positive")
        if not 0 < self.sample_size <= self.max_file_size:
            raise ValueError("sample_size must be between 1 and max_file_size")
        if not 0.0 <= self.entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold must be between 0 and 8")
        if self.suspicion_threshold < 0:
            raise ValueError("suspicion_threshold cannot be negative")
        if not 1 <= self.jobs <= 64:
            raise ValueError("jobs must be between 1 and 64")
        for name in (
            "container_max_entries",
            "container_max_uncompressed",
            "container_max_depth",
            "container_max_ratio",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
