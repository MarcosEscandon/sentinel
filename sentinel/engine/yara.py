"""Optional YARA integration.

``yara-python`` is not a required dependency: if it is not installed, the
scanner still works with SHA-256 signatures, content rules, and heuristics.
To enable it::

    pip install -e ".[yara]"
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from ..core.models import Detection, RuleHit, Severity


class YaraUnavailable(RuntimeError):
    """Raised when YARA is requested but the module is not installed."""


class YaraEngine:
    """Compiles a set of YARA rules and applies them to a sample."""

    def __init__(self, rule_paths: list[str | Path] | None = None) -> None:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise YaraUnavailable(
                "yara-python is not installed. Install it with: pip install -e '.[yara]'"
            ) from exc

        self._yara = yara
        paths = [Path(item) for item in (rule_paths or [])]
        missing = [str(path) for path in paths if not path.is_file()]
        if missing:
            raise FileNotFoundError(f"YARA rules not found: {missing}")
        sources = {path.stem: str(path) for path in paths}
        self.rules = yara.compile(filepaths=sources) if sources else yara.compile(source="")
        self.rule_count = len(paths)

    @classmethod
    def available(cls) -> bool:
        return importlib.util.find_spec("yara") is not None

    def match(self, sample: bytes, file_size: int, timeout: int = 5) -> list[RuleHit]:
        try:
            matches = self.rules.match(data=sample, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - YARA raises its own exceptions
            return [
                RuleHit(
                    rule_id="YARA-ERROR",
                    detection=Detection.YARA,
                    severity=Severity.INFO,
                    description=f"Error evaluating YARA rules: {exc}",
                )
            ]

        hits: list[RuleHit] = []
        for match in matches:
            meta: dict[str, Any] = dict(match.meta or {})
            rule_id = str(meta.get("id") or match.rule)
            severity = Severity.parse(meta.get("severity", "medium"))
            description = str(meta.get("description") or f"YARA rule {match.rule}")
            indicators = tuple(
                f"{namespace}:{offset}" for namespace, offset, _ in (match.strings or [])[:8]
            )
            hits.append(
                RuleHit(
                    rule_id=rule_id,
                    detection=Detection.YARA,
                    severity=severity,
                    description=description,
                    indicators=indicators,
                )
            )
        return hits

    def stats(self) -> dict[str, Any]:
        return {"available": True, "rule_files": self.rule_count}
