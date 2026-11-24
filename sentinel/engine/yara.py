"""Integración opcional con YARA.

``yara-python`` no es una dependencia obligatoria: si no está instalado,
el escáner sigue funcionando con firmas SHA-256, reglas de contenido y
heurística. Para activarlo::

    pip install -e ".[yara]"
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from ..core.models import Detection, RuleHit, Severity


class YaraUnavailable(RuntimeError):
    """Se lanza cuando se solicita YARA pero el módulo no está instalado."""


class YaraEngine:
    """Compila un conjunto de reglas YARA y las aplica sobre una muestra."""

    def __init__(self, rule_paths: list[str | Path] | None = None) -> None:
        try:
            import yara  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - depende del entorno
            raise YaraUnavailable(
                "yara-python no está instalado. Instálalo con: pip install -e '.[yara]'"
            ) from exc

        self._yara = yara
        paths = [Path(item) for item in (rule_paths or [])]
        missing = [str(path) for path in paths if not path.is_file()]
        if missing:
            raise FileNotFoundError(f"Reglas YARA no encontradas: {missing}")
        sources = {path.stem: str(path) for path in paths}
        self.rules = yara.compile(filepaths=sources) if sources else yara.compile(source="")
        self.rule_count = len(paths)

    @classmethod
    def available(cls) -> bool:
        return importlib.util.find_spec("yara") is not None

    def match(self, sample: bytes, file_size: int, timeout: int = 5) -> list[RuleHit]:
        try:
            matches = self.rules.match(data=sample, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - YARA lanza sus propias excepciones
            return [
                RuleHit(
                    rule_id="YARA-ERROR",
                    detection=Detection.YARA,
                    severity=Severity.INFO,
                    description=f"Error al evaluar reglas YARA: {exc}",
                )
            ]

        hits: list[RuleHit] = []
        for match in matches:
            meta: dict[str, Any] = dict(match.meta or {})
            rule_id = str(meta.get("id") or match.rule)
            severity = Severity.parse(meta.get("severity", "medium"))
            description = str(meta.get("description") or f"Regla YARA {match.rule}")
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
