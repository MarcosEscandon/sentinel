"""Base de datos de firmas y reglas de coincidencia.

Formato de ``signatures.json`` (esquema 1)::

    {
      "schema": 1,
      "version": "2026-11-23",
      "updated_at": "2026-11-23T00:00:00+00:00",
      "hashes": {
        "<sha256>": {
          "id": "TEST-001",
          "severity": "high",
          "description": "..."
        }
      },
      "filenames": [
        {"id": "FN-001", "pattern": "\\\\.doc\\\\.exe$",
         "severity": "medium", "description": "..."}
      ],
      "content": [
        {"id": "CT-001", "pattern": "sospechoso", "severity": "low",
         "description": "...", "max_size": 1048576}
      ]
    }

Las reglas ``content`` se compilan como expresiones regulares sobre bytes;
por eso conviene usar patrones ASCII y escapar correctamente el JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.models import Detection, RuleHit, Severity, utc_now

try:  # ``regex`` permite limitar el tiempo de evaluación; ``re`` es el fallback.
    import regex as _engine

    _TIMEOUT_SUPPORTED = True
except ImportError:  # pragma: no cover - depende del entorno
    _engine = re
    _TIMEOUT_SUPPORTED = False

SCHEMA_VERSION = 1
DEFAULT_RULE_TIMEOUT_MS = 100.0
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _search(rule: _CompiledRule, data: bytes, timeout_ms: float) -> Any:
    if _TIMEOUT_SUPPORTED:
        return rule.regex.search(data, timeout=timeout_ms / 1000.0)
    return rule.regex.search(data)


@dataclass(frozen=True)
class _CompiledRule:
    rule_id: str
    regex: Any
    detection: Detection
    severity: Severity
    description: str
    max_size: int | None = None


def _required_str(item: dict[str, Any], key: str, context: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}: '{key}' debe ser una cadena no vacía")
    return value.strip()


def _compile_rule(
    item: Any, detection: Detection, index: int, section: str
) -> _CompiledRule:
    if not isinstance(item, dict):
        raise TypeError(f"{section}[{index}]: se esperaba un objeto")
    context = f"{section}[{index}]"
    rule_id = _required_str(item, "id", context)
    pattern = _required_str(item, "pattern", context)
    severity = Severity.parse(item.get("severity", "medium"))
    description = _required_str(item, "description", context)
    flags = re.IGNORECASE
    if item.get("dotall"):
        flags |= re.DOTALL
    try:
        regex = _engine.compile(pattern.encode("utf-8"), flags)
    except _engine.error as exc:
        raise ValueError(f"{context}: patrón inválido: {exc}") from exc
    max_size = item.get("max_size")
    if max_size is not None and (not isinstance(max_size, int) or max_size < 0):
        raise ValueError(f"{context}: max_size debe ser un entero >= 0")
    return _CompiledRule(rule_id, regex, detection, severity, description, max_size)


class SignatureDatabase:
    """Conjunto inmutable de firmas cargadas desde un JSON."""

    def __init__(
        self,
        hashes: dict[str, dict[str, Any]],
        filename_rules: list[_CompiledRule],
        content_rules: list[_CompiledRule],
        version: str = "local",
        updated_at: str = "",
        revision: int = 0,
        rule_timeout_ms: float = DEFAULT_RULE_TIMEOUT_MS,
    ) -> None:
        self.hashes = hashes
        self._filename_rules = filename_rules
        self._content_rules = content_rules
        self.version = version
        self.updated_at = updated_at or utc_now()
        self.revision = revision
        self.rule_timeout_ms = rule_timeout_ms

    @classmethod
    def from_dict(cls, payload: Any) -> SignatureDatabase:
        if not isinstance(payload, dict):
            raise TypeError("La base de firmas debe ser un objeto JSON")
        schema = payload.get("schema", SCHEMA_VERSION)
        if schema != SCHEMA_VERSION:
            raise ValueError(
                f"Esquema de firmas no soportado: {schema!r} (se espera {SCHEMA_VERSION})"
            )

        raw_hashes = payload.get("hashes", {})
        if not isinstance(raw_hashes, dict):
            raise TypeError("'hashes' debe ser un objeto")
        hashes: dict[str, dict[str, Any]] = {}
        for digest, meta in raw_hashes.items():
            key = str(digest).lower().strip()
            if not _HEX64.match(key):
                raise ValueError(f"Hash inválido en la base de firmas: {digest!r}")
            if not isinstance(meta, dict):
                raise TypeError(f"Metadatos inválidos para el hash {digest}")
            rule_id = _required_str(meta, "id", f"hashes[{digest}]")
            description = _required_str(meta, "description", f"hashes[{digest}]")
            severity = Severity.parse(meta.get("severity", "high"))
            hashes[key] = {
                "id": rule_id,
                "severity": severity,
                "description": description,
            }

        revision = payload.get("revision", 0)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise ValueError("'revision' debe ser un entero >= 0")

        filename_rules = [
            _compile_rule(item, Detection.FILENAME, i, "filenames")
            for i, item in enumerate(payload.get("filenames", []))
        ]
        content_rules = [
            _compile_rule(item, Detection.CONTENT, i, "content")
            for i, item in enumerate(payload.get("content", []))
        ]
        return cls(
            hashes=hashes,
            filename_rules=filename_rules,
            content_rules=content_rules,
            version=str(payload.get("version", "local")),
            updated_at=str(payload.get("updated_at", "")),
            revision=revision,
        )

    @classmethod
    def load(cls, path: str | Path) -> SignatureDatabase:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(payload)

    @classmethod
    def empty(cls) -> SignatureDatabase:
        return cls({}, [], [], version="empty")

    def match_hash(self, digest: str) -> list[RuleHit]:
        meta = self.hashes.get(digest.lower())
        if meta is None:
            return []
        return [
            RuleHit(
                rule_id=meta["id"],
                detection=Detection.HASH,
                severity=meta["severity"],
                description=meta["description"],
            )
        ]

    def match_filename(self, name: str) -> list[RuleHit]:
        encoded = name.encode("utf-8", errors="ignore")
        hits: list[RuleHit] = []
        for rule in self._filename_rules:
            try:
                matched = _search(rule, encoded, self.rule_timeout_ms) is not None
            except TimeoutError:
                hits.append(self._timeout_hit(rule, Detection.FILENAME))
                continue
            if matched:
                hits.append(
                    RuleHit(
                        rule_id=rule.rule_id,
                        detection=rule.detection,
                        severity=rule.severity,
                        description=rule.description,
                        indicators=(
                            f"nombre coincide con /{rule.regex.pattern.decode('utf-8', 'ignore')}/",
                        ),
                    )
                )
        return hits

    def match_content(self, sample: bytes, file_size: int) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in self._content_rules:
            if rule.max_size is not None and file_size > rule.max_size:
                continue
            try:
                match = _search(rule, sample, self.rule_timeout_ms)
            except TimeoutError:
                hits.append(self._timeout_hit(rule, Detection.CONTENT))
                continue
            if match is not None:
                token = match.group(0)[:80].decode("utf-8", errors="replace")
                hits.append(
                    RuleHit(
                        rule_id=rule.rule_id,
                        detection=rule.detection,
                        severity=rule.severity,
                        description=rule.description,
                        indicators=(f"contenido coincide con {token!r}",),
                    )
                )
        return hits

    def check_rollback(self, current: SignatureDatabase) -> None:
        """Rechaza una base más antigua que la instalada."""
        if self.revision < current.revision:
            raise ValueError(
                f"Rollback detectado: la descarga es revisión {self.revision} "
                f"y la instalada es {current.revision}"
            )

    def _timeout_hit(self, rule: _CompiledRule, detection: Detection) -> RuleHit:
        return RuleHit(
            rule_id="RULE-TIMEOUT",
            detection=detection,
            severity=Severity.INFO,
            description=(
                f"La regla {rule.rule_id} superó el límite de {self.rule_timeout_ms:g} ms "
                "y se omitió"
            ),
            indicators=(rule.rule_id,),
        )

    def stats(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "hashes": len(self.hashes),
            "filename_rules": len(self._filename_rules),
            "content_rules": len(self._content_rules),
            "timeout_ms": self.rule_timeout_ms,
            "timeout_support": _TIMEOUT_SUPPORTED,
        }
