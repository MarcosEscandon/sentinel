"""Autoevaluación de seguridad de una instalación de Sentinel.

El comando ``sentinel audit`` ejecuta comprobaciones reales sobre la base de
firmas, la cuarentena, el registro de auditoría, las exclusiones, el monitor en
tiempo real y la configuración. Ninguna comprobación lanza excepciones hacia
la CLI: los errores se convierten en ``AuditCheck(passed=False)``.

La clave pública utilizada por ``signatures.signed`` se resuelve, en este
orden, desde ``SENTINEL_PUBLIC_KEY``, ``<home>/signing.pub`` y
``<signatures>.pub``. La CLI solo recibe la clave como opción de
``sentinel signatures update --public-key``; no existe una configuración
persistente, por lo que esta auditoría define esa convención explícitamente.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import crypto
from .config import ScanConfig
from .core.allowlist import AllowList
from .core.logging import AuditLogger
from .core.quarantine import Quarantine
from .engine.signatures import SignatureDatabase
from .realtime import available_backends

PUBLIC_KEY_ENV = "SENTINEL_PUBLIC_KEY"
"""Variable de entorno con la ruta a la clave pública de confianza."""

AUDIT_EVENT = "audit.check"
"""Evento de prueba escrito por la comprobación ``logging.enabled``."""

_REMEDIAR_BASE = "Repara o sustituye signatures.json y ejecuta `sentinel signatures validate`."
_REMEDIAR_FIRMA = (
    "Producción exige firma Ed25519: genera un par con `sentinel keys generate`, firma "
    "con `sentinel signatures sign --key <privada> --output <signatures>.sig` y "
    "distribuye la clave pública por un canal seguro."
)
_REMEDIAR_CLAVE = (
    f"Configura {PUBLIC_KEY_ENV}=<ruta.pem> o copia la clave pública a "
    "<home>/signing.pub o junto a la base como <signatures>.pub."
)
_REMEDIAR_CUARENTENA = (
    "No restaures entradas alteradas; conserva el índice y la clave, e investiga "
    "el cambio con `sentinel quarantine verify`."
)
_REMEDIAR_LOG = (
    "Comprueba que <home> es escribible y que audit.jsonl no ha sido editado a mano."
)
_REMEDIAR_ALLOWLIST = (
    "Revisa AllowList.for_self: la auto-exclusión es necesaria para evitar auto-detección."
)
_REMEDIAR_REALTIME = "Instala `watchdog` o verifica el backend nativo de Windows (ctypes)."
_REMEDIAR_CONFIG = "Corrige los límites anti-bomba en el JSON pasado con --config-file."
_REMEDIAR_HOME = (
    "Usa %ProgramData%\\Sentinel u otra ruta escribible fuera de Windows/Program Files."
)

_CheckResult = tuple[bool, str, str]


@dataclass
class AuditCheck:
    """Resultado de una comprobación concreta de la autoevaluación."""

    name: str
    passed: bool
    detail: str
    remediation: str = ""


@dataclass
class SecurityAudit:
    """Informe agregado con todas las comprobaciones ejecutadas."""

    home: Path
    signatures: Path
    checks: list[AuditCheck]

    @property
    def passed(self) -> bool:
        """``True`` solo si hay comprobaciones y todas pasaron."""
        return bool(self.checks) and all(check.passed for check in self.checks)

    @property
    def failures(self) -> list[AuditCheck]:
        """Comprobaciones fallidas, en el orden en que se ejecutaron."""
        return [check for check in self.checks if not check.passed]

    @property
    def score(self) -> int:
        """Porcentaje de comprobaciones superadas (0-100)."""
        if not self.checks:
            return 0
        ok = sum(1 for check in self.checks if check.passed)
        return round(100 * ok / len(self.checks))

    def to_dict(self) -> dict[str, Any]:
        """Serialización JSON-compatible, con las propiedades calculadas."""
        return {
            "home": str(self.home),
            "signatures": str(self.signatures),
            "passed": self.passed,
            "score": self.score,
            "failures": [asdict(check) for check in self.failures],
            "checks": [asdict(check) for check in self.checks],
        }


def _check(
    name: str,
    fallback_remediation: str,
    operation: Callable[[], _CheckResult],
) -> AuditCheck:
    """Ejecuta una comprobación y convierte cualquier error en un fallo."""
    try:
        passed, detail, remediation = operation()
        return AuditCheck(name, bool(passed), str(detail), str(remediation))
    except Exception as exc:  # noqa: BLE001 - la auditoría nunca debe propagar errores
        return AuditCheck(
            name,
            False,
            f"{type(exc).__name__}: {exc}",
            fallback_remediation,
        )


def _check_signatures_valid(signatures: Path) -> _CheckResult:
    """Carga y valida la base, exigiendo una revisión estrictamente positiva."""
    database = SignatureDatabase.load(signatures)
    # Una base vacía (revisión 0) es válida como punto de partida, pero no como
    # base instalada: ``check_rollback`` verifica que no retrocedemos desde ahí.
    database.check_rollback(SignatureDatabase.empty())
    stats = database.stats()
    revision = database.revision
    if not isinstance(revision, int) or isinstance(revision, bool) or revision <= 0:
        return (
            False,
            f"revisión inválida: {revision!r} (debe ser un entero > 0)",
            _REMEDIAR_BASE,
        )
    detail = (
        f"base válida: revisión {revision}, {stats['hashes']} hashes, "
        f"{stats['content_rules']} reglas de contenido"
    )
    return True, detail, ""


def _public_key_candidates(home: Path, signatures: Path) -> list[Path]:
    """Devuelve las ubicaciones admitidas para la clave pública de confianza."""
    candidates: list[Path] = []
    configured = os.environ.get(PUBLIC_KEY_ENV, "").strip()
    if configured:
        candidates.append(Path(configured))
    candidates.extend(
        [
            home / "signing.pub",
            Path(str(signatures) + ".pub"),
        ]
    )
    return candidates


def _check_signatures_signed(home: Path, signatures: Path) -> _CheckResult:
    """Verifica la firma Ed25519 separada contra la clave pública configurada."""
    signature_path = Path(str(signatures) + ".sig")
    if not signature_path.is_file():
        return (
            False,
            f"no existe la firma {signature_path.name}; la base no es verificable",
            _REMEDIAR_FIRMA,
        )
    if not crypto.available():
        return (
            False,
            "cryptography no está instalado; no se puede verificar Ed25519",
            "Instala el extra de firma: pip install -e '.[signing]'.",
        )

    candidates = _public_key_candidates(home, signatures)
    key_path = next(
        (candidate for candidate in candidates if candidate.is_file()),
        None,
    )
    if key_path is None:
        return (
            False,
            "hay firma pero no hay clave pública configurada",
            _REMEDIAR_CLAVE,
        )

    payload = signatures.read_bytes()
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        return (
            False,
            f"firma de {len(signature)} bytes; Ed25519 exige 64",
            _REMEDIAR_FIRMA,
        )
    if crypto.verify_payload(payload, signature, key_path):
        return True, f"firma Ed25519 válida con {key_path}", ""
    return (
        False,
        "la firma Ed25519 no coincide con el contenido de la base",
        "No uses esta base: vuelve a distribuir el JSON y su firma desde la fuente de confianza.",
    )


def _check_quarantine_integrity(home: Path) -> _CheckResult:
    """Verifica entradas y MAC de la cuarentena sin lanzar excepciones."""
    store = Quarantine(home / "quarantine")
    if not store.index_path.exists():
        return True, "sin entradas", ""
    results = store.verify_all()
    if not results:
        return True, "sin entradas", ""
    altered = [(entry.id, error) for entry, error in results if error]
    if altered:
        first_id, first_error = altered[0]
        return (
            False,
            (
                f"{len(altered)} de {len(results)} entradas alteradas "
                f"({first_id}: {first_error})"
            ),
            _REMEDIAR_CUARENTENA,
        )
    return True, f"{len(results)} entrada(s) íntegras", ""


def _check_quarantine_key_permissions(home: Path) -> _CheckResult:
    """Comprueba los permisos de ``quarantine.key`` sin modificarlos nunca."""
    key_path = home / "quarantine.key"
    if not key_path.is_file():
        return True, "sin clave de cuarentena: no hay permisos que comprobar", ""
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    readable_by_others = bool(mode & (stat.S_IRGRP | stat.S_IROTH))
    if os.name == "nt":
        # os.stat en Windows no expone ACLs: incluso un archivo con una ACL
        # restrictiva suele mostrar modo 0666. Solo podemos afirmar ausencia de
        # lectura para grupo/otros cuando los bits así lo indican; en caso
        # contrario declaramos la limitación y pasamos el check.
        if not readable_by_others:
            return True, f"os.stat: modo {mode:04o} sin lectura para grupo/otros", ""
        return (
            True,
            (
                f"os.stat en Windows no expone ACLs (modo {mode:04o}); no se puede "
                f"confirmar si la clave es legible por todos. Revisar con: icacls {key_path}"
            ),
            "",
        )
    if readable_by_others:
        return False, f"modo {mode:04o} permite lectura a grupo/otros", f"chmod 600 {key_path}"
    return True, f"modo {mode:04o} restringido", ""


def _check_logging(home: Path) -> _CheckResult:
    """Escribe un evento de prueba con ``AuditLogger`` y valida el JSONL."""
    path = home / "audit.jsonl"
    logger = AuditLogger(path)
    logger.emit(AUDIT_EVENT, component="audit")
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False, "el logger no escribió ninguna línea", _REMEDIAR_LOG
    try:
        records = [json.loads(line) for line in lines]
    except json.JSONDecodeError as exc:
        return False, f"audit.jsonl contiene una línea no JSON: {exc}", _REMEDIAR_LOG
    if records[-1].get("event") != AUDIT_EVENT:
        return False, f"último evento inesperado: {records[-1].get('event')!r}", _REMEDIAR_LOG
    return True, f"evento {AUDIT_EVENT} escrito y leído correctamente ({len(records)} línea(s))", ""


def _check_allowlist_self(home: Path) -> _CheckResult:
    """Comprueba que la auto-exclusión de la propia aplicación no esté vacía."""
    package_root = Path(__file__).parent.parent
    rules = AllowList.for_self([home, package_root])
    if not rules.directories or not rules.allows_path(home / "sentinel-audit.txt"):
        return False, "la auto-exclusión está vacía o no cubre la home", _REMEDIAR_ALLOWLIST
    return True, f"{len(rules.directories)} directorios propios excluidos", ""


def _check_realtime_backend() -> _CheckResult:
    """Exige un backend de eventos en Windows y ``polling`` en otros SO."""
    backends = available_backends()
    if os.name == "nt":
        usable = [backend for backend in backends if backend != "polling"]
        if not usable:
            return False, f"solo está disponible polling: {backends}", _REMEDIAR_REALTIME
        return True, f"backend no-polling disponible: {', '.join(usable)}", ""
    if "polling" not in backends:
        return False, f"no hay backend de sondeo: {backends}", _REMEDIAR_REALTIME
    return True, f"backend disponible: {', '.join(backends)}", ""


def _check_config() -> _CheckResult:
    """Valida los límites anti-bomba de la configuración por defecto."""
    config = ScanConfig()
    config.validate()
    names = (
        "max_file_size",
        "sample_size",
        "container_max_entries",
        "container_max_uncompressed",
        "container_max_depth",
        "container_max_ratio",
    )
    values = {name: getattr(config, name) for name in names}
    if any(value <= 0 for value in values.values()) or config.container_max_depth < 1:
        return False, f"límites no válidos: {values}", _REMEDIAR_CONFIG
    return (
        True,
        (
            f"max_file_size={config.max_file_size}, sample_size={config.sample_size}, "
            f"container_max_depth={config.container_max_depth}"
        ),
        "",
    )


def _home_location_problem(home: Path) -> str | None:
    """Devuelve el motivo por el que la home es inválida, o ``None``."""
    if os.name != "nt":
        return None
    try:
        resolved = home.resolve()
    except OSError:
        resolved = Path(os.path.abspath(str(home)))
    parts = [part.lower() for part in resolved.parts]
    # ProgramData es la ubicación de configuración de máquina recomendada.
    if any(part == "programdata" for part in parts):
        return None
    if len(parts) >= 2 and parts[0].rstrip("\\/").endswith(":"):
        forbidden = {
            "windows": "Windows",
            "program files": "Program Files",
            "program files (x86)": "Program Files (x86)",
        }
        if parts[1] in forbidden:
            return f"la home está dentro de {forbidden[parts[1]]} (ruta de solo lectura)"
    return None


def _check_home_location(home: Path) -> _CheckResult:
    """Rechaza homes bajo directorios del sistema de solo lectura."""
    problem = _home_location_problem(home)
    if problem:
        return False, problem, _REMEDIAR_HOME
    return True, f"home en ruta escribible: {home}", ""


def _check_iocs_minimum(signatures: Path) -> _CheckResult:
    """Exige al menos un hash y una regla de contenido en la base."""
    stats = SignatureDatabase.load(signatures).stats()
    hashes = int(stats["hashes"])
    content = int(stats["content_rules"])
    if hashes < 1 or content < 1:
        return (
            False,
            f"base insuficiente: {hashes} hash(es), {content} regla(s) de contenido",
            "Instala una base con al menos un hash y una regla de contenido (por ejemplo EICAR).",
        )
    return True, f"{hashes} hash(es) y {content} regla(s) de contenido", ""


def run_security_audit(home: str | Path, signatures: str | Path) -> SecurityAudit:
    """Ejecuta todas las comprobaciones sin lanzar excepciones.

    ``home`` es el directorio de datos de Sentinel y ``signatures`` la ruta a
    ``signatures.json``. Cada check captura sus propios errores; los problemas
    al construir las rutas se convierten en un check ``audit.setup`` fallido.
    """
    try:
        home_path = Path(home)
        signatures_path = Path(signatures)
    except Exception as exc:  # noqa: BLE001 - rutas inválidas no deben propagarse
        return SecurityAudit(
            Path(),
            Path(),
            [
                AuditCheck(
                    "audit.setup",
                    False,
                    f"{type(exc).__name__}: {exc}",
                    "Pasa rutas válidas a run_security_audit(home, signatures).",
                )
            ],
        )

    checks = [
        _check(
            "signatures.valid",
            _REMEDIAR_BASE,
            lambda: _check_signatures_valid(signatures_path),
        ),
        _check(
            "signatures.signed",
            _REMEDIAR_FIRMA,
            lambda: _check_signatures_signed(home_path, signatures_path),
        ),
        _check(
            "quarantine.integrity",
            _REMEDIAR_CUARENTENA,
            lambda: _check_quarantine_integrity(home_path),
        ),
        _check(
            "quarantine.key_permissions",
            "Revisa los permisos de <home>/quarantine.key manualmente; no los cambies "
            "automáticamente.",
            lambda: _check_quarantine_key_permissions(home_path),
        ),
        _check("logging.enabled", _REMEDIAR_LOG, lambda: _check_logging(home_path)),
        _check(
            "allowlist.self",
            _REMEDIAR_ALLOWLIST,
            lambda: _check_allowlist_self(home_path),
        ),
        _check("realtime.backend", _REMEDIAR_REALTIME, _check_realtime_backend),
        _check("config.sane", _REMEDIAR_CONFIG, _check_config),
        _check("home.location", _REMEDIAR_HOME, lambda: _check_home_location(home_path)),
        _check("iocs.minimum", _REMEDIAR_BASE, lambda: _check_iocs_minimum(signatures_path)),
    ]
    return SecurityAudit(home_path, signatures_path, checks)


__all__ = [
    "AUDIT_EVENT",
    "PUBLIC_KEY_ENV",
    "AuditCheck",
    "SecurityAudit",
    "run_security_audit",
]
