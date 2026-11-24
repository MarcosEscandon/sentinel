"""Extracción y análisis del código fuente VBA de proyectos MS-OVBA.

Este módulo no añade dependencias: implementa el contenedor comprimido descrito
en [MS-OVBA] 2.4.1, un parser mínimo del stream ``dir`` y reglas heurísticas
sobre el código fuente recuperado. El análisis es de solo lectura y complementa
la detección genérica de macros de :func:`~sentinel.engine.containers.find_macro_entries`.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ..config import ScanConfig
from ..core.models import Detection, RuleHit, Severity
from .containers import ContainerEntry, ContainerError
from .ole import unpack_ole

_CHUNK_SIZE = 4096
"""Tamaño máximo, en bytes, de cada chunk descomprimido (MS-OVBA 2.4.1.1.3)."""

_CONTAINER_SIGNATURE = 0x01
_CHUNK_SIGNATURE = 0b011
"""Firma de 3 bits de la cabecera de chunk; el bit restante es el flag de compresión."""

_RID_PROJECT_MODULES = 0x0040
_RID_MODULE_NAME = 0x0019
_RID_MODULE_NAME_UNICODE = 0x0047
_RID_MODULE_STREAM_NAME = 0x001A
_RID_MODULE_OFFSET = 0x0031

_MAX_INDICATOR = 120

_PERMISSIVE_CONFIG = ScanConfig(
    max_file_size=64 * 1024 * 1024,
    sample_size=16 * 1024 * 1024,
    container_max_entries=2048,
    container_max_uncompressed=128 * 1024 * 1024,
    container_max_depth=1,
    container_max_ratio=10_000,
)
"""Límites amplios para leer los streams internos de un ``vbaProject.bin``."""


# ---------------------------------------------------------------------------
# Descompresión MS-OVBA
# ---------------------------------------------------------------------------


def _copy_token_bit_count(position: int) -> int:
    """Devuelve los bits del token usados para la distancia (4..12).

    MS-OVBA calcula ``BitCount = max(ceil(log2(position)), 4)``: los bits altos
    del token codifican la distancia (el grupo que incluye la máscara 0x7000) y
    los bajos codifican la longitud. El valor se recalcula para cada token.
    """
    bits = max(0, position - 1).bit_length()
    return min(max(bits, 4), 12)


def _decompress_chunk(data: bytes, pos: int, end: int, output: bytearray) -> int:
    """Descomprime un chunk comprimido y devuelve la posición siguiente.

    Cada ``FlagByte`` rige hasta ocho tokens: bit a 0 es un literal de un byte y
    bit a 1 es un ``CopyToken`` de dos bytes con longitud y distancia.
    """
    chunk_start = len(output)
    while pos < end:
        flags = data[pos]
        pos += 1
        for bit in range(8):
            if pos >= end:
                return pos
            position = len(output) - chunk_start
            if position >= _CHUNK_SIZE:
                raise ValueError("chunk VBA excede los 4096 bytes descomprimidos")
            if not (flags >> bit) & 1:
                output.append(data[pos])
                pos += 1
                continue
            if end - pos < 2:
                raise ValueError("CopyToken VBA truncado al final del chunk")
            token = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            bit_count = _copy_token_bit_count(position)
            length_mask = 0xFFFF >> bit_count
            offset_mask = 0xFFFF ^ length_mask
            length = (token & length_mask) + 3
            offset = ((token & offset_mask) >> (16 - bit_count)) + 1
            if offset > position:
                raise ValueError(f"distancia de copia VBA {offset} fuera del chunk")
            if position + length > _CHUNK_SIZE:
                raise ValueError("chunk VBA excede los 4096 bytes descomprimidos")
            source = len(output) - offset
            # Copia byte a byte: la referencia puede solaparse con la salida (RLE).
            for index in range(length):
                output.append(output[source + index])
    return pos


def decompress(compressed: bytes) -> bytes:
    """Descomprime un ``CompressedContainer`` MS-OVBA.

    Comienza con la firma ``0x01`` y contiene chunks de hasta 4096 bytes. Cada
    cabecera de 2 bytes codifica el tamaño (bits 0-11, tamaño total menos 3), la
    firma ``0b011`` (bits 12-14) y el flag de compresión (bit 15). Los errores de
    formato se informan con :class:`ValueError` y mensajes en español.
    """
    if not compressed:
        raise ValueError("contenedor VBA vacío: falta la firma 0x01")
    if compressed[0] != _CONTAINER_SIGNATURE:
        raise ValueError(
            f"firma de contenedor VBA inválida: 0x{compressed[0]:02X} (esperado 0x01)"
        )

    output = bytearray()
    total = len(compressed)
    pos = 1
    while pos < total:
        if total - pos < 2:
            raise ValueError("cabecera de chunk VBA truncada")
        header = struct.unpack_from("<H", compressed, pos)[0]
        chunk_start = pos
        pos += 2
        if (header >> 12) & 0x07 != _CHUNK_SIGNATURE:
            raise ValueError(f"firma de chunk VBA inválida: 0x{header:04X}")
        chunk_size = (header & 0x0FFF) + 3
        chunk_end = min(total, chunk_start + chunk_size)
        is_compressed = bool(header & 0x8000)
        produced_start = len(output)

        if is_compressed:
            pos = _decompress_chunk(compressed, pos, chunk_end, output)
        else:
            # RawChunk: 4096 bytes literales sin tokens.
            if chunk_end - pos != _CHUNK_SIZE:
                raise ValueError(
                    f"chunk VBA sin comprimir de {chunk_end - pos} bytes (esperado 4096)"
                )
            output.extend(compressed[pos : pos + _CHUNK_SIZE])
            pos = chunk_end

        produced = len(output) - produced_start
        if not 0 < produced <= _CHUNK_SIZE:
            raise ValueError(f"chunk VBA produjo {produced} bytes (máximo 4096)")
    return bytes(output)


# ---------------------------------------------------------------------------
# Parser mínimo del stream `dir`
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModuleInfo:
    """Nombre, stream de código y desplazamiento del texto de un módulo VBA."""

    name: str
    stream: str = ""
    offset: int = 0


@dataclass(frozen=True)
class ProjectInfo:
    """Información mínima extraída del stream ``dir`` de MS-OVBA."""

    modules: tuple[ModuleInfo, ...] = ()

    @property
    def by_stream(self) -> dict[str, ModuleInfo]:
        """Mapa de nombre de stream (en minúsculas) a módulo."""
        return {item.stream.lower(): item for item in self.modules if item.stream}


def _iter_dir_records(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Genera ``(id, carga útil)`` para los registros del stream ``dir``.

    Se recurse en PROJECTMODULES (cuyo payload empieza con un contador de 2
    bytes) y se detiene ante registros truncados, conservando lo ya leído.
    """
    pos = 0
    while pos + 6 <= len(data):
        record_id, size = struct.unpack_from("<HI", data, pos)
        pos += 6
        if size > len(data) - pos:
            return
        payload = data[pos : pos + size]
        pos += size
        yield record_id, payload
        if record_id == _RID_PROJECT_MODULES and size > 2:
            yield from _iter_dir_records(payload[2:])


def _sized_text(payload: bytes, *, utf16: bool = False) -> str:
    """Decodifica un campo ``Size`` (4 bytes) seguido de su texto."""
    if len(payload) < 4:
        return ""
    size = struct.unpack_from("<I", payload, 0)[0]
    raw = payload[4 : 4 + size]
    if not raw:
        return ""
    return raw.decode("utf-16-le" if utf16 else "cp1252", errors="replace")


def _module_stream_name(payload: bytes) -> str:
    """Extrae el nombre de stream de un registro MODULESTREAMNAME (0x001A)."""
    ascii_name = _sized_text(payload)
    if len(payload) < 4:
        return ascii_name
    # Nombre ASCII, Reserved (0x0032) y la variante UTF-16 incrustada.
    size = struct.unpack_from("<I", payload, 0)[0]
    unicode_at = 4 + size + 2
    if unicode_at + 4 <= len(payload):
        unicode_size = struct.unpack_from("<I", payload, unicode_at)[0]
        if unicode_size:
            raw = payload[unicode_at + 4 : unicode_at + 4 + unicode_size]
            return raw.decode("utf-16-le", errors="replace") or ascii_name
    return ascii_name


def parse_project_dir(data: bytes) -> ProjectInfo:
    """Parsea los registros del stream ``dir`` y devuelve los módulos VBA.

    Solo se interpretan los registros de nombre de módulo (0x0019/0x0047),
    nombre de stream (0x001A) y offset de texto (0x0031). Los campos
    desconocidos se ignoran de forma segura.
    """
    modules: list[ModuleInfo] = []
    for record_id, payload in _iter_dir_records(data):
        if record_id == _RID_MODULE_NAME:
            modules.append(ModuleInfo(name=_sized_text(payload)))
        elif record_id == _RID_MODULE_NAME_UNICODE and modules:
            name = _sized_text(payload, utf16=True)
            if name:
                current = modules[-1]
                modules[-1] = ModuleInfo(name, current.stream, current.offset)
        elif record_id == _RID_MODULE_STREAM_NAME and modules:
            current = modules[-1]
            modules[-1] = ModuleInfo(current.name, _module_stream_name(payload), current.offset)
        elif record_id == _RID_MODULE_OFFSET and modules and len(payload) >= 4:
            offset = struct.unpack_from("<I", payload, 0)[0]
            current = modules[-1]
            modules[-1] = ModuleInfo(current.name, current.stream, offset)
    return ProjectInfo(tuple(item for item in modules if item.name or item.stream))


# ---------------------------------------------------------------------------
# Extracción de código fuente
# ---------------------------------------------------------------------------


def _is_vba_project(path: str) -> bool:
    """Comprueba si la ruta termina en ``vbaProject.bin`` (insensible a mayúsculas)."""
    inner = path.replace("\\", "/").lower().rsplit("!/", 1)[-1]
    return inner.endswith("vbaproject.bin")


def _extract_project(entry: ContainerEntry) -> dict[str, str]:
    """Extrae los módulos de un único proyecto VBA."""
    children = unpack_ole(entry.data, entry.path or "vbaProject.bin", _PERMISSIVE_CONFIG)
    streams: dict[str, bytes] = {}
    for child in children:
        name = child.path.replace("\\", "/").rsplit("!/", 1)[-1].lower()
        streams.setdefault(name, child.data)
    raw_dir = streams.get("dir")
    if not raw_dir:
        return {}

    info = parse_project_dir(decompress(raw_dir))
    sources: dict[str, str] = {}
    for module in info.modules:
        raw_code = streams.get(module.stream.lower())
        if raw_code is None:
            continue
        try:
            code = decompress(raw_code)
        except ValueError:
            continue  # Stream de código corrupto: se conservan los demás módulos.
        if module.offset:
            code = code[module.offset :]
        sources[module.name or module.stream] = code.decode("cp1252", errors="replace")
    return sources


def extract_sources(entries: Iterable[ContainerEntry]) -> dict[str, str]:
    """Devuelve ``{nombre_del_módulo: código_VBA}`` para los proyectos encontrados.

    Nunca propaga errores al llamador: los proyectos ilegibles se omiten y se
    devuelve todo el código que se haya podido recuperar de los demás.
    """
    sources: dict[str, str] = {}
    for entry in entries:
        if not _is_vba_project(entry.path):
            continue
        try:
            sources.update(_extract_project(entry))
        except (ContainerError, ValueError, OSError, struct.error, TypeError, IndexError):
            continue
    return sources


# ---------------------------------------------------------------------------
# Análisis de código fuente
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatternRule:
    """Regla regex con identificador, severidad y descripción."""

    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


def _rule(rule_id: str, expression: str, severity: Severity, description: str) -> PatternRule:
    """Compila una expresión regular insensible a mayúsculas."""
    return PatternRule(rule_id, re.compile(expression, re.IGNORECASE), severity, description)


SUSPICIOUS_PATTERNS: tuple[PatternRule, ...] = (
    _rule(
        "VBA-AUTOEXEC",
        r"\b(?:autoopen|autoexec|autoclose|autonew|autoexit|auto_open|document_open|"
        r"document_change|workbook_open|workbook_activate|workbook_beforeclose)\b",
        Severity.MEDIUM,
        "Macro que se ejecuta automáticamente al abrir o cerrar el documento",
    ),
    _rule(
        "VBA-OBFUSCATION",
        r"(?:\bchr(?:b|w)?\$?\s*\([^()]*\)\s*(?:&|\+)\s*){3,}\bchr(?:b|w)?\$?\s*\(",
        Severity.HIGH,
        "Concatenación excesiva de Chr para construir cadenas ofuscadas",
    ),
    _rule(
        "VBA-CREATEOBJECT",
        r"\bcreateobject\s*\(",
        Severity.MEDIUM,
        "Creación de un objeto COM desde VBA",
    ),
    _rule(
        "VBA-SHELL",
        r"(?:\bshell\b|\.run\s*\()",
        Severity.HIGH,
        "Ejecución de comandos o procesos desde VBA",
    ),
    _rule(
        "VBA-CALLBYNAME",
        r"\bcallbyname\s*\(",
        Severity.MEDIUM,
        "Llamada dinámica a miembros para ocultar el código ejecutado",
    ),
    _rule(
        "VBA-CHR",
        r"\bchr(?:b|w)?\$?\s*\(",
        Severity.MEDIUM,
        "Uso de Chr para construir caracteres de forma indirecta",
    ),
    _rule(
        "VBA-POWERSHELL",
        r"\bpowershell(?:\.exe)?\b",
        Severity.HIGH,
        "Referencia a PowerShell en el código VBA",
    ),
    _rule(
        "VBA-CMDEXE",
        r"\bcmd(?:\.exe)?\b",
        Severity.HIGH,
        "Referencia al intérprete de comandos de Windows",
    ),
    _rule(
        "VBA-DOWNLOAD",
        r"\b(?:urldownloadtofile(?:a|w)?|msxml2\.xmlhttp|microsoft\.xmlhttp|net\.webclient)\b",
        Severity.HIGH,
        "Descarga de contenido remoto desde VBA",
    ),
    _rule(
        "VBA-INJECT",
        r"\b(?:virtualalloc(?:ex)?|rtlmovememory|writeprocessmemory|virtualprotect|"
        r"createremotethread)\b",
        Severity.HIGH,
        "Funciones de inyección o ejecución de código en memoria",
    ),
)
"""Secuencias regex sospechosas aplicadas al código fuente VBA."""


def analyze_sources(sources: dict[str, str]) -> list[RuleHit]:
    """Aplica :data:`SUSPICIOUS_PATTERNS` al código de cada módulo.

    Los impactos se deduplican por regla e indicador, se ordenan por identificador
    y la coincidencia se trunca a 120 caracteres dentro del indicador.
    """
    hits: list[RuleHit] = []
    seen: set[tuple[str, str]] = set()
    for module, code in sources.items():
        for rule in SUSPICIOUS_PATTERNS:
            match = rule.pattern.search(code)
            if match is None:
                continue
            snippet = match.group(0).strip()[:_MAX_INDICATOR]
            indicator = f"{module[:60]}: {snippet}"
            key = (rule.rule_id, indicator)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                RuleHit(
                    rule_id=rule.rule_id,
                    detection=Detection.HEURISTIC,
                    severity=rule.severity,
                    description=rule.description,
                    indicators=(indicator,),
                )
            )
    hits.sort(key=lambda item: (item.rule_id, item.indicators))
    return hits


def analyze_macro_entries(entries: Iterable[ContainerEntry]) -> list[RuleHit]:
    """Extrae el código VBA de las entradas y aplica las reglas sospechosas."""
    return analyze_sources(extract_sources(entries))


__all__ = [
    "SUSPICIOUS_PATTERNS",
    "ModuleInfo",
    "PatternRule",
    "ProjectInfo",
    "analyze_macro_entries",
    "analyze_sources",
    "decompress",
    "extract_sources",
    "parse_project_dir",
]
