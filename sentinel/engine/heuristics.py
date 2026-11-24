"""Heurísticas de detección.

No sustituyen a las firmas: buscan propiedades sospechosas de un archivo
(entropía elevada, doble extensión, imports típicos de inyección, secciones
empaquetadas, etc.). El objetivo es priorizar archivos para análisis posterior,
no declararlos maliciosos de forma automática.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..config import ScanConfig
from ..core.models import Detection, RuleHit, Severity

# APIs legítimas en muchos programas, pero muy habituales en cargadores y
# inyectores. Se usan como señal de peso, nunca como prueba de malware.
SUSPICIOUS_IMPORTS = frozenset(
    {
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "createremotethreadex",
        "openprocess",
        "setthreadcontext",
        "queueuserapc",
        "ntunmapviewofsection",
        "mapviewoffile",
        "createfilemappinga",
        "createfilemappingw",
        "loadlibrarya",
        "loadlibraryw",
        "getprocaddress",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "internetopena",
        "internetopenw",
        "internetopenurla",
        "internetopenurlw",
        "winhttpopen",
        "winexec",
        "shellexecutea",
        "shellexecutew",
        "createprocessa",
        "createprocessw",
        "adjusttokenprivileges",
        "setwindowshookexa",
        "setwindowshookexw",
        "regsetvalueexa",
        "regsetvalueexw",
    }
)

PACKER_SECTION_HINTS = (
    "upx",
    "aspack",
    "themida",
    "vmp",
    "nsp",
    "petite",
    "confuser",
    "enigma",
    "obsidium",
    "armadillo",
    ".pack",
    "crypt",
)

HIGH_RISK_EXTENSIONS = (
    "exe",
    "scr",
    "pif",
    "com",
    "bat",
    "cmd",
    "vbs",
    "vbe",
    "ps1",
    "js",
    "jse",
    "jar",
    "hta",
    "lnk",
    "msi",
    "msp",
    "reg",
    "wsf",
    "wsh",
    "chm",
    "cpl",
    "dll",
    "iso",
    "img",
    "vhd",
)

DOUBLE_EXTENSION = re.compile(
    r"\.[a-z0-9]{1,5}\.(" + "|".join(HIGH_RISK_EXTENSIONS) + r")$",
    re.IGNORECASE,
)


def shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon de una secuencia de bytes, en bits por byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


@dataclass
class PEInfo:
    """Información extraída de la cabecera de un ejecutable PE."""

    is_pe: bool = False
    machine: int = 0
    bitness: int = 0
    sections: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    suspicious_imports: tuple[str, ...] = ()
    max_section_entropy: float = 0.0
    overlay_size: int = 0
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "is_pe": self.is_pe,
            "machine": hex(self.machine),
            "bitness": self.bitness,
            "sections": list(self.sections),
            "imports": list(self.imports[:50]),
            "suspicious_imports": list(self.suspicious_imports),
            "max_section_entropy": round(self.max_section_entropy, 3),
            "overlay_size": self.overlay_size,
            "notes": list(self.notes),
        }


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _cstring(data: bytes, offset: int, limit: int = 4096) -> str:
    end = data.find(b"\x00", offset, min(offset + limit, len(data)))
    if end < 0:
        end = min(offset + limit, len(data))
    return data[offset:end].decode("utf-8", errors="replace")


def analyze_pe(data: bytes) -> PEInfo:
    """Analiza una cabecera PE con un parser mínimo y sin dependencias.

    Nunca lanza excepciones por datos malformados: los problemas se recogen
    en ``PEInfo.notes`` para que el escáner pueda seguir adelante.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return PEInfo()
    try:
        pe_offset = _u32(data, 0x3C)
    except struct.error:
        return PEInfo(notes=("e_lfanew ilegible",))
    if pe_offset <= 0 or pe_offset + 24 > len(data):
        return PEInfo(notes=("e_lfanew fuera de rango",))
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return PEInfo(notes=("firma PE ausente",))

    notes: list[str] = []
    coff = pe_offset + 4
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    optional = coff + 20
    if optional + 2 > len(data):
        return PEInfo(is_pe=True, machine=machine, notes=("cabecera opcional truncada",))
    magic = _u16(data, optional)
    if magic == 0x10B:
        bitness = 32
        directories_offset = optional + 96
        count_offset = optional + 92
    elif magic == 0x20B:
        bitness = 64
        directories_offset = optional + 112
        count_offset = optional + 108
    else:
        return PEInfo(
            is_pe=True, machine=machine, notes=(f"magic de cabecera opcional desconocido {magic:#x}",)
        )

    section_table = optional + optional_size
    if section_table > len(data):
        return PEInfo(is_pe=True, machine=machine, notes=("tabla de secciones fuera de rango",))

    sections: list[str] = []
    section_ranges: list[tuple[int, int, int, int]] = []
    max_entropy = 0.0
    raw_end = 0
    for index in range(min(section_count, 96)):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            notes.append("sección truncada")
            break
        name = _cstring(data, offset, 8)
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        sections.append(name)
        section_ranges.append((virtual_address, virtual_size, raw_offset, raw_size))
        if raw_offset and raw_offset < len(data) and raw_size:
            end = min(len(data), raw_offset + min(raw_size, 256 * 1024))
            if end > raw_offset:
                max_entropy = max(max_entropy, shannon_entropy(data[raw_offset:end]))
            raw_end = max(raw_end, raw_offset + raw_size)

    def rva_to_offset(rva: int) -> int | None:
        for virtual_address, virtual_size, raw_offset, raw_size in section_ranges:
            span = max(virtual_size, raw_size)
            if virtual_address <= rva < virtual_address + span:
                delta = rva - virtual_address
                if delta >= raw_size:
                    return None
                return raw_offset + delta
        return None

    imports: list[str] = []
    if count_offset + 4 <= len(data) and directories_offset + 8 <= len(data):
        directory_count = _u32(data, count_offset)
        if directory_count > 1:
            import_rva, import_size = struct.unpack_from("<II", data, directories_offset + 8)
            if import_rva and import_size:
                cursor = rva_to_offset(import_rva)
                if cursor is None:
                    notes.append("directorio de imports no resoluble")
                else:
                    step = 8 if bitness == 64 else 4
                    seen = 0
                    while seen < 512 and cursor + 20 <= len(data):
                        original_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
                            "<IIIII", data, cursor
                        )
                        if not (original_thunk or name_rva or first_thunk):
                            break
                        dll = ""
                        if name_rva:
                            name_offset = rva_to_offset(name_rva)
                            if name_offset is not None:
                                dll = _cstring(data, name_offset)
                        thunk = original_thunk or first_thunk
                        thunk_offset = rva_to_offset(thunk) if thunk else None
                        if thunk_offset is not None:
                            for _ in range(512):
                                if thunk_offset + step > len(data):
                                    break
                                entry = (
                                    struct.unpack_from("<Q", data, thunk_offset)[0]
                                    if bitness == 64
                                    else _u32(data, thunk_offset)
                                )
                                if entry == 0:
                                    break
                                if entry & (1 << (bitness - 1)):
                                    symbol = f"ordinal#{entry & 0xFFFF}"
                                else:
                                    symbol_offset = rva_to_offset(entry)
                                    symbol = (
                                        _cstring(data, symbol_offset + 2)
                                        if symbol_offset is not None
                                        else "?"
                                    )
                                qualified = f"{dll}.{symbol}" if dll else symbol
                                if qualified not in imports:
                                    imports.append(qualified)
                                thunk_offset += step
                        cursor += 20
                        seen += 1

    normalized = {item.rsplit(".", 1)[-1].lower() for item in imports}
    suspicious = sorted(name for name in normalized if name in SUSPICIOUS_IMPORTS)
    overlay = max(0, len(data) - raw_end) if raw_end else 0

    return PEInfo(
        is_pe=True,
        machine=machine,
        bitness=bitness,
        sections=tuple(sections),
        imports=tuple(imports),
        suspicious_imports=tuple(suspicious),
        max_section_entropy=max_entropy,
        overlay_size=overlay,
        notes=tuple(notes),
    )


@dataclass
class HeuristicAssessment:
    """Salida de las heurísticas para un archivo."""

    hits: list[RuleHit] = field(default_factory=list)
    score: float = 0.0
    pe: PEInfo | None = None


class HeuristicEngine:
    """Aplica reglas heurísticas configurables a la muestra de un archivo."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()

    def assess(self, path: str | Path, sample: bytes, file_size: int) -> HeuristicAssessment:
        cfg = self.config
        result = HeuristicAssessment()
        name = Path(path).name.lower()

        if DOUBLE_EXTENSION.search(name):
            result.hits.append(
                RuleHit(
                    rule_id="HEUR-DOUBLE-EXT",
                    detection=Detection.HEURISTIC,
                    severity=Severity.MEDIUM,
                    description="Doble extensión: el nombre oculta un tipo ejecutable",
                    indicators=(name,),
                )
            )
            result.score += 3.0

        if file_size >= cfg.entropy_min_size:
            entropy = shannon_entropy(sample)
            if entropy >= cfg.entropy_threshold:
                result.hits.append(
                    RuleHit(
                        rule_id="HEUR-ENTROPY",
                        detection=Detection.HEURISTIC,
                        severity=Severity.LOW,
                        description=f"Entropía elevada ({entropy:.2f} bits/byte)",
                        indicators=(f"entropy={entropy:.3f}",),
                    )
                )
                result.score += 1.5

        info = analyze_pe(sample)
        if info.is_pe:
            result.pe = info
            if info.suspicious_imports:
                weight = min(6.0, 2.0 * len(info.suspicious_imports))
                result.hits.append(
                    RuleHit(
                        rule_id="HEUR-PE-IMPORTS",
                        detection=Detection.HEURISTIC,
                        severity=Severity.HIGH if len(info.suspicious_imports) >= 2 else Severity.MEDIUM,
                        description="Imports asociados a inyección o descarga",
                        indicators=tuple(info.suspicious_imports[:12]),
                    )
                )
                result.score += weight

            packed = sorted(
                section
                for section in info.sections
                if any(hint in section.lower() for hint in PACKER_SECTION_HINTS)
            )
            if packed:
                result.hits.append(
                    RuleHit(
                        rule_id="HEUR-PE-PACKED",
                        detection=Detection.HEURISTIC,
                        severity=Severity.MEDIUM,
                        description="Secciones típicas de empaquetador/protector",
                        indicators=tuple(packed[:8]),
                    )
                )
                result.score += 2.0

            if info.overlay_size > 1024 * 1024:
                result.hits.append(
                    RuleHit(
                        rule_id="HEUR-PE-OVERLAY",
                        detection=Detection.HEURISTIC,
                        severity=Severity.LOW,
                        description=f"Sobrepósito PE grande ({info.overlay_size} bytes)",
                        indicators=(f"overlay={info.overlay_size}",),
                    )
                )
                result.score += 1.0

        if result.score >= cfg.suspicion_threshold:
            severity = (
                Severity.CRITICAL
                if result.score >= 10
                else Severity.HIGH
                if result.score >= 7
                else Severity.MEDIUM
            )
            result.hits.append(
                RuleHit(
                    rule_id="HEUR-SCORE",
                    detection=Detection.HEURISTIC,
                    severity=severity,
                    description=f"Puntuación heurística acumulada: {result.score:.1f}",
                    indicators=tuple(hit.rule_id for hit in result.hits),
                )
            )
        return result


# Permite inyectar un analizador alternativo en pruebas o plugins.
PEAnalyzer = Callable[[bytes], PEInfo]
