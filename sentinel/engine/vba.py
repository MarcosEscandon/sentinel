"""Extraction and analysis of VBA source code from MS-OVBA projects.

This module adds no dependencies: it implements the compressed container
described in [MS-OVBA] 2.4.1, a minimal parser for the ``dir`` stream, and
heuristic rules over the recovered source code. The analysis is read-only and
complements generic macro detection in
:func:`~sentinel.engine.containers.find_macro_entries`.
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
"""Maximum size, in bytes, of each decompressed chunk (MS-OVBA 2.4.1.1.3)."""

_CONTAINER_SIGNATURE = 0x01
_CHUNK_SIGNATURE = 0b011
"""3-bit signature of the chunk header; the remaining bit is the compression flag."""

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
"""Generous limits for reading the internal streams of a ``vbaProject.bin``."""


# ---------------------------------------------------------------------------
# MS-OVBA decompression
# ---------------------------------------------------------------------------


def _copy_token_bit_count(position: int) -> int:
    """Returns the number of token bits used for the distance (4..12).

    MS-OVBA computes ``BitCount = max(ceil(log2(position)), 4)``: the high bits
    of the token encode the distance (the group including the 0x7000 mask) and
    the low bits encode the length. The value is recalculated for each token.
    """
    bits = max(0, position - 1).bit_length()
    return min(max(bits, 4), 12)


def _decompress_chunk(data: bytes, pos: int, end: int, output: bytearray) -> int:
    """Decompresses a compressed chunk and returns the next position.

    Each ``FlagByte`` governs up to eight tokens: a 0 bit is a one-byte literal
    and a 1 bit is a two-byte ``CopyToken`` with length and distance.
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
                raise ValueError("VBA chunk exceeds 4096 decompressed bytes")
            if not (flags >> bit) & 1:
                output.append(data[pos])
                pos += 1
                continue
            if end - pos < 2:
                raise ValueError("VBA CopyToken truncated at end of chunk")
            token = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            bit_count = _copy_token_bit_count(position)
            length_mask = 0xFFFF >> bit_count
            offset_mask = 0xFFFF ^ length_mask
            length = (token & length_mask) + 3
            offset = ((token & offset_mask) >> (16 - bit_count)) + 1
            if offset > position:
                raise ValueError(f"VBA copy distance {offset} outside chunk")
            if position + length > _CHUNK_SIZE:
                raise ValueError("VBA chunk exceeds 4096 decompressed bytes")
            source = len(output) - offset
            # Copy byte by byte: the reference may overlap with the output (RLE).
            for index in range(length):
                output.append(output[source + index])
    return pos


def decompress(compressed: bytes) -> bytes:
    """Decompresses an MS-OVBA ``CompressedContainer``.

    It starts with the signature ``0x01`` and contains chunks of up to 4096
    bytes. Each 2-byte header encodes the size (bits 0-11, total size minus 3),
    the signature ``0b011`` (bits 12-14), and the compression flag (bit 15).
    Format errors are reported with :class:`ValueError` and clear messages.
    """
    if not compressed:
        raise ValueError("empty VBA container: missing signature 0x01")
    if compressed[0] != _CONTAINER_SIGNATURE:
        raise ValueError(
            f"invalid VBA container signature: 0x{compressed[0]:02X} (expected 0x01)"
        )

    output = bytearray()
    total = len(compressed)
    pos = 1
    while pos < total:
        if total - pos < 2:
            raise ValueError("truncated VBA chunk header")
        header = struct.unpack_from("<H", compressed, pos)[0]
        chunk_start = pos
        pos += 2
        if (header >> 12) & 0x07 != _CHUNK_SIGNATURE:
            raise ValueError(f"invalid VBA chunk signature: 0x{header:04X}")
        chunk_size = (header & 0x0FFF) + 3
        chunk_end = min(total, chunk_start + chunk_size)
        is_compressed = bool(header & 0x8000)
        produced_start = len(output)

        if is_compressed:
            pos = _decompress_chunk(compressed, pos, chunk_end, output)
        else:
            # RawChunk: 4096 literal bytes without tokens.
            if chunk_end - pos != _CHUNK_SIZE:
                raise ValueError(
                    f"uncompressed VBA chunk of {chunk_end - pos} bytes (expected 4096)"
                )
            output.extend(compressed[pos : pos + _CHUNK_SIZE])
            pos = chunk_end

        produced = len(output) - produced_start
        if not 0 < produced <= _CHUNK_SIZE:
            raise ValueError(f"VBA chunk produced {produced} bytes (maximum 4096)")
    return bytes(output)


# ---------------------------------------------------------------------------
# Minimal `dir` stream parser
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModuleInfo:
    """Name, code stream, and text offset of a VBA module."""

    name: str
    stream: str = ""
    offset: int = 0


@dataclass(frozen=True)
class ProjectInfo:
    """Minimal information extracted from the MS-OVBA ``dir`` stream."""

    modules: tuple[ModuleInfo, ...] = ()

    @property
    def by_stream(self) -> dict[str, ModuleInfo]:
        """Map from lowercase stream name to module."""
        return {item.stream.lower(): item for item in self.modules if item.stream}


def _iter_dir_records(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yields ``(id, payload)`` for records in the ``dir`` stream.

    It recurses into PROJECTMODULES (whose payload starts with a 2-byte count)
    and stops at truncated records, preserving what has already been read.
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
    """Decodes a ``Size`` field (4 bytes) followed by its text."""
    if len(payload) < 4:
        return ""
    size = struct.unpack_from("<I", payload, 0)[0]
    raw = payload[4 : 4 + size]
    if not raw:
        return ""
    return raw.decode("utf-16-le" if utf16 else "cp1252", errors="replace")


def _module_stream_name(payload: bytes) -> str:
    """Extracts the stream name from a MODULESTREAMNAME record (0x001A)."""
    ascii_name = _sized_text(payload)
    if len(payload) < 4:
        return ascii_name
    # ASCII name, Reserved (0x0032), and the embedded UTF-16 variant.
    size = struct.unpack_from("<I", payload, 0)[0]
    unicode_at = 4 + size + 2
    if unicode_at + 4 <= len(payload):
        unicode_size = struct.unpack_from("<I", payload, unicode_at)[0]
        if unicode_size:
            raw = payload[unicode_at + 4 : unicode_at + 4 + unicode_size]
            return raw.decode("utf-16-le", errors="replace") or ascii_name
    return ascii_name


def parse_project_dir(data: bytes) -> ProjectInfo:
    """Parses records in the ``dir`` stream and returns the VBA modules.

    Only module name (0x0019/0x0047), stream name (0x001A), and text offset
    (0x0031) records are interpreted. Unknown fields are safely ignored.
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
# Source code extraction
# ---------------------------------------------------------------------------


def _is_vba_project(path: str) -> bool:
    """Checks whether the path ends in ``vbaProject.bin`` (case-insensitive)."""
    inner = path.replace("\\", "/").lower().rsplit("!/", 1)[-1]
    return inner.endswith("vbaproject.bin")


def _extract_project(entry: ContainerEntry) -> dict[str, str]:
    """Extracts the modules of a single VBA project."""
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
            continue  # Corrupt code stream: keep the other modules.
        if module.offset:
            code = code[module.offset :]
        sources[module.name or module.stream] = code.decode("cp1252", errors="replace")
    return sources


def extract_sources(entries: Iterable[ContainerEntry]) -> dict[str, str]:
    """Returns ``{module_name: vba_code}`` for the projects found.

    Errors are never propagated to the caller: unreadable projects are skipped
    and all code recovered from the other projects is returned.
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
# Source code analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PatternRule:
    """Regex rule with an identifier, severity, and description."""

    rule_id: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str


def _rule(rule_id: str, expression: str, severity: Severity, description: str) -> PatternRule:
    """Compiles a case-insensitive regular expression."""
    return PatternRule(rule_id, re.compile(expression, re.IGNORECASE), severity, description)


SUSPICIOUS_PATTERNS: tuple[PatternRule, ...] = (
    _rule(
        "VBA-AUTOEXEC",
        r"\b(?:autoopen|autoexec|autoclose|autonew|autoexit|auto_open|document_open|"
        r"document_change|workbook_open|workbook_activate|workbook_beforeclose)\b",
        Severity.MEDIUM,
        "Macro that runs automatically when the document is opened or closed",
    ),
    _rule(
        "VBA-OBFUSCATION",
        r"(?:\bchr(?:b|w)?\$?\s*\([^()]*\)\s*(?:&|\+)\s*){3,}\bchr(?:b|w)?\$?\s*\(",
        Severity.HIGH,
        "Excessive Chr concatenation to build obfuscated strings",
    ),
    _rule(
        "VBA-CREATEOBJECT",
        r"\bcreateobject\s*\(",
        Severity.MEDIUM,
        "Creation of a COM object from VBA",
    ),
    _rule(
        "VBA-SHELL",
        r"(?:\bshell\b|\.run\s*\()",
        Severity.HIGH,
        "Execution of commands or processes from VBA",
    ),
    _rule(
        "VBA-CALLBYNAME",
        r"\bcallbyname\s*\(",
        Severity.MEDIUM,
        "Dynamic member call to hide the executed code",
    ),
    _rule(
        "VBA-CHR",
        r"\bchr(?:b|w)?\$?\s*\(",
        Severity.MEDIUM,
        "Use of Chr to build characters indirectly",
    ),
    _rule(
        "VBA-POWERSHELL",
        r"\bpowershell(?:\.exe)?\b",
        Severity.HIGH,
        "Reference to PowerShell in the VBA code",
    ),
    _rule(
        "VBA-CMDEXE",
        r"\bcmd(?:\.exe)?\b",
        Severity.HIGH,
        "Reference to the Windows command interpreter",
    ),
    _rule(
        "VBA-DOWNLOAD",
        r"\b(?:urldownloadtofile(?:a|w)?|msxml2\.xmlhttp|microsoft\.xmlhttp|net\.webclient)\b",
        Severity.HIGH,
        "Download of remote content from VBA",
    ),
    _rule(
        "VBA-INJECT",
        r"\b(?:virtualalloc(?:ex)?|rtlmovememory|writeprocessmemory|virtualprotect|"
        r"createremotethread)\b",
        Severity.HIGH,
        "Functions for injection or in-memory code execution",
    ),
)
"""Suspicious regex sequences applied to VBA source code."""


def analyze_sources(sources: dict[str, str]) -> list[RuleHit]:
    """Applies :data:`SUSPICIOUS_PATTERNS` to each module's code.

    Hits are deduplicated by rule and indicator, sorted by identifier, and the
    matched text is truncated to 120 characters within the indicator.
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
    """Extracts VBA code from entries and applies the suspicious rules."""
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
