"""Tests for the VBA source code extractor and analyzer (MS-OVBA)."""

from __future__ import annotations

import struct

import pytest

from sentinel.core.models import Detection, RuleHit, Severity
from sentinel.engine.containers import ContainerEntry
from sentinel.engine.vba import (
    analyze_macro_entries,
    analyze_sources,
    decompress,
    extract_sources,
    parse_project_dir,
)

_NOSTREAM = 0xFFFFFFFF
_END_OF_CHAIN = 0xFFFFFFFE
_FAT_SECT = 0xFFFFFFFD


def _chunk_header(body_size: int, compressed: bool = True) -> bytes:
    """Builds a chunk header for a body of ``body_size`` bytes."""
    total = body_size + 2
    header = 0x3000 | (total - 3)  # Signature 0b011 + size (total - 3).
    if compressed:
        header |= 0x8000
    return struct.pack("<H", header)


def _literal_stream(data: bytes) -> bytes:
    """Compresses ``data`` with a chunk of literal tokens only (FlagByte 0x00)."""
    body = bytearray()
    for start in range(0, len(data), 8):
        body.append(0x00)
        body.extend(data[start : start + 8])
    return b"\x01" + _chunk_header(len(body)) + bytes(body)


def _record(record_id: int, payload: bytes) -> bytes:
    """Builds a ``dir`` stream record: id (2), size (4), data."""
    return struct.pack("<HI", record_id, len(payload)) + payload


def _dir_stream(module: str, offset: int) -> bytes:
    """Builds a synthetic ``dir`` stream with a single module."""
    encoded = module.encode("cp1252")
    name = _record(0x0019, struct.pack("<I", len(encoded)) + encoded)
    stream_name = _record(
        0x001A,
        struct.pack("<I", len(encoded)) + encoded + struct.pack("<H", 0x0032) + struct.pack("<I", 0),
    )
    text_offset = _record(0x0031, struct.pack("<I", offset))
    modules = struct.pack("<H", 1) + name + stream_name + text_offset
    return _record(0x0001, struct.pack("<I", 1)) + _record(0x0040, modules)


def _write_dir_entry(
    data: bytearray,
    base: int,
    index: int,
    name: str,
    obj_type: int,
    start: int,
    size: int,
    child: int = _NOSTREAM,
    right: int = _NOSTREAM,
) -> None:
    """Writes a 128-byte CFB directory entry."""
    offset = base + index * 128
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    data[offset : offset + len(encoded)] = encoded
    struct.pack_into("<H", data, offset + 64, len(encoded))
    data[offset + 66] = obj_type
    data[offset + 67] = 1  # Black node of the red-black tree.
    struct.pack_into("<III", data, offset + 68, _NOSTREAM, right, child)
    struct.pack_into("<I", data, offset + 116, start)
    struct.pack_into("<Q", data, offset + 120, size)


def _make_ole(streams: dict[str, bytes]) -> bytes:
    """Builds a minimal OLE2 file whose streams live in the mini-stream."""
    mini = bytearray()
    minifat: list[int] = []
    directory: list[tuple[str, int, int]] = []
    for name, payload in streams.items():
        first = len(minifat)
        count = max(1, (len(payload) + 63) // 64)
        for index in range(count):
            following = first + index + 1 if index + 1 < count else _END_OF_CHAIN
            minifat.append(following)
        mini.extend(payload.ljust(count * 64, b"\x00"))
        directory.append((name, first, len(payload)))
    assert len(mini) <= 512

    data = bytearray(512 + 4 * 512)  # Header, FAT, directory, MiniFAT, mini-stream.
    data[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHH", data, 24, 0x3E, 3, 0xFFFE)
    struct.pack_into("<HH", data, 30, 9, 6)  # 512 bytes/sector, 64 bytes/mini-sector.
    struct.pack_into("<I", data, 44, 1)  # One FAT sector.
    struct.pack_into("<I", data, 48, 1)  # First directory sector.
    struct.pack_into("<I", data, 56, 4096)  # Mini-stream cutoff.
    struct.pack_into("<I", data, 60, 2)  # First MiniFAT sector.
    struct.pack_into("<I", data, 64, 1)  # One MiniFAT sector.
    struct.pack_into("<I", data, 76, 0)  # DIFAT[0] = FAT sector 0.
    for index in range(1, 109):
        struct.pack_into("<I", data, 76 + 4 * index, _NOSTREAM)

    fat = 512
    struct.pack_into(
        "<4I", data, fat, _FAT_SECT, _END_OF_CHAIN, _END_OF_CHAIN, _END_OF_CHAIN
    )
    mini_fat = 512 + 2 * 512
    for index, following in enumerate(minifat):
        struct.pack_into("<I", data, mini_fat + 4 * index, following)
    mini_start = 512 + 3 * 512
    data[mini_start : mini_start + len(mini)] = mini

    directory_base = 512 + 512
    _write_dir_entry(data, directory_base, 0, "Root Entry", 5, 3, len(mini), child=1)
    for index, (name, start, size) in enumerate(directory, start=1):
        right = index + 1 if index < len(directory) else _NOSTREAM
        _write_dir_entry(data, directory_base, index, name, 2, start, size, right=right)
    return bytes(data)


def test_decompress_literals_and_copy_token():
    """A chunk with five literals and one copy reproduces the original string."""
    tokens = bytearray([0x20])  # Bit 5: literal, literal, literal, literal, literal, copy.
    tokens.extend(b"ABCDE")
    # At position 5, BitCount=4: distance 5 is encoded as 4 (5-1) in the
    # high bits and length 5 as 2 (5-3) in the low bits.
    tokens.extend(struct.pack("<H", (4 << 12) | 2))
    stream = b"\x01" + _chunk_header(len(tokens)) + bytes(tokens)

    assert decompress(stream) == b"ABCDEABCDE"


def test_decompress_raw_chunk_and_multiple_chunks():
    """Uncompressed chunks copy 4096 bytes and can follow other chunks."""
    payload = bytes(range(256)) * 16
    raw = b"\x01" + _chunk_header(4096, compressed=False) + payload
    assert decompress(raw) == payload

    combined = b"\x01" + _chunk_header(2) + b"\x00Z" + _chunk_header(4096, False) + payload
    assert decompress(combined) == b"Z" + payload


def test_decompress_rejects_malformed_streams():
    """Format errors are reported with ValueError and a clear message."""
    with pytest.raises(ValueError, match="container signature"):
        decompress(b"\x02\x00\x00")
    with pytest.raises(ValueError, match="chunk signature"):
        decompress(b"\x01" + struct.pack("<H", 0x2003))
    with pytest.raises(ValueError, match="chunk header"):
        decompress(b"\x01\x07")
    # Copy at position 0: distance 1 cannot refer to anything.
    with pytest.raises(ValueError, match="copy distance"):
        decompress(b"\x01" + _chunk_header(3) + b"\x01" + struct.pack("<H", 0x0003))


def test_parse_project_dir_extracts_module_mapping():
    """The parser maps module name, code stream, and text offset."""
    info = parse_project_dir(_dir_stream("Module1", 12))
    assert len(info.modules) == 1
    module = info.modules[0]
    assert (module.name, module.stream, module.offset) == ("Module1", "Module1", 12)
    assert info.by_stream["module1"] is module

    noisy = _record(0x1234, b"xyz") + _dir_stream("Module1", 12)
    assert parse_project_dir(noisy).modules[0].name == "Module1"


def test_parse_project_dir_prefers_unicode_name():
    """Record 0x0047 replaces the name encoded in cp1252."""
    marker = _record(0x0019, struct.pack("<I", 7) + b"Module1")
    name_utf16 = "Module1".encode("utf-16-le")
    unicode_record = _record(0x0047, struct.pack("<I", len(name_utf16)) + name_utf16)
    data = _dir_stream("Module1", 8).replace(marker, marker + unicode_record, 1)
    assert parse_project_dir(data).modules[0].name == "Module1"


def test_analyze_sources_detects_autoexec_shell_and_powershell():
    """The sample malicious code triggers the execution rules."""
    code = (
        "Private Sub Document_Open()\n"
        "    Dim obj As Object\n"
        '    Set obj = CreateObject("WScript.Shell")\n'
        '    obj.Run "powershell -enc AAAA"\n'
        "End Sub\n"
    )
    hits = analyze_sources({"Module1": code})
    rules = {item.rule_id for item in hits}
    assert {"VBA-AUTOEXEC", "VBA-CREATEOBJECT", "VBA-SHELL", "VBA-POWERSHELL"} <= rules
    assert all(isinstance(item, RuleHit) for item in hits)
    assert all(item.detection is Detection.HEURISTIC for item in hits)
    assert all(item.severity in {Severity.MEDIUM, Severity.HIGH} for item in hits)
    assert all(any("Module1" in text for text in item.indicators) for item in hits)
    powershell = next(item for item in hits if item.rule_id == "VBA-POWERSHELL")
    assert any(len(text) <= 200 for text in powershell.indicators)


def test_analyze_sources_detects_obfuscation_patterns():
    """Chr concatenation and injection APIs are classified as high severity."""
    code = "s = Chr(72) & Chr(105) & Chr(100) & Chr(100) & Chr(101)\nPtr = VirtualAlloc(0, 1, 1, 1)\n"
    hits = analyze_sources({"Module1": code})
    rules = {item.rule_id for item in hits}
    assert {"VBA-CHR", "VBA-OBFUSCATION", "VBA-INJECT"} <= rules
    assert all(
        item.severity is Severity.HIGH
        for item in hits
        if item.rule_id in {"VBA-OBFUSCATION", "VBA-INJECT"}
    )


def test_analyze_sources_ignores_benign_code():
    """Benign code produces no execution or obfuscation hits."""
    code = (
        "Public Function AddNumbers(ByVal a As Long, ByVal b As Long) As Long\n"
        "    AddNumbers = a + b\n"
        "End Function\n"
    )
    assert analyze_sources({"Module1": code}) == []


def test_extract_sources_ignores_empty_and_invalid_entries():
    """Empty or corrupt entries do not raise exceptions."""
    assert extract_sources([]) == {}
    invalid = [
        ContainerEntry("a.docx!/word/vbaProject.bin", b"", 0),
        ContainerEntry("b.docx!/word/vbaProject.bin", b"this is not an OLE", 17),
        ContainerEntry("c.docx!/word/document.xml", b"\x01\x00\x00", 3),
        ContainerEntry("d.doc!/VBA/dir", b"\x01", 1),
    ]
    assert extract_sources(invalid) == {}


def test_extract_and_analyze_real_vba_project_streams():
    """The full flow recovers the source from the OLE and generates VBA hits."""
    code = b'Sub AutoOpen()\r\nShell "cmd.exe /c whoami"\r\nEnd Sub\r\n'
    project = _make_ole(
        {
            "dir": _literal_stream(_dir_stream("Module1", 0)),
            "Module1": _literal_stream(code),
        }
    )
    entry = ContainerEntry("doc.doc!/word/vbaProject.bin", project, len(project))

    sources = extract_sources([entry])
    assert list(sources) == ["Module1"]
    assert "AutoOpen" in sources["Module1"]
    assert "cmd.exe" in sources["Module1"]

    rules = {item.rule_id for item in analyze_macro_entries([entry])}
    assert {"VBA-AUTOEXEC", "VBA-SHELL", "VBA-CMDEXE"} <= rules
