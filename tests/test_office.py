"""Tests for Office documents (ZIP/OOXML) and OLE2 compound files (MSI/DOC)."""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from sentinel.config import ScanConfig
from sentinel.core.models import Detection, RuleHit, Severity
from sentinel.engine import scanner as scanner_module
from sentinel.engine.containers import (
    ContainerEntry,
    ContainerError,
    find_macro_entries,
    unpack,
)
from sentinel.engine.ole import unpack_ole
from sentinel.engine.scanner import Scanner

MARKER = b"SENTINEL_TEST_MARKER"
_NOSTREAM = 0xFFFFFFFF
_END_OF_CHAIN = 0xFFFFFFFE
_FAT_SECT = 0xFFFFFFFD


def make_docx() -> bytes:
    """Builds a minimal .docx with content and a fake VBA project."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", b"<w:t>" + MARKER + b"</w:t>")
        archive.writestr("word/vbaProject.bin", b"VBA-PROJECT-FAKE")
    return buffer.getvalue()


def write_dir_entry(
    data: bytearray,
    base: int,
    index: int,
    name: str,
    obj_type: int,
    start: int,
    size: int,
    left: int = _NOSTREAM,
    right: int = _NOSTREAM,
    child: int = _NOSTREAM,
) -> None:
    """Writes a 128-byte CFB directory entry."""
    offset = base + index * 128
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    data[offset : offset + len(encoded)] = encoded
    struct.pack_into("<H", data, offset + 64, len(encoded))
    data[offset + 66] = obj_type
    data[offset + 67] = 1  # Black node of the red-black tree.
    struct.pack_into("<III", data, offset + 68, left, right, child)
    struct.pack_into("<I", data, offset + 116, start)
    struct.pack_into("<Q", data, offset + 120, size)


def make_minimal_ole(stream_name: str = "VBAStream") -> bytes:
    """Builds a valid OLE2 file: FAT, directory, MiniFAT, and a 64-byte stream.

    The layout uses 512-byte sectors: 0 = FAT, 1 = directory, 2 = MiniFAT,
    and 3 = mini-stream (whose first mini-sector contains the marker).
    """
    payload = MARKER.ljust(64, b"\x00")[:64]
    data = bytearray(512 + 4 * 512)

    # 512-byte CFB header.
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

    # FAT: sectors 1, 2, and 3 form single-element chains.
    fat = 512
    struct.pack_into(
        "<5I",
        data,
        fat,
        _FAT_SECT,
        _END_OF_CHAIN,
        _END_OF_CHAIN,
        _END_OF_CHAIN,
        _NOSTREAM,
    )

    # MiniFAT: mini-sector 0 terminates the chain.
    struct.pack_into("<I", data, 512 + 2 * 512, _END_OF_CHAIN)

    # Mini-stream: the stream occupies the first mini-sector.
    mini_stream = 512 + 3 * 512
    data[mini_stream : mini_stream + 64] = payload

    # Directory: root with one child (the stream).
    directory = 512 + 512
    write_dir_entry(data, directory, 0, "Root Entry", 5, start=3, size=512, child=1)
    write_dir_entry(data, directory, 1, stream_name, 2, start=0, size=64)
    return bytes(data)


def test_unpack_docx_and_find_macros():
    entries = unpack(make_docx(), "report.docx", ScanConfig())
    assert [item.path for item in entries] == [
        "report.docx!/word/document.xml",
        "report.docx!/word/vbaProject.bin",
    ]
    assert any(MARKER in item.data for item in entries)

    macros = find_macro_entries(entries)
    assert [item.path for item in macros] == ["report.docx!/word/vbaProject.bin"]


def test_zip_based_extensions_use_zip_reader():
    for suffix in (".docx", ".xlsx", ".odt", ".jar", ".apk", ".nupkg", ".ipa", ".vsix"):
        entries = unpack(make_docx(), f"package{suffix}", ScanConfig())
        assert entries[0].path == f"package{suffix}!/word/document.xml"
        assert MARKER in entries[0].data


def test_scanner_reports_office_macro_and_content(tmp_path, default_db):
    document = tmp_path / "report.docx"
    document.write_bytes(make_docx())

    result = Scanner(default_db).scan([document])
    rules = {finding.rule_id for finding in result.findings}
    assert {"OFFICE-MACRO", "TEST-CONTENT-MARKER"} <= rules
    macro = next(item for item in result.findings if item.rule_id == "OFFICE-MACRO")
    assert macro.path.endswith("word/vbaProject.bin")
    assert any(str(document) in indicator for indicator in macro.indicators)


def test_scanner_attaches_vba_hits_to_macro_entry(tmp_path, default_db, monkeypatch):
    vba_hit = RuleHit("VBA-TEST", Detection.HEURISTIC, Severity.HIGH, "test macro")
    monkeypatch.setattr(scanner_module, "analyze_macro_entries", lambda _entries: [vba_hit])

    document = tmp_path / "macro.docx"
    document.write_bytes(make_docx())
    result = Scanner(default_db).scan([document])

    hits = [item for item in result.findings if item.rule_id == "VBA-TEST"]
    assert len(hits) == 1
    assert hits[0].path.endswith("word/vbaProject.bin")


def test_find_macro_entries_is_case_and_separator_insensitive():
    entries = [
        ContainerEntry("a.docx!/WORD/VBAProject.BIN", b"", 0),
        ContainerEntry("b.doc!/Basic\\Module1", b"", 0),
        ContainerEntry("c.doc!/VBA/dir", b"", 0),
        ContainerEntry("d.docx!/word/document.xml", b"", 0),
    ]
    found = find_macro_entries(entries)
    assert [item.path for item in found] == [
        "a.docx!/WORD/VBAProject.BIN",
        "b.doc!/Basic\\Module1",
        "c.doc!/VBA/dir",
    ]


def test_unpack_ole_extracts_stream():
    payload = make_minimal_ole()
    entries = unpack(payload, "package.msi", ScanConfig())
    assert len(entries) == 1
    assert entries[0].path == "package.msi!/VBAStream"
    assert MARKER in entries[0].data
    assert entries[0].size == 64
    assert not entries[0].truncated
    assert unpack_ole(payload, "other.msi", ScanConfig())[0].data == entries[0].data


def test_ole_respects_depth_limits():
    payload = make_minimal_ole()
    assert unpack(payload, "package.msi", ScanConfig(container_max_depth=0)) == []
    assert unpack(payload, "package.msi", ScanConfig(container_max_depth=1), depth=1) == []


def test_unpack_rejects_invalid_ole():
    with pytest.raises(ContainerError, match="OLE2"):
        unpack(b"this is not an OLE", "mal.msi", ScanConfig())


def test_unpack_rejects_stream_traversal():
    for name in ("../evil", "..\\evil", "/abs/evil"):
        with pytest.raises(ContainerError, match="Unsafe"):
            unpack(make_minimal_ole(name), "mal.doc", ScanConfig())
