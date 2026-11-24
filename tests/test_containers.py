import gzip
import io
import zipfile

import pytest

from sentinel.config import ScanConfig
from sentinel.engine.containers import ContainerError, unpack
from sentinel.engine.scanner import Scanner


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def test_unpack_zip(tmp_path):
    payload = make_zip({"a.txt": b"hola", "sub/b.bin": b"mundo"})
    entries = unpack(payload, "paquete.zip", ScanConfig())
    assert [item.path for item in entries] == [
        "paquete.zip!/a.txt",
        "paquete.zip!/sub/b.bin",
    ]
    assert entries[0].data == b"hola"


def test_unpack_nested_zip():
    inner = make_zip({"marker.txt": b"SENTINEL_TEST_MARKER"})
    outer = make_zip({"inner.zip": inner})
    entries = unpack(outer, "outer.zip", ScanConfig())
    assert any("inner.zip!/marker.txt" in item.path for item in entries)


def test_unpack_gzip():
    payload = gzip.compress(b"SENTINEL_TEST_MARKER")
    entries = unpack(payload, "data.gz", ScanConfig())
    assert entries[0].path == "data.gz!/data"
    assert entries[0].data == b"SENTINEL_TEST_MARKER"


def test_rejects_unsafe_names():
    with pytest.raises(ContainerError):
        unpack(make_zip({"../evil.txt": b"x"}), "bad.zip", ScanConfig())


def test_rejects_compression_bomb():
    payload = make_zip({"zeros.bin": b"\x00" * (1024 * 1024)})
    config = ScanConfig(container_max_ratio=10)
    with pytest.raises(ContainerError):
        unpack(payload, "bomb.zip", config)


def test_scanner_detects_inside_zip(tmp_path):
    from pathlib import Path

    from sentinel.engine.signatures import SignatureDatabase

    archive = tmp_path / "paquete.zip"
    archive.write_bytes(make_zip({"marker.txt": b"SENTINEL_TEST_MARKER"}))
    database = SignatureDatabase.load(
        Path(__file__).parent.parent / "sentinel" / "data" / "signatures.json"
    )
    result = Scanner(database).scan([archive])
    assert result.container_entries == 1
    assert any("marker.txt" in item.path for item in result.findings)
    assert all("contenedor:" in " ".join(item.indicators) for item in result.findings)
