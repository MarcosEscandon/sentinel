"""Shared test utilities."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from sentinel.config import ScanConfig
from sentinel.core.models import Severity
from sentinel.engine.signatures import SignatureDatabase


@pytest.fixture
def sample_db() -> SignatureDatabase:
    return SignatureDatabase.from_dict(
        {
            "schema": 1,
            "version": "test",
            "hashes": {
                "a" * 64: {
                    "id": "HASH-TEST",
                    "severity": "critical",
                    "description": "Test signature",
                }
            },
            "filenames": [
                {
                    "id": "NAME-TEST",
                    "pattern": r"\.bad$",
                    "severity": "medium",
                    "description": "Test extension",
                }
            ],
            "content": [
                {
                    "id": "CONTENT-TEST",
                    "pattern": "MARKER",
                    "severity": "low",
                    "description": "Test content",
                }
            ],
        }
    )


@pytest.fixture
def default_db() -> SignatureDatabase:
    return SignatureDatabase.load(Path(__file__).parent.parent / "sentinel" / "data" / "signatures.json")


@pytest.fixture
def tuned_config() -> ScanConfig:
    return ScanConfig(entropy_threshold=7.0, entropy_min_size=64, suspicion_threshold=5.0)


def make_minimal_pe() -> bytes:
    """Builds a minimal PE32 with a suspicious import and no real code."""
    data = bytearray(0x600)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH", data, 0x44, 0x014C, 1, 0, 0, 0, 224, 0x0102
    )

    optional = 0x58
    struct.pack_into("<H", data, optional, 0x010B)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 8, 0x1000, 40)

    section = optional + 224
    data[section : section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x200)

    # IMAGE_IMPORT_DESCRIPTOR at the start of the section.
    struct.pack_into("<IIIII", data, 0x200, 0x1200, 0, 0, 0x1100, 0x1210)
    data[0x300 : 0x300 + len(b"KERNEL32.dll\x00")] = b"KERNEL32.dll\x00"
    struct.pack_into("<II", data, 0x400, 0x1300, 0)
    data[0x500 : 0x502] = b"\x02\x00"
    name = b"VirtualAllocEx\x00"
    data[0x502 : 0x502 + len(name)] = name
    return bytes(data)


def make_severity(value: str) -> Severity:
    return Severity.parse(value)
