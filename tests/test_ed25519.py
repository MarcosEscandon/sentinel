"""Tests for the pure-Python Ed25519 fallback and backend interoperability."""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path

import pytest

from sentinel import _ed25519, crypto

VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
            "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        (
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    ),
]


@pytest.mark.parametrize(("seed_hex", "public_hex", "message_hex", "signature_hex"), VECTORS)
def test_rfc8032_test_vectors(seed_hex, public_hex, message_hex, signature_hex) -> None:
    seed = bytes.fromhex(seed_hex)
    public = bytes.fromhex(public_hex)
    message = bytes.fromhex(message_hex)
    signature = bytes.fromhex(signature_hex)

    assert _ed25519.public_from_seed(seed) == public
    assert _ed25519.sign(seed, message) == signature
    assert _ed25519.verify(public, signature, message)


def test_invalid_signatures_are_rejected() -> None:
    seed = bytes.fromhex(VECTORS[0][0])
    public = _ed25519.public_from_seed(seed)
    signature = _ed25519.sign(seed, b"message")

    assert not _ed25519.verify(public, signature, b"tampered")
    assert not _ed25519.verify(public, signature[:-1], b"message")
    assert not _ed25519.verify(public, b"\x00" * 64, b"message")
    assert not _ed25519.verify(b"\xff" * 32, signature, b"message")
    assert not _ed25519.verify(public, signature[:32] + b"\xff" * 32, b"message")


def test_pem_roundtrip() -> None:
    private, public = _ed25519.generate_pem_keypair()
    seed = _ed25519.parse_private_pem(private)
    key = _ed25519.parse_public_pem(public)

    assert _ed25519.public_from_seed(seed) == key
    assert _ed25519.pkcs8_pem(seed) == private
    assert _ed25519.spki_pem(key) == public


def test_standard_library_backend_signs_and_verifies(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(crypto, "_ed25519", None)
    monkeypatch.setattr(crypto, "_serialization", None)
    assert crypto.backend() == "stdlib"

    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    crypto.generate_keypair(private, public)
    signature = crypto.sign_payload(b"fallback payload", private)

    assert len(signature) == 64
    assert crypto.verify_payload(b"fallback payload", signature, public)
    assert not crypto.verify_payload(b"modified payload", signature, public)


@pytest.mark.skipif(find_spec("cryptography") is None, reason="cryptography not installed")
def test_cross_backend_compatibility(tmp_path: Path, monkeypatch) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    crypto.generate_keypair(private, public)
    assert crypto.backend() == "cryptography"

    seed = _ed25519.parse_private_pem(private.read_bytes())
    assert _ed25519.public_from_seed(seed) == _ed25519.parse_public_pem(public.read_bytes())
    signature = _ed25519.sign(seed, b"cross backend")
    assert crypto.verify_payload(b"cross backend", signature, public)

    with monkeypatch.context() as patch:
        patch.setattr(crypto, "_ed25519", None)
        patch.setattr(crypto, "_serialization", None)
        signature = crypto.sign_payload(b"cross backend", private)
    assert crypto.verify_payload(b"cross backend", signature, public)
