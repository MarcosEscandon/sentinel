"""Tests for fail-closed verification of signature databases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import crypto, trust

pytest.importorskip("cryptography")

BUNDLED = Path(__file__).parent.parent / "sentinel" / "data" / "signatures.json"


def _unsigned_database(directory: Path, revision: int = 1) -> Path:
    database = directory / "signatures.json"
    database.write_text(
        json.dumps(
            {
                "schema": 1,
                "version": "test",
                "revision": revision,
                "hashes": {},
                "filenames": [],
                "content": [],
            }
        ),
        encoding="utf-8",
    )
    return database


def test_bundled_database_verifies_with_adjacent_public_key() -> None:
    database = trust.load_database(BUNDLED)
    assert database.revision >= 3
    assert database.hashes


def test_tampered_database_is_rejected(tmp_path: Path) -> None:
    payload = json.loads(BUNDLED.read_text(encoding="utf-8"))
    payload["revision"] += 1
    database = _unsigned_database(tmp_path, payload["revision"])
    database.write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "signatures.json.pub").write_bytes(
        (BUNDLED.parent / "signatures.json.pub").read_bytes()
    )

    with pytest.raises(ValueError, match="was modified"):
        trust.load_database(database)


def test_unsigned_database_is_rejected_unless_opted_out(tmp_path: Path) -> None:
    database = _unsigned_database(tmp_path)

    with pytest.raises(ValueError, match="No trusted Ed25519 public key"):
        trust.load_database(database)

    assert trust.load_database(database, require_signature=False).revision == 1


def test_public_key_resolution_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "explicit.pub"
    from_env = tmp_path / "env.pub"
    from_home = tmp_path / "home" / "signing.pub"
    adjacent = tmp_path / "signatures.json.pub"
    for path in (explicit, from_env, from_home, adjacent):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((BUNDLED.parent / "signatures.json.pub").read_bytes())
    monkeypatch.setenv(trust.PUBLIC_KEY_ENV, str(from_env))

    database = tmp_path / "signatures.json"
    candidates = trust.public_key_candidates(tmp_path / "home", database, explicit)

    assert candidates[:4] == [explicit, from_env, from_home, adjacent]
    assert trust.trusted_public_key(tmp_path / "home", database, explicit) == explicit
    assert trust.trusted_public_key(tmp_path / "home", database) == from_env


def test_explicit_missing_key_is_an_error(tmp_path: Path) -> None:
    database = _unsigned_database(tmp_path)

    with pytest.raises(ValueError, match="Trusted public key not found"):
        trust.load_database(database, public_key=tmp_path / "missing.pub")


def test_signed_database_loads_with_explicit_key(tmp_path: Path) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    crypto.generate_keypair(private, public)
    database = _unsigned_database(tmp_path, 7)
    Path(f"{database}.sig").write_bytes(crypto.sign_payload(database.read_bytes(), private))

    assert trust.load_database(database, public_key=public).revision == 7
