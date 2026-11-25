"""Trust anchors and verified loading of signature databases.

The CLI, GUI, real-time monitor, and Windows service all resolve the trusted
Ed25519 public key the same way: an explicit path, ``SENTINEL_PUBLIC_KEY``,
``<home>/signing.pub``, and ``<signatures>.pub`` (in that order). A database is
only used when its detached 64-byte signature validates against one of those
keys, unless the caller explicitly opts out for local development.
"""

from __future__ import annotations

import os
from pathlib import Path

from .engine.signatures import SignatureDatabase
from .integrity import verify_signatures_bundle

PUBLIC_KEY_ENV = "SENTINEL_PUBLIC_KEY"
"""Environment variable pointing at the trusted PEM public key."""

DEFAULT_HOME = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")))


def public_key_candidates(
    home: str | Path | None,
    signatures: str | Path,
    explicit: str | Path | None = None,
) -> list[Path]:
    """Return the supported public-key locations, most trusted first."""
    root = Path(home) if home is not None else DEFAULT_HOME
    database = Path(signatures)
    candidates = [
        Path(explicit) if explicit is not None else None,
        Path(configured) if (configured := os.environ.get(PUBLIC_KEY_ENV, "").strip()) else None,
        root / "signing.pub",
        Path(f"{database}.pub"),
    ]
    unique: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate is not None and candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique


def trusted_public_key(
    home: str | Path | None,
    signatures: str | Path,
    explicit: str | Path | None = None,
) -> Path | None:
    """Return the first configured public key that exists on disk."""
    return next(
        (candidate for candidate in public_key_candidates(home, signatures, explicit) if candidate.is_file()),
        None,
    )


def load_database(
    signatures: str | Path,
    *,
    home: str | Path | None = None,
    public_key: str | Path | None = None,
    require_signature: bool = True,
) -> SignatureDatabase:
    """Load a database, verifying its Ed25519 signature by default.

    ``require_signature=False`` is intended only for local development with
    unsigned test databases; production callers must keep the default.
    """
    database = Path(signatures)
    if not require_signature:
        return SignatureDatabase.load(database)

    key = Path(public_key) if public_key is not None else None
    if key is not None and not key.is_file():
        raise ValueError(f"Trusted public key not found: {key}")
    if key is None:
        key = trusted_public_key(home, database)
    if key is None:
        raise ValueError(
            "No trusted Ed25519 public key found for the signature database; "
            f"set {PUBLIC_KEY_ENV}, add <home>/signing.pub, or place <signatures>.pub next to it"
        )
    if not verify_signatures_bundle(database, key):
        raise ValueError(
            f"Signature database is unsigned or was modified: {database} "
            f"(verified with {key})"
        )
    return SignatureDatabase.load(database)


__all__ = [
    "PUBLIC_KEY_ENV",
    "load_database",
    "public_key_candidates",
    "trusted_public_key",
]
