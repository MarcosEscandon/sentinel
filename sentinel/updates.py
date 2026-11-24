"""Secure updating of the signature database.

Chain of trust:

1. Download the JSON and its separate Ed25519 signature (``<url>.sig`` by default).
2. Verify the signature with a mandatory trusted public key.
3. Validate the schema and that the revision is newer than the installed one.
4. Replace the file atomically, keeping a ``.bak`` copy.

If any step fails, the installed file remains intact.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from . import crypto
from .engine.signatures import SignatureDatabase

MAX_DOWNLOAD = 10 * 1024 * 1024
MAX_SIGNATURE = 4096


def _download(url: str, limit: int, timeout: float) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"URL not allowed (http/https only): {url}")
    # The scheme was already validated explicitly above; file:/custom are not accepted.
    with urllib.request.urlopen(url, timeout=timeout) as response:  # nosec B310
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"Download exceeds the {limit}-byte limit: {url}")
    if not payload:
        raise ValueError(f"Download is empty: {url}")
    return payload


def update_signatures(
    url: str,
    target: str | Path,
    public_key_path: str | Path,
    signature_url: str | None = None,
    expected_sha256: str | None = None,
    timeout: float = 30.0,
) -> dict[str, object]:
    """Downloads, verifies, and installs a signature database.

    ``public_key_path`` and the separate signature are mandatory: an update
    without a chain of trust is always rejected.
    """
    if not crypto.available():
        raise crypto.SigningUnavailable(
            "cryptography is not installed. Install it with: pip install -e '.[signing]'"
        )
    if not Path(public_key_path).is_file():
        raise FileNotFoundError(f"Trusted public key not found: {public_key_path}")

    destination = Path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    sig_url = signature_url or f"{url}.sig"

    payload = _download(url, MAX_DOWNLOAD, timeout)
    signature = _download(sig_url, MAX_SIGNATURE, timeout)
    if len(signature) != 64:
        raise ValueError(f"Invalid Ed25519 signature: expected 64 bytes, received {len(signature)}")

    if not crypto.verify_payload(payload, signature, public_key_path):
        raise ValueError("Invalid Ed25519 signature: the signature database has NOT been installed")

    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise ValueError(
            f"Download hash mismatch: expected {expected_sha256}, got {digest}"
        )

    new_database = SignatureDatabase.from_dict(json.loads(payload.decode("utf-8")))
    current = (
        SignatureDatabase.load(destination)
        if destination.is_file()
        else SignatureDatabase.empty()
    )
    new_database.check_rollback(current)
    if current.revision > 0 and new_database.revision <= current.revision:
        raise ValueError(
            f"Downloaded revision ({new_database.revision}) must be greater "
            f"than the installed revision ({current.revision})"
        )

    handle, temp_name = tempfile.mkstemp(
        prefix="sentinel-sig-", suffix=".json", dir=str(destination.parent)
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
        if destination.exists():
            shutil.copy2(destination, destination.with_suffix(destination.suffix + ".bak"))
        temp_path.replace(destination)
    finally:
        if temp_path.exists():
            temp_path.unlink()

    return {
        "sha256": digest,
        "revision": new_database.revision,
        "stats": new_database.stats(),
        "destination": str(destination),
        "signature_url": sig_url,
    }


__all__ = ["MAX_DOWNLOAD", "update_signatures"]
