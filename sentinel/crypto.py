"""Ed25519 signing and verification of signature packages.

``cryptography`` is used when available. A self-contained RFC 8032 fallback in
:mod:`sentinel._ed25519` keeps signing, updating, and fail-closed verification
working with the standard library alone. Both backends use identical PKCS#8 /
SPKI PEM files and 64-byte detached signatures.
"""

from __future__ import annotations

from pathlib import Path

from . import _ed25519 as _pure
from .security_fs import restrict_permissions

try:  # pragma: no cover - depends on the environment
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
except ImportError:  # pragma: no cover
    _InvalidSignature = None
    _serialization = None
    _ed25519 = None


class SigningUnavailable(RuntimeError):
    """Retained for API compatibility; the stdlib backend makes it unreachable."""


def available() -> bool:
    """Return ``True`` because one of the two Ed25519 backends is always usable."""
    return True


def backend() -> str:
    """Return the active backend name (``cryptography`` or ``stdlib``)."""
    return "cryptography" if _ed25519 is not None and _serialization is not None else "stdlib"


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Generate an Ed25519 key pair and save it in PEM format.

    The private key is created with restricted permissions (POSIX mode and a
    Windows ACL that grants only the current user).
    """
    private = Path(private_path)
    public = Path(public_path)
    if backend() == "stdlib":
        _pure.write_keypair(private, public)
        return

    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    key = _ed25519.Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        encoding=_serialization.Encoding.PEM,
        format=_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=_serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        encoding=_serialization.Encoding.PEM,
        format=_serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private.write_bytes(private_bytes)
    try:
        private.chmod(0o600)
    except OSError:
        pass
    restrict_permissions(private)
    public.write_bytes(public_bytes)


def sign_payload(payload: bytes, private_key_path: str | Path) -> bytes:
    """Return the Ed25519 signature (64 bytes) of ``payload``."""
    data = Path(private_key_path).read_bytes()
    if backend() == "stdlib":
        return _pure.sign(_pure.parse_private_pem(data), payload)
    key = _serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, _ed25519.Ed25519PrivateKey):
        raise TypeError("The private key must be Ed25519")
    return key.sign(payload)


def verify_payload(payload: bytes, signature: bytes, public_key_path: str | Path) -> bool:
    """Verify a signature. Returns ``False`` if it does not match or is invalid."""
    data = Path(public_key_path).read_bytes()
    if backend() == "stdlib":
        return _pure.verify(_pure.parse_public_pem(data), signature, payload)
    key = _serialization.load_pem_public_key(data)
    if not isinstance(key, _ed25519.Ed25519PublicKey):
        raise TypeError("The public key must be Ed25519")
    try:
        key.verify(signature, payload)
    except (_InvalidSignature, ValueError, TypeError):
        return False
    return True


__all__ = [
    "SigningUnavailable",
    "available",
    "backend",
    "generate_keypair",
    "sign_payload",
    "verify_payload",
]
