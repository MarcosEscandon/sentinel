"""Ed25519 signing and verification of signature packages.

The ``cryptography`` dependency is optional for normal scanning, but required
to sign or update the signature database::

    pip install -e ".[signing]"
"""

from __future__ import annotations

from pathlib import Path

try:  #pragma: no cover - depends on the environment
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
except ImportError:  # pragma: no cover
    _InvalidSignature = None
    _serialization = None
    _ed25519 = None


class SigningUnavailable(RuntimeError):
    """Raised when signing is required but ``cryptography`` is not installed."""


def available() -> bool:
    return _serialization is not None and _ed25519 is not None


def _require() -> None:
    if not available():
        raise SigningUnavailable(
            "cryptography is not installed. Install it with: pip install -e '.[signing]'"
        )


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Generates an Ed25519 key pair and saves it in PEM format.

    The private key is created with restricted permissions on POSIX systems.
    """
    _require()
    private = Path(private_path)
    public = Path(public_path)
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
    public.write_bytes(public_bytes)


def sign_payload(payload: bytes, private_key_path: str | Path) -> bytes:
    """Returns the Ed25519 signature (64 bytes) of ``payload``."""
    _require()
    data = Path(private_key_path).read_bytes()
    key = _serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, _ed25519.Ed25519PrivateKey):
        raise TypeError("The private key must be Ed25519")
    return key.sign(payload)


def verify_payload(payload: bytes, signature: bytes, public_key_path: str | Path) -> bool:
    """Verifies a signature. Returns ``False`` if it does not match or is invalid."""
    _require()
    data = Path(public_key_path).read_bytes()
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
    "generate_keypair",
    "sign_payload",
    "verify_payload",
]
