"""Firma y verificación Ed25519 de paquetes de firmas.

La dependencia ``cryptography`` es opcional para el escaneo normal, pero
obligatoria para firmar o actualizar la base de firmas::

    pip install -e ".[signing]"
"""

from __future__ import annotations

from pathlib import Path

try:  #pragma: no cover - depende del entorno
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519
except ImportError:  # pragma: no cover
    _InvalidSignature = None
    _serialization = None
    _ed25519 = None


class SigningUnavailable(RuntimeError):
    """Se lanza cuando se requiere firma y ``cryptography`` no está instalado."""


def available() -> bool:
    return _serialization is not None and _ed25519 is not None


def _require() -> None:
    if not available():
        raise SigningUnavailable(
            "cryptography no está instalado. Instálalo con: pip install -e '.[signing]'"
        )


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Genera un par de claves Ed25519 y lo guarda en PEM.

    La clave privada se crea con permisos restringidos en sistemas POSIX.
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
    """Devuelve la firma Ed25519 (64 bytes) de ``payload``."""
    _require()
    data = Path(private_key_path).read_bytes()
    key = _serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, _ed25519.Ed25519PrivateKey):
        raise TypeError("La clave privada debe ser Ed25519")
    return key.sign(payload)


def verify_payload(payload: bytes, signature: bytes, public_key_path: str | Path) -> bool:
    """Comprueba la firma. Devuelve ``False`` si no coincide o es inválida."""
    _require()
    data = Path(public_key_path).read_bytes()
    key = _serialization.load_pem_public_key(data)
    if not isinstance(key, _ed25519.Ed25519PublicKey):
        raise TypeError("La clave pública debe ser Ed25519")
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
