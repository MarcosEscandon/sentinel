"""Minimal pure-Python Ed25519 (RFC 8032) with PKCS#8/SPKI PEM support.

This is the fallback backend used when ``cryptography`` is not installed. The
``cryptography`` backend remains preferred; both produce and accept the same
PEM formats and 64-byte detached signatures. The implementation is covered by
the RFC 8032 test vectors and by cross-backend tests.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from pathlib import Path

from .security_fs import restrict_permissions

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_MINUS_ONE = pow(2, (P - 1) // 4, P)
BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
OID_ED25519 = bytes.fromhex("06032b6570")
_PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----", re.DOTALL)

_Point = tuple[int, int, int, int]
_Base = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)


def _encodepoint(x: int, y: int) -> bytes:
    """Encode an affine point in the 32-byte RFC 8032 format."""
    encoded = bytearray(y.to_bytes(32, "little"))
    encoded[31] |= (x & 1) << 7
    return bytes(encoded)


def _decodepoint(data: bytes) -> _Point:
    """Decode and validate a compressed point, returning extended coordinates."""
    if len(data) != 32:
        raise ValueError("Ed25519 points must be 32 bytes")
    encoded = bytearray(data)
    sign = encoded[31] >> 7
    encoded[31] &= 0x7F
    y = int.from_bytes(encoded, "little")
    if y >= P:
        raise ValueError("Non-canonical Ed25519 point")
    y2 = y * y % P
    xx = (y2 - 1) * pow(D * y2 + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if x * x % P != xx:
        x = x * SQRT_MINUS_ONE % P
    if x * x % P != xx:
        raise ValueError("Point is not on the Ed25519 curve")
    if x == 0 and sign == 1:
        raise ValueError("Non-canonical Ed25519 point")
    if sign != (x & 1):
        x = P - x
    if _encodepoint(x, y) != data:
        raise ValueError("Non-canonical Ed25519 point")
    return (x, y, 1, x * y % P)


def _affine(point: _Point) -> tuple[int, int]:
    x, y, z, _ = point
    inverse = pow(z, P - 2, P)
    return x * inverse % P, y * inverse % P


def _add(a: _Point, b: _Point) -> _Point:
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    first = (y1 - x1) * (y2 - x2) % P
    second = (y1 + x1) * (y2 + x2) % P
    third = t1 * (2 * D * t2 % P) % P
    fourth = z1 * (2 * z2) % P
    e = (second - first) % P
    f = (fourth - third) % P
    g = (fourth + third) % P
    h = (second + first) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _double(point: _Point) -> _Point:
    x, y, z, _ = point
    a = x * x % P
    b = y * y % P
    c = 2 * z * z % P
    d = -a % P
    e = ((x + y) * (x + y) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _multiply(scalar: int, point: _Point) -> _Point:
    result = (0, 1, 1, 0)
    for index in range(scalar.bit_length() - 1, -1, -1):
        result = _double(result)
        if (scalar >> index) & 1:
            result = _add(result, point)
    return result


def _clamp(seed_hash: bytes) -> int:
    scalar = bytearray(seed_hash[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def public_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte Ed25519 seed."""
    if len(seed) != 32:
        raise ValueError("An Ed25519 seed must be 32 bytes")
    secret = _clamp(hashlib.sha512(seed).digest())
    return _encodepoint(*_affine(_multiply(secret, _Base)))


def sign(seed: bytes, message: bytes) -> bytes:
    """Return the deterministic 64-byte Ed25519 signature of ``message``."""
    if len(seed) != 32:
        raise ValueError("An Ed25519 seed must be 32 bytes")
    hashed = hashlib.sha512(seed).digest()
    secret = _clamp(hashed)
    public = _encodepoint(*_affine(_multiply(secret, _Base)))
    nonce = int.from_bytes(hashlib.sha512(hashed[32:] + message).digest(), "little") % L
    commitment = _encodepoint(*_affine(_multiply(nonce, _Base)))
    challenge = (
        int.from_bytes(hashlib.sha512(commitment + public + message).digest(), "little") % L
    )
    proof = (nonce + challenge * secret) % L
    return commitment + proof.to_bytes(32, "little")


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify a 64-byte signature; return ``False`` for any invalid input."""
    if len(signature) != 64:
        return False
    proof = int.from_bytes(signature[32:], "little")
    if proof >= L:
        return False
    try:
        public = _decodepoint(public_key)
        commitment = _decodepoint(signature[:32])
    except ValueError:
        return False
    challenge = (
        int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
        % L
    )
    left = _encodepoint(*_affine(_multiply(proof, _Base)))
    right = _encodepoint(*_affine(_add(commitment, _multiply(challenge, public))))
    return left == right


def _pem_to_der(data: bytes, expected: str) -> bytes:
    match = _PEM_RE.search(data)
    if match is None or match.group(1).decode("ascii") != expected:
        raise ValueError(f"Expected a PEM block labeled {expected!r}")
    try:
        return base64.b64decode(re.sub(rb"\s+", b"", match.group(2)), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid base64 in PEM block") from exc


def _der_to_pem(label: str, der: bytes) -> bytes:
    body = base64.b64encode(der)
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    header = f"-----BEGIN {label}-----\n".encode("ascii")
    footer = f"-----END {label}-----\n".encode("ascii")
    return header + b"\n".join(lines) + b"\n" + footer


def _length(value: int) -> bytes:
    if value < 128:
        return bytes([value])
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("Truncated DER structure")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("Unsupported DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("Truncated DER value")
    return tag, data[offset:end], end


def _algorithm_der() -> bytes:
    return _tlv(0x30, OID_ED25519)


def _check_algorithm(encoded: bytes) -> None:
    """Validate the OID inside an AlgorithmIdentifier's content."""
    if encoded != OID_ED25519:
        raise TypeError("The key must be Ed25519")


def parse_private_pem(data: bytes) -> bytes:
    """Extract the 32-byte seed from a PKCS#8 Ed25519 private key."""
    der = _pem_to_der(data, "PRIVATE KEY")
    tag, info, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("Invalid PKCS#8 structure")
    offset = 0
    tag, version, offset = _read_tlv(info, offset)
    if tag != 0x02 or version not in (b"\x00", b"\x01"):
        raise ValueError("Unsupported PKCS#8 version")
    tag, algorithm, offset = _read_tlv(info, offset)
    if tag != 0x30:
        raise ValueError("Invalid AlgorithmIdentifier")
    _check_algorithm(algorithm)
    tag, private, offset = _read_tlv(info, offset)
    if tag != 0x04 or offset != len(info):
        raise ValueError("Invalid PKCS#8 private key")
    if len(private) == 32:
        return private
    inner_tag, seed, inner_end = _read_tlv(private, 0)
    if inner_tag != 0x04 or inner_end != len(private) or len(seed) != 32:
        raise ValueError("Invalid Ed25519 seed")
    return seed


def parse_public_pem(data: bytes) -> bytes:
    """Extract and validate the 32-byte key from an SPKI Ed25519 public key."""
    der = _pem_to_der(data, "PUBLIC KEY")
    tag, info, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("Invalid SubjectPublicKeyInfo structure")
    offset = 0
    tag, algorithm, offset = _read_tlv(info, offset)
    if tag != 0x30:
        raise ValueError("Invalid AlgorithmIdentifier")
    _check_algorithm(algorithm)
    tag, bits, offset = _read_tlv(info, offset)
    if tag != 0x03 or offset != len(info) or not bits or bits[0] != 0:
        raise ValueError("Invalid public key BIT STRING")
    key = bits[1:]
    _decodepoint(key)
    return key


def pkcs8_pem(seed: bytes) -> bytes:
    """Encode a seed as an unencrypted PKCS#8 PEM private key."""
    if len(seed) != 32:
        raise ValueError("An Ed25519 seed must be 32 bytes")
    info = _tlv(0x02, b"\x00") + _algorithm_der() + _tlv(0x04, _tlv(0x04, seed))
    return _der_to_pem("PRIVATE KEY", _tlv(0x30, info))


def spki_pem(public_key: bytes) -> bytes:
    """Encode a raw public key as an SPKI PEM public key."""
    if len(public_key) != 32:
        raise ValueError("An Ed25519 public key must be 32 bytes")
    _decodepoint(public_key)
    info = _algorithm_der() + _tlv(0x03, b"\x00" + public_key)
    return _der_to_pem("PUBLIC KEY", _tlv(0x30, info))


def generate_pem_keypair() -> tuple[bytes, bytes]:
    """Return ``(private_pem, public_pem)`` from a fresh random seed."""
    seed = os.urandom(32)
    return pkcs8_pem(seed), spki_pem(public_from_seed(seed))


def write_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Write a PEM key pair restricted to the current OS user."""
    private_pem, public_pem = generate_pem_keypair()
    private = Path(private_path)
    public = Path(public_path)
    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    private.write_bytes(private_pem)
    try:
        private.chmod(0o600)
    except OSError:
        pass
    restrict_permissions(private)
    public.write_bytes(public_pem)


__all__ = [
    "generate_pem_keypair",
    "parse_private_pem",
    "parse_public_pem",
    "public_from_seed",
    "sign",
    "verify",
    "write_keypair",
]
