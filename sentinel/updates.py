"""Actualización segura de la base de firmas.

Cadena de confianza:

1. Se descargan el JSON y su firma Ed25519 separada (``<url>.sig`` por defecto).
2. Se verifica la firma con una clave pública de confianza obligatoria.
3. Se valida el esquema y que la revisión sea mayor que la instalada.
4. Se sustituye el archivo de forma atómica conservando un ``.bak``.

Si cualquiera de los pasos falla, el archivo instalado queda intacto.
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
        raise ValueError(f"URL no permitida (solo http/https): {url}")
    # El esquema ya se validó explícitamente arriba; no se aceptan file:/custom.
    with urllib.request.urlopen(url, timeout=timeout) as response:  # nosec B310
        payload = response.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"La descarga supera el límite de {limit} bytes: {url}")
    if not payload:
        raise ValueError(f"La descarga está vacía: {url}")
    return payload


def update_signatures(
    url: str,
    target: str | Path,
    public_key_path: str | Path,
    signature_url: str | None = None,
    expected_sha256: str | None = None,
    timeout: float = 30.0,
) -> dict[str, object]:
    """Descarga, verifica e instala una base de firmas.

    ``public_key_path`` y la firma separada son obligatorios: una actualización
    sin cadena de confianza se rechaza siempre.
    """
    if not crypto.available():
        raise crypto.SigningUnavailable(
            "cryptography no está instalado. Instálalo con: pip install -e '.[signing]'"
        )
    if not Path(public_key_path).is_file():
        raise FileNotFoundError(f"Clave pública de confianza no encontrada: {public_key_path}")

    destination = Path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    sig_url = signature_url or f"{url}.sig"

    payload = _download(url, MAX_DOWNLOAD, timeout)
    signature = _download(sig_url, MAX_SIGNATURE, timeout)
    if len(signature) != 64:
        raise ValueError(f"Firma Ed25519 inválida: se esperaban 64 bytes, se recibieron {len(signature)}")

    if not crypto.verify_payload(payload, signature, public_key_path):
        raise ValueError("Firma Ed25519 no válida: la base de firmas NO se ha instalado")

    digest = hashlib.sha256(payload).hexdigest()
    if expected_sha256 and digest.lower() != expected_sha256.lower():
        raise ValueError(
            f"Hash de la descarga no coincide: esperado {expected_sha256}, obtenido {digest}"
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
            f"La revisión descargada ({new_database.revision}) debe ser mayor "
            f"que la instalada ({current.revision})"
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
