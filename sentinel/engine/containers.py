"""Descompresión segura de contenedores para análisis anidado.

Se admiten ZIP (incluidos formatos Office OOXML), TAR (con gzip/bz2/xz),
streams simples gzip/bz2/xz y compuestos OLE2/CFB (MSI, DOC, XLS, PPT, MSG).
Todos los límites son configurables en :class:`~sentinel.config.ScanConfig`
para evitar bombas de descompresión y archivos excesivamente grandes.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..config import ScanConfig
from .ole import OLE_EXTENSIONS, unpack_ole

SIMPLE_COMPRESSION = frozenset({".gz", ".bz2", ".xz"})
_TAR_EXTENSIONS = frozenset({".tar", ".tgz", ".tbz2", ".txz"})

ZIP_EXTENSIONS = frozenset(
    {
        ".zip",
        # Documentos Office abiertos y formatos OOXML.
        ".docx",
        ".xlsx",
        ".pptx",
        ".odt",
        ".ods",
        ".odp",
        # Paquetes, extensiones y aplicaciones basadas en ZIP.
        ".jar",
        ".apk",
        ".epub",
        ".nupkg",
        ".vsix",
        ".xpi",
        ".crx",
        ".ipa",
    }
)
"""Formatos que deben abrirse con el lector ZIP."""

ARCHIVE_EXTENSIONS = ZIP_EXTENSIONS | SIMPLE_COMPRESSION | _TAR_EXTENSIONS | OLE_EXTENSIONS
"""Todos los contenedores reconocidos por :func:`unpack`."""

MACRO_PATHS = frozenset(
    {
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "ppt/vbaProject.bin",
        "word/templates/vbaProject.bin",
        "xl/templates/vbaProject.bin",
        "ppt/templates/vbaProject.bin",
        "Basic",
        "Basic/Module1",
        "VBA",
        "VBA/_VBA_PROJECT",
        "VBA/dir",
        "VBA/Project",
    }
)
"""Rutas relativas típicas de proyectos VBA/macros dentro de contenedores."""

_MACRO_PATHS_LOWER = frozenset(path.lower() for path in MACRO_PATHS)


class ContainerError(Exception):
    """Un contenedor superó los límites o no se pudo abrir."""


@dataclass(frozen=True)
class ContainerEntry:
    """Un archivo extraído de un contenedor."""

    path: str
    data: bytes
    size: int
    truncated: bool = False


def _safe_name(name: str) -> str:
    """Rechaza rutas absolutas y traversal dentro del contenedor."""
    candidate = name.replace("\\", "/")
    parts = [part for part in candidate.split("/") if part not in {"", "."}]
    if (
        candidate.startswith("/")
        or ".." in parts
        or any(len(part) > 1 and part[1] == ":" for part in parts[:1])
        or not parts
    ):
        raise ContainerError(f"Nombre de archivo inseguro en contenedor: {name!r}")
    return "/".join(parts)


def _entry_limit(config: ScanConfig) -> int:
    return min(config.max_file_size, max(config.sample_size, 8 * 1024 * 1024))


def _check_size(config: ScanConfig, raw_size: int, compressed_size: int, total: int) -> None:
    if raw_size > config.container_max_uncompressed:
        raise ContainerError("un archivo del contenedor supera el tamaño descomprimido permitido")
    if total + raw_size > config.container_max_uncompressed:
        raise ContainerError("el contenedor supera el total descomprimido permitido")
    if raw_size and compressed_size:
        ratio = raw_size / compressed_size
        if ratio > config.container_max_ratio:
            raise ContainerError(f"ratio de compresión sospechoso: {ratio:.1f}")


def unpack(
    data: bytes,
    name: str,
    config: ScanConfig,
    depth: int = 0,
) -> list[ContainerEntry]:
    """Extrae entradas de un contenedor; puede llamarse recursivamente."""
    if depth >= config.container_max_depth:
        return []
    suffix = Path(name).suffix.lower()
    if suffix not in ARCHIVE_EXTENSIONS:
        return []

    entries: list[ContainerEntry] = []
    if suffix in ZIP_EXTENSIONS:
        entries = _unpack_zip(data, name, config, depth)
    elif suffix in OLE_EXTENSIONS:
        entries = unpack_ole(data, name, config, depth)
    elif suffix in SIMPLE_COMPRESSION:
        entries = _unpack_simple(data, name, config, depth)
    else:
        entries = _unpack_tar(data, name, config, depth)
    if len(entries) > config.container_max_entries:
        raise ContainerError("demasiadas entradas en el contenedor")
    return entries


def _virtual(container_name: str, inner_name: str) -> str:
    return f"{container_name}!/{inner_name}"


def _maybe_recurse(
    container_name: str,
    inner_name: str,
    content: bytes,
    config: ScanConfig,
    depth: int,
    output: list[ContainerEntry],
) -> None:
    output.append(
        ContainerEntry(
            path=_virtual(container_name, inner_name),
            data=content,
            size=len(content),
        )
    )
    if Path(inner_name).suffix.lower() in ARCHIVE_EXTENSIONS:
        output.extend(unpack(content, inner_name, config, depth + 1))


def _unpack_zip(
    data: bytes, name: str, config: ScanConfig, depth: int
) -> list[ContainerEntry]:
    output: list[ContainerEntry] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if len(infos) > config.container_max_entries:
            raise ContainerError("demasiadas entradas en el ZIP")
        total = 0
        for info in infos:
            if info.is_dir() or info.flag_bits & 0x1:
                continue  # directorios y entradas cifradas
            inner = _safe_name(info.filename)
            _check_size(config, info.file_size, len(data), total)
            with archive.open(info) as stream:
                raw = stream.read(_entry_limit(config) + 1)
            truncated = len(raw) > _entry_limit(config)
            raw = raw[: _entry_limit(config)]
            total += len(raw)
            output.append(
                ContainerEntry(
                    path=_virtual(name, inner), data=raw, size=len(raw), truncated=truncated
                )
            )
            if Path(inner).suffix.lower() in ARCHIVE_EXTENSIONS and not truncated:
                output.extend(unpack(raw, inner, config, depth + 1))
    return output


def _unpack_tar(
    data: bytes, name: str, config: ScanConfig, depth: int
) -> list[ContainerEntry]:
    output: list[ContainerEntry] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        members = archive.getmembers()
        if len(members) > config.container_max_entries:
            raise ContainerError("demasiadas entradas en el TAR")
        total = 0
        for member in members:
            if not member.isfile():
                continue
            inner = _safe_name(member.name)
            _check_size(config, member.size, len(data), total)
            stream = archive.extractfile(member)
            if stream is None:
                continue
            with stream:
                raw = stream.read(_entry_limit(config) + 1)
            truncated = len(raw) > _entry_limit(config)
            raw = raw[: _entry_limit(config)]
            total += len(raw)
            output.append(
                ContainerEntry(
                    path=_virtual(name, inner), data=raw, size=len(raw), truncated=truncated
                )
            )
            if Path(inner).suffix.lower() in ARCHIVE_EXTENSIONS and not truncated:
                output.extend(unpack(raw, inner, config, depth + 1))
    return output


def _unpack_simple(
    data: bytes, name: str, config: ScanConfig, depth: int
) -> list[ContainerEntry]:
    suffix = Path(name).suffix.lower()
    decompress = {".gz": gzip.decompress, ".bz2": bz2.decompress, ".xz": lzma.decompress}[suffix]
    raw = decompress(data[: config.container_max_uncompressed + 1])
    if len(raw) > config.container_max_uncompressed:
        raise ContainerError("el stream descomprimido supera el límite")
    _check_size(config, len(raw), len(data), 0)
    inner = name[: -len(suffix)] or "contenido"
    truncated = len(raw) > _entry_limit(config)
    content = raw[: _entry_limit(config)]
    output: list[ContainerEntry] = []
    _maybe_recurse(name, inner, content, config, depth, output)
    output[-1] = ContainerEntry(output[-1].path, content, len(content), truncated)
    return output


def find_macro_entries(entries: Iterable[ContainerEntry]) -> list[ContainerEntry]:
    """Devuelve las entradas que parecen proyectos VBA/macros.

    La comparación es insensible a mayúsculas y acepta tanto ``/`` como ``\\``.
    Se ignora el prefijo virtual del contenedor (``archivo.zip!/``) para que
    funcione igual con entradas ZIP, TAR u OLE, incluidas las anidadas.
    """
    found: list[ContainerEntry] = []
    for entry in entries:
        inner = entry.path.replace("\\", "/").lower().rsplit("!/", 1)[-1]
        parts = [part for part in inner.split("/") if part]
        if (
            inner in _MACRO_PATHS_LOWER
            or inner.endswith("vbaproject.bin")
            or any(part in {"vba", "basic"} for part in parts)
        ):
            found.append(entry)
    return found


__all__ = [
    "ARCHIVE_EXTENSIONS",
    "MACRO_PATHS",
    "OLE_EXTENSIONS",
    "ZIP_EXTENSIONS",
    "ContainerEntry",
    "ContainerError",
    "find_macro_entries",
    "unpack",
]
