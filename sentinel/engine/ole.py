"""Minimal dependency-free Compound File Binary (OLE2/CFB) parser.

Extracts streams from legacy Office documents (``.doc``, ``.xls``, ``.ppt``,
``.msg``) and MSI packages so the scanner can apply its signatures to the
content. It implements only what is needed: FAT, MiniFAT, directory, and
mini-stream, always respecting the limits of :class:`~sentinel.config.ScanConfig`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..config import ScanConfig

if TYPE_CHECKING:  # pragma: no cover - for type checkers only
    from .containers import ContainerEntry

OLE_EXTENSIONS = frozenset({".msi", ".doc", ".xls", ".ppt", ".msg"})
"""Compound File Binary (OLE2) formats that the CFB reader must open."""

_OLE_SIGNATURE = bytes.fromhex("d0cf11e0a1b11ae1")
_MAXREGSECT = 0xFFFFFFFA  # Above this value, sectors/pointers are special.
_DEFAULT_MINI_CUTOFF = 4096
_DIR_ENTRY_SIZE = 128


class _ContainerFormatError(Exception):
    """Internal CFB parsing error (translated to ContainerError)."""


@dataclass(frozen=True)
class _DirectoryEntry:
    """128-byte entry in the CFB directory."""

    name: str
    obj_type: int  # 1 = storage, 2 = stream, 5 = root
    left: int
    right: int
    child: int
    start: int
    size: int


def _invalid(message: str) -> _ContainerFormatError:
    """Builds a format error with a clear message."""
    return _ContainerFormatError(f"invalid OLE2 file: {message}")


class _CompoundFile:
    """Low-level reader for the CFB structure."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._read_header()
        self.fat = self._read_fat()
        self.minifat = self._read_minifat()
        self.entries = self._read_directory()
        self.streams = self._collect_streams()
        self.mini_stream = self._read_mini_stream()

    def _read_header(self) -> None:
        """Validates the 512-byte header and extracts the global parameters."""
        data = self.data
        if len(data) < 512 or data[:8] != _OLE_SIGNATURE:
            raise _invalid("missing CFB header (D0 CF 11 E0 A1 B1 1A E1)")

        sector_shift = struct.unpack_from("<H", data, 30)[0]
        if sector_shift not in (9, 12):
            raise _invalid(f"unsupported sector size (2^{sector_shift})")
        self.sector_size = 1 << sector_shift

        mini_shift = struct.unpack_from("<H", data, 32)[0]
        self.mini_size = 1 << mini_shift if 1 <= mini_shift <= 12 else 64
        self.mini_cutoff = struct.unpack_from("<I", data, 56)[0] or _DEFAULT_MINI_CUTOFF
        self.num_fat = struct.unpack_from("<I", data, 44)[0]
        self.first_dir = struct.unpack_from("<I", data, 48)[0]
        self.first_minifat = struct.unpack_from("<I", data, 60)[0]
        self.num_minifat = struct.unpack_from("<I", data, 64)[0]
        self.first_difat = struct.unpack_from("<I", data, 68)[0]
        self.num_difat = struct.unpack_from("<I", data, 72)[0]
        self.difat = list(struct.unpack_from("<109I", data, 76))
        if self.first_dir >= _MAXREGSECT:
            raise _invalid("no directory sector")

    def _sector(self, sid: int) -> bytes:
        """Returns the contents of a regular sector by its identifier."""
        offset = (sid + 1) * self.sector_size
        if sid >= _MAXREGSECT or offset + self.sector_size > len(self.data):
            raise _invalid(f"sector out of range: {sid}")
        return self.data[offset : offset + self.sector_size]

    def _fat_sector_ids(self) -> list[int]:
        """Collects FAT sectors from the main DIFAT and the extended DIFAT."""
        ids = [sid for sid in self.difat if sid < _MAXREGSECT]
        sid = self.first_difat
        seen: set[int] = set()
        for _ in range(min(self.num_difat, 65536)):
            if sid in seen or sid >= _MAXREGSECT:
                break
            seen.add(sid)
            values = struct.unpack(f"<{self.sector_size // 4}I", self._sector(sid))
            ids.extend(value for value in values[:-1] if value < _MAXREGSECT)
            sid = values[-1]
        # A FAT sector must not be counted twice.
        return list(dict.fromkeys(ids))

    def _chain(self, start: int, table: list[int]) -> list[int]:
        """Follows a sector chain, detecting loops and short tables."""
        if start >= _MAXREGSECT:
            return []
        chain: list[int] = []
        seen: set[int] = set()
        sid = start
        limit = len(self.data) // self.sector_size + 1
        while sid < _MAXREGSECT and sid not in seen:
            if len(chain) > limit:
                raise _invalid("sector chain too long")
            if sid >= len(table):
                raise _invalid("incomplete FAT/MiniFAT table")
            seen.add(sid)
            chain.append(sid)
            sid = table[sid]
        return chain

    def _read_fat(self) -> list[int]:
        """Builds the FAT table from its sectors."""
        fat: list[int] = []
        for sid in self._fat_sector_ids():
            fat.extend(struct.unpack(f"<{self.sector_size // 4}I", self._sector(sid)))
        if not fat:
            raise _invalid("empty FAT table")
        return fat

    def _read_minifat(self) -> list[int]:
        """Builds the MiniFAT, needed for small streams."""
        if self.first_minifat >= _MAXREGSECT or not self.num_minifat:
            return []
        minifat: list[int] = []
        chain = self._chain(self.first_minifat, self.fat)[: self.num_minifat]
        for sid in chain:
            minifat.extend(struct.unpack(f"<{self.sector_size // 4}I", self._sector(sid)))
        return minifat

    def _read_directory(self) -> list[_DirectoryEntry]:
        """Parses the directory entry tree."""
        raw = b"".join(self._sector(sid) for sid in self._chain(self.first_dir, self.fat))
        entries: list[_DirectoryEntry] = []
        for offset in range(0, len(raw) - _DIR_ENTRY_SIZE + 1, _DIR_ENTRY_SIZE):
            chunk = raw[offset : offset + _DIR_ENTRY_SIZE]
            name_len = struct.unpack_from("<H", chunk, 64)[0]
            if not 0 < name_len <= 64 or name_len % 2:
                continue
            obj_type = chunk[66]
            if obj_type not in (1, 2, 5):
                continue
            name = chunk[: name_len - 2].decode("utf-16-le", errors="replace")
            left, right, child = struct.unpack_from("<III", chunk, 68)
            start = struct.unpack_from("<I", chunk, 116)[0]
            size = struct.unpack_from("<Q", chunk, 120)[0]
            if start >= _MAXREGSECT:
                start = 0
            if self.sector_size == 512:
                size &= 0xFFFFFFFF  # Version 3 uses only the lower 32 bits.
            entries.append(_DirectoryEntry(name, obj_type, left, right, child, start, size))
        if not entries or entries[0].obj_type != 5:
            raise _invalid("directory without a root entry")
        return entries

    def _collect_streams(self) -> list[tuple[str, _DirectoryEntry]]:
        """Returns ``(path, entry)`` for each stream in the directory."""
        streams: list[tuple[str, _DirectoryEntry]] = []
        visited: set[int] = set()

        def walk(index: int, prefix: str) -> None:
            if index >= len(self.entries) or index >= _MAXREGSECT or index in visited:
                return
            visited.add(index)
            entry = self.entries[index]
            walk(entry.left, prefix)
            if entry.obj_type == 2:
                streams.append((f"{prefix}{entry.name}", entry))
            else:
                child_prefix = prefix if entry.obj_type == 5 else f"{prefix}{entry.name}/"
                walk(entry.child, child_prefix)
            walk(entry.right, prefix)

        walk(0, "")
        return streams

    def _read_regular(self, start: int, size: int) -> bytes:
        """Reads up to ``size`` bytes by following the FAT chain."""
        if start >= _MAXREGSECT or size <= 0:
            return b""
        output = bytearray()
        for sid in self._chain(start, self.fat):
            output.extend(self._sector(sid))
            if len(output) >= size:
                break
        return bytes(output[:size])

    def _read_mini_stream(self) -> bytes:
        """Reconstructs the mini-stream from the root entry's size."""
        root = self.entries[0]
        if root.start >= _MAXREGSECT or not root.size:
            return b""
        return self._read_regular(root.start, min(root.size, len(self.data)))

    def _read_mini(self, start: int, size: int) -> bytes:
        """Reads up to ``size`` bytes from the mini-stream using the MiniFAT."""
        if start >= _MAXREGSECT or size <= 0 or not self.minifat:
            return b""
        output = bytearray()
        seen: set[int] = set()
        sid = start
        while sid < _MAXREGSECT and sid not in seen:
            if sid >= len(self.minifat):
                raise _invalid("incomplete MiniFAT")
            seen.add(sid)
            offset = sid * self.mini_size
            output.extend(self.mini_stream[offset : offset + self.mini_size])
            if len(output) >= size:
                break
            sid = self.minifat[sid]
        return bytes(output[:size])

    def read_stream(self, entry: _DirectoryEntry, max_bytes: int) -> bytes:
        """Reads a complete stream or at most ``max_bytes``."""
        wanted = min(entry.size, max_bytes)
        if wanted <= 0:
            return b""
        if entry.size < self.mini_cutoff:
            return self._read_mini(entry.start, wanted)
        return self._read_regular(entry.start, wanted)


def unpack_ole(
    data: bytes,
    name: str,
    config: ScanConfig,
    depth: int = 0,
) -> list[ContainerEntry]:
    """Extracts OLE2 streams as virtual entries ``file.msi!/Stream``.

    Streams are treated like ZIP entries: the name is validated, size/ratio
    limits are applied, and nested analysis is allowed.
    """
    # Local import to avoid a cycle with containers.py.
    from .containers import (
        ARCHIVE_EXTENSIONS,
        ContainerEntry,
        ContainerError,
        _check_size,
        _entry_limit,
        _safe_name,
        _virtual,
        unpack,
    )

    if depth >= config.container_max_depth:
        return []

    try:
        container = _CompoundFile(data)
    except _ContainerFormatError as exc:
        raise ContainerError(str(exc)) from exc
    except (struct.error, ValueError, OverflowError) as exc:
        raise ContainerError(f"invalid OLE2 file: {exc}") from exc

    if len(container.streams) > config.container_max_entries:
        raise ContainerError("too many streams in OLE2 container")

    limit = _entry_limit(config)
    output: list[ContainerEntry] = []
    total = 0
    for stream_name, stream in container.streams:
        inner = _safe_name(stream_name)
        _check_size(config, stream.size, len(data), total)
        try:
            raw = container.read_stream(stream, limit + 1)
        except _ContainerFormatError as exc:
            raise ContainerError(str(exc)) from exc
        truncated = len(raw) > limit or len(raw) < stream.size
        content = raw[:limit]
        total += len(content)
        output.append(ContainerEntry(_virtual(name, inner), content, len(content), truncated))
        if Path(inner).suffix.lower() in ARCHIVE_EXTENSIONS and not truncated:
            output.extend(unpack(content, inner, config, depth + 1))

    if len(output) > config.container_max_entries:
        raise ContainerError("too many entries in OLE2 container")
    return output


__all__ = ["OLE_EXTENSIONS", "unpack_ole"]
