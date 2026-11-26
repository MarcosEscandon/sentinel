"""Filesystem hardening helpers for outputs that may contain sensitive data.

Audit logs can reveal scanned paths and findings, and quarantine files are
live malware samples. Both must be readable only by the current OS user, and
generated outputs should not accumulate indefinitely. These helpers are
best-effort: a failure to change permissions is logged by the caller but never
prevents the scan from running.
"""

from __future__ import annotations

import os

# icacls is a fixed Windows tool; no user-supplied command or shell is used.
import subprocess  # nosec B404
import time
from pathlib import Path

DEFAULT_RETENTION_DAYS = 30


def restrict_permissions(path: str | Path) -> bool:
    """Restrict a file/directory to the current user.

    Windows uses ``icacls`` with inheritance removed; POSIX uses ``chmod``.
    Returns True when the restriction was applied, False on best-effort
    failure (e.g. an unsupported platform or a locked-down filesystem).
    """
    target = Path(path)
    if not target.exists():
        return False

    if os.name == "nt":
        username = os.environ.get("USERNAME")
        if not username:
            return False
        inheritance = "(OI)(CI)F" if target.is_dir() else "F"
        try:
            # Fixed executable and internal paths; no shell, no user command.
            result = subprocess.run(  # nosec B603, B607
                ["icacls", str(target), "/inheritance:r", "/grant:r", f"{username}:{inheritance}"],
                check=False,
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    try:
        os.chmod(target, 0o700 if target.is_dir() else 0o600)
        return True
    except OSError:
        return False


def secure_write_text(path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Atomically write text and restrict permissions on the new file."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    restrict_permissions(target.parent)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(text, encoding=encoding)
    restrict_permissions(temporary)
    temporary.replace(target)


def cleanup_old_files(
    directory: str | Path,
    *,
    days: int = DEFAULT_RETENTION_DAYS,
    pattern: str = "*",
) -> int:
    """Delete generated files older than ``days`` from ``directory``.

    ``pattern`` is intentionally explicit: callers must name the outputs they
    own instead of deleting arbitrary files from a user-selected directory.
    Returns the number of files removed.
    """
    if days < 0:
        raise ValueError("days must be >= 0")
    folder = Path(directory)
    if not folder.is_dir():
        return 0

    cutoff = time.time() - days * 86400
    removed = 0
    for candidate in folder.glob(pattern):
        if not candidate.is_file():
            continue
        try:
            if candidate.stat().st_mtime < cutoff:
                candidate.unlink()
                removed += 1
        except OSError:
            continue
    return removed


__all__ = ["DEFAULT_RETENTION_DAYS", "cleanup_old_files", "restrict_permissions", "secure_write_text"]
