"""Desktop notifications for real-time findings.

Backends are independent of the detection engine. On Windows, a toast is
preferred if an optional package is installed (``winotify``); otherwise, a
native message box via ``ctypes`` with automatic dismissal is used. The
``none`` backend exists for services and environments without a desktop.

Native API calls are made on a daemon thread so they do not block the worker
that is scanning.
"""

from __future__ import annotations

import os
import threading
from typing import Any

BACKENDS = ("auto", "toast", "messagebox", "none")
_MESSAGEBOX_TIMEOUT_MS = 2500
_ICONS = {"low": 0x40, "medium": 0x30, "high": 0x30, "critical": 0x10}


def _has_winotify() -> bool:
    """Checks whether the optional ``winotify`` package is available."""
    try:
        import winotify  # noqa: F401
    except ImportError:
        return False
    return True


def available_backends() -> list[str]:
    """Returns the backends usable on the current platform."""
    backends = ["none"]
    if os.name == "nt":
        if _has_winotify():
            backends.append("toast")
        backends.append("messagebox")
    return backends


def resolve_backend(preferred: str = "auto") -> str:
    """Resolves ``auto`` to the best available backend and validates the rest."""
    if preferred not in BACKENDS:
        raise ValueError(
            f"Unknown notification backend '{preferred}'. Options: {', '.join(BACKENDS)}"
        )
    if preferred != "auto":
        return preferred
    available = available_backends()
    for candidate in ("toast", "messagebox"):
        if candidate in available:
            return candidate
    return "none"


class Notifier:
    """Publishes desktop alerts with graceful degradation."""

    def __init__(self, backend: str = "auto") -> None:
        self._backend = resolve_backend(backend)

    @property
    def backend(self) -> str:
        """Backend resolved at construction time."""
        return self._backend

    def notify(self, title: str, message: str, severity: str = "info") -> bool:
        """Attempts to display an alert; returns ``True`` if it could be published."""
        if self._backend == "none":
            return False
        if self._backend == "toast":
            return self._notify_toast(title, message, severity)
        return self._notify_messagebox(title, message, severity)

    def notify_finding(self, finding: Any, action: str) -> bool:
        """Convenience wrapper for findings from the monitor."""
        severity = getattr(getattr(finding, "severity", None), "value", "info")
        return self.notify(
            f"Sentinel · {severity.upper()} · {finding.rule_id}",
            f"{finding.path}\n{action}",
            str(severity),
        )

    def _notify_toast(self, title: str, message: str, severity: str) -> bool:
        if not _has_winotify():
            return False
        try:
            from winotify import Notification

            toast = Notification(app_id="Sentinel", title=title, msg=message)
            toast.show()
            return True
        except (ImportError, OSError, RuntimeError, ValueError):
            return False

    def _notify_messagebox(self, title: str, message: str, severity: str) -> bool:
        if os.name != "nt":
            return False
        icon = _ICONS.get(severity.lower(), 0x40)
        thread = threading.Thread(
            target=self._messagebox_thread,
            args=(title, message, icon),
            name="sentinel-notify",
            daemon=True,
        )
        thread.start()
        return True

    @staticmethod
    def _messagebox_thread(title: str, message: str, icon: int) -> None:
        try:
            import ctypes

            # MB_TOPMOST | MB_SETFOREGROUND; the timeout is enforced by MessageBoxTimeoutW.
            flags = icon | 0x00040000 | 0x00010000
            ctypes.windll.user32.MessageBoxTimeoutW(
                0, message, title, flags, 0, _MESSAGEBOX_TIMEOUT_MS
            )
        except (AttributeError, OSError, ValueError):
            pass
