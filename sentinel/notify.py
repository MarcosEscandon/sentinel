"""Notificaciones de escritorio para hallazgos en tiempo real.

Los backends son independientes del motor de detección. En Windows se prefiere
un *toast* si hay un paquete opcional instalado (``winotify``); si no, se usa un
cuadro de mensaje nativo vía ``ctypes`` con cierre automático. El backend
``none`` existe para servicios y entornos sin escritorio.

Las llamadas a API nativas se hacen en un hilo daemon para no bloquear al
trabajador que está escaneando.
"""

from __future__ import annotations

import os
import threading
from typing import Any

BACKENDS = ("auto", "toast", "messagebox", "none")
_MESSAGEBOX_TIMEOUT_MS = 2500
_ICONS = {"low": 0x40, "medium": 0x30, "high": 0x30, "critical": 0x10}


def _has_winotify() -> bool:
    """Comprueba si el paquete opcional ``winotify`` está disponible."""
    try:
        import winotify  # noqa: F401
    except ImportError:
        return False
    return True


def available_backends() -> list[str]:
    """Devuelve los backends utilizables en la plataforma actual."""
    backends = ["none"]
    if os.name == "nt":
        if _has_winotify():
            backends.append("toast")
        backends.append("messagebox")
    return backends


def resolve_backend(preferred: str = "auto") -> str:
    """Resuelve ``auto`` al mejor backend disponible y valida el resto."""
    if preferred not in BACKENDS:
        raise ValueError(
            f"Backend de notificación desconocido '{preferred}'. Opciones: {', '.join(BACKENDS)}"
        )
    if preferred != "auto":
        return preferred
    available = available_backends()
    for candidate in ("toast", "messagebox"):
        if candidate in available:
            return candidate
    return "none"


class Notifier:
    """Publica avisos de escritorio con degradación limpia."""

    def __init__(self, backend: str = "auto") -> None:
        self._backend = resolve_backend(backend)

    @property
    def backend(self) -> str:
        """Backend resuelto en tiempo de construcción."""
        return self._backend

    def notify(self, title: str, message: str, severity: str = "info") -> bool:
        """Intenta mostrar un aviso; devuelve ``True`` si se pudo publicar."""
        if self._backend == "none":
            return False
        if self._backend == "toast":
            return self._notify_toast(title, message, severity)
        return self._notify_messagebox(title, message, severity)

    def notify_finding(self, finding: Any, action: str) -> bool:
        """Forma abreviada para los hallazgos del monitor."""
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

            # MB_TOPMOST | MB_SETFOREGROUND; el timeout lo impone MessageBoxTimeoutW.
            flags = icon | 0x00040000 | 0x00010000
            ctypes.windll.user32.MessageBoxTimeoutW(
                0, message, title, flags, 0, _MESSAGEBOX_TIMEOUT_MS
            )
        except (AttributeError, OSError, ValueError):
            pass
