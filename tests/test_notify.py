"""Pruebas de las notificaciones nativas (sin abrir ventanas reales)."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from sentinel.notify import BACKENDS, Notifier, available_backends, resolve_backend


def test_available_backends_includes_none_everywhere():
    backends = available_backends()
    assert backends[0] == "none"
    assert (os.name == "nt") == ("messagebox" in backends)


def test_resolve_backend_validates_and_resolves_auto():
    assert resolve_backend("auto") in set(available_backends()) | {"toast"}
    assert resolve_backend("none") == "none"
    with pytest.raises(ValueError, match="Backend de notificación desconocido"):
        resolve_backend("inexistente")


def test_notifier_none_is_silent():
    notifier = Notifier("none")
    assert notifier.backend == "none"
    assert notifier.notify("título", "mensaje") is False
    finding = SimpleNamespace(rule_id="PRUEBA", path="/tmp/archivo", severity=SimpleNamespace(value="high"))
    assert notifier.notify_finding(finding, "detectado") is False


def test_messagebox_is_noop_outside_windows():
    notifier = Notifier("messagebox")
    assert notifier.notify("título", "mensaje") is (os.name == "nt")


def test_all_documented_backends_are_resolvable():
    for backend in BACKENDS:
        if backend == "auto":
            continue
        if backend == "toast" and backend not in available_backends():
            continue
        assert resolve_backend(backend) == backend
