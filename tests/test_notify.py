"""Tests for native notifications (without opening real windows)."""

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
    with pytest.raises(ValueError, match="Unknown notification backend"):
        resolve_backend("nonexistent")


def test_notifier_none_is_silent():
    notifier = Notifier("none")
    assert notifier.backend == "none"
    assert notifier.notify("title", "message") is False
    finding = SimpleNamespace(rule_id="TEST", path="/tmp/file", severity=SimpleNamespace(value="high"))
    assert notifier.notify_finding(finding, "detected") is False


def test_messagebox_is_noop_outside_windows():
    notifier = Notifier("messagebox")
    assert notifier.notify("title", "message") is (os.name == "nt")


def test_all_documented_backends_are_resolvable():
    for backend in BACKENDS:
        if backend == "auto":
            continue
        if backend == "toast" and backend not in available_backends():
            continue
        assert resolve_backend(backend) == backend
