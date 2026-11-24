"""Pruebas del monitor en tiempo real (sin hilos en los casos unitarios)."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from sentinel.core.allowlist import AllowList
from sentinel.core.logging import AuditLogger
from sentinel.core.quarantine import Quarantine
from sentinel.realtime import RealtimeMonitor, available_backends

MARKER = b"SENTINEL_TEST_MARKER"


def _make_monitor(
    root: Path,
    signatures: object,
    quarantine: Quarantine | None = None,
    logger: AuditLogger | None = None,
    allowlist: AllowList | None = None,
    on_finding: object = None,
    backend: str = "polling",
) -> RealtimeMonitor:
    """Construye un monitor con opciones comunes para los tests."""
    return RealtimeMonitor(
        [root],
        signatures=signatures,
        quarantine=quarantine,
        logger=logger,
        allowlist=allowlist,
        on_finding=on_finding,
        poll_interval=0.05,
        grace_period=0.01,
        backend=backend,
    )


def test_process_path_detects_quarantines_and_audits(tmp_path, default_db):
    watch = tmp_path / "watch"
    watch.mkdir()
    target = watch / "sospechoso.bin"
    target.write_bytes(MARKER)
    store = Quarantine(tmp_path / "q")
    audit_path = tmp_path / "audit.jsonl"
    events: list[tuple[str, str]] = []

    monitor = _make_monitor(
        watch,
        default_db,
        quarantine=store,
        logger=AuditLogger(audit_path),
        on_finding=lambda finding, action: events.append((finding.rule_id, action)),
    )
    result, action = monitor.process_path(target)

    marked = [item for item in result.findings if item.rule_id == "TEST-CONTENT-MARKER"]
    assert marked
    assert action == "quarantined"
    assert not target.exists()
    assert events and all(item[1] == "quarantined" for item in events)

    entries = store.list()
    assert len(entries) == 1
    assert entries[0].sha256 == marked[0].sha256
    assert "TEST-CONTENT-MARKER" in entries[0].reason
    assert marked[0].quarantined and marked[0].quarantine_id == entries[0].id

    records = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
    emitted = {record["event"] for record in records}
    assert {"realtime.detection", "realtime.quarantine"} <= emitted
    quarantine_events = [item for item in records if item["event"] == "realtime.quarantine"]
    assert quarantine_events[0]["quarantine_id"] == entries[0].id


def test_process_path_allowlist_skips_quarantine(tmp_path, default_db):
    watch = tmp_path / "watch"
    watch.mkdir()
    target = watch / "permitido.bin"
    target.write_bytes(MARKER)
    store = Quarantine(tmp_path / "q")
    events: list[tuple[str, str]] = []

    monitor = _make_monitor(
        watch,
        default_db,
        quarantine=store,
        allowlist=AllowList.for_files([target]),
        on_finding=lambda finding, action: events.append((finding.rule_id, action)),
    )
    result, action = monitor.process_path(target)

    assert result.findings == []
    assert result.allowed == 1
    assert action == "clean"
    assert target.exists()
    assert store.list() == []
    assert events == []


def test_process_path_without_quarantine_reports_detected(tmp_path, default_db):
    target = tmp_path / "detectado.bin"
    target.write_bytes(MARKER)
    actions: list[str] = []
    monitor = _make_monitor(
        tmp_path, default_db, on_finding=lambda _finding, action: actions.append(action)
    )

    result, action = monitor.process_path(target)

    assert result.findings
    assert action == "detected"
    assert target.exists()
    assert actions == ["detected"]


def test_excluded_directory_is_not_processed(tmp_path, default_db):
    target = tmp_path / "node_modules" / "ignorado.bin"
    target.parent.mkdir()
    target.write_bytes(MARKER)
    store = Quarantine(tmp_path / "q")
    monitor = _make_monitor(target.parent, default_db, quarantine=store)

    result, action = monitor.process_path(target)

    assert result.findings == []
    assert action == "clean"
    assert target.exists()
    assert store.list() == []


def test_available_backends_and_lifecycle():
    backends = available_backends()
    assert "polling" in backends
    assert backends[-1] == "polling"
    assert RealtimeMonitor.available_backends() == backends

    monitor = RealtimeMonitor([], poll_interval=0.05, grace_period=0.01)
    assert monitor.backend == backends[0]
    assert not monitor.is_alive
    monitor.start()
    monitor.start()
    assert monitor.is_alive
    monitor.stop(timeout=1)
    monitor.stop(timeout=1)
    assert not monitor.is_alive


def test_available_backends_native_depends_on_os():
    """El backend nativo solo se ofrece en Windows."""
    backends = available_backends()
    if os.name == "nt":
        assert backends[0] == "native"
    else:
        assert "native" not in backends
    assert len(backends) == len(set(backends))


def test_invalid_backend_raises_value_error():
    """Forzar un backend no disponible debe fallar con un mensaje claro."""
    with pytest.raises(ValueError, match="backend"):
        RealtimeMonitor([], backend="inexistente")


def test_worker_detects_new_file(tmp_path, default_db):
    """El backend de sondeo detecta altas (se fuerza para no depender del SO)."""
    watch = tmp_path / "watch"
    watch.mkdir()
    store = Quarantine(tmp_path / "q")
    actions: list[str] = []
    monitor = _make_monitor(
        watch,
        default_db,
        quarantine=store,
        on_finding=lambda _finding, action: actions.append(action),
    )
    assert monitor.backend == "polling"
    monitor.start()
    try:
        target = watch / "nuevo.bin"
        target.write_bytes(MARKER)
        deadline = time.monotonic() + 5.0
        while not actions and time.monotonic() < deadline:
            time.sleep(0.02)
        assert actions
        assert all(action == "quarantined" for action in actions)
        assert not target.exists()
        assert len(store.list()) == 1
    finally:
        monitor.stop(timeout=2)


@pytest.mark.skipif(os.name != "nt", reason="el backend nativo es exclusivo de Windows")
def test_native_backend_detects_changes_and_stops_cleanly(tmp_path, default_db):
    """En Windows el backend nativo vigila directorios y sondea archivos sueltos."""
    watch = tmp_path / "watch"
    watch.mkdir()
    loose = tmp_path / "suelta.bin"
    loose.write_bytes(MARKER)
    store = Quarantine(tmp_path / "q")
    actions: list[str] = []
    monitor = RealtimeMonitor(
        [watch, loose],
        signatures=default_db,
        quarantine=store,
        on_finding=lambda _finding, action: actions.append(action),
        poll_interval=0.05,
        grace_period=0.01,
        backend="native",
    )
    monitor.start()
    try:
        assert monitor.backend == "native"
        # Espera a que el vigilante abra el handle antes de generar eventos.
        ready = time.monotonic() + 2.0
        while (
            not all(watcher._handle for watcher in monitor._native_watchers)
            and time.monotonic() < ready
        ):
            time.sleep(0.01)
        (watch / "nuevo.bin").write_bytes(MARKER)
        loose.write_bytes(MARKER + b"cambio")
        deadline = time.monotonic() + 5.0
        while len(actions) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert len(actions) >= 2
        assert all(action == "quarantined" for action in actions)
    finally:
        monitor.stop(timeout=3)

    assert not monitor.is_alive
    remaining = [
        thread.name for thread in threading.enumerate() if thread.name.startswith("sentinel-native")
    ]
    assert not remaining
