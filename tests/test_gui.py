"""Pruebas de la lógica de la interfaz gráfica, sin abrir ventanas reales."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.core.models import Detection, Finding, ScanResult, Severity
from sentinel.core.quarantine import Quarantine

pytest.importorskip("tkinter")

from sentinel.gui import SentinelGUI


def make_result(tmp_path: Path) -> ScanResult:
    """Construye un informe real con un hallazgo de severidad alta."""
    target = tmp_path / "sospechoso.txt"
    return ScanResult(
        roots=[str(tmp_path)],
        started_at="2026-11-21T00:00:00+00:00",
        finished_at="2026-11-21T00:00:02+00:00",
        files_scanned=3,
        bytes_scanned=2048,
        findings=[
            Finding(
                path=str(target),
                rule_id="TEST-REGLA",
                detection=Detection.CONTENT,
                severity=Severity.HIGH,
                description="Contenido sintético de prueba",
            )
        ],
    )


def test_format_summary_con_resultado_real(tmp_path: Path) -> None:
    gui = SentinelGUI(home=tmp_path / "home", headless=True)
    summary = gui.format_summary(make_result(tmp_path))

    assert "INFORME DE ESCANEO" in summary
    assert "Archivos   : 3" in summary
    assert "Hallazgos  : 1" in summary
    assert "severidad máxima: HIGH" in summary
    assert "TEST-REGLA" in summary
    assert "Contenido sintético de prueba" in summary


def test_scan_path_detecta_marcador(tmp_path: Path) -> None:
    target = tmp_path / "marker.txt"
    target.write_bytes(b"SENTINEL_TEST_MARKER payload de prueba\n")
    gui = SentinelGUI(home=tmp_path / "home", headless=True)

    result = gui.scan_path(str(target))

    assert result.files_scanned == 1
    assert any(item.rule_id == "TEST-CONTENT-MARKER" for item in result.findings)
    assert "TEST-CONTENT-MARKER" in gui.format_summary(result)
    assert "Completado" in gui.status


def test_scan_path_sin_hallazgos(tmp_path: Path) -> None:
    target = tmp_path / "limpio.txt"
    target.write_bytes(b"contenido inocuo\n")
    gui = SentinelGUI(home=tmp_path / "home", headless=True)

    result = gui.scan_path(str(target))

    assert result.findings == []
    assert "No se encontraron amenazas." in gui.format_summary(result)
    assert "severidad máxima: NINGUNA" in gui.format_summary(result)


def test_refresh_quarantine(tmp_path: Path) -> None:
    home = tmp_path / "home"
    store = Quarantine(home / "quarantine")
    sample = tmp_path / "sospechoso.bin"
    sample.write_bytes(b"datos")
    entry_id = store.add(sample, "TEST-REGLA")

    gui = SentinelGUI(home=home, headless=True)
    entries = gui.refresh_quarantine()

    assert [entry.id for entry in entries] == [entry_id]
    assert entries[0].original_name == "sospechoso.bin"
    assert entries[0].reason == "TEST-REGLA"


def test_quarantine_findings_confirmado(tmp_path: Path) -> None:
    target = tmp_path / "marker.txt"
    target.write_bytes(b"SENTINEL_TEST_MARKER")
    gui = SentinelGUI(home=tmp_path / "home", headless=True)
    result = gui.scan_path(str(target))

    ids = gui.quarantine_findings(result, confirmed=True)

    assert len(ids) == 1
    assert not target.exists()
    assert result.findings[0].quarantined
    assert [entry.id for entry in gui.refresh_quarantine()] == ids
