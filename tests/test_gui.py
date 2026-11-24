"""Tests for the GUI logic without opening real windows."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.core.models import Detection, Finding, ScanResult, Severity
from sentinel.core.quarantine import Quarantine

pytest.importorskip("tkinter")

from sentinel.gui import SentinelGUI


def make_result(tmp_path: Path) -> ScanResult:
    """Build a realistic report with a high-severity finding."""
    target = tmp_path / "suspicious.txt"
    return ScanResult(
        roots=[str(tmp_path)],
        started_at="2026-11-21T00:00:00+00:00",
        finished_at="2026-11-21T00:00:02+00:00",
        files_scanned=3,
        bytes_scanned=2048,
        findings=[
            Finding(
                path=str(target),
                rule_id="TEST-RULE",
                detection=Detection.CONTENT,
                severity=Severity.HIGH,
                description="Synthetic test content",
            )
        ],
    )


def test_format_summary_with_real_result(tmp_path: Path) -> None:
    gui = SentinelGUI(home=tmp_path / "home", headless=True)
    summary = gui.format_summary(make_result(tmp_path))

    assert "SCAN REPORT" in summary
    assert "Files      : 3" in summary
    assert "Findings   : 1" in summary
    assert "max severity: HIGH" in summary
    assert "TEST-RULE" in summary
    assert "Synthetic test content" in summary


def test_scan_path_detects_marker(tmp_path: Path) -> None:
    target = tmp_path / "marker.txt"
    target.write_bytes(b"SENTINEL_TEST_MARKER test payload\n")
    gui = SentinelGUI(home=tmp_path / "home", headless=True)

    result = gui.scan_path(str(target))

    assert result.files_scanned == 1
    assert any(item.rule_id == "TEST-CONTENT-MARKER" for item in result.findings)
    assert "TEST-CONTENT-MARKER" in gui.format_summary(result)
    assert "Completed" in gui.status


def test_scan_path_without_findings(tmp_path: Path) -> None:
    target = tmp_path / "clean.txt"
    target.write_bytes(b"harmless content\n")
    gui = SentinelGUI(home=tmp_path / "home", headless=True)

    result = gui.scan_path(str(target))

    assert result.findings == []
    assert "No threats found." in gui.format_summary(result)
    assert "max severity: NONE" in gui.format_summary(result)


def test_refresh_quarantine(tmp_path: Path) -> None:
    home = tmp_path / "home"
    store = Quarantine(home / "quarantine")
    sample = tmp_path / "suspicious.bin"
    sample.write_bytes(b"data")
    entry_id = store.add(sample, "TEST-RULE")

    gui = SentinelGUI(home=home, headless=True)
    entries = gui.refresh_quarantine()

    assert [entry.id for entry in entries] == [entry_id]
    assert entries[0].original_name == "suspicious.bin"
    assert entries[0].reason == "TEST-RULE"


def test_quarantine_findings_confirmed(tmp_path: Path) -> None:
    target = tmp_path / "marker.txt"
    target.write_bytes(b"SENTINEL_TEST_MARKER")
    gui = SentinelGUI(home=tmp_path / "home", headless=True)
    result = gui.scan_path(str(target))

    ids = gui.quarantine_findings(result, confirmed=True)

    assert len(ids) == 1
    assert not target.exists()
    assert result.findings[0].quarantined
    assert [entry.id for entry in gui.refresh_quarantine()] == ids
