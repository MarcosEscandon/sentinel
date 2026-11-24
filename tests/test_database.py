from sentinel.core.database import ScanDatabase
from sentinel.core.models import Detection, Finding, ScanResult, Severity


def _result(paths: list[str], started_at: str = "2026-01-01T00:00:00+00:00") -> ScanResult:
    result = ScanResult(
        roots=["C:/tmp"],
        started_at=started_at,
        finished_at="2026-01-01T00:00:02+00:00",
    )
    result.findings = [
        Finding(path, f"R-{index}", Detection.HASH, Severity.HIGH, "demo")
        for index, path in enumerate(paths)
    ]
    return result


def test_mark_quarantined_respects_scan_scope(tmp_path):
    db = ScanDatabase(tmp_path / "history.db")
    first_id = db.save_scan(_result(["C:/a.bin", "C:/b.bin"]))
    second_id = db.save_scan(
        _result(["C:/a.bin", "C:/c.bin"], "2026-01-02T00:00:00+00:00")
    )

    assert db.mark_quarantined(["C:/a.bin", "C:/b.bin"], first_id) == 2
    assert db.stats() == {"scans": 2, "findings": 4, "quarantined": 2}
    second_flags = {f["path"]: f["quarantined"] for f in db.get_scan(second_id)["findings"]}
    assert second_flags == {"C:/a.bin": 0, "C:/c.bin": 0}

    # SQLite cuenta las filas coincidentes aunque el valor ya fuera 1.
    assert db.mark_quarantined(["C:/a.bin"]) == 2
    assert db.stats()["quarantined"] == 3
    assert db.mark_quarantined([]) == 0


def test_mark_quarantined_binds_paths_with_quotes(tmp_path):
    db = ScanDatabase(tmp_path / "history.db")
    tricky = "C:/a' OR 1=1 --/x.bin"
    db.save_scan(_result([tricky, "C:/normal.bin"]))

    assert db.mark_quarantined([tricky]) == 1
    assert db.stats()["quarantined"] == 1
