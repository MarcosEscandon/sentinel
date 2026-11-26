import json
import os
import sqlite3
import time

from sentinel import cli
from sentinel.core.database import ScanDatabase
from sentinel.core.quarantine import Quarantine


def _mode(path):
    return os.stat(path).st_mode & 0o777


def test_quarantine_outputs_are_private(tmp_path):
    store = Quarantine(tmp_path / "quarantine")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    entry_id = store.add(sample, reason="hardening-test")

    assert store.get(entry_id).stored_path.endswith(".qtn")
    if os.name != "nt":
        assert _mode(store.files_dir) == 0o700
        assert _mode(store.index_path) == 0o600
        assert _mode(store.key_path) == 0o600
        assert _mode(store.files_dir / f"{entry_id}.qtn") == 0o600


def test_history_database_is_private_and_prunable(tmp_path):
    database = ScanDatabase(tmp_path / "history.db")
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            "INSERT INTO scans (started_at, finished_at) VALUES (?, ?)",
            ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:02+00:00"),
        )

    assert database.prune(days=30) == 1
    assert database.stats()["scans"] == 0
    if os.name != "nt":
        assert _mode(database.path) == 0o600


def test_registered_reports_are_restricted_and_expire(tmp_path):
    home = tmp_path / "home"
    old_report = tmp_path / "old-report.json"
    new_report = tmp_path / "new-report.json"
    old_report.write_text("{}", encoding="utf-8")
    new_report.write_text("{}", encoding="utf-8")

    cli._remember_report(home, str(old_report))
    stale = time.time() - 45 * 86400
    os.utime(old_report, (stale, stale))
    cli._remember_report(home, str(new_report))

    assert not old_report.exists()
    assert new_report.exists()
    registry = home / "reports.json"
    assert str(new_report.resolve()) in json.loads(registry.read_text(encoding="utf-8"))
    if os.name != "nt":
        assert _mode(registry) == 0o600
