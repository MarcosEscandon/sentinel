import json
from pathlib import Path

from sentinel.cli import main

SIGNATURES = Path(__file__).parent.parent / "sentinel" / "data" / "signatures.json"


def _common(home: Path) -> list[str]:
    return ["--home", str(home), "--signatures", str(SIGNATURES)]


def test_cli_scan_writes_audit_and_excludes_report(tmp_path, capsys):
    home = tmp_path / "home"
    target = tmp_path / "scan"
    target.mkdir()
    (target / "marker.txt").write_bytes(b"SENTINEL_TEST_MARKER")
    report = target / "report.json"

    code = main([*_common(home), "scan", str(target), "--json", str(report), "--quiet"])
    assert code == 1
    assert report.is_file()

    events = [json.loads(line) for line in (home / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    names = {item["event"] for item in events}
    assert {"command", "scan.start", "finding", "scan.finish"} <= names
    assert any(item["event"] == "finding" and item["rule_id"] == "TEST-CONTENT-MARKER" for item in events)

    second = main([*_common(home), "scan", str(target), "--quiet"])
    assert second == 1  # the marker is still there; the report is no longer scanned
    excluded = json.loads((home / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert excluded["event"] == "scan.finish"
    assert excluded["files_scanned"] == 1
    capsys.readouterr()


def test_cli_custom_log_file(tmp_path, capsys):
    home = tmp_path / "home"
    log = tmp_path / "custom.jsonl"
    (tmp_path / "clean.txt").write_text("nothing", encoding="utf-8")
    code = main(
        [*_common(home), "--log-file", str(log), "scan", str(tmp_path / "clean.txt"), "--quiet"]
    )
    assert code == 0
    assert log.is_file()
    assert not (home / "audit.jsonl").exists()
    capsys.readouterr()


def test_cli_no_log(tmp_path, capsys):
    home = tmp_path / "home"
    (tmp_path / "clean.txt").write_text("nothing", encoding="utf-8")
    code = main(
        [*_common(home), "--no-log", "scan", str(tmp_path / "clean.txt"), "--quiet"]
    )
    assert code == 0
    assert not (home / "audit.jsonl").exists()
    capsys.readouterr()


def test_cli_signatures_validate_and_feeds_dry_run(tmp_path, capsys):
    home = tmp_path / "home"
    assert main([*_common(home), "signatures", "validate"]) == 0

    feed = tmp_path / "hashes.txt"
    feed.write_text("a" * 64 + "\n", encoding="utf-8")
    target = tmp_path / "signatures.json"
    assert main(
        [*_common(home), "feeds", "import", str(feed), "--format", "hashes", "--dry-run"]
    ) == 0
    assert not target.exists()
    events = [json.loads(line) for line in (home / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(item["event"] == "feeds.import" and item["dry_run"] for item in events)
    capsys.readouterr()
