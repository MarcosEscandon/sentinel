import csv
from pathlib import Path

from sentinel.engine.scanner import Scanner
from sentinel.engine.signatures import SignatureDatabase
from sentinel.feeds import import_feed

SIGNATURES = Path(__file__).parent.parent / "sentinel" / "data" / "signatures.json"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_eicar_hash_and_content_are_detected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)

    database = SignatureDatabase.load(SIGNATURES)
    assert database.revision >= 2
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in database.hashes

    result = Scanner(database).scan([sample])
    rules = {finding.rule_id for finding in result.findings}
    assert {"EICAR-HASH", "EICAR-CONTENT"} <= rules


def test_curated_real_iocs_are_valid_and_shipped():
    database = SignatureDatabase.load(SIGNATURES)
    feed = SIGNATURES.parent / "iocs" / "curated.csv"
    with feed.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) >= 10
    for row in rows:
        assert len(row["value"]) == 64
        assert row["value"] in database.hashes
        assert database.hashes[row["value"]]["id"] == row["id"]


def test_shipped_eicar_feed_imports_and_detects(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sample = tmp_path / "eicar.com"
    sample.write_bytes(EICAR)
    target = tmp_path / "imported.json"

    report = import_feed(SIGNATURES.parent / "iocs" / "eicar.csv", target, source="eicar")
    assert (report.added_hashes, report.added_content) == (1, 1)

    result = Scanner(SignatureDatabase.load(target)).scan([sample])
    rules = {finding.rule_id for finding in result.findings}
    assert {"EICAR-HASH", "EICAR-CONTENT"} <= rules
