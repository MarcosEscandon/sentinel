import hashlib
import os

from sentinel.config import ScanConfig
from sentinel.core.allowlist import AllowList, normalize_path
from sentinel.core.models import Detection
from sentinel.engine.scanner import Scanner, summarize
from sentinel.engine.signatures import SignatureDatabase


def test_scans_file_and_matches_all_engines(tmp_path, sample_db, tuned_config):
    target = tmp_path / "MARCADOR.bad"
    target.write_bytes(b"contenido con MARCADOR")
    result = Scanner(sample_db, tuned_config, yara=None).scan([target])

    assert result.files_scanned == 1
    assert {"NAME-TEST", "CONTENT-TEST"} <= {finding.rule_id for finding in result.findings}
    assert all(finding.path == str(target) for finding in result.findings)
    assert summarize(result)["findings"] == len(result.findings)


def test_recursive_scan_respects_excludes(tmp_path, sample_db, tuned_config):
    included = tmp_path / "include"
    excluded = tmp_path / "node_modules"
    included.mkdir()
    excluded.mkdir()
    (included / "a.bad").write_bytes(b"MARCADOR")
    (excluded / "b.bad").write_bytes(b"MARCADOR")

    result = Scanner(sample_db, tuned_config, yara=None).scan([tmp_path])
    assert result.files_scanned == 1
    assert result.findings[0].path == str(included / "a.bad")


def test_size_limit_and_missing_target(tmp_path, sample_db, tuned_config):
    big = tmp_path / "big.bad"
    big.write_bytes(b"x" * 1000)
    config = ScanConfig(max_file_size=100, sample_size=100)
    result = Scanner(sample_db, config, yara=None).scan([big, tmp_path / "no-existe"])
    assert result.files_scanned == 0
    assert result.skipped == 1
    assert len(result.errors) == 1


def test_single_string_target(tmp_path, sample_db, tuned_config):
    target = tmp_path / "a.bad"
    target.write_bytes(b" MARCADOR ")
    result = Scanner(sample_db, tuned_config, yara=None).scan(str(target))
    assert result.files_scanned == 1
    assert any(item.detection is Detection.CONTENT for item in result.findings)


def test_progress_callback(tmp_path, sample_db, tuned_config):
    target = tmp_path / "a.bad"
    target.write_bytes(b" MARCADOR ")
    events = []
    result = Scanner(sample_db, tuned_config, yara=None).scan(
        [target], lambda event, path, count: events.append(event)
    )
    assert result.findings
    assert "file" in events and "finding" in events


def test_allowlist_skips_by_path_and_hash(tmp_path, sample_db, tuned_config):
    first = tmp_path / "a.bad"
    second = tmp_path / "b.bad"
    first.write_bytes(b"MARCADOR")
    second.write_bytes(b"MARCADOR")
    rules = AllowList(
        paths=frozenset({normalize_path(first)}),
        hashes=frozenset({hashlib.sha256(second.read_bytes()).hexdigest()}),
    )
    result = Scanner(sample_db, tuned_config, yara=None, allowlist=rules).scan([tmp_path])
    assert result.files_scanned == 0
    assert result.allowed == 2
    assert result.findings == []


def test_high_entropy_file_is_flagged(tmp_path, tuned_config):
    target = tmp_path / "blob.bin"
    target.write_bytes(os.urandom(4096))
    result = Scanner(SignatureDatabase.empty(), tuned_config, yara=None).scan([target])
    assert any(item.rule_id == "HEUR-ENTROPY" for item in result.findings)
