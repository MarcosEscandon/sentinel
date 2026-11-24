from sentinel.config import ScanConfig
from sentinel.engine.scanner import Scanner, summarize
from sentinel.engine.signatures import SignatureDatabase


def _fixture_db():
    return SignatureDatabase.from_dict(
        {
            "hashes": {},
            "content": [
                {
                    "id": "MARK",
                    "pattern": "SENTINEL_TEST_MARKER",
                    "severity": "low",
                    "description": "marcador",
                }
            ],
        }
    )


def test_parallel_matches_sequential(tmp_path):
    for index in range(24):
        (tmp_path / f"f{index}.txt").write_bytes(b"SENTINEL_TEST_MARKER")

    database = _fixture_db()
    sequential = Scanner(database, ScanConfig(jobs=1)).scan([tmp_path])
    parallel = Scanner(database, ScanConfig(jobs=4)).scan([tmp_path])

    assert parallel.files_scanned == sequential.files_scanned == 24
    assert len(parallel.findings) == len(sequential.findings) == 24
    assert {item.path for item in parallel.findings} == {item.path for item in sequential.findings}
    assert summarize(parallel)["findings"] == 24


def test_invalid_job_count():
    from pytest import raises

    with raises(ValueError):
        ScanConfig(jobs=0).validate()
