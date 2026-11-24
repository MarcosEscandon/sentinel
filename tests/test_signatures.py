import pytest

from sentinel.core.models import Detection, Severity
from sentinel.engine.signatures import SignatureDatabase


def test_match_hash(sample_db):
    hits = sample_db.match_hash("A" * 64)
    assert len(hits) == 1
    assert hits[0].detection is Detection.HASH
    assert hits[0].severity is Severity.CRITICAL


def test_match_filename_and_content(sample_db):
    assert sample_db.match_filename("archivo.bad")[0].rule_id == "NAME-TEST"
    assert sample_db.match_content(b"xxx MARCADOR yyy", 15)[0].rule_id == "CONTENT-TEST"
    assert sample_db.match_content(b"limpio", 6) == []


def test_content_respects_max_size():
    db = SignatureDatabase.from_dict(
        {
            "hashes": {},
            "content": [
                {
                    "id": "S",
                    "pattern": "x",
                    "severity": "low",
                    "description": "d",
                    "max_size": 4,
                }
            ],
        }
    )
    assert db.match_content(b"xxxx", 5) == []
    assert len(db.match_content(b"xxx", 3)) == 1


def test_invalid_database_rejected():
    with pytest.raises(ValueError):
        SignatureDatabase.from_dict({"schema": 99})
    with pytest.raises(ValueError):
        SignatureDatabase.from_dict({"hashes": {"not-a-hash": {}}})
    with pytest.raises(ValueError):
        SignatureDatabase.from_dict(
            {"content": [{"id": "x", "pattern": "[", "description": "d"}]}
        )


def test_empty_database_and_stats():
    db = SignatureDatabase.empty()
    assert db.match_hash("0" * 64) == []
    assert db.stats()["hashes"] == 0


def test_rollback_check():
    older = SignatureDatabase.from_dict({"revision": 1})
    newer = SignatureDatabase.from_dict({"revision": 4})
    newer.check_rollback(older)
    with pytest.raises(ValueError, match="Rollback"):
        older.check_rollback(newer)


def test_regex_timeout_is_reported():
    pytest.importorskip("regex")
    db = SignatureDatabase.from_dict(
        {
            "content": [
                {
                    "id": "REDOS",
                    "pattern": r"(a+)+$",
                    "severity": "low",
                    "description": "patrón con backtracking",
                }
            ]
        }
    )
    db.rule_timeout_ms = 1
    hits = db.match_content(b"a" * 20000 + b"b", 20001)
    assert any(hit.rule_id == "RULE-TIMEOUT" for hit in hits)
