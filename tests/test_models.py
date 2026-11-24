import json

import pytest

from sentinel.core.models import Detection, Finding, RuleHit, ScanResult, Severity


def test_severity_ranking_and_parse():
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank
    with pytest.raises(ValueError):
        Severity.parse("unknown")


def test_finding_is_json_serializable():
    finding = Finding(
        path="C:/x/a.bin",
        rule_id="R-1",
        detection=Detection.HASH,
        severity=Severity.HIGH,
        description="demo",
    )
    payload = json.loads(json.dumps(finding.to_dict()))
    assert payload["severity"] == "high"
    assert payload["detection"] == "hash"


def test_scan_result_ordering_and_summary():
    result = ScanResult(roots=["C:/tmp"], started_at="2026-01-01T00:00:00+00:00",
                        finished_at="2026-01-01T00:00:02+00:00")
    result.findings = [
        Finding("a", "R-LOW", Detection.HEURISTIC, Severity.LOW, "baja"),
        Finding("b", "R-HIGH", Detection.HASH, Severity.HIGH, "alta"),
    ]
    assert result.max_severity is Severity.HIGH
    assert [item.rule_id for item in result.sorted_findings()] == ["R-HIGH", "R-LOW"]
    assert round(result.duration_seconds, 1) == 2.0
    assert result.to_dict()["max_severity"] == "high"


def test_rule_hit_to_dict():
    hit = RuleHit("R", Detection.YARA, Severity.MEDIUM, "desc", ("i1",))
    assert hit.to_dict()["indicators"] == ["i1"]
