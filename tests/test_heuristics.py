import os

from sentinel.config import ScanConfig
from sentinel.core.models import Severity
from sentinel.engine.heuristics import HeuristicEngine, analyze_pe, shannon_entropy
from tests.conftest import make_minimal_pe


def test_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1024) == 0.0
    assert shannon_entropy(os.urandom(4096)) > 7.5


def test_minimal_pe_parser():
    info = analyze_pe(make_minimal_pe())
    assert info.is_pe
    assert info.bitness == 32
    assert info.sections == (".text",)
    assert "KERNEL32.dll.VirtualAllocEx" in info.imports
    assert info.suspicious_imports == ("virtualallocex",)


def test_non_pe_returns_empty():
    assert analyze_pe(b"no soy un PE").is_pe is False
    assert analyze_pe(b"MZ" + b"\x00" * 100).is_pe is False


def test_double_extension_and_score():
    tuned = ScanConfig(entropy_threshold=7.0, entropy_min_size=64, suspicion_threshold=3.0)
    engine = HeuristicEngine(tuned)
    assessment = engine.assess("factura.pdf.exe", b"contenido inocuo" * 10, 170)
    ids = {hit.rule_id for hit in assessment.hits}
    assert "HEUR-DOUBLE-EXT" in ids
    assert "HEUR-SCORE" in ids
    assert assessment.score >= tuned.suspicion_threshold


def test_pe_imports_are_flagged(tuned_config):
    engine = HeuristicEngine(tuned_config)
    data = make_minimal_pe()
    assessment = engine.assess("sample.bin", data, len(data))
    ids = {hit.rule_id for hit in assessment.hits}
    assert "HEUR-PE-IMPORTS" in ids
    assert assessment.pe is not None
    assert next(hit for hit in assessment.hits if hit.rule_id == "HEUR-PE-IMPORTS").severity in (
        Severity.MEDIUM,
        Severity.HIGH,
    )


def test_entropy_only_when_big_enough(tuned_config):
    engine = HeuristicEngine(tuned_config)
    small = engine.assess("random.bin", os.urandom(8192), 32)
    assert not any(hit.rule_id == "HEUR-ENTROPY" for hit in small.hits)
    big = engine.assess("random.bin", os.urandom(8192), 8192)
    assert any(hit.rule_id == "HEUR-ENTROPY" for hit in big.hits)
