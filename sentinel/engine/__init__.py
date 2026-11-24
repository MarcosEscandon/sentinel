"""Motor de detección."""

from .heuristics import HeuristicEngine, analyze_pe, shannon_entropy
from .scanner import Scanner
from .signatures import SignatureDatabase
from .yara import YaraEngine, YaraUnavailable

__all__ = [
    "HeuristicEngine",
    "Scanner",
    "SignatureDatabase",
    "YaraEngine",
    "YaraUnavailable",
    "analyze_pe",
    "shannon_entropy",
]
