"""Sentinel: a modular malware detection and scanning engine.

The project is organized into three layers:

* ``sentinel.engine``: detection (signatures, heuristics, optional YARA).
* ``sentinel.core``: quarantine, history, and data models.
* ``sentinel.cli``: command-line interface.

All code is intended for defensive use: it contains no harmful payloads.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
