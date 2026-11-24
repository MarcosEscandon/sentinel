"""Orchestration of file, container, and directory scanning."""

from __future__ import annotations

import ctypes
import hashlib
import lzma
import os
import tarfile
import zipfile
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..config import ScanConfig
from ..core.allowlist import AllowList
from ..core.models import Detection, Finding, RuleHit, ScanResult, Severity, utc_now
from .containers import ARCHIVE_EXTENSIONS, ContainerError, find_macro_entries, unpack
from .heuristics import HeuristicAssessment, HeuristicEngine
from .signatures import SignatureDatabase
from .vba import analyze_macro_entries

ProgressCallback = Callable[[str, str, int], None]
"""Signature: ``(event, path, count)`` where event ∈ file|skip|error|finding."""

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_READ_CHUNK = 1024 * 1024


def _is_reparse_point(path: Path) -> bool:
    """Detects Windows junctions and reparse points (not covered by ``islink``)."""
    if os.name != "nt":
        return False
    try:
        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    except (AttributeError, OSError):
        return False
    return attributes != -1 and bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


class Scanner:
    """Scans paths using signatures, heuristics, YARA, and containers."""

    def __init__(
        self,
        signatures: SignatureDatabase | None = None,
        config: ScanConfig | None = None,
        heuristics: HeuristicEngine | None = None,
        yara: object | None = None,
        allowlist: AllowList | None = None,
    ) -> None:
        self.signatures = signatures or SignatureDatabase.empty()
        self.config = config or ScanConfig()
        self.config.validate()
        self.heuristics = heuristics or HeuristicEngine(self.config)
        self.yara = yara
        self.allowlist = allowlist

    def scan(
        self,
        targets: Sequence[str | Path] | str | Path,
        on_progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Analyzes files or directories and returns an aggregated report."""
        if isinstance(targets, (str, Path)):
            targets = [targets]
        roots = [str(Path(item)) for item in targets]
        result = ScanResult(roots=roots, started_at=utc_now())

        paths: list[Path] = []
        for target in targets:
            paths.extend(self._iter_files(Path(target), result, on_progress))

        need_hash = self.config.hash_all or bool(self.signatures.hashes)
        if self.config.jobs <= 1:
            for path in paths:
                self._merge(result, self._scan_file(path, need_hash), on_progress)
                self._emit(on_progress, "file", str(path), result.files_scanned)
        else:
            with ThreadPoolExecutor(max_workers=self.config.jobs) as pool:
                futures = {
                    pool.submit(self._scan_file, path, need_hash): path for path in paths
                }
                for future in as_completed(futures):
                    self._merge(result, future.result(), on_progress)
                    self._emit(
                        on_progress, "file", str(futures[future]), result.files_scanned
                    )

        result.finished_at = utc_now()
        return result

    @staticmethod
    def _merge(
        target: ScanResult, partial: ScanResult, callback: ProgressCallback | None
    ) -> None:
        target.files_scanned += partial.files_scanned
        target.bytes_scanned += partial.bytes_scanned
        target.skipped += partial.skipped
        target.allowed += partial.allowed
        target.container_entries += partial.container_entries
        target.errors.extend(partial.errors)
        before = len(target.findings)
        target.findings.extend(partial.findings)
        for finding in target.findings[before:]:
            Scanner._emit(callback, "finding", finding.path, len(target.findings))

    @staticmethod
    def _emit(
        callback: ProgressCallback | None,
        event: str,
        path: str,
        count: int,
    ) -> None:
        if callback is not None:
            callback(event, path, count)

    def _iter_files(
        self,
        target: Path,
        result: ScanResult,
        callback: ProgressCallback | None = None,
    ) -> Iterable[Path]:
        try:
            if target.is_file():
                yield target
                return
            if not target.is_dir():
                result.errors.append({"path": str(target), "error": "path does not exist"})
                self._emit(callback, "error", str(target), len(result.errors))
                return
        except OSError as exc:
            result.errors.append({"path": str(target), "error": str(exc)})
            self._emit(callback, "error", str(target), len(result.errors))
            return

        for root, dirs, files in os.walk(
            target, topdown=True, followlinks=self.config.follow_symlinks
        ):
            dirs[:] = [
                name
                for name in dirs
                if name.lower() not in self.config.exclude_dirs
                and not _is_reparse_point(Path(root) / name)
            ]
            for name in files:
                path = Path(root) / name
                try:
                    if path.is_symlink() and not self.config.follow_symlinks:
                        result.skipped += 1
                        continue
                    if _is_reparse_point(path) and not self.config.follow_symlinks:
                        result.skipped += 1
                        continue
                except OSError as exc:
                    result.errors.append({"path": str(path), "error": str(exc)})
                    continue
                yield path

    def _scan_file(self, path: Path, need_hash: bool) -> ScanResult:
        """Analyzes a file and returns a partial result (thread-safe)."""
        cfg = self.config
        result = ScanResult(roots=[])
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.errors.append({"path": str(path), "error": str(exc)})
            return result

        if size > cfg.max_file_size:
            result.skipped += 1
            return result
        if cfg.include_extensions is not None and path.suffix.lower() not in cfg.include_extensions:
            result.skipped += 1
            return result
        if self.allowlist is not None and self.allowlist.allows_path(path):
            result.allowed += 1
            return result

        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                sample = handle.read(cfg.sample_size)
                digest.update(sample)
                if need_hash:
                    while True:
                        chunk = handle.read(_READ_CHUNK)
                        if not chunk:
                            break
                        digest.update(chunk)
        except OSError as exc:
            result.errors.append({"path": str(path), "error": str(exc)})
            return result

        sha256 = digest.hexdigest() if need_hash else ""
        if self.allowlist is not None and self.allowlist.allows_hash(sha256):
            result.allowed += 1
            return result

        result.files_scanned += 1
        result.bytes_scanned += size
        hits, score = self._detect(str(path), sample, size, sha256)
        self._add_findings(result, str(path), hits, score, sha256, size)

        if cfg.scan_containers and path.suffix.lower() in ARCHIVE_EXTENSIONS:
            self._scan_container(path, result, need_hash)
        return result

    def _scan_container(self, path: Path, result: ScanResult, need_hash: bool) -> None:
        try:
            payload = path.read_bytes()
            entries = unpack(payload, path.name, self.config)
        except ContainerError as exc:
            result.errors.append({"path": str(path), "error": f"container: {exc}"})
            return
        except (
            OSError,
            ValueError,
            EOFError,
            lzma.LZMAError,
            tarfile.TarError,
            zipfile.BadZipFile,
        ) as exc:
            result.errors.append({"path": str(path), "error": f"unreadable container: {exc}"})
            return

        result.container_entries += len(entries)
        macro_paths = {item.path for item in find_macro_entries(entries)}

        # Analyze the VBA code once and attach it to vbaProject.bin.
        vba_hits = analyze_macro_entries(entries)
        vba_path = next(
            (
                item.path
                for item in entries
                if item.path.replace("\\", "/").lower().rsplit("!/", 1)[-1].endswith(
                    "vbaproject.bin"
                )
            ),
            None,
        )
        for entry in entries:
            digest = hashlib.sha256(entry.data).hexdigest() if need_hash else ""
            if self.allowlist is not None and self.allowlist.allows_hash(digest):
                result.allowed += 1
                continue
            hits, score = self._detect(
                entry.path, entry.data[: self.config.sample_size], entry.size, digest
            )
            if entry.path in macro_paths:
                hits.append(
                    RuleHit(
                        rule_id="OFFICE-MACRO",
                        detection=Detection.HEURISTIC,
                        severity=Severity.MEDIUM,
                        description="VBA/macro project embedded in an Office document",
                        indicators=(f"macro: {entry.path}",),
                    )
                )
            if vba_path is not None and entry.path == vba_path:
                hits.extend(vba_hits)
            if entry.truncated:
                hits = [
                    RuleHit(
                        rule_id=hit.rule_id,
                        detection=hit.detection,
                        severity=hit.severity,
                        description=hit.description,
                        indicators=hit.indicators + ("truncated entry",),
                    )
                    for hit in hits
                ]
            self._add_findings(
                result, entry.path, hits, score, digest, entry.size, container=str(path)
            )

    def _detect(
        self, label: str, sample: bytes, size: int, sha256: str
    ) -> tuple[list[RuleHit], float]:
        """Applies all detectors to a sample and returns unique hits."""
        hits: list[RuleHit] = []
        hits.extend(self.signatures.match_filename(Path(label).name))
        hits.extend(self.signatures.match_hash(sha256))
        hits.extend(self.signatures.match_content(sample, size))

        score = 0.0
        if self.config.use_heuristics:
            assessment: HeuristicAssessment = self.heuristics.assess(label, sample, size)
            hits.extend(assessment.hits)
            score = assessment.score

        if self.config.use_yara and self.yara is not None:
            hits.extend(self.yara.match(sample, size))
        return self._dedupe(hits), score

    def _add_findings(
        self,
        result: ScanResult,
        label: str,
        hits: list[RuleHit],
        score: float,
        sha256: str,
        size: int,
        container: str = "",
    ) -> None:
        indicators_prefix = (f"container: {container}",) if container else ()
        for hit in hits:
            result.findings.append(
                Finding(
                    path=label,
                    rule_id=hit.rule_id,
                    detection=hit.detection,
                    severity=hit.severity,
                    description=hit.description,
                    sha256=sha256,
                    size=size,
                    score=score if hit.rule_id == "HEUR-SCORE" else 0.0,
                    indicators=list(indicators_prefix + hit.indicators),
                )
            )

    @staticmethod
    def _dedupe(hits: Iterable[RuleHit]) -> list[RuleHit]:
        """Removes duplicate rules while keeping the highest severity."""
        by_id: dict[str, RuleHit] = {}
        for hit in hits:
            existing = by_id.get(hit.rule_id)
            if existing is None or hit.severity.rank > existing.severity.rank:
                by_id[hit.rule_id] = hit
        return list(by_id.values())


def summarize(result: ScanResult) -> dict[str, object]:
    """Quick summary for use in scripts."""
    by_severity: dict[str, int] = {}
    for finding in result.findings:
        key = finding.severity.value
        by_severity[key] = by_severity.get(key, 0) + 1
    return {
        "files_scanned": result.files_scanned,
        "container_entries": result.container_entries,
        "findings": len(result.findings),
        "by_severity": by_severity,
        "max_severity": result.max_severity.value if result.max_severity else None,
        "errors": len(result.errors),
    }


__all__ = ["Detection", "ProgressCallback", "Scanner", "Severity", "summarize"]
