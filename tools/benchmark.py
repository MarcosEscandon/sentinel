"""Reproducible benchmark for the Sentinel scanner.

Generates a temporary tree of mixed-size files, measures sequential and
parallel scanning, and saves a JSON file with the results.

Typical usage from the project root::

    python tools/benchmark.py --files 2000 --output docs/benchmark-results.json
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sentinel.engine.signatures import SignatureDatabase

# When running ``python tools/benchmark.py``, ``tools/`` is first on
# sys.path; add the root so ``sentinel`` imports work even if the package
# is not installed in editable mode. Actual imports happen inside the
# functions, after this adjustment.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MARKER = b"SENTINEL_TEST_MARKER"
MIN_SIZE = 1024  # 1 KiB
MAX_SIZE = 64 * 1024  # 64 KiB
DEFAULT_FILES = 2000
DEFAULT_JOBS = (1, 2, 4, 8)
SEED = 20261123
SUBDIRS = 8
MARKER_EVERY = 50


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Validate and return the command-line arguments."""
    parser = argparse.ArgumentParser(description="Measure the performance of the Sentinel scanner.")
    parser.add_argument(
        "--files",
        type=int,
        default=DEFAULT_FILES,
        help=f"Number of files to generate (default: {DEFAULT_FILES}).",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        nargs="+",
        default=list(DEFAULT_JOBS),
        metavar="N",
        help="Thread counts to test (default: 1 2 4 8).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs" / "benchmark-results.json",
        help="Path to the results JSON.",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep the temporary tree (its path is printed).",
    )
    args = parser.parse_args(argv)

    if args.files <= 0:
        parser.error("--files must be a positive integer")
    if not args.jobs or any(jobs < 1 or jobs > 64 for jobs in args.jobs):
        parser.error("--jobs must contain values between 1 and 64")
    return args


def generate_tree(root: Path, count: int, rng: random.Random) -> tuple[int, int]:
    """Create ``count`` files spread across subdirectories.

    Return the total number of bytes written and how many files contain the
    test marker recognized by the real signature database.
    """
    directories = [root / f"batch_{index:02d}" for index in range(SUBDIRS)]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    marked = 0
    for index in range(count):
        size = rng.randint(MIN_SIZE, MAX_SIZE)
        data = bytearray(rng.randbytes(size))
        if index % MARKER_EVERY == 0:
            data[: len(MARKER)] = MARKER
            marked += 1
        path = directories[index % SUBDIRS] / f"file_{index:06d}.bin"
        path.write_bytes(data)
        total_bytes += size
    return total_bytes, marked


def run_once(database: SignatureDatabase, tree: Path, jobs: int) -> dict[str, Any]:
    """Run a full scan and return its metrics."""
    from sentinel.config import ScanConfig
    from sentinel.engine.scanner import Scanner

    config = ScanConfig(jobs=jobs)
    started = time.perf_counter()
    result = Scanner(database, config).scan([tree])
    elapsed = time.perf_counter() - started

    files = result.files_scanned
    scanned_bytes = result.bytes_scanned
    megabytes = scanned_bytes / (1024 * 1024)
    return {
        "jobs": jobs,
        "elapsed_seconds": round(elapsed, 4),
        "files_scanned": files,
        "bytes_scanned": scanned_bytes,
        "mb_per_second": round(megabytes / elapsed, 2) if elapsed > 0 else 0.0,
        "files_per_second": round(files / elapsed, 2) if elapsed > 0 else 0.0,
        "findings": len(result.findings),
        "errors": len(result.errors),
    }


def print_table(results: list[dict[str, Any]], total_bytes: int) -> None:
    """Print a readable comparison table."""
    print(f"\nResults: {len(results)} configurations over {total_bytes / 1048576:.1f} MiB\n")
    header = (
        f"{'jobs':>5} | {'time (s)':>10} | {'MB/s':>8} | {'files/s':>11} "
        f"| {'findings':>9} | {'speedup':>9}"
    )
    print(header)
    print("-" * len(header))
    baseline = results[0]["elapsed_seconds"]
    for row in results:
        speedup = baseline / row["elapsed_seconds"] if row["elapsed_seconds"] > 0 else 0.0
        print(
            f"{row['jobs']:>5} | {row['elapsed_seconds']:>10.4f} | {row['mb_per_second']:>8.2f} "
            f"| {row['files_per_second']:>11.2f} | {row['findings']:>9} | {speedup:>8.2f}x"
        )


def main(argv: list[str] | None = None) -> int:
    """Script entry point; return the exit code."""
    from sentinel.engine.signatures import SignatureDatabase

    args = parse_args(argv)
    database = SignatureDatabase.load(ROOT / "sentinel" / "data" / "signatures.json")
    rng = random.Random(SEED)

    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.keep:
        tree = Path(tempfile.mkdtemp(prefix="sentinel-benchmark-"))
    else:
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-benchmark-")
        tree = Path(temporary.name)

    try:
        print(f"Generating {args.files} files in {tree} ...")
        total_bytes, marked = generate_tree(tree, args.files, rng)
        print(f"Tree ready: {marked} files with the marker, {total_bytes / 1048576:.1f} MiB.")

        results: list[dict[str, Any]] = []
        for jobs in args.jobs:
            print(f"Scanning with {jobs} thread(s) ...", flush=True)
            results.append(run_once(database, tree, jobs))

        payload: dict[str, Any] = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "files_requested": args.files,
            "marker_files": marked,
            "total_bytes": total_bytes,
            "jobs_tested": args.jobs,
            "results": results,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

        print_table(results, total_bytes)
        print(f"\nResults saved to {args.output}")
        if args.keep:
            print(f"Tree kept at {tree}")
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted by the user; no results were written.", file=sys.stderr)
        if args.keep:
            print(f"Tree kept at {tree}", file=sys.stderr)
        return 130
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
