"""Benchmark reproducible del escáner de Sentinel.

Genera un árbol temporal con archivos de tamaño mixto, mide el escaneo
secuencial y paralelo y guarda un JSON con los resultados.

Uso típico desde la raíz del proyecto::

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

# Al ejecutar ``python tools/benchmark.py`` el directorio ``tools/`` encabeza
# sys.path; añadimos la raíz para que los imports de ``sentinel`` funcionen
# aunque el paquete no esté instalado en modo editable. Los imports reales se
# hacen dentro de las funciones, después de este ajuste.
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
    """Valida y devuelve los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(description="Mide el rendimiento del escáner de Sentinel.")
    parser.add_argument(
        "--files",
        type=int,
        default=DEFAULT_FILES,
        help=f"Número de archivos a generar (por defecto: {DEFAULT_FILES}).",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        nargs="+",
        default=list(DEFAULT_JOBS),
        metavar="N",
        help="Números de hilos a probar (por defecto: 1 2 4 8).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs" / "benchmark-results.json",
        help="Ruta del JSON de resultados.",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Conserva el árbol temporal (se imprime su ruta).",
    )
    args = parser.parse_args(argv)

    if args.files <= 0:
        parser.error("--files debe ser un entero positivo")
    if not args.jobs or any(jobs < 1 or jobs > 64 for jobs in args.jobs):
        parser.error("--jobs debe contener valores entre 1 y 64")
    return args


def generate_tree(root: Path, count: int, rng: random.Random) -> tuple[int, int]:
    """Crea ``count`` archivos repartidos en subdirectorios.

    Devuelve el total de bytes escritos y cuántos archivos llevan el marcador
    de prueba reconocido por la base de firmas real.
    """
    directories = [root / f"lote_{index:02d}" for index in range(SUBDIRS)]
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
        path = directories[index % SUBDIRS] / f"archivo_{index:06d}.bin"
        path.write_bytes(data)
        total_bytes += size
    return total_bytes, marked


def run_once(database: SignatureDatabase, tree: Path, jobs: int) -> dict[str, Any]:
    """Ejecuta un escaneo completo y devuelve sus métricas."""
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
    """Imprime una tabla comparativa legible en español."""
    print(f"\nResultados: {len(results)} configuraciones sobre {total_bytes / 1048576:.1f} MiB\n")
    header = (
        f"{'hilos':>5} | {'tiempo (s)':>10} | {'MB/s':>8} | {'archivos/s':>11} "
        f"| {'hallazgos':>9} | {'vs 1 hilo':>9}"
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
    """Punto de entrada del script; devuelve el código de salida."""
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
        print(f"Generando {args.files} archivos en {tree} ...")
        total_bytes, marked = generate_tree(tree, args.files, rng)
        print(f"Árbol listo: {marked} archivos con marcador, {total_bytes / 1048576:.1f} MiB.")

        results: list[dict[str, Any]] = []
        for jobs in args.jobs:
            print(f"Escaneando con {jobs} hilo(s) ...", flush=True)
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
        print(f"\nResultados guardados en {args.output}")
        if args.keep:
            print(f"Árbol conservado en {tree}")
        return 0
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario; no se escribieron resultados.", file=sys.stderr)
        if args.keep:
            print(f"Árbol conservado en {tree}", file=sys.stderr)
        return 130
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
