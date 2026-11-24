# Scanner performance

This document describes the methodology of the benchmark included in
`tools/benchmark.py`, the actual results obtained and the recommendations
derived from them. The raw data is in `docs/benchmark-results.json`.

## Methodology

The script generates a temporary tree with `tempfile` (not included in the
repository) and removes it when finished unless `--keep` is used. By default it
creates 2000 files distributed across 8 subdirectories, with uniform random
sizes between 1 KiB and 64 KiB (63.0 MiB in total). The seed is fixed
(`20261123`) so that the experiment is reproducible. Every 50 files, the marker
`SENTINEL_TEST_MARKER` is inserted, recognized by the real signature database
`sentinel/data/signatures.json` (40 marked files in this run).

For each `--jobs` value a new `Scanner` is created with an identical `ScanConfig`
except for the thread count, and a single complete pass is measured with
`time.perf_counter()`:

- default configuration: `hash_all=True` (SHA-256 of the whole file), heuristics
  enabled, container analysis enabled and `sample_size=1 MiB`;
- YARA is not exercised because the benchmark does not inject a YARA engine;
- enumeration + reading + hashing + detection + result merging are measured;
  tree generation and writing the results JSON are not measured;
- `MB/s` uses MiB (1024² bytes) and `files/s` uses `files_scanned`.

Command executed:

```powershell
python tools/benchmark.py --files 2000 --output docs/benchmark-results.json
```

Environment: Python 3.10.11, Windows 10 (10.0.26200), 2000 files, 66109688
bytes, generated on 2026-11-23T12:59:48+00:00.

## Actual results

| Threads | Time (s) | MB/s | Files/s | Findings | Speedup vs. 1 thread |
| ------: | ---------: | ---: | ---------: | --------: | -------------------: |
|       1 |     2,3863 | 26,42 |     838,12 |      1948 |                 1,00× |
|       2 |     2,2431 | 28,11 |     891,64 |      1948 |                 1,06× |
|       4 |     2,2036 | 28,61 |     907,61 |      1948 |                 1,08× |
|       8 |     2,2148 | 28,47 |     903,02 |      1948 |                 1,08× |

The four scans processed all 2000 files and 66109688 bytes, with 0 errors. The
number of findings is identical across all configurations, confirming that
parallelism does not alter the result.

## Interpretation

Going from 1 to 2 threads reduces the time by 6% (2.3863 s → 2.2431 s) and from
1 to 4 threads by 8% (2.2036 s). At 8 threads there is no further improvement:
the time even rises slightly (2.2148 s) compared with 4 threads.

This behavior is expected for small files:

- per-file work is mostly CPU (SHA-256, signature regular expressions and
  heuristics) and the GIL prevents those threads from executing Python bytecode
  simultaneously;
- read operations are short (1–64 KiB), so the I/O thread blocks little and
  little time remains to overlap while another thread does CPU work;
- there is a fixed cost per file (file system calls, creation of the partial
  `ScanResult`, future submission, finding merging and progress emission). With
  files averaging ~33 KiB, that cost dominates;
- from 4 threads onward, GIL contention and `ThreadPoolExecutor` overhead
  outweigh the small overlap gain.

The figure of 1948 findings does not indicate real malware: the data is random
and the entropy and scoring heuristics flag most of them. What matters for the
benchmark is that the count is constant across thread counts.

## Production recommendations

1. Use `--jobs 4` as a starting point on 4- or 8-core machines with SSDs. It is
   the value with the best measured time and leaves headroom for the operating
   system.
2. Do not go above 8 threads for this type of workload: it brings no benefit and
   consumes more memory and context switches. The maximum allowed by
   `ScanConfig` is 64, but it is intended for workloads with much more I/O wait.
3. Keep `--jobs 1` for very small trees, debugging, or when deterministic
   progress order is needed (parallel mode emits events in completion order,
   not input order).
4. On network drives or high-latency disks, measure again: there I/O overlap may
   justify 8 or more threads.
5. Tune the configuration rather than the thread count when the bottleneck is
   CPU: reduce `sample_size`, disable `hash_all` if hashes of all files are not
   needed, or pass `--no-containers` in directories without compressed files.
6. Exclude cache and dependency directories in advance (`node_modules`,
   `.venv`, `__pycache__`) to avoid paying the cost of files that provide no
   signal.
7. Repeat the measurement on the target machine and with representative data
   before fixing a value in `config.json`.

## Known limitations

- A single run per configuration: there is no mean, standard deviation or
  warm-up. Differences below 5% (such as 4 vs. 8 threads) are not statistically
  significant.
- Sizes are limited to 1–64 KiB. The results do not extrapolate to large files,
  where sequential hashing and reading dominate and I/O overlap may behave
  differently.
- The tree is created in the system's temporary directory (`%TEMP%` on Windows).
  The file system cache and the antivirus may influence the results; that
  effect is neither controlled nor measured.
- YARA, rules with real `regex` timeouts and compressed containers are not
  exercised (the generated files are `.bin`), even though the configuration
  enables them.
- Memory consumption, per-core CPU usage and per-file latency are not measured:
  only total time and aggregate throughput.
- The measurement machine may be shared; the numbers are indicative and should
  only be compared between rows of the same run.
