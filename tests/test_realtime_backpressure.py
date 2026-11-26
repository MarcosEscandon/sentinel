"""Backpressure tests for the real-time monitor's pending queue."""

from __future__ import annotations

import json

import pytest

from sentinel.core.logging import AuditLogger
from sentinel.realtime import DEFAULT_MAX_PENDING, RealtimeMonitor


def _monitor(tmp_path, max_pending):
    log = tmp_path / "audit.jsonl"
    monitor = RealtimeMonitor(
        [tmp_path],
        logger=AuditLogger(log),
        poll_interval=0.05,
        grace_period=0.01,
        backend="polling",
        max_pending=max_pending,
    )
    return monitor, log


def test_pending_set_is_bounded_and_drop_is_audited(tmp_path):
    monitor, log = _monitor(tmp_path, 2)
    files = [tmp_path / f"sample-{index}.bin" for index in range(3)]
    for path in files:
        path.write_bytes(b"x")
        monitor._enqueue(path)

    assert len(monitor._pending) == 2
    assert str(files[2]) not in monitor._pending

    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    errors = [event for event in events if event["event"] == "realtime.error"]
    assert len(errors) == 1
    assert errors[0]["path"] == "queue"
    assert "pending limit 2 reached" in errors[0]["error"]


def test_repeated_event_does_not_consume_budget(tmp_path):
    monitor, _ = _monitor(tmp_path, 1)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"x")

    monitor._enqueue(sample)
    first_deadline = monitor._pending[str(sample)]
    monitor._enqueue(sample)

    assert len(monitor._pending) == 1
    assert monitor._pending[str(sample)] >= first_deadline
    assert monitor._dropped_events == 0


def test_default_limit_is_positive_and_invalid_values_rejected(tmp_path):
    assert DEFAULT_MAX_PENDING > 0
    with pytest.raises(ValueError, match="max_pending"):
        _monitor(tmp_path, 0)


def test_stop_with_full_wakeup_queue_does_not_block(tmp_path):
    monitor, _ = _monitor(tmp_path, 1)
    for index in range(monitor._queue.maxsize):
        monitor._queue.put_nowait(str(index))
    monitor.stop(timeout=0.1)
    assert monitor._stop_event.is_set()
