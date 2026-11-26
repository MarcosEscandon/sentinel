import json
import os
import time

from sentinel.core.logging import AuditLogger


def test_audit_log_is_restricted_to_current_user(tmp_path):
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.emit("scan.start", roots=["C:\\data"])

    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert events[0]["event"] == "scan.start"
    if os.name != "nt":
        assert os.stat(log).st_mode & 0o777 == 0o600


def test_stale_audit_files_are_removed_on_startup(tmp_path):
    stale = tmp_path / "audit-old.jsonl"
    current = tmp_path / "audit.jsonl"
    unrelated = tmp_path / "other.jsonl"
    for path in (stale, current, unrelated):
        path.write_text("{}\n", encoding="utf-8")

    old = time.time() - 45 * 86400
    os.utime(stale, (old, old))

    AuditLogger(current)

    assert not stale.exists()
    assert current.exists()
    assert unrelated.exists()
