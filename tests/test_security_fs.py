import os
import time

from sentinel.security_fs import cleanup_old_files, restrict_permissions, secure_write_text


def test_secure_write_text_is_atomic_and_restrictive(tmp_path):
    target = tmp_path / "audit.jsonl"
    secure_write_text(target, '{"event":"scan.start"}\n')

    assert target.read_text(encoding="utf-8") == '{"event":"scan.start"}\n'
    assert not (tmp_path / "audit.jsonl.tmp").exists()
    if os.name != "nt":
        assert os.stat(target).st_mode & 0o777 == 0o600


def test_restrict_permissions_on_directory(tmp_path):
    # On Windows this is best-effort via icacls; it must never raise.
    assert restrict_permissions(tmp_path) in (True, False)
    if os.name != "nt":
        assert os.stat(tmp_path).st_mode & 0o777 == 0o700


def test_cleanup_only_removes_matching_old_files(tmp_path):
    old = tmp_path / "audit-2026-01-01.jsonl"
    recent = tmp_path / "audit-2026-11-26.jsonl"
    key = tmp_path / "quarantine.key"
    for path in (old, recent, key):
        path.write_text("x", encoding="utf-8")

    forty_five_days_ago = time.time() - 45 * 86400
    os.utime(old, (forty_five_days_ago, forty_five_days_ago))
    now = time.time()
    os.utime(recent, (now, now))

    removed = cleanup_old_files(tmp_path, days=30, pattern="audit-*.jsonl")

    assert removed == 1
    assert not old.exists()
    assert recent.exists()
    assert key.exists()


def test_cleanup_rejects_negative_retention(tmp_path):
    try:
        cleanup_old_files(tmp_path, days=-1)
    except ValueError:
        return
    raise AssertionError("negative retention must be rejected")
