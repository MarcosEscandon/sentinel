import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.core.quarantine import Quarantine, QuarantineIntegrityError


def test_add_list_restore(tmp_path):
    original = tmp_path / "sospechoso.bin"
    original.write_bytes(b"datos")
    store = Quarantine(tmp_path / "quarantine")

    entry_id = store.add(original, "TEST-1", "abc")
    assert not original.exists()
    assert len(store.list()) == 1
    entry = store.get(entry_id)
    assert entry.reason == "TEST-1"
    assert entry.sha256 == "abc"

    restored = store.restore(entry_id)
    assert restored == original.resolve()
    assert original.read_bytes() == b"datos"
    assert store.list() == []


def test_restore_refuses_overwrite(tmp_path):
    original = tmp_path / "a.bin"
    original.write_bytes(b"viejo")
    store = Quarantine(tmp_path / "q")
    entry_id = store.add(original)
    original.write_bytes(b"nuevo")

    with pytest.raises(FileExistsError):
        store.restore(entry_id)
    restored = store.restore(entry_id, overwrite=True)
    assert restored.read_bytes() == b"viejo"


def test_delete_and_prune(tmp_path):
    for name in ("a.bin", "b.bin"):
        (tmp_path / name).write_bytes(b"x")
    store = Quarantine(tmp_path / "q")
    first = store.add(tmp_path / "a.bin")
    second = store.add(tmp_path / "b.bin")

    assert store.prune(days=30) == 0
    index = store.index_path
    payload = json.loads(index.read_text(encoding="utf-8"))
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    for entry in payload["entries"]:
        if entry["id"] == first:
            entry["quarantined_at"] = old
    index.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    assert store.prune(days=30) == 1
    assert [entry.id for entry in store.list()] == [second]
    store.delete(second)
    assert store.list() == []


def test_invalid_id(tmp_path):
    store = Quarantine(tmp_path / "q")
    with pytest.raises(ValueError):
        store.get("../index.json")


def test_verify_detects_modified_file(tmp_path):
    original = tmp_path / "sospechoso.bin"
    original.write_bytes(b"datos originales")
    store = Quarantine(tmp_path / "q")
    entry_id = store.add(original, "TEST")

    assert store.verify_entry(entry_id)
    stored = Path(store.get(entry_id).stored_path)
    stored.write_bytes(b"datos manipulado")  # mismo tamaño: debe fallar por hash

    with pytest.raises(QuarantineIntegrityError, match="Hash modificado"):
        store.verify_entry(entry_id)
    with pytest.raises(QuarantineIntegrityError):
        store.restore(entry_id)
    assert [(item.id, bool(error)) for item, error in store.verify_all()] == [(entry_id, True)]


def test_verify_detects_modified_index(tmp_path):
    original = tmp_path / "sospechoso.bin"
    original.write_bytes(b"datos")
    store = Quarantine(tmp_path / "q")
    entry_id = store.add(original)

    payload = json.loads(store.index_path.read_text(encoding="utf-8"))
    payload["entries"][0]["reason"] = "MANIPULADO"
    store.index_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(QuarantineIntegrityError, match="índice"):
        store.verify_entry(entry_id)
    with pytest.raises(QuarantineIntegrityError):
        store.restore(entry_id)
    # La limpieza sigue disponible aunque el índice esté dañado.
    assert store.prune(days=30) == 0
    store.delete(entry_id)
    assert store.list() == []


def test_key_lives_outside_quarantine(tmp_path):
    store = Quarantine(tmp_path / "q")
    (tmp_path / "a.bin").write_bytes(b"x")
    store.add(tmp_path / "a.bin")
    assert store.key_path == tmp_path / "quarantine.key"
    assert store.key_path.is_file()
    assert not (store.directory / "quarantine.key").exists()
