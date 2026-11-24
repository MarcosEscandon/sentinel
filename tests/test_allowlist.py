import hashlib
import json

import pytest

from sentinel.core.allowlist import AllowList, normalize_path


def test_exact_path_directory_glob_and_hash(tmp_path):
    allowed_file = tmp_path / "good.exe"
    allowed_file.write_bytes(b"ok")
    other = tmp_path / "bad.exe"
    other.write_bytes(b"mal")
    nested = tmp_path / "sub" / "x.exe"
    nested.parent.mkdir()
    nested.write_bytes(b"x")

    rules = AllowList(
        paths=frozenset({normalize_path(allowed_file)}),
        directories=frozenset({normalize_path(tmp_path / "sub")}),
        globs=frozenset({"*\\tmp\\pytest-*\\odd.exe"}),
        hashes=frozenset({hashlib.sha256(b"mal").hexdigest()}),
    )

    assert rules.allows_path(allowed_file)
    assert rules.allows_path(nested)
    assert not rules.allows_path(other)
    assert rules.allows_hash(hashlib.sha256(b"mal").hexdigest())
    assert not rules.allows_hash(hashlib.sha256(b"ok").hexdigest())


def test_glob_matching(tmp_path):
    target = tmp_path / "cualquiera.exe"
    pattern = normalize_path(target).replace("cualquiera.exe", "*.exe")
    rules = AllowList(globs=frozenset({pattern}))
    assert rules.allows_path(target)
    assert not rules.allows_path(tmp_path / "otro.txt")


def test_self_and_files(tmp_path):
    report = tmp_path / "report.json"
    rules = AllowList.combine(
        AllowList.for_self([tmp_path]),
        AllowList.for_files([report]),
    )
    assert rules.allows_path(tmp_path / "history.db")
    assert rules.allows_path(report)
    assert not rules.allows_path(tmp_path.parent / "externo.exe")
    assert "auto:sel" in rules.sources[0]


def test_load_and_validate(tmp_path):
    path = tmp_path / "allowlist.json"
    path.write_text(
        json.dumps({"version": 1, "paths": [], "directories": [], "globs": [], "hashes": []}),
        encoding="utf-8",
    )
    assert AllowList.load(path).stats()["paths"] == 0
    assert AllowList.load(tmp_path / "missing.json").stats()["paths"] == 0
    with pytest.raises(FileNotFoundError):
        AllowList.load(tmp_path / "missing.json", required=True)

    path.write_text(json.dumps({"version": 99}), encoding="utf-8")
    with pytest.raises(ValueError):
        AllowList.load(path)
