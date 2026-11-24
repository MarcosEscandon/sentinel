import json

import pytest

from sentinel import service as windows_service
from sentinel.cli import main

SIGNATURES = "C:\\signatures\\signatures.json"


def test_save_and_load_config(tmp_path):
    home = tmp_path / "home"
    path = windows_service.save_config(
        home, paths=["C:\\Users\\marco\\Downloads", "D:\\docs"], signatures=SIGNATURES
    )
    assert path == home / "service.json"

    config = windows_service.load_config(home)
    assert config["paths"] == ["C:\\Users\\marco\\Downloads", "D:\\docs"]
    assert config["signatures"] == SIGNATURES
    assert config["poll_interval"] == 2.0
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 1


def test_config_validation(tmp_path):
    with pytest.raises(ValueError):
        windows_service.save_config(tmp_path, paths=[])
    with pytest.raises(ValueError):
        windows_service.save_config(tmp_path, paths=["C:\\tmp"], poll_interval=0)
    with pytest.raises(windows_service.ServiceUnavailable):
        windows_service.load_config(tmp_path / "no-config")

    broken = tmp_path / "service.json"
    broken.write_text("not json", encoding="utf-8")
    with pytest.raises((ValueError, TypeError)):
        windows_service.load_config(tmp_path)


def test_service_home_pointer_roundtrip(tmp_path, monkeypatch):
    pointer = tmp_path / "ProgramData" / "sentinel" / "service_home.txt"
    monkeypatch.setattr(windows_service, "SERVICE_HOME_POINTER", pointer)
    home = tmp_path / "home"

    windows_service.save_service_home(home)
    assert pointer.read_text(encoding="utf-8") == str(home.resolve())
    assert windows_service.load_service_home() == home.resolve()

    windows_service.clear_service_home()
    assert not pointer.exists()
    assert windows_service.load_service_home() == windows_service.DEFAULT_HOME


def test_cli_service_reports_missing_pywin32(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(windows_service, "service_available", lambda: False)
    assert main(["--home", str(tmp_path), "service", "status"]) == 2
    assert "pywin32" in capsys.readouterr().err


def test_cli_service_install_writes_config(tmp_path, monkeypatch, capsys):
    saved: dict[str, object] = {}

    def fake_install(home, *, startup="auto"):
        saved["home"] = home
        saved["startup"] = startup
        return "SentinelRealtime"

    monkeypatch.setattr(windows_service, "install", fake_install)
    assert main(
        [
            "--home",
            str(tmp_path),
            "--signatures",
            SIGNATURES,
            "service",
            "install",
            "--paths",
            "C:\\Downloads",
            "--startup",
            "manual",
        ]
    ) == 0
    assert saved == {"home": str(tmp_path), "startup": "manual"}
    config = windows_service.load_config(tmp_path)
    assert config["paths"] == ["C:\\Downloads"]
    assert (tmp_path / "audit.jsonl").is_file()
    capsys.readouterr()
