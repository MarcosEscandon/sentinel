"""Pruebas de la autoevaluación de seguridad de Sentinel."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sentinel import crypto
from sentinel.audit import (
    PUBLIC_KEY_ENV,
    AuditCheck,
    SecurityAudit,
    _home_location_problem,
    run_security_audit,
)

BUNDLED_SIGNATURES = Path(__file__).parent.parent / "sentinel" / "data" / "signatures.json"

pytest.importorskip("cryptography")

CHECK_NAMES = {
    "signatures.valid",
    "signatures.signed",
    "quarantine.integrity",
    "quarantine.key_permissions",
    "logging.enabled",
    "allowlist.self",
    "realtime.backend",
    "config.sane",
    "home.location",
    "iocs.minimum",
}


@pytest.fixture
def signed_database(tmp_path: Path):
    """Copia la base incluida, la firma y devuelve ``(json, pública)``."""
    payload = BUNDLED_SIGNATURES.read_bytes()
    database = tmp_path / "signatures.json"
    database.write_bytes(payload)
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    crypto.generate_keypair(private, public)
    Path(str(database) + ".sig").write_bytes(crypto.sign_payload(payload, private))
    return database, public


def _by_name(audit: SecurityAudit) -> dict[str, AuditCheck]:
    return {check.name: check for check in audit.checks}


def test_bundled_signatures_pass_everything(tmp_path: Path) -> None:
    audit = run_security_audit(tmp_path, BUNDLED_SIGNATURES)

    assert set(_by_name(audit)) == CHECK_NAMES
    assert audit.failures == []
    assert audit.passed
    assert audit.score == 100
    assert "Ed25519" in _by_name(audit)["signatures.signed"].detail
    assert "sin entradas" in _by_name(audit)["quarantine.integrity"].detail
    # El evento de prueba queda como una línea JSON válida, no como un archivo roto.
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["event"] == "audit.check"


def test_valid_ed25519_signature_passes(tmp_path: Path, signed_database) -> None:
    database, public = signed_database
    (tmp_path / "signing.pub").write_bytes(public.read_bytes())

    audit = run_security_audit(tmp_path, database)

    assert _by_name(audit)["signatures.signed"].passed
    assert audit.passed
    assert audit.score == 100
    assert audit.failures == []


def test_public_key_from_environment(tmp_path: Path, signed_database, monkeypatch) -> None:
    database, public = signed_database
    monkeypatch.setenv(PUBLIC_KEY_ENV, str(public))

    audit = run_security_audit(tmp_path, database)

    assert _by_name(audit)["signatures.signed"].passed


def test_tampering_signed_json_fails_signature(tmp_path: Path, signed_database) -> None:
    database, public = signed_database
    (tmp_path / "signing.pub").write_bytes(public.read_bytes())
    original = run_security_audit(tmp_path, database)
    assert original.passed

    payload = json.loads(database.read_text(encoding="utf-8"))
    payload["revision"] = payload["revision"] + 1
    database.write_text(json.dumps(payload), encoding="utf-8")

    tampered = run_security_audit(tmp_path, database)
    assert not _by_name(tampered)["signatures.signed"].passed
    assert _by_name(tampered)["signatures.valid"].passed
    assert not tampered.passed
    assert tampered.score < original.score


def test_wrong_signature_length_fails(tmp_path: Path, signed_database) -> None:
    database, public = signed_database
    (tmp_path / "signing.pub").write_bytes(public.read_bytes())
    Path(str(database) + ".sig").write_bytes(b"\x00" * 63)

    audit = run_security_audit(tmp_path, database)

    assert not _by_name(audit)["signatures.signed"].passed
    assert "64" in _by_name(audit)["signatures.signed"].detail


def test_to_dict_failures_and_invalid_paths(tmp_path: Path) -> None:
    missing_home = tmp_path / "no-existe" / "anidada"
    missing_signatures = tmp_path / "no-existe.json"

    audit = run_security_audit(missing_home, missing_signatures)
    payload = audit.to_dict()

    # El informe es serializable y refleja exactamente las propiedades.
    json.dumps(payload)
    assert payload["home"] == str(missing_home)
    assert payload["signatures"] == str(missing_signatures)
    assert payload["passed"] == audit.passed
    assert payload["score"] == audit.score
    assert payload["failures"]
    assert {item["name"] for item in payload["failures"]} == {
        check.name for check in audit.failures
    }
    assert 0 <= payload["score"] < 100
    assert audit.score == round(100 * sum(c.passed for c in audit.checks) / len(audit.checks))
    failed_names = {check.name for check in audit.failures}
    assert {"signatures.valid", "signatures.signed", "iocs.minimum"} <= failed_names
    # Aun con la home ausente, el check de logging crea el directorio y el JSONL.
    assert json.loads((missing_home / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])[
        "event"
    ] == "audit.check"


def test_no_exceptions_with_invalid_types() -> None:
    audit = run_security_audit(None, None)  # type: ignore[arg-type]

    assert isinstance(audit, SecurityAudit)
    assert not audit.passed
    assert audit.score == 0
    assert [check.name for check in audit.failures] == ["audit.setup"]


def test_security_audit_score_edges(tmp_path: Path) -> None:
    empty = SecurityAudit(tmp_path, BUNDLED_SIGNATURES, [])
    assert not empty.passed
    assert empty.score == 0
    assert empty.failures == []

    checks = [
        AuditCheck("uno", True, "bien"),
        AuditCheck("dos", True, "bien", "remediación no usada"),
    ]
    full = SecurityAudit(tmp_path, BUNDLED_SIGNATURES, checks)
    assert full.passed
    assert full.score == 100
    assert full.failures == []
    assert full.to_dict()["checks"][1]["remediation"] == "remediación no usada"


@pytest.mark.skipif(os.name != "nt", reason="Rutas exclusivas de Windows")
def test_home_location_helper_windows() -> None:
    assert _home_location_problem(Path(r"C:\Windows\Temp")) is not None
    assert _home_location_problem(Path(r"C:\Program Files\Sentinel")) is not None
    assert _home_location_problem(Path(r"C:\Program Files (x86)\Sentinel")) is not None
    assert _home_location_problem(Path(r"C:\ProgramData\Sentinel")) is None
    assert _home_location_problem(Path(r"C:\Users\marco\.sentinel")) is None
