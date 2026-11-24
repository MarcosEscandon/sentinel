"""Tests for the integrity manifest and the signature package signature."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import crypto
from sentinel.integrity import (
    IntegrityReport,
    build_manifest,
    verify_manifest,
    verify_signatures_bundle,
)


def _tree(root: Path) -> list[Path]:
    """Creates a small tree with three files and returns their paths."""
    files = [root / "one.txt", root / "sub" / "two.txt", root / "sub" / "three.txt"]
    files[1].parent.mkdir(parents=True, exist_ok=True)
    for index, path in enumerate(files):
        path.write_text(f"content {index}\n", encoding="utf-8")
    return files


def _build(root: Path) -> tuple[list[Path], Path, dict[str, object]]:
    """Prepares the tree, generates the manifest, and returns both."""
    files = _tree(root)
    manifest_path = root / "manifest.json"
    manifest = build_manifest(root, manifest_path)
    return files, manifest_path, manifest


def test_build_and_verify_ok(tmp_path: Path) -> None:
    """An intact tree verifies successfully and does not include the manifest."""
    _, manifest_path, manifest = _build(tmp_path)

    assert manifest["algorithm"] == "sha256"
    assert manifest["generated_at"]
    assert {item["path"] for item in manifest["files"]} == {
        "one.txt",
        "sub/two.txt",
        "sub/three.txt",
    }
    assert json.loads(manifest_path.read_text(encoding="utf-8")) == manifest

    report = verify_manifest(tmp_path, manifest_path)
    assert isinstance(report, IntegrityReport)
    assert report.ok is True
    assert report.expected == 3
    assert (report.missing, report.modified, report.added) == (0, 0, 0)
    assert report.details == []


def test_detect_modified(tmp_path: Path) -> None:
    """Changing a file's content is reported as ``modified``."""
    files, manifest_path, _ = _build(tmp_path)
    files[0].write_text("modified content\n", encoding="utf-8")

    report = verify_manifest(tmp_path, manifest_path)
    assert report.ok is False
    assert report.modified == 1
    assert (report.missing, report.added) == (0, 0)
    assert report.details[0]["status"] == "modified"
    assert report.details[0]["path"] == "one.txt"
    assert report.details[0]["expected_sha256"] != report.details[0]["actual_sha256"]


def test_detect_missing(tmp_path: Path) -> None:
    """Deleting a file is reported as ``missing`` without raising exceptions."""
    files, manifest_path, _ = _build(tmp_path)
    files[1].unlink()

    report = verify_manifest(tmp_path, manifest_path)
    assert report.ok is False
    assert report.missing == 1
    assert (report.modified, report.added) == (0, 0)
    assert report.details[0]["status"] == "missing"
    assert report.details[0]["path"] == "sub/two.txt"
    assert report.details[0]["actual_sha256"] is None


def test_detect_added(tmp_path: Path) -> None:
    """Adding a file after the manifest is reported as ``added``."""
    _, manifest_path, _ = _build(tmp_path)
    (tmp_path / "new.txt").write_text("extra\n", encoding="utf-8")

    report = verify_manifest(tmp_path, manifest_path)
    assert report.ok is False
    assert report.added == 1
    assert (report.missing, report.modified) == (0, 0)
    assert report.details[0]["status"] == "added"
    assert report.details[0]["path"] == "new.txt"
    assert report.details[0]["expected_sha256"] is None


def test_combined_changes_and_to_dict(tmp_path: Path) -> None:
    """All three change types coexist and are serialized by ``to_dict``."""
    files, manifest_path, _ = _build(tmp_path)
    files[0].write_text("change\n", encoding="utf-8")
    files[2].unlink()
    (tmp_path / "extra.bin").write_bytes(b"\x00\x01")

    report = verify_manifest(tmp_path, manifest_path)
    assert report.ok is False
    assert report.expected == 3
    assert (report.missing, report.modified, report.added) == (1, 1, 1)

    payload = report.to_dict()
    assert set(payload) == {"ok", "expected", "missing", "modified", "added", "details"}
    assert payload["ok"] is False
    assert {item["status"] for item in payload["details"]} == {
        "missing",
        "modified",
        "added",
    }


def test_default_exclusions(tmp_path: Path) -> None:
    """Caches, keys, quarantine, and metadata are omitted by default."""
    _tree(tmp_path)
    ignored = [
        tmp_path / "__pycache__" / "mod.pyc",
        tmp_path / "quarantine_store" / "sample.bin",
        tmp_path / "signing.key",
        tmp_path / "signature.sig",
        tmp_path / "audit.jsonl",
        tmp_path / "build" / "artifact.txt",
    ]
    for path in ignored:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")

    manifest = build_manifest(tmp_path, tmp_path / "manifest.json")
    listed = {item["path"] for item in manifest["files"]}
    assert "one.txt" in listed
    assert not any("__pycache__" in item or item.endswith(".pyc") for item in listed)
    assert not any(item.startswith("quarantine_store") for item in listed)
    assert not any(item.endswith((".key", ".jsonl")) for item in listed)
    # Signatures of data unrelated to the manifest are still recorded.
    assert "signature.sig" in listed
    assert not any(item.startswith("build/") for item in listed)


def _signed_bundle(root: Path) -> tuple[Path, Path, bytes]:
    """Generates a key pair and signs a test signature package."""
    pytest.importorskip("cryptography")
    private = root / "private.key"
    public = root / "public.pem"
    crypto.generate_keypair(private, public)
    bundle = root / "signatures.json"
    payload = b'{"schema": 1, "revision": 1}'
    bundle.write_bytes(payload)
    signature = crypto.sign_payload(payload, private)
    Path(f"{bundle}.sig").write_bytes(signature)
    return bundle, public, signature


def test_verify_signatures_bundle_valid_and_corrupt(tmp_path: Path) -> None:
    """A valid signature passes; a corrupt signature is rejected."""
    bundle, public, signature = _signed_bundle(tmp_path)
    assert verify_signatures_bundle(bundle, public) is True

    tampered = bytearray(signature)
    tampered[0] ^= 0x01
    Path(f"{bundle}.sig").write_bytes(bytes(tampered))
    assert verify_signatures_bundle(bundle, public) is False


def test_verify_signatures_bundle_missing_files(tmp_path: Path) -> None:
    """Without a signature, package, or key, ``False`` is returned."""
    bundle, public, _ = _signed_bundle(tmp_path)
    assert verify_signatures_bundle(bundle, tmp_path / "nonexistent.pem") is False
    assert verify_signatures_bundle(tmp_path / "nonexistent.json", public) is False

    Path(f"{bundle}.sig").unlink()
    assert verify_signatures_bundle(bundle, public) is False
