import io
import json

import pytest

from sentinel import crypto, updates
from sentinel.engine.signatures import SignatureDatabase
from sentinel.updates import update_signatures

pytest.importorskip("cryptography")


def payload_for(revision: int) -> bytes:
    return json.dumps(
        {
            "schema": 1,
            "version": "2026-11-21",
            "revision": revision,
            "hashes": {},
            "filenames": [],
            "content": [],
        }
    ).encode("utf-8")


def signed_bundle(tmp_path, revision: int, private, name: str):
    document = tmp_path / f"{name}.json"
    signature = tmp_path / f"{name}.json.sig"
    payload = payload_for(revision)
    document.write_bytes(payload)
    signature.write_bytes(crypto.sign_payload(payload, private))
    return document, signature


def install_current(target, revision: int) -> None:
    target.write_bytes(payload_for(revision))


def fake_download(monkeypatch, url: str, document, signature) -> None:
    """Serves the package over simulated https, without using file:// schemes."""

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()
            return False

    files = {
        url: document.read_bytes(),
        f"{url}.sig": signature.read_bytes(),
    }

    def fake_urlopen(target, timeout=None):
        return Response(files[target])

    monkeypatch.setattr(updates.urllib.request, "urlopen", fake_urlopen)


def test_signed_update_succeeds(tmp_path, monkeypatch):
    private = tmp_path / "key.pem"
    public = tmp_path / "key.pub"
    crypto.generate_keypair(private, public)
    document, signature = signed_bundle(tmp_path, 2, private, "new")
    target = tmp_path / "signatures.json"
    install_current(target, 1)
    url = "https://signatures.local/signatures.json"
    fake_download(monkeypatch, url, document, signature)

    info = update_signatures(url, target, public)

    assert info["revision"] == 2
    assert SignatureDatabase.load(target).revision == 2
    assert (target.with_suffix(".json.bak")).is_file()


def test_tampered_bundle_is_rejected(tmp_path, monkeypatch):
    private = tmp_path / "key.pem"
    public = tmp_path / "key.pub"
    crypto.generate_keypair(private, public)
    document, signature = signed_bundle(tmp_path, 2, private, "new")
    target = tmp_path / "signatures.json"
    install_current(target, 1)
    original = target.read_bytes()

    bad_signature = bytearray(signature.read_bytes())
    bad_signature[0] ^= 0x01
    signature.write_bytes(bytes(bad_signature))

    url = "https://signatures.local/signatures.json"
    fake_download(monkeypatch, url, document, signature)

    with pytest.raises(ValueError, match="Invalid Ed25519 signature"):
        update_signatures(url, target, public)
    assert target.read_bytes() == original


def test_rollback_is_rejected(tmp_path, monkeypatch):
    private = tmp_path / "key.pem"
    public = tmp_path / "key.pub"
    crypto.generate_keypair(private, public)
    document, signature = signed_bundle(tmp_path, 1, private, "old")
    target = tmp_path / "signatures.json"
    install_current(target, 5)
    original = target.read_bytes()
    url = "https://signatures.local/signatures.json"
    fake_download(monkeypatch, url, document, signature)

    with pytest.raises(ValueError, match="Rollback"):
        update_signatures(url, target, public)
    assert target.read_bytes() == original


def test_missing_public_key_is_rejected(tmp_path, monkeypatch):
    private = tmp_path / "key.pem"
    public = tmp_path / "key.pub"
    crypto.generate_keypair(private, public)
    document, signature = signed_bundle(tmp_path, 2, private, "new")
    target = tmp_path / "signatures.json"
    url = "https://signatures.local/signatures.json"
    fake_download(monkeypatch, url, document, signature)

    with pytest.raises(FileNotFoundError):
        update_signatures(url, target, tmp_path / "missing.pub")
    assert not target.exists()


@pytest.mark.parametrize("url", ["file:///C:/tmp/signatures.json", "ftp://signatures.local/x", "https:///no-host"])
def test_non_http_url_is_rejected(tmp_path, url):
    private = tmp_path / "key.pem"
    public = tmp_path / "key.pub"
    crypto.generate_keypair(private, public)
    target = tmp_path / "signatures.json"

    with pytest.raises(ValueError, match="URL not allowed"):
        update_signatures(url, target, public)
    assert not target.exists()
