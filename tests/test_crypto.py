import pytest

from sentinel import crypto

pytest.importorskip("cryptography")


def test_keypair_sign_and_verify(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    crypto.generate_keypair(private, public)

    signature = crypto.sign_payload(b"test payload", private)
    assert len(signature) == 64
    assert crypto.verify_payload(b"test payload", signature, public)
    assert not crypto.verify_payload(b"modified payload", signature, public)

    tampered = bytearray(signature)
    tampered[0] ^= 0x01
    assert not crypto.verify_payload(b"test payload", bytes(tampered), public)


def test_wrong_key_fails(tmp_path):
    priv_a, pub_a = tmp_path / "a.key", tmp_path / "a.pub"
    priv_b, pub_b = tmp_path / "b.key", tmp_path / "b.pub"
    crypto.generate_keypair(priv_a, pub_a)
    crypto.generate_keypair(priv_b, pub_b)

    signature = crypto.sign_payload(b"test data", priv_a)
    assert not crypto.verify_payload(b"test data", signature, pub_b)


def test_missing_public_key_raises(tmp_path):
    private = tmp_path / "key.pem"
    crypto.generate_keypair(private, tmp_path / "pub.pem")
    signature = crypto.sign_payload(b"test data", private)
    with pytest.raises(OSError):
        crypto.verify_payload(b"test data", signature, tmp_path / "nonexistent.pem")
