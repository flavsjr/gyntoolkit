"""Testes unitários dos utilitários crypto (offline, sem rede)."""
import base64
import hashlib
import json

from gyntoolkit import utils


def test_hash_text_sha256_matches_hashlib():
    assert utils.hash_text("hello") == hashlib.sha256(b"hello").hexdigest()


def test_hash_text_algorithms():
    assert utils.hash_text("abc", "md5") == hashlib.md5(b"abc").hexdigest()
    assert utils.hash_text("abc", "sha1") == hashlib.sha1(b"abc").hexdigest()
    assert utils.hash_text("abc", "sha512") == hashlib.sha512(b"abc").hexdigest()


def test_hash_file_streaming(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"gyntoolkit")
    assert utils.hash_file(str(f)) == hashlib.sha256(b"gyntoolkit").hexdigest()


def test_hash_file_missing(tmp_path):
    assert "não encontrado" in utils.hash_file(str(tmp_path / "nope.txt"))


def test_base64_roundtrip():
    s = "segurança — autorizado"
    assert utils.b64_decode(utils.b64_encode(s)) == s


def test_b64_decode_handles_missing_padding():
    raw = "security"
    encoded = base64.b64encode(raw.encode()).decode().rstrip("=")
    assert utils.b64_decode(encoded) == raw


def test_jwt_decode_valid():
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    token = f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'sub': '123', 'name': 'ph'})}.sig"
    out = utils.jwt_decode(token)
    assert out["header"]["alg"] == "HS256"
    assert out["payload"]["sub"] == "123"
    assert out["signature"] == "sig"


def test_jwt_decode_wrong_parts():
    assert "erro" in utils.jwt_decode("only.two")
