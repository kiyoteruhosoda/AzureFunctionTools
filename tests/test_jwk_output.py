"""`format=jwk` と `analyze_keystore?jwk=true` の検証。

外部コマンド（openssl / keytool）を使わずに OIDC 用の鍵を受け取れることを、
「返ってきた JWK と秘密鍵が実際に対になっているか」まで確かめる。

    pytest tests/
"""

import base64
import hashlib
import json

import azure.functions as func
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from blueprints.generate_keystore import analyze_keystore, generate_keystore

PASSWORD = "TestPass123"


def _get(params: dict) -> func.HttpResponse:
    return generate_keystore(
        func.HttpRequest(method="GET", url="/api/generate_keystore", params=params, body=b"")
    )


def _post(body: bytes, params: dict) -> func.HttpResponse:
    return analyze_keystore(
        func.HttpRequest(method="POST", url="/api/analyze_keystore", params=params, body=body)
    )


def _json(resp: func.HttpResponse) -> dict:
    assert resp.status_code == 200, resp.get_body()
    return json.loads(resp.get_body())


def _b64u_int(value: str) -> int:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return int.from_bytes(raw, "big")


def _thumbprint(jwk: dict) -> str:
    canonical = (
        {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
        if jwk["kty"] == "RSA"
        else {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    )
    digest = hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode())
    return base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode()


def _assert_pair(private_pem: str, jwk: dict, password: str | None = None):
    """PEM の秘密鍵で署名し、JWK 由来の公開鍵で検証できることを確かめる。"""
    key = serialization.load_pem_private_key(
        private_pem.encode(), password=password.encode() if password else None
    )
    message = b"idp client assertion"
    if jwk["kty"] == "RSA":
        assert isinstance(key, rsa.RSAPrivateKey)
        numbers = key.public_key().public_numbers()
        assert numbers.n == _b64u_int(jwk["n"])
        assert numbers.e == _b64u_int(jwk["e"])
        signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        rsa.RSAPublicNumbers(_b64u_int(jwk["e"]), _b64u_int(jwk["n"])).public_key().verify(
            signature, message, padding.PKCS1v15(), hashes.SHA256()
        )
    else:
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
        ec.EllipticCurvePublicNumbers(
            _b64u_int(jwk["x"]), _b64u_int(jwk["y"]), ec.SECP256R1()
        ).public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))


# ──────────────────────────────────────────────
# format=jwk
# ──────────────────────────────────────────────

def test_rsa_jwk_contains_a_usable_key_pair():
    body = _json(_get({"format": "jwk", "alias": "idp-client"}))

    assert body["format"] == "jwk"
    assert body["alg"] == "RS256"
    jwk = body["jwks"]["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert "d" not in jwk and "p" not in jwk      # 公開鍵側に秘密成分を混ぜない
    assert body["private_key_encrypted"] is False

    _assert_pair(body["private_key_pem"], jwk)
    assert body["private_key_jwk"]["kid"] == jwk["kid"]
    assert body["private_key_jwk"]["d"]           # 署名側は秘密成分を持つ


def test_kid_defaults_to_the_rfc7638_thumbprint_and_can_be_overridden():
    jwk = _json(_get({"format": "jwk"}))["jwks"]["keys"][0]
    assert jwk["kid"] == _thumbprint(jwk)

    named = _json(_get({"format": "jwk", "kid": "idpstub-machine-1"}))
    assert named["kid"] == "idpstub-machine-1"
    assert named["jwks"]["keys"][0]["kid"] == "idpstub-machine-1"
    assert named["private_key_jwk"]["kid"] == "idpstub-machine-1"


def test_password_is_optional_for_jwk_and_encrypts_the_pem_when_given():
    plain = _json(_get({"format": "jwk"}))
    assert "ENCRYPTED" not in plain["private_key_pem"]

    encrypted = _json(_get({"format": "jwk", "password": PASSWORD}))
    assert encrypted["private_key_encrypted"] is True
    assert "ENCRYPTED PRIVATE KEY" in encrypted["private_key_pem"]
    _assert_pair(encrypted["private_key_pem"], encrypted["jwks"]["keys"][0], PASSWORD)


def test_private_false_returns_only_the_public_key():
    body = _json(_get({"format": "jwk", "private": "false"}))
    assert "private_key_pem" not in body
    assert "private_key_jwk" not in body
    assert body["jwks"]["keys"][0]["n"]


def test_ec_p256_produces_an_es256_key():
    body = _json(_get({"format": "jwk", "kty": "EC", "crv": "P-256"}))
    jwk = body["jwks"]["keys"][0]
    assert (jwk["kty"], jwk["crv"], jwk["alg"]) == ("EC", "P-256", "ES256")
    # 座標は曲線サイズ固定長（左 0 埋め）でなければならない
    assert len(base64.urlsafe_b64decode(jwk["x"] + "==")) == 32
    _assert_pair(body["private_key_pem"], jwk)


def test_rsa_key_size_is_configurable():
    jwk = _json(_get({"format": "jwk", "key_size": "3072"}))["jwks"]["keys"][0]
    assert _b64u_int(jwk["n"]).bit_length() == 3072


# ──────────────────────────────────────────────
# 既存の形式を壊していないこと
# ──────────────────────────────────────────────

def test_keystore_output_still_requires_a_password():
    resp = _get({"format": "p12"})
    assert resp.status_code == 400

    assert _get({"format": "jwk"}).status_code == 200   # JWK は入れ物が無いので不要


def test_ec_is_rejected_for_keystore_formats():
    resp = _get({"format": "p12", "password": PASSWORD, "kty": "EC"})
    assert resp.status_code == 400


def test_fingerprint_json_now_carries_the_jwks_of_the_generated_key():
    body = _json(_get({"format": "p12", "password": PASSWORD, "fingerprint": "true"}))
    assert body["keystore_base64"]
    jwk = body["jwks"]["keys"][0]

    key, cert, _ = pkcs12.load_key_and_certificates(
        base64.b64decode(body["keystore_base64"]), PASSWORD.encode()
    )
    numbers = cert.public_key().public_numbers()
    assert numbers.n == _b64u_int(jwk["n"])       # keystore の中身と一致している
    assert body["kid"] == jwk["kid"] == _thumbprint(jwk)


def test_binary_download_is_unchanged():
    resp = _get({"format": "p12", "password": PASSWORD})
    assert resp.status_code == 200
    assert resp.mimetype == "application/octet-stream"
    pkcs12.load_key_and_certificates(resp.get_body(), PASSWORD.encode())


# ──────────────────────────────────────────────
# analyze_keystore?jwk=true（既存の keystore を JWKS へ変換）
# ──────────────────────────────────────────────

@pytest.mark.parametrize("fmt", ["p12", "jks"])
def test_analyze_converts_an_existing_keystore_into_a_jwks(fmt):
    generated = _json(_get({"format": fmt, "password": PASSWORD, "fingerprint": "true"}))
    keystore = base64.b64decode(generated["keystore_base64"])

    body = _json(_post(keystore, {"password": PASSWORD, "format": fmt, "jwk": "true",
                                  "private": "true"}))
    jwk = body["jwks"]["keys"][0]
    assert jwk["kid"] == generated["jwks"]["keys"][0]["kid"]      # 生成時と同じ鍵
    assert body["certificates"][0]["fingerprint_sha256"]
    _assert_pair(body["private_keys"][0]["pem"], jwk)


def test_analyze_without_jwk_flag_is_unchanged():
    generated = _json(_get({"format": "p12", "password": PASSWORD, "fingerprint": "true"}))
    body = _json(_post(base64.b64decode(generated["keystore_base64"]),
                       {"password": PASSWORD, "format": "p12"}))
    assert "jwks" not in body
    assert body["certificates"][0]["subject"]


def test_analyze_accepts_both_binary_and_base64_bodies():
    generated = _json(_get({"format": "p12", "password": PASSWORD, "fingerprint": "true"}))
    keystore = base64.b64decode(generated["keystore_base64"])
    params = {"password": PASSWORD, "format": "p12", "jwk": "true"}

    from_binary = _json(_post(keystore, params))
    from_base64 = _json(_post(generated["keystore_base64"].encode(), params))
    assert from_binary["jwks"] == from_base64["jwks"]
