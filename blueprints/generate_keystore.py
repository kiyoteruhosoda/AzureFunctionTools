import azure.functions as func
import logging
import datetime
import base64
import binascii
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import hashlib
import jks
import json

bp = func.Blueprint()

# JWK で扱える EC 曲線（`crv` 値と既定の署名アルゴリズム）。
_EC_CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
_EC_ALGS = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}
_EC_BY_CRV = {
    "P-256": ec.SECP256R1,
    "P-384": ec.SECP384R1,
    "P-521": ec.SECP521R1,
}

# ──────────────────────────────────────────────
# ユーティリティ
# ──────────────────────────────────────────────

def _sha256_fingerprint(cert: x509.Certificate) -> str:
    """証明書の SHA-256 フィンガープリントを "XX:XX:..." 形式で返す"""
    raw = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in raw)


def _cert_info(cert: x509.Certificate) -> dict:
    """証明書の基本情報をまとめて返す"""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "fingerprint_sha256": _sha256_fingerprint(cert),
    }


# ──────────────────────────────────────────────
# JWK / JWKS ユーティリティ（RFC 7517 / 7518 / 7638）
#
# OIDC / OAuth 2.0 のクライアント（`private_key_jwt` など）は、鍵を keystore ではなく
# **JWK Set** で受け取る。p12 / jks は「鍵ペアと証明書の入れ物」なので、そのままでは
# 登録できず、利用側で openssl や keytool を通す必要があった。ここで JWK を直接返せるように
# しておくと、利用側は外部コマンドなしで鍵を扱える。
# ──────────────────────────────────────────────

def _b64u(data: bytes) -> str:
    """base64url（パディング無し）。JWK の数値表現に使う。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64u_uint(value: int, length: int | None = None) -> str:
    """非負整数を base64url へ。`length` 指定時は左 0 埋めで固定長にする（EC の座標用）。"""
    size = length if length is not None else max(1, (value.bit_length() + 7) // 8)
    return _b64u(value.to_bytes(size, "big"))


def _jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 の JWK Thumbprint（SHA-256）。kid 未指定時の既定値に使う。"""
    if jwk["kty"] == "RSA":
        canonical = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    payload = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return _b64u(hashlib.sha256(payload).digest())


def _public_jwk(public_key, kid: str | None = None) -> dict:
    """公開鍵から JWK を作る（RSA / EC P-256）。`use` と `alg` も補う。"""
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        jwk = {"kty": "RSA", "n": _b64u_uint(numbers.n), "e": _b64u_uint(numbers.e)}
        alg = "RS256"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        numbers = public_key.public_numbers()
        size = (public_key.curve.key_size + 7) // 8
        jwk = {
            "kty": "EC",
            "crv": _EC_CURVES[public_key.curve.name],
            "x": _b64u_uint(numbers.x, size),
            "y": _b64u_uint(numbers.y, size),
        }
        alg = _EC_ALGS[public_key.curve.name]
    else:
        raise ValueError("unsupported key type for JWK")

    jwk["kid"] = kid or _jwk_thumbprint(jwk)
    jwk["use"] = "sig"
    jwk["alg"] = alg
    return jwk


def _private_jwk(private_key, kid: str | None = None) -> dict:
    """秘密鍵成分まで含む JWK。署名に使う側（クライアント）が読む。"""
    jwk = dict(_public_jwk(private_key.public_key(), kid))
    if isinstance(private_key, rsa.RSAPrivateKey):
        numbers = private_key.private_numbers()
        jwk.update({
            "d": _b64u_uint(numbers.d),
            "p": _b64u_uint(numbers.p),
            "q": _b64u_uint(numbers.q),
            "dp": _b64u_uint(numbers.dmp1),
            "dq": _b64u_uint(numbers.dmq1),
            "qi": _b64u_uint(numbers.iqmp),
        })
    else:
        size = (private_key.curve.key_size + 7) // 8
        jwk["d"] = _b64u_uint(private_key.private_numbers().private_value, size)
    return jwk


def _private_pem(private_key, password: str | None) -> str:
    """PKCS#8 の PEM。`password` があれば暗号化する（無ければ平文 PKCS#8）。"""
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password
        else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode()

def _decode_keystore_body(raw: bytes) -> bytes:
    """POST された keystore を取り出す（バイナリ直送・Base64 テキストのどちらでも）。

    `base64.b64decode` は既定（`validate=False`）だと **base64 の文字集合に無い
    バイトを黙って捨てる**。バイナリの p12 / jks をそのまま渡すと、例外にならずに
    壊れたデータが返ることがある（`--data-binary @myapp.p12` が時々失敗していた原因）。
    先に形式を見分け、Base64 として読むときも `validate=True` で確かめる。
    """
    if raw[:1] == b"\x30" or raw[:4] == b"\xfe\xed\xfe\xed":
        # DER SEQUENCE（PKCS#12）または JKS のマジックナンバー = バイナリ直送
        return raw
    try:
        return base64.b64decode(b"".join(raw.split()), validate=True)
    except (binascii.Error, ValueError):
        return raw

# ──────────────────────────────────────────────
# 生成エンドポイント
# ──────────────────────────────────────────────

@bp.route(route="generate_keystore", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def generate_keystore(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Keystore generation requested.')

    alias      = req.params.get('alias', 'flutterbase')
    password   = req.params.get('password')
    cn         = req.params.get('cn', 'Unknown')
    out_format = req.params.get('format', 'p12').lower()
    # fingerprint=true のとき JSON レスポンスに切り替え
    want_fp    = req.params.get('fingerprint', 'false').lower() == 'true'
    # format=jwk / jwks: keystore を作らず JWK Set をそのまま返す（OIDC クライアント向け）
    want_jwk   = out_format in ('jwk', 'jwks')
    kid        = req.params.get('kid') or None
    kty        = req.params.get('kty', 'RSA').upper()
    crv        = req.params.get('crv', 'P-256')
    with_private = req.params.get('private', 'true').lower() != 'false'

    try:
        key_size = int(req.params.get('key_size', '2048'))
    except ValueError:
        return func.HttpResponse("Error: 'key_size' must be an integer.", status_code=400)

    # keystore を作る形式ではパスワードが要る。JWK は入れ物が無いので任意
    # （渡された場合は PEM を暗号化する）。
    if not password and not want_jwk:
        return func.HttpResponse("Error: 'password' parameter is required.", status_code=400)

    if kty not in ('RSA', 'EC'):
        return func.HttpResponse("Error: 'kty' must be RSA or EC.", status_code=400)
    if kty == 'EC':
        # p12 / jks の既存利用（Android 署名）は RSA 前提なので、EC は JWK 出力に限る。
        if not want_jwk:
            return func.HttpResponse(
                "Error: EC keys are available only with format=jwk.", status_code=400)
        if crv not in _EC_BY_CRV:
            return func.HttpResponse(
                f"Error: 'crv' must be one of {', '.join(_EC_BY_CRV)}.", status_code=400)

    # 1. 鍵・証明書の生成
    if kty == 'EC':
        private_key = ec.generate_private_key(_EC_BY_CRV[crv]())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"JP"),
    ])
    now  = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=36135))
        .sign(private_key, hashes.SHA256())
    )

    # 2. format=jwk / jwks: keystore を経由せず JWK Set を返す
    if want_jwk:
        public_jwk = _public_jwk(private_key.public_key(), kid)
        payload = {
            "format": "jwk",
            "alias": alias,
            "kid": public_jwk["kid"],
            "alg": public_jwk["alg"],
            # 認可サーバ / RP へ登録する側（公開鍵のみ）
            "jwks": {"keys": [public_jwk]},
            "certificate": _cert_info(cert),
        }
        if with_private:
            # 署名する側。JWK と PEM(PKCS#8) の両方を入れておく（利用側の実装に合わせて選べる）
            payload["private_key_jwk"] = _private_jwk(private_key, public_jwk["kid"])
            payload["private_key_pem"] = _private_pem(private_key, password)
            payload["private_key_encrypted"] = bool(password)
        return func.HttpResponse(
            body=json.dumps(payload, ensure_ascii=False),
            mimetype="application/json",
        )

    # 3. キーストアデータ生成
    p12_data = pkcs12.serialize_key_and_certificates(
        name=alias.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    if "jks" in out_format:
        key_der  = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        new_jks  = jks.KeyStore.new('jks', [
            jks.PrivateKeyEntry.new(alias, [cert_der], key_der, 'pkcs8')
        ])
        final_data = new_jks.saves(password)
        file_ext   = "jks"
    else:
        final_data = p12_data
        file_ext   = "p12"

    # 4. fingerprint=true → JSON で返す（Base64 keystore + 証明書情報 + JWKS）
    if want_fp:
        public_jwk = _public_jwk(private_key.public_key(), kid)
        payload = {
            "format": file_ext,
            "alias": alias,
            "keystore_base64": base64.b64encode(final_data).decode(),
            "certificate": _cert_info(cert),
            # keystore を openssl / keytool で開かなくても公開鍵を登録できるように併記する
            "kid": public_jwk["kid"],
            "jwks": {"keys": [public_jwk]},
        }
        return func.HttpResponse(
            body=json.dumps(payload, ensure_ascii=False),
            mimetype="application/json",
        )

    # 5. 通常: Base64 文字列
    if "base64" in out_format:
        return func.HttpResponse(
            body=base64.b64encode(final_data),
            mimetype="text/plain",
        )

    # 6. 通常: バイナリダウンロード
    return func.HttpResponse(
        body=final_data,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={alias}.{file_ext}"}
    )


# ──────────────────────────────────────────────
# 解析エンドポイント
# ──────────────────────────────────────────────

@bp.route(route="analyze_keystore", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def analyze_keystore(req: func.HttpRequest) -> func.HttpResponse:
    """
    既存の p12 / jks ファイルを解析してフィンガープリント等を返す。

    Query params:
      password  (必須)
      format    p12 (default) | jks
      jwk       true にすると公開鍵を JWK Set としても返す（既存の keystore を
                openssl / keytool 無しで OIDC 用の JWKS へ変換する用途）
      private   jwk=true のとき true にすると秘密鍵（JWK / PKCS#8 PEM）も返す
      kid       JWK の kid。省略時は RFC 7638 の thumbprint
    Body:
      キーストアのバイナリ、または Base64 エンコードされたテキスト
    """
    logging.info('Keystore analysis requested.')

    password   = req.params.get('password')
    in_format  = req.params.get('format', 'p12').lower()
    want_jwk   = req.params.get('jwk', 'false').lower() == 'true'
    with_private = req.params.get('private', 'false').lower() == 'true'
    kid        = req.params.get('kid') or None

    if not password:
        return func.HttpResponse("Error: 'password' parameter is required.", status_code=400)

    raw_body = req.get_body()
    if not raw_body:
        return func.HttpResponse("Error: Request body is empty.", status_code=400)

    keystore_bytes = _decode_keystore_body(raw_body)

    try:
        results = []
        jwk_keys = []
        private_keys = []

        if "jks" in in_format:
            # JKS 解析
            ks = jks.KeyStore.loads(keystore_bytes, password)
            for alias, entry in ks.private_keys.items():
                entry.decrypt(password)
                # 先頭の証明書を使用
                cert_der  = entry.cert_chain[0][1]
                cert_obj  = x509.load_der_x509_certificate(cert_der)
                results.append({"alias": alias, **_cert_info(cert_obj)})
                if want_jwk:
                    jwk_keys.append(_public_jwk(cert_obj.public_key(), kid))
                    if with_private:
                        private_keys.append(
                            serialization.load_der_private_key(entry.pkey_pkcs8, password=None)
                        )
        else:
            # P12 解析
            priv_key, cert_obj, additional_certs = pkcs12.load_key_and_certificates(
                keystore_bytes, password.encode()
            )
            results.append({"alias": "(p12 default)", **_cert_info(cert_obj)})
            for i, extra in enumerate(additional_certs or []):
                results.append({"alias": f"(ca-{i})", **_cert_info(extra)})
            if want_jwk:
                jwk_keys.append(_public_jwk(cert_obj.public_key(), kid))
                if with_private and priv_key is not None:
                    private_keys.append(priv_key)

        payload = {"format": in_format, "certificates": results}
        if want_jwk:
            # 認可サーバへ登録する側（公開鍵のみ）
            payload["jwks"] = {"keys": jwk_keys}
            if with_private:
                payload["private_keys"] = [
                    {
                        "jwk": _private_jwk(key, jwk_keys[i]["kid"] if i < len(jwk_keys) else kid),
                        "pem": _private_pem(key, None),
                    }
                    for i, key in enumerate(private_keys)
                ]
        return func.HttpResponse(
            body=json.dumps(payload, ensure_ascii=False, indent=2),
            mimetype="application/json",
        )

    except Exception as e:
        logging.exception("Failed to analyze keystore")
        return func.HttpResponse(
            f"Error: Failed to parse keystore. {e}",
            status_code=400
        )
