import azure.functions as func
import logging
import datetime
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jks
import json

bp = func.Blueprint()

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

    if not password:
        return func.HttpResponse("Error: 'password' parameter is required.", status_code=400)

    # 1. 鍵・証明書の生成
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

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

    # 2. キーストアデータ生成
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

    # 3. fingerprint=true → JSON で返す（Base64 keystore + 証明書情報）
    if want_fp:
        payload = {
            "format": file_ext,
            "alias": alias,
            "keystore_base64": base64.b64encode(final_data).decode(),
            "certificate": _cert_info(cert),
        }
        return func.HttpResponse(
            body=json.dumps(payload, ensure_ascii=False),
            mimetype="application/json",
        )

    # 4. 通常: Base64 文字列
    if "base64" in out_format:
        return func.HttpResponse(
            body=base64.b64encode(final_data),
            mimetype="text/plain",
        )

    # 5. 通常: バイナリダウンロード
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
    Body:
      キーストアのバイナリ、または Base64 エンコードされたテキスト
    """
    logging.info('Keystore analysis requested.')

    password   = req.params.get('password')
    in_format  = req.params.get('format', 'p12').lower()

    if not password:
        return func.HttpResponse("Error: 'password' parameter is required.", status_code=400)

    raw_body = req.get_body()
    if not raw_body:
        return func.HttpResponse("Error: Request body is empty.", status_code=400)

    # Body が Base64 文字列の場合はデコード
    try:
        keystore_bytes = base64.b64decode(raw_body)
    except Exception:
        keystore_bytes = raw_body

    try:
        results = []

        if "jks" in in_format:
            # JKS 解析
            ks = jks.KeyStore.loads(keystore_bytes, password)
            for alias, entry in ks.private_keys.items():
                entry.decrypt(password)
                # 先頭の証明書を使用
                cert_der  = entry.cert_chain[0][1]
                cert_obj  = x509.load_der_x509_certificate(cert_der)
                results.append({"alias": alias, **_cert_info(cert_obj)})
        else:
            # P12 解析
            priv_key, cert_obj, additional_certs = pkcs12.load_key_and_certificates(
                keystore_bytes, password.encode()
            )
            results.append({"alias": "(p12 default)", **_cert_info(cert_obj)})
            for i, extra in enumerate(additional_certs or []):
                results.append({"alias": f"(ca-{i})", **_cert_info(extra)})

        payload = {"format": in_format, "certificates": results}
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
