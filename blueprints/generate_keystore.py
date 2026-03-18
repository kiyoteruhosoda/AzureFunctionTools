import azure.functions as func
import logging
import datetime
import base64
import io
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import jks

bp = func.Blueprint()

@bp.route(route="generate_keystore", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def generate_keystore(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Keystore generation requested.')

    # パラメータ取得
    alias = req.params.get('alias', 'flutterbase')
    password = req.params.get('password')
    cn = req.params.get('cn', 'Unknown')
    # format: p12 (default), jks, p12_base64, jks_base64
    out_format = req.params.get('format', 'p12').lower()

    if not password:
        return func.HttpResponse("Error: 'password' parameter is required.", status_code=400)

    # 1. 鍵と証明書の生成 (RSA 2048bit)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Personal"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"JP"),
    ])

    # 有効期限を99年 (36135日) に設定
    now  = datetime.datetime.now(datetime.timezone.utc)    
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(
        now + datetime.timedelta(days=36135)
    ).sign(private_key, hashes.SHA256())

    # 2. データの生成
    final_data = b""
    mimetype = "application/octet-stream"
    file_ext = out_format.split('_')[0]

    # P12形式の作成
    p12_data = pkcs12.serialize_key_and_certificates(
        name=alias.encode(),
        key=private_key,
        cert=cert,
        cas=None,  # 'other_certs' ではなく 'cas' を使用
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    if "jks" in out_format:
        # P12からJKSへ変換
        # pyjksを使用してJKS構造を作成
        key_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        
        new_jks = jks.KeyStore.new('jks', [
            jks.PrivateKeyEntry.new(alias, [cert_der], key_der, 'pkcs8')
        ])
        
        final_data = new_jks.saves(password)
    else:
        final_data = p12_data

    # 3. Base64オプションの処理
    if "base64" in out_format:
        final_data = base64.b64encode(final_data)
        mimetype = "text/plain"
        return func.HttpResponse(body=final_data, mimetype=mimetype)

    # バイナリをファイルとして返す
    return func.HttpResponse(
        body=final_data,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={alias}.{file_ext}"}
    )