# AzureFunctionTools


## generateKey: Android App Signing Generator API

### エンドポイント
`GET /generate_keystore`

### クエリパラメータ

| パラメータ | デフォルト値 | 説明 |
| :--- | :--- | :--- |
| `code` | (必須) | Azure Function Key |
| `password` | (必須) | キーストアおよび秘密鍵の共通パスワード |
| `alias` | `flutterbase` | 鍵の別名（エイリアス） |
| `cn` | `Unknown` | 証明書の Common Name (発行者名) |
| `format` | `p12` | 出力形式 (`p12`, `jks`, `p12_base64`, `jks_base64`, **`jwk`**) |
| `fingerprint` | `false ` | 生成エンドポイント → fingerprint=true を付けるとバイナリの代わりにJSONで返す（Base64keystore・SHA-256フィンガープリント・**JWKS** をセット） |
| `kid` | (thumbprint) | JWK の `kid`。省略時は RFC 7638 の JWK Thumbprint |
| `kty` | `RSA` | 鍵種別 (`RSA`, `EC`)。`EC` は `format=jwk` のときだけ指定できる |
| `crv` | `P-256` | `kty=EC` のときの曲線 (`P-256`, `P-384`, `P-521`) |
| `key_size` | `2048` | RSA の鍵長 |
| `private` | `true` | `format=jwk` で `false` にすると公開鍵（JWKS）だけを返す |

`password` は keystore を作る形式（`p12` / `jks`）でのみ必須です。`format=jwk` は入れ物が無いので
省略でき、渡した場合は返す PEM を暗号化します（PKCS#8）。

### URL 例

#### ① Android Studio 等で使う JKS ファイルをダウンロード

```text
/generate_keystore?code=<KEY>&alias=upload_key&password=MyPass123&format=jks
```

#### ② GitHub Secrets 登録用に Base64 文字列を表示

```text
/generate_keystore?code=<KEY>&alias=flutterbase&password=MyPass123&format=p12_base64
```

生成 + フィンガープリント同時取得
```
GET /api/generate_keystore?alias=myapp&password=secret&cn=MyApp&fingerprint=true
json{
  "format": "p12",
  "alias": "myapp",
  "keystore_base64": "MIIJkA...",
  "certificate": {
    "subject": "CN=MyApp,C=JP",
    "not_valid_before": "2026-04-24T...",
    "not_valid_after": "2125-...",
    "fingerprint_sha256": "A1:B2:C3:..."
  }
}
```


### ③ OIDC / OAuth 2.0 のクライアント鍵（JWK Set）を作る

`format=jwk` は **keystore を経由せず** JWK Set をそのまま返します。`private_key_jwt`（RFC 7523）や
JWT 署名に使う鍵を、利用側で `openssl` / `keytool` を通さずに受け取るための形式です。

```text
/generate_keystore?code=<KEY>&format=jwk&kid=my-client-1
```

```json
{
  "format": "jwk",
  "alias": "flutterbase",
  "kid": "my-client-1",
  "alg": "RS256",
  "jwks": {
    "keys": [
      {"kty":"RSA","n":"…","e":"AQAB","kid":"my-client-1","use":"sig","alg":"RS256"}
    ]
  },
  "private_key_jwk": {"kty":"RSA","n":"…","e":"AQAB","d":"…","p":"…","q":"…","dp":"…","dq":"…","qi":"…","kid":"my-client-1","use":"sig","alg":"RS256"},
  "private_key_pem": "-----BEGIN PRIVATE KEY-----\n…",
  "private_key_encrypted": false,
  "certificate": { "...": "参考情報。JWK 利用時は使いません" }
}
```

* `jwks` … 認可サーバ（IdP）へ**登録する**側。公開鍵だけで、秘密鍵成分は入りません
* `private_key_jwk` / `private_key_pem` … **署名する**側。同じ鍵を JWK と PKCS#8 PEM の両方で入れて
  あるので、利用側の実装に合わせて選べます（Node なら `crypto.createPrivateKey({key, format:'jwk'})`）
* `kid` は省略時 RFC 7638 の thumbprint。鍵ローテーションで新旧を並べるときは明示指定が楽です
* ES256 が要るときは `kty=EC&crv=P-256`

`fingerprint=true`（`p12` / `jks`）のレスポンスにも同じ `jwks` と `kid` を載せてあるので、
**Android 署名用の keystore と OIDC 用の公開鍵を一度に**受け取れます。

> ⚠ `private_key_*` は秘密鍵そのものです。Function Key で保護されている前提の応答なので、
> ログ・Application Insights に本文を残す設定にしないでください。`private=false` を付ければ
> 公開鍵だけを取得できます。

## Analyze keystore

### エンドポイント
`POST /analyze_keystore `
p12/jksをアップロードするとフィンガープリント等を返す

### クエリパラメータ

| パラメータ | デフォルト値 | 説明 |
| :--- | :--- | :--- |
| `password` | (必須) | キーストアのパスワード |
| `format` | `p12` | `p12` または `jks` |
| `jwk` | `false` | `true` で公開鍵を **JWK Set** としても返す（既存 keystore の JWKS 変換） |
| `private` | `false` | `jwk=true` のとき `true` で秘密鍵（JWK / PKCS#8 PEM）も返す |
| `kid` | (thumbprint) | JWK の `kid` |

既に持っている keystore（Android の署名鍵など）を OIDC 用の JWKS へ変換したいときに使います。

```bash
curl -X POST "https://.../api/analyze_keystore?code=<KEY>&password=secret&format=jks&jwk=true" \
  --data-binary @myapp.jks
```


### URL 例

既存ファイルの解析
```
# バイナリ直接送信
curl -X POST \
  "https://.../api/analyze_keystore?password=secret&format=p12" \
  --data-binary @myapp.p12

# Base64 で送信
curl -X POST \
  "https://.../api/analyze_keystore?password=secret" \
  --data "$(base64 myapp.p12)"
```

## healthz

### エンドポイント
`GET /healthz`

### レスポンス例

```json
{
  "status": "ok",
  "timestamp": "2026-03-19T00:00:00+00:00",
  "version": {
    "git_version": "v1.2.3-4-gabcdef0",
    "commit_sha": "abcdef0123456789",
    "branch": "main",
    "source": "github_actions",
    "build_number": "123",
    "workflow_run_id": "9999999999",
    "workflow_name": "Build and deploy Python project to Azure Function App - AzureFunctionTools"
  }
}
```

### バージョン解決ルール
1. ビルド時に `scripts/generate_version_metadata.py` が `version-metadata.txt` を生成します。
2. 実行時の `healthz` は OS コマンドを実行せず、同梱された `version-metadata.txt` のみを読み取ります。
3. ファイルが存在しない場合は `source=unavailable` として返します。

### `version-metadata.txt` 形式
```text
git_version=v1.2.3-4-gabcdef0
commit_sha=abcdef0123456789
branch=main
source=github_actions
build_number=123
workflow_run_id=9999999999
workflow_name=Build and deploy Python project to Azure Function App - AzureFunctionTools
```


## テスト

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest tests/
```

`tests/test_jwk_output.py` は JWK 出力（RSA / EC・kid・秘密鍵の暗号化・`private=false`）と、
`analyze_keystore` の JWKS 変換、既存形式（バイナリ / Base64 / fingerprint）が壊れていないことを
確認します。**返ってきた JWK と秘密鍵が実際に対になっているか**（署名 → 検証）まで見ています。
CI（`main_azurefunctiontools.yml`）にはまだ組み込んでいません。
