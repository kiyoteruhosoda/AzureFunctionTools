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
| `format` | `p12` | 出力形式 (`p12`, `jks`, `p12_base64`, `jks_base64`) |
| `fingerprint` | `false ` | 生成エンドポイント → fingerprint=true を付けるとバイナリの代わりにJSONで返す（Base64keystoreとSHA-256フィンガープリントをセット） |

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


## Analyze keystore

### エンドポイント
`POST /analyze_keystore `
p12/jksをアップロードするとフィンガープリント等を返す


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
