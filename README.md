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

### URL 例

#### ① Android Studio 等で使う JKS ファイルをダウンロード

```text
/generate_keystore?code=<KEY>&alias=upload_key&password=MyPass123&format=jks
```

#### ② GitHub Secrets 登録用に Base64 文字列を表示

```text
/generate_keystore?code=<KEY>&alias=flutterbase&password=MyPass123&format=p12_base64
```


## healthz

### エンドポイント
`GET /healthz`

### レスポンス例

```json
{
  "status": "ok",
  "timestamp": "2026-03-18T00:00:00+00:00",
  "version": {
    "git_version": "v1.2.3-4-gabcdef0",
    "commit_sha": "abcdef0123456789",
    "branch": "main",
    "source": "github_actions",
    "build_number": "123",
    "workflow_run_id": "9999999999",
    "workflow_name": "deploy"
  }
}
```

### バージョン解決ルール
1. GitHub Actions 実行時は `GITHUB_*` を優先して表示
2. Azure Pipelines 実行時は `BUILD_*` を優先して表示
3. 上記が無い場合はローカル Git 情報を表示
