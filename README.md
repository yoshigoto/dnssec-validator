# DNSSEC委任状態検証ツール

ドメイン名の DNSSEC 委任状態を検証する Web アプリケーションです。親ゾーンの DS レコードと、子ゾーンの DNSKEY / RRSIG を取得して照合し、DNSSEC の信頼の連鎖を確認します。

## 公開 URL

<https://www.on-link.jp/dnssecvalidator/>

## 主な機能

- ルート DNS サーバーから対象ドメインのゾーン頂点と権威 DNS サーバーを探索
- 親ゾーンから DS レコードを取得
- 子ゾーンから DNSKEY と DNSKEY に対する RRSIG を取得
- DS と KSK のダイジェストを照合
- DS、DNSKEY、A レコードに対する RRSIG を検証
- 対象ドメインがゾーン頂点でない場合、A レコードの DNSSEC 検証も実行
- A レコードが存在しない場合、NSEC / NSEC3 による不在証明を確認
- 検証結果を親ゾーンと子ゾーンの関係図として表示

## 使い方

1. 公開 URL を開きます。
2. 検証したいドメイン名を入力します（例: `example.com`）。URL を入力した場合はホスト名を取り出して検証します。
3. **検証スタート**を押します。
4. 成功または失敗の結果と、DS、DNSKEY、RRSIG の検証状況を確認します。

入力したドメイン名はブラウザーの `localStorage` に保存され、次回表示時に再利用されます。URL の `domain` クエリーパラメーターから初期値を指定することもできます。

例:

```text
https://www.on-link.jp/dnssecvalidator/?domain=example.com
```

## ローカルでの起動

### 必要環境

- Node.js
- 外部の権威 DNS サーバーへ UDP/TCP 53 番ポートで接続できるネットワーク

### 手順

```bash
npm install
node dnssec-validator.js
```

起動後、次の URL を開きます。

<http://localhost:3002/>

このアプリは `3002` 番ポートで待ち受けます。ポート番号を変更する場合は、`dnssec-validator.js` の `PORT` 定数を変更してください。

## API

画面からの検証処理は、次のエンドポイントを使用します。

### `POST /api/validate`

リクエスト:

```http
Content-Type: application/json
```

```json
{
  "domain": "example.com"
}
```

成功時のレスポンスには、次の情報が含まれます。

```json
{
  "success": true,
  "logs": [],
  "diagram": {
    "parent": {},
    "child": {},
    "checks": {}
  }
}
```

`success` は親ゾーンの DS と子ゾーンの DNSKEY が一致した場合に `true` になります。詳細な検証結果やエラーは `logs` と `diagram` に格納されます。

入力不備の場合は `400`、レート制限超過時は `429`、サーバー内部エラー時は `500` を返します。

## 検証方式

アプリケーションは OS のフルサービスリゾルバーに依存せず、ルートサーバー（`198.41.0.4`）から委任を辿って DNS レコードを取得します。UDP 応答が切り詰められている場合は TCP に切り替えます。

署名検証では、次の DNSSEC アルゴリズムに対応しています。

- RSA: RSASHA1、RSASHA1-NSEC3-SHA1、RSASHA256、RSASHA512
- ECDSA: ECDSAP256SHA256、ECDSAP384SHA384
- EdDSA: ED25519、ED448

委任情報とネームサーバーの IP アドレスは、TTL を使ったプロセス内キャッシュに保存されます。API には、1 クライアント IP あたり 1 分 30 回のレート制限があります。

## ファイル構成

| ファイル | 役割 |
| --- | --- |
| `dnssec-validator.js` | Express サーバー、DNS 探索、DNSSEC レコード取得・署名検証、API 実装 |
| `dnssec-validator-client.js` | 入力処理、API 呼び出し、検証結果の表示 |
| `index.html` | Web UI と検証結果の関係図の HTML / CSS |
| `package.json` | Node.js の依存パッケージ定義 |
| `package-lock.json` | 依存パッケージの固定バージョン |

## 依存パッケージ

- [Express](https://expressjs.com/): Web サーバーと API
- [dns-packet](https://github.com/mafintosh/dns-packet): DNS パケットのエンコード / デコード

## 注意事項

- DNS の応答は権威サーバーやネットワークの状態に左右されるため、タイムアウトや一時的な検証失敗が発生する場合があります。
- CNAME / DNAME を含む入力は、ゾーン頂点を特定できないため検証できない場合があります。
- 検証結果はその時点で取得した DNS 応答に基づく診断結果です。DNSSEC の設定変更後はキャッシュや TTL の影響に注意してください。
- 本番環境で公開する場合は、HTTPS、プロセス監視、ログ管理、必要に応じたリバースプロキシなどを別途構成してください。