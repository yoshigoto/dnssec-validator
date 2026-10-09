# DNSSEC委任状態検証ツール

ドメイン名の DNSSEC 委任状態を検証する Web アプリケーションです。親ゾーンの DS レコードと、子ゾーンの DNSKEY / RRSIG を取得して照合し、DNSSEC の信頼の連鎖を確認します。

## 公開 URL

<https://www.on-link.jp/dnssecvalidator/>

## 主な機能

- ルート DNS サーバーから対象ドメインのゾーン頂点と権威 DNS サーバーを探索
- 親ゾーンから DS レコードを取得
- 子ゾーンから DNSKEY と DNSKEY に対する RRSIG を取得
- DS と KSK のダイジェストを照合
- 子ゾーンの CDS / CDNSKEY から提案された DS と親側に登録された DS の差分を診断（自動変更や提案の署名検証は行いません）
- DS、DNSKEY、選択した対象レコードに対する RRSIG を検証
- RRSIG の有効期限を日本時間の日時と残り時間で表示し、期限まで7日以内の場合は更新確認を促す
- 親・子それぞれの全権威サーバーから NS / DS / DNSKEY を取得し、RRset の差分や応答失敗を比較
- 対象ドメインがゾーン頂点でない場合、A / AAAA / CNAME / MX / NS / TXT / CAA / SRV から選択したレコードの DNSSEC 検証も実行
- 選択したレコードが存在しない場合、NSEC / NSEC3 による不在証明を確認
- 検証結果を親ゾーンと子ゾーンの関係図として表示

## 使い方

1. 公開 URL を開きます。
2. 検証したいドメイン名を入力します（例: `example.com`）。URL を入力した場合はホスト名を取り出して検証します。
3. 検証するレコード種別を選択します。
4. **検証スタート**を押します。
5. 成功または失敗の結果と、DS、DNSKEY、RRSIG の検証状況を確認します。

入力したドメイン名はブラウザーの `localStorage` に保存され、次回表示時に再利用されます。URL の `domain` クエリーパラメーターでドメイン名、`recordType` クエリーパラメーターで検証するレコード種別の初期値を指定することもできます。`recordType` には `A`、`AAAA`、`CNAME`、`MX`、`NS`、`TXT`、`CAA`、`SRV` を指定できます。

例:

```text
https://www.on-link.jp/dnssecvalidator/?domain=example.com&recordType=AAAA
```

## ローカルでの起動

### 必要環境

- WSL2 上の Ubuntu
- Node.js 22 LTS（`nvm` の利用を推奨）
- 外部の権威 DNS サーバーへ UDP/TCP 53 番ポートで接続できるネットワーク

### 手順

WSL2 の Ubuntu ターミナルで実行します。Node.js を `nvm` で管理する場合は、リポジトリの `.nvmrc` に合わせてください。

```bash
nvm install
nvm use
npm install
npm start
```

`nvm` が未導入の場合は、Ubuntu 側でインストールしてからシェルを再起動してください。Node.js 18 以上で動作します。

起動後、次の URL を開きます。

<http://localhost:3002/>

このアプリは `127.0.0.1:3002` のみで待ち受けます。ポート番号を変更する場合は、`dnssec-validator.js` の `PORT` 定数を変更し、nginx の upstream も合わせてください。nginx は同一ホストの loopback を指定して転送します。

```nginx
location / {
  proxy_pass http://127.0.0.1:3002;
}
```

この設定により、外部から Node.js のポートへ直接接続できなくなります。同一ホスト上の他プロセスからの接続は引き続き可能です。

### テスト

外部 DNS サーバーへ接続せず、入力バリデーション、DNSSEC の DS/DNSKEY 突合、CDS/CDNSKEY 提案と親DSの比較、署名期限、ZSK ビット判定、NSEC/NSEC3 の A レコード不存在証明と NXDOMAIN 証明、権威サーバー間 RRset 比較、ゾーン頂点の探索、親子が同じネームサーバーになるケース、グルー選択と NS フォールバック、UDP/TCP 切り替え、HTTP エンドポイント、セキュリティヘッダーを確認できます。

```bash
npm test
```

VS Code では WSL 拡張機能でこのフォルダーを開くと、統合ターミナル、起動設定、テスト設定が Ubuntu 側で実行されます。

テスト本体は `test/dnssec-validator.test.js` にあります。実際の DNS 応答を使う検証はネットワーク状態に左右されるため、必要に応じてアプリを起動して画面または API から別途確認してください。

dnssec-check.jp の掲載ドメインを起動済みの API で一括検証する場合:

```bash
python3 test/validate_all_domains.py --url http://localhost:3002
```

HTTP 429 の場合は `Retry-After` の秒数だけ待ち、同じドメインを最大3回再試行します。ヘッダーがない、または秒数形式でない場合は60秒待ちます。`--rate-limit-retries` で回数を変更でき、`0` で再試行を無効にできます。HTTP エラーは DNSSEC の検証失敗とは区別し、テスト不一致として扱います。`--url` を省略するとドメインごとに独立した Node プロセスを起動するため、レート制限の状態は共有されません。

一括検証スクリプトの待機・再試行のテストは、外部通信なしで実行できます。

```bash
python3 -m unittest discover -s test -p 'test_validate_all_domains.py'
```

## API

画面からの検証処理は、次のエンドポイントを使用します。

### `POST /api/validate`

リクエスト:

```http
Content-Type: application/json
```

```json
{
  "domain": "example.com",
  "recordType": "AAAA"
}
```

`recordType` は任意です。省略時は `A` を検証し、指定する場合は `A`、`AAAA`、`CNAME`、`MX`、`NS`、`TXT`、`CAA`、`SRV` のいずれかを指定します。

Secure と判定された場合のレスポンス例です。すべての検証結果に、状態を示す `status`、表示用の `statusLabel`、次の確認箇所を示す `nextChecks` が含まれます。

```json
{
  "success": true,
  "status": "secure",
  "statusLabel": "Secure（検証成功）",
  "nextChecks": ["追加確認は不要です。"],
  "logs": [],
  "diagram": {
    "parent": {},
    "child": {},
    "checks": {},
    "authorityChecks": {
      "parent": { "nameservers": {}, "ds": {} },
      "child": { "nameservers": {}, "dnskey": {} }
    },
    "dsProposal": {
      "parentDs": [],
      "cds": { "status": "match", "proposed": [], "toAdd": [], "toRemove": [] },
      "cdnskey": { "status": "match", "proposed": [], "toAdd": [], "toRemove": [] },
      "notes": []
    }
  }
}
```

`status` は次のいずれかです。

- `secure`: DSから対象レコードまでの信頼の連鎖と署名または不在証明を検証できた状態です。`success` は `true` になります。
- `insecure`: 親側のNSEC/NSEC3不在証明を検証し、DSのない未署名委任と確認できた状態です。DNSSECの検証成功ではないため、`success` は `false` です。
- `bogus`: DSと子の鍵の不一致や署名・不在証明の検証失敗が確認された状態です。DSがなくても、署名を検証できたNSEC3 Opt-Outの範囲終端と対象名のハッシュが一致し、DS不在証明が不整合な場合はこの状態になります。
- `indeterminate`: タイムアウトや必要な応答・不在証明の不足などにより判定できない状態です。

`success` は親DSと子DNSKEYの一致だけではなく、信頼の連鎖および対象レコードの署名、または不在証明まで検証できた場合に `true` になります。次に確認する内容は `nextChecks`、詳細な検証結果やエラーは `logs` と `diagram` に格納されます。入力不備やレート制限のHTTP 400/429応答は、検証結果の分類対象外です。
`diagram.authorityChecks` には、親・子の各権威サーバーが返した NS / DS / DNSKEY の比較結果が含まれます。応答が得られないサーバーは、RRset の不一致とは区別して記録されます。
`diagram.dsProposal` には、親のDSと子のCDS / CDNSKEYが提案するDSの比較結果が含まれます。`diagram.dsProposal.cds.status` と `diagram.dsProposal.cdnskey.status` は `match`、`different`、`delete`、`absent`、`error` のいずれかです。

入力不備の場合は `400`、レート制限超過時は `429`、サーバー内部エラー時は `500` を返します。`429` 応答には、再試行までの待機秒数を示す `Retry-After` ヘッダーが含まれます。

## 検証方式

アプリケーションは `dns-self-resolver` を使い、OS のフルサービスリゾルバーに依存せず、ルートサーバー（`198.41.0.4`）から委任を辿ってネームサーバー名を解決します。DNSSEC レコードの取得では DO ビットを設定し、UDP 応答が切り詰められている場合は TCP に切り替えます。

委任先の権威 SOA が取得できない場合も、探索中に得た委任点と親サーバーを保持し、親側の DS と NSEC/NSEC3 不在証明を検証します。同じ委任点の referral が繰り返される場合は探索を打ち切り、その理由をログに表示します。子側の権威 SOA が未取得の場合、子側の権威サーバー比較と CDS/CDNSKEY 提案の取得は省略します。
`diagram.parent.dsAbsenceProof` の `invalid` は検出した不在証明の不整合、`signaturesVerified` は検査対象の NSEC/NSEC3 の署名検証結果、`verified` は DS 不在証明全体の検証結果を表します。不整合な範囲は、署名が有効でも `verified: false` になります。証明・署名・親 DNSKEY の不足や問い合わせ失敗だけでは `bogus` とせず、`indeterminate` とします。

署名検証では、次の DNSSEC アルゴリズムに対応しています。

- RSA: RSASHA1、RSASHA1-NSEC3-SHA1、RSASHA256、RSASHA512
- ECDSA: ECDSAP256SHA256、ECDSAP384SHA384
- EdDSA: ED25519、ED448
- ML-DSA: ML-DSA-44

ネームサーバーの IP アドレスは `dns-self-resolver` の TTL 付きプロセス内キャッシュに保存されます。API には、サーバーが認識する接続元 IP あたり 1 分 60 回のレート制限があります。最初のリクエストから60秒でリセットされ、全ドメインの一括検証後すぐに再実行すると制限に達する場合があります。nginx 経由の場合は通常、nginx の接続元 IP が使われるため、その経由でアクセスするクライアント全体で同じ枠を共有します。

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
- [dns-self-resolver](https://github.com/yoshigoto/dns-self-resolver): DNS 問い合わせ、ネームサーバー名の自己解決、グルー判定
- [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum): ML-DSA-44 署名の検証

## 注意事項

- DNS の応答は権威サーバーやネットワークの状態に左右されるため、タイムアウトや一時的な検証失敗が発生する場合があります。
- CNAME / DNAME を含む入力は、ゾーン頂点を特定できないため検証できない場合があります。
- 検証結果はその時点で取得した DNS 応答に基づく診断結果です。DNSSEC の設定変更後はキャッシュや TTL の影響に注意してください。
- 本番環境で公開する場合は、HTTPS、プロセス監視、ログ管理、必要に応じたリバースプロキシなどを別途構成してください。