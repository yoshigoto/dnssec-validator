# DNSSEC委任状態検証ツール

ドメインの DNSSEC 委任状態を確認する Web アプリケーションです。親ゾーンの DS と子ゾーンの DNSKEY・RRSIG を取得して検証し、委任関係の整合性を診断します。

## 公開 URL

<https://www.on-link.jp/dnssec-validator/>

画面右上の **English** から英語表示に切り替えられます。英語表示は `?lang=en` で開き、ドメイン名とレコード種別の指定は言語を切り替えても引き継がれます。サーバーが返す詳細な診断ログは、日本語で表示される場合があります。

## 主な機能

- ルートから委任をたどり、対象ドメインのゾーン頂点と権威サーバーを探索
- 親ゾーンの DS と子ゾーンの DNSKEY・RRSIG を検証
- A、AAAA、CNAME、MX、NS、TXT、CAA、SRV のいずれかを選び、対象レコードの署名または NSEC / NSEC3 による不在証明を検証
- 親・子の権威サーバー間で NS、DS、DNSKEY の応答を比較
- CDS / CDNSKEY の提案と親の DS の差分を表示（親への変更や提案の署名検証は行いません）
- 検証結果を図示し、RRSIG の有効期限を日本時間で表示（期限まで7日以内の場合は警告）

## 使い方

1. 公開 URL を開き、検証するドメイン名（例: `example.com`）を入力します。URL を入力した場合はホスト名を使います。
2. 検証するレコード種別を選び、**検証スタート**を押します。
3. 判定結果と DS、DNSKEY、RRSIG の検証状況を確認します。

入力したドメイン名はブラウザーの `localStorage` に保存され、次回の表示時に復元されます。URL の `domain` と `recordType` クエリーパラメーターでも初期値を指定できます。`recordType` に指定できる値は `A`、`AAAA`、`CNAME`、`MX`、`NS`、`TXT`、`CAA`、`SRV` です。

例:

```text
https://www.on-link.jp/dnssec-validator/?domain=example.com&recordType=AAAA
```

## ローカルでの起動

### 動作環境

- Node.js 18 以上（`.nvmrc` は 22 を指定。`nvm` の利用を推奨）
- 外部の権威 DNS サーバーへ UDP/TCP 53 番ポートで接続できるネットワーク

### 起動方法

リポジトリのルートで実行します。`nvm` を使う場合は `.nvmrc` に指定された Node.js を利用してください。

```bash
nvm install
nvm use
npm ci
npm start
```

起動後、次の URL を開きます。

<http://localhost:3002/>

サーバーは `127.0.0.1:3002` で待ち受けます。リバースプロキシを使う場合は、同じホストの loopback に転送します。たとえば nginx では次のように設定できます。

```nginx
location / {
  proxy_pass http://127.0.0.1:3002;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

この設定では Node.js のポートは外部に公開されませんが、同じホスト上のプロセスからは接続できます。アプリは既定で loopback のプロキシを信頼し、`X-Forwarded-For` から取得したクライアント IP アドレスをレート制限に使います。プロキシが別のアドレスにある場合は、環境変数 `DNSSEC_VALIDATOR_TRUST_PROXY` に Express の `trust proxy` 形式（例: `loopback, 10.0.0.5`）で指定してください。信頼できない送信元を指定すると、IP アドレスを偽装されるおそれがあります。

### テスト

通常のテストは外部 DNS に接続せず、DNSSEC の署名・不在証明、ゾーン探索、API、画面表示、入力・負荷制限などを確認します。実際の DNS パケット処理を確認する結合テストも、ループバック上の模擬 DNS サーバーを使って実行します。

```bash
npm test
```

署名検証テストでは、対応する全アルゴリズムと8種類のレコードを対象に、RRset の順序や TTL の違いを許容すること、データや署名の改ざんを拒否することを確認します。API を通した信頼の連鎖や、NSEC / NSEC3 による NODATA・NXDOMAIN の証明もテストします。

ML-DSA-44 は固定ベクトルを使い、署名を再生成せずに検証します。このベクトルはプロジェクト内で作成したもので、公式の適合性ベクトルではなく、実際の権威サーバーとの相互運用を保証するものでもありません。秘密鍵は含まず、通常のテストに OpenSSL や外部通信は不要です。

画面テストは jsdom で HTML とクライアントスクリプトを読み込み、DOM の構造や API 応答に応じた表示を確認します。実ブラウザーでのレイアウト、レスポンシブ表示、CSS・CSP の適用を検証する E2E テストではありません。

画面側のテストだけを実行する場合:

```bash
node --test test/client.test.js
```

VS Code で WSL を使う場合は、WSL 側でこのフォルダーを開くと、統合ターミナルや起動・テスト設定を同じ環境で実行できます。

単体・API テストは `test/dnssec-validator.test.js`、DNS パケット処理を含む結合テストは `test/resolver-integration.test.js` にあります。結合テストはループバック上の模擬 DNS サーバーを使うため、外部 DNS や特権ポートは不要です。どちらも `npm test` に含まれます。

結合テストだけを実行する場合:

```bash
node --test test/resolver-integration.test.js
```

公開 DNS を使った検証はネットワークや権威サーバーの状態に左右されます。必要に応じてアプリを起動し、画面または API から確認してください。

公開されている dnssec-check.jp のテスト用ドメインを一括検証する場合は、アプリを起動してから次を実行します。このスクリプトは掲載ページの取得と実際の DNS 問い合わせを行うため、インターネット接続が必要です。

```bash
python3 test/validate_all_domains.py --url http://localhost:3002
```

掲載ページからドメイン一覧を取得できない場合は、スクリプト内の一覧を使います。検証結果が想定と一致しない場合、スクリプトは終了コード `1` を返します。HTTP 経由で実行する場合は、連続リクエストに対して API のレート制限が適用されます。HTTP 429 の場合は `Retry-After` に従って待機し、既定では最大3回再試行します。`--rate-limit-retries` で回数を変更でき、`0` で再試行を無効にできます。`--url` を省略するとドメインごとに独立した Node.js プロセスを起動するため、プロセス間でレート制限は共有されません。

このスクリプトの待機・再試行ロジックを外部通信なしでテストするには、次を実行します。

```bash
python3 -m unittest discover -s test -p 'test_validate_all_domains.py'
```

## API

画面は次の API を呼び出して検証します。

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

`recordType` は省略できます。省略時は `A` を検証します。指定する場合は `A`、`AAAA`、`CNAME`、`MX`、`NS`、`TXT`、`CAA`、`SRV` のいずれかを指定してください。

検証結果のレスポンス例です（`diagram` は省略しています）。入力が有効であれば、DNSSEC の判定が `secure` 以外の場合も HTTP `200` を返します。結果の状態は `status` で確認してください。

```json
{
  "success": true,
  "status": "secure",
  "statusLabel": "Secure（検証成功）",
  "nextChecks": ["追加確認は不要です。"],
  "logs": []
}
```

検証結果には、状態を示す `status`、画面表示用の `statusLabel`、次に確認する項目の `nextChecks`、診断ログの `logs`、詳細な検証データの `diagram` が含まれます。`status` は次のいずれかです。

- `secure`: DS から対象レコードまでの信頼の連鎖と、署名または不在証明を検証できた状態です。`success` は `true` です。
- `insecure`: 親側の NSEC / NSEC3 不在証明を検証し、DS のない未署名委任と確認できた状態です。DNSSEC 検証の成功ではないため、`success` は `false` です。
- `bogus`: DS と子の鍵が一致しない、または署名・不在証明に不整合がある状態です。
- `indeterminate`: タイムアウトや、必要な応答・不在証明の不足などにより判定できない状態です。

`success` は `secure` の場合のみ `true` です。親 DS と子 DNSKEY の一致だけでなく、対象レコードの署名または不在証明まで検証した結果を表します。

`diagram.authorityChecks` には、親側の NS / DS と子側の NS / DNSKEY について、権威サーバー間の応答比較が含まれます。問い合わせに失敗したサーバーは、RRset の差分とは分けて記録します。`diagram.dsProposal` には、親の DS と子の CDS / CDNSKEY から算出した提案との差分が含まれます。各提案の状態は `match`、`different`、`delete`、`absent`、`error` のいずれかです。提案を取得できない場合は `null` になることがあります。

入力不備は HTTP `400`、レート制限超過または同じクライアントからの同時検証数超過は `429`、サーバー全体の同時実行数超過は `503`、予期しないサーバーエラーは `500` です。`429` と `503` には `Retry-After` ヘッダーが付きます。`500` の詳細はレスポンスに含めず、サーバーログに記録します。検証が25秒を超えるとタイムアウト結果を返し、それ以降の DNS 問い合わせを中断します。

## 検証方式

アプリケーションは `dns-self-resolver` のバージョン `1.3.0` のマージ済みコミット `85784a33490317494c355a9d58990d154c5f05eb` に依存先を固定し、OS のフルサービスリゾルバーに頼らず、ルートサーバー（`198.41.0.4`）から委任をたどってネームサーバー名を解決します。非公開アドレスのみの最終回答も TTL 内は再問い合わせを抑制します。DNSSEC レコードの取得時は DO ビットを設定し、UDP 応答が切り詰められた場合は TCP に切り替えます。

委任先の権威 SOA を取得できない場合も、探索中に得た委任点と親サーバーを使って、親側の DS と不在証明の検証を試みます。同じ委任点への referral が繰り返された場合は探索を中断します。子側の権威 SOA を取得できない場合、子側の権威サーバー比較と CDS / CDNSKEY の取得は省略します。

`diagram.parent.dsAbsenceProof` では、`invalid` が不在証明の不整合、`signaturesVerified` が対象レコードの署名検証、`verified` が DS 不在証明全体の検証結果を表します。不整合な範囲は署名が有効でも `verified: false` です。証明・署名・親 DNSKEY の不足や問い合わせ失敗は `bogus` ではなく `indeterminate` と判定します。

署名検証では、次の DNSSEC アルゴリズムに対応しています。

- RSA: RSASHA1、RSASHA1-NSEC3-SHA1、RSASHA256、RSASHA512
- ECDSA: ECDSAP256SHA256、ECDSAP384SHA384
- EdDSA: ED25519、ED448
- ML-DSA: ML-DSA-44

ネームサーバーの IP アドレスは `dns-self-resolver` の TTL 付きプロセス内キャッシュに保存されます。DNS 応答キャッシュとレート制限の記録は、期限切れのものを定期的に削除します。API のレート制限は接続元 IP アドレスあたり1分60回で、IPv6 は `/64` 単位で集計します。カウントは最初のリクエストから60秒後にリセットされます。リバースプロキシ経由では、プロキシが付与した `X-Forwarded-For` の IP アドレスを使います。

### 攻撃への対策

検証対象ドメインの権威サーバーは、信頼できない応答を返す可能性があります。そのため、次の対策を行っています。

- DS は親ゾーンの権威サーバーだけから取得し、子ゾーンの権威サーバーには問い合わせません。DS の RRSIG の署名者は親ゾーン（対象ゾーンより上位のゾーン）である必要があります。DNSKEY・対象レコード・不在証明の RRSIG の署名者は、ゾーン頂点と一致する必要があります。
- Zone Key ビットがない DNSKEY と REVOKE ビットが立っている DNSKEY は、署名検証に使いません。
- ゾーン頂点の探索では、問い合わせ名の上位ではない SOA の所有者名を採用しません。また、問い合わせ名と無関係な委任（referral）は辿りません。
- 問い合わせ先がプライベート、ループバック、リンクローカル、CGNAT、ドキュメント用、マルチキャストなどの内部・特殊用途アドレスの場合、DNS 問い合わせを送信しません（DNS 経由の SSRF 対策）。
- 宛先判定は `dns-self-resolver` の `isPublicDnsServerAddress` を選択し、委任チェッカーと共通化しています。IPv6 は `2000::/3` 内に限定し、Teredo、ベンチマーク、ORCHID / ORCHIDv2、文書用、6to4 の範囲と `%` 付きアドレスを拒否します。従来の除外リスト方式より許可範囲を狭めています。入れ子の NS 名前解決と TCP 再試行にも同じ制限を適用します。
- RFC 9276 に従い、反復回数が150を超える NSEC3 は不在証明に使いません。1回の解析で計算する NSEC3 ハッシュの数にも上限を設けています。
- KeyTrap などの CPU 枯渇攻撃に備え、処理件数に上限を設けています。DNSKEY RRset は32件、DS RRset は16件、1つの RRset で検証する RRSIG は8件、NSEC / NSEC3 は32件、NS 名は1ゾーンあたり16件までです。RSA 鍵は4096ビットまでで、公開指数の長さにも上限があります。

この検証は、親ゾーンの DNSKEY を DS の署名検証に使いますが、その DNSKEY をルートのトラストアンカーまで遡って検証するものではありません。結果は「親と子の委任関係が DNSSEC として整合しているか」の診断です。経路上の攻撃者が親側の応答まで偽装する場合には、完全な検証済みリゾルバー（`delv` など）の結果と併せて確認してください。

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
- 入力した名前が CNAME / DNAME による別名の場合、ゾーン頂点を特定できず検証できないことがあります。
- 検証結果はその時点で取得した DNS 応答に基づく診断結果です。DNSSEC の設定変更後はキャッシュや TTL の影響に注意してください。
- 本番環境で公開する場合は、HTTPS、プロセス監視、ログ管理、必要に応じたリバースプロキシなどを別途構成してください。