# eolscan — 実装設計書 v0.3

**文書ステータス:** MVP 0.1実装済み / v0.2レビュー4件の採用判断を反映  
**改訂日:** 2026-10-11  
**対象:** CLI実装者・セキュリティレビュー担当者・CI管理者  
**正本:** 本Markdown。JSON Schemaとサンプル設定は本書に準拠する。  
**対応する実装リリース:** MVP 0.1（文書の版とは別）

> **最重要原則:** `SUPPORTED`は「上流のセキュリティ修正サポートが現在継続している」という**明示的な根拠**がなければ返さない。対象版の実在と公開日時を確認できない場合も、Lifecycleは`UNKNOWN`とする。

## 0. 改訂履歴と確定事項

### v0.3の採用事項

| ID | 確定した判断 | 影響箇所 |
|---|---|---|
| D-06 | 未来の終了日も保持して最高Tier内の矛盾を検出し、その後に評価日の状態を導出する | §7 |
| D-07 | 一般EOLは製品・PURL・系列・サポート範囲をレビュー済みの場合だけEOL/MEDIUMへ使用。既定のホワイトリストは0件 | §2、§6、§7 |
| D-08 | CI対象SignalはPRESENT/ABSENT/UNKNOWNで評価。代替情報でもUNKNOWNならincomplete | §6、§7、§8 |
| D-09 | VersionAssertionに公開日時を必須化。版証明・レビューの有効期限は実行日で検証 | §5、§6、§7 |

文書はv0.3だが、初回MVPで実装する未リリースの契約は引き続き設定2／レポート2.0とする。Go CLI MVP 0.1はこの契約を実装する。初期Go試作との互換性は保証しない。

### v0.2で採用済みの事項

| ID | 問題点 | v0.2での決定 | 影響箇所 |
|---|---|---|---|
| D-01 | 一般的なEOL日からSUPPORTEDを推論できてしまう | `UPSTREAM_SECURITY_WINDOW`を明示的に確認した場合だけSUPPORTED。endoflife.dateの`eolFrom`単体はSUPPORTEDの根拠にしない | §2、§6、§7 |
| D-02 | CIの既定0と利用者期待の差 | デフォルトは**report-first**。`EOL/HIGH`のみexit 1、API不完全は原則exit 0。別途Strict設定を提供 | §8、§9 |
| D-03 | `7.2.9999`など架空版への判定 | Lifecycle判定前に**実在版の検証を必須**とする。未検証はUNKNOWN。deps.dev GetVersion またはローカルの正確な版登録で検証 | §5、§7 |
| D-04 | `/products/full`と製品別GETの重複 | endoflife.dateは`/identifiers/purl`の対応表→一致製品だけ詳細GET。全量fullはMVPで使わない。ディスクキャッシュは**任意・既定OFF** | §6、§11 |
| D-05 | EOL_SOON型、矛盾設定、出力例が不一致 | `EOL_SOON`は`Notice`へ分離。`unknown_on_same_tier_conflict`は削除し同格矛盾は固定でUNKNOWN。必須・nullableフィールドをSchemaに確定 | §7、§8、§10 |

互換性：v0.1試作の設定・レポートとの機械的な後方互換性は保証しない。設定`schema_version: 2`、出力`schema_version: "2.0"`とし、v0.1契約を黙って読み替えない。

## 1. システム概要と範囲

単一のCycloneDX／SPDX JSON形式SBOMからパッケージを抽出し、PURLで識別、実在版を検証、ライフサイクル情報とメンテナンスシグナルを取得して判定・報告するCLI。

### 1.1 MVPの範囲

| 分類 | MVP | 将来拡張 |
|---|---|---|
| 入力 | CycloneDX JSON 1.4–1.7、SPDX 2.3 JSON | SPDX 3.x、XML、複数SBOM |
| 依存識別 | 完全なPURL（versionあり） | CPE等、明示的な手動マッピング |
| エコシステム | gem、npm、pypi、maven、golang、cargo、nuget | OSディストリビューション、oci、composer等 |
| EOL根拠 | 手動レビュー済み公式サポートカタログ、endoflife.date API v1 | ベンダー公式API、後継プロジェクト |
| バージョン実在確認 | deps.dev GetVersion、カタログの正確な版登録 | Registry直結、署名付きスナップショット |
| シグナル | deps.dev deprecated、公開日（取得可能な場合） | GitHub、Go retract、PyPI project status等 |
| 出力 | table、JSON Schema 2.0 | SARIF、HTML、CycloneDX annotation |
| 実行モード | report-first既定、CI Strict設定、offline | 組織向けポリシー配布 |

**非目標:** 脆弱性・CVSSの検出、古いリリースのみを根拠とするEOL断定、名前の曖昧一致、延長サポートの自動合算、LLMによるウェブページ解釈は行わない。

## 2. 概念とEOLの意味

| 概念 | 仕様 |
|---|---|
| `EOL` | 上流のセキュリティ修正サポートが終了したと確認された状態。一般EOL情報は、その意味を対象製品・系列・サポート範囲についてレビュー済みの場合だけMEDIUMの根拠にできる |
| `SUPPORTED` | **上流のセキュリティ修正サポートが評価日を含む期間に明示的に継続**していると確認できる状態 |
| `UNKNOWN` | EOL/SUPPORTEDを確定するための根拠が不足。安全・サポート中を意味しない |
| `GENERAL_EOL_END` | endoflife.date等が公開する一般的なEOL日。未来であることはSUPPORTEDを意味しない |
| `UPSTREAM_SECURITY_WINDOW` | 公式情報で明示された、上流セキュリティ修正が継続する区間 `[start, end)` |
| `UPSTREAM_SECURITY_END` | 公式に確認した上流セキュリティ修正の終了日。終了前のSUPPORTEDは保証しない |
| `MaintenanceSignal` | 非推奨、アーカイブ、長期間更新なし等。Lifecycleとは独立 |
| `Notice` | 判定結果から計算する通知。MVPは`EOL_SOON`のみ |
| `Confidence` | Lifecycle判定根拠の信頼度。セキュリティリスクの強弱ではない |

### 2.1 日付の意味と境界

- LifecycleはUTC暦日（`YYYY-MM-DD`）で評価する。`as_of >= eol_effective_date`なら終了済み。
- 実行開始時に`run_started_at`を1回取得する。版証明、サポートカタログ、一般EOLレビュー、CI例外の`valid_until`／`expires_on`は、その実行UTC日付で検証する。`--as-of`を過去にしても期限切れ資料は復活しない。期限日は当日まで有効とし、翌日から失効する。
- `published_at`はUTCへ変換した暦日と`as_of`を比較する。同じ暦日に公開された版はその日の評価対象にできる（時刻単位の過去再現ではない）。実行時刻より未来の公開日時を返す情報は、未来の版の実在証明に使わない。
- `eol_effective_date`は**その日の0:00 UTC以降終了扱い**。資料が「当日末までサポート」を意味するなら、正規化処理で翌日に直す。元の日付・変換をEvidenceに残す。
- `UPSTREAM_SECURITY_WINDOW`は`support_start_date <= as_of < eol_effective_date`でSUPPORTEDを返せる。`UPSTREAM_SECURITY_END`は終了前もUNKNOWN。
- endoflife.dateの`eolFrom`は`GENERAL_EOL_END`として保存する。ホワイトリストの有効なレビューが製品・PURL・系列・サポート範囲すべてに一致し、終了済みの場合だけ`EOL/MEDIUM`を返せる。未レビュー情報はEvidenceに保持し`UNKNOWN/GENERAL_EOL_UNREVIEWED`とする。終了前は別途Security Windowがない限りUNKNOWN。booleanからSUPPORTEDを推論しない。
- `isMaintained=true`には延長サポートが含まれ得る。上流サポートと延長サポートを混同せず、`isMaintained`によって終了済みの上流EOLを取り消さない。情報が衝突する場合は診断を記録する。
- 一般EOLレビューの既定登録件数は0。製品名だけの許可や全製品の包括許可は禁止。レビュー期限切れもEOL根拠にしない。
- `--as-of`未来は`projection=true`。未来時点の公開バージョン存在やサポート継続は推測しない。

### 2.2 保守主体

MVPの判定対象は`upstream_security`。ディストリビューションのバックポート／有償延長サポートは別の主体であり、上流サポート中には昇格しない。MVPの公式カタログSchemaは上流セキュリティの根拠だけを受理する。一般EOL Evidenceの元スコープは`general_eol`のまま保持し、有効なレビューで対応を確認した場合だけ比較上のスコープを`upstream_security`へ対応付ける。レビューによりsource_classやConfidenceをHIGHへ変更してはいけない。

## 3. 機能要件と品質要件

| ID | 要件 |
|---|---|
| FR-01 | SBOM内のパッケージをすべて抽出し、元参照IDと版を保持 |
| FR-02 | PURLを標準パーサで解釈し、誤った名前一致・誤ったバージョン一致を禁止 |
| FR-03 | **Lifecycle評価に先立ってバージョン実在検証を完了** |
| FR-04 | endoflife.dateのPURL索引と詳細を別々に必要量だけ取得 |
| FR-05 | 公式Security Window／終了日／一般的EOL日を区別してEvidence保存 |
| FR-06 | Lifecycle、メンテナンスSignal、派生Notice、Diagnosticを別型で保存 |
| FR-07 | 設定とreportにJSON Schemaを持たせ、双方を検証 |
| FR-08 | default report-first、strict CI例、安定したexit codeを提供 |
| FR-09 | 矛盾・欠損・不完全スキャンを監査可能な理由コードとして出力 |
| FR-10 | オフライン、再試行、実行中のメモ化、任意の永続キャッシュを提供 |

- **再現性:** `as_of`、`tool_version`、`policy_hash`、`input_sha256`、根拠の`observed_at`を保存。過去の外部APIレスポンスは復元しないため、完全なhistorical replayには固定Fixtureが必要。
- **障害隔離:** 1パッケージのネットワーク障害で全件処理を止めない。
- **安全性:** SBOMから任意URLをfetchしない。TLS／許可ホスト、認証情報の非出力、入力サイズ／深度の上限を設ける。
- **プライバシー:** PURL等を公開APIへ送信し得る旨をヘルプに明記し、`--offline`を提供。

## 4. アーキテクチャとモジュール境界

```text
SBOM JSON
  -> FormatDetector / Parser
  -> Normalizer / PURL Resolver
  -> VersionVerifier (deps.dev GetVersion | exact local assertions)
        |                             \
        |                              -> Maintenance Signals
        v
     LifecycleEvidenceProviders
       - Official Support Catalog
       - endoflife.date PURL Index -> Product Details
        |
        v
     EvidenceValidator (scope, version, freshness, dates)
        |
        v
     LifecycleEvaluator (EOL | SUPPORTED | UNKNOWN)
        |
        +-> NoticeEvaluator (EOL_SOON)
        +-> Diagnostics / IncompleteTracker
        |
        v
     Exception / CI Gate -> table | JSON | exit
```

| Module | 責務 | 禁止事項 |
|---|---|---|
| `sbom` | CycloneDX/SPDX構文と対象抽出 | 名前で公式製品に結び付けない |
| `identity` | PURL正規化、同一性、系列解決 | 単純な文字列prefixによる誤一致 |
| `verification` | 登録された版の存在を証明 | API 404を「ソフトウェアは存在しない」と断定 |
| `provider` | 根拠・シグナル・診断を取得 | Lifecycleを最終決定しない |
| `policy` | スコープ・Tier・競合・日付・Notice | deprecatedをEOLへ自動昇格しない |
| `transport` | HTTP、retry、並列、memo、任意disk cache | SBOM由来の任意URLをfetchしない |
| `report` | JSON/table、集計、exit | 不明を成功確認として表示しない |

## 5. SBOM／PURL／バージョン検証

### 5.1 SBOM抽出

| 形式 | 抽出 | PURL | ソース参照 |
|---|---|---|---|
| CycloneDX JSON 1.4–1.7 | `components[]`およびネストした`components[]` | `component.purl` | `bom-ref`、なければ安定したJSONパス |
| SPDX 2.3 JSON | `packages[]` | `externalRefs`で`referenceType=purl` | `SPDXID` |

CycloneDX`metadata.component`は既定で除外。SPDX packageは種別フィルタを適用しない。重複PURLのネットワーク照会は1回だけ、結果は元コンポーネントごとに出力。`input.include_component_types`と`input.include_metadata_component`を設定可能とする。

### 5.2 パッケージとバージョンの妥当性

1. PURL標準パーサを使用。`name/version`の単純splitは禁止。name/namespace/case/qualifier/subpathはエコシステム規約に従う。
2. PURLとSBOMの`version`が両方あり異なれば`VERSION_CONFLICT`でUNKNOWN。バージョンなしやrangeのみは`VERSION_UNRESOLVED`でUNKNOWN。
3. 公開同名パッケージとprivate packageを混同しない。プライベート依存の疑いは`PRIVATE_SOURCE_UNSUPPORTED`でUNKNOWN。
4. PURLの**対象バージョン完全一致**で実在確認する（`version_verification.mode=required`がMVP唯一のモード）。
5. 確認方法は(a) deps.devの`GetVersion` 200と正規化されたversion一致、または(b)信頼したローカル`verified_versions`の完全一致。系列名の一致だけは実在根拠にしない。
6. deps.devにない404は`NOT_FOUND_IN_INDEX`であって、世界中でバージョンが存在しないと断定するものではない。LifecycleはUNKNOWNにし、理由`VERSION_NOT_FOUND_IN_INDEX`を記録する。
7. timeout/429/5xxは`UNVERIFIED`で理由`VERSION_UNVERIFIED`および`SOURCE_ERROR`。同時にscan incompleteの判定材料にする。
8. `published_at`のUTC暦日が`as_of`より後なら`NOT_RELEASED_AS_OF`でUNKNOWN。公開日時が欠落・不正なら、現在日の評価でも`UNVERIFIED / VERSION_UNVERIFIED`とする。GetVersionの200・version一致だけではVERIFIEDにしない。代替の有効なローカル版証明で公開日時を補えなければincomplete=true。実行時刻より未来の公開日時は`UNVERIFIED / PUBLICATION_IN_FUTURE`とする。
9. `VERIFIED`ではないコンポーネントへLifecycle=`EOL`／`SUPPORTED`を割り当ててはならない。ただし取得済みのMaintenance Signals・Diagnosticsは出力する。
10. `version_verification.mode=required`はポリシーの安全性を守る固定ルール。将来の緩和モードは別仕様・版で検討する。

`VerificationResult`の固定値は`VERIFIED | NOT_FOUND_IN_INDEX | UNVERIFIED | NOT_RELEASED_AS_OF | NOT_APPLICABLE`。`NOT_APPLICABLE`もLifecycleはUNKNOWNとする。

### 5.3 リリース系列のマッチング

- PURLのtype・パッケージ識別が厳密一致した後で、製品のリリース系列に対応付ける。
- MVPの自動対応は**数値ドット区切りの系列**のみ（例: `7.2` → `7.2.4`）。各数値セグメントの境界で比較し、`7.2`と`7.20`を混同しない。
- 複数一致したら最長の系列を選ぶ。同順位・複数候補で意味が違う場合`AMBIGUOUS_CYCLE`。
- 日付系列、コードネーム、LTS名、pre-releaseなどは明示的なcatalog mappingがなければUNKNOWN。
- **系列一致はLifecycle Evidenceの適用範囲を確認するだけであり、バージョン実在検証の代替にはならない。**

## 6. Provider／データ取得方式

### 6.1 Providerの共通契約

```text
Provider {
  id(): string
  supports(component): bool
  fetch(component, context): ProviderResult
}
ProviderResult {
  lifecycle_evidence: LifecycleEvidence[]
  version_assertions: VersionAssertion[]
  signals: SignalEvidence[]
  signal_evaluations: SignalEvaluation[]
  diagnostics: Diagnostic[]
}
```

通信は`transport`経由。Providerは命名・日付・適用範囲を正規化するがLifecycleの最終Statusを返さない。元の出典リンク・フィールド名・取得時刻を保存する。HTTP 404／429／timeoutを混同しない。

### 6.2 Official Support Catalog／版証明／一般EOLレビュー

ローカル`support-catalog.yaml`を明示指定した場合にロードする。未指定なら3種類とも登録0件。URLの内容をCLIが自動レビューするのではなく、運用者の確認を信頼する境界である。

- `entries[]`: 公式Security Window／Security End。公式根拠URL、サポート主体、レビュー日、有効期限が必須。Windowは開始日・終了日の両方を必須とする。Endだけでは終了前のSUPPORTEDを導出しない。
- `verified_versions[]`: 下記VersionAssertionの配列。version付きPURLの完全一致と公開日時を人手で確認したもの。系列から版を生成しない。
- `general_eol_reviews[]`: 下記GeneralEolReviewの配列。製品slug・versionなしPURL・系列・`upstream_security`への意味対応を確認したもの。製品だけの包括許可、ワイルドカードは禁止。
- 各配列の有効期限は`run_started_at`のUTC暦日で確認。失効した資料は根拠として使わず`STALE_EVIDENCE`を残す。
- 公式Entryの`match`は`numeric_segment_prefix`または`exact_versions`。前者の`versions`は空配列、後者は明示する版文字列の配列とする。系列対応と版の実在証明は別の処理である。
- 公式根拠の正式な撤回・更新が確認できた場合だけ、`superseded_by`と`supersession_source_url`に新しい根拠IDと撤回・更新の確認URLを保存できる。単に観測時刻が新しい情報を優先してはいけない。

```text
VersionAssertion {
  package_purl: string       # 正確なversion付きPURL
  published_at: timestamp   # 必須。UTCへ正規化
  source_url: https_url
  reviewed_at: date
  valid_until: date         # 実行日のUTC暦日で検証
}
GeneralEolReview {
  id: string
  product_slug: string
  package_purl: string       # versionなし
  matched_cycle: string
  support_scope: upstream_security
  evidence_url: https_url
  reviewed_at: date
  valid_until: date
}
```

カタログ例は架空の製品であり、実在製品のサポート証明として使用しない。

```yaml
schema_version: 2
entries:
  - id: example-security-2.4
    package_purl: pkg:gem/example
    matched_cycle: "2.4"
    match: numeric_segment_prefix
    versions: []
    claim: UPSTREAM_SECURITY_WINDOW
    support_scope: upstream_security
    support_start_date: "2024-04-12"
    eol_effective_date: "2026-12-01"
    evidence_url: https://example.org/support/2.4
    support_authority: example-upstream
    reviewed_at: "2026-10-01"
    valid_until: "2026-12-01"
    superseded_by: null
    supersession_source_url: null
verified_versions:
  - package_purl: pkg:gem/example@2.4.7
    published_at: "2024-04-12T09:00:00Z"
    source_url: https://example.org/releases/2.4.7
    reviewed_at: "2026-10-01"
    valid_until: "2026-12-01"
general_eol_reviews:
  - id: example-general-eol-2.4
    product_slug: example
    package_purl: pkg:gem/example
    matched_cycle: "2.4"
    support_scope: upstream_security
    evidence_url: https://example.org/support/2.4
    reviewed_at: "2026-10-01"
    valid_until: "2026-12-01"
```

Schemaは`../schemas/support-catalog.schema.json`、完全なサンプルは`../examples/support-catalog.example.yaml`。レビューの対象と実際の製品詳細が一致しない場合も未レビュー扱いとする。

### 6.3 endoflife.date API v1：PURL索引 → 製品詳細

**MVPで採用するネットワーク方式は以下に固定する。** `/products/full`は使わない。

1. 実行時に必要なら、1回だけ`GET https://endoflife.date/api/v1/identifiers/purl/`（スラッシュなし等へのリダイレクトは固定ホスト内のみ許可）。
2. レスポンス`result[].identifier`（versionなしPURL）と`result[].product.uri`から索引を生成する。製品URIは`https://endoflife.date/api/v1/products/{slug}/`形式であることを検証し、未知ホスト・意図しないパスなら拒否。
3. 対象コンポーネントのversionなしPURLとの**完全一致**だけを採用。複数製品が一致した場合は`AMBIGUOUS_IDENTITY`。
4. 一致した製品に対してのみ`GET /api/v1/products/{slug}/`。同じ製品へのリクエストは1回にまとめる。
5. 製品詳細の`identifiers[type=purl]`でも同一識別子を再確認し、`releases[].name`へ系列一致。
6. `releases[].eolFrom`が日付なら`GENERAL_EOL_END`／`confidence=MEDIUM`として保存。`isEol`／`isMaintained`は補助情報であり、SUPPORTEDの根拠にしない。
7. 一般EOLレビューを製品slug・PURL・系列・サポート範囲で照合。有効な一致レビューはEvidenceの`general_eol_review`へ保存。不一致・未登録はnull、失効レビューは保存するが判定には使わない。いずれも元Evidenceを保持する。
8. レビューなしの一般EOLは`UNKNOWN/GENERAL_EOL_UNREVIEWED`。有効なレビューありの場合は、未来の終了日も含めてTier・矛盾の比較対象にする。矛盾がなければ、終了日当日以降はEOL/MEDIUM、終了前はUNKNOWN/GENERAL_EOL_ONLY。公式Windowがある場合は公式Tierの規則に従う。

OpenAPIでは`/identifiers/{identifier_type}`の`result[]`は`identifier`と`product`（URI参照）を持つ。`/products/full`が全件の詳細を返すため、索引目的の取得には使用しない。

### 6.4 deps.dev API v3：版実在確認・シグナル

- `GET /v3/systems/{system}/packages/{name}/versions/{version}`がバージョン検証の主要Provider。`GO/RUBYGEMS/NPM/CARGO/MAVEN/PYPI/NUGET`。
- HTTP 200だけでなく`versionKey.system/name/version`が正規化後の対象と一致するか確認。不一致は`VERSION_CONFLICT`。
- `isDeprecated=true`は`DEPRECATED/PRESENT`を記録するだけ。`deprecatedReason`も保存。false・欠落をABSENTとするには、そのエコシステムとAPI契約で否定情報を提供することを確認する。収集機能のないエコシステム、欠損、API障害はUNKNOWNでありABSENTではない。
- `publishedAt`は版検証に必須。欠落・不正は代替版証明で補えなければUNVERIFIED。
- STALE_RELEASEはGetPackageの完全な版一覧から、評価日までに公開された版の公開日時の最大値を使う。必要な公開日が欠落、全件取得を確認できない、API障害、対応取得手段なし、未来as_ofで推測が必要な場合はUNKNOWN。情報が揃い、評価日との差が`stale_release_days`を超えればPRESENT、それ以下ならABSENT。
- 404は`NOT_FOUND_IN_INDEX`であり実在版の否定確定ではない。再試行すべき障害ではないが、UNKNOWNとする。
- Mavenは`group:artifact`、npmスコープ、Goパス、URLエンコードを公式API仕様に従って変換する。
- システムに関わらず、deps.dev自身が上流セキュリティサポートを保証するとはみなさない。

### 6.5 将来のProviderとMVPでの扱い

GitHub Archived、PyPI project status、Go retract、NuGet deprecation、各Registry APIは後続対応。MVPの設定で`github.enabled=true`と指定された場合は**未実装の有効化を黙認せず設定エラー（exit 2）**。未知Provider設定も拒否する。一方、`ci.fail_on_signals`に将来対応のSignal種別を指定することは可能。そのSignalの取得手段がなければ評価はUNKNOWNでincomplete=trueとなる。

## 7. 内部型・判定処理・矛盾ルール

### 7.1 型契約（論理モデル）

`LifecycleEvidence`（**全フィールド必須、`| null`は明示null**）:

```text
LifecycleEvidence {
  id: string
  provider_id: string
  source_class: OFFICIAL | CURATED_DATABASE
  claim: UPSTREAM_SECURITY_WINDOW | UPSTREAM_SECURITY_END | GENERAL_EOL_END
  package_purl: string                    # versionなし
  product_slug: string | null             # GENERAL_EOL_ENDでは必須
  matched_cycle: string
  support_scope: upstream_security | general_eol
  support_start_date: date | null
  eol_effective_date: date
  source_url: https_url
  source_field: string
  observed_at: timestamp
  source_updated_at: timestamp | null
  reviewed_at: date | null                 # OFFICIALでは必須
  valid_until: date | null                 # OFFICIALでは必須。実行日で検証
  raw_payload_hash: string | null         # SHA-256 hex
  confidence: HIGH | MEDIUM
  rule_id: string                         # この根拠の解釈ルール系統
  general_eol_review: GeneralEolReview | null
  superseded_by: string | null
  supersession_source_url: https_url | null
}
```

`VersionVerification`:

```text
VersionVerification {
  status: VERIFIED | NOT_FOUND_IN_INDEX | UNVERIFIED |
          NOT_RELEASED_AS_OF | NOT_APPLICABLE
  provider_id: string | null
  source_url: https_url | null
  checked_at: timestamp | null
  published_at: timestamp | null
  reason_code: string | null
}
```

`SignalEvidence`（MVP enum）：

```text
SignalEvidence {
  type: DEPRECATED | ARCHIVED | RETRACTED | QUARANTINED |
        STALE_RELEASE | STALE_REPOSITORY
  provider_id: string
  source_url: https_url | null
  observed_at: timestamp
  details: object
}
```

`SignalEvaluation`（有効化された検出種別とCI要求種別の和集合について、種別ごとに必須）：

```text
SignalEvaluation {
  type: SignalEvidence.type
  status: PRESENT | ABSENT | UNKNOWN
  provider_id: string | null
  source_url: https_url | null
  checked_at: timestamp | null
  reason_code: string | null
}
```

PRESENTには対応する`signals[]`の根拠が必要。ABSENTは正常かつ十分な情報による否定確認であり、HTTP成功だけでは付与しない。UNKNOWNには理由を必須とする。複数Providerは正常な同等情報を集約し、相反する評価はUNKNOWN/SIGNAL_CONFLICT。例外は評価状態やincompleteを変更しない。

`Notice`は**派生情報**で、Provider Signalではない：

```text
Notice {
  type: EOL_SOON
  days_remaining: integer                 # 1..通知閾値
  evidence_id: string
  rule_id: "R-009"
}
```

`Diagnostic`: `code`, `provider_id|null`, `http_status|null`, `retryable`, `message`を必須とする。`source_url`はLifecycleEvidenceの正式な出典URL。認証パラメータ付きの取得URLは出力しない。

### 7.2 判定Tierと比較

1. 対象PURL・対象版・適用系列に合うEvidenceを収集し、元データと診断を保持する。
2. 有効期限・日付の構文・サポート範囲・一般EOLレビューを確認する。無効・失効・未レビュー情報は判定用集合から除くが、`evidence[]`から削除しない。正式な撤回・更新の確認URLと新根拠IDがある古い情報だけを比較対象から外す。
3. **この時点で`as_of`と終了日を比較して候補を削除しない。未来の終了日も必ず保持する。**
4. 有効な集合の最高Tierを選ぶ：`OFFICIAL/HIGH > CURATED_DATABASE/MEDIUM`。レビュー済み一般EOLの比較上の範囲はupstream_securityだが、元Evidenceのsource_class／confidence／scopeは書き換えない。
5. 最高Tierで同じ対象版・サポート範囲に適用される終了日が不一致なら`UNKNOWN/CONFLICT`。Window同士の開始日が不一致の場合もCONFLICT。同じ終了日のWindowとEndは矛盾ではなく、明示Windowが継続中の根拠を提供する。低いTierの異なる終了日・状態は`SOURCE_DISAGREEMENT`として残し、上位を覆さない。
6. 矛盾がなければ、この段階で評価日と日付を比較する。Windowは`start <= as_of < end`ならSUPPORTED、`as_of >= end`ならEOL、開始前ならUNKNOWN。Security Endは終了済みならEOL、終了前ならUNKNOWN。レビュー済みGENERAL_EOL_ENDは終了済みならEOL/MEDIUM、終了前ならUNKNOWN/GENERAL_EOL_ONLY。
7. 上位Tierが終了前のSecurity EndでUNKNOWNとなる場合、低いTierだけを使ってEOLにしてはいけない。最高Tierの根拠を先に選ぶことと、状態導出を分離する。
8. 版の実在・公開日時が未検証なら、根拠の比較結果にかかわらずLifecycleはUNKNOWN。CONFLICT等の取得済み診断も保持する。確定したLifecycleの採用Evidence IDを`selected_evidence_ids[]`へ保存する。
9. `SUPPORTED`かつ`0 < days_until_eol <= notices.eol_soon_days`の場合だけEOL_SOON Noticeを追加する。

例：公式Security Endの2026-10-01と2026-12-01は、as_of=2026-10-11でもUNKNOWN/CONFLICT。正式な更新を確認して旧根拠を撤回した場合だけ、旧根拠を比較対象から外せる。

**重複の扱い:** 同じ一次資料・適用範囲・日付の主張は重複排除する。独立した根拠の数でConfidenceを格上げしない。

### 7.3 固定Rule ID

| Rule ID | 条件 |
|---|---|
| `R-001` | OFFICIAL Security Window/EndからEOL / HIGH |
| `R-002` | OFFICIAL Security Windowが評価日を包含 → SUPPORTED / HIGH |
| `R-003` | 有効な意味レビューが一致するCURATED GENERAL_EOL_ENDが終了済み → EOL / MEDIUM |
| `R-004` | **廃止・予約済み**。v0.1のCURATED→SUPPORTEDは実施禁止 |
| `R-005` | Maintenance Signal抽出。Lifecycle変更なし |
| `R-006` | 有効なLifecycle候補なし → UNKNOWN |
| `R-007` | 同格根拠の矛盾 → UNKNOWN / CONFLICT |
| `R-008` | 下位Tierの意見不一致 → 上位優先＋Diagnostic |
| `R-009` | SUPPORTEDで終了予定が閾値以内 → EOL_SOON Notice |
| `R-010` | 例外／CI Gate適用（Lifecycle不変） |
| `R-011` | バージョン未検証／索引未収録／未公開 → UNKNOWN |

### 7.4 必須アルゴリズム（擬似コード）

```text
run_started_at = utc_now_once()
run_date = utc_date(run_started_at)
required_signal_types = ci.fail_on_signals
requested_signal_types = enabled_signal_types union required_signal_types

for component in normalized_sbom:
  initialize lifecycle=UNKNOWN, confidence=null, chosen=[], reasons=[]
  initialize evidence=[], signals=[], diagnostics=[], signal_evaluations=[]
  if invalid_identity_or_version:
    verification = NOT_APPLICABLE
    reasons = identity_reasons
    signal_evaluations = UNKNOWN for each requested_signal_type
  else:
    verification = verify_exact_version_and_publication(component, as_of, run_started_at)
    collected = fetch_lifecycle_and_signals(component, requested_signal_types)
    evidence = normalize_evidence_keep_all(collected)
    eligible = validate_identity_cycle_scope_dates_freshness(evidence, run_date)
    eligible = require_matching_general_eol_review(eligible, run_date)
    eligible = remove_explicitly_superseded_with_proof(eligible)
    top = evidence_at_highest_tier(eligible)  # 終了日が未来でも除外しない
    conflict = compare_end_dates_and_support_windows(top)
    diagnostics += lower_tier_disagreements(eligible, top)
    signal_evaluations, signals = aggregate_signal_evaluations(collected)

    if verification.status != VERIFIED:
      reasons = verification_reasons(verification)
      diagnostics += conflict_if_present(conflict)
    elif conflict:
      reasons = [CONFLICT]
    elif top is empty:
      reasons = explain_no_eligible_evidence(evidence)
    else:
      lifecycle, reasons = derive_state_after_conflict_check(top, as_of)
      if lifecycle != UNKNOWN:
        chosen = deterministic_applicable_evidence(top, lifecycle)
        confidence = HIGH if top.tier == OFFICIAL else MEDIUM

  selected_evidence_ids = ids(chosen)
  notices = derive_eol_soon_only_if_supported(chosen, as_of, soon_days)
  required_signal_unknown = any(e.status == UNKNOWN for e in signal_evaluations
                                if e.type in required_signal_types)
  incomplete = required_lookup_unavailable_without_equivalent_success(component)
               or required_signal_unknown
  ci_failure = evaluate_component_ci(lifecycle, confidence, signal_evaluations, exceptions)
  emit result with all evidence, verification, evaluations, diagnostics, incomplete

report.ci_gate = aggregate_component_failures_unknown_ratio_incomplete()
exit_code = apply_exit_precedence(report.ci_gate)
```

### 7.5 UNKNOWN理由／不完全スキャンの区別

Lifecycle理由：`MISSING_PURL`, `INVALID_PURL`, `VERSION_UNRESOLVED`, `VERSION_CONFLICT`, `VERSION_NOT_FOUND_IN_INDEX`, `VERSION_UNVERIFIED`, `NOT_RELEASED_AS_OF`, `PUBLICATION_IN_FUTURE`, `PRIVATE_SOURCE_UNSUPPORTED`, `UNSUPPORTED_ECOSYSTEM`, `AMBIGUOUS_IDENTITY`, `AMBIGUOUS_CYCLE`, `GENERAL_EOL_ONLY`, `GENERAL_EOL_UNREVIEWED`, `NO_LIFECYCLE_EVIDENCE`, `STALE_EVIDENCE`, `CONFLICT`, `SOURCE_ERROR`。

- 必須の版検証・公開日時・最高Tier根拠の取得が障害や欠損で完了せず、同等以上の有効な情報で代替できなければincomplete=true。
- 未収録、索引404、未レビュー一般EOL、NOT_RELEASED_AS_OF、通常の根拠不足はそれだけでは不完全扱いしない。
- **CIで要求するSignalがUNKNOWNなら、API障害、公開日欠落、取得手段なしを問わずincomplete=true。** SignalのUNKNOWNをABSENTへ変更してはいけない。
- 必須Signalの正常な代替評価があればincompleteを回避できる。任意Signalだけの失敗は診断に残すが、それだけではincompleteにしない。
- `fail_on_incomplete_scan=true`なら不完全をGate違反にする。falseでも`result.incomplete`と`ci_gate.incomplete`に残す。例外は不完全を免除しない。
- 無効な識別子でもCI必須Signalを照会できなければ、そのSignalはUNKNOWNでincomplete=true。コンポーネントを早期returnして必須評価を消してはいけない。

## 8. YAML設定と規定値

### 8.1 設定の解決と不変条件

- 設定の優先順位は`CLIフラグ > YAML > ビルトイン既定値`。設定YAMLは`schema_version: 2`を必須とし、他の項目は**差分記述も許可**する。入力Schemaで未知キー・型を検査した後にビルトイン既定値と再帰マージし、生成した有効設定を再検証する。YAML内の相対パスは設定ファイルの場所を基準に解決する。
- 設定キー未知・型不一致・未実装機能のenable・矛盾する値は`policy validate`および`scan`で`exit 2`。
- **削除するキー：** `decision.unknown_on_same_tier_conflict`、`decision.excluded_general_eol_products`。同格矛盾は常にUNKNOWN、一般EOLは有効なレビューのあるものだけ使用する。旧キーは未知キーとしてエラー。
- `version_verification.mode`は`required`固定。`decision.support_scope`は`upstream_security`固定。Lifecycleの意味は設定で変更できない。
- 設定で変更できるのは照会Provider、通知閾値、キャッシュ、ネットワーク、CI Gate、ローカルカタログ・レビュー、例外。
- 本書と同梱の`policy.schema.json`が設定の正本。`policy_hash`は既定補完した設定・参照カタログ・例外を、`{policy, catalog, exceptions}`オブジェクトのUTF-8 JSON（キー順ソート、余分な空白なし）に正規化したSHA-256。カタログや例外が未使用ならnull。設定の相対パスは記述値を保持してハッシュへ含め、実ファイルは設定のディレクトリ基準で解決する。秘密値は含めない。

### 8.2 Default: report-first

```yaml
schema_version: 2
input:
  include_component_types: [library, framework, application, operating-system]
  include_metadata_component: false
  max_input_bytes: 52428800
  max_components: 100000
  max_json_depth: 128
sources:
  official_catalog:
    enabled: false
    path: null
  endoflife_date:
    enabled: true
    base_url: https://endoflife.date/api/v1
    match_purl_exactly: true
  deps_dev:
    enabled: true
    base_url: https://api.deps.dev/v3
version_verification:
  mode: required
  sources: [deps_dev, official_catalog]
signals:
  deprecated: true
  stale_release_days: 730
notices:
  eol_soon_days: 90
decision:
  support_scope: upstream_security
  max_evidence_age_days: 30
network:
  allowed_hosts: [endoflife.date, api.deps.dev]
  timeout_seconds: 8
  retries: 2
  max_concurrency: 6
cache:
  enabled: false
  positive_ttl_hours: 24
  negative_ttl_hours: 6
ci:
  fail_on_statuses: [EOL]
  min_confidence: HIGH
  fail_on_signals: []
  fail_on_incomplete_scan: false
  max_unknown_ratio: null
exceptions:
  path: null
output:
  include_unknown: true
  include_evidence: true
```

**明示的な利用者への説明:** 既定ではカタログが無効で、公式根拠・一般EOLレビュー・ローカル版証明の登録は0件。そのためendoflife.dateの一般EOLもUNKNOWNとなり、SUPPORTEDとEOL_SOONも出ない。カタログを指定して一般EOLの意味レビューだけを登録した場合はEOL/MEDIUMを出せるが、既定のHIGH閾値ではそれだけでCIを失敗させない。API障害によるincompleteも既定ではCIを止めない。Report-firstは報告・棚卸しを優先するモードである。

### 8.3 Strict CIプロファイル

同梱の`eol-policy.ci-strict.yaml`は上記設定を基礎として、以下を変更した**単独で読み込める完全な設定ファイル**。

```yaml
ci:
  fail_on_statuses: [EOL]
  min_confidence: MEDIUM
  fail_on_signals: []
  fail_on_incomplete_scan: true
  max_unknown_ratio: 0.25
```

上記はStrictの**差分表示**。実際に読み込ませるファイルには全設定が含まれる。`max_unknown_ratio: 0.25`はサンプル値であり、組織の許容値に合わせて調整する。UNKNOWNが多いエコシステムでは過剰に失敗し得るため、report-firstでカバレッジを観察してから有効化する。

- `ci.min_confidence`はEOLのみで評価する。UNKNOWNを`fail_on_statuses`へ設定した場合はConfidenceに依存せず失敗。
- `ci.fail_on_signals`はSignal種別だけを対象とし、指定種別の評価を必須化する（検出設定がfalseでもCI要求が優先する）。PRESENTはコンポーネント違反、ABSENTは違反なし、UNKNOWNはincomplete。Noticeは対象外。STALE_RELEASEを要求しつつ閾値をnullにする設定は矛盾としてexit 2。
- `max_unknown_ratio`は`unknown/in_scope > threshold`のとき違反。`in_scope=0`では比率0とする。
- 例外はコンポーネント単位のCI失敗だけを抑制。全体のUNKNOWN率／scan incompleteを免除しない。

## 9. CLI仕様・終了コード

```bash
eolscan scan -i sbom.cdx.json --format table
eolscan scan -i sbom.cdx.json -c eol-policy.ci-strict.yaml --format json -o report.json
eolscan scan --input sbom.spdx.json --offline --as-of 2026-10-11
eolscan policy validate --config eol-policy.example.yaml
eolscan providers list
eolscan version
```

| オプション | 意味 |
|---|---|
| `scan -i, --input` | 必須。ファイルまたは`-`でstdin |
| `-c, --config` | 任意。省略時はReport-first |
| `-f, --format` | `table`既定／`json` |
| `-o, --output` | 省略時stdout。ファイル出力は一時ファイルから原子的置換 |
| `--as-of` | UTC日付。既定は実行時点のUTC暦日 |
| `--offline` | 外部HTTPを行わずローカルcatalog／使用可能なdisk cacheだけ利用 |
| `--no-cache` | disk cache無効（`--offline`と併用禁止） |
| `--verbose` | stderrに診断ログ。トークンと秘密値はマスク |

| Exit | 条件 |
|---|---|
| `0` | 実行完了、CI違反なし。**UNKNOWN／MEDIUM EOL／不完全が残っていても既定では0** |
| `1` | 設定されたCI Gate違反（EOL、UNKNOWN率など） |
| `2` | 入力、設定、対応外Schema版など利用者修正可能エラー |
| `3` | `ci.fail_on_incomplete_scan=true`かつ、他の明確なポリシー違反がない不完全スキャン |
| `4` | 想定外の内部エラー |

優先順位：`2/4`（処理不能）`> 1`（明確な違反）`> 3`（不完全）`> 0`。`ci_gate.incomplete=true`でかつEOL violationがある場合はexit 1、両方レポートに残す。

## 10. レポートJSON 2.0契約

`../schemas/report.schema.json`と本書を一致させ、`../examples/report.example.json`を有効な完全サンプルとする。Schemaは構造を検証し、日付比較・参照ID・集計等は追加の意味検証で確認する。

### 10.1 結果構造

```text
Report {
  schema_version: "2.0", tool_version, as_of, projection, generated_at,
  input_sha256, policy_hash,
  summary: {in_scope, excluded, eol, supported, unknown,
            assessment_coverage, provider_error_count, ci_failure_count},
  ci_gate: {passed, violation_codes, incomplete},
  results: ComponentResult[]
}
ComponentResult {
  source_ref, purl, name, version,
  version_verification: VersionVerification,  # 必須
  lifecycle: EOL | SUPPORTED | UNKNOWN,
  confidence: HIGH | MEDIUM | null,
  eol_effective_date: date | null,
  matched_cycle: string | null,
  signals: SignalEvidence[],                  # PRESENTの根拠のみ
  signal_evaluations: SignalEvaluation[],      # PRESENT/ABSENT/UNKNOWN
  selected_evidence_ids: string[],             # UNKNOWNなら空
  notices: Notice[],                          # EOL_SOONはここ
  unknown_reasons: string[],
  rule_ids: string[],
  evidence: LifecycleEvidence[],              # 全必須フィールドを保持
  diagnostics: Diagnostic[],
  incomplete: bool,
  ci_failure: bool,
  exception_applied: bool
}
```

### 10.2 不変条件

1. `in_scope == eol + supported + unknown`。
2. `assessment_coverage == (eol + supported) / in_scope`（0件なら0）。
3. `lifecycle=UNKNOWN`は`confidence=null`、`eol_effective_date=null`、`unknown_reasons`が1件以上。
4. `lifecycle!=UNKNOWN`は`version_verification.status=VERIFIED`、`confidence in [HIGH,MEDIUM]`、`eol_effective_date`あり、採用根拠が少なくとも1件。
5. `SUPPORTED`を出す場合、採用Evidenceは公式Window・upstream_securityで評価日が期間内。一般EOLからEOLを出す場合は製品・PURL・系列・範囲が一致し、実行日に有効なレビューを必須とする。VERIFIEDには公開日時を必須とする。
6. `notices[].type=EOL_SOON`は`SUPPORTED`の場合のみ存在。`Notice.evidence_id`は存在するLifecycleEvidenceの`id`を参照。
7. `evidence[]`の全フィールドを出力する。任意ではなくnullableに指定した属性も必ずキーを出し`null`とする。
8. `ci_gate.passed=false`なら`violation_codes`非空。`ci_gate.incomplete=true`と`passed=true`は**report-firstでは許容**。
9. `ci_failure_count`はコンポーネント単位で例外を適用した後の失敗件数。全体条件の失敗は`violation_codes`に記載。
10. JSONはEvidence・Unknownを削除しない。`output.include_unknown/include_evidence`はtableの表示制御だけに適用する。
11. `results[]`はPURL（nullは最後）、`source_ref`で安定ソート。各配列内の要素は安定キーで重複排除する。元SBOMの別コンポーネントの結果は同一PURLでも削除しない。
12. selected_evidence_idsとNotice.evidence_idは出力Evidenceに存在し、採用IDは期限・Tier・矛盾の検証を通過している。UNKNOWNでは採用IDは空。
13. CI必須SignalのUNKNOWNはresult.incomplete=trueを要求する。PRESENT評価には同種のsignals[]根拠が必要。
14. reportのgenerated_atが実行開始時刻run_started_atであり、期限検証と版公開日時の実行時点確認に使用する。完了時刻が必要ならログへ出す。

### 10.3 Evidence JSONの必須フィールド

**LifecycleEvidence:** `id`, `provider_id`, `source_class`, `claim`, `package_purl`, `product_slug`, `matched_cycle`, `support_scope`, `support_start_date`, `eol_effective_date`, `source_url`, `source_field`, `observed_at`, `source_updated_at`, `reviewed_at`, `valid_until`, `raw_payload_hash`, `confidence`, `rule_id`, `general_eol_review`, `superseded_by`, `supersession_source_url`。

**SignalEvidence:** `type`, `provider_id`, `source_url`, `observed_at`, `details`。

**SignalEvaluation:** `type`, `status`, `provider_id`, `source_url`, `checked_at`, `reason_code`。

**Notice:** `type`, `days_remaining`, `evidence_id`, `rule_id`。

**VersionVerification:** `status`, `provider_id`, `source_url`, `checked_at`, `published_at`, `reason_code`。

**VersionAssertion:** `package_purl`, `published_at`, `source_url`, `reviewed_at`, `valid_until`。

**GeneralEolReview:** `id`, `product_slug`, `package_purl`, `matched_cycle`, `support_scope`, `evidence_url`, `reviewed_at`, `valid_until`。

**Diagnostic:** `code`, `provider_id`, `http_status`, `retryable`, `message`。

`report.example.json`は架空のFixtureに基づく有効サンプル。個々のEvidence項目を省略しない。

## 11. HTTP・メモ化・永続キャッシュ

### 11.1 HTTP

- 許可Host：`endoflife.date`、`api.deps.dev`（設定`base_url`を変更する場合もTLSとnetwork.allowed_hostsへの明示登録が必要。HTTPへ無条件に送信しない）。
- timeout 8秒／request、最大2回retry（429、5xx、短期的ネットワーク障害のみ）。`Retry-After`尊重、指数バックオフ。404は再試行なし。
- 全Provider通算max concurrency 6。`PURL`と`product slug`をキーにin-flightを重複排除。
- endoflife.dateのHTTP 304はdisk cacheが有効な場合のみ既存内容と結合。キャッシュなしで304は異常診断。
- レスポンスSchema不整合は`PROVIDER_SCHEMA_MISMATCH`。成功扱いしない。

### 11.2 キャッシュ

| 種別 | MVP既定 | 仕様 |
|---|---|---|
| インメモリ・リクエストメモ | **必須・常時ON** | 1スキャン内の同一PURL・製品slugを再照会しない。プロセス終了で消去 |
| ファイルベース永続キャッシュ | **任意・既定OFF** | `cache.enabled=true`にした場合のみ使用。DB不要 |

永続キャッシュの内容は、許可Host・APIパス・正規化照会キー・レスポンスschema版でハッシュ化し、OS標準のcache dirに保存する。正常200はTTL 24h、確定的404は6h、429/timeout/5xxは保存しない。保存先は安全な権限で作成。`--offline`はネットワーク完全禁止：catalogや有効なdisk cacheだけで版検証・EOL判断する。**cache既定OFFでcatalogにも版アサーションがないオフライン実行では、多くがUNKNOWNになってよい。**

ディスクcacheが期限切れの場合はオンラインで再取得。offlineでTTL超過・最大証拠年齢内なら使用してCACHE_STALE診断を残す。最大証拠年齢を超えた場合はSTALE_EVIDENCEで使用不可。年齢はrun_started_atと取得時刻の差で計算し、as_ofを基準にしない。カタログの期限は各項目`valid_until`に従い、外部動的APIは`decision.max_evidence_age_days`も適用。

## 12. セキュリティ・監査・観測

- SBOM input既定50MiB上限、コンポーネント100,000件上限、JSON深度上限を設定。超過はexit 2。
- Providerが組み立てた固定host URLだけGET可能。カタログの`evidence_url`は出力用であり自動fetchしない。
- 外部HTTPへのリクエストでPURL等が外部送信されることをREADMEと`--help`で明示。`--offline`では確実にHTTPゼロ。
- 出力にAPI key/Authorizationを含めず、stderrログと証拠URLからも削除。`input_sha256`は元ファイルbytesに対するSHA-256。
- metrics：`in_scope, eol, supported, unknown, assessment_coverage, provider_error_count, incomplete_component_count, version_unverified_count, version_not_found_count, cache_hit_count, ci_failure_count`。
- アプリの公開リリースにはポリシー版、Schema、固定Fixture、依存ツールの版を記録する。

## 13. テスト設計（必須受け入れ条件）

| Test | Fixture | 期待結果 |
|---|---|---|
| UT-01 | verified版＋公式Security Window、終了日前 | SUPPORTED/HIGH |
| UT-02 | verified版＋公式Security Window、終了日当日 | EOL/HIGH |
| UT-03 | verified版＋公式Security End、終了日前 | UNKNOWN（SUPPORTED禁止） |
| UT-04 | verified版＋endoflife.date一般的EOL日、終了日前 | UNKNOWN/GENERAL_EOL_ONLY、SUPPORTED禁止 |
| UT-05 | verified版＋有効な意味レビュー＋一般的EOL日、終了日当日 | EOL/MEDIUM |
| UT-06 | `isMaintained=true`のみ | UNKNOWN、SUPPORTED禁止 |
| UT-07 | `isMaintained=true`かつ一般EOL日を過ぎた | upstream EOLの判断にbooleanを混ぜない |
| UT-08 | 不存在の`7.2.9999`が系列7.2に一致する | UNKNOWN/VERSION_NOT_FOUND_IN_INDEX |
| UT-09 | deps.dev版照会タイムアウト | UNKNOWN/VERSION_UNVERIFIED、incomplete=true |
| UT-10 | カタログの`verified_versions`完全一致 | VERIFIED（オンライン不要） |
| UT-11 | 過去のas_ofより版公開が未来 | UNKNOWN/NOT_RELEASED_AS_OF |
| UT-12 | `7.2`と`7.20`の系列境界 | 誤照合しない |
| UT-13 | `/identifiers/purl`→一致製品2件のみ詳細GET | `/products/full`ゼロGET、必要な製品だけGET |
| UT-14 | PURLが索引に存在しない | UNKNOWN／曖昧な名称検索禁止 |
| UT-15 | 索引1PURLに複数製品 | UNKNOWN/AMBIGUOUS_IDENTITY |
| UT-16 | 同格のEOL日不一致 | UNKNOWN/CONFLICT（設定で変更不可） |
| UT-17 | OFFICIALとCURATEDの状態不一致 | OFFICIAL優先、SOURCE_DISAGREEMENT |
| UT-18 | EOLまで90日・Security Windowあり | SUPPORTED＋`notices:EOL_SOON`、signalsには入れない |
| UT-19 | 一般EOL未来まで90日・Security Windowなし | UNKNOWN、EOL_SOONなし |
| UT-20 | EOL/MEDIUM、report-first | exit 0。レポートにはEOLを表示 |
| UT-21 | EOL/MEDIUM、Strict | exit 1 |
| UT-22 | 必須API障害、report-first | incomplete=true、exit 0（ほか違反なし） |
| UT-23 | 必須API障害、Strict、UNKNOWN率違反なしの4件中1件UNKNOWN | incomplete=true、exit 3 |
| UT-24 | API障害＋Strictで別コンポーネントEOL | exit 1、incompleteもtrue |
| UT-25 | `unknown_on_same_tier_conflict`旧設定キー | exit 2（未知キー） |
| UT-26 | Notice/Evidenceの必須フィールド欠落 | JSON Schema検証エラー |
| UT-27 | disk cache OFF | ファイルを書かずメモ化は動く |
| UT-28 | offline＋cache OFF＋カタログ版証明なし | HTTPゼロ、UNKNOWN |
| UT-29 | 有効な期限付き例外でEOL/HIGH | EOL保持、CI failureだけ抑止 |
| UT-30 | 同一PURLがSBOMに3回 | Provider照会1回、結果3件 |
| UT-31 | 未来`as_of`のEOL見通し | projection=true。未来の版存在を推定しない |
| UT-32 | 同梱default/strict設定＋catalog＋report | 対応Schemaで全件validation成功 |
| UT-33 | 同格公式Endが10月1日・12月1日、as_of=10月11日 | UNKNOWN/CONFLICT、未来根拠を除外しない |
| UT-34 | 上位公式Endは未来、下位レビュー済み一般EOLは過去 | UNKNOWN、下位EOLへフォールバックしない |
| UT-35 | 一般EOL経過だがレビュー0件 | UNKNOWN/GENERAL_EOL_UNREVIEWED、元Evidence保持 |
| UT-36 | レビューの系列・範囲不一致または期限切れ | 一般EOLを採用しない |
| UT-37 | 正式な撤回証明のある古い根拠 | 元Evidence保持、比較集合からだけ除外 |
| UT-38 | CI必須STALE_RELEASEのAPI障害・公開日欠落・取得手段なし | UNKNOWN評価、incomplete=true |
| UT-39 | CI必須Signalの代替データで正常な否定確認 | ABSENT、当該照会のincomplete=false |
| UT-40 | 任意Signal失敗、Lifecycle確定、CIでは要求なし | 診断保持、当該照会のincomplete=false |
| UT-41 | ローカルVersionAssertionに公開日時欠落 | カタログSchemaエラー（exit 2） |
| UT-42 | deps.dev公開日時欠落、代替証明なし、現在日のas_of | UNVERIFIED、UNKNOWN、incomplete=true |
| UT-43 | 過去as_of、ローカル版証明は実行日時点で失効 | VERIFIEDにしない。過去日に戻して復活させない |
| UT-44 | UTC同日公開、タイムゾーン付き公開日時 | UTC暦日で比較し、同日公開は評価対象 |
| UT-45 | ci必須Signal UNKNOWNだがfail_on_incomplete_scan=false | incompleteを報告、他違反なしならexit 0 |

外部API依存テストは固定レスポンスFixtureを用いて、毎回のlive API接続をCI必須にしない。OpenAPIとの互換性確認は別のIntegration jobとする。

## 14. 開発順序／Definition of Done

**Phase 1 — 型と判定器:** 入力Parser、PURL、VersionVerification型、LifecycleEvidence／Signal／Notice分離、Evaluator、Schema、UT-01–12。すべてFixture。

**Phase 2 — Provider:** カタログ、deps.dev GetVersion、endoflife.date PURL索引→詳細、同一キーmemo、API障害、UT-13–19。

**Phase 3 — CIと品質:** default/strict、Exit、例外、offline、任意disk cache、JSON出力、Schema検証、UT-20–45。

DoD：全45テスト通過／`SUPPORTED`すべてにSecurity Window Evidenceあり／Lifecycleすべてに`VERIFIED`版あり／Reportと同梱Schema整合／不完全scan診断あり／ネットワーク・SSRF・秘密情報非露出の確認／READMEに既定report-firstを明示。

## 15. 例外と保留事項

### 15.1 例外ファイル

`eol-exceptions.example.yaml`に従い、`package_purl`の完全一致、`reason`、`owner`、`expires_on`を必須とする。期限超過は無視し`EXPIRED_EXCEPTION`診断。例外はLifecycleやUNKNOWN率を変更しない。

### 15.2 本仕様で意図的に保留する事項

- 実在製品の一般EOLレビューの収集・維持。初期同梱データは0件、サンプルは架空製品だけ。未レビュー製品をEOL確定に使わない。
- バイナリ配布先、データソースレート制限に合わせた数値チューニング。実装はGo 1.24以上。
- endoflife.date実レスポンスがOpenAPI記載と差異を持つ場合のAdapter修正（Schema不整合を成功扱いにしない）。
- private registryとディストリビューションによるバックポート対応。

これらは本仕様のLifecycle不変条件を緩める理由にはならない。

## 16. 参照資料（確認日：2026-10-11）

1. endoflife.date v1 OpenAPI：<https://github.com/endoflife-date/endoflife.date/blob/master/api_v1/openapi.yml>
2. endoflife.date API v1：<https://endoflife.date/docs/api/v1/>
3. deps.dev GetVersion：<https://docs.deps.dev/api/v3/>
4. PURL specification：<https://github.com/package-url/purl-spec>
5. CycloneDX JSON：<https://cyclonedx.org/docs/1.7/json/>
6. SPDX 2.3：<https://spdx.github.io/spdx-spec/v2.3.1-dev/>

## 17. 同梱成果物と契約検証

- 設定: `../schemas/policy-input.schema.json`（差分入力）、`../schemas/policy.schema.json`（既定補完後）。
- カタログ: `../schemas/support-catalog.schema.json`。版証明と一般EOLレビューを含む。
- 例外: `../schemas/exceptions.schema.json`。
- 共通型／レポート: `../schemas/common.schema.json`、`../schemas/report.schema.json`。
- 設定・カタログ・例外・レポート例: `../examples/`。
- `../scripts/validate_design.py`は固定した実行日時のサンプルとSchemaを検証する。Go CLIの仕様適合は別途Goの受け入れテストとCLI Fixtureテストで検証する。

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

**実装担当への重要な注意:** 未レビュー一般EOLでEOLを作る、未来の終了日を矛盾検出前に捨てる、公開日時なしでVERIFIEDにする、CI必須SignalのUNKNOWNをABSENTにするコードは仕様違反。EOL_SOONはNoticeであり、SUPPORTEDは公式Security Windowだけから導出する。
