# eolscan

eolscanは、SBOMを入力に、上流のセキュリティ修正サポートの終了状況を調べるGo CLIです。[v0.3の設計](docs/EOL_Checker_Design_v0.3.md)に対応しています。

データベースは不要です。同じAPI照会は実行中のメモリにまとめます。ディスクキャッシュは既定で無効です。Go 1.24以上でビルドし、実行時は単一バイナリを使用します。

## ビルドと実行

```sh
go build -o bin/eolscan .

./bin/eolscan scan -i sbom.cdx.json
./bin/eolscan scan -i sbom.spdx.json -f json -o report.json
cat sbom.cdx.json | ./bin/eolscan scan -i - -f json
./bin/eolscan policy validate -c examples/eol-policy.ci-strict.yaml
./bin/eolscan providers list
```

入力はCycloneDX JSON 1.4–1.7とSPDX 2.3 JSONです。PURLで識別し、gem、npm、pypi、maven、golang、cargo、nugetを扱います。版が欠けたコンポーネントも捨てず、UNKNOWNとして報告します。CycloneDXのmetadata.componentは既定で除外されます。

初期試作のCLI・出力との互換性はありません。新しいコマンドは `scan -i ...`、設定の契約版は2、JSONレポートは2.0です。Syft独自JSON、CPE、OS名の照合とレジストリ直接照会はこのMVPの範囲外です。Syftを使用する場合はCycloneDXまたはSPDX JSONを入力してください。

## 判定の意味

| Lifecycle | 意味 |
| --- | --- |
| `EOL` | 上流のセキュリティ修正サポート終了を確認 |
| `SUPPORTED` | 公式の明示的なセキュリティサポート期間が評価日を含む |
| `UNKNOWN` | 版の実在・公開日時・適用できるサポート根拠を十分に確認できない |

Lifecycleとメンテナンスシグナルは独立しています。非推奨や更新停止からEOLを断定しません。シグナルは `PRESENT / ABSENT / UNKNOWN` の3値で報告します。`EOL_SOON` はSUPPORTEDの終了予定から導くNoticeです。

**既定のカタログと一般EOLレビューは0件です。** endoflife.dateの一般EOL日だけではEOL／SUPPORTEDを確定しません。レビューを登録していない通常のオンライン実行では、多くがUNKNOWNになります。

| データ源 | 役割 |
| --- | --- |
| ローカルのサポートカタログ | レビュー済みの公式サポート期間・終了日、正確な版の公開日時、一般EOLの意味レビュー |
| [endoflife.date API v1](https://endoflife.date/docs/api/v1/) | PURL索引を1回取得し、一致した製品の一般EOL日だけ取得 |
| [deps.dev API v3](https://docs.deps.dev/api/v3/) | 完全一致する版と公開日時、取得できる非推奨情報と公開版一覧 |

版がdeps.devの索引に見つからない場合はUNKNOWNです。公開日時が欠落した場合も、別の有効なローカル版証明がなければUNKNOWN／不完全です。RubyGemsを含む公開レジストリへの直接問い合わせは実装せず、公開レジストリ由来の情報をdeps.dev経由で参照します。

`DEPRECATED` は明示的なtrueを肯定根拠として使います。正常な否定確認は、npmで明示的なfalseが返る場合に限ります。他のエコシステムのfalseやフィールド欠落はUNKNOWNです。PyPIのproject status、Go retract、GitHubのArchivedなどは将来対応であり、CIで要求すると現状はUNKNOWN／不完全になります。

`STALE_RELEASE` は公開日の揃った版一覧から評価日までの最新公開日を求めます。欠損や未来の評価日はUNKNOWNです。deps.devはGo／PyPIに収集範囲の制限を明記しているため、この2種類では完全な版一覧を前提とするSTALE_RELEASEの判定を保留します。

## カタログを使う

設定はビルトイン既定値へ再帰マージできます。相対パスは設定ファイルの場所を基準に解決します。

```yaml
schema_version: 2
sources:
  official_catalog:
    enabled: true
    path: ./support-catalog.yaml
```

カタログは次の3配列を持ちます。完全な型と記載例は[サンプル](examples/support-catalog.example.yaml)と[Schema](schemas/support-catalog.schema.json)を参照してください。

- `entries`：公式のSecurity WindowまたはSecurity End。適用系列、出典URL、レビュー日、有効期限を必須にします。
- `verified_versions`：正確なversion付きPURLと公開日時。オフラインの版確認や、deps.devに情報がない版の代替に使います。
- `general_eol_reviews`：製品slug・versionなしPURL・リリース系列・サポート範囲が完全一致する一般EOLの意味レビュー。

公式根拠はHIGH、レビュー済み一般EOLはMEDIUMです。未レビュー／期限切れの一般EOLはEvidenceへ残し、判定には使いません。一般EOLが未来でもSUPPORTEDにはしません。同格の終了日が違えば、未来の根拠も含めてUNKNOWN／CONFLICTにします。正式な更新・撤回の証明がある根拠だけを比較から除外できます。

同梱の製品・レビュー・版証明は**架空の検証データ**です。動作例：

```sh
./bin/eolscan scan \
  -i examples/fixtures/supported.cdx.json \
  -c examples/eol-policy.catalog.example.yaml \
  --offline --as-of 2026-10-11
```

この例はSUPPORTED/HIGHを返します。サンプルのレビュー・版証明は2026-12-01まで有効です。期限の評価には実行日のUTC日付を使うため、期限後に過去の `--as-of` を指定しても復活しません。実運用のカタログには、確認した実際の根拠を登録してください。

## CIで使う

既定はreport-firstです。EOL/HIGHでのみ失敗し、UNKNOWN、EOL/MEDIUM、API障害による不完全はレポートに残します。

```sh
./bin/eolscan scan \
  -i sbom.cdx.json \
  -c examples/eol-policy.ci-strict.yaml \
  -f json -o report.json
```

Strict設定はMEDIUM以上のEOL、不完全スキャン、UNKNOWN率が0.25を超えた場合に失敗します。一般EOLの意味レビューや公式根拠は、Strict設定でも別途カタログへ登録する必要があります。

CIで使用するシグナルの照会は必須です。

```yaml
schema_version: 2
ci:
  fail_on_signals: [STALE_RELEASE]
  fail_on_incomplete_scan: true
```

この設定で更新停止を確認した場合はexit 1、正常な否定確認ならexit 0、照会できない場合は不完全としてexit 3になります。他の明確なポリシー違反もあればexit 1を優先します。

| Exit | 意味 |
| --- | --- |
| 0 | 設定したCI条件を通過。不明・不完全の有無はレポートで確認 |
| 1 | コンポーネントのCI違反、またはUNKNOWN率の超過 |
| 2 | 入力・設定・出力エラー |
| 3 | 必須検査が不完全で、ほかの明確なCI違反はない |
| 4 | 内部エラー |

CIではビルドしたバイナリを実行してください。`go run` はプログラムの終了コードをそのまま返さないため、コード1と3の区別には使えません。

[期限付き例外](examples/eol-exceptions.example.yaml)は `exceptions.path` で指定します。正確なPURLに一致するコンポーネントのCI失敗だけを抑制し、Lifecycle、UNKNOWN率、不完全の報告は維持します。

## オフライン・キャッシュ・出力

- `--offline`：HTTPを行わず、ローカルカタログと有効なディスクキャッシュを使います。
- `cache.enabled: true`：OS標準のcache dir配下の `eolscan/v2` へ、正常200／404だけを保存します。DBは不要です。
- `--no-cache`：永続キャッシュを無効にします。`--offline` との併用は設定エラーです。
- オンラインではTTL超過のキャッシュを更新します。オフラインでは最大証拠年齢以内のTTL超過データを `CACHE_STALE` 付きで使い、それ以上古いデータは採用しません。
- `--as-of YYYY-MM-DD`：UTC暦日で評価します。未来の評価は `projection: true` になります。公開日前の版はUNKNOWNです。
- JSONは全コンポーネント・Evidence・診断・CI結果を保持します。ファイル出力は一時ファイルから原子的に置換します。`output.include_unknown/include_evidence` はtableの表示だけを制御します。

オンラインではパッケージ名と版を許可した公開APIへ送信します。SBOMや出典に書かれた任意のURLは取得しません。接続先は明示的な許可ホストのHTTPSに限定し、認証情報やクエリ付きの設定URLは拒否します。

## 開発と検証

```sh
go test -race ./...
go vet ./...
go build -o bin/eolscan .
```

設計のUT-01〜45をGoテストで確認し、10件のレポートFixtureを実際のCLIから生成して、判定・終了コード・入力ハッシュ・設定ハッシュを照合します。外部APIは固定レスポンスとローカルHTTPSサーバーで代替するため、テスト時の公開API接続は不要です。

Schemaはバイナリへ埋め込み、設定と出力を検証します。ドキュメントとサンプルの追加検証はPythonで実行できます。PythonはCLIの実行時依存ではありません。

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

[設計・Schema・固定ケース一覧](docs/README.md)も同梱しています。過去時点のサポートポリシーの完全な再現には、外部Evidenceの固定スナップショットが必要です。
