# Detection validation on real packages

## Recorded result

On **2026-10-17 JST**, eolscan **0.6.0** evaluated **47 actual public package versions across all seven supported ecosystems**: 36 independently reviewed retirement/deprecation targets, ten default-policy controls, and one separate inactivity candidate (nose).

| Policy profile | Retirement targets detected | Other results | Scanner exit |
| --- | ---: | --- | ---: |
| Default EOL criteria | **34/36** | All ten controls NO_EOL_DETECTED; nose UNKNOWN | 0 |
| Default plus release inactivity over 730 days | **36/36** | nose, is-number, and pathlib2 also EOL; eight other controls NO_EOL_DETECTED | 1 |
| Publisher declarations only (nine selected versions) | **7/7** | Both controls NO_EOL_DETECTED | 1 |

All 47 exact versions were verified. The default report has 34 EOL, ten NO_EOL_DETECTED, and three UNKNOWN results. PyCrypto, Commons HttpClient, and nose remain incomplete under default rules. The inactivity report has 39 EOL, eight NO_EOL_DETECTED, no UNKNOWN, and no incomplete result. All observed EOL results have MEDIUM confidence.

The default HIGH confidence CI threshold reports EOL warnings without failing; the other profiles select MEDIUM and fail for detected EOL. The validator itself still exits 1 because the two reviewed default misses remain unmet goals. A scanner exit of 0 is not evidence that all targets were detected.

These are deliberately selected diagnostic examples, **not an estimate of recall on arbitrary SBOMs**. A default-policy control means the selected criteria should not flag that package; it does not certify security support. Release inactivity deliberately changes that criterion: old but non-deprecated is-number and pathlib2 match the opt-in threshold.

## Improvement against the original sample

The original 0.5.0 observation detected **24/30** targets by default. On those same 30 targets, 0.6.0 detects **28/30** by default and **30/30** with the inactivity rule.

| Previously missed package | Default in 0.6.0 | Acquired criterion |
| --- | --- | --- |
| Struts 2.3.37 | EOL | Matching 2.3 series ended; general Support phase accepted. |
| Spring 4.3.30.RELEASE | EOL | Stable Maven qualifier resolves to 4.3; elapsed OSS support cutoff accepted. |
| Log4j 1.2.17 | EOL | Matching 1.x general support cutoff accepted. |
| pep8 1.7.1 | EOL | Exact PyPI description explicitly says fixes are released only under pycodestyle. |
| PyCrypto 2.6.1 | UNKNOWN | No usable publisher source-repository mapping or retirement marker in queried metadata. The opt-in release inactivity rule detects it. |
| Commons HttpClient 3.1 | UNKNOWN | No applicable feed entry or usable source mapping. The upstream website declares EOL, but this adapter does not extract arbitrary website notices. Release inactivity detects it. |

The general EOL rule no longer requires proof that security support ended. The original phase, URL, cutoff when supplied, and payload hash remain in the report. Formal security assessment remains separate. Log4j's feed cutoff (2015-10-15) differs from [Apache's EOL announcement](https://logging.apache.org/log4j/1.x/); the tool retains the feed's stated date and does not present it as an official date.

## Publisher declaration coverage

The isolated declarations profile disables support-date classification and removes archival/deprecation rules. Each positive result therefore requires DECLARED_UNMAINTAINED; being archived cannot make this profile pass.

| Package | Independently reviewed declaration | Result |
| --- | --- | --- |
| [pep8 1.7.1](https://pypi.org/project/pep8/) | Distribution replaced by pycodestyle; fixes published only under the new name. | EOL |
| [sklearn 0.0.post12](https://pypi.org/project/sklearn/0.0.post12/) | Publisher deprecates the placeholder distribution and directs users to scikit-learn. | EOL |
| [pathlib 1.0.1](https://pypi.org/project/pathlib/1.0.1/) | Publisher says the backport is no longer maintained. | EOL |
| [cbor 0.4.1](https://github.com/BurntSushi/rust-cbor) | Original README declares the project unmaintained. | EOL |
| [jasmine-rails 0.15.0](https://github.com/testdouble/jasmine-rails) | Maintainer says the project is no longer actively maintained; old repository URL redirects. | EOL |
| [better_html 2.1.1](https://github.com/Shopify/better-html) | Deprecation in an HTML heading; development ended, with only possible best-effort critical security patches. | EOL |
| [liquid-c 4.2.0](https://github.com/Shopify/liquid-c) | Bold quoted warning explicitly ends maintenance. | EOL |
| [pathlib2 2.3.7.post1](https://pypi.org/project/pathlib2/2.3.7.post1/) | Its description discusses the retired predecessor pathlib; that statement must not retire pathlib2. | NO_EOL_DETECTED |
| [orjson 3.11.3](https://github.com/ijl/orjson) | Active-project control with platform/dependency support discussions. | NO_EOL_DETECTED |

The live checks exposed two real parser misses: HTML retirement headings and bold quoted warnings. Both were corrected and re-scanned. Default matching is still bounded English pattern matching, not a general interpretation of every maintenance notice. Custom expressions, source limitations, thresholds, and failure semantics are documented in [EOL criteria](eol-rules.md).

## Coverage by ecosystem

| Ecosystem | Retirement targets | Detected by default | Controls without default EOL |
| --- | ---: | ---: | ---: |
| npm | 8 | 8 | 2 |
| gem | 7 | 7 | 1 |
| pypi | 6 | 5 | 3 |
| golang | 3 | 3 | 1 |
| cargo | 4 | 4 | 1 |
| maven | 4 | 3 | 1 |
| nuget | 4 | 4 | 1 |
| Total | 36 | 34 | 10 |

## Execution and evidence

Inputs contain only package identities and versions, with no injected repository mapping, end date, or local support catalog. Public API responses were fetched by the normal online CLI on October 17 JST, then shared by the three profiles using the supported file cache. Re-scans after parser corrections reused those same-day responses. Detection criteria in the default profile are unchanged from built-in defaults; its only policy override enables the cache. This is not an offline reconstruction of an earlier support policy.

The CLI's evaluation date is **2026-10-16 UTC**, the current UTC date during execution on October 17 in Japan. No `--as-of` override was used, so current status flags were eligible. GitHub authentication used the already configured account credential through EOLSCAN_GITHUB_TOKEN, passed in process memory; no token was logged or persisted. The validation script itself does not retrieve gh credentials.

One optional provider diagnostic remains: deps.dev returned VERSION_CONFLICT for sklearn's exact-version fallback. Native PyPI independently verified that version, and its publisher declaration establishes EOL. This diagnostic is retained in the reports; it is not silently counted as a successful source lookup.

[Recorded observations](../testdata/real-packages/observations/2026-10-17/) contain unmodified CLI reports, stderr, execution receipts, complete effective policies, input/manifest snapshots, binary and report hashes, and the source commit. The [original 0.5.0 observations](../testdata/real-packages/observations/2026-10-15/) retain their original 39-case inputs and reports. Neither snapshot is a runtime lifecycle catalog.

## All default and inactivity outcomes

| Package/version and independent source | Role | Default | With inactivity |
| --- | --- | --- | --- |
| [request 2.88.2](https://github.com/request/request) | Target | EOL | EOL |
| [node-sass 9.0.0](https://sass-lang.com/blog/node-sass-is-end-of-life/) | Target | EOL | EOL |
| [har-validator 5.1.5](https://registry.npmjs.org/har-validator/5.1.5) | Target | EOL | EOL |
| [istanbul 0.4.5](https://registry.npmjs.org/istanbul/0.4.5) | Target | EOL | EOL |
| [glob 7.2.3](https://registry.npmjs.org/glob/7.2.3) | Target | EOL | EOL |
| [rimraf 3.0.2](https://registry.npmjs.org/rimraf/3.0.2) | Target | EOL | EOL |
| [left-pad 1.3.0](https://registry.npmjs.org/left-pad/1.3.0) | Target | EOL | EOL |
| [uuid 3.4.0](https://registry.npmjs.org/uuid/3.4.0) | Target | EOL | EOL |
| [picocolors 1.1.1](https://github.com/alexeyraspopov/picocolors) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [is-number 7.0.0](https://github.com/jonschlinkert/is-number) | Control | NO_EOL_DETECTED | EOL |
| [therubyracer 0.12.3](https://github.com/rubyjs/therubyracer) | Target | EOL | EOL |
| [sass 3.7.4](https://sass-lang.com/blog/ruby-sass-is-unsupported/) | Target | EOL | EOL |
| [thread_safe 0.3.6](https://github.com/ruby-concurrency/thread_safe) | Target | EOL | EOL |
| [rails 6.1.7.10](https://rubyonrails.org/2024/10/15/new-maintenance-policy-and-eol-annouments) | Target | EOL | EOL |
| [concurrent-ruby 1.3.5](https://github.com/ruby-concurrency/concurrent-ruby) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [pycrypto 2.6.1](https://github.com/pycrypto/pycrypto) | Target | UNKNOWN | EOL |
| [nose 1.3.7](https://nose.readthedocs.io/en/latest/) | Candidate | UNKNOWN | EOL |
| [django-rest-swagger 2.2.0](https://github.com/marcgibbons/django-rest-swagger) | Target | EOL | EOL |
| [pep8 1.7.1](https://pypi.org/project/pep8/) | Target | EOL | EOL |
| [django 2.2.28](https://www.djangoproject.com/weblog/2022/apr/11/security-releases/) | Target | EOL | EOL |
| [attrs 25.3.0](https://github.com/python-attrs/attrs) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [github.com/dgrijalva/jwt-go v3.2.0+incompatible](https://github.com/dgrijalva/jwt-go) | Target | EOL | EOL |
| [github.com/mitchellh/mapstructure v1.5.0](https://github.com/mitchellh/mapstructure) | Target | EOL | EOL |
| [github.com/boltdb/bolt v1.3.1](https://github.com/boltdb/bolt) | Target | EOL | EOL |
| [github.com/stretchr/testify v1.10.0](https://github.com/stretchr/testify) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [failure 0.1.8](https://github.com/rust-lang-deprecated/failure) | Target | EOL | EOL |
| [rustc-serialize 0.3.25](https://github.com/rust-lang-deprecated/rustc-serialize) | Target | EOL | EOL |
| [serde_yaml 0.9.34+deprecated](https://github.com/dtolnay/serde-yaml/releases) | Target | EOL | EOL |
| [serde 1.0.228](https://github.com/serde-rs/serde) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [log4j/log4j 1.2.17](https://logging.apache.org/log4j/1.x/) | Target | EOL | EOL |
| [org.apache.struts/struts2-core 2.3.37](https://struts.apache.org/struts23-eol-announcement) | Target | EOL | EOL |
| [org.springframework/spring-core 4.3.30.RELEASE](https://spring.io/blog/2019/12/03/spring-framework-maintenance-roadmap-in-2020-including-4-3-eol/) | Target | EOL | EOL |
| [commons-httpclient/commons-httpclient 3.1](https://hc.apache.org/httpclient-legacy/) | Target | UNKNOWN | EOL |
| [com.google.guava/guava 33.4.8-jre](https://github.com/google/guava) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [Microsoft.Azure.KeyVault 3.0.5](https://www.nuget.org/packages/Microsoft.Azure.KeyVault/3.0.5) | Target | EOL | EOL |
| [Microsoft.Azure.DocumentDB 2.22.0](https://www.nuget.org/packages/Microsoft.Azure.DocumentDB/2.22.0) | Target | EOL | EOL |
| [WindowsAzure.Storage 9.3.3](https://www.nuget.org/packages/WindowsAzure.Storage/9.3.3) | Target | EOL | EOL |
| [Microsoft.Azure.Management.Fluent 1.38.1](https://www.nuget.org/packages/Microsoft.Azure.Management.Fluent/1.38.1) | Target | EOL | EOL |
| [Newtonsoft.Json 13.0.3](https://github.com/JamesNK/Newtonsoft.Json) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| [sklearn 0.0.post12](https://pypi.org/project/sklearn/0.0.post12/) | Target | EOL | EOL |
| [pathlib 1.0.1](https://pypi.org/project/pathlib/1.0.1/) | Target | EOL | EOL |
| [cbor 0.4.1](https://github.com/BurntSushi/rust-cbor) | Target | EOL | EOL |
| [jasmine-rails 0.15.0](https://github.com/testdouble/jasmine-rails) | Target | EOL | EOL |
| [better_html 2.1.1](https://github.com/Shopify/better-html) | Target | EOL | EOL |
| [liquid-c 4.2.0](https://github.com/Shopify/liquid-c) | Target | EOL | EOL |
| [pathlib2 2.3.7.post1](https://pypi.org/project/pathlib2/2.3.7.post1/) | Control | NO_EOL_DETECTED | EOL |
| [orjson 3.11.3](https://github.com/ijl/orjson) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |

## Re-run

```sh
make validate-real-packages

# Choose a profile:
python3 scripts/validate_real_packages.py --profile default
python3 scripts/validate_real_packages.py --profile inactivity
python3 scripts/validate_real_packages.py --profile declarations

# Inspect recorded reports without network requests:
python3 scripts/validate_real_packages.py \
  --reports-dir testdata/real-packages/observations/2026-10-17 \
  --output-dir artifacts/real-packages-recorded
```

The live validator uses only the Python standard library and invokes the normal compiled CLI. `--profile all` is the default; `both` retains the older default/inactivity pair. It writes raw reports, stderr, execution receipts, and derived results. It exits 1 for unmet detection goals and 2 for run/validation errors; each original scanner exit is retained separately.

Results can change with source metadata, releases, cache freshness, and API availability. Live requests consume provider quota; explicit GitHub authentication is optional through EOLSCAN_GITHUB_TOKEN. Deterministic CI validates recorded schemas, input/report/policy hashes, case correspondence, and CI decisions without public requests. These checks protect evidence integrity and do not claim complete real-world detection.
