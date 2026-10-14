# Detection validation on real packages

## Recorded result

On **2026-10-15 JST**, the actual eolscan 0.5.0 executable scanned **39 public package versions across all seven supported ecosystems**. Upstream announcements, publisher registry metadata, and repository archival were reviewed independently of the scanner's classification.

The default policy detected **24 of 30 retirement/deprecation targets**. Four targets were `UNKNOWN`; two were `NO_EOL_DETECTED`. All eight default-policy controls were `NO_EOL_DETECTED`. One separate inactivity candidate, nose, was `UNKNOWN`.

Adding a **730-day release inactivity rule** detected four of the six missed targets and nose. Struts 2.3 and Spring 4.3 remained undetected. Across the two profiles, **28 of 30 targets** were detected. The inactivity profile also classified the old, non-deprecated is-number project as EOL, illustrating how a configurable maintenance threshold changes the meaning of EOL.

**The tool still misses known ended release series.** This validation does not support a claim of complete EOL detection.

| Ecosystem | Retirement/deprecation targets | Detected by default | Controls without EOL |
| --- | ---: | ---: | ---: |
| npm | 8 | 8 | 2 |
| RubyGems | 4 | 4 | 1 |
| PyPI | 4 | 2 | 1 |
| Go | 3 | 3 | 1 |
| Cargo | 3 | 3 | 1 |
| Maven | 4 | 0 | 1 |
| NuGet | 4 | 4 | 1 |
| Total | 30 | 24 | 8 |

The corpus deliberately includes ordinary libraries, older versions of active projects, archived projects, and ended framework series. It is a selected diagnostic sample, not a representative SBOM or an estimate of recall on arbitrary dependencies. Controls check for an unwanted EOL result under the selected policy; they do not certify security support for their exact versions.

The 30 targets have different evidence:

- Eight have explicit upstream support-end/EOL announcements. Four were detected by default.
- Eleven have publisher registry deprecation. All eleven were detected by default.
- Four have explicit upstream retirement or replacement announcements. Three were detected by default.
- Seven have archived upstream repositories. Six were detected by default.

These categories are recorded in the manifest. Registry deprecation and source archival establish policy-based maintenance EOL, not a dated security-support commitment. nose is an inactivity candidate, excluded from the 30-target denominator: its documentation recommends alternatives and warns about maintenance, without establishing a dated security EOL.

## What was run

The default profile used the built-in policy, automatic public data retrieval, no local support catalog, and no persistent cache. The input contains only actual package identities and versions; it supplies no manually added source repository or EOL date. All **39 exact versions were verified**, and the scan reported **zero provider errors**.

The default report contains 24 EOL results, five UNKNOWN results, and ten NO_EOL_DETECTED results. Its `incomplete` flag is true because some required archival checks could not be completed. All 24 EOL results have MEDIUM confidence: 22 match maintenance rules, and two use automatically retrieved security-support dates (Rails and Django).

The scanner emitted a warning for 24 EOL components and exited **0**, consistent with its default HIGH confidence CI threshold. EOL warnings and CI failure are separate decisions.

The inactivity profile scanned the six misses, nose, and three controls. It retained the default deprecation/archive rules, added `STALE_RELEASE` with a 730-day threshold, and set `ci.min_confidence: MEDIUM`. It produced six EOL and four NO_EOL_DETECTED results, with no UNKNOWN or incomplete result, and exited **1**. Four EOL results recover retirement targets; the other two are nose and is-number.

The CLI uses UTC dates. The recorded scans' `as_of` is **2026-10-14**, which was the current UTC date during execution on October 15 in Japan. No historical `--as-of` value was supplied. Live registry and archival flags were therefore eligible.

## Six default misses

| Package | Independent upstream evidence | Default | With inactivity | Acquisition or decision gap |
| --- | --- | --- | --- | --- |
| pycrypto 2.6.1 | [Upstream repository is archived](https://github.com/pycrypto/pycrypto) | UNKNOWN | EOL | Exact PyPI metadata supplies only a non-repository homepage; deps.dev has no source links or related projects. The registry's project status does not report retirement. |
| pep8 1.7.1 | [Publisher says fixes are released only as pycodestyle](https://pypi.org/project/pep8/) | UNKNOWN | EOL | Exact metadata points to documentation, with no source mapping or registry retirement marker. The tool does not interpret the package description's retirement notice. |
| log4j:log4j 1.2.17 | [Apache declares Log4j 1.x EOL and no further security fixes](https://logging.apache.org/log4j/1.x/) | UNKNOWN | EOL | No usable GitHub source mapping. endoflife.date supplies a generic `Supported` label, excluded without a meaning review. Its date also differs from the upstream EOL announcement. |
| commons-httpclient:commons-httpclient 3.1 | [Apache declares the project EOL](https://hc.apache.org/httpclient-legacy/) | UNKNOWN | EOL | No usable GitHub source mapping or exact product entry. The tool does not extract a support-end claim from the upstream website. |
| org.apache.struts:struts2-core 2.3.37 | [Apache ended support for the 2.3 series](https://struts.apache.org/struts23-eol-announcement) | NO_EOL_DETECTED | NO_EOL_DETECTED | endoflife.date's generic `Support` label remains unreviewed. The shared repository and newer releases are active, so project-wide archive/inactivity criteria do not identify this ended series. |
| org.springframework:spring-core 4.3.30.RELEASE | [Spring specifies the 4.3 EOL cutoff](https://spring.io/blog/2019/12/03/spring-framework-maintenance-roadmap-in-2020-including-4-3-eol/) | NO_EOL_DETECTED | NO_EOL_DETECTED | The exact product mapping and 4.3 end date exist, but numeric cycle matching rejects `.RELEASE`. The product's `OSS support` label also lacks a security-scope review. The shared project remains active. |

The observed limitations identify two distinct needs: authoritative source discovery for packages with sparse metadata, and support information applicable to the exact release series. Project activity cannot establish that an old series remains supported. A missing/unused support-end claim also cannot be repaired merely by checking whether the latest version is recent.

Generic dates retain the accepted security-scope checks. This corpus serves as validation data; runtime scans still acquire public evidence automatically. Repository criteria were evaluated on the original upstream projects.

## All package outcomes

The following table links each package to independently reviewed public evidence. `POLICY_RULE` means a maintenance criterion matched; `SUPPORT_DATE` means an eligible support-end date matched. A dash in the inactivity column means that profile did not scan the package.

| Ecosystem | Package/version and independent source | Role | Default result / basis | With inactivity |
| --- | --- | --- | --- | --- |
| npm | [request 2.88.2](https://github.com/request/request) | Target | EOL / POLICY_RULE | — |
| npm | [node-sass 9.0.0](https://sass-lang.com/blog/node-sass-is-end-of-life/) | Target | EOL / POLICY_RULE | — |
| npm | [har-validator 5.1.5](https://registry.npmjs.org/har-validator/5.1.5) | Target | EOL / POLICY_RULE | — |
| npm | [istanbul 0.4.5](https://registry.npmjs.org/istanbul/0.4.5) | Target | EOL / POLICY_RULE | — |
| npm | [glob 7.2.3](https://registry.npmjs.org/glob/7.2.3) | Target | EOL / POLICY_RULE | — |
| npm | [rimraf 3.0.2](https://registry.npmjs.org/rimraf/3.0.2) | Target | EOL / POLICY_RULE | — |
| npm | [left-pad 1.3.0](https://registry.npmjs.org/left-pad/1.3.0) | Target | EOL / POLICY_RULE | — |
| npm | [uuid 3.4.0](https://registry.npmjs.org/uuid/3.4.0) | Target | EOL / POLICY_RULE | — |
| npm | [picocolors 1.1.1](https://github.com/alexeyraspopov/picocolors) | Control | NO_EOL_DETECTED | — |
| npm | [is-number 7.0.0](https://github.com/jonschlinkert/is-number) | Control | NO_EOL_DETECTED | EOL |
| gem | [therubyracer 0.12.3](https://github.com/rubyjs/therubyracer) | Target | EOL / POLICY_RULE | — |
| gem | [sass 3.7.4](https://sass-lang.com/blog/ruby-sass-is-unsupported/) | Target | EOL / POLICY_RULE | — |
| gem | [thread_safe 0.3.6](https://github.com/ruby-concurrency/thread_safe) | Target | EOL / POLICY_RULE | — |
| gem | [rails 6.1.7.10](https://rubyonrails.org/2024/10/15/new-maintenance-policy-and-eol-annouments) | Target | EOL / SUPPORT_DATE | — |
| gem | [concurrent-ruby 1.3.5](https://github.com/ruby-concurrency/concurrent-ruby) | Control | NO_EOL_DETECTED | — |
| pypi | [pycrypto 2.6.1](https://github.com/pycrypto/pycrypto) | Target | UNKNOWN | EOL |
| pypi | [nose 1.3.7](https://nose.readthedocs.io/en/latest/) | Inactivity candidate | UNKNOWN | EOL |
| pypi | [django-rest-swagger 2.2.0](https://github.com/marcgibbons/django-rest-swagger) | Target | EOL / POLICY_RULE | — |
| pypi | [pep8 1.7.1](https://pypi.org/project/pep8/) | Target | UNKNOWN | EOL |
| pypi | [django 2.2.28](https://www.djangoproject.com/weblog/2022/apr/11/security-releases/) | Target | EOL / SUPPORT_DATE | — |
| pypi | [attrs 25.3.0](https://github.com/python-attrs/attrs) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| golang | [github.com/dgrijalva/jwt-go v3.2.0+incompatible](https://github.com/dgrijalva/jwt-go) | Target | EOL / POLICY_RULE | — |
| golang | [github.com/mitchellh/mapstructure v1.5.0](https://github.com/mitchellh/mapstructure) | Target | EOL / POLICY_RULE | — |
| golang | [github.com/boltdb/bolt v1.3.1](https://github.com/boltdb/bolt) | Target | EOL / POLICY_RULE | — |
| golang | [github.com/stretchr/testify v1.10.0](https://github.com/stretchr/testify) | Control | NO_EOL_DETECTED | — |
| cargo | [failure 0.1.8](https://github.com/rust-lang-deprecated/failure) | Target | EOL / POLICY_RULE | — |
| cargo | [rustc-serialize 0.3.25](https://github.com/rust-lang-deprecated/rustc-serialize) | Target | EOL / POLICY_RULE | — |
| cargo | [serde_yaml 0.9.34+deprecated](https://github.com/dtolnay/serde-yaml/releases) | Target | EOL / POLICY_RULE | — |
| cargo | [serde 1.0.228](https://github.com/serde-rs/serde) | Control | NO_EOL_DETECTED | — |
| maven | [log4j/log4j 1.2.17](https://logging.apache.org/log4j/1.x/) | Target | UNKNOWN | EOL |
| maven | [org.apache.struts/struts2-core 2.3.37](https://struts.apache.org/struts23-eol-announcement) | Target | NO_EOL_DETECTED | NO_EOL_DETECTED |
| maven | [org.springframework/spring-core 4.3.30.RELEASE](https://spring.io/blog/2019/12/03/spring-framework-maintenance-roadmap-in-2020-including-4-3-eol/) | Target | NO_EOL_DETECTED | NO_EOL_DETECTED |
| maven | [commons-httpclient/commons-httpclient 3.1](https://hc.apache.org/httpclient-legacy/) | Target | UNKNOWN | EOL |
| maven | [com.google.guava/guava 33.4.8-jre](https://github.com/google/guava) | Control | NO_EOL_DETECTED | NO_EOL_DETECTED |
| nuget | [Microsoft.Azure.KeyVault 3.0.5](https://www.nuget.org/packages/Microsoft.Azure.KeyVault/3.0.5) | Target | EOL / POLICY_RULE | — |
| nuget | [Microsoft.Azure.DocumentDB 2.22.0](https://www.nuget.org/packages/Microsoft.Azure.DocumentDB/2.22.0) | Target | EOL / POLICY_RULE | — |
| nuget | [WindowsAzure.Storage 9.3.3](https://www.nuget.org/packages/WindowsAzure.Storage/9.3.3) | Target | EOL / POLICY_RULE | — |
| nuget | [Microsoft.Azure.Management.Fluent 1.38.1](https://www.nuget.org/packages/Microsoft.Azure.Management.Fluent/1.38.1) | Target | EOL / POLICY_RULE | — |
| nuget | [Newtonsoft.Json 13.0.3](https://github.com/JamesNK/Newtonsoft.Json) | Control | NO_EOL_DETECTED | — |

## Re-run live validation

```sh
make validate-real-packages
```

Or choose a profile and output directory:

```sh
go build -o bin/eolscan ./cmd/eolscan
python3 scripts/validate_real_packages.py \
  --profile default --output-dir artifacts/real-packages
python3 scripts/validate_real_packages.py \
  --profile inactivity --output-dir artifacts/real-packages
```

This calls the normal executable against public APIs. It writes the raw reports, execution receipts, stderr, and a derived `results.json`. The Python script needs only the standard library. It does not mock providers, bypass version verification, or manufacture source mappings.

The validation script exits **1 when a reviewed detection goal is unmet**, including known misses; it exits **2 for a validation/run error**. These are the validator's exit codes. The scanner's original exit code is preserved in each execution receipt. Unmet goals must not be relabeled as successful detection merely because the scanner's own CI gate passed.

Results can change with publisher metadata, releases, data coverage, and API availability. Live validation consumes provider quota. GitHub authentication remains optional through `EOLSCAN_GITHUB_TOKEN`; the script does not read or borrow credentials from gh. Normal deterministic CI does not run live requests.

## Inspect the recorded observations without network access

```sh
python3 scripts/validate_real_packages.py \
  --reports-dir testdata/real-packages/observations/2026-10-15 \
  --output-dir artifacts/real-packages-recorded
```

This reproduces the detection summary from the recorded CLI output, and still exits 1 for unmet goals. It does not perform a new scan or reconstruct historical support policies.

The [review manifest](../testdata/real-packages/manifest.json) records identities, roles, goals, source URLs, and review notes. The [recorded observations](../testdata/real-packages/observations/2026-10-15/) retain unmodified reports, effective policies, binary/report/input hashes, scanner exits, and independent API observations with retrieval timestamps and payload hashes.

The ordinary design validator also checks the recorded report schemas, input/report/policy hashes, case correspondence, and CI decisions without public requests. Those contract checks verify the integrity of the recorded evidence; they do not assert that all retirement targets were detected.
