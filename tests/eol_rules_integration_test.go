package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/cli"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func rulePolicy(rules ...model.EOLRule) model.Policy {
	p := offlinePolicy()
	p.Sources.NPM.Enabled, p.Sources.GitHub.Enabled = true, true
	p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
	p.Decision.EOLRules = rules
	p.CI.MinConfidence, p.CI.FailOnIncompleteScan = "MEDIUM", true
	return p
}

func npmSource(t *testing.T, stub *testutil.StubAPI, repository, deprecation, published string) {
	t.Helper()
	npmPackage(t, stub, "transitive-leaf", map[string]string{"1.0.0": published}, map[string]string{"1.0.0": deprecation})
	var doc map[string]any
	json.Unmarshal([]byte(stub.Bodies["registry.npmjs.org/transitive-leaf"]), &doc)
	doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["repository"] = map[string]string{"type": "git", "url": repository}
	testutil.PutJSON(t, stub, "registry.npmjs.org/transitive-leaf", doc)
}

func TestConfiguredMaintenanceConditionsBecomeEOLWithoutSupportCatalog(t *testing.T) {
	for _, tc := range []struct {
		name, deprecation, published string
		rule                         model.EOLRule
		archived                     bool
		threshold                    int
		want                         string
	}{
		{"deprecated", "No longer maintained", "2026-10-01T00:00:00Z", model.EOLRule{ID: "deprecated", AnyOf: []string{"DEPRECATED"}}, false, 0, "EOL"},
		{"archive", "", "2026-10-01T00:00:00Z", model.EOLRule{ID: "archive", AnyOf: []string{"ARCHIVED"}}, true, 0, "EOL"},
		{"archive_and_stale", "", "2020-01-01T00:00:00Z", model.EOLRule{ID: "both", AllOf: []string{"ARCHIVED", "STALE_RELEASE"}}, true, 365, "EOL"},
		{"archive_recent_does_not_match_and", "", "2026-10-01T00:00:00Z", model.EOLRule{ID: "both", AllOf: []string{"ARCHIVED", "STALE_RELEASE"}}, true, 365, "NO_EOL_DETECTED"},
		{"archive_recent_matches_or", "", "2026-10-01T00:00:00Z", model.EOLRule{ID: "either", AnyOf: []string{"ARCHIVED", "STALE_RELEASE"}}, true, 365, "EOL"},
		{"custom_inactivity", "", "2025-01-01T00:00:00Z", model.EOLRule{ID: "stale", AnyOf: []string{"STALE_RELEASE"}}, false, 365, "EOL"},
		{"different_inactivity_threshold", "", "2025-01-01T00:00:00Z", model.EOLRule{ID: "stale", AnyOf: []string{"STALE_RELEASE"}}, false, 730, "NO_EOL_DETECTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(tc.rule)
			if tc.threshold > 0 {
				p.Signals.StaleReleaseDays = model.Ptr(tc.threshold)
			}
			stub := testutil.NewStub()
			npmSource(t, stub, "git+https://github.com/publisher/leaf.git", tc.deprecation, tc.published)
			stub.Bodies["api.github.com/repos/publisher/leaf"] = `{"full_name":"publisher/leaf","archived":` + map[bool]string{true: "true", false: "false"}[tc.archived] + `}`
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
			row := report.Results[0]
			if row.Lifecycle != tc.want || row.Incomplete || row.SupportAssessment.Lifecycle != "UNKNOWN" || len(row.Evidence) != 0 {
				t.Fatalf("result: %+v", row)
			}
			if tc.want == "EOL" && (reporting.ExitCode(report) != 1 || model.Text(row.EOLBasis) != "POLICY_RULE" || row.EOLEffectiveDate != nil || row.EOLRuleEvaluations[0].Status != "PRESENT") {
				t.Fatalf("EOL rule did not control the result/CI: %+v", row)
			}
			if tc.want != "EOL" && reporting.ExitCode(report) != 0 {
				t.Fatal("unmatched rule failed CI")
			}
		})
	}
}

func TestEOLConditionFailureDoesNotBecomeNegative(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		rule                   model.EOLRule
		deprecation, published string
		want                   string
		incomplete             bool
		exit                   int
	}{
		{"required_unknown", model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}}, "", "2026-10-01T00:00:00Z", "UNKNOWN", true, 3},
		{"or_has_positive", model.EOLRule{ID: "either", AnyOf: []string{"DEPRECATED", "ARCHIVED"}}, "No longer supported", "2026-10-01T00:00:00Z", "EOL", false, 1},
		{"and_has_negative", model.EOLRule{ID: "both", AllOf: []string{"ARCHIVED", "STALE_RELEASE"}}, "", "2026-10-01T00:00:00Z", "NO_EOL_DETECTED", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(tc.rule)
			if strings.Contains(tc.name, "and") {
				p.Signals.StaleReleaseDays = model.Ptr(365)
			}
			stub := testutil.NewStub()
			npmSource(t, stub, "https://github.com/publisher/leaf", tc.deprecation, tc.published)
			stub.Status["api.github.com/repos/publisher/leaf"] = 503
			p.Network.Retries = 0
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
			row := report.Results[0]
			if row.Lifecycle != tc.want || row.Incomplete != tc.incomplete || reporting.ExitCode(report) != tc.exit {
				t.Fatalf("result: %+v", report)
			}
			signalStatus(t, row, "ARCHIVED", "UNKNOWN")
		})
	}
}

func TestRuleChangeScopesAndVersionVerificationAffectEOL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rules     []model.EOLRule
		published string
		want      string
	}{
		{"rule_removed", []model.EOLRule{}, "2020-01-01T00:00:00Z", "UNKNOWN"},
		{"wrong_ecosystem", []model.EOLRule{{ID: "deprecation", AnyOf: []string{"DEPRECATED"}, Ecosystems: []string{"gem"}}}, "2020-01-01T00:00:00Z", "NO_EOL_DETECTED"},
		{"wrong_exact_package", []model.EOLRule{{ID: "deprecation", AnyOf: []string{"DEPRECATED"}, Packages: []string{"pkg:npm/transitive-leaf@2.0.0"}}}, "2020-01-01T00:00:00Z", "NO_EOL_DETECTED"},
		{"publication_unverified", []model.EOLRule{{ID: "deprecation", AnyOf: []string{"DEPRECATED"}}}, "", "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(tc.rules...)
			p.Signals.Deprecated = true
			stub := testutil.NewStub()
			npmSource(t, stub, "https://github.com/publisher/leaf", "No longer supported", tc.published)
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
			if report.Results[0].Lifecycle != tc.want || stub.Count("api.github.com/repos/publisher/leaf") != 0 {
				t.Fatalf("rule/version scope: %+v", report.Results[0])
			}
		})
	}
}

func TestRubyGemsArchiveUsesExactVersionPublisherLink(t *testing.T) {
	p := rulePolicy(model.EOLRule{ID: "archived-gem", AnyOf: []string{"ARCHIVED"}})
	p.Sources.NPM.Enabled = false
	p.Sources.RubyGems.Enabled = true
	stub := testutil.NewStub()
	stub.Bodies["rubygems.org/api/v1/versions/transitive-leaf.json"] = `[{"number":"1.0.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z"}]`
	stub.Bodies["rubygems.org/api/v2/rubygems/transitive-leaf/versions/1.0.0.json"] = `{"name":"transitive-leaf","version":"1.0.0","platform":"ruby","version_created_at":"2020-01-01T00:00:00Z","source_code_uri":"http://github.com/publisher/leaf"}`
	stub.Bodies["api.github.com/repos/publisher/leaf"] = `{"full_name":"publisher/leaf","archived":true}`
	report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/transitive-leaf@1.0.0"), false)
	row := expectLifecycle(t, report, "EOL", "MEDIUM", "")
	if model.Text(row.VersionVerification.ProviderID) != "rubygems" || len(stub.Calls) != 3 || row.Incomplete {
		t.Fatalf("native gem archive: %+v calls=%v", row, stub.Calls)
	}
}

func TestRepositoryDiscoveryAcrossAllRegistryEcosystems(t *testing.T) {
	for _, purl := range []string{"pkg:gem/leaf@1.0.0", "pkg:npm/leaf@1.0.0", "pkg:pypi/leaf@1.0.0", "pkg:maven/org.example/leaf@1.0.0", "pkg:golang/github.com/publisher/leaf@v1.0.0", "pkg:cargo/leaf@1.0.0", "pkg:nuget/leaf@1.0.0"} {
		t.Run(purl, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
			p.Sources.NPM.Enabled = false
			p.Sources.DepsDev.Enabled = true
			id, reason := identity.Resolve(model.Component{PURL: purl})
			if reason != "" {
				t.Fatal(reason)
			}
			stub := testutil.NewStub()
			testutil.PutJSON(t, stub, strings.TrimPrefix(identity.VersionURL(p.Sources.DepsDev.BaseURL, id), "https://"), map[string]any{
				"versionKey": map[string]string{"system": id.System, "name": id.Name, "version": id.Version}, "publishedAt": "2020-01-01T00:00:00Z",
				"relatedProjects": []map[string]any{{"projectKey": map[string]string{"id": "github.com/publisher/leaf"}, "relationType": "SOURCE_REPO", "relationProvenance": "UNVERIFIED_METADATA"}},
			})
			stub.Bodies["api.github.com/repos/publisher/leaf"] = `{"full_name":"publisher/leaf","archived":true}`
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM(purl), false)
			row := expectLifecycle(t, report, "EOL", "MEDIUM", "")
			if row.Incomplete || len(stub.Calls) != 2 {
				t.Fatalf("discovery: %+v calls=%v", row, stub.Calls)
			}
		})
	}
}

func TestCustomPolicyThroughCLIWarnsEvenWhenCIGateIsReportFirst(t *testing.T) {
	for _, threshold := range []string{"HIGH", "MEDIUM"} {
		t.Run(threshold, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "retired-version", AnyOf: []string{"DEPRECATED"}})
			p.CI.MinConfidence = threshold
			b, _ := json.Marshal(p)
			path := filepath.Join(t.TempDir(), "policy.yaml")
			os.WriteFile(path, b, 0600)
			stub := testutil.NewStub()
			npmSource(t, stub, "", "No longer supported", "2020-01-01T00:00:00Z")
			input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"transitive-leaf","purl":"pkg:npm/transitive-leaf@1.0.0"}]}`
			var out, errs bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "-i", "-", "-c", path, "-f", "json"}, strings.NewReader(input), &out, &errs, stub.Client(), testutil.FixedNow)
			want := 0
			if threshold == "MEDIUM" {
				want = 1
			}
			if code != want || !json.Valid(out.Bytes()) || !strings.Contains(errs.String(), "WARNING: 1 component") {
				t.Fatalf("CLI code=%d stderr=%s", code, errs.String())
			}
			var report model.Report
			json.Unmarshal(out.Bytes(), &report)
			row := report.Results[0]
			row.EOLRuleEvaluations[0].Status = "ABSENT"
			report.Results[0] = row
			if reporting.Validate(report, p) == nil {
				t.Fatal("report accepted a policy EOL with an unmatched rule")
			}
		})
	}
}

func TestRenamedRepositoryThroughHTTPSAndOfflineCache(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/publisher/leaf":
			http.Redirect(w, r, "/repositories/123", http.StatusMovedPermanently)
		case "/repositories/123":
			io.WriteString(w, `{"id":123,"full_name":"new-owner/leaf","archived":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
	p.Sources.GitHub.BaseURL = server.URL
	p.Network.AllowedHosts = append(p.Network.AllowedHosts, u.Hostname())
	stub := testutil.NewStub()
	npmSource(t, stub, "https://github.com/publisher/leaf", "", "2020-01-01T00:00:00Z")
	native := stub.Client().Transport
	client := server.Client()
	https := client.Transport
	client.Transport = testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == u.Hostname() {
			return https.RoundTrip(r)
		}
		return native.RoundTrip(r)
	})
	path := filepath.Join(t.TempDir(), "policy.yaml")
	b, _ := json.Marshal(p)
	os.WriteFile(path, b, 0600)
	input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"transitive-leaf","purl":"pkg:npm/transitive-leaf@1.0.0"}]}`
	var out, errs bytes.Buffer
	code := cli.Run(context.Background(), []string{"scan", "-i", "-", "-c", path, "-f", "json"}, strings.NewReader(input), &out, &errs, client, testutil.FixedNow)
	if code != 1 {
		t.Fatalf("rename code=%d stderr=%s", code, errs.String())
	}
	var report model.Report
	json.Unmarshal(out.Bytes(), &report)
	expectLifecycle(t, report, "EOL", "MEDIUM", "")

	// Persist the resolved numeric repository URL, then replay with no HTTP
	// access. The original publisher URL differs from the response identity.
	p.Cache.Enabled = true
	dir := t.TempDir()
	bundle := testBundle(t, p, nil)
	scanAt := func(now time.Time, offline bool) model.Report {
		clock := testutil.NewClock(now)
		tr := transport.New(client, p, now, offline, transport.WithCacheDir(dir), transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
		r, err := scanner.NewWithTransport(bundle, tr, model.UTCDate(now)).Scan(context.Background(), componentSBOM("pkg:npm/transitive-leaf@1.0.0"))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	expectLifecycle(t, scanAt(testutil.FixedNow, false), "EOL", "MEDIUM", "")
	server.Close()
	client.Transport = testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("offline replay attempted an HTTP request")
		return nil, nil
	})
	row := expectLifecycle(t, scanAt(testutil.FixedNow.Add(time.Hour), true), "EOL", "MEDIUM", "")
	if row.Incomplete || len(row.Signals) != 1 || row.Signals[0].Details["repository"] != "https://github.com/new-owner/leaf" {
		t.Fatalf("renamed repository identity was lost from the cache: %+v", row)
	}
}
