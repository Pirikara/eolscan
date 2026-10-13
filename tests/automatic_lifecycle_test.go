package acceptance

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

const automaticProductURL = "endoflife.date/api/v1/products/example/"

func automaticPolicy() model.Policy {
	p := offlinePolicy()
	p.Sources.EndoflifeDate.Enabled, p.Sources.DepsDev.Enabled = true, true
	p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
	p.CI.MinConfidence = "MEDIUM"
	return p
}

func setSupportLabel(t *testing.T, stub *testutil.StubAPI, key string, label *string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(stub.Bodies[key]), &doc); err != nil {
		t.Fatal(err)
	}
	doc["result"].(map[string]any)["labels"] = map[string]any{"eol": label}
	testutil.PutJSON(t, stub, key, doc)
}

func automaticResponses(t *testing.T, end, label *string) *testutil.StubAPI {
	t.Helper()
	stub := testutil.NewStub()
	stub.Bodies["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = testutil.VersionBody("example", "2.4.7", "2024-04-12T09:00:00Z")
	stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
	stub.Bodies[automaticProductURL] = testutil.ProductBody("example", "2.4", end, false)
	setSupportLabel(t, stub, automaticProductURL, label)
	return stub
}

func TestAutomaticSecurityScopeWithoutProductOrCycleCatalog(t *testing.T) {
	for _, tc := range []struct {
		name, status, confidence, reason string
		label, end                       *string
		disable                          bool
	}{
		{"security_end", "EOL", "MEDIUM", "", model.Ptr("Security Support"), model.Ptr("2026-10-01"), false},
		{"combined_phase", "EOL", "MEDIUM", "", model.Ptr("Maintenance & Security Support"), model.Ptr("2026-10-01"), false},
		{"future_security_end", "UNKNOWN", "", "SECURITY_END_ONLY", model.Ptr("Security Support"), model.Ptr("2026-12-01"), false},
		{"unknown_label", "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", model.Ptr("OSS support"), model.Ptr("2026-10-01"), false},
		{"generic_label", "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", model.Ptr("End of Life"), model.Ptr("2026-10-01"), false},
		{"extended_label", "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", model.Ptr("Extended Security Support"), model.Ptr("2026-10-01"), false},
		{"missing_label", "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", nil, model.Ptr("2026-10-01"), false},
		{"missing_date", "UNKNOWN", "", "NO_LIFECYCLE_EVIDENCE", model.Ptr("Security Support"), nil, false},
		{"scope_rule_disabled", "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", model.Ptr("Security Support"), model.Ptr("2026-10-01"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := automaticPolicy()
			p.Sources.EndoflifeDate.UseSecuritySupportLabel = !tc.disable
			stub := automaticResponses(t, tc.end, tc.label)
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
			row := expectLifecycle(t, report, tc.status, tc.confidence, tc.reason)
			if row.Incomplete || stub.Count(automaticProductURL) != 1 || report.CIGate.Passed != (tc.status != "EOL") {
				t.Fatalf("report=%+v calls=%v", report, stub.Calls)
			}
			if tc.status == "EOL" && (row.Evidence[0].Claim != "CURATED_SECURITY_END" || row.Evidence[0].SourceClass != "CURATED_DATABASE" || row.Evidence[0].GeneralEolReview != nil) {
				t.Fatalf("automatic evidence misrepresented: %+v", row.Evidence)
			}
		})
	}
}

func TestAutomaticSecurityEvidenceRespectsVersionAndOfficialPrecedence(t *testing.T) {
	for _, endpoint := range []string{"endoflife.date/api/v1/identifiers/purl/", automaticProductURL} {
		t.Run("missing_source_"+endpoint, func(t *testing.T) {
			p := automaticPolicy()
			p.CI.FailOnIncompleteScan = true
			stub := automaticResponses(t, model.Ptr("2026-10-01"), model.Ptr("Security Support"))
			stub.Status[endpoint] = 404
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
			row := expectLifecycle(t, report, "UNKNOWN", "", "SOURCE_ERROR")
			if !row.Incomplete || reporting.ExitCode(report) != 3 {
				t.Fatal("a missing lifecycle API endpoint was treated as a complete lookup")
			}
		})
	}
	t.Run("version_required", func(t *testing.T) {
		stub := automaticResponses(t, model.Ptr("2026-10-01"), model.Ptr("Security Support"))
		stub.Status["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = 404
		report := runScan(t, automaticPolicy(), nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		expectLifecycle(t, report, "UNKNOWN", "", "VERSION_NOT_FOUND_IN_INDEX")
	})
	t.Run("official_window", func(t *testing.T) {
		stub := automaticResponses(t, model.Ptr("2026-10-01"), model.Ptr("Security Support"))
		report := runScan(t, automaticPolicy(), testCatalog(), "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		row := expectLifecycle(t, report, "SUPPORTED", "HIGH", "")
		found := false
		for _, d := range row.Diagnostics {
			found = found || d.Code == "SOURCE_DISAGREEMENT"
		}
		if !found {
			t.Fatal("disagreement with automatically retrieved data was hidden")
		}
	})
	t.Run("product_identity", func(t *testing.T) {
		stub := automaticResponses(t, model.Ptr("2026-10-01"), model.Ptr("Security Support"))
		var doc map[string]any
		json.Unmarshal([]byte(stub.Bodies[automaticProductURL]), &doc)
		doc["result"].(map[string]any)["name"] = "other"
		testutil.PutJSON(t, stub, automaticProductURL, doc)
		report := runScan(t, automaticPolicy(), nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		row := expectLifecycle(t, report, "UNKNOWN", "", "SOURCE_ERROR")
		if !row.Incomplete {
			t.Fatal("identity failure must make the scan incomplete")
		}
	})
	t.Run("report_first_default", func(t *testing.T) {
		p := automaticPolicy()
		p.CI.MinConfidence = "HIGH"
		stub := automaticResponses(t, model.Ptr("2026-10-01"), model.Ptr("Security Support"))
		report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		expectLifecycle(t, report, "EOL", "MEDIUM", "")
		if reporting.ExitCode(report) != 0 {
			t.Fatal("automatic evidence must not change the configured confidence threshold")
		}
	})
	t.Run("schema_requires_security_label", func(t *testing.T) {
		p := automaticPolicy()
		stub := automaticResponses(t, model.Ptr("2026-10-01"), model.Ptr("Security Support"))
		report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		report.Results[0].Evidence[0].SourceLabel = model.Ptr("Commercial Support")
		if reporting.Validate(report, p) == nil {
			t.Fatal("curated security evidence with an unconfirmed scope was accepted")
		}
	})
}

func TestAutomaticLifecycleRefreshAndOfflineCache(t *testing.T) {
	for _, caching := range []bool{false, true} {
		name := "fresh_every_scan"
		if caching {
			name = "cache_ttl_refresh"
		}
		t.Run(name, func(t *testing.T) {
			p := automaticPolicy()
			p.Cache.Enabled, p.Cache.PositiveTTLHours = caching, 1
			bundle := testBundle(t, p, nil)
			stub := automaticResponses(t, model.Ptr("2026-12-01"), model.Ptr("Security Support"))
			dir := t.TempDir()
			scanAt := func(now time.Time, offline bool) model.Report {
				clock := testutil.NewClock(now)
				tr := transport.New(stub.Client(), p, now, offline, transport.WithCacheDir(dir), transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
				report, err := scanner.NewWithTransport(bundle, tr, model.UTCDate(now)).Scan(context.Background(), componentSBOM("pkg:gem/example@2.4.7"))
				if err != nil {
					t.Fatal(err)
				}
				return report
			}
			first := scanAt(testutil.FixedNow, false)
			expectLifecycle(t, first, "UNKNOWN", "", "SECURITY_END_ONLY")
			stub.Bodies[automaticProductURL] = testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false)
			setSupportLabel(t, stub, automaticProductURL, model.Ptr("Security Support"))
			second := scanAt(testutil.FixedNow.Add(30*time.Minute), false)
			if caching {
				expectLifecycle(t, second, "UNKNOWN", "", "SECURITY_END_ONLY")
				if stub.Count(automaticProductURL) != 1 {
					t.Fatal("fresh cached lifecycle data was fetched again")
				}
			} else {
				expectLifecycle(t, second, "EOL", "MEDIUM", "")
				if model.Text(second.Results[0].Evidence[0].RawPayloadHash) == model.Text(first.Results[0].Evidence[0].RawPayloadHash) {
					t.Fatal("changed remote evidence was not recorded")
				}
			}
			third := scanAt(testutil.FixedNow.Add(2*time.Hour), false)
			expectLifecycle(t, third, "EOL", "MEDIUM", "")
			if caching {
				calls := stub.Count(automaticProductURL)
				fourth := scanAt(testutil.FixedNow.Add(3*time.Hour), true)
				expectLifecycle(t, fourth, "EOL", "MEDIUM", "")
				if stub.Count(automaticProductURL) != calls {
					t.Fatal("offline scan made a network request")
				}
				old := scanAt(testutil.FixedNow.AddDate(0, 0, 32), true)
				row := expectLifecycle(t, old, "UNKNOWN", "", "")
				if !row.Incomplete || stub.Count(automaticProductURL) != calls {
					t.Fatal("expired offline evidence was accepted or queried online")
				}
			}
		})
	}
}
