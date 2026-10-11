package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Pirikara/eolscan/internal/cli"
	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/model"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func testCatalog() *model.Catalog {
	return &model.Catalog{SchemaVersion: 2, Entries: []model.CatalogEntry{{
		ID: "test-window", PackagePURL: "pkg:gem/example", MatchedCycle: "2.4", Match: "numeric_segment_prefix", Versions: []string{},
		Claim: "UPSTREAM_SECURITY_WINDOW", SupportScope: "upstream_security", SupportStartDate: model.Ptr("2024-04-12"),
		EOLEffectiveDate: "2026-12-01", EvidenceURL: "https://example.org/support/2.4", SupportAuthority: "upstream",
		ReviewedAt: "2026-10-01", ValidUntil: "2026-12-01",
	}}, VerifiedVersions: []model.VersionAssertion{{
		PackagePURL: "pkg:gem/example@2.4.7", PublishedAt: "2024-04-12T09:00:00Z", SourceURL: "https://example.org/releases/2.4.7",
		ReviewedAt: "2026-10-01", ValidUntil: "2026-12-01",
	}}, GeneralEolReviews: []model.GeneralEolReview{{
		ID: "test-review", ProductSlug: "example", PackagePURL: "pkg:gem/example", MatchedCycle: "2.4", SupportScope: "upstream_security",
		EvidenceURL: "https://example.org/support/2.4", ReviewedAt: "2026-10-01", ValidUntil: "2026-12-01",
	}}}
}

func testBundle(t *testing.T, p model.Policy, c *model.Catalog) model.PolicyBundle {
	t.Helper()
	if err := config.Validate(p); err != nil {
		t.Fatal(err)
	}
	if c != nil {
		v, _ := contract.JSONValue(c)
		if err := contract.Validate("support-catalog", v); err != nil {
			t.Fatal(err)
		}
		if err := config.ValidateCatalog(*c); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := contract.CanonicalJSON(map[string]any{"policy": p, "catalog": c, "exceptions": nil})
	ch, _ := contract.CanonicalJSON(c)
	return model.PolicyBundle{Policy: p, Catalog: c, Hash: contract.Digest(h), CatalogHash: contract.Digest(ch)}
}

func offlinePolicy() model.Policy {
	p := config.Default()
	p.Sources.EndoflifeDate.Enabled = false
	p.Sources.DepsDev.Enabled = false
	p.Sources.NPM.Enabled = false
	p.Sources.PyPI.Enabled = false
	p.Sources.RubyGems.Enabled = false
	return p
}

func componentSBOM(purl string) model.SBOM {
	return model.SBOM{Components: []model.Component{{SourceRef: "component-1", Name: "example", PURL: purl}}, SHA256: contract.Digest([]byte("fixture"))}
}

func runScan(t *testing.T, p model.Policy, c *model.Catalog, asOf string, stub *testutil.StubAPI, sbom model.SBOM, offline bool) model.Report {
	t.Helper()
	clock := testutil.NewClock(testutil.FixedNow)
	tr := transport.New(stub.Client(), p, testutil.FixedNow, offline, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
	s := scanner.NewWithTransport(testBundle(t, p, c), tr, asOf)
	r, err := s.Scan(context.Background(), sbom)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func expectLifecycle(t *testing.T, r model.Report, status, confidence, reason string) model.ComponentResult {
	t.Helper()
	if len(r.Results) != 1 {
		t.Fatalf("results: %+v", r)
	}
	row := r.Results[0]
	if row.Lifecycle != status || model.Text(row.Confidence) != confidence || reason != "" && !model.Contains(row.UnknownReasons, reason) {
		t.Fatalf("result: %+v", row)
	}
	return row
}

func signalStatus(t *testing.T, row model.ComponentResult, kind, status string) {
	t.Helper()
	for _, e := range row.SignalEvaluations {
		if e.Type == kind {
			if e.Status != status {
				t.Fatalf("%s: %+v", kind, e)
			}
			return
		}
	}
	t.Fatalf("missing signal %s", kind)
}

func TestLifecycleAcceptance(t *testing.T) {
	tests := []struct {
		name       string
		asOf       string
		status     string
		confidence string
		reason     string
		edit       func(*model.Catalog)
	}{
		{"UT01_security_window", "2026-10-11", "SUPPORTED", "HIGH", "", func(*model.Catalog) {}},
		{"UT02_end_day", "2026-12-01", "EOL", "HIGH", "", func(*model.Catalog) {}},
		{"UT03_security_end_future", "2026-10-11", "UNKNOWN", "", "NO_LIFECYCLE_EVIDENCE", func(c *model.Catalog) {
			c.Entries[0].Claim = "UPSTREAM_SECURITY_END"
			c.Entries[0].SupportStartDate = nil
		}},
		{"UT16_same_tier_conflict", "2026-10-11", "UNKNOWN", "", "CONFLICT", func(c *model.Catalog) {
			e := c.Entries[0]
			e.ID = "second"
			e.EOLEffectiveDate = "2026-10-01"
			c.Entries = append(c.Entries, e)
		}},
		{"UT33_future_date_conflict", "2026-10-11", "UNKNOWN", "", "CONFLICT", func(c *model.Catalog) {
			c.Entries[0].Claim = "UPSTREAM_SECURITY_END"
			c.Entries[0].SupportStartDate = nil
			e := c.Entries[0]
			e.ID = "past"
			e.EOLEffectiveDate = "2026-10-01"
			c.Entries = append(c.Entries, e)
		}},
		{"UT37_formally_superseded", "2026-10-11", "SUPPORTED", "HIGH", "", func(c *model.Catalog) {
			e := c.Entries[0]
			e.ID = "old"
			e.EOLEffectiveDate = "2026-10-01"
			e.SupersededBy = model.Ptr("test-window")
			e.SupersessionSourceURL = model.Ptr("https://example.org/correction")
			c.Entries = append(c.Entries, e)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testCatalog()
			tt.edit(c)
			r := runScan(t, offlinePolicy(), c, tt.asOf, testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true)
			row := expectLifecycle(t, r, tt.status, tt.confidence, tt.reason)
			if tt.name == "UT37_formally_superseded" {
				if len(row.Evidence) != 2 || model.Contains(row.SelectedEvidenceIDs, "old") {
					t.Fatalf("supersession discarded audit or selected old claim: %+v", row)
				}
			}
		})
	}
}

func TestGeneralEOLAcceptance(t *testing.T) {
	tests := []struct {
		name                       string
		end                        *string
		maintained                 bool
		status, confidence, reason string
		edit                       func(*model.Catalog)
	}{
		{"UT04_general_future", model.Ptr("2026-12-01"), false, "UNKNOWN", "", "GENERAL_EOL_ONLY", func(c *model.Catalog) { c.Entries = []model.CatalogEntry{} }},
		{"UT05_reviewed_end_day", model.Ptr("2026-10-11"), false, "EOL", "MEDIUM", "", func(c *model.Catalog) { c.Entries = []model.CatalogEntry{} }},
		{"UT06_maintained_without_date", nil, true, "UNKNOWN", "", "NO_LIFECYCLE_EVIDENCE", func(c *model.Catalog) { c.Entries = []model.CatalogEntry{} }},
		{"UT07_extended_maintenance", model.Ptr("2026-10-01"), true, "EOL", "MEDIUM", "", func(c *model.Catalog) { c.Entries = []model.CatalogEntry{} }},
		{"UT17_official_over_curated", model.Ptr("2026-10-01"), false, "SUPPORTED", "HIGH", "", func(*model.Catalog) {}},
		{"UT19_general_no_notice", model.Ptr("2026-12-01"), false, "UNKNOWN", "", "GENERAL_EOL_ONLY", func(c *model.Catalog) { c.Entries = []model.CatalogEntry{} }},
		{"UT34_upper_future_end_no_fallback", model.Ptr("2026-10-01"), false, "UNKNOWN", "", "NO_LIFECYCLE_EVIDENCE", func(c *model.Catalog) {
			c.Entries[0].Claim = "UPSTREAM_SECURITY_END"
			c.Entries[0].SupportStartDate = nil
		}},
		{"UT35_unreviewed", model.Ptr("2026-10-01"), false, "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", func(c *model.Catalog) {
			c.Entries = []model.CatalogEntry{}
			c.GeneralEolReviews = []model.GeneralEolReview{}
		}},
		{"UT36_wrong_cycle", model.Ptr("2026-10-01"), false, "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", func(c *model.Catalog) {
			c.Entries = []model.CatalogEntry{}
			c.GeneralEolReviews[0].MatchedCycle = "2.5"
		}},
		{"UT36_expired_review", model.Ptr("2026-10-01"), false, "UNKNOWN", "", "GENERAL_EOL_UNREVIEWED", func(c *model.Catalog) {
			c.Entries = []model.CatalogEntry{}
			c.GeneralEolReviews[0].ValidUntil = "2026-10-10"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.EndoflifeDate.Enabled = true
			c := testCatalog()
			tt.edit(c)
			stub := testutil.NewStub()
			stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
			stub.Bodies["endoflife.date/api/v1/products/example/"] = testutil.ProductBody("example", "2.4", tt.end, tt.maintained)
			row := expectLifecycle(t, runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), tt.status, tt.confidence, tt.reason)
			if row.Lifecycle == "UNKNOWN" && len(row.Notices) != 0 {
				t.Fatal("notice on UNKNOWN")
			}
			if tt.end != nil && len(row.Evidence) == 0 {
				t.Fatal("general evidence disappeared")
			}
			if tt.name == "UT17_official_over_curated" {
				found := false
				for _, d := range row.Diagnostics {
					if d.Code == "SOURCE_DISAGREEMENT" {
						found = true
					}
				}
				if !found {
					t.Fatal("missing disagreement")
				}
			}
		})
	}
}

func TestVersionAcceptance(t *testing.T) {
	t.Run("UT08_nonexistent_numeric_version", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.DepsDev.Enabled = true
		c := testCatalog()
		r := runScan(t, p, c, "2026-10-11", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.9999"), false)
		row := expectLifecycle(t, r, "UNKNOWN", "", "VERSION_NOT_FOUND_IN_INDEX")
		if row.Incomplete {
			t.Fatal("404 index absence is not a failed scan")
		}
	})
	t.Run("UT09_timeout", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.DepsDev.Enabled = true
		stub := testutil.NewStub()
		stub.Errors["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = context.DeadlineExceeded
		row := expectLifecycle(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "VERSION_UNVERIFIED")
		if !row.Incomplete {
			t.Fatal("verification timeout must be incomplete")
		}
	})
	t.Run("UT10_exact_local_without_HTTP", func(t *testing.T) {
		stub := testutil.NewStub()
		row := expectLifecycle(t, runScan(t, offlinePolicy(), testCatalog(), "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), true), "SUPPORTED", "HIGH", "")
		if row.VersionVerification.Status != "VERIFIED" || len(stub.Calls) != 0 {
			t.Fatal("local version needs no HTTP")
		}
	})
	t.Run("UT11_not_released_as_of", func(t *testing.T) {
		row := expectLifecycle(t, runScan(t, offlinePolicy(), testCatalog(), "2024-01-01", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true), "UNKNOWN", "", "NOT_RELEASED_AS_OF")
		if row.Incomplete {
			t.Fatal("known later publication is complete")
		}
	})
	t.Run("UT42_missing_API_publication", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.DepsDev.Enabled = true
		stub := testutil.NewStub()
		stub.Bodies["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = testutil.VersionBody("example", "2.4.7", "")
		row := expectLifecycle(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "VERSION_UNVERIFIED")
		if row.VersionVerification.Status != "UNVERIFIED" || !row.Incomplete {
			t.Fatal("missing publication must not verify")
		}
	})
	t.Run("UT43_expiry_uses_run_date", func(t *testing.T) {
		c := testCatalog()
		c.VerifiedVersions[0].ValidUntil = "2026-10-10"
		row := expectLifecycle(t, runScan(t, offlinePolicy(), c, "2024-04-12", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true), "UNKNOWN", "", "VERSION_UNVERIFIED")
		if row.VersionVerification.Status == "VERIFIED" {
			t.Fatal("as_of revived expired assertion")
		}
	})
	t.Run("UT44_UTC_publication_day", func(t *testing.T) {
		c := testCatalog()
		c.VerifiedVersions[0].PublishedAt = "2024-04-13T01:00:00+09:00"
		row := expectLifecycle(t, runScan(t, offlinePolicy(), c, "2024-04-12", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true), "SUPPORTED", "HIGH", "")
		if model.Text(row.VersionVerification.PublishedAt) != "2024-04-12T16:00:00Z" {
			t.Fatal("publication not normalized to UTC")
		}
	})
}

func TestProviderAcceptance(t *testing.T) {
	t.Run("UT13_only_matched_products", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.EndoflifeDate.Enabled = true
		c := testCatalog()
		c.Entries = []model.CatalogEntry{}
		second := c.VerifiedVersions[0]
		second.PackagePURL = "pkg:gem/second@2.4.7"
		c.VerifiedVersions = append(c.VerifiedVersions, second)
		stub := testutil.NewStub()
		stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example", "second", "unrelated")
		for _, name := range []string{"example", "second", "unrelated"} {
			stub.Bodies["endoflife.date/api/v1/products/"+name+"/"] = testutil.ProductBody(name, "2.4", model.Ptr("2026-12-01"), false)
		}
		sbom := componentSBOM("pkg:gem/example@2.4.7")
		sbom.Components = append(sbom.Components, model.Component{SourceRef: "second", Name: "second", PURL: "pkg:gem/second@2.4.7"})
		runScan(t, p, c, "2026-10-11", stub, sbom, false)
		if stub.Count("endoflife.date/api/v1/identifiers/purl/") != 1 || stub.Count("endoflife.date/api/v1/products/example/") != 1 || stub.Count("endoflife.date/api/v1/products/second/") != 1 ||
			stub.Count("endoflife.date/api/v1/products/unrelated/") != 0 || stub.Count("endoflife.date/api/v1/products/full/") != 0 {
			t.Fatalf("calls: %+v", stub.Calls)
		}
	})
	t.Run("UT14_no_name_fallback", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.EndoflifeDate.Enabled = true
		c := testCatalog()
		c.Entries = []model.CatalogEntry{}
		stub := testutil.NewStub()
		stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("other")
		expectLifecycle(t, runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "NO_LIFECYCLE_EVIDENCE")
		if len(stub.Calls) != 1 {
			t.Fatal("unmatched product fetched")
		}
	})
	t.Run("UT15_ambiguous_identity", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.EndoflifeDate.Enabled = true
		c := testCatalog()
		c.Entries = []model.CatalogEntry{}
		stub := testutil.NewStub()
		stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = `{"schema_version":"1.2.1","generated_at":"2026-10-11T00:00:00Z","result":[{"identifier":"pkg:gem/example","product":{"name":"one","uri":"https://endoflife.date/api/v1/products/one/"}},{"identifier":"pkg:gem/example","product":{"name":"two","uri":"https://endoflife.date/api/v1/products/two/"}}]}`
		expectLifecycle(t, runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "AMBIGUOUS_IDENTITY")
		if len(stub.Calls) != 1 {
			t.Fatal("ambiguous product fetched")
		}
	})
	t.Run("UT18_notice_90_days", func(t *testing.T) {
		c := testCatalog()
		c.Entries[0].EOLEffectiveDate = "2027-01-09"
		row := expectLifecycle(t, runScan(t, offlinePolicy(), c, "2026-10-11", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true), "SUPPORTED", "HIGH", "")
		if len(row.Notices) != 1 || row.Notices[0].DaysRemaining != 90 || len(row.Signals) != 0 {
			t.Fatalf("notice: %+v", row)
		}
	})
	t.Run("UT30_duplicate_components_single_lookup", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.EndoflifeDate.Enabled = true
		p.Sources.DepsDev.Enabled = true
		stub := testutil.NewStub()
		stub.Bodies["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = testutil.VersionBody("example", "2.4.7", "2024-04-12T09:00:00Z")
		stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
		stub.Bodies["endoflife.date/api/v1/products/example/"] = testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false)
		sbom := componentSBOM("pkg:gem/example@2.4.7")
		for _, ref := range []string{"b", "c"} {
			c := sbom.Components[0]
			c.SourceRef = ref
			sbom.Components = append(sbom.Components, c)
		}
		r := runScan(t, p, nil, "2026-10-11", stub, sbom, false)
		if len(r.Results) != 3 {
			t.Fatal("duplicate components lost")
		}
		for key, count := range stub.Calls {
			if count != 1 {
				t.Fatalf("%s called %d times", key, count)
			}
		}
	})
	t.Run("UT31_future_projection", func(t *testing.T) {
		r := runScan(t, offlinePolicy(), testCatalog(), "2026-12-01", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true)
		if !r.Projection || r.Results[0].Lifecycle != "EOL" {
			t.Fatalf("projection: %+v", r)
		}
		signalStatus(t, r.Results[0], "STALE_RELEASE", "UNKNOWN")
	})
}

func TestRequiredSignalAcceptance(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		enabled  bool
		required bool
		strict   bool
		status   string
		exit     int
	}{
		{"UT38_no_capability", "", false, true, true, "UNKNOWN", 3},
		{"UT38_API_failure", "", true, true, true, "UNKNOWN", 3},
		{"UT38_missing_publication", `{"packageKey":{"system":"RUBYGEMS","name":"example"},"versions":[{"versionKey":{"system":"RUBYGEMS","name":"example","version":"2.4.7"}}]}`, true, true, true, "UNKNOWN", 3},
		{"UT39_equivalent_successful_negative", `{"packageKey":{"system":"RUBYGEMS","name":"example"},"versions":[{"versionKey":{"system":"RUBYGEMS","name":"example","version":"2.4.7"},"publishedAt":"2026-10-01T00:00:00Z"}]}`, true, true, true, "ABSENT", 0},
		{"UT40_optional_failure", "", true, false, true, "UNKNOWN", 0},
		{"UT45_required_report_first", "", false, true, false, "UNKNOWN", 0},
		{"required_present", `{"packageKey":{"system":"RUBYGEMS","name":"example"},"versions":[{"versionKey":{"system":"RUBYGEMS","name":"example","version":"2.4.7"},"publishedAt":"2024-04-12T09:00:00Z"}]}`, true, true, true, "PRESENT", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := offlinePolicy()
			p.Signals.Deprecated = false
			p.Sources.DepsDev.Enabled = tt.enabled
			p.CI.FailOnIncompleteScan = tt.strict
			if tt.required {
				p.CI.FailOnSignals = []string{"STALE_RELEASE"}
			}
			stub := testutil.NewStub()
			key := "api.deps.dev/v3/systems/rubygems/packages/example"
			if tt.body != "" {
				stub.Bodies[key] = tt.body
			} else {
				stub.Status[key] = 503
			}
			r := runScan(t, p, testCatalog(), "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
			signalStatus(t, r.Results[0], "STALE_RELEASE", tt.status)
			if r.Results[0].Incomplete != (tt.required && tt.status == "UNKNOWN") || reporting.ExitCode(r) != tt.exit {
				t.Fatalf("gate: %+v", r)
			}
		})
	}
	t.Run("required_unknown_invalid_PURL", func(t *testing.T) {
		p := offlinePolicy()
		p.CI.FailOnSignals = []string{"ARCHIVED"}
		p.CI.FailOnIncompleteScan = true
		r := runScan(t, p, nil, "2026-10-11", testutil.NewStub(), componentSBOM("bad"), true)
		if !r.Results[0].Incomplete || reporting.ExitCode(r) != 3 {
			t.Fatal("invalid PURL bypassed required signal")
		}
		signalStatus(t, r.Results[0], "ARCHIVED", "UNKNOWN")
	})
}

func TestCIAcceptance(t *testing.T) {
	t.Run("UT20_medium_default", func(t *testing.T) { mediumGate(t, false, 0) })
	t.Run("UT21_medium_strict", func(t *testing.T) { mediumGate(t, true, 1) })
	t.Run("UT22_incomplete_default", func(t *testing.T) {
		p := offlinePolicy()
		r := runScan(t, p, nil, "2026-10-11", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true)
		if !r.CIGate.Incomplete || reporting.ExitCode(r) != 0 {
			t.Fatalf("gate: %+v", r.CIGate)
		}
	})
	t.Run("UT23_strict_incomplete_at_ratio_boundary", func(t *testing.T) {
		p := offlinePolicy()
		p.CI.FailOnIncompleteScan = true
		p.CI.MaxUnknownRatio = model.Ptr(0.25)
		c := testCatalog()
		sbom := componentSBOM("pkg:gem/example@2.4.7")
		for i := 1; i < 3; i++ {
			x := sbom.Components[0]
			x.SourceRef = fmt.Sprint(i)
			sbom.Components = append(sbom.Components, x)
		}
		sbom.Components = append(sbom.Components, model.Component{SourceRef: "unknown", Name: "unknown", PURL: "pkg:gem/unknown@1.0"})
		r := runScan(t, p, c, "2026-10-11", testutil.NewStub(), sbom, true)
		if reporting.ExitCode(r) != 3 || r.Summary.Unknown != 1 {
			t.Fatalf("gate: %+v", r.CIGate)
		}
	})
	t.Run("UT24_EOLOutweighsIncomplete", func(t *testing.T) {
		p := offlinePolicy()
		p.CI.FailOnIncompleteScan = true
		c := testCatalog()
		c.Entries[0].EOLEffectiveDate = "2026-10-01"
		sbom := componentSBOM("pkg:gem/example@2.4.7")
		sbom.Components = append(sbom.Components, model.Component{SourceRef: "unknown", Name: "unknown", PURL: "pkg:gem/unknown@1.0"})
		r := runScan(t, p, c, "2026-10-11", testutil.NewStub(), sbom, true)
		if reporting.ExitCode(r) != 1 || !r.CIGate.Incomplete {
			t.Fatalf("gate: %+v", r.CIGate)
		}
	})
	t.Run("UT29_exception_preserves_lifecycle", func(t *testing.T) {
		p := offlinePolicy()
		c := testCatalog()
		c.Entries[0].EOLEffectiveDate = "2026-10-01"
		b := testBundle(t, p, c)
		b.Exceptions = &model.Exceptions{SchemaVersion: 2, Exceptions: []model.Exception{{PackagePURL: "pkg:gem/example@2.4.7", Suppress: []string{"CI_FAILURE"}, Reason: "migration", Owner: "appsec", ExpiresOn: "2026-10-11"}}}
		s := scanner.New(b, testutil.NewStub().Client(), testutil.FixedNow, "2026-10-11", true)
		r, err := s.Scan(context.Background(), componentSBOM("pkg:gem/example@2.4.7"))
		if err != nil {
			t.Fatal(err)
		}
		row := expectLifecycle(t, r, "EOL", "HIGH", "")
		if row.CIFailure || !row.ExceptionApplied || reporting.ExitCode(r) != 0 {
			t.Fatalf("exception: %+v", row)
		}
	})
}

func mediumGate(t *testing.T, strict bool, want int) {
	t.Helper()
	p := offlinePolicy()
	p.Sources.EndoflifeDate.Enabled = true
	if strict {
		p.CI.MinConfidence = "MEDIUM"
		p.CI.FailOnIncompleteScan = true
	}
	c := testCatalog()
	c.Entries = []model.CatalogEntry{}
	stub := testutil.NewStub()
	stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
	stub.Bodies["endoflife.date/api/v1/products/example/"] = testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false)
	r := runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
	expectLifecycle(t, r, "EOL", "MEDIUM", "")
	if reporting.ExitCode(r) != want {
		t.Fatalf("exit %d wanted %d", reporting.ExitCode(r), want)
	}
}

func TestContractAcceptance(t *testing.T) {
	t.Run("UT25_old_config_key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		os.WriteFile(path, []byte("schema_version: 2\ndecision:\n  unknown_on_same_tier_conflict: false\n"), 0600)
		var out, errout bytes.Buffer
		code := cli.Run(context.Background(), []string{"policy", "validate", "-c", path}, nil, &out, &errout, testutil.NewStub().Client(), testutil.FixedNow)
		if code != 2 {
			t.Fatalf("code=%d: %s", code, errout.String())
		}
	})
	t.Run("UT26_required_report_fields", func(t *testing.T) {
		b, err := os.ReadFile(testutil.Path(t, "examples/report.example.json"))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		json.Unmarshal(b, &value)
		row := value["results"].([]any)[0].(map[string]any)
		delete(row["notices"].([]any)[0].(map[string]any), "evidence_id")
		if contract.Validate("report", value) == nil {
			t.Fatal("missing notice evidence accepted")
		}
		json.Unmarshal(b, &value)
		row = value["results"].([]any)[0].(map[string]any)
		delete(row["evidence"].([]any)[0].(map[string]any), "valid_until")
		if contract.Validate("report", value) == nil {
			t.Fatal("missing nullable evidence field accepted")
		}
	})
	t.Run("UT32_artifact_schema_and_hashes", func(t *testing.T) {
		for _, name := range []string{"eol-policy.example.yaml", "eol-policy.ci-strict.yaml", "eol-policy.catalog.example.yaml", "eol-policy.partial.example.yaml"} {
			p, err := config.Load(testutil.Path(t, "examples", name))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := config.LoadBundle(p, testutil.Path(t, "examples", name)); err != nil {
				t.Fatal(err)
			}
		}
		p, err := config.Load(testutil.Path(t, "examples/eol-policy.catalog.example.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := config.LoadBundle(p, testutil.Path(t, "examples/eol-policy.catalog.example.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(testutil.Path(t, "examples/report.example.json"))
		var r model.Report
		json.Unmarshal(data, &r)
		if b.Hash != r.PolicyHash {
			t.Fatalf("portable hash: got %s wanted %s", b.Hash, r.PolicyHash)
		}
		for _, name := range []string{testutil.Path(t, "examples/report.example.json"), testutil.Path(t, "testdata/fixtures/report.future-date-conflict.json")} {
			data, _ := os.ReadFile(name)
			var v any
			json.Unmarshal(data, &v)
			if err := contract.Validate("report", v); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("UT41_catalog_publication_required", func(t *testing.T) {
		c := testCatalog()
		v, _ := contract.JSONValue(c)
		m := v.(map[string]any)
		delete(m["verified_versions"].([]any)[0].(map[string]any), "published_at")
		if contract.Validate("support-catalog", v) == nil {
			t.Fatal("missing local publication accepted")
		}
	})
}
