package acceptance

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func npmPackage(t *testing.T, stub *testutil.StubAPI, name string, times map[string]string, deprecated map[string]string) {
	t.Helper()
	versions := map[string]any{}
	for v := range times {
		item := map[string]any{"name": name, "version": v}
		if reason, ok := deprecated[v]; ok {
			item["deprecated"] = reason
		}
		versions[v] = item
	}
	testutil.PutJSON(t, stub, "registry.npmjs.org/"+name, map[string]any{"name": name, "versions": versions, "time": times})
}

func pypiPackage(t *testing.T, stub *testutil.StubAPI, name, status string, files []map[string]any) {
	t.Helper()
	doc := map[string]any{"name": name, "meta": map[string]any{"api-version": "1.4"}, "files": files}
	if status != "" {
		doc["project-status"] = map[string]any{"status": status}
	}
	testutil.PutJSON(t, stub, "pypi.org/simple/"+name+"/", doc)
}

func TestNativeNPMPackageIsSharedAcrossSBOMVersions(t *testing.T) {
	p := offlinePolicy()
	p.Sources.NPM.Enabled = true
	p.Sources.DepsDev.Enabled = true
	p.CI.FailOnSignals = []string{"DEPRECATED"}
	stub := testutil.NewStub()
	npmPackage(t, stub, "example", map[string]string{"1.0.0": "2023-04-12T09:00:00Z", "2.0.0": "2026-09-01T09:00:00Z"}, map[string]string{"1.0.0": "Use version 2"})
	sbom := componentSBOM("pkg:npm/example@1.0.0")
	sbom.Components = append(sbom.Components, model.Component{SourceRef: "component-2", Name: "example", PURL: "pkg:npm/example@2.0.0"})
	r := runScan(t, p, nil, "2026-10-11", stub, sbom, false)
	if len(stub.Calls) != 1 || stub.Count("registry.npmjs.org/example") != 1 || r.CIGate.Incomplete {
		t.Fatalf("native package request was duplicated or fell back: calls=%v gate=%+v", stub.Calls, r.CIGate)
	}
	for i, row := range r.Results {
		if row.VersionVerification.Status != "VERIFIED" || model.Text(row.VersionVerification.ProviderID) != "npm" || row.Lifecycle != "UNKNOWN" || len(row.Evidence) != 0 {
			t.Fatalf("registry metadata became lifecycle evidence: %+v", row)
		}
		want := "ABSENT"
		if i == 0 {
			want = "PRESENT"
		}
		signalStatus(t, row, "DEPRECATED", want)
		signalStatus(t, row, "STALE_RELEASE", "ABSENT")
	}
	if !r.Results[0].CIFailure || r.Results[1].CIFailure || r.Summary.CIFailureCount != 1 {
		t.Fatal("deprecation gate did not use the exact version")
	}
}

func TestPyPIYankAndReleaseDatesUseAllArtifacts(t *testing.T) {
	p := offlinePolicy()
	p.Sources.PyPI.Enabled = true
	p.Sources.DepsDev.Enabled = true
	p.Signals.Yanked = true
	p.CI.FailOnSignals = []string{"YANKED", "STALE_RELEASE"}
	stub := testutil.NewStub()
	pypiPackage(t, stub, "example", "active", []map[string]any{
		{"filename": "example-1.0.0.tar.gz", "upload-time": "2020-01-01T09:00:00Z", "yanked": "bad release"},
		{"filename": "example-1.0.0-py3-none-any.whl", "upload-time": "2026-10-10T09:00:00Z", "yanked": ""},
		{"filename": "example-2.0.0.tar.gz", "upload-time": "2021-01-01T09:00:00Z", "yanked": true},
		{"filename": "example-2.0.0-py3-none-any.whl", "upload-time": "2021-01-02T09:00:00Z", "yanked": false},
	})
	sbom := componentSBOM("pkg:pypi/example@1.0.0")
	sbom.Components = append(sbom.Components, model.Component{SourceRef: "component-2", Name: "example", PURL: "pkg:pypi/example@2.0.0"})
	r := runScan(t, p, nil, "2026-10-11", stub, sbom, false)
	if len(stub.Calls) != 1 || r.CIGate.Incomplete || model.Text(r.Results[0].VersionVerification.PublishedAt) != "2020-01-01T09:00:00Z" {
		t.Fatalf("publication or sharing: calls=%v report=%+v", stub.Calls, r)
	}
	signalStatus(t, r.Results[0], "YANKED", "PRESENT")
	signalStatus(t, r.Results[1], "YANKED", "ABSENT")
	for _, row := range r.Results {
		signalStatus(t, row, "STALE_RELEASE", "PRESENT")
		signalStatus(t, row, "DEPRECATED", "ABSENT")
		if row.Lifecycle != "UNKNOWN" || len(row.Evidence) != 0 {
			t.Fatal("maintenance metadata inferred EOL")
		}
		for _, signal := range row.Signals {
			if signal.Type == "STALE_RELEASE" && signal.Details["latest_published_at"] != "2021-01-01T09:00:00Z" {
				t.Fatal("a new wheel for an old version reset its release date")
			}
		}
	}
}

func TestPyPIProjectStatusAndMissingInformation(t *testing.T) {
	for _, tc := range []struct {
		status, deprecated, archived, quarantined string
		incomplete                                bool
	}{
		{"active", "ABSENT", "ABSENT", "ABSENT", false},
		{"deprecated", "PRESENT", "ABSENT", "ABSENT", false},
		{"archived", "ABSENT", "PRESENT", "ABSENT", false},
		{"quarantined", "ABSENT", "ABSENT", "PRESENT", false},
		{"", "UNKNOWN", "UNKNOWN", "UNKNOWN", true},
		{"future-status", "UNKNOWN", "UNKNOWN", "UNKNOWN", true},
	} {
		t.Run(tc.status, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.PyPI.Enabled = true
			p.Signals.StaleReleaseDays = nil
			p.Signals.Archived, p.Signals.Quarantined = true, true
			p.CI.FailOnSignals = []string{"ARCHIVED"}
			p.CI.FailOnIncompleteScan = true
			stub := testutil.NewStub()
			pypiPackage(t, stub, "example", tc.status, []map[string]any{{"filename": "example-1.0.0.tar.gz", "upload-time": "2024-04-12T09:00:00Z", "yanked": false}})
			r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:pypi/example@1.0.0"), false)
			row := expectLifecycle(t, r, "UNKNOWN", "", "NO_LIFECYCLE_EVIDENCE")
			signalStatus(t, row, "DEPRECATED", tc.deprecated)
			signalStatus(t, row, "ARCHIVED", tc.archived)
			signalStatus(t, row, "QUARANTINED", tc.quarantined)
			if row.Incomplete != tc.incomplete || r.CIGate.Incomplete != tc.incomplete {
				t.Fatalf("missing status was treated as a confirmed negative: %+v", row)
			}
		})
	}
	t.Run("unknown_artifact_cannot_confirm_all_yanked", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.PyPI.Enabled = true
		p.Signals.StaleReleaseDays = nil
		p.CI.FailOnSignals = []string{"YANKED"}
		stub := testutil.NewStub()
		pypiPackage(t, stub, "example", "active", []map[string]any{
			{"filename": "example-1.0.0.tar.gz", "upload-time": "2024-04-12T09:00:00Z", "yanked": true},
			{"filename": "legacy.egg", "upload-time": "2024-04-12T09:00:00Z", "yanked": false},
		})
		r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:pypi/example@1.0.0"), false)
		signalStatus(t, r.Results[0], "YANKED", "UNKNOWN")
		if !r.CIGate.Incomplete || r.Results[0].CIFailure {
			t.Fatal("unknown artifact created a false positive")
		}
	})
}

func TestRubyGemsPublicationAndPlatformScope(t *testing.T) {
	for _, platform := range []string{"", "ruby", "java"} {
		t.Run(platform, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.RubyGems.Enabled = true
			p.Sources.DepsDev.Enabled = true
			p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
			p.CI.FailOnSignals = []string{"YANKED"}
			stub := testutil.NewStub()
			stub.Bodies["rubygems.org/api/v1/versions/example.json"] = `[{"number":"2.4.7","platform":"ruby","created_at":"2024-04-12T09:00:00Z","built_at":"2026-10-10T00:00:00Z"}]`
			stub.Bodies["rubygems.org/api/v2/rubygems/example/versions/2.4.7.json"] = `{"name":"example","version":"2.4.7","platform":"ruby","version_created_at":"2024-04-12T09:00:00Z","yanked":false}`
			purl := "pkg:gem/example@2.4.7"
			if platform != "" {
				purl += "?platform=" + platform
			}
			r := runScan(t, p, nil, "2025-01-01", stub, componentSBOM(purl), false)
			row := r.Results[0]
			if platform == "java" {
				if row.VersionVerification.Status == "VERIFIED" {
					t.Fatal("another platform certified an absent artifact")
				}
			} else if row.VersionVerification.Status != "VERIFIED" || model.Text(row.VersionVerification.PublishedAt) != "2024-04-12T09:00:00Z" {
				t.Fatal("build time was used as publication time")
			}
			if platform == "" {
				signalStatus(t, row, "YANKED", "ABSENT")
				if len(stub.Calls) != 2 || row.Incomplete {
					t.Fatalf("v2 lookup: %v %+v", stub.Calls, row)
				}
			} else {
				signalStatus(t, row, "YANKED", "UNKNOWN")
				if len(stub.Calls) != 1 || !row.Incomplete {
					t.Fatalf("platform fallback was unsafe: %v %+v", stub.Calls, row)
				}
			}
		})
	}
}

func TestRubyGemsDetailCannotCertifyOtherPlatforms(t *testing.T) {
	for _, yanked := range []bool{true, false} {
		p := offlinePolicy()
		p.Sources.RubyGems.Enabled = true
		p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
		p.CI.FailOnSignals = []string{"YANKED"}
		stub := testutil.NewStub()
		stub.Bodies["rubygems.org/api/v1/versions/example.json"] = `[
			{"number":"2.4.7","platform":"ruby","created_at":"2024-04-12T09:00:00Z"},
			{"number":"2.4.7","platform":"java","created_at":"2024-04-12T09:00:00Z"}]`
		testutil.PutJSON(t, stub, "rubygems.org/api/v2/rubygems/example/versions/2.4.7.json", map[string]any{
			"name": "example", "version": "2.4.7", "platform": "ruby", "version_created_at": "2024-04-12T09:00:00Z", "yanked": yanked,
		})
		r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		want := "ABSENT"
		if yanked {
			want = "UNKNOWN"
		}
		signalStatus(t, r.Results[0], "YANKED", want)
		if r.Results[0].Incomplete != yanked || r.Results[0].CIFailure {
			t.Fatal("one platform created an all-artifacts yank finding")
		}
	}
}

func TestNativeVersionFailuresUseEquivalentDepsFallback(t *testing.T) {
	for _, tc := range []struct {
		name, body, diagnostic string
		status                 int
	}{
		{"not_found", "", "", 404},
		{"rate_limited", "", "RATE_LIMITED", 429},
		{"unavailable", "", "SOURCE_ERROR", 503},
		{"malformed", `{"name":`, "PROVIDER_SCHEMA_MISMATCH", 200},
		{"wrong_identity", `{"name":"other","versions":{}}`, "PROVIDER_SCHEMA_MISMATCH", 200},
		{"missing_date", `{"name":"example","versions":{"1.0.0":{"name":"example","version":"1.0.0"}}}`, "MISSING_PUBLICATION_DATE", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.NPM.Enabled, p.Sources.DepsDev.Enabled = true, true
			p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
			p.Network.Retries = 0
			stub := testutil.NewStub()
			stub.Status["registry.npmjs.org/example"] = tc.status
			stub.Bodies["registry.npmjs.org/example"] = tc.body
			stub.Bodies["api.deps.dev/v3/systems/npm/packages/example/versions/1.0.0"] = `{"versionKey":{"system":"NPM","name":"example","version":"1.0.0"},"publishedAt":"2024-04-12T09:00:00Z","isDeprecated":false}`
			r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/example@1.0.0"), false)
			row := r.Results[0]
			if row.VersionVerification.Status != "VERIFIED" || model.Text(row.VersionVerification.ProviderID) != "deps_dev" || r.CIGate.Incomplete || len(stub.Calls) != 2 {
				t.Fatalf("fallback did not complete: %+v calls=%v", row, stub.Calls)
			}
			if tc.diagnostic != "" && !hasDiagnostic(row, tc.diagnostic, "npm") {
				t.Fatalf("native failure disappeared: %+v", row.Diagnostics)
			}
		})
	}
	t.Run("conflicting_deprecation_is_not_hidden", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.NPM.Enabled, p.Sources.DepsDev.Enabled = true, true
		p.Signals.StaleReleaseDays = nil
		p.CI.FailOnSignals = []string{"DEPRECATED"}
		stub := testutil.NewStub()
		stub.Bodies["registry.npmjs.org/example"] = `{"name":"example","versions":{"1.0.0":{"name":"example","version":"1.0.0","deprecated":"withdrawn"}}}`
		stub.Bodies["api.deps.dev/v3/systems/npm/packages/example/versions/1.0.0"] = `{"versionKey":{"system":"NPM","name":"example","version":"1.0.0"},"publishedAt":"2024-04-12T09:00:00Z","isDeprecated":false}`
		r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/example@1.0.0"), false)
		signalStatus(t, r.Results[0], "DEPRECATED", "UNKNOWN")
		if !r.CIGate.Incomplete || !hasDiagnostic(r.Results[0], "SIGNAL_CONFLICT", "") || len(stub.Calls) != 2 {
			t.Fatalf("conflicting source status was lost: %+v", r.Results[0])
		}
	})
}

func TestNativeProofAndRequiredSignalsControlFallback(t *testing.T) {
	t.Run("published_after_as_of_is_terminal", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.NPM.Enabled, p.Sources.DepsDev.Enabled = true, true
		p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
		stub := testutil.NewStub()
		npmPackage(t, stub, "example", map[string]string{"1.0.0": "2024-04-12T09:00:00Z"}, nil)
		r := runScan(t, p, nil, "2024-01-01", stub, componentSBOM("pkg:npm/example@1.0.0"), false)
		if r.Results[0].VersionVerification.Status != "NOT_RELEASED_AS_OF" || len(stub.Calls) != 1 {
			t.Fatalf("historical publication proof was overridden: %+v calls=%v", r.Results[0], stub.Calls)
		}
	})
	t.Run("local_proof_and_no_signals_need_no_http", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.RubyGems.Enabled, p.Sources.DepsDev.Enabled = true, true
		p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
		stub := testutil.NewStub()
		r := runScan(t, p, testCatalog(), "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		expectLifecycle(t, r, "SUPPORTED", "HIGH", "")
		if len(stub.Calls) != 0 || model.Text(r.Results[0].VersionVerification.ProviderID) != "official_catalog" {
			t.Fatal("valid local version assertion was not preferred")
		}
	})
	t.Run("unsupported_required_signal_is_incomplete", func(t *testing.T) {
		p := offlinePolicy()
		p.Sources.NPM.Enabled = true
		p.Signals.Deprecated, p.Signals.StaleReleaseDays = false, nil
		p.CI.FailOnSignals = []string{"YANKED"}
		p.CI.FailOnIncompleteScan = true
		stub := testutil.NewStub()
		npmPackage(t, stub, "example", map[string]string{"1.0.0": "2024-04-12T09:00:00Z"}, nil)
		r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/example@1.0.0"), false)
		signalStatus(t, r.Results[0], "YANKED", "UNKNOWN")
		if !r.CIGate.Incomplete || r.CIGate.Passed || len(stub.Calls) != 1 {
			t.Fatalf("unsupported signal passed: %+v", r.CIGate)
		}
	})
}

func TestNativePyPICacheWorksOffline(t *testing.T) {
	p := offlinePolicy()
	p.Sources.PyPI.Enabled = true
	p.Cache.Enabled = true
	p.Signals.Yanked = true
	p.CI.FailOnSignals = []string{"YANKED"}
	p.CI.FailOnIncompleteScan = true
	stub := testutil.NewStub()
	pypiPackage(t, stub, "example", "active", []map[string]any{{"filename": "example-1.0.0.tar.gz", "upload-time": "2024-04-12T09:00:00Z", "yanked": false}})
	dir := t.TempDir()
	for i, tc := range []struct {
		age        time.Duration
		offline    bool
		incomplete bool
	}{
		{0, false, false}, {time.Hour, true, false}, {48 * time.Hour, true, false}, {31 * 24 * time.Hour, true, true},
	} {
		now := testutil.FixedNow.Add(tc.age)
		clock := testutil.NewClock(now)
		tr := transport.New(stub.Client(), p, now, tc.offline, transport.WithClock(clock.Now), transport.WithWait(clock.Wait), transport.WithCacheDir(dir))
		s := scanner.NewWithTransport(testBundle(t, p, nil), tr, model.UTCDate(now))
		r, err := s.Scan(context.Background(), componentSBOM("pkg:pypi/example@1.0.0"))
		if err != nil {
			t.Fatal(err)
		}
		if r.CIGate.Incomplete != tc.incomplete || stub.Count("pypi.org/simple/example/") != 1 {
			t.Fatalf("case %d: cache state=%+v calls=%v", i, r.CIGate, stub.Calls)
		}
		if !tc.incomplete {
			signalStatus(t, r.Results[0], "YANKED", "ABSENT")
			if r.Results[0].VersionVerification.Status != "VERIFIED" {
				t.Fatal("cached publication proof was lost")
			}
		}
	}
}

func TestNativeRequiredSignalAPIFailureRemainsUnknown(t *testing.T) {
	p := offlinePolicy()
	p.Sources.NPM.Enabled = true
	p.CI.FailOnSignals = []string{"DEPRECATED"}
	p.CI.FailOnIncompleteScan = true
	p.Signals.StaleReleaseDays = nil
	p.Network.Retries = 0
	clock := testutil.NewClock(testutil.FixedNow)
	client := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"86400"}}, Body: http.NoBody}, nil
	})}
	tr := transport.New(client, p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
	s := scanner.NewWithTransport(testBundle(t, p, nil), tr, "2026-10-11")
	r, err := s.Scan(context.Background(), componentSBOM("pkg:npm/example@1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	signalStatus(t, r.Results[0], "DEPRECATED", "UNKNOWN")
	if !r.CIGate.Incomplete || r.CIGate.Passed || r.Results[0].CIFailure || r.Summary.ProviderErrorCount == 0 || !clock.Now().Equal(testutil.FixedNow) {
		t.Fatalf("API failure became absence: %+v", r)
	}
}

func hasDiagnostic(row model.ComponentResult, code, provider string) bool {
	for _, d := range row.Diagnostics {
		if d.Code == code && (provider == "" || model.Text(d.ProviderID) == provider) {
			return true
		}
	}
	return false
}

func TestRegistrySchemaErrorsCannotProveVersion(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"unsupported_api", `{"name":"example","meta":{"api-version":"2.0"},"files":[]}`},
		{"wrong_package", `{"name":"other","meta":{"api-version":"1.4"},"files":[]}`},
		{"missing_files", `{"name":"example","meta":{"api-version":"1.4"}}`},
		{"wrong_yanked_type", `{"name":"example","meta":{"api-version":"1.4"},"files":[{"filename":"example-1.0.0.tar.gz","upload-time":"2024-04-12T09:00:00Z","yanked":123}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.PyPI.Enabled = true
			p.Signals.StaleReleaseDays = nil
			stub := testutil.NewStub()
			stub.Bodies["pypi.org/simple/example/"] = tc.body
			r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:pypi/example@1.0.0"), false)
			if !r.CIGate.Incomplete || r.Results[0].VersionVerification.Status != "UNVERIFIED" || !hasDiagnostic(r.Results[0], "PROVIDER_SCHEMA_MISMATCH", "pypi") {
				t.Fatalf("malformed provider data was accepted: %+v", r.Results[0])
			}
		})
	}
}
