package acceptance

import (
	"strings"
	"testing"

	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestPyPIActivityUsesReleaseDatesAndRetainedLegacyEggs(t *testing.T) {
	for _, tc := range []struct {
		name, expected string
		files          []map[string]any
	}{
		{"legacy_egg", "ABSENT", []map[string]any{
			{"filename": "example-1.0.0.tar.gz", "upload-time": "2020-01-01T00:00:00Z", "yanked": false},
			{"filename": "example-1.0.0-py2.7.egg", "upload-time": "2020-01-02T00:00:00Z", "yanked": false},
			{"filename": "example-2.0.0.tar.gz", "upload-time": "2026-09-01T00:00:00Z", "yanked": false},
		}},
		{"missing_old_date", "ABSENT", []map[string]any{
			{"filename": "example-1.0.0.tar.gz", "yanked": false},
			{"filename": "example-2.0.0.tar.gz", "upload-time": "2026-09-01T00:00:00Z", "yanked": false},
		}},
		{"missing_same_release_date", "UNKNOWN", []map[string]any{
			{"filename": "example-2.0.0.tar.gz", "upload-time": "2026-09-01T00:00:00Z", "yanked": false},
			{"filename": "example-2.0.0-py3-none-any.whl", "yanked": false},
		}},
		{"unassigned_artifact", "UNKNOWN", []map[string]any{
			{"filename": "unknown-format.bin", "upload-time": "2020-01-01T00:00:00Z", "yanked": false},
			{"filename": "example-2.0.0.tar.gz", "upload-time": "2026-09-01T00:00:00Z", "yanked": false},
		}},
		{"new_wheel_for_old_release", "PRESENT", []map[string]any{
			{"filename": "example-2.0.0.tar.gz", "upload-time": "2020-01-01T00:00:00Z", "yanked": false},
			{"filename": "example-2.0.0-py3-none-any.whl", "upload-time": "2026-09-01T00:00:00Z", "yanked": false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.PyPI.Enabled = true
			p.CI.FailOnSignals = []string{"STALE_RELEASE"}
			p.CI.FailOnIncompleteScan = true
			stub := testutil.NewStub()
			pypiPackage(t, stub, "example", "active", tc.files)
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:pypi/example@2.0.0"), false)
			signalStatus(t, report.Results[0], "STALE_RELEASE", tc.expected)
			wantExit := map[string]int{"ABSENT": 0, "PRESENT": 1, "UNKNOWN": 3}[tc.expected]
			if reporting.ExitCode(report) != wantExit || stub.Count("pypi.org/simple/example/") != 1 {
				t.Fatalf("exit=%d requests=%v report=%+v", reporting.ExitCode(report), stub.Calls, report)
			}
		})
	}
}

func TestNativeNPMActivitySurvivesMissingOlderPublication(t *testing.T) {
	p := offlinePolicy()
	p.Sources.NPM.Enabled = true
	p.CI.FailOnSignals = []string{"STALE_RELEASE"}
	p.CI.FailOnIncompleteScan = true
	stub := testutil.NewStub()
	npmPackage(t, stub, "example", map[string]string{"1.0.0": "", "2.0.0": "2026-09-01T00:00:00Z"}, nil)
	report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/example@2.0.0"), false)
	signalStatus(t, report.Results[0], "STALE_RELEASE", "ABSENT")
	if reporting.ExitCode(report) != 0 {
		t.Fatalf("gate=%+v", report.CIGate)
	}
}

func TestDepsDevRecentPublicationCanProveActivityInLimitedIndices(t *testing.T) {
	for _, tc := range []struct {
		system, name, purl string
	}{
		{"NUGET", "example", "pkg:nuget/example@2.0.0"},
		{"GO", "github.com/example/project", "pkg:golang/github.com/example/project@v2.0.0"},
		{"PYPI", "example", "pkg:pypi/example@2.0.0"},
	} {
		t.Run(tc.system, func(t *testing.T) {
			p := offlinePolicy()
			p.Sources.DepsDev.Enabled = true
			p.CI.FailOnSignals = []string{"STALE_RELEASE"}
			p.CI.FailOnIncompleteScan = true
			p.Signals.Deprecated = false
			stub := testutil.NewStub()
			id, reason := identity.Resolve(model.Component{PURL: tc.purl})
			if reason != "" {
				t.Fatal(reason)
			}
			testutil.PutJSON(t, stub, strings.TrimPrefix(identity.VersionURL(p.Sources.DepsDev.BaseURL, id), "https://"), map[string]any{
				"versionKey": provider.DepsKey{System: tc.system, Name: tc.name, Version: id.Version}, "publishedAt": "2026-09-01T00:00:00Z",
			})
			testutil.PutJSON(t, stub, strings.TrimPrefix(identity.PackageURL(p.Sources.DepsDev.BaseURL, id), "https://"), map[string]any{
				"packageKey": provider.DepsKey{System: tc.system, Name: tc.name},
				"versions": []provider.DepsVersion{
					{Key: provider.DepsKey{System: tc.system, Name: tc.name, Version: "1.0.0"}},
					{Key: provider.DepsKey{System: tc.system, Name: tc.name, Version: id.Version}, PublishedAt: "2026-09-01T00:00:00Z"},
				},
			})
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM(tc.purl), false)
			signalStatus(t, report.Results[0], "STALE_RELEASE", "ABSENT")
			if reporting.ExitCode(report) != 0 || model.Text(report.Results[0].SignalEvaluations[0].ProviderID) != "deps_dev" {
				t.Fatalf("report=%+v", report)
			}
		})
	}
}
