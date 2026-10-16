package acceptance

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
	reporting "github.com/Pirikara/eolscan/internal/report"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestNativeStaleEOLThresholdBoundaries(t *testing.T) {
	for _, ecosystem := range []string{"npm", "pypi", "gem"} {
		for _, days := range []int{364, 365, 366} {
			t.Run(ecosystem+"/"+strconv.Itoa(days), func(t *testing.T) {
				p := rulePolicy(model.EOLRule{ID: "inactive", AnyOf: []string{"STALE_RELEASE"}})
				p.Signals.StaleReleaseDays = model.Ptr(365)
				p.Sources.NPM.Enabled, p.Sources.PyPI.Enabled, p.Sources.RubyGems.Enabled = ecosystem == "npm", ecosystem == "pypi", ecosystem == "gem"
				published := testutil.FixedNow.AddDate(0, 0, -days).Format(time.RFC3339)
				stub := testutil.NewStub()
				switch ecosystem {
				case "npm":
					npmPackage(t, stub, "leaf", map[string]string{"1.0.0": published}, nil)
				case "pypi":
					pypiPackage(t, stub, "leaf", "active", []map[string]any{{"filename": "leaf-1.0.0.tar.gz", "upload-time": published, "yanked": false}})
				case "gem":
					testutil.PutJSON(t, stub, "rubygems.org/api/v1/versions/leaf.json", []map[string]string{{"number": "1.0.0", "platform": "ruby", "created_at": published}})
				}
				report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:"+ecosystem+"/leaf@1.0.0"), false)
				want, status, exit := "NO_EOL_DETECTED", "ABSENT", 0
				if days == 366 {
					want, status, exit = "EOL", "PRESENT", 1
				}
				row := report.Results[0]
				signalStatus(t, row, "STALE_RELEASE", status)
				if row.Lifecycle != want || row.Incomplete || reporting.ExitCode(report) != exit || len(stub.Calls) != 1 {
					t.Fatalf("native threshold boundary: %+v calls=%v", report, stub.Calls)
				}
			})
		}
	}
}

func TestStaleEOLUsesLatestProjectReleaseRatherThanSBOMVersionAge(t *testing.T) {
	for _, ecosystem := range []string{"npm", "pypi", "gem"} {
		t.Run(ecosystem, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "inactive", AnyOf: []string{"STALE_RELEASE"}})
			p.Signals.StaleReleaseDays = model.Ptr(365)
			p.Sources.NPM.Enabled, p.Sources.PyPI.Enabled, p.Sources.RubyGems.Enabled = ecosystem == "npm", ecosystem == "pypi", ecosystem == "gem"
			stub := testutil.NewStub()
			switch ecosystem {
			case "npm":
				npmPackage(t, stub, "leaf", map[string]string{"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-10-01T00:00:00Z"}, nil)
			case "pypi":
				pypiPackage(t, stub, "leaf", "active", []map[string]any{
					{"filename": "leaf-1.0.0.tar.gz", "upload-time": "2020-01-01T00:00:00Z", "yanked": false},
					{"filename": "leaf-2.0.0.tar.gz", "upload-time": "2026-10-01T00:00:00Z", "yanked": false},
				})
			case "gem":
				stub.Bodies["rubygems.org/api/v1/versions/leaf.json"] = `[{"number":"1.0.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z"},{"number":"2.0.0","platform":"ruby","created_at":"2026-10-01T00:00:00Z"}]`
			}
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:"+ecosystem+"/leaf@1.0.0"), false)
			row := expectLifecycle(t, report, "NO_EOL_DETECTED", "", "")
			if row.Incomplete || reporting.ExitCode(report) != 0 || model.Text(row.VersionVerification.PublishedAt) != "2020-01-01T00:00:00Z" {
				t.Fatal("a recent project release was ignored or rewrote the SBOM version's publication")
			}
		})
	}
}

func TestUnavailableRuleConditionsRemainUnresolved(t *testing.T) {
	for _, kind := range []string{"RETRACTED", "STALE_REPOSITORY"} {
		for _, tc := range []struct {
			name, group, deprecation, want string
			ciRequiresUnavailable          bool
			incomplete                     bool
		}{
			{"required_unknown", "any", "", "UNKNOWN", false, true},
			{"positive_or_resolves", "any", "No longer maintained", "EOL", false, false},
			{"negative_and_resolves", "all", "", "NO_EOL_DETECTED", false, false},
			{"ci_requirement_stays_incomplete", "all", "", "NO_EOL_DETECTED", true, true},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				rule := model.EOLRule{ID: "custom"}
				if tc.group == "all" {
					rule.AllOf = []string{kind, "DEPRECATED"}
				} else {
					rule.AnyOf = []string{kind, "DEPRECATED"}
				}
				p := rulePolicy(rule)
				if kind == "STALE_REPOSITORY" {
					p.Signals.StaleRepositoryDays = model.Ptr(730)
				}
				if tc.ciRequiresUnavailable {
					p.CI.FailOnSignals = []string{kind}
				}
				stub := testutil.NewStub()
				npmSource(t, stub, "", tc.deprecation, "2020-01-01T00:00:00Z")
				report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
				row := report.Results[0]
				signalStatus(t, row, kind, "UNKNOWN")
				if row.Lifecycle != tc.want || row.Incomplete != tc.incomplete || report.CIGate.Incomplete != tc.incomplete {
					b, _ := json.Marshal(report)
					t.Fatalf("unavailable capability was hidden: %s", b)
				}
			})
		}
	}
}
