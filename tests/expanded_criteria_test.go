package acceptance

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestGeneralSeriesEndCanWarnWhileSecurityWindowContinues(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		p := offlinePolicy()
		p.Sources.EndoflifeDate.Enabled = true
		if enabled {
			p.Decision.EOLRules = []model.EOLRule{{ID: "series-ended", AnyOf: []string{"RELEASE_SERIES_EOL"}}}
		}
		stub := testutil.NewStub()
		stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
		var doc map[string]any
		json.Unmarshal([]byte(testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false)), &doc)
		doc["result"].(map[string]any)["labels"] = map[string]any{"eol": "OSS support"}
		testutil.PutJSON(t, stub, "endoflife.date/api/v1/products/example/", doc)
		catalog := testCatalog()
		catalog.GeneralEolReviews = []model.GeneralEolReview{}
		report := runScan(t, p, catalog, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		row := report.Results[0]
		want := "SUPPORTED"
		if enabled {
			want = "EOL"
		}
		if row.Lifecycle != want || row.SupportAssessment.Lifecycle != "SUPPORTED" || row.Incomplete {
			t.Fatalf("enabled=%v: %+v", enabled, row)
		}
		if enabled {
			signalStatus(t, row, "RELEASE_SERIES_EOL", "PRESENT")
			if row.Signals[0].Details["support_label"] != "OSS support" || row.Signals[0].Details["eol_effective_date"] != "2026-10-01" {
				t.Fatal("original support phase or end date was lost")
			}
		}
	}
}

func TestDeclaredUnmaintainedWithConfigurableRepositoryInactivity(t *testing.T) {
	for _, tc := range []struct{ name, text, pushed, want string }{
		{"ended_and_old", "This project is no longer actively maintained!", "2020-01-01T00:00:00Z", "EOL"},
		{"ended_but_recent", "This project is no longer actively maintained!", "2026-10-01T00:00:00Z", "NO_EOL_DETECTED"},
		{"other_dependency", "The old pathlib module on bitbucket is no longer maintained.", "2020-01-01T00:00:00Z", "NO_EOL_DETECTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "both", AllOf: []string{"DECLARED_UNMAINTAINED", "STALE_REPOSITORY"}})
			p.Signals.StaleRepositoryDays = model.Ptr(730)
			stub := testutil.NewStub()
			npmSource(t, stub, "https://github.com/publisher/leaf", "", "2020-01-01T00:00:00Z")
			stub.Bodies["registry.npmjs.org/transitive-leaf/1.0.0"] = `{"name":"transitive-leaf","version":"1.0.0","description":"A utility."}`
			testutil.PutJSON(t, stub, "api.github.com/repos/publisher/leaf", map[string]any{"full_name": "publisher/leaf", "archived": false, "pushed_at": tc.pushed})
			testutil.PutJSON(t, stub, "api.github.com/repos/publisher/leaf/readme", map[string]any{"type": "file", "path": "README.md", "encoding": "base64", "size": len(tc.text), "content": base64.StdEncoding.EncodeToString([]byte(tc.text))})
			report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
			if row := report.Results[0]; row.Lifecycle != tc.want || row.Incomplete {
				t.Fatalf("%+v", row)
			}
			if stub.Count("api.github.com/repos/publisher/leaf") != 1 {
				t.Fatal("repository was requested repeatedly")
			}
		})
	}
}

func TestIndependentEOLRuleDoesNotSkipCIRequiredDeclaration(t *testing.T) {
	for _, required := range []bool{false, true} {
		p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}}, model.EOLRule{ID: "declared", AnyOf: []string{"DECLARED_UNMAINTAINED"}})
		if required {
			p.CI.FailOnSignals = []string{"DECLARED_UNMAINTAINED"}
		}
		stub := testutil.NewStub()
		npmSource(t, stub, "https://github.com/publisher/leaf", "", "2020-01-01T00:00:00Z")
		stub.Bodies["api.github.com/repos/publisher/leaf"] = `{"full_name":"publisher/leaf","archived":true}`
		stub.Status["api.github.com/repos/publisher/leaf/readme"] = 404
		report := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:npm/transitive-leaf@1.0.0"), false)
		row := report.Results[0]
		if row.Lifecycle != "EOL" || row.Incomplete != required || (stub.Count("api.github.com/repos/publisher/leaf/readme") > 0) != required {
			t.Fatalf("required=%v row=%+v calls=%v", required, row, stub.Calls)
		}
		signalStatus(t, row, "DECLARED_UNMAINTAINED", "UNKNOWN")
	}
}

func TestSeriesEndAvoidsUnneededDeclarationRequests(t *testing.T) {
	p := config.Default()
	p.Sources.NPM.Enabled, p.Sources.PyPI.Enabled, p.Sources.RubyGems.Enabled, p.Sources.DepsDev.Enabled = false, false, false, false
	stub := testutil.NewStub()
	stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = testutil.IndexBody("example")
	stub.Bodies["endoflife.date/api/v1/products/example/"] = testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false)
	report := runScan(t, p, testCatalog(), "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
	if report.Results[0].Lifecycle != "EOL" {
		t.Fatal(report.Results[0])
	}
	for key := range stub.Calls {
		if len(key) >= 14 && key[:14] == "api.github.com" {
			t.Fatal("unneeded declaration lookup", stub.Calls)
		}
	}
}
