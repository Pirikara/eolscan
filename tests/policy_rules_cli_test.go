package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/eolscan/internal/cli"
	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

// The expected outcomes are deliberately specified independently of the
// provider responses and report aggregation implementation.
var mixedPackages = []struct{ purl, lifecycle string }{
	{"pkg:npm/mixed-leaf@1.0.0", "EOL"},
	{"pkg:npm/mixed-leaf@2.0.0", "NO_EOL_DETECTED"},
	{"pkg:npm/mixed-leaf@1.0.0", "EOL"},
	{"pkg:gem/mixed-gem@1.0.0", "EOL"},
	{"pkg:cargo/mixed-crate@1.0.0", "EOL"},
	{"pkg:maven/org.example/mixed-lib@1.0.0", "NO_EOL_DETECTED"},
	{"pkg:golang/github.com/publisher/mixed-go@v1.0.0", "NO_EOL_DETECTED"},
	{"pkg:nuget/Mixed.Lib@1.0.0", "EOL"},
	{"pkg:pypi/mixed-python@1.0.0", "UNKNOWN"},
	{"pkg:gem/unversioned", "UNKNOWN"},
}

func mixedInput(t *testing.T, format string) []byte {
	t.Helper()
	components := []map[string]any{}
	for i, item := range mixedPackages {
		ref := fmt.Sprintf("dependency-%d", i)
		if format == "cyclonedx" {
			components = append(components, map[string]any{"type": "library", "name": ref, "bom-ref": ref, "purl": item.purl})
		} else {
			components = append(components, map[string]any{"name": ref, "SPDXID": ref, "externalRefs": []map[string]string{{"referenceType": "purl", "referenceLocator": item.purl}}})
		}
	}
	doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": components}
	if format == "spdx" {
		doc = map[string]any{"spdxVersion": "SPDX-2.3", "packages": components}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mixedProviderResponses(t *testing.T) *testutil.StubAPI {
	t.Helper()
	stub := testutil.NewStub()
	stub.Bodies["endoflife.date/api/v1/identifiers/purl/"] = `{"schema_version":"1.2.1","generated_at":"2026-10-11T00:00:00Z","result":[]}`
	npmPackage(t, stub, "mixed-leaf", map[string]string{"1.0.0": "2020-01-01T00:00:00Z", "2.0.0": "2026-10-01T00:00:00Z"}, map[string]string{"1.0.0": "No longer supported"})
	var npm map[string]any
	if err := json.Unmarshal([]byte(stub.Bodies["registry.npmjs.org/mixed-leaf"]), &npm); err != nil {
		t.Fatal(err)
	}
	for _, v := range npm["versions"].(map[string]any) {
		v.(map[string]any)["repository"] = "git+https://github.com/publisher/current.git"
	}
	testutil.PutJSON(t, stub, "registry.npmjs.org/mixed-leaf", npm)
	stub.Bodies["registry.npmjs.org/mixed-leaf/2.0.0"] = `{"name":"mixed-leaf","version":"2.0.0","description":"A maintained utility."}`
	stub.Bodies["rubygems.org/api/v1/versions/mixed-gem.json"] = `[{"number":"1.0.0","platform":"ruby","created_at":"2020-01-01T00:00:00Z"}]`
	stub.Bodies["rubygems.org/api/v2/rubygems/mixed-gem/versions/1.0.0.json"] = `{"name":"mixed-gem","version":"1.0.0","platform":"ruby","version_created_at":"2020-01-01T00:00:00Z","source_code_uri":"https://github.com/publisher/retired"}`
	pypiPackage(t, stub, "mixed-python", "active", []map[string]any{{"filename": "mixed_python-1.0.0.tar.gz", "upload-time": "2026-10-01T00:00:00Z", "yanked": false}})
	stub.Bodies["pypi.org/pypi/mixed-python/1.0.0/json"] = `{"info":{"name":"mixed-python","version":"1.0.0","project_urls":{},"description":"A maintained utility.","classifiers":[]}}`
	stub.Bodies["api.github.com/repos/publisher/current"] = `{"full_name":"publisher/current","archived":false}`
	stub.Bodies["api.github.com/repos/publisher/current/readme"] = `{"type":"file","path":"README.md","encoding":"base64","size":0,"content":""}`
	stub.Bodies["api.github.com/repos/publisher/retired"] = `{"full_name":"publisher/retired","archived":true}`
	for _, item := range mixedPackages {
		id, reason := identity.Resolve(model.Component{PURL: item.purl})
		if reason != "" || !model.Contains([]string{"maven", "golang", "cargo", "nuget"}, id.Type) {
			continue
		}
		project := "github.com/publisher/current"
		if id.Type == "cargo" {
			project = "github.com/publisher/retired"
		}
		key := map[string]string{"system": id.System, "name": id.Name, "version": id.Version}
		version := map[string]any{"versionKey": key, "publishedAt": "2026-10-01T00:00:00Z", "isDeprecated": id.Type == "nuget",
			"relatedProjects": []map[string]any{{"projectKey": map[string]string{"id": project}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}}}
		testutil.PutJSON(t, stub, strings.TrimPrefix(identity.VersionURL(config.Default().Sources.DepsDev.BaseURL, id), "https://"), version)
		testutil.PutJSON(t, stub, strings.TrimPrefix(identity.PackageURL(config.Default().Sources.DepsDev.BaseURL, id), "https://"),
			map[string]any{"packageKey": map[string]string{"system": id.System, "name": id.Name}, "versions": []any{version}})
	}
	return stub
}

func TestMixedEcosystemSBOMThroughCLI(t *testing.T) {
	for _, format := range []string{"cyclonedx", "spdx"} {
		for _, outputFormat := range []string{"json", "table"} {
			t.Run(format+"/"+outputFormat, func(t *testing.T) {
				p := config.Default()
				p.CI.MinConfidence, p.CI.FailOnIncompleteScan = "MEDIUM", true
				p.Network.RequestsPerSecond = 100
				policy, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "policy.yaml")
				if err := os.WriteFile(path, policy, 0600); err != nil {
					t.Fatal(err)
				}
				stub, input := mixedProviderResponses(t), mixedInput(t, format)
				var out, errs bytes.Buffer
				code := cli.Run(context.Background(), []string{"scan", "-i", "-", "-c", path, "-f", outputFormat}, bytes.NewReader(input), &out, &errs, stub.Client(), testutil.FixedNow)
				if code != 1 || !strings.Contains(errs.String(), "WARNING: 5 component") {
					t.Fatalf("mixed scan exit=%d stderr=%s stdout=%s", code, errs.String(), out.String())
				}
				if stub.Count("registry.npmjs.org/mixed-leaf") != 1 || stub.Count("api.github.com/repos/publisher/current") != 1 || stub.Count("api.github.com/repos/publisher/retired") != 1 {
					t.Fatalf("shared packages/repositories were queried repeatedly: %v", stub.Calls)
				}
				if outputFormat == "table" {
					for _, fragment := range []string{"EOL RULES", "deprecated=PRESENT", "archived=UNKNOWN", "NO_EOL_DETECTED", "Scanned 10", "EOL 5", "no EOL detected 3", "unknown 2", "policy coverage 80.0%", "CI violations:"} {
						if !strings.Contains(out.String(), fragment) {
							t.Fatalf("table omits %q: %s", fragment, out.String())
						}
					}
					return
				}
				var report model.Report
				if err := json.Unmarshal(out.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if report.InputSHA256 != contract.Digest(input) || report.Summary.InScope != 10 || report.Summary.EOL != 5 || report.Summary.NoEOLDetected != 3 || report.Summary.Unknown != 2 || report.Summary.AssessmentCoverage != 0.8 || report.Summary.CIFailureCount != 5 || !report.CIGate.Incomplete || len(report.Results) != 10 {
					t.Fatalf("mixed scan summary: %+v", report)
				}
				byRef := map[string]model.ComponentResult{}
				for _, row := range report.Results {
					byRef[row.SourceRef] = row
				}
				for i, item := range mixedPackages {
					row, ok := byRef[fmt.Sprintf("dependency-%d", i)]
					if !ok || row.Lifecycle != item.lifecycle || row.CIFailure != (item.lifecycle == "EOL") || row.Incomplete != (item.lifecycle == "UNKNOWN") {
						t.Fatalf("original SBOM component %d was lost or misclassified: %+v", i, row)
					}
				}
			})
		}
	}
}

func TestEOLRuleCIGatesAndExceptionsThroughCLI(t *testing.T) {
	for _, tc := range []struct {
		name, confidence, expires, exceptionPURL string
		missingRepository, strict                bool
		want                                     int
	}{
		{"report_first_warns", "HIGH", "", "", false, false, 0},
		{"medium_fails", "MEDIUM", "", "", false, false, 1},
		{"matching_exception_keeps_eol_and_warning", "MEDIUM", "2026-10-11", "pkg:npm/transitive-leaf@1.0.0", false, false, 0},
		{"expired_exception_does_not_waive", "MEDIUM", "2026-10-10", "pkg:npm/transitive-leaf@1.0.0", false, false, 1},
		{"another_version_exception_does_not_waive", "MEDIUM", "2026-12-01", "pkg:npm/transitive-leaf@2.0.0", false, false, 1},
		{"exception_cannot_waive_required_failure", "MEDIUM", "2026-12-01", "pkg:npm/transitive-leaf@1.0.0", true, true, 3},
		{"report_first_retains_incomplete", "MEDIUM", "", "", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := rulePolicy(model.EOLRule{ID: "archived", AnyOf: []string{"ARCHIVED"}})
			p.CI.MinConfidence, p.CI.FailOnIncompleteScan = tc.confidence, tc.strict
			dir := t.TempDir()
			if tc.expires != "" {
				data, _ := json.Marshal(map[string]any{"schema_version": 2, "exceptions": []map[string]any{{"package_purl": tc.exceptionPURL, "suppress": []string{"CI_FAILURE"}, "owner": "fixture-owner", "reason": "Reviewed temporary exception", "expires_on": tc.expires}}})
				if err := os.WriteFile(filepath.Join(dir, "exceptions.yaml"), data, 0600); err != nil {
					t.Fatal(err)
				}
				p.Exceptions.Path = model.Ptr("exceptions.yaml")
			}
			data, _ := json.Marshal(p)
			path := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			stub := testutil.NewStub()
			npmSource(t, stub, "https://github.com/publisher/leaf", "", "2020-01-01T00:00:00Z")
			stub.Bodies["api.github.com/repos/publisher/leaf"] = `{"full_name":"publisher/leaf","archived":true}`
			if tc.missingRepository {
				stub.Status["api.github.com/repos/publisher/leaf"] = 404
			}
			input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"leaf","purl":"pkg:npm/transitive-leaf@1.0.0"}]}`
			var out, errs bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "-i", "-", "-c", path, "-f", "json"}, strings.NewReader(input), &out, &errs, stub.Client(), testutil.FixedNow)
			if code != tc.want {
				t.Fatalf("exit=%d want=%d stderr=%s", code, tc.want, errs.String())
			}
			var report model.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			row := report.Results[0]
			if row.Incomplete != tc.missingRepository || strings.Contains(errs.String(), "WARNING:") == tc.missingRepository {
				t.Fatal("CI settings or an exception altered the warning/completeness facts")
			}
			if tc.missingRepository {
				if row.Lifecycle != "UNKNOWN" || row.ExceptionApplied || !report.CIGate.Incomplete {
					t.Fatal("an exception hid an unresolved criterion")
				}
			} else if row.Lifecycle != "EOL" || model.Text(row.EOLBasis) != "POLICY_RULE" {
				t.Fatal("CI settings changed an EOL classification")
			}
			if tc.name == "matching_exception_keeps_eol_and_warning" && (!row.ExceptionApplied || row.CIFailure) {
				t.Fatal("matching exception did not suppress only the CI failure")
			}
		})
	}
}
