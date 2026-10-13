package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/cli"
	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/lifecycle"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestRuntimeFixtureManifest(t *testing.T) {
	data, err := os.ReadFile(testutil.Path(t, "testdata/fixtures/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name         string `json:"name"`
		Report       string `json:"report"`
		Policy       string `json:"policy"`
		Input        string `json:"input"`
		ExpectedExit int    `json:"expected_exit"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			b, err := os.ReadFile(testutil.Path(t, tc.Report))
			if err != nil {
				t.Fatal(err)
			}
			var expected model.Report
			if err := json.Unmarshal(b, &expected); err != nil {
				t.Fatal(err)
			}
			stub := testutil.NewStub()
			indices := []provider.EolIndexRow{}
			for _, row := range expected.Results {
				id, reason := identity.Resolve(model.Component{PURL: model.Text(row.PURL)})
				if reason != "" {
					t.Fatal(reason)
				}
				stub.Bodies[strings.TrimPrefix(identity.VersionURL(config.Default().Sources.DepsDev.BaseURL, id), "https://")] = testutil.VersionBody(id.Name, id.Version, model.Text(row.VersionVerification.PublishedAt))
				for _, e := range row.Evidence {
					if e.ProviderID != "endoflife_date" {
						continue
					}
					name := model.Text(e.ProductSlug)
					indices = append(indices, provider.EolIndexRow{Identifier: e.PackagePURL, Product: provider.ProductRef{Name: name, URI: "https://endoflife.date/api/v1/products/" + name + "/"}})
					stub.Bodies["endoflife.date/api/v1/products/"+name+"/"] = testutil.ProductBody(name, e.MatchedCycle, model.Ptr(e.EOLEffectiveDate), false)
					if e.SourceLabel != nil {
						setSupportLabel(t, stub, "endoflife.date/api/v1/products/"+name+"/", e.SourceLabel)
					}
				}
				for _, e := range row.SignalEvaluations {
					if e.Type != "STALE_RELEASE" || e.Status == "UNKNOWN" {
						continue
					}
					published := "2026-10-01T00:00:00Z"
					if e.Status == "PRESENT" {
						published = "2024-04-12T09:00:00Z"
					}
					testutil.PutJSON(t, stub, strings.TrimPrefix(identity.PackageURL(config.Default().Sources.DepsDev.BaseURL, id), "https://"),
						map[string]any{"packageKey": provider.DepsKey{System: id.System, Name: id.Name},
							"versions": []provider.DepsVersion{{Key: provider.DepsKey{System: id.System, Name: id.Name, Version: "3.0.0"}, PublishedAt: published}}})
				}
			}
			testutil.PutJSON(t, stub, "endoflife.date/api/v1/identifiers/purl/", map[string]any{"schema_version": "1.2.1", "generated_at": model.Timestamp(testutil.FixedNow), "result": indices})
			var out, errs bytes.Buffer
			code := cli.Run(context.Background(), []string{"scan", "-i", testutil.Path(t, tc.Input), "-c", testutil.Path(t, tc.Policy), "-f", "json", "--as-of", expected.AsOf}, nil, &out, &errs, stub.Client(), testutil.FixedNow)
			if code != tc.ExpectedExit {
				t.Fatalf("exit=%d want=%d stderr=%s", code, tc.ExpectedExit, errs.String())
			}
			var got model.Report
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got.PolicyHash != expected.PolicyHash || got.InputSHA256 != expected.InputSHA256 || !sameGate(got.CIGate, expected.CIGate) {
				t.Fatalf("report contract mismatch: %+v", got.CIGate)
			}
			if len(got.Results) != len(expected.Results) {
				t.Fatal("result count changed")
			}
			for i, row := range got.Results {
				want := expected.Results[i]
				if row.Lifecycle != want.Lifecycle || model.Text(row.Confidence) != model.Text(want.Confidence) || model.Text(row.EOLEffectiveDate) != model.Text(want.EOLEffectiveDate) ||
					row.Incomplete != want.Incomplete || row.CIFailure != want.CIFailure || len(row.Notices) != len(want.Notices) {
					t.Fatalf("runtime result: %+v", row)
				}
			}
		})
	}
}

// Compare slices separately because CIGate contains a slice.
func sameGate(got, want model.CIGate) bool {
	if got.Passed == want.Passed && got.Incomplete == want.Incomplete && strings.Join(got.ViolationCodes, ",") == strings.Join(want.ViolationCodes, ",") {
		return true
	}
	return false
}

func TestMixedEOLIndexScope(t *testing.T) {
	p := offlinePolicy()
	p.Sources.EndoflifeDate.Enabled = true
	c := testCatalog()
	c.Entries = []model.CatalogEntry{}
	stub := testutil.NewStub()
	rows := []provider.EolIndexRow{
		{Identifier: "pkg:oci/envoy?repository_url=cgr.dev/chainguard", Product: provider.ProductRef{Name: "envoy", URI: "https://endoflife.date/api/v1/products/envoy/"}},
		{Identifier: "pkg:swid/alpine?tag_id=alpine", Product: provider.ProductRef{Name: "alpine", URI: "https://endoflife.date/api/v1/products/alpine/"}},
		{Identifier: "pkg:rpm/aliyun/dragonwell?repository_url=http://mirrors.aliyun.com", Product: provider.ProductRef{Name: "dragonwell", URI: "https://endoflife.date/api/v1/products/dragonwell/"}},
		{Identifier: "pkg:gem/example", Product: provider.ProductRef{Name: "example", URI: "https://endoflife.date/api/v1/products/example/"}},
	}
	testutil.PutJSON(t, stub, "endoflife.date/api/v1/identifiers/purl/", map[string]any{"schema_version": "1.2.1", "generated_at": model.Timestamp(testutil.FixedNow), "result": rows})
	stub.Bodies["endoflife.date/api/v1/products/example/"] = testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false)
	row := expectLifecycle(t, runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "EOL", "MEDIUM", "")
	if row.Incomplete || len(stub.Calls) != 2 {
		t.Fatal("out-of-scope index entries broke supported packages")
	}
}

func TestSignalAggregationFallbackAndConflict(t *testing.T) {
	requested := []string{"STALE_RELEASE"}
	failed := provider.UnknownSignal("STALE_RELEASE", "SOURCE_ERROR")
	negative := model.SignalEvaluation{Type: "STALE_RELEASE", Status: "ABSENT", ProviderID: model.Ptr("equivalent_fixture"), SourceURL: model.Ptr("https://example.org/releases"), CheckedAt: model.Ptr(model.Timestamp(testutil.FixedNow))}
	es, _, ds := lifecycle.AggregateSignals(requested, []model.SignalEvaluation{failed, negative}, nil)
	if len(es) != 1 || es[0].Status != "ABSENT" || len(ds) != 0 {
		t.Fatal("valid negative alternative was lost")
	}
	positive := negative
	positive.Status = "PRESENT"
	positive.ProviderID = model.Ptr("other_fixture")
	es, signals, ds := lifecycle.AggregateSignals(requested, []model.SignalEvaluation{positive, negative},
		[]model.SignalEvidence{{Type: "STALE_RELEASE", ProviderID: "other_fixture", ObservedAt: model.Timestamp(testutil.FixedNow), Details: map[string]any{}}})
	if es[0].Status != "UNKNOWN" || model.Text(es[0].ReasonCode) != "SIGNAL_CONFLICT" || len(ds) != 1 || len(signals) != 1 {
		t.Fatal("conflicting positive evidence was hidden")
	}
}

func TestSecretRedactionAndInternalExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(path, []byte("schema_version: 2\nsources:\n  deps_dev:\n    base_url: https://user:must-not-print@api.deps.dev/v3\n"), 0600)
	var out, errs bytes.Buffer
	code := cli.Run(context.Background(), []string{"policy", "validate", "-c", path}, nil, &out, &errs, testutil.NewStub().Client(), testutil.FixedNow)
	if code != 2 || strings.Contains(errs.String(), "must-not-print") {
		t.Fatalf("credential printed: %s", errs.String())
	}
	out.Reset()
	errs.Reset()
	input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"private","purl":"pkg:gem/private@1.0?repository_url=https%3A%2F%2Fuser%3Amust-not-print%40example.org%3Ftoken%3Dmust-not-print"}]}`
	stub := testutil.NewStub()
	code = cli.Run(context.Background(), []string{"scan", "-i", "-", "--offline", "-f", "json"}, strings.NewReader(input), &out, &errs, stub.Client(), testutil.FixedNow)
	if code != 0 || strings.Contains(out.String(), "must-not-print") || len(stub.Calls) != 0 {
		t.Fatalf("private source leaked: %s %s", out.String(), errs.String())
	}
	// Panics in worker/transport code become exit 4 and must also release memo
	// waiters, rather than hanging duplicate components.
	out.Reset()
	errs.Reset()
	client := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) { panic("must-not-print") })}
	input = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"example","purl":"pkg:gem/example@2.4.7"},{"type":"library","name":"example","purl":"pkg:gem/example@2.4.7"}]}`
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(context.Background(), []string{"scan", "-i", "-", "-f", "json"}, strings.NewReader(input), &out, &errs, client, testutil.FixedNow)
	}()
	select {
	case code = <-done:
		if code != 4 || out.Len() != 0 || strings.Contains(errs.String(), "must-not-print") {
			t.Fatalf("internal exit=%d output=%s error=%s", code, out.String(), errs.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker panic left a memo waiter blocked")
	}
}

func TestAPIErrorFallbackAndPublicationFuture(t *testing.T) {
	p := offlinePolicy()
	p.Sources.DepsDev.Enabled = true
	p.Sources.EndoflifeDate.Enabled = true
	stub := testutil.NewStub()
	stub.Errors["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = errors.New("unavailable")
	stub.Status["endoflife.date/api/v1/identifiers/purl/"] = 503
	row := expectLifecycle(t, runScan(t, p, testCatalog(), "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "SUPPORTED", "HIGH", "")
	if row.Incomplete {
		t.Fatal("optional lookup failures overrode higher tier equivalents")
	}
	p.Sources.EndoflifeDate.Enabled = false
	stub = testutil.NewStub()
	stub.Bodies["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = testutil.VersionBody("example", "2.4.7", "2027-01-01T00:00:00Z")
	row = expectLifecycle(t, runScan(t, p, nil, "2027-01-01", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "PUBLICATION_IN_FUTURE")
	if row.VersionVerification.Status == "VERIFIED" || !row.Incomplete {
		t.Fatal("future publication accepted")
	}
}

func TestAllExampleAndFixtureSchemas(t *testing.T) {
	validateFile := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, "eol-policy") || strings.HasPrefix(name, "policy.") {
			p, err := config.Load(path)
			if err != nil {
				return err
			}
			_, err = config.LoadBundle(p, path)
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		v, err := contract.DecodeYAML(b)
		if err != nil {
			return err
		}
		if strings.HasPrefix(name, "eol-exceptions") {
			return contract.Validate("exceptions", v)
		}
		if err := contract.Validate("support-catalog", v); err != nil {
			return err
		}
		j, _ := json.Marshal(v)
		var c model.Catalog
		json.Unmarshal(j, &c)
		return config.ValidateCatalog(c)
	}
	for _, dir := range []string{"examples", "testdata"} {
		t.Run(dir, func(t *testing.T) {
			if err := filepath.WalkDir(testutil.Path(t, dir), validateFile); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCanonicalUTF8JSON(t *testing.T) {
	b, err := contract.CanonicalJSON(map[string]any{"日本語": "<>&\u2028\\u2028\n", "a": 8})
	if err != nil || !json.Valid(b) || string(b) != `{"a":8,"日本語":"<>& \\u2028\n"}` {
		t.Fatalf("canonical JSON: %q %v", b, err)
	}
}

func TestWithdrawnEvidenceCannotReviveAndDuplicateClaims(t *testing.T) {
	t.Run("expired_replacement", func(t *testing.T) {
		c := testCatalog()
		old := c.Entries[0]
		old.ID = "old-withdrawn"
		old.EOLEffectiveDate = "2026-10-01"
		old.SupersededBy = model.Ptr("test-window")
		old.SupersessionSourceURL = model.Ptr("https://example.org/correction")
		c.Entries[0].ValidUntil = "2026-10-10"
		c.Entries = append(c.Entries, old)
		row := expectLifecycle(t, runScan(t, offlinePolicy(), c, "2026-10-11", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true), "UNKNOWN", "", "STALE_EVIDENCE")
		if len(row.Evidence) != 2 || len(row.SelectedEvidenceIDs) != 0 {
			t.Fatal("withdrawal or expired replacement was hidden")
		}
	})
	t.Run("same_primary_source", func(t *testing.T) {
		c := testCatalog()
		duplicate := c.Entries[0]
		duplicate.ID = "duplicate"
		c.Entries = append(c.Entries, duplicate)
		row := expectLifecycle(t, runScan(t, offlinePolicy(), c, "2026-10-11", testutil.NewStub(), componentSBOM("pkg:gem/example@2.4.7"), true), "SUPPORTED", "HIGH", "")
		if len(row.Evidence) != 1 || len(row.SelectedEvidenceIDs) != 1 {
			t.Fatal("duplicate primary claim counted independently")
		}
	})
}
