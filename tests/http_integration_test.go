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
	"sync/atomic"
	"testing"

	"github.com/Pirikara/eolscan/internal/cli"
	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func TestRegistryAdaptersThroughCLIAndHTTPS(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/npm/@scope/example":
			if !strings.Contains(r.RequestURI, "%2F") {
				t.Error("native npm scope slash was not encoded")
			}
			io.WriteString(w, `{"name":"@scope/example","versions":{"1.0.0":{"name":"@scope/example","version":"1.0.0"}},"time":{"1.0.0":"2024-04-12T09:00:00Z"}}`)
		case "/pypi/simple/example-name/":
			if r.Header.Get("Accept") != "application/vnd.pypi.simple.v1+json" {
				t.Error("PyPI request did not negotiate the JSON Index API")
			}
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
			io.WriteString(w, `{"meta":{"api-version":"1.4"},"name":"Example_Name","project-status":{"status":"active"},"files":[{"filename":"example_name-1.0.0-py3-none-any.whl","upload-time":"2024-04-12T09:00:00Z","yanked":false,"url":"https://files.example.invalid/artifact.whl"}]}`)
		case "/gems/api/v1/versions/example.json":
			io.WriteString(w, `[{"number":"1.0.0","platform":"ruby","created_at":"2024-04-12T09:00:00Z"}]`)
		default:
			t.Errorf("unexpected registry or artifact request: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	p := offlinePolicy()
	p.Sources.NPM.Enabled, p.Sources.PyPI.Enabled, p.Sources.RubyGems.Enabled = true, true, true
	p.Sources.NPM.BaseURL, p.Sources.PyPI.BaseURL, p.Sources.RubyGems.BaseURL = server.URL+"/npm", server.URL+"/pypi", server.URL+"/gems"
	p.Network.AllowedHosts = []string{u.Hostname()}
	p.Network.RequestsPerSecond = 100
	policy, _ := json.Marshal(p)
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, policy, 0600); err != nil {
		t.Fatal(err)
	}
	input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
		{"type":"library","name":"@scope/example","purl":"pkg:npm/%40scope/example@1.0.0"},
		{"type":"library","name":"Example_Name","purl":"pkg:pypi/Example_Name@1.0.0"},
		{"type":"library","name":"example","purl":"pkg:gem/example@1.0.0"}]}`
	var out, stderr bytes.Buffer
	code := cli.Run(context.Background(), []string{"scan", "-i", "-", "-c", policyPath, "-f", "json"}, strings.NewReader(input), &out, &stderr, server.Client(), testutil.FixedNow)
	if code != 0 || requests.Load() != 3 {
		t.Fatalf("native CLI: code=%d requests=%d stderr=%s", code, requests.Load(), stderr.String())
	}
	var report model.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != "2.1" || report.CIGate.Incomplete {
		t.Fatalf("report contract: %+v", report)
	}
	for _, row := range report.Results {
		if row.VersionVerification.Status != "VERIFIED" || model.Text(row.VersionVerification.ProviderID) == "deps_dev" || row.Lifecycle != "UNKNOWN" {
			t.Fatalf("native source selection: %+v", row)
		}
	}
}

func TestOfflineWithoutCacheOrCatalog(t *testing.T) {
	t.Run("UT28_offline_no_network", func(t *testing.T) {
		p := config.Default()
		stub := testutil.NewStub()
		r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), true)
		if len(stub.Calls) != 0 || r.Results[0].Lifecycle != "UNKNOWN" {
			t.Fatal("offline sent HTTP")
		}
	})
}

func TestRealHTTPSAdaptersAndRedirectBoundary(t *testing.T) {
	var requests atomic.Int32
	var base string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/identifiers/purl/":
			put := map[string]any{"schema_version": "1.2.1", "generated_at": model.Timestamp(testutil.FixedNow), "result": []provider.EolIndexRow{
				{Identifier: "pkg:gem/example", Product: provider.ProductRef{Name: "example", URI: base + "/api/v1/products/example/"}}}}
			json.NewEncoder(w).Encode(put)
		case "/api/v1/products/example/":
			io.WriteString(w, testutil.ProductBody("example", "2.4", model.Ptr("2026-10-01"), false))
		case "/v3/systems/rubygems/packages/example/versions/2.4.7":
			io.WriteString(w, testutil.VersionBody("example", "2.4.7", "2024-04-12T09:00:00Z"))
		case "/v3/systems/rubygems/packages/example":
			io.WriteString(w, `{"packageKey":{"system":"RUBYGEMS","name":"example"},"versions":[{"versionKey":{"system":"RUBYGEMS","name":"example","version":"2.4.7"},"publishedAt":"2024-04-12T09:00:00Z"}]}`)
		case "/v3/systems/npm/packages/@scope/name/versions/1.2.3":
			if !strings.Contains(r.RequestURI, "%2F") {
				t.Error("npm scope slash was not URL-encoded")
			}
			io.WriteString(w, `{"versionKey":{"system":"NPM","name":"@scope/name","version":"1.2.3"},"publishedAt":"2024-04-12T09:00:00Z","isDeprecated":false}`)
		case "/v3/systems/redirect":
			http.Redirect(w, r, "https://example.invalid/v3/systems/other", http.StatusMovedPermanently)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL
	host, _ := url.Parse(base)
	p := config.Default()
	p.Sources.NPM.Enabled = false
	p.Sources.PyPI.Enabled = false
	p.Sources.RubyGems.Enabled = false
	p.Network.AllowedHosts = []string{host.Hostname()}
	p.Network.Retries = 0
	p.Sources.EndoflifeDate.BaseURL = base + "/api/v1"
	p.Sources.DepsDev.BaseURL = base + "/v3"
	b := testBundle(t, p, testCatalog())
	b.Catalog.Entries = []model.CatalogEntry{}
	s := scanner.New(b, server.Client(), testutil.FixedNow, "2026-10-11", false)
	report, err := s.Scan(context.Background(), componentSBOM("pkg:gem/example@2.4.7"))
	if err != nil {
		t.Fatal(err)
	}
	expectLifecycle(t, report, "EOL", "MEDIUM", "")
	if requests.Load() != 4 {
		t.Fatalf("real HTTP requests: %d", requests.Load())
	}
	tr := transport.New(server.Client(), p, testutil.FixedNow, false)
	id, reason := identity.Resolve(model.Component{PURL: "pkg:npm/%40scope/name@1.2.3"})
	if reason != "" {
		t.Fatal(reason)
	}
	v, data, err := provider.FetchVersion(context.Background(), tr, id)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := provider.Deprecation(tr, id, v, data, nil)
	if e.Status != "ABSENT" {
		t.Fatalf("npm negative: %+v", e)
	}
	if _, err := tr.Get(context.Background(), base+"/v3/systems/redirect"); err == nil {
		t.Fatal("cross-host redirect accepted")
	}
}

func TestProviderSchemaAndUntrustedURI(t *testing.T) {
	for _, uri := range []string{
		"https://other.invalid/api/v1/products/example/",
		"https://endoflife.date/api/v1/products/full/",
		"https://endoflife.date/private/example/",
		"https://endoflife.date/api/v1/products/example/?token=secret",
		"http://endoflife.date/api/v1/products/example/",
	} {
		p := offlinePolicy()
		p.Sources.EndoflifeDate.Enabled = true
		c := testCatalog()
		c.Entries = []model.CatalogEntry{}
		stub := testutil.NewStub()
		testutil.PutJSON(t, stub, "endoflife.date/api/v1/identifiers/purl/", map[string]any{"schema_version": "1.2.1", "generated_at": model.Timestamp(testutil.FixedNow),
			"result": []provider.EolIndexRow{{Identifier: "pkg:gem/example", Product: provider.ProductRef{Name: "example", URI: uri}}}})
		r := runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		if !r.Results[0].Incomplete || r.Results[0].Lifecycle != "UNKNOWN" || len(stub.Calls) != 1 {
			t.Fatalf("URI %s accepted", uri)
		}
	}
	p := offlinePolicy()
	p.Sources.DepsDev.Enabled = true
	stub := testutil.NewStub()
	stub.Bodies["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = testutil.VersionBody("wrong", "2.4.7", "2024-04-12T09:00:00Z")
	row := expectLifecycle(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "VERSION_CONFLICT")
	if row.VersionVerification.Status == "VERIFIED" {
		t.Fatal("API identity mismatch verified")
	}
}
