package acceptance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/identity"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/provider"
	"github.com/Pirikara/eolscan/internal/scanner"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

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
