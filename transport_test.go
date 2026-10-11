package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheAndOfflineAcceptance(t *testing.T) {
	t.Run("UT27_cache_off_memo_always_on", func(t *testing.T) {
		p := defaultPolicy()
		stub := newStub()
		raw := "https://api.deps.dev/v3/test"
		stub.bodies["api.deps.dev/v3/test"] = `{"value":1}`
		dir := filepath.Join(t.TempDir(), "not-created")
		tr := newTransport(stub.client(), p, fixedNow, false)
		tr.cacheDir = dir
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := tr.get(context.Background(), raw)
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if stub.count("api.deps.dev/v3/test") != 1 {
			t.Fatal("in-flight request was duplicated")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("cache-off scan wrote to disk")
		}
	})
	t.Run("UT28_offline_no_network", func(t *testing.T) {
		p := defaultPolicy()
		stub := newStub()
		r := runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), true)
		if len(stub.calls) != 0 || r.Results[0].Lifecycle != "UNKNOWN" {
			t.Fatal("offline sent HTTP")
		}
	})
	t.Run("persistent_cache_TTL_age_and_404", func(t *testing.T) {
		p := defaultPolicy()
		p.Cache.Enabled = true
		stub := newStub()
		raw := "https://api.deps.dev/v3/test"
		stub.bodies["api.deps.dev/v3/test"] = `{"value":1}`
		dir := t.TempDir()
		tr := newTransport(stub.client(), p, fixedNow, false)
		tr.cacheDir = dir
		data, err := tr.get(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			age     time.Duration
			wantErr bool
			stale   bool
		}{
			{12 * time.Hour, false, false}, {48 * time.Hour, false, true}, {31 * 24 * time.Hour, true, false},
		} {
			next := newTransport(stub.client(), p, fixedNow.Add(tc.age), true)
			next.cacheDir = dir
			d, err := next.get(context.Background(), raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("age %v error %v", tc.age, err)
			}
			if tc.stale && (len(d.Diagnostics) != 1 || d.Diagnostics[0].Code != "CACHE_STALE") {
				t.Fatalf("stale diagnostics: %+v", d)
			}
		}
		if stub.count("api.deps.dev/v3/test") != 1 {
			t.Fatal("offline cache hit fetched HTTP")
		}
		path, _ := tr.diskPath(raw)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe cache permissions")
		}
		missing := "https://api.deps.dev/v3/missing"
		if _, err := tr.get(context.Background(), missing); err != nil {
			t.Fatal(err)
		}
		cached := newTransport(stub.client(), p, fixedNow.Add(time.Hour), true)
		cached.cacheDir = dir
		v, err := cached.get(context.Background(), missing)
		if err != nil || v.Status != 404 {
			t.Fatal("404 cache missing")
		}
		// The cache cannot substitute a different query or a modified payload.
		rec := diskRecord{SchemaVersion: "2.0", URL: raw, Status: 200, Body: []byte(`{"changed":true}`), BodyHash: digest(data.Body), ObservedAt: data.ObservedAt}
		b, _ := json.Marshal(rec)
		os.WriteFile(path, b, 0600)
		corrupt := newTransport(stub.client(), p, fixedNow, true)
		corrupt.cacheDir = dir
		if _, err := corrupt.get(context.Background(), raw); err == nil {
			t.Fatal("tampered cache accepted")
		}
	})
}
func TestTransportRetryAndConcurrency(t *testing.T) {
	p := defaultPolicy()
	p.Network.MaxConcurrency = 2
	var calls, active, maxActive atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		n := active.Add(1)
		for {
			m := maxActive.Load()
			if n <= m || maxActive.CompareAndSwap(m, n) {
				break
			}
		}
		defer active.Add(-1)
		time.Sleep(5 * time.Millisecond)
		calls.Add(1)
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Retry-After": []string{"0"}}}, nil
	})}
	tr := newTransport(client, p, fixedNow, false)
	tr.wait = func(context.Context, time.Duration) error { return nil }
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := "https://api.deps.dev/v3/test/" + string(rune('a'+i))
			if _, err := tr.get(context.Background(), raw); err == nil {
				t.Error("503 reported success")
			}
		}(i)
	}
	wg.Wait()
	if maxActive.Load() > 2 || calls.Load() != 24 {
		t.Fatalf("concurrency=%d calls=%d", maxActive.Load(), calls.Load())
	}
	count := 0
	client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	tr = newTransport(client, p, fixedNow, false)
	if _, err := tr.get(context.Background(), "https://api.deps.dev/v3/missing"); err != nil || count != 1 {
		t.Fatal("404 retried")
	}
}
func TestRealHTTPSAdaptersAndRedirectBoundary(t *testing.T) {
	var requests atomic.Int32
	var base string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/identifiers/purl/":
			put := map[string]any{"schema_version": "1.2.1", "generated_at": stamp(fixedNow), "result": []eolIndexRow{
				{Identifier: "pkg:gem/example", Product: productRef{Name: "example", URI: base + "/api/v1/products/example/"}}}}
			json.NewEncoder(w).Encode(put)
		case "/api/v1/products/example/":
			io.WriteString(w, productBody("example", "2.4", ptr("2026-10-01"), false))
		case "/v3/systems/rubygems/packages/example/versions/2.4.7":
			io.WriteString(w, versionBody("example", "2.4.7", "2024-04-12T09:00:00Z"))
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
	p := defaultPolicy()
	p.Network.AllowedHosts = []string{host.Hostname()}
	p.Network.Retries = 0
	p.Sources.EndoflifeDate.BaseURL = base + "/api/v1"
	p.Sources.DepsDev.BaseURL = base + "/v3"
	b := testBundle(t, p, testCatalog())
	b.Catalog.Entries = []CatalogEntry{}
	s := newScanner(b, server.Client(), fixedNow, "2026-10-11", false)
	report, err := s.scan(context.Background(), componentSBOM("pkg:gem/example@2.4.7"))
	if err != nil {
		t.Fatal(err)
	}
	expectLifecycle(t, report, "EOL", "MEDIUM", "")
	if requests.Load() != 4 {
		t.Fatalf("real HTTP requests: %d", requests.Load())
	}
	tr := newTransport(server.Client(), p, fixedNow, false)
	id, reason := resolveIdentity(Component{PURL: "pkg:npm/%40scope/name@1.2.3"})
	if reason != "" {
		t.Fatal(reason)
	}
	v, data, err := depsVersionData(context.Background(), tr, id)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := deprecatedSignal(tr, id, v, data, nil)
	if e.Status != "ABSENT" {
		t.Fatalf("npm negative: %+v", e)
	}
	if _, err := tr.get(context.Background(), base+"/v3/systems/redirect"); err == nil {
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
		c.Entries = []CatalogEntry{}
		stub := newStub()
		putJSON(t, stub, "endoflife.date/api/v1/identifiers/purl/", map[string]any{"schema_version": "1.2.1", "generated_at": stamp(fixedNow),
			"result": []eolIndexRow{{Identifier: "pkg:gem/example", Product: productRef{Name: "example", URI: uri}}}})
		r := runScan(t, p, c, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false)
		if !r.Results[0].Incomplete || r.Results[0].Lifecycle != "UNKNOWN" || len(stub.calls) != 1 {
			t.Fatalf("URI %s accepted", uri)
		}
	}
	p := offlinePolicy()
	p.Sources.DepsDev.Enabled = true
	stub := newStub()
	stub.bodies["api.deps.dev/v3/systems/rubygems/packages/example/versions/2.4.7"] = versionBody("wrong", "2.4.7", "2024-04-12T09:00:00Z")
	row := expectLifecycle(t, runScan(t, p, nil, "2026-10-11", stub, componentSBOM("pkg:gem/example@2.4.7"), false), "UNKNOWN", "", "VERSION_CONFLICT")
	if row.VersionVerification.Status == "VERIFIED" {
		t.Fatal("API identity mismatch verified")
	}
}
func TestCacheRevalidationAndLongRetryAfter(t *testing.T) {
	p := defaultPolicy()
	p.Cache.Enabled = true
	raw := "https://api.deps.dev/v3/test"
	dir := t.TempDir()
	var count int
	var conditional bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		count++
		if count == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"valid":true}`)), Header: http.Header{"Etag": []string{`"example"`}}}, nil
		}
		conditional = req.Header.Get("If-None-Match") == `"example"`
		return &http.Response{StatusCode: 304, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	tr := newTransport(client, p, fixedNow, false)
	tr.cacheDir = dir
	if _, err := tr.get(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	tr = newTransport(client, p, fixedNow.Add(48*time.Hour), false)
	tr.cacheDir = dir
	d, err := tr.get(context.Background(), raw)
	if err != nil || !conditional || string(d.Body) != `{"valid":true}` || d.ObservedAt != stamp(fixedNow.Add(48*time.Hour)) {
		t.Fatalf("304 merge: %+v %v", d, err)
	}
	p.Cache.Enabled = false
	tr = newTransport(client, p, fixedNow, false)
	if _, err := tr.get(context.Background(), raw); err == nil {
		t.Fatal("304 without cache accepted")
	}
	count = 0
	client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Retry-After": []string{"86400"}}}, nil
	})}
	tr = newTransport(client, p, fixedNow, false)
	tr.wait = func(context.Context, time.Duration) error { t.Fatal("long Retry-After blocked scan"); return nil }
	if _, err := tr.get(context.Background(), raw); err == nil || count != 1 {
		t.Fatal("ignored long Retry-After")
	}
}
