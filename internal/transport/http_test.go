package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func TestCacheAndOfflineAcceptance(t *testing.T) {
	t.Run("UT27_cache_off_memo_always_on", func(t *testing.T) {
		p := config.Default()
		stub := testutil.NewStub()
		raw := "https://api.deps.dev/v3/test"
		stub.Bodies["api.deps.dev/v3/test"] = `{"value":1}`
		dir := filepath.Join(t.TempDir(), "not-created")
		tr := New(stub.Client(), p, testutil.FixedNow, false)
		tr.cacheDir = dir
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := tr.Get(context.Background(), raw)
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if stub.Count("api.deps.dev/v3/test") != 1 {
			t.Fatal("in-flight request was duplicated")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("cache-off scan wrote to disk")
		}
	})
	t.Run("persistent_cache_TTL_age_and_404", func(t *testing.T) {
		p := config.Default()
		p.Cache.Enabled = true
		stub := testutil.NewStub()
		raw := "https://api.deps.dev/v3/test"
		stub.Bodies["api.deps.dev/v3/test"] = `{"value":1}`
		dir := t.TempDir()
		tr := New(stub.Client(), p, testutil.FixedNow, false)
		tr.cacheDir = dir
		data, err := tr.Get(context.Background(), raw)
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
			next := New(stub.Client(), p, testutil.FixedNow.Add(tc.age), true)
			next.cacheDir = dir
			d, err := next.Get(context.Background(), raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("age %v error %v", tc.age, err)
			}
			if tc.stale && (len(d.Diagnostics) != 1 || d.Diagnostics[0].Code != "CACHE_STALE") {
				t.Fatalf("stale diagnostics: %+v", d)
			}
		}
		if stub.Count("api.deps.dev/v3/test") != 1 {
			t.Fatal("offline cache hit fetched HTTP")
		}
		path, _ := tr.diskPath(raw)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe cache permissions")
		}
		missing := "https://api.deps.dev/v3/missing"
		if _, err := tr.Get(context.Background(), missing); err != nil {
			t.Fatal(err)
		}
		cached := New(stub.Client(), p, testutil.FixedNow.Add(time.Hour), true)
		cached.cacheDir = dir
		v, err := cached.Get(context.Background(), missing)
		if err != nil || v.Status != 404 {
			t.Fatal("404 cache missing")
		}
		// The cache cannot substitute a different query or a modified payload.
		rec := diskRecord{SchemaVersion: "2.0", URL: raw, Status: 200, Body: []byte(`{"changed":true}`), BodyHash: contract.Digest(data.Body), ObservedAt: data.ObservedAt}
		b, _ := json.Marshal(rec)
		os.WriteFile(path, b, 0600)
		corrupt := New(stub.Client(), p, testutil.FixedNow, true)
		corrupt.cacheDir = dir
		if _, err := corrupt.Get(context.Background(), raw); err == nil {
			t.Fatal("tampered cache accepted")
		}
	})
}

func TestTransportRetryAndConcurrency(t *testing.T) {
	p := config.Default()
	p.Network.MaxConcurrency = 2
	var calls, active, maxActive atomic.Int32
	client := &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
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
	tr := New(client, p, testutil.FixedNow, false)
	clock := testutil.NewClock(testutil.FixedNow)
	tr.clock, tr.wait = clock.Now, clock.Wait
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw := "https://api.deps.dev/v3/test/" + string(rune('a'+i))
			if _, err := tr.Get(context.Background(), raw); err == nil {
				t.Error("503 reported success")
			}
		}(i)
	}
	wg.Wait()
	if maxActive.Load() > 2 || calls.Load() != 24 {
		t.Fatalf("concurrency=%d calls=%d", maxActive.Load(), calls.Load())
	}
	count := 0
	client = &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	tr = New(client, p, testutil.FixedNow, false)
	if _, err := tr.Get(context.Background(), "https://api.deps.dev/v3/missing"); err != nil || count != 1 {
		t.Fatal("404 retried")
	}
}

func TestCacheRevalidationAndLongRetryAfter(t *testing.T) {
	p := config.Default()
	p.Cache.Enabled = true
	raw := "https://api.deps.dev/v3/test"
	dir := t.TempDir()
	var count int
	var conditional bool
	client := &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		count++
		if count == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"valid":true}`)), Header: http.Header{"Etag": []string{`"example"`}}}, nil
		}
		conditional = req.Header.Get("If-None-Match") == `"example"`
		return &http.Response{StatusCode: 304, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	tr := New(client, p, testutil.FixedNow, false)
	tr.cacheDir = dir
	if _, err := tr.Get(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	tr = New(client, p, testutil.FixedNow.Add(48*time.Hour), false)
	tr.cacheDir = dir
	d, err := tr.Get(context.Background(), raw)
	if err != nil || !conditional || string(d.Body) != `{"valid":true}` || d.ObservedAt != model.Timestamp(testutil.FixedNow.Add(48*time.Hour)) {
		t.Fatalf("304 merge: %+v %v", d, err)
	}
	p.Cache.Enabled = false
	tr = New(client, p, testutil.FixedNow, false)
	if _, err := tr.Get(context.Background(), raw); err == nil {
		t.Fatal("304 without cache accepted")
	}
	count = 0
	client = &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Retry-After": []string{"86400"}}}, nil
	})}
	tr = New(client, p, testutil.FixedNow, false)
	tr.wait = func(context.Context, time.Duration) error { t.Fatal("long Retry-After blocked scan"); return nil }
	if _, err := tr.Get(context.Background(), raw); err == nil || count != 1 {
		t.Fatal("ignored long Retry-After")
	}
}
