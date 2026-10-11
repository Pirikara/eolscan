package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/testutil"
)

func response(status int, header http.Header) *http.Response {
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}
}

func TestRequestStartsRespectHostRateAndBurst(t *testing.T) {
	p := config.Default()
	p.Network.Retries = 0
	p.Network.HostLimits["pypi.org"] = model.RateLimit{RequestsPerSecond: 4, Burst: 2}
	clock := testutil.NewClock(testutil.FixedNow)
	starts := map[string][]time.Duration{}
	client := &http.Client{Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		starts[r.URL.Hostname()] = append(starts[r.URL.Hostname()], clock.Now().Sub(testutil.FixedNow))
		return response(200, nil), nil
	})}
	tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait))
	for _, raw := range []string{
		"https://api.deps.dev/a", "https://api.deps.dev/b", "https://api.deps.dev/c",
		"https://pypi.org/a", "https://pypi.org/b", "https://pypi.org/c",
	} {
		if _, err := tr.Get(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string][]time.Duration{
		"api.deps.dev": {0, 500 * time.Millisecond, time.Second},
		"pypi.org":     {time.Second, time.Second, 1250 * time.Millisecond},
	}
	for host, times := range want {
		for i, at := range times {
			if starts[host][i] != at {
				t.Fatalf("%s request %d started at %v, want %v", host, i, starts[host][i], at)
			}
		}
	}
}

func TestRateLimitCooldownIsSharedOnlyWithinHost(t *testing.T) {
	for _, tc := range []struct {
		name, after string
		wait        time.Duration
		blocked     bool
		status      int
		code        string
	}{
		{"short", "3", 3 * time.Second, false, 429, "RATE_LIMITED"},
		{"long", "86400", 0, true, 429, "RATE_LIMITED"},
		{"overflow_duration", "9223372036854775807", 0, true, 429, "RATE_LIMITED"},
		{"overflow_integer", "999999999999999999999", 0, true, 429, "RATE_LIMITED"},
		{"unavailable_host", "86400", 0, true, 503, "SOURCE_ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Network.Retries = 0
			clock := testutil.NewClock(testutil.FixedNow)
			calls := map[string]int{}
			client := &http.Client{Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls[r.URL.Hostname()]++
				if r.URL.Path == "/first" {
					return response(tc.status, http.Header{"Retry-After": {tc.after}}), nil
				}
				return response(200, nil), nil
			})}
			tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait), WithJitter(func(d time.Duration) time.Duration { return d }))
			_, err := tr.Get(context.Background(), "https://api.deps.dev/first")
			var lookup *LookupError
			if !errors.As(err, &lookup) || lookup.Code != tc.code || lookup.Status != tc.status {
				t.Fatalf("server cooldown: %v", err)
			}
			if _, err := tr.Get(context.Background(), "https://pypi.org/other"); err != nil || !clock.Now().Equal(testutil.FixedNow) {
				t.Fatalf("another host was blocked: %v", err)
			}
			_, err = tr.Get(context.Background(), "https://api.deps.dev/second")
			if tc.blocked {
				if !errors.As(err, &lookup) || lookup.Code != tc.code || lookup.Status != tc.status || calls["api.deps.dev"] != 1 {
					t.Fatalf("host cooldown ignored: %v, calls=%v", err, calls)
				}
			} else if err != nil || calls["api.deps.dev"] != 2 {
				t.Fatalf("short cooldown did not recover: %v", err)
			}
			if clock.Now().Sub(testutil.FixedNow) != tc.wait {
				t.Fatalf("waited %v, want %v", clock.Now().Sub(testutil.FixedNow), tc.wait)
			}
		})
	}
}

func TestRetryAfterDateUsesSchedulingClock(t *testing.T) {
	p := config.Default()
	start := testutil.FixedNow.Add(time.Hour)
	clock := testutil.NewClock(start)
	var starts []time.Time
	client := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		starts = append(starts, clock.Now())
		if len(starts) == 1 {
			return response(429, http.Header{"Retry-After": {start.Add(4 * time.Second).Format(http.TimeFormat)}}), nil
		}
		return response(200, nil), nil
	})}
	tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait), WithJitter(func(d time.Duration) time.Duration { return d }))
	data, err := tr.Get(context.Background(), "https://api.deps.dev/test")
	if err != nil || len(starts) != 2 || starts[1].Sub(starts[0]) != 4*time.Second || data.ObservedAt != model.Timestamp(testutil.FixedNow) {
		t.Fatalf("scheduling and evidence clocks: starts=%v data=%+v err=%v", starts, data, err)
	}
}

func TestJitteredBackoffAndRedirectsArePaced(t *testing.T) {
	t.Run("backoff", func(t *testing.T) {
		p := config.Default()
		p.Network.RequestsPerSecond = 100
		clock := testutil.NewClock(testutil.FixedNow)
		var starts []time.Time
		client := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
			starts = append(starts, clock.Now())
			return response(503, http.Header{"Retry-After": {"invalid"}}), nil
		})}
		tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait), WithJitter(func(d time.Duration) time.Duration { return 2 * d }))
		if _, err := tr.Get(context.Background(), "https://api.deps.dev/test"); err == nil || len(starts) != 3 {
			t.Fatal("retry count")
		}
		if starts[1].Sub(starts[0]) != 400*time.Millisecond || starts[2].Sub(starts[1]) != 800*time.Millisecond {
			t.Fatalf("backoff: %v", starts)
		}
	})
	t.Run("redirect", func(t *testing.T) {
		p := config.Default()
		clock := testutil.NewClock(testutil.FixedNow)
		var starts []time.Time
		client := &http.Client{Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
			starts = append(starts, clock.Now())
			if len(starts) == 1 {
				return response(302, http.Header{"Location": {"https://api.deps.dev/v3/systems/example/redirect"}}), nil
			}
			return response(200, nil), nil
		})}
		tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait))
		if _, err := tr.Get(context.Background(), "https://api.deps.dev/v3/systems/example"); err != nil {
			t.Fatal(err)
		}
		if len(starts) != 2 || starts[1].Sub(starts[0]) != 500*time.Millisecond {
			t.Fatalf("redirect bypassed host rate: %v", starts)
		}
	})
}

func TestRateWaitBudgetAndCancellation(t *testing.T) {
	p := config.Default()
	p.Network.RequestsPerSecond = 0.01
	clock := testutil.NewClock(testutil.FixedNow)
	calls := 0
	client := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(200, nil), nil
	})}
	tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait))
	tr.Get(context.Background(), "https://api.deps.dev/first")
	_, err := tr.Get(context.Background(), "https://api.deps.dev/second")
	var lookup *LookupError
	if !errors.As(err, &lookup) || lookup.Code != "RATE_LIMIT_WAIT_TIMEOUT" || calls != 1 || !clock.Now().Equal(testutil.FixedNow) {
		t.Fatalf("wait budget ignored: %v calls=%d", err, calls)
	}
	p = config.Default()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr = New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}))
	tr.Get(context.Background(), "https://api.deps.dev/first")
	if _, err := tr.Get(ctx, "https://api.deps.dev/second"); !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatalf("cancelled wait sent HTTP: %v calls=%d", err, calls)
	}
}

func TestRejectedRedirectIsNotRetried(t *testing.T) {
	p := config.Default()
	clock := testutil.NewClock(testutil.FixedNow)
	calls := 0
	client := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response(302, http.Header{"Location": {"https://other.invalid/test"}}), nil
	})}
	tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait))
	_, err := tr.Get(context.Background(), "https://api.deps.dev/test")
	var lookup *LookupError
	if !errors.As(err, &lookup) || lookup.Code != "UNSAFE_PROVIDER_URL" || calls != 1 {
		t.Fatalf("rejected redirect was retried: calls=%d err=%v", calls, err)
	}
}

func TestCachedJSONRepresentationsAreIsolated(t *testing.T) {
	p := config.Default()
	p.Cache.Enabled = true
	clock := testutil.NewClock(testutil.FixedNow)
	calls := 0
	client := &http.Client{Transport: testutil.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"accept":"` + r.Header.Get("Accept") + `"}`))}, nil
	})}
	dir := t.TempDir()
	tr := New(client, p, testutil.FixedNow, false, WithClock(clock.Now), WithWait(clock.Wait), WithCacheDir(dir))
	raw := "https://pypi.org/simple/example/"
	for _, accept := range []string{"application/json", "application/vnd.pypi.simple.v1+json"} {
		if _, err := tr.GetWithAccept(context.Background(), raw, accept); err != nil {
			t.Fatal(err)
		}
	}
	offline := New(client, p, testutil.FixedNow.Add(time.Hour), true, WithCacheDir(dir))
	for _, accept := range []string{"application/json", "application/vnd.pypi.simple.v1+json"} {
		data, err := offline.GetWithAccept(context.Background(), raw, accept)
		if err != nil || !strings.Contains(string(data.Body), accept) {
			t.Fatalf("representation mixed: %s %v", data.Body, err)
		}
	}
	if calls != 2 || offline.CacheHits() != 2 {
		t.Fatalf("cache fetched HTTP: calls=%d hits=%d", calls, offline.CacheHits())
	}
}
