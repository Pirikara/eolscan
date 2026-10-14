package transport_test

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/config"
	"github.com/Pirikara/eolscan/internal/testutil"
	"github.com/Pirikara/eolscan/internal/transport"
)

func TestGitHubTokenIsLimitedToConfiguredPublicAPI(t *testing.T) {
	t.Setenv("EOLSCAN_TEST_GITHUB_TOKEN", "fixture-token")
	p := config.Default()
	p.Sources.GitHub.TokenEnv = "EOLSCAN_TEST_GITHUB_TOKEN"
	client := &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		want := ""
		if req.URL.Host == "api.github.com" && strings.HasPrefix(req.URL.Path, "/repos/") {
			want = "Bearer fixture-token"
		}
		if req.Header.Get("Authorization") != want {
			t.Error("token was missing or sent to another provider")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header), Request: req}, nil
	})}
	clock := testutil.NewClock(testutil.FixedNow)
	tr := transport.New(client, p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
	for _, raw := range []string{"https://api.github.com/repos/publisher/leaf", "https://registry.npmjs.org/leaf", "https://api.github.com/other"} {
		if _, err := tr.Get(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
	}
	// An explicitly configured mirror never receives the public API token.
	p.Sources.GitHub.BaseURL = "https://registry.npmjs.org"
	tr = transport.New(client, p, testutil.FixedNow, false)
	if _, err := tr.Get(context.Background(), "https://registry.npmjs.org/repos/publisher/leaf"); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubPrimaryRateLimitCreatesSharedCooldown(t *testing.T) {
	p := config.Default()
	p.Network.Retries = 2
	clock := testutil.NewClock(testutil.FixedNow)
	requests := 0
	client := &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 403, Header: http.Header{"X-Ratelimit-Remaining": []string{"0"}, "X-Ratelimit-Reset": []string{strconv.FormatInt(clock.Now().Add(time.Hour).Unix(), 10)}}, Body: io.NopCloser(strings.NewReader(`{"message":"API rate limit exceeded"}`)), Request: req}, nil
	})}
	tr := transport.New(client, p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
	for _, repo := range []string{"first", "second"} {
		_, err := tr.Get(context.Background(), "https://api.github.com/repos/publisher/"+repo)
		lookup, ok := err.(*transport.LookupError)
		if !ok || lookup.Code != "RATE_LIMITED" {
			t.Fatalf("rate-limit result: %v", err)
		}
	}
	if requests != 1 {
		t.Fatalf("ignored the shared reset time: %d requests", requests)
	}
}

func TestGitHubShortQuotaLimitsRetryAfterReset(t *testing.T) {
	for _, kind := range []string{"primary", "secondary", "ordinary_forbidden"} {
		t.Run(kind, func(t *testing.T) {
			p := config.Default()
			p.Network.RequestsPerSecond = 100
			clock := testutil.NewClock(testutil.FixedNow)
			requests := 0
			client := &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if requests > 1 {
					if kind != "ordinary_forbidden" && clock.Now().Before(testutil.FixedNow.Add(2*time.Second)) {
						t.Error("retried a repository request before the provider's reset")
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
				}
				headers := make(http.Header)
				if kind == "primary" {
					headers.Set("X-RateLimit-Remaining", "0")
					headers.Set("X-RateLimit-Reset", strconv.FormatInt(testutil.FixedNow.Add(2*time.Second).Unix(), 10))
				} else if kind == "secondary" {
					headers.Set("Retry-After", "2")
				}
				return &http.Response{StatusCode: 403, Header: headers, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
			})}
			tr := transport.New(client, p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait), transport.WithJitter(func(d time.Duration) time.Duration { return d }))
			data, err := tr.Get(context.Background(), "https://api.github.com/repos/publisher/first")
			if kind == "ordinary_forbidden" {
				lookup, ok := err.(*transport.LookupError)
				if !ok || lookup.Code != "SOURCE_ERROR" || lookup.Retryable || requests != 1 {
					t.Fatalf("ordinary forbidden response was retried: data=%+v err=%v requests=%d", data, err, requests)
				}
				if _, err := tr.Get(context.Background(), "https://api.github.com/repos/publisher/second"); err != nil {
					t.Fatal("ordinary authorization failure blocked another repository")
				}
			} else if err != nil || data.Status != 200 || requests != 2 {
				t.Fatalf("quota reset did not recover: data=%+v err=%v requests=%d", data, err, requests)
			}
		})
	}
}

func TestGitHubRedirectsPreserveIdentityAndTokenScope(t *testing.T) {
	t.Setenv("EOLSCAN_TEST_GITHUB_TOKEN", "fixture-token")
	for _, tc := range []struct {
		name, target string
		allowed      bool
	}{
		{"numeric_repository", "https://api.github.com/repositories/123", true},
		{"renamed_repository", "https://api.github.com/repos/new-owner/leaf", true},
		{"other_allowed_host", "https://registry.npmjs.org/repos/publisher/leaf", false},
		{"unrelated_api_path", "https://api.github.com/user", false},
		{"scheme_downgrade", "http://api.github.com/repos/publisher/leaf", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Default()
			p.Sources.GitHub.TokenEnv = "EOLSCAN_TEST_GITHUB_TOKEN"
			clock := testutil.NewClock(testutil.FixedNow)
			requests := 0
			client := &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Host != "api.github.com" || req.Header.Get("Authorization") != "Bearer fixture-token" || req.Header.Get("X-GitHub-Api-Version") != "2026-03-10" {
					t.Error("repository redirects lost API headers or exposed the token")
				}
				if requests == 1 {
					return &http.Response{StatusCode: 301, Header: http.Header{"Location": []string{tc.target}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
			})}
			tr := transport.New(client, p, testutil.FixedNow, false, transport.WithClock(clock.Now), transport.WithWait(clock.Wait))
			data, err := tr.Get(context.Background(), "https://api.github.com/repos/publisher/leaf")
			if tc.allowed {
				if err != nil || requests != 2 || data.ResolvedURL != tc.target {
					t.Fatalf("allowed rename failed: data=%+v err=%v requests=%d", data, err, requests)
				}
			} else if err == nil || requests != 1 {
				t.Fatalf("unsafe redirect was followed or retried: err=%v requests=%d", err, requests)
			}
		})
	}
}
