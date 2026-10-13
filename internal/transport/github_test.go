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
