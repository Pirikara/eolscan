// Package transport handles allowed HTTPS requests, retries, memoization, and disk caching.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Pirikara/eolscan/internal/contract"
	"github.com/Pirikara/eolscan/internal/fileio"
	"github.com/Pirikara/eolscan/internal/model"
	"github.com/Pirikara/eolscan/internal/version"
)

const maxResponseBytes = 32 << 20

type HTTPData struct {
	Status      int
	Body        []byte
	ObservedAt  string
	ETag        string
	ResolvedURL string
	Diagnostics []model.Diagnostic
}

type LookupError struct {
	Code      string
	Status    int
	Retryable bool
}

func (e *LookupError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("%s (HTTP %d)", e.Code, e.Status)
	}
	return e.Code
}

func ErrorDiagnostic(provider string, err error) model.Diagnostic {
	d := model.NewDiagnostic("SOURCE_ERROR", provider, "Provider lookup could not be completed")
	var e *LookupError
	if errors.As(err, &e) {
		d.Code = e.Code
		d.Retryable = e.Retryable
		if e.Status != 0 {
			d.HTTPStatus = model.Ptr(e.Status)
		}
	}
	return d
}

type requestMemo struct {
	done chan struct{}
	data HTTPData
	err  error
}

type diskRecord struct {
	SchemaVersion string `json:"schema_version"`
	URL           string `json:"url"`
	Status        int    `json:"status"`
	Body          []byte `json:"body"`
	BodyHash      string `json:"body_hash"`
	ObservedAt    string `json:"observed_at"`
	ETag          string `json:"etag"`
	ResolvedURL   string `json:"resolved_url,omitempty"`
}

type Transport struct {
	client      *http.Client
	p           model.Policy
	now         time.Time
	offline     bool
	cacheDir    string
	sem         chan struct{}
	mu          sync.Mutex
	memo        map[string]*requestMemo
	wait        func(context.Context, time.Duration) error
	clock       func() time.Time
	jitter      func(time.Duration) time.Duration
	hosts       map[string]*hostBudget
	cacheHits   atomic.Int64
	githubToken string
}

func New(client *http.Client, p model.Policy, now time.Time, offline bool, options ...TransportOption) *Transport {
	c := *client
	c.Timeout = time.Duration(p.Network.TimeoutSeconds * float64(time.Second))
	t := &Transport{client: &c, p: p, now: now, offline: offline, sem: make(chan struct{}, p.Network.MaxConcurrency),
		memo: map[string]*requestMemo{}, wait: waitContext, clock: time.Now, hosts: map[string]*hostBudget{},
		jitter: func(base time.Duration) time.Duration { return base + time.Duration(rand.Float64()*float64(base)) }}
	for _, option := range options {
		option(t)
	}
	// Authentication is opt-in through a named environment variable. Never
	// send that value to a custom mirror or include it in policy/cache data.
	if p.Sources.GitHub.Enabled && strings.TrimRight(p.Sources.GitHub.BaseURL, "/") == "https://api.github.com" {
		t.githubToken = os.Getenv(p.Sources.GitHub.TokenEnv)
	}
	previous := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return &LookupError{Code: "UNSAFE_PROVIDER_URL"}
		}
		first := via[0].URL
		if !AllowedURL(req.URL, p) || req.URL.Host != first.Host || req.URL.Scheme != first.Scheme ||
			!allowedRedirectPath(first.Path, req.URL.Path) {
			return &LookupError{Code: "UNSAFE_PROVIDER_URL"}
		}
		if previous != nil {
			if err := previous(req, via); err != nil {
				return err
			}
		}
		return t.acquireHost(req.Context(), req.URL.Hostname())
	}
	return t
}

func allowedRedirectPath(first, target string) bool {
	if i := strings.Index(first, "/repos/"); i >= 0 {
		prefix := first[:i]
		if strings.HasPrefix(target, prefix+"/repos/") {
			return true
		}
		// GitHub redirects transferred/renamed repositories to their stable
		// numeric ID endpoint. The provider verifies this ID against the body.
		if suffix, ok := strings.CutPrefix(target, prefix+"/repositories/"); ok {
			id, err := strconv.ParseUint(suffix, 10, 63)
			return err == nil && id > 0
		}
		return false
	}
	return strings.HasPrefix(target, redirectPrefix(first))
}

func redirectPrefix(path string) string {
	if strings.HasPrefix(path, "/repos/") {
		return "/repos/"
	}
	if i := strings.Index(path, "/products/"); i >= 0 {
		return path[:i] + "/products/"
	}
	if i := strings.Index(path, "/identifiers/"); i >= 0 {
		return path[:i] + "/identifiers/"
	}
	if i := strings.Index(path, "/systems/"); i >= 0 {
		return path[:i] + "/systems/"
	}
	return path
}

func AllowedURL(u *url.URL, p model.Policy) bool {
	return u.Scheme == "https" && u.User == nil && u.Opaque == "" && u.Fragment == "" && u.RawQuery == "" && model.Contains(p.Network.AllowedHosts, u.Hostname())
}

func waitContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (t *Transport) Get(ctx context.Context, raw string) (HTTPData, error) {
	return t.GetWithAccept(ctx, raw, "application/json")
}

// GetWithAccept isolates cached representations and only accepts the JSON
// media types used by supported providers.
func (t *Transport) GetWithAccept(ctx context.Context, raw, accept string) (HTTPData, error) {
	if accept != "application/json" && accept != "application/vnd.pypi.simple.v1+json" {
		return HTTPData{}, &LookupError{Code: "UNSUPPORTED_MEDIA_TYPE"}
	}
	u, err := url.Parse(raw)
	if err != nil || !AllowedURL(u, t.p) {
		return HTTPData{}, &LookupError{Code: "UNSAFE_PROVIDER_URL"}
	}
	key := representationKey(raw, accept)
	t.mu.Lock()
	if m, exists := t.memo[key]; exists {
		t.mu.Unlock()
		select {
		case <-m.done:
			return m.data, m.err
		case <-ctx.Done():
			return HTTPData{}, ctx.Err()
		}
	}
	m := &requestMemo{done: make(chan struct{})}
	t.memo[key] = m
	t.mu.Unlock()
	defer close(m.done)
	defer func() {
		if failure := recover(); failure != nil {
			m.err = &LookupError{Code: "INTERNAL_TRANSPORT_ERROR"}
			panic(failure)
		}
	}()
	m.data, m.err = t.fetch(ctx, raw, key, accept)
	return m.data, m.err
}

func representationKey(raw, accept string) string {
	if accept == "application/json" {
		return raw
	}
	return raw + "\x00" + accept
}

func (t *Transport) diskPath(raw string) (string, error) {
	if t.cacheDir == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		t.cacheDir = filepath.Join(dir, "eolscan", "v2")
	}
	return filepath.Join(t.cacheDir, contract.Digest([]byte("report-2.0|"+raw))+".json"), nil
}

func (t *Transport) cached(raw string) (HTTPData, bool, bool) {
	if !t.p.Cache.Enabled {
		return HTTPData{}, false, false
	}
	// cacheDir initialization is synchronized because multiple components may
	// share a transport. Disk IO itself does not hold the memo lock.
	t.mu.Lock()
	path, err := t.diskPath(raw)
	t.mu.Unlock()
	if err != nil {
		return HTTPData{}, false, false
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 2*maxResponseBytes {
		return HTTPData{}, false, false
	}
	body, err := fileio.ReadLimited(path, 2*maxResponseBytes)
	if err != nil {
		return HTTPData{}, false, false
	}
	var record diskRecord
	if json.Unmarshal(body, &record) != nil || record.SchemaVersion != "2.0" || record.URL != raw ||
		(record.Status != 200 && record.Status != 404) || record.BodyHash != contract.Digest(record.Body) {
		return HTTPData{}, false, false
	}
	at, err := time.Parse(time.RFC3339Nano, record.ObservedAt)
	if err != nil || at.After(t.now) {
		return HTTPData{}, false, false
	}
	age := t.now.Sub(at).Hours()
	data := HTTPData{Status: record.Status, Body: record.Body, ObservedAt: record.ObservedAt, ETag: record.ETag, ResolvedURL: record.ResolvedURL, Diagnostics: []model.Diagnostic{}}
	if age/24 > float64(t.p.Decision.MaxEvidenceAgeDays) {
		data.Diagnostics = append(data.Diagnostics, model.NewDiagnostic("STALE_EVIDENCE", "", "Disk cache exceeds maximum evidence age"))
		return data, false, false
	}
	ttl := t.p.Cache.PositiveTTLHours
	if record.Status == 404 {
		ttl = t.p.Cache.NegativeTTLHours
	}
	return data, true, age <= ttl
}

func (t *Transport) save(raw string, data HTTPData) error {
	if !t.p.Cache.Enabled || (data.Status != 200 && data.Status != 404) {
		return nil
	}
	if data.Status == 200 {
		if err := contract.InspectJSON(data.Body, 256); err != nil {
			return err
		}
	}
	t.mu.Lock()
	path, err := t.diskPath(raw)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe cache directory")
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return err
	}
	record := diskRecord{SchemaVersion: "2.0", URL: raw, Status: data.Status, Body: data.Body, BodyHash: contract.Digest(data.Body), ObservedAt: data.ObservedAt, ETag: data.ETag, ResolvedURL: data.ResolvedURL}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return fileio.AtomicWrite(path, b)
}

func (t *Transport) Invalidate(raw string) {
	t.InvalidateWithAccept(raw, "application/json")
}

func (t *Transport) InvalidateWithAccept(raw, accept string) {
	if !t.p.Cache.Enabled {
		return
	}
	t.mu.Lock()
	path, err := t.diskPath(representationKey(raw, accept))
	t.mu.Unlock()
	if err == nil {
		_ = os.Remove(path)
	}
}

func (t *Transport) fetch(ctx context.Context, raw, key, accept string) (HTTPData, error) {
	cached, exists, fresh := t.cached(key)
	if fresh {
		t.cacheHits.Add(1)
		return cached, nil
	}
	if t.offline {
		if exists {
			t.cacheHits.Add(1)
			cached.Diagnostics = append(cached.Diagnostics, model.NewDiagnostic("CACHE_STALE", "", "Offline scan uses cache beyond TTL but within maximum evidence age"))
			return cached, nil
		}
		code := "OFFLINE_UNAVAILABLE"
		if len(cached.Diagnostics) > 0 {
			code = "STALE_EVIDENCE"
		}
		return cached, &LookupError{Code: code}
	}
	var data HTTPData
	var last error
	u, _ := url.Parse(raw)
	for attempt := 0; attempt <= t.p.Network.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return data, &LookupError{Code: "INVALID_PROVIDER_REQUEST"}
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", "eolscan/"+version.Current)
		github := u.Scheme == "https" && u.Host == "api.github.com" && strings.HasPrefix(u.Path, "/repos/")
		if github {
			req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
			if t.githubToken != "" {
				req.Header.Set("Authorization", "Bearer "+t.githubToken)
			}
		}
		if exists && cached.ETag != "" {
			req.Header.Set("If-None-Match", cached.ETag)
		}
		select {
		case t.sem <- struct{}{}:
		case <-ctx.Done():
			return data, &LookupError{Code: "SOURCE_ERROR"}
		}
		if err := t.acquireHost(ctx, u.Hostname()); err != nil {
			<-t.sem
			return data, err
		}
		resp, err := t.client.Do(req)
		retry := false
		delay := t.jitter(time.Duration(200*(1<<attempt)) * time.Millisecond)
		if err != nil {
			<-t.sem
			var lookup *LookupError
			if errors.As(err, &lookup) {
				return data, lookup
			}
			var n net.Error
			retry = errors.As(err, &n)
			last = &LookupError{Code: "SOURCE_ERROR", Retryable: retry}
		} else {
			if after, valid := retryAfter(resp.Header.Get("Retry-After"), t.clock()); valid {
				delay = max(delay, after)
			}
			if resp.StatusCode == 429 || resp.StatusCode == 503 {
				t.coolDown(u.Hostname(), delay, resp.StatusCode)
			}
			githubLimited := github && resp.StatusCode == 403 &&
				(resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != "")
			if githubLimited {
				if reset, parseErr := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); parseErr == nil {
					delay = max(delay, time.Unix(reset, 0).Sub(t.clock()))
				}
				t.coolDown(u.Hostname(), delay, 429)
			}
			resolved := raw
			if resp.Request != nil && resp.Request.URL != nil {
				resolved = resp.Request.URL.String()
			}
			data = HTTPData{Status: resp.StatusCode, ObservedAt: model.Timestamp(t.now), ETag: resp.Header.Get("ETag"), ResolvedURL: resolved, Diagnostics: []model.Diagnostic{}}
			data.Body, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
			resp.Body.Close()
			<-t.sem
			if err != nil {
				last = &LookupError{Code: "SOURCE_ERROR", Status: resp.StatusCode, Retryable: true}
				retry = true
			} else if len(data.Body) > maxResponseBytes {
				return data, &LookupError{Code: "PROVIDER_RESPONSE_TOO_LARGE", Status: resp.StatusCode}
			} else if resp.StatusCode == 304 {
				if !exists || cached.Status != 200 {
					return data, &LookupError{Code: "PROVIDER_SCHEMA_MISMATCH", Status: 304}
				}
				data = cached
				data.ObservedAt = model.Timestamp(t.now)
				if err := t.save(key, data); err != nil {
					data.Diagnostics = append(data.Diagnostics, model.NewDiagnostic("CACHE_WRITE_ERROR", "", "Disk cache write failed"))
				}
				return data, nil
			} else if resp.StatusCode == 200 || resp.StatusCode == 404 {
				if err := t.save(key, data); err != nil {
					data.Diagnostics = append(data.Diagnostics, model.NewDiagnostic("CACHE_WRITE_ERROR", "", "Disk cache write failed"))
				}
				return data, nil
			} else {
				retry = resp.StatusCode == 429 || resp.StatusCode >= 500 || githubLimited
				last = &LookupError{Code: "SOURCE_ERROR", Status: resp.StatusCode, Retryable: retry}
				if resp.StatusCode == 429 || githubLimited {
					last = &LookupError{Code: "RATE_LIMITED", Status: resp.StatusCode, Retryable: true}
				}
			}
		}
		if !retry || attempt == t.p.Network.Retries {
			return data, last
		}
		// A long Retry-After is respected by returning an incomplete lookup,
		// instead of sending an early retry or blocking a CI job indefinitely.
		if delay > time.Duration(t.p.Network.MaxWaitSeconds*float64(time.Second)) {
			return data, last
		}
		if err := t.wait(ctx, delay); err != nil {
			return data, &LookupError{Code: "SOURCE_ERROR"}
		}
	}
	return data, last
}
