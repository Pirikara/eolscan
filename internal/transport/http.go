// Package transport handles allowed HTTPS requests, retries, memoization, and disk caching.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
}

type Transport struct {
	client    *http.Client
	p         model.Policy
	now       time.Time
	offline   bool
	cacheDir  string
	sem       chan struct{}
	mu        sync.Mutex
	memo      map[string]*requestMemo
	wait      func(context.Context, time.Duration) error
	cacheHits atomic.Int64
}

func New(client *http.Client, p model.Policy, now time.Time, offline bool, options ...TransportOption) *Transport {
	c := *client
	c.Timeout = time.Duration(p.Network.TimeoutSeconds * float64(time.Second))
	previous := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("redirect limit")
		}
		first := via[0].URL
		if !AllowedURL(req.URL, p) || req.URL.Host != first.Host || req.URL.Scheme != first.Scheme ||
			!strings.HasPrefix(req.URL.Path, redirectPrefix(first.Path)) {
			return fmt.Errorf("provider redirect rejected")
		}
		if previous != nil {
			return previous(req, via)
		}
		return nil
	}
	t := &Transport{client: &c, p: p, now: now, offline: offline, sem: make(chan struct{}, p.Network.MaxConcurrency),
		memo: map[string]*requestMemo{}, wait: waitContext}
	for _, option := range options {
		option(t)
	}
	return t
}

func redirectPrefix(path string) string {
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
	u, err := url.Parse(raw)
	if err != nil || !AllowedURL(u, t.p) {
		return HTTPData{}, &LookupError{Code: "UNSAFE_PROVIDER_URL"}
	}
	t.mu.Lock()
	if m, exists := t.memo[raw]; exists {
		t.mu.Unlock()
		select {
		case <-m.done:
			return m.data, m.err
		case <-ctx.Done():
			return HTTPData{}, ctx.Err()
		}
	}
	m := &requestMemo{done: make(chan struct{})}
	t.memo[raw] = m
	t.mu.Unlock()
	defer close(m.done)
	defer func() {
		if failure := recover(); failure != nil {
			m.err = &LookupError{Code: "INTERNAL_TRANSPORT_ERROR"}
			panic(failure)
		}
	}()
	m.data, m.err = t.fetch(ctx, raw)
	return m.data, m.err
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
	data := HTTPData{Status: record.Status, Body: record.Body, ObservedAt: record.ObservedAt, ETag: record.ETag, Diagnostics: []model.Diagnostic{}}
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
	record := diskRecord{SchemaVersion: "2.0", URL: raw, Status: data.Status, Body: data.Body, BodyHash: contract.Digest(data.Body), ObservedAt: data.ObservedAt, ETag: data.ETag}
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return fileio.AtomicWrite(path, b)
}

func (t *Transport) Invalidate(raw string) {
	if !t.p.Cache.Enabled {
		return
	}
	t.mu.Lock()
	path, err := t.diskPath(raw)
	t.mu.Unlock()
	if err == nil {
		_ = os.Remove(path)
	}
}

func (t *Transport) fetch(ctx context.Context, raw string) (HTTPData, error) {
	cached, exists, fresh := t.cached(raw)
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
	for attempt := 0; attempt <= t.p.Network.Retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return data, &LookupError{Code: "INVALID_PROVIDER_REQUEST"}
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "eolscan/"+version.Current)
		if exists && cached.ETag != "" {
			req.Header.Set("If-None-Match", cached.ETag)
		}
		select {
		case t.sem <- struct{}{}:
		case <-ctx.Done():
			return data, &LookupError{Code: "SOURCE_ERROR"}
		}
		resp, err := t.client.Do(req)
		retry := false
		delay := time.Duration(200*(1<<attempt)) * time.Millisecond
		if err != nil {
			<-t.sem
			var n net.Error
			retry = errors.As(err, &n)
			last = &LookupError{Code: "SOURCE_ERROR", Retryable: retry}
		} else {
			data = HTTPData{Status: resp.StatusCode, ObservedAt: model.Timestamp(t.now), ETag: resp.Header.Get("ETag"), Diagnostics: []model.Diagnostic{}}
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
				if err := t.save(raw, data); err != nil {
					data.Diagnostics = append(data.Diagnostics, model.NewDiagnostic("CACHE_WRITE_ERROR", "", "Disk cache write failed"))
				}
				return data, nil
			} else if resp.StatusCode == 200 || resp.StatusCode == 404 {
				if err := t.save(raw, data); err != nil {
					data.Diagnostics = append(data.Diagnostics, model.NewDiagnostic("CACHE_WRITE_ERROR", "", "Disk cache write failed"))
				}
				return data, nil
			} else {
				retry = resp.StatusCode == 429 || resp.StatusCode >= 500
				last = &LookupError{Code: "SOURCE_ERROR", Status: resp.StatusCode, Retryable: retry}
				if after := resp.Header.Get("Retry-After"); after != "" {
					if seconds, err := strconv.ParseInt(after, 10, 32); err == nil && seconds >= 0 {
						delay = time.Duration(seconds) * time.Second
					} else if when, err := http.ParseTime(after); err == nil {
						delay = when.Sub(t.now)
						if delay < 0 {
							delay = 0
						}
					}
				}
			}
		}
		if !retry || attempt == t.p.Network.Retries {
			return data, last
		}
		// A long Retry-After is respected by returning an incomplete lookup,
		// instead of sending an early retry or blocking a CI job indefinitely.
		if delay > 30*time.Second {
			return data, last
		}
		if err := t.wait(ctx, delay); err != nil {
			return data, &LookupError{Code: "SOURCE_ERROR"}
		}
	}
	return data, last
}
