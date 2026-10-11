// Package testutil provides deterministic HTTP fixtures and repository paths for tests.
package testutil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
)

var FixedNow = time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)

type RoundTripFunc func(*http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type StubAPI struct {
	mu     sync.Mutex
	Bodies map[string]string
	Status map[string]int
	Errors map[string]error
	Calls  map[string]int
}

func NewStub() *StubAPI {
	return &StubAPI{Bodies: map[string]string{}, Status: map[string]int{}, Errors: map[string]error{}, Calls: map[string]int{}}
}

func (s *StubAPI) Client() *http.Client {
	return &http.Client{Transport: RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		key := r.URL.Host + r.URL.EscapedPath()
		s.Calls[key]++
		if err := s.Errors[key]; err != nil {
			return nil, err
		}
		status := s.Status[key]
		if status == 0 {
			status = 200
			if _, ok := s.Bodies[key]; !ok {
				status = 404
			}
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(s.Bodies[key])), Header: make(http.Header), Request: r}, nil
	})}
}

func (s *StubAPI) Count(key string) int { s.mu.Lock(); defer s.mu.Unlock(); return s.Calls[key] }

func PutJSON(t *testing.T, s *StubAPI, key string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	s.Bodies[key] = string(b)
}

func VersionBody(name, version, published string) string {
	return fmt.Sprintf(`{"versionKey":{"system":"RUBYGEMS","name":%q,"version":%q},"publishedAt":%q,"isDeprecated":false}`, name, version, published)
}

func IndexBody(names ...string) string {
	rows := []map[string]any{}
	for _, name := range names {
		rows = append(rows, map[string]any{"identifier": "pkg:gem/" + name, "product": map[string]string{"name": name, "uri": "https://endoflife.date/api/v1/products/" + name + "/"}})
	}
	b, _ := json.Marshal(map[string]any{"schema_version": "1.2.1", "generated_at": model.Timestamp(FixedNow), "result": rows})
	return string(b)
}

func ProductBody(name, cycle string, end *string, maintained bool) string {
	b, _ := json.Marshal(map[string]any{"schema_version": "1.2.1", "generated_at": model.Timestamp(FixedNow),
		"result": map[string]any{"name": name, "identifiers": []map[string]string{{"type": "purl", "id": "pkg:gem/" + name}},
			"links":    map[string]string{"html": "https://endoflife.date/" + name},
			"releases": []map[string]any{{"name": cycle, "eolFrom": end, "isEol": true, "isMaintained": maintained}}}})
	return string(b)
}
