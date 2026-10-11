package transport

import (
	"context"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
)

// TransportOption configures an injected transport dependency.
type TransportOption func(*Transport)

// WithWait injects a cancellable wait function for deterministic retry tests.
func WithWait(wait func(context.Context, time.Duration) error) TransportOption {
	return func(t *Transport) { t.wait = wait }
}

// Policy returns the effective policy used by this transport.
func (t *Transport) Policy() model.Policy { return t.p }

// Now returns the execution timestamp used for cache and evidence freshness.
func (t *Transport) Now() time.Time { return t.now }

// CacheHits returns the number of successful disk cache reads.
func (t *Transport) CacheHits() int64 { return t.cacheHits.Load() }
