package transport

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Pirikara/eolscan/internal/model"
)

type hostBudget struct {
	mu             sync.Mutex
	tokens         float64
	updated        time.Time
	cooldown       time.Time
	cooldownStatus int
}

func (t *Transport) hostLimit(host string) model.RateLimit {
	if limit, ok := t.p.Network.HostLimits[host]; ok {
		return limit
	}
	return model.RateLimit{RequestsPerSecond: t.p.Network.RequestsPerSecond, Burst: t.p.Network.Burst}
}

func (t *Transport) hostBudget(host string) *hostBudget {
	t.mu.Lock()
	defer t.mu.Unlock()
	if b := t.hosts[host]; b != nil {
		return b
	}
	b := &hostBudget{tokens: float64(t.hostLimit(host).Burst), updated: t.clock()}
	t.hosts[host] = b
	return b
}

// acquireHost limits actual request starts, including retries and redirects.
// The caller already owns an HTTP concurrency slot, so queued requests cannot
// reserve tokens and then create a burst when a slot becomes available.
func (t *Transport) acquireHost(ctx context.Context, host string) error {
	b := t.hostBudget(host)
	limit := t.hostLimit(host)
	started := t.clock()
	budget := time.Duration(t.p.Network.MaxWaitSeconds * float64(time.Second))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := t.clock()
		b.mu.Lock()
		elapsed := now.Sub(b.updated).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(float64(limit.Burst), b.tokens+elapsed*limit.RequestsPerSecond)
			b.updated = now
		}
		delay := b.cooldown.Sub(now)
		code, status := "SOURCE_ERROR", b.cooldownStatus
		if status == http.StatusTooManyRequests {
			code = "RATE_LIMITED"
		}
		if delay <= 0 {
			if b.tokens >= 1 {
				b.tokens--
				b.mu.Unlock()
				return nil
			}
			delay = time.Duration(math.Ceil((1 - b.tokens) / limit.RequestsPerSecond * float64(time.Second)))
			code, status = "RATE_LIMIT_WAIT_TIMEOUT", 0
		}
		b.mu.Unlock()
		if delay > budget-now.Sub(started) {
			return &LookupError{Code: code, Status: status, Retryable: true}
		}
		if err := t.wait(ctx, delay); err != nil {
			return err
		}
	}
}

func (t *Transport) coolDown(host string, delay time.Duration, status int) {
	b := t.hostBudget(host)
	until := t.clock().Add(delay)
	b.mu.Lock()
	if until.After(b.cooldown) {
		b.cooldown = until
		b.cooldownStatus = status
	}
	b.mu.Unlock()
}

func retryAfter(raw string, now time.Time) (time.Duration, bool) {
	if raw == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(raw, 10, 64); err == nil && seconds >= 0 {
		// Do not let a large server-provided value wrap into an early retry.
		if seconds > math.MaxInt64/int64(time.Second) {
			return time.Duration(math.MaxInt64), true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if strings.Trim(raw, "0123456789") == "" {
		// A digits-only value that overflows int64 still describes a long wait.
		return time.Duration(math.MaxInt64), true
	}
	if at, err := http.ParseTime(raw); err == nil {
		return max(0, at.Sub(now)), true
	}
	return 0, false
}
