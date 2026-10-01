package proxy

import (
	"sync"
	"time"
)

// rateLimiter is a token bucket per destination host: perMin new connections per minute with a
// burst of perMin. It exists to stop a runaway or malicious process hammering one destination.
type rateLimiter struct {
	mu    sync.Mutex
	m     map[string]*bucket
	now   func() time.Time
	prune time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	pruneAfter    = 4096        // entries before idle buckets are swept
	maxBucketKeys = 100_000     // hard cap, so wildcard rules cannot grow the map without bound
	pruneInterval = time.Minute //
)

func newRateLimiter(now func() time.Time) *rateLimiter {
	return &rateLimiter{m: map[string]*bucket{}, now: now}
}

// Allow consumes a token for host. perMin <= 0 means unlimited.
func (r *rateLimiter) Allow(host string, perMin int) bool {
	if perMin <= 0 {
		return true
	}
	now := r.now()
	rate := float64(perMin) / 60.0
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.m) > pruneAfter && now.Sub(r.prune) > pruneInterval {
		r.sweepLocked(now)
	}
	b, ok := r.m[host]
	if !ok {
		if len(r.m) >= maxBucketKeys {
			return false // refuse brand-new hosts rather than evicting someone's accounting
		}
		b = &bucket{tokens: float64(perMin), last: now}
		r.m[host] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > float64(perMin) {
		b.tokens = float64(perMin)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that have been idle long enough to be full again.
func (r *rateLimiter) sweepLocked(now time.Time) {
	r.prune = now
	for k, b := range r.m {
		if now.Sub(b.last) > 2*time.Minute {
			delete(r.m, k)
		}
	}
}
