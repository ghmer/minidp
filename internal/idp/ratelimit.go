package idp

import (
	"sync"
	"time"
)

// loginLimiter is a per-client-IP token bucket that throttles login attempts
// (POST /authorize and POST /login) to blunt credential stuffing without
// adding any external dependency. Buckets start full (burst == perMinute) and
// refill continuously; idle buckets are swept lazily.
type loginLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	perMinute int
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter returns a limiter allowing perMinute attempts per IP. A
// non-positive perMinute disables limiting (allow all).
func newLimiter(perMinute int) *loginLimiter {
	return &loginLimiter{
		buckets:   make(map[string]*bucket),
		perMinute: perMinute,
		lastSweep: time.Now(),
	}
}

// allow reports whether a login attempt from key (the client IP) is permitted.
func (l *loginLimiter) allow(key string) bool {
	if l == nil || l.perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.sweepLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.perMinute), last: now}
		l.buckets[key] = b
	}

	// Continuous refill.
	refill := float64(l.perMinute) / 60
	b.tokens = min(float64(l.perMinute), b.tokens+now.Sub(b.last).Seconds()*refill)
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked drops buckets that have been idle for more than twice the
// refill period. The caller must hold the lock.
func (l *loginLimiter) sweepLocked(now time.Time) {
	if len(l.buckets) < 1024 && now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	// Refill to a full bucket always takes 60 s regardless of perMinute, so
	// "twice the refill period" is a fixed two minutes (a fixed constant also
	// keeps high-rate configurations from sweeping buckets too eagerly).
	idle := 2 * time.Minute
	for key, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, key)
		}
	}
}
