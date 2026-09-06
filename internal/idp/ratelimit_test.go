package idp

import (
	"testing"
	"time"
)

func TestLimiterAllowsBurstThenBlocks(t *testing.T) {
	l := newLimiter(3) // burst of 3, refill 3/minute
	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("attempt %d blocked within burst", i+1)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("attempt beyond the burst must be blocked")
	}
	// Other clients are unaffected.
	if !l.allow("5.6.7.8") {
		t.Fatal("a different client IP must have its own bucket")
	}
}

func TestLimiterRefillsOverTime(t *testing.T) {
	l := newLimiter(60) // refill 1 per second
	if !l.allow("1.2.3.4") {
		t.Fatal("first attempt must pass")
	}
	// Simulate the passage of time by backdating the bucket.
	l.mu.Lock()
	l.buckets["1.2.3.4"].tokens = 0
	l.buckets["1.2.3.4"].last = time.Now().Add(-5 * time.Second)
	l.mu.Unlock()
	if !l.allow("1.2.3.4") {
		t.Fatal("after 5 seconds one token must have refilled")
	}
}

func TestLimiterDisabledWithNonPositiveLimit(t *testing.T) {
	l := newLimiter(0)
	for i := 0; i < 1000; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatal("a disabled limiter must allow everything")
		}
	}
}

func TestLimiterSweepsIdleBuckets(t *testing.T) {
	l := newLimiter(10)
	l.allow("1.2.3.4")
	// Backdate the bucket and the last sweep so a sweep becomes due. This must
	// happen without calling allow() while holding the mutex: allow() locks
	// l.mu itself and sync.Mutex is not reentrant.
	l.mu.Lock()
	l.buckets["1.2.3.4"].last = time.Now().Add(-time.Hour)
	l.lastSweep = time.Now().Add(-time.Hour)
	l.mu.Unlock()
	l.allow("5.6.7.8") // triggers the sweep
	l.mu.Lock()
	_, present := l.buckets["1.2.3.4"]
	l.mu.Unlock()
	if present {
		t.Fatal("idle bucket should have been swept")
	}
}
