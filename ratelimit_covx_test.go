package main

import (
	"testing"
	"time"
)

// hcovClock is a controllable clock for exercising the login rate limiter's
// time-based pruning and lockout-expiry branches deterministically.
type hcovClock struct {
	current time.Time
}

func (c *hcovClock) now() time.Time { return c.current }

func (c *hcovClock) advance(d time.Duration) { c.current = c.current.Add(d) }

func hcovNewClock() *hcovClock {
	return &hcovClock{current: time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)}
}

func hcovNewLimiter(maxAttempts int, window, lockout time.Duration, clock *hcovClock) *loginRateLimiter {
	return &loginRateLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		lockout:     lockout,
		attempts:    make(map[string]*loginAttemptBucket),
		now:         clock.now,
	}
}

func hcovBucketCount(limiter *loginRateLimiter) int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return len(limiter.attempts)
}

func TestHcovNewLoginRateLimiterNilSettings(t *testing.T) {
	limiter := newLoginRateLimiter(nil)
	if limiter == nil {
		t.Fatal("expected a limiter for nil settings")
	}
	if limiter.enabled() {
		t.Fatal("expected nil-settings limiter to be disabled")
	}
}

func TestHcovLoginRateLimiterDisabledIsNoop(t *testing.T) {
	limiter := hcovNewLimiter(0, 0, 0, hcovNewClock())

	if retryAfter := limiter.RecordFailure("alice", "192.0.2.9:1000"); retryAfter != 0 {
		t.Fatalf("disabled RecordFailure returned %s", retryAfter)
	}
	if retryAfter, limited := limiter.RetryAfter("alice", "192.0.2.9:1000"); limited || retryAfter != 0 {
		t.Fatalf("disabled RetryAfter returned (%s, %t)", retryAfter, limited)
	}
	limiter.RecordSuccess("alice", "192.0.2.9:1000")
	if count := hcovBucketCount(limiter); count != 0 {
		t.Fatalf("disabled limiter tracked %d buckets", count)
	}
}

func TestHcovLoginRateLimiterLockExpiresAndBucketsPruned(t *testing.T) {
	clock := hcovNewClock()
	limiter := hcovNewLimiter(2, time.Minute, 5*time.Minute, clock)

	if retryAfter := limiter.RecordFailure("alice", "192.0.2.9:1000"); retryAfter != 0 {
		t.Fatalf("first failure should not lock, got %s", retryAfter)
	}
	if retryAfter := limiter.RecordFailure("alice", "192.0.2.9:1000"); retryAfter != 5*time.Minute {
		t.Fatalf("expected 5m lockout after second failure, got %s", retryAfter)
	}
	if _, limited := limiter.RetryAfter("alice", "192.0.2.9:1000"); !limited {
		t.Fatal("expected limiter to report the lockout")
	}

	clock.advance(10 * time.Minute)
	if retryAfter, limited := limiter.RetryAfter("alice", "192.0.2.9:1000"); limited || retryAfter != 0 {
		t.Fatalf("expected expired lockout to clear, got (%s, %t)", retryAfter, limited)
	}
	if count := hcovBucketCount(limiter); count != 0 {
		t.Fatalf("expected cleanup to delete idle buckets, got %d", count)
	}
}

func TestHcovLoginRateLimiterRecordFailureWhileLocked(t *testing.T) {
	clock := hcovNewClock()
	limiter := hcovNewLimiter(1, time.Minute, 5*time.Minute, clock)

	// An empty username tracks only the client-IP bucket, so the remaining
	// lockout reported while already locked is deterministic.
	if retryAfter := limiter.RecordFailure("", "192.0.2.9:2000"); retryAfter != 5*time.Minute {
		t.Fatalf("expected immediate lockout with maxAttempts=1, got %s", retryAfter)
	}

	clock.advance(time.Second)
	want := 5*time.Minute - time.Second
	if retryAfter := limiter.RecordFailure("", "192.0.2.9:2000"); retryAfter != want {
		t.Fatalf("expected remaining lockout %s while locked, got %s", want, retryAfter)
	}
}

func TestHcovLoginRateLimiterWindowExpiryDropsOldFailures(t *testing.T) {
	clock := hcovNewClock()
	limiter := hcovNewLimiter(2, time.Minute, 5*time.Minute, clock)

	if retryAfter := limiter.RecordFailure("carol", "192.0.2.9:3000"); retryAfter != 0 {
		t.Fatalf("first failure should not lock, got %s", retryAfter)
	}

	clock.advance(2 * time.Minute)
	if retryAfter := limiter.RecordFailure("carol", "192.0.2.9:3000"); retryAfter != 0 {
		t.Fatalf("expected expired failures to be forgotten, got %s", retryAfter)
	}
}

func TestHcovLoginRateLimitClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"host and port", "192.0.2.7:1234", "192.0.2.7"},
		{"mapped ipv6", "[::ffff:192.0.2.8]:99", "192.0.2.8"},
		{"empty", "", "unknown"},
		{"whitespace only", "   ", "unknown"},
		{"opaque address", "not-an-address", "not-an-address"},
		{"opaque trimmed", "  tunnel-peer  ", "tunnel-peer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := loginRateLimitClientIP(tc.remoteAddr); got != tc.want {
				t.Fatalf("loginRateLimitClientIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

func TestHcovLoginRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		name       string
		retryAfter time.Duration
		want       string
	}{
		{"zero clamps to one", 0, "1"},
		{"negative clamps to one", -5 * time.Second, "1"},
		{"sub second rounds up", 900 * time.Millisecond, "1"},
		{"fractional rounds up", 1200 * time.Millisecond, "2"},
		{"exact seconds", 2 * time.Second, "2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := loginRetryAfterSeconds(tc.retryAfter); got != tc.want {
				t.Fatalf("loginRetryAfterSeconds(%s) = %q, want %q", tc.retryAfter, got, tc.want)
			}
		})
	}
}
