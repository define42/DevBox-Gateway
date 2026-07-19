package main

import (
	"crypto/sha256"
	"devboxgateway/internal/config"
	"devboxgateway/internal/session"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginRateLimiterLocksUsernameAcrossIPs(t *testing.T) {
	limiter := newTestLoginRateLimiter(t)

	if retryAfter := limiter.RecordFailure("Alice", "192.0.2.10:1234"); retryAfter != 0 {
		t.Fatalf("first failure should not lock, got retry-after %s", retryAfter)
	}
	if _, locked := limiter.RetryAfter("alice", "198.51.100.20:1234"); locked {
		t.Fatal("single username failure should not lock")
	}
	if retryAfter := limiter.RecordFailure("ALICE", "198.51.100.20:1234"); retryAfter <= 0 {
		t.Fatal("second username failure across IPs should lock")
	}
	if _, locked := limiter.RetryAfter("alice", "203.0.113.30:1234"); !locked {
		t.Fatal("username should remain locked from a third IP")
	}
}

func TestLoginRateLimiterLocksIPAcrossUsernames(t *testing.T) {
	limiter := newTestLoginRateLimiter(t)

	if retryAfter := limiter.RecordFailure("alice", "192.0.2.10:1234"); retryAfter != 0 {
		t.Fatalf("first failure should not lock, got retry-after %s", retryAfter)
	}
	if retryAfter := limiter.RecordFailure("bob", "192.0.2.10:5678"); retryAfter <= 0 {
		t.Fatal("second IP failure across usernames should lock")
	}
	if _, locked := limiter.RetryAfter("carol", "192.0.2.10:9999"); !locked {
		t.Fatal("client IP should remain locked for another username")
	}
}

func TestLoginRateLimiterSuccessClearsBuckets(t *testing.T) {
	limiter := newTestLoginRateLimiter(t)

	limiter.RecordFailure("alice", "192.0.2.10:1234")
	limiter.RecordSuccess("alice", "192.0.2.10:1234")
	if retryAfter := limiter.RecordFailure("alice", "192.0.2.10:1234"); retryAfter != 0 {
		t.Fatalf("failure after success should not lock, got retry-after %s", retryAfter)
	}
}

func TestLoginPostRateLimitsFailedAttempts(t *testing.T) {
	router := newLocalLoginRouter(t)
	remoteAddr := "192.0.2.44:12345"

	rec := postLogin(t, router, remoteAddr, "alice", "wrong")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected first failed login to return 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid credentials.") {
		t.Fatalf("expected invalid credentials response, got %q", rec.Body.String())
	}

	rec = postLogin(t, router, remoteAddr, "alice", "wrong-again")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second failed login to return 429, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After header")
	}
	if !strings.Contains(rec.Body.String(), loginLocked) {
		t.Fatalf("expected rate limit response, got %q", rec.Body.String())
	}

	rec = postLogin(t, router, remoteAddr, "alice", "secret")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected lockout to reject valid credentials with 429, got %d", rec.Code)
	}
}

func TestLoginPostSuccessClearsFailedAttempts(t *testing.T) {
	router := newLocalLoginRouter(t)
	remoteAddr := "192.0.2.55:12345"

	rec := postLogin(t, router, remoteAddr, "alice", "wrong")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected failed login to return 200, got %d", rec.Code)
	}

	rec = postLogin(t, router, remoteAddr, "alice", "secret")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected successful login to return 303, got %d", rec.Code)
	}

	rec = postLogin(t, router, remoteAddr, "alice", "wrong")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected failed login after success to return 200, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), loginLocked) {
		t.Fatalf("success should clear rate limit buckets, got %q", rec.Body.String())
	}
}

func newTestLoginRateLimiter(t *testing.T) *loginRateLimiter {
	t.Helper()
	settings := newRateLimitTestSettings(t)
	limiter := newLoginRateLimiter(settings)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	return limiter
}

func newLocalLoginRouter(t *testing.T) http.Handler {
	t.Helper()
	t.Setenv(config.LDAP_URL, "")
	t.Setenv(config.LOCAL_USER_SHA256, localUserSHA256("alice", "secret"))
	settings := newRateLimitTestSettings(t)
	return getRemoteGatewayRotuer(session.NewManager(), settings)
}

func newRateLimitTestSettings(t *testing.T) *config.SettingsType {
	t.Helper()
	t.Setenv(config.LOGIN_RATE_LIMIT_MAX_ATTEMPTS, "2")
	t.Setenv(config.LOGIN_RATE_LIMIT_WINDOW, "1m")
	t.Setenv(config.LOGIN_RATE_LIMIT_LOCKOUT, "1h")
	return config.NewSettingType(false)
}

func postLogin(t *testing.T, router http.Handler, remoteAddr, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"username": {username},
		"password": {password},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// A real browser posting the login form is same-origin; mirror that so the
	// request clears the login handler's same-origin (CSRF) gate and reaches
	// the rate-limiting and authentication logic under test.
	setSameOriginHeader(req)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func localUserSHA256(username, password string) string {
	sum := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(sum[:])
}
