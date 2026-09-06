package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
)

func TestLoginPostCancelsAuthenticationWithRequest(t *testing.T) {
	settings := newRateLimitTestSettings(t)
	sessionManager := session.New()
	started := make(chan struct{})
	abort := make(chan struct{})
	handler := handleLoginPostWithAuthenticator(
		sessionManager,
		settings,
		newLoginRateLimiter(settings),
		func(ctx context.Context, _, _ string, _ *config.Settings) (*identity.User, error) {
			close(started)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-abort:
				return nil, context.Canceled
			}
		},
	)
	router := sessionManager.LoadAndSave(sessionManager.EnforceClientIP(handler))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	form := url.Values{"username": {"alice"}, "password": {"secret"}}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.44:12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		router.ServeHTTP(rec, req)
	}()
	t.Cleanup(func() {
		close(abort)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("login handler did not stop during cleanup")
		}
	})

	waitForLoginSignal(t, started, "authentication to start")
	cancel()
	waitForLoginSignal(t, done, "canceled authentication to return")

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid credentials.") {
		t.Fatalf("canceled authentication returned status %d without the login failure response", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Errorf("canceled authentication redirected to %q", got)
	}
	if got := rec.Header().Get("Set-Cookie"); got != "" {
		t.Errorf("canceled authentication set a session cookie")
	}
	if sessionManager.UserHasActiveSessionFromIP("alice", "192.0.2.44") {
		t.Error("canceled authentication created an authenticated session")
	}
}

func waitForLoginSignal(t *testing.T, signal <-chan struct{}, action string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", action)
	}
}
