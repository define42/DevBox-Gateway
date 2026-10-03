package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
	"libvirt.org/go/libvirt"
)

func TestMigratedDirectoryOwnerCanActOnOriginalDomainName(t *testing.T) {
	t.Setenv("LIBVIRT_URI", "test:///default")
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	dom, err := conn.DomainDefineXML(`<domain type="test"><name>alice.ops.desktop</name>
<memory>1024</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = dom.Undefine()
		_ = dom.Free()
	})
	// Simulate the documented metadata-only migration. The domain retains
	// the old alias, which starts with the canonical username plus a dot.
	for _, owner := range []string{"alice.ops", "alice"} {
		if err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "<owner>"+owner+"</owner>",
			"devboxgateway", "urn:devboxgateway:domain:owner", libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
			t.Fatal(err)
		}
	}
	manager := session.New()
	t.Cleanup(func() { _ = manager.Close() })
	router := NewHandler(manager, config.NewSettings(false))
	for _, tt := range []struct {
		name string
		want int
	}{
		{name: "alice", want: http.StatusOK},
		{name: "alice.ops", want: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cookie := issueSessionCookie(t, manager, tt.name)
			rec := hcovPostForm(t, router, cookie, "/api/dashboard/shutdown", url.Values{"vm_name": {"alice.ops.desktop"}})
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestLoginUsesDirectoryIdentityAcrossSubmittedSpellings(t *testing.T) {
	settings := newRateLimitTestSettings(t)
	manager := session.New()
	handler := handleLoginPostWithAuthenticator(
		manager, settings, newLoginRateLimiter(settings),
		func(_ context.Context, username, _ string, _ *config.Settings) (*identity.User, error) {
			if !strings.EqualFold(username, "alice") {
				return nil, fmt.Errorf("unexpected login name")
			}
			return identity.New("alice")
		},
	)
	login := manager.LoadAndSave(manager.EnforceClientIP(handler))
	var firstCookie *http.Cookie
	for i, spelling := range []string{"alice", "ALICE"} {
		ip := fmt.Sprintf("192.0.2.%d", 44+i)
		cookie := loginDirectoryIdentity(t, login, spelling, ip)
		if i == 0 {
			firstCookie = cookie
		}
		if !manager.UserHasActiveSessionFromIP("alice", ip) {
			t.Fatalf("login %q did not store the directory identity", spelling)
		}
	}
	if manager.UserHasActiveSessionFromIP("ALICE", "192.0.2.45") {
		t.Fatal("submitted spelling created a second session identity")
	}
	if firstCookie == nil {
		t.Fatal("login did not set a session cookie")
	}

	logout := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logout.RemoteAddr = "192.0.2.44:12345"
	logout.AddCookie(firstCookie)
	setSameOriginHeader(logout)
	rec := httptest.NewRecorder()
	NewHandler(manager, settings).ServeHTTP(rec, logout)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout returned status %d: %s", rec.Code, rec.Body.String())
	}
	for _, ip := range []string{"192.0.2.44", "192.0.2.45"} {
		if manager.UserHasActiveSessionFromIP("alice", ip) {
			t.Errorf("logout left a session for the same directory account at %s", ip)
		}
	}
}

func loginDirectoryIdentity(t *testing.T, login http.Handler, spelling, ip string) *http.Cookie {
	t.Helper()
	form := url.Values{"username": {spelling}, "password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = ip + ":12345"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setSameOriginHeader(req)
	rec := httptest.NewRecorder()
	login.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login %q returned status %d: %s", spelling, rec.Code, rec.Body.String())
	}
	response := rec.Result()
	defer func() { _ = response.Body.Close() }()
	for _, cookie := range response.Cookies() {
		if cookie.Name == "cv_session" {
			return cookie
		}
	}
	t.Fatal("login did not set a session cookie")
	return nil
}

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
