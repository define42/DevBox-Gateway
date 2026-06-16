package session

import (
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/types"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

const testSessionRemoteAddr = "192.0.2.10:12345"

func issueSession(t *testing.T, m *Manager, user *types.User, remoteAddr string) *http.Cookie {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.CreateSession(r.Context(), user, r.RemoteAddr); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer func() {
		_ = res.Body.Close()
	}()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "cv_session" {
			return cookie
		}
	}

	t.Fatal("session cookie not set")
	return nil
}

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("expected non-nil Manager")
		return
	}
	if m.SessionManager == nil {
		t.Fatal("expected non-nil SessionManager")
	}
}

func TestCreateAndGetSession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("alice")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	sessionCookie := issueSession(t, m, user, testSessionRemoteAddr)

	sess, ok := m.getSessionFromUserName("alice")
	if !ok {
		t.Fatal("expected to find session for alice")
	}
	if sess.ClientIP != "192.0.2.10" {
		t.Fatalf("expected canonical client IP %q, got %q", "192.0.2.10", sess.ClientIP)
	}

	// Now verify UserFromContext works in a subsequent request with the cookie
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(sessionCookie)

	handler2 := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := m.UserFromContext(r.Context())
		if !ok {
			t.Fatal("expected user from context")
		}
		if u.GetName() != "alice" {
			t.Fatalf("expected user %q, got %q", "alice", u.GetName())
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler2.ServeHTTP(rec2, req2)
}

func TestUserFromContextNil(t *testing.T) {
	m := NewManager()

	//nolint:staticcheck // testing nil context behavior
	u, ok := m.UserFromContext(nil)
	if ok {
		t.Fatal("expected ok=false for nil context")
	}
	if u != nil {
		t.Fatal("expected nil user for nil context")
	}
}

func TestUserFromContextNoSession(t *testing.T) {
	m := NewManager()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := m.UserFromContext(r.Context())
		if ok {
			t.Fatal("expected ok=false when no session exists")
		}
		if u != nil {
			t.Fatal("expected nil user when no session exists")
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)
}

func TestGetSessionFromUserName(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("bob")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, testSessionRemoteAddr)

	sess, ok := m.getSessionFromUserName("bob")
	if !ok {
		t.Fatal("expected to find session for bob")
	}
	if sess.User == nil {
		t.Fatal("expected non-nil user in session")
	}
	if sess.User.GetName() != "bob" {
		t.Fatalf("expected user %q, got %q", "bob", sess.User.GetName())
	}
	if sess.ClientIP != "192.0.2.10" {
		t.Fatalf("expected canonical client IP %q, got %q", "192.0.2.10", sess.ClientIP)
	}

	// Test non-existing user
	_, ok = m.getSessionFromUserName("nonexistent")
	if ok {
		t.Fatal("expected not to find session for nonexistent user")
	}
}

func TestDestroySession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("charlie")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	sessionCookie := issueSession(t, m, user, testSessionRemoteAddr)

	// Now destroy the session
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req2.AddCookie(sessionCookie)

	handler2 := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.DestroySession(r.Context()); err != nil {
			t.Fatalf("destroy session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler2.ServeHTTP(rec2, req2)

	// Verify the session is destroyed by checking the user is gone
	_, found := m.getSessionFromUserName("charlie")
	if found {
		t.Fatal("expected session to be destroyed")
	}
	if m.UserHasActiveSessionFromIP("charlie", "192.0.2.10") {
		t.Fatal("expected destroyed session to be ignored")
	}
}

func TestUserHasActiveSessionFromIP(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("dora")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "192.0.2.20:5000")

	if !m.UserHasActiveSessionFromIP("dora", "192.0.2.20") {
		t.Fatal("expected matching username/IP pair to authorize")
	}
	if m.UserHasActiveSessionFromIP("dora", "192.0.2.21") {
		t.Fatal("did not expect different IP to authorize")
	}
}

func TestUserHasActiveSessionFromIPIgnoresExpiredSessions(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("dora")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	values := map[string]interface{}{
		sessionKey: sessionData{
			User:      user,
			CreatedAt: time.Now(),
			ClientIP:  "192.0.2.20",
		},
	}
	token := "session-token"

	activeDeadline := time.Now().Add(time.Hour)
	activeData, err := m.Codec.Encode(activeDeadline, values)
	if err != nil {
		t.Fatalf("encode active session: %v", err)
	}
	if err := m.Store.Commit(token, activeData, activeDeadline); err != nil {
		t.Fatalf("commit active session: %v", err)
	}

	if !m.UserHasActiveSessionFromIP("dora", "192.0.2.20") {
		t.Fatal("expected active session to authorize")
	}

	expiredDeadline := time.Now().Add(-time.Minute)
	expiredData, err := m.Codec.Encode(expiredDeadline, values)
	if err != nil {
		t.Fatalf("encode expired session: %v", err)
	}
	if err := m.Store.Commit(token, expiredData, expiredDeadline); err != nil {
		t.Fatalf("commit expired session: %v", err)
	}

	if m.UserHasActiveSessionFromIP("dora", "192.0.2.20") {
		t.Fatal("expected expired session to be ignored")
	}
}

func TestUserHasActiveSessionFromIPAllowsAnyMatchingOwnerSession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("erin")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "192.0.2.30:5000")
	issueSession(t, m, user, "192.0.2.31:5001")

	if !m.UserHasActiveSessionFromIP("erin", "192.0.2.31") {
		t.Fatal("expected one of multiple active sessions to authorize")
	}
}

func TestUserHasActiveSessionFromIPDoesNotCrossAuthorizeUsers(t *testing.T) {
	m := NewManager()

	alice, err := types.NewUser("alice")
	if err != nil {
		t.Fatalf("new alice: %v", err)
	}
	bob, err := types.NewUser("bob")
	if err != nil {
		t.Fatalf("new bob: %v", err)
	}

	issueSession(t, m, alice, "192.0.2.40:5000")
	issueSession(t, m, bob, "192.0.2.40:5001")

	if !m.UserHasActiveSessionFromIP("alice", "192.0.2.40") {
		t.Fatal("expected alice to authorize from her active session IP")
	}
	if !m.UserHasActiveSessionFromIP("bob", "192.0.2.40") {
		t.Fatal("expected bob to authorize from his active session IP")
	}
	if m.UserHasActiveSessionFromIP("carol", "192.0.2.40") {
		t.Fatal("did not expect unrelated user to authorize from shared IP")
	}
}

func TestCreateSessionNormalizesIPv4MappedIPv6(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("frank")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "[::ffff:192.0.2.50]:5000")

	sess, ok := m.getSessionFromUserName("frank")
	if !ok {
		t.Fatal("expected to find session for frank")
	}
	if sess.ClientIP != "192.0.2.50" {
		t.Fatalf("expected canonical client IP %q, got %q", "192.0.2.50", sess.ClientIP)
	}
	if !m.UserHasActiveSessionFromIP("frank", "192.0.2.50") {
		t.Fatal("expected IPv4-mapped IPv6 login to authorize plain IPv4 lookups")
	}
}

func TestCanonicalClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		wantIP     string
		wantOK     bool
	}{
		{name: "ipv4 with port", remoteAddr: "192.0.2.70:443", wantIP: "192.0.2.70", wantOK: true},
		{name: "plain ipv4", remoteAddr: "192.0.2.71", wantIP: "192.0.2.71", wantOK: true},
		{name: "ipv4 mapped ipv6", remoteAddr: "[::ffff:192.0.2.72]:443", wantIP: "192.0.2.72", wantOK: true},
		{name: "empty", remoteAddr: "", wantIP: "", wantOK: false},
		{name: "unparseable", remoteAddr: "not-an-ip:443", wantIP: "", wantOK: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotIP, gotOK := CanonicalClientIP(tc.remoteAddr)
			if gotOK != tc.wantOK {
				t.Fatalf("expected ok=%v, got %v", tc.wantOK, gotOK)
			}
			if gotIP != tc.wantIP {
				t.Fatalf("expected ip %q, got %q", tc.wantIP, gotIP)
			}
		})
	}
}

func TestGetSessionFromUserNameEmpty(t *testing.T) {
	m := NewManager()

	if _, ok := m.getSessionFromUserName("   "); ok {
		t.Fatal("expected blank username lookup to fail")
	}
}

func TestUserHasActiveSessionFromIPRejectsInvalidInput(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("grace")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	issueSession(t, m, user, "192.0.2.80:5000")

	if m.UserHasActiveSessionFromIP("", "192.0.2.80") {
		t.Fatal("expected blank username to fail authorization")
	}
	if m.UserHasActiveSessionFromIP("grace", "not-an-ip") {
		t.Fatal("expected invalid client IP to fail authorization")
	}
}

func TestSessionMiddlewareRedirectsWithoutSession(t *testing.T) {
	m := NewManager()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := humachi.NewContext(nil, r, w)
		m.SessionMiddleware()(ctx, func(huma.Context) {
			t.Fatal("next should not be called without a session")
		})
	}))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected %d, got %d", http.StatusSeeOther, rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestSessionMiddlewareCallsNextWithSession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("heidi")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	sessionCookie := issueSession(t, m, user, "192.0.2.90:5000")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(sessionCookie)

	called := false
	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := humachi.NewContext(nil, r, w)
		m.SessionMiddleware()(ctx, func(nextCtx huma.Context) {
			called = true

			sess, ok := nextCtx.Context().Value(sessionContextKey{}).(sessionData)
			if !ok {
				t.Fatal("expected session data in huma context")
			}
			if sess.User == nil || sess.User.GetName() != "heidi" {
				t.Fatalf("expected session user %q, got %#v", "heidi", sess.User)
			}

			w.WriteHeader(http.StatusNoContent)
		})
	}))
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected middleware to call next handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected %d, got %d", http.StatusNoContent, rec.Code)
	}
}

// withLoadedSession runs fn inside a request whose context has been through
// LoadAndSave, so session reads/writes work like a real handler. cookie may be
// nil to exercise an unauthenticated (loaded but empty) session.
func withLoadedSession(t *testing.T, m *Manager, remoteAddr string, cookie *http.Cookie, fn func(r *http.Request)) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/rdp", nil)
	req.RemoteAddr = remoteAddr
	if cookie != nil {
		req.AddCookie(cookie)
	}

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fn(r)
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)
}

func TestConsumeRDPConnectGrantIsSingleUse(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("alice")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	cookie := issueSession(t, m, user, testSessionRemoteAddr)

	// No grant yet: a standing session must not authorize RDP on its own.
	if m.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice-desk") {
		t.Fatal("did not expect a grant before Connect was clicked")
	}

	withLoadedSession(t, m, testSessionRemoteAddr, cookie, func(r *http.Request) {
		if err := m.GrantRDPConnect(r.Context(), "alice-desk"); err != nil {
			t.Fatalf("grant rdp connect: %v", err)
		}
	})

	// The grant authorizes exactly one RDP connection.
	if !m.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice-desk") {
		t.Fatal("expected the Connect grant to authorize the first RDP connection")
	}
	if m.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice-desk") {
		t.Fatal("expected the grant to be single-use (second connection denied)")
	}
}

func TestGrantRDPConnectRejectsBadInput(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("alice")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	cookie := issueSession(t, m, user, testSessionRemoteAddr)

	var blankErr, noSessionErr error
	withLoadedSession(t, m, testSessionRemoteAddr, cookie, func(r *http.Request) {
		blankErr = m.GrantRDPConnect(r.Context(), "   ")
	})
	if blankErr == nil {
		t.Fatal("expected an error granting a blank VM name")
	}

	// A loaded but unauthenticated session (no cookie) must not grant.
	withLoadedSession(t, m, testSessionRemoteAddr, nil, func(r *http.Request) {
		noSessionErr = m.GrantRDPConnect(r.Context(), "alice-desk")
	})
	if noSessionErr == nil {
		t.Fatal("expected an error granting without an authenticated session")
	}
}

func TestConsumeRDPConnectGrantIgnoresExpiredGrant(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("dora")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	// The session itself is still valid; only the grant has expired.
	deadline := time.Now().Add(time.Hour)
	values := map[string]interface{}{
		sessionKey: sessionData{
			User:             user,
			CreatedAt:        time.Now(),
			ClientIP:         "192.0.2.20",
			RDPConnectGrants: map[string]time.Time{"vm1": time.Now().Add(-time.Minute)},
		},
	}
	data, err := m.Codec.Encode(deadline, values)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	if err := m.Store.Commit("token", data, deadline); err != nil {
		t.Fatalf("commit session: %v", err)
	}

	if m.ConsumeRDPConnectGrant("dora", "192.0.2.20", "vm1") {
		t.Fatal("expected an expired connect grant to be ignored")
	}
}

func TestConsumeRDPConnectGrantRejectsScopeAndInputMismatches(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("dora")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	deadline := time.Now().Add(time.Hour)
	values := map[string]interface{}{
		sessionKey: sessionData{
			User:             user,
			CreatedAt:        time.Now(),
			ClientIP:         "192.0.2.20",
			RDPConnectGrants: map[string]time.Time{"vm1": time.Now().Add(time.Minute)},
		},
	}
	data, err := m.Codec.Encode(deadline, values)
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	if err := m.Store.Commit("token", data, deadline); err != nil {
		t.Fatalf("commit session: %v", err)
	}

	// Mismatches never match, so they must not consume the grant.
	if m.ConsumeRDPConnectGrant("dora", "192.0.2.20", "vm2") {
		t.Fatal("did not expect authorization for a different VM")
	}
	if m.ConsumeRDPConnectGrant("dora", "192.0.2.21", "vm1") {
		t.Fatal("did not expect authorization from a different IP")
	}
	if m.ConsumeRDPConnectGrant("erin", "192.0.2.20", "vm1") {
		t.Fatal("did not expect authorization for a different user")
	}
	if m.ConsumeRDPConnectGrant("", "192.0.2.20", "vm1") || m.ConsumeRDPConnectGrant("dora", "192.0.2.20", "") {
		t.Fatal("expected blank user or VM name to fail authorization")
	}
	if m.ConsumeRDPConnectGrant("dora", "not-an-ip", "vm1") {
		t.Fatal("expected an invalid client IP to fail authorization")
	}

	// The real grant survived every mismatch and authorizes exactly once.
	if !m.ConsumeRDPConnectGrant("dora", "192.0.2.20", "vm1") {
		t.Fatal("expected the unexpired grant to authorize")
	}
	if m.ConsumeRDPConnectGrant("dora", "192.0.2.20", "vm1") {
		t.Fatal("expected the grant to be single-use")
	}
}
