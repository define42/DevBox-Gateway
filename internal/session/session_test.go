package session

import (
	"net/http"
	"net/http/httptest"
	"rdptlsgateway/internal/types"
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("expected non-nil Manager")
	}
	if m.SessionManager == nil {
		t.Fatal("expected non-nil SessionManager")
	}
}

func TestCreateAndGetSession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("alice", "secret")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	var sessionCookie *http.Cookie

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.CreateSession(r.Context(), user); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "cv_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
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

	user, err := types.NewUser("bob", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.CreateSession(r.Context(), user); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	sess, ok := m.GetSessionFromUserName("bob")
	if !ok {
		t.Fatal("expected to find session for bob")
	}
	if sess.User == nil {
		t.Fatal("expected non-nil user in session")
	}
	if sess.User.GetName() != "bob" {
		t.Fatalf("expected user %q, got %q", "bob", sess.User.GetName())
	}

	// Test non-existing user
	_, ok = m.GetSessionFromUserName("nonexistent")
	if ok {
		t.Fatal("expected not to find session for nonexistent user")
	}
}

func TestDestroySession(t *testing.T) {
	m := NewManager()

	user, err := types.NewUser("charlie", "pass")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	var sessionCookie *http.Cookie

	handler := m.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.CreateSession(r.Context(), user); err != nil {
			t.Fatalf("create session: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rec, req)

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "cv_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("session cookie not set")
	}

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
	_, found := m.GetSessionFromUserName("charlie")
	if found {
		t.Fatal("expected session to be destroyed")
	}
}
