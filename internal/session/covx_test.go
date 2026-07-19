package session

import (
	"context"
	"devboxgateway/internal/types"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
)

const covxRemoteAddr = "192.0.2.99:4321"

// covxIterableStore is a controllable scs.IterableStore for driving store-level
// error branches that the real memstore cannot produce.
type covxIterableStore struct {
	sessions  map[string][]byte
	allErr    error
	deleteErr error
}

func (s *covxIterableStore) Delete(string) error                    { return s.deleteErr }
func (s *covxIterableStore) Find(string) ([]byte, bool, error)      { return nil, false, nil }
func (s *covxIterableStore) Commit(string, []byte, time.Time) error { return nil }

func (s *covxIterableStore) All() (map[string][]byte, error) {
	if s.allErr != nil {
		return nil, s.allErr
	}
	return s.sessions, nil
}

// covxPlainStore implements only scs.Store, so iterable-store type assertions
// fail against it.
type covxPlainStore struct{}

func (covxPlainStore) Delete(string) error                    { return nil }
func (covxPlainStore) Find(string) ([]byte, bool, error)      { return nil, false, nil }
func (covxPlainStore) Commit(string, []byte, time.Time) error { return nil }

// covxDeleteFailingStore delegates to a real store but refuses deletions, so
// scs Destroy/RenewToken fail while sessions still load normally.
type covxDeleteFailingStore struct {
	scs.Store

	deleteErr error
}

func (s covxDeleteFailingStore) Delete(string) error { return s.deleteErr }

func covxUser(t *testing.T, name string) *types.User {
	t.Helper()
	user, err := types.NewUser(name)
	if err != nil {
		t.Fatalf("new user %q: %v", name, err)
	}
	return user
}

func TestCovxStoreNotIterable(t *testing.T) {
	m := NewManager()
	m.Store = covxPlainStore{}

	if got := m.allSessions(); got != nil {
		t.Fatalf("expected nil sessions for a non-iterable store, got %v", got)
	}
	if err := m.DestroyAllSessionsForUser("alice"); err == nil {
		t.Fatal("expected an error destroying sessions on a non-iterable store")
	}
	if m.ConsumeRDPConnectGrant("alice", "192.0.2.1", "vm1") {
		t.Fatal("expected no grant consumption on a non-iterable store")
	}
}

func TestCovxStoreIterationError(t *testing.T) {
	allErr := errors.New("iteration failed")
	m := NewManager()
	m.Store = &covxIterableStore{allErr: allErr}

	if got := m.allSessions(); got != nil {
		t.Fatalf("expected nil sessions when iteration fails, got %v", got)
	}
	if err := m.DestroyAllSessionsForUser("alice"); !errors.Is(err, allErr) {
		t.Fatalf("expected the iteration error to surface, got %v", err)
	}
	if m.ConsumeRDPConnectGrant("alice", "192.0.2.1", "vm1") {
		t.Fatal("expected no grant consumption when iteration fails")
	}
}

func TestCovxStoreSkipsUndecodableSessions(t *testing.T) {
	m := NewManager()
	if err := m.Store.Commit("covx-bad", []byte("not-a-gob-session"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("commit garbage session: %v", err)
	}

	if got := m.allSessions(); len(got) != 0 {
		t.Fatalf("expected undecodable sessions to be skipped, got %v", got)
	}
	if err := m.DestroyAllSessionsForUser("alice"); err != nil {
		t.Fatalf("expected undecodable sessions to be skipped on destroy, got %v", err)
	}
}

func TestCovxDestroyAllSessionsForUserDeleteError(t *testing.T) {
	m := NewManager()
	deleteErr := errors.New("delete refused")

	deadline := time.Now().Add(time.Hour)
	encoded, err := m.Codec.Encode(deadline, map[string]interface{}{
		sessionKey: sessionData{User: covxUser(t, "alice"), CreatedAt: time.Now(), ClientIP: "192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}

	m.Store = &covxIterableStore{
		sessions:  map[string][]byte{"covx-token": encoded},
		deleteErr: deleteErr,
	}

	if err := m.DestroyAllSessionsForUser("alice"); !errors.Is(err, deleteErr) {
		t.Fatalf("expected the first delete error to surface, got %v", err)
	}
}

func TestCovxConsumeStoredGrantRejectsInvalidStoredData(t *testing.T) {
	m := NewManager()
	now := time.Now()

	if m.consumeStoredGrant("tok", []byte("not-a-gob-session"), "alice", "192.0.2.1", "vm1", now) {
		t.Fatal("expected undecodable session data to be rejected")
	}

	deadline := now.Add(time.Hour)
	userless, err := m.Codec.Encode(deadline, map[string]interface{}{
		sessionKey: sessionData{ClientIP: "192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("encode userless session: %v", err)
	}
	if m.consumeStoredGrant("tok", userless, "alice", "192.0.2.1", "vm1", now) {
		t.Fatal("expected a session without a user to be rejected")
	}
}

func TestCovxUserHasActiveSessionFromIPSkipsUserlessSession(t *testing.T) {
	m := NewManager()

	deadline := time.Now().Add(time.Hour)
	userless, err := m.Codec.Encode(deadline, map[string]interface{}{
		sessionKey: sessionData{CreatedAt: time.Now(), ClientIP: "192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("encode userless session: %v", err)
	}
	if err := m.Store.Commit("covx-userless", userless, deadline); err != nil {
		t.Fatalf("commit userless session: %v", err)
	}

	if m.UserHasActiveSessionFromIP("alice", "192.0.2.1") {
		t.Fatal("expected a userless session never to authorize")
	}
}

func TestCovxGrantRDPConnectPrunesExpiredGrants(t *testing.T) {
	m := NewManager()
	user := covxUser(t, "nora")
	cookie := issueSession(t, m, user, covxRemoteAddr)

	withLoadedSession(t, m, covxRemoteAddr, cookie, func(r *http.Request) {
		sess, ok := m.Get(r.Context(), sessionKey).(sessionData)
		if !ok {
			t.Fatal("expected an authenticated session")
		}
		sess.RDPConnectGrants = map[string]time.Time{
			"kept-vm":  time.Now().Add(time.Minute),
			"stale-vm": time.Now().Add(-time.Minute),
		}
		m.Put(r.Context(), sessionKey, sess)
		if err := m.GrantRDPConnect(r.Context(), "new-vm"); err != nil {
			t.Fatalf("grant rdp connect: %v", err)
		}
	})

	if m.ConsumeRDPConnectGrant("nora", "192.0.2.99", "stale-vm") {
		t.Fatal("expected the expired grant to be pruned by a new grant")
	}
	if !m.ConsumeRDPConnectGrant("nora", "192.0.2.99", "kept-vm") {
		t.Fatal("expected the unexpired grant to be carried over")
	}
	if !m.ConsumeRDPConnectGrant("nora", "192.0.2.99", "new-vm") {
		t.Fatal("expected the freshly issued grant to authorize")
	}
}

func TestCovxRegisterUserConnectionInitializesNilMap(t *testing.T) {
	m := &Manager{}

	unregister := m.RegisterUserConnection("alice", func() {})
	if m.userConnections == nil {
		t.Fatal("expected the connection registry map to be initialized lazily")
	}
	if got := m.CloseUserConnections("alice"); got != 1 {
		t.Fatalf("expected the lazily registered connection to close, got %d", got)
	}
	unregister()
}

func TestCovxUserFromContextContextKeyFallback(t *testing.T) {
	m := NewManager()
	user := covxUser(t, "mona")

	withLoadedSession(t, m, covxRemoteAddr, nil, func(r *http.Request) {
		ctx := context.WithValue(r.Context(), sessionContextKey{}, sessionData{User: user})
		got, ok := m.UserFromContext(ctx)
		if !ok || got == nil || got.GetName() != "mona" {
			t.Fatalf("expected the context-key fallback user, got ok=%v user=%#v", ok, got)
		}
	})
}

func TestCovxCreateSessionRenewTokenError(t *testing.T) {
	m := NewManager()
	user := covxUser(t, "lena")
	cookie := issueSession(t, m, user, covxRemoteAddr)
	m.Store = covxDeleteFailingStore{Store: m.Store, deleteErr: errors.New("delete refused")}

	var createErr error
	withLoadedSession(t, m, covxRemoteAddr, cookie, func(r *http.Request) {
		createErr = m.CreateSession(r.Context(), user, r.RemoteAddr)
	})
	if createErr == nil {
		t.Fatal("expected CreateSession to fail when the old token cannot be deleted")
	}
}

func TestCovxEnforceClientIPDestroyFailureStillServes(t *testing.T) {
	m := NewManager()
	user := covxUser(t, "kate")
	cookie := issueSession(t, m, user, "192.0.2.60:5000")
	m.Store = covxDeleteFailingStore{Store: m.Store, deleteErr: errors.New("delete refused")}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = "198.51.100.9:6000" // roamed IP forces a destroy attempt
	req.AddCookie(cookie)

	served := false
	handler := m.LoadAndSave(m.EnforceClientIP(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	})))
	handler.ServeHTTP(rec, req)

	if !served {
		t.Fatal("expected the request to be served even when destroying the roamed session fails")
	}
}
