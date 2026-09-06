package session

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
)

func pendingConnectionAuthorization(
	t *testing.T,
	manager *Manager,
	token, username string,
	rdp bool,
) ConnectionAuthorization {
	t.Helper()
	var auth ConnectionAuthorization
	var allowed bool
	if rdp {
		auth, allowed = manager.AuthorizeRDPConnection(username, "192.0.2.10", username+".desktop")
	} else {
		ctx := loadConnectionSession(t, manager, token)
		auth, allowed = manager.AuthorizeConnection(ctx)
	}
	if !allowed {
		t.Fatal("active session did not authorize a connection")
	}
	if auth.Username() != username {
		t.Fatalf("authorization username = %q, want %q", auth.Username(), username)
	}
	return auth
}

func loadConnectionSession(t *testing.T, manager *Manager, token string) context.Context {
	t.Helper()
	ctx, err := manager.Load(t.Context(), token)
	if err != nil {
		t.Fatalf("load connection session: %v", err)
	}
	return ctx
}

func rejectConnectionAuthorization(t *testing.T, manager *Manager, auth ConnectionAuthorization) {
	t.Helper()
	unregister, allowed := manager.RegisterUserConnection(auth, func() {})
	unregister()
	if allowed {
		t.Error("invalid or revoked authorization registered a connection")
	}
}

func registerConnectionAuthorization(t *testing.T, manager *Manager, auth ConnectionAuthorization) {
	t.Helper()
	unregister, allowed := manager.RegisterUserConnection(auth, func() {})
	t.Cleanup(unregister)
	if !allowed {
		t.Fatal("valid authorization could not register a connection")
	}
}

func TestConnectionAuthorizationRejectsLogoutBeforeRegistration(t *testing.T) {
	for _, rdp := range []bool{false, true} {
		name := "HTTP"
		if rdp {
			name = "RDP"
		}
		t.Run(name, func(t *testing.T) {
			checkPendingConnectionLogout(t, rdp)
		})
	}
}

func checkPendingConnectionLogout(t *testing.T, rdp bool) {
	t.Helper()
	manager := New()
	aliceToken := commitTestRDPGrant(t, manager, "alice")
	bobToken := commitTestRDPGrant(t, manager, "bob")
	aliceAuth := pendingConnectionAuthorization(t, manager, aliceToken, "alice", rdp)
	bobAuth := pendingConnectionAuthorization(t, manager, bobToken, "bob", rdp)

	// No connection is registered yet: logout must invalidate authorization
	// already held by a handler that is still opening its backend transport.
	if err := manager.DestroyAllSessionsForUser("alice"); err != nil {
		t.Fatalf("delete Alice's sessions: %v", err)
	}
	if closed := manager.CloseUserConnections("alice"); closed != 0 {
		t.Fatalf("logout closed %d connections before any registered", closed)
	}
	rejectConnectionAuthorization(t, manager, aliceAuth)
	registerConnectionAuthorization(t, manager, bobAuth)

	freshToken := commitTestRDPGrant(t, manager, "alice")
	if freshToken == aliceToken {
		t.Fatal("fresh login reused the revoked token")
	}
	freshAuth := pendingConnectionAuthorization(t, manager, freshToken, "alice", rdp)
	registerConnectionAuthorization(t, manager, freshAuth)
	rejectConnectionAuthorization(t, manager, aliceAuth)
	if closed := manager.CloseUserConnections("alice"); closed != 1 {
		t.Errorf("logout closed %d Alice connections, want 1", closed)
	}
	if closed := manager.CloseUserConnections("bob"); closed != 1 {
		t.Errorf("Alice's logout affected Bob's connection: closed %d, want 1", closed)
	}
}

func TestAuthorizeConnectionRejectsRevokedLoadedSession(t *testing.T) {
	manager := New()
	oldToken := commitTestRDPGrant(t, manager, "alice")
	loadedBeforeLogout := loadConnectionSession(t, manager, oldToken)
	if err := manager.DestroyAllSessionsForUser("alice"); err != nil {
		t.Fatalf("delete Alice's sessions: %v", err)
	}
	manager.CloseUserConnections("alice")
	if _, allowed := manager.AuthorizeConnection(loadedBeforeLogout); allowed {
		t.Error("request loaded before logout minted a new authorization after logout")
	}

	freshToken := commitTestRDPGrant(t, manager, "alice")
	if _, allowed := manager.AuthorizeConnection(loadedBeforeLogout); allowed {
		t.Error("fresh login reauthorized a request carrying the revoked token")
	}
	if _, found, err := manager.Store.Find(oldToken); err != nil || found {
		t.Errorf("old token lookup after fresh login: found=%v, err=%v", found, err)
	}
	registerConnectionAuthorization(t, manager,
		pendingConnectionAuthorization(t, manager, freshToken, "alice", false))
	registerConnectionAuthorization(t, manager,
		pendingConnectionAuthorization(t, manager, freshToken, "alice", true))
}

func TestConnectionAuthorizationRequiresValidManager(t *testing.T) {
	manager := New()
	rejectConnectionAuthorization(t, manager, ConnectionAuthorization{})

	otherManager := New()
	token := commitTestRDPGrant(t, otherManager, "alice")
	foreignAuth := pendingConnectionAuthorization(t, otherManager, token, "alice", false)
	rejectConnectionAuthorization(t, manager, foreignAuth)
	registerConnectionAuthorization(t, otherManager, foreignAuth)
}

func TestConnectionAuthorizationRejectsExpiredTicket(t *testing.T) {
	manager := New()
	token := commitTestRDPGrant(t, manager, "alice")
	auth := pendingConnectionAuthorization(t, manager, token, "alice", false)
	auth.deadline = time.Now().Add(-time.Second)
	rejectConnectionAuthorization(t, manager, auth)

	registerConnectionAuthorization(t, manager,
		pendingConnectionAuthorization(t, manager, token, "alice", false))
}

func TestAuthorizeConnectionRejectsUnauthenticatedSession(t *testing.T) {
	manager := New()
	ctx := loadConnectionSession(t, manager, "")
	if _, allowed := manager.AuthorizeConnection(ctx); allowed {
		t.Error("unauthenticated request received a connection authorization")
	}
	if _, allowed := manager.AuthorizeRDPConnection("alice", "192.0.2.10", "alice.desktop"); allowed {
		t.Error("missing RDP grant received a connection authorization")
	}
}

func TestConnectionAuthorizationConcurrentRegistrationAndLogout(t *testing.T) {
	manager := New()
	token := commitTestRDPGrant(t, manager, "alice")
	for range 64 {
		auth := pendingConnectionAuthorization(t, manager, token, "alice", false)
		checkConcurrentConnectionLogout(t, manager, auth)
	}
}

func checkConcurrentConnectionLogout(t *testing.T, manager *Manager, auth ConnectionAuthorization) {
	t.Helper()
	var closed atomic.Bool
	start := make(chan struct{})
	registrationDone := make(chan struct{})
	logoutDone := make(chan struct{})
	var unregister func()
	var allowed bool
	go func() {
		defer close(registrationDone)
		<-start
		unregister, allowed = manager.RegisterUserConnection(auth, func() { closed.Store(true) })
	}()
	go func() {
		defer close(logoutDone)
		<-start
		manager.CloseUserConnections("alice")
	}()
	close(start)
	<-registrationDone
	<-logoutDone
	unregister()
	if allowed && !closed.Load() {
		t.Fatal("concurrent logout left a registered connection open")
	}
	rejectConnectionAuthorization(t, manager, auth)
}

type pausedConnectionAuthorizationStore struct {
	scs.Store
	scs.IterableStore

	pauseAll bool
	paused   atomic.Bool
	entered  chan struct{}
	resume   chan struct{}
}

func (s *pausedConnectionAuthorizationStore) Find(token string) ([]byte, bool, error) {
	data, found, err := s.Store.Find(token)
	if !s.pauseAll {
		s.pause()
	}
	return data, found, err
}

func (s *pausedConnectionAuthorizationStore) All() (map[string][]byte, error) {
	data, err := s.IterableStore.All()
	if s.pauseAll {
		s.pause()
	}
	return data, err
}

func (s *pausedConnectionAuthorizationStore) pause() {
	if s.paused.CompareAndSwap(false, true) {
		close(s.entered)
		<-s.resume
	}
}

func TestConnectionAuthorizationCapturesLogoutBeforeStoreValidation(t *testing.T) {
	for _, rdp := range []bool{false, true} {
		name := "HTTP"
		if rdp {
			name = "RDP"
		}
		t.Run(name, func(t *testing.T) {
			checkLogoutDuringConnectionAuthorization(t, rdp)
		})
	}
}

func checkLogoutDuringConnectionAuthorization(t *testing.T, rdp bool) {
	t.Helper()
	manager := New()
	token := commitTestRDPGrant(t, manager, "alice")
	ctx := loadConnectionSession(t, manager, token)
	store := &pausedConnectionAuthorizationStore{
		Store:         manager.Store,
		IterableStore: manager.Store.(scs.IterableStore),
		pauseAll:      rdp,
		entered:       make(chan struct{}),
		resume:        make(chan struct{}),
	}
	manager.Store = store
	resume := sync.OnceFunc(func() { close(store.resume) })
	done := make(chan struct{})
	t.Cleanup(func() {
		resume()
		<-done
	})
	var auth ConnectionAuthorization
	var allowed bool
	go func() {
		defer close(done)
		if rdp {
			auth, allowed = manager.AuthorizeRDPConnection("alice", "192.0.2.10", "alice.desktop")
		} else {
			auth, allowed = manager.AuthorizeConnection(ctx)
		}
	}()
	<-store.entered
	// Closing the user's connections while validation is paused must revoke
	// the pending authorization even if its store snapshot still exists.
	manager.CloseUserConnections("alice")
	resume()
	<-done
	if allowed {
		rejectConnectionAuthorization(t, manager, auth)
	}
}
