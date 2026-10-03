package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/identity"

	"github.com/alexedwards/scs/v2"
)

type testRDPGrant struct {
	sessionToken string
	token        string
}

func commitTestRDPGrant(t *testing.T, manager *Manager, username string) testRDPGrant {
	t.Helper()
	ctx, err := manager.Load(t.Context(), "")
	if err != nil {
		t.Fatalf("load new session: %v", err)
	}
	if err := manager.CreateSession(ctx, &identity.User{Name: username}, testSessionRemoteAddr, testLoginPasswordHash); err != nil {
		t.Fatalf("create session: %v", err)
	}
	token, _, err := manager.Commit(ctx)
	if err != nil {
		t.Fatalf("commit session: %v", err)
	}
	ctx, err = manager.Load(t.Context(), token)
	if err != nil {
		t.Fatalf("load committed session: %v", err)
	}
	rdpToken, err := manager.GrantRDPConnect(ctx, username+".desktop")
	if err != nil {
		t.Fatalf("grant RDP access: %v", err)
	}
	return testRDPGrant{sessionToken: token, token: rdpToken}
}

// pauseConnectRequest suspends a real LoadAndSave request either immediately
// before granting access or before its first response write. Resuming waits for
// the middleware's deferred persistence as well as the handler to complete.
func pauseConnectRequest(
	t *testing.T, manager *Manager, cookie *http.Cookie, vmName string, beforeGrant bool,
) (func() (*httptest.ResponseRecorder, error), *string) {
	t.Helper()
	captured, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	resumeRequest := sync.OnceFunc(func() { close(resume) })
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/dashboard/rdp", nil)
	request.RemoteAddr = testSessionRemoteAddr
	request.AddCookie(cookie)
	var grantErr error
	var rdpToken string
	handler := manager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if beforeGrant {
			close(captured)
			<-resume
		}
		rdpToken, grantErr = manager.GrantRDPConnect(r.Context(), vmName)
		if !beforeGrant {
			close(captured)
			<-resume
		}
		if grantErr != nil {
			http.Error(w, "grant rejected", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(func() {
		resumeRequest()
		<-done
	})
	go func() {
		defer close(done)
		handler.ServeHTTP(response, request)
	}()
	<-captured
	return func() (*httptest.ResponseRecorder, error) {
		resumeRequest()
		<-done
		return response, grantErr
	}, &rdpToken
}

func TestGrantRDPConnectPendingResponseCannotRestoreRevokedSession(t *testing.T) {
	revocations := []struct {
		name   string
		revoke func(*Manager, context.Context) error
	}{
		{
			name: "logout everywhere",
			revoke: func(manager *Manager, _ context.Context) error {
				return manager.DestroyAllSessionsForUser("alice")
			},
		},
		{
			name:   "destroy current session",
			revoke: (*Manager).DestroySession,
		},
		{
			name: "renew token at login",
			revoke: func(manager *Manager, ctx context.Context) error {
				if err := manager.CreateSession(ctx, &identity.User{Name: "alice"}, testSessionRemoteAddr, testLoginPasswordHash); err != nil {
					return err
				}
				_, _, err := manager.Commit(ctx)
				return err
			},
		},
	}
	for _, revocation := range revocations {
		t.Run(revocation.name, func(t *testing.T) {
			for _, stage := range []struct {
				name        string
				beforeGrant bool
			}{
				{name: "before grant", beforeGrant: true},
				{name: "before response"},
			} {
				t.Run(stage.name, func(t *testing.T) {
					checkPendingConnectRevocation(t, revocation.revoke, stage.beforeGrant)
				})
			}
		})
	}
}

func checkPendingConnectRevocation(t *testing.T, revoke func(*Manager, context.Context) error, beforeGrant bool) {
	t.Helper()
	manager := New()
	cookie := issueSession(t, manager, &identity.User{Name: "alice"}, testSessionRemoteAddr)
	ctx, err := manager.Load(t.Context(), cookie.Value)
	if err != nil {
		t.Fatalf("load session for revocation: %v", err)
	}
	finish, rdpToken := pauseConnectRequest(t, manager, cookie, "alice.desktop", beforeGrant)
	if err := revoke(manager, ctx); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, exists, err := manager.Store.Find(cookie.Value); err != nil || exists {
		t.Fatalf("token was not revoked: exists=%v, err=%v", exists, err)
	}
	response, grantErr := finish()
	wantStatus := http.StatusNoContent
	if beforeGrant {
		wantStatus = http.StatusUnauthorized
	}
	if (grantErr != nil) != beforeGrant {
		t.Errorf("grant error=%v, want rejection=%v", grantErr, beforeGrant)
	}
	if response.Code != wantStatus {
		t.Errorf("response status=%d, want %d", response.Code, wantStatus)
	}
	if _, exists, err := manager.Store.Find(cookie.Value); err != nil || exists {
		t.Errorf("pending Connect response restored revoked token: exists=%v, err=%v", exists, err)
	}
	if manager.ConsumeRDPConnectGrant(*rdpToken, "alice", "192.0.2.10", "alice.desktop") {
		t.Error("pending Connect response restored revoked RDP access")
	}
}

func TestGrantRDPConnectPendingResponseCannotRestoreConsumedGrant(t *testing.T) {
	for _, stage := range []struct {
		name        string
		beforeGrant bool
	}{
		{name: "before grant", beforeGrant: true},
		{name: "before response"},
	} {
		t.Run(stage.name, func(t *testing.T) {
			checkPendingConnectConsumption(t, stage.beforeGrant)
		})
	}
}

func checkPendingConnectConsumption(t *testing.T, beforeGrant bool) {
	t.Helper()
	manager := New()
	cookie := issueSession(t, manager, &identity.User{Name: "alice"}, testSessionRemoteAddr)
	firstToken := grantCookieRDPToken(t, manager, cookie, "alice.first")
	finish, secondToken := pauseConnectRequest(t, manager, cookie, "alice.second", beforeGrant)
	if !manager.ConsumeRDPConnectGrant(firstToken, "alice", "192.0.2.10", "alice.first") {
		t.Fatal("first VM grant was unavailable before response completed")
	}
	response, err := finish()
	if err != nil || response.Code != http.StatusNoContent {
		t.Fatalf("second VM Connect failed: status=%d, err=%v", response.Code, err)
	}
	if manager.ConsumeRDPConnectGrant(firstToken, "alice", "192.0.2.10", "alice.first") {
		t.Error("pending Connect response restored an already-consumed grant")
	}
	if !manager.ConsumeRDPConnectGrant(*secondToken, "alice", "192.0.2.10", "alice.second") {
		t.Error("second VM Connect did not persist its grant")
	}
	if manager.ConsumeRDPConnectGrant(*secondToken, "alice", "192.0.2.10", "alice.second") {
		t.Error("second VM grant authorized more than one connection")
	}
}

func TestGrantRDPConnectConcurrentRequestsPreserveDifferentVMGrants(t *testing.T) {
	manager := New()
	cookie := issueSession(t, manager, &identity.User{Name: "alice"}, testSessionRemoteAddr)
	finish, firstToken := pauseConnectRequest(t, manager, cookie, "alice.first", false)
	secondToken := grantCookieRDPToken(t, manager, cookie, "alice.second")
	response, err := finish()
	if err != nil || response.Code != http.StatusNoContent {
		t.Fatalf("first VM Connect failed: status=%d, err=%v", response.Code, err)
	}
	for vmName, rdpToken := range map[string]string{"alice.first": *firstToken, "alice.second": secondToken} {
		if !manager.ConsumeRDPConnectGrant(rdpToken, "alice", "192.0.2.10", vmName) {
			t.Errorf("concurrent Connect requests lost grant for %s", vmName)
		}
		if manager.ConsumeRDPConnectGrant(rdpToken, "alice", "192.0.2.10", vmName) {
			t.Errorf("grant for %s authorized more than one connection", vmName)
		}
	}
}

func TestConsumeRDPConnectGrantDoesNotRestoreRevokedSession(t *testing.T) {
	tests := []struct {
		name   string
		revoke func(*Manager, context.Context) error
	}{
		{
			name: "logout everywhere",
			revoke: func(manager *Manager, _ context.Context) error {
				return manager.DestroyAllSessionsForUser("alice")
			},
		},
		{
			name: "destroy current session",
			revoke: func(manager *Manager, ctx context.Context) error {
				return manager.DestroySession(ctx)
			},
		},
		{
			name: "renew token at login",
			revoke: func(manager *Manager, ctx context.Context) error {
				if err := manager.CreateSession(ctx, &identity.User{Name: "alice"}, testSessionRemoteAddr, testLoginPasswordHash); err != nil {
					return err
				}
				_, _, err := manager.Commit(ctx)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRDPGrantRevocation(t, tt.revoke)
		})
	}
}

func checkRDPGrantRevocation(t *testing.T, revoke func(*Manager, context.Context) error) {
	t.Helper()
	manager := New()
	old := commitTestRDPGrant(t, manager, "alice")
	bob := commitTestRDPGrant(t, manager, "bob")
	ctx, err := manager.Load(t.Context(), old.sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	// Routing may finish before logout, but subsequent consumption must reload
	// the session and reject that exact token rather than reuse a stale decision.
	if vm, ok := manager.RDPConnectTarget(old.token, "192.0.2.10"); !ok || vm != "alice.desktop" {
		t.Fatal("initial token did not route")
	}
	if err := revoke(manager, ctx); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := manager.Store.Find(old.sessionToken); err != nil || exists {
		t.Fatalf("token was not revoked: exists=%v err=%v", exists, err)
	}
	if manager.ConsumeRDPConnectGrant(old.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("revoked token authorized a connection")
	}
	if !manager.ConsumeRDPConnectGrant(bob.token, "bob", "192.0.2.10", "bob.desktop") {
		t.Fatal("Alice logout invalidated Bob token")
	}
	fresh := commitTestRDPGrant(t, manager, "alice")
	if fresh.sessionToken == old.sessionToken || fresh.token == old.token {
		t.Fatal("fresh login reused a token")
	}
	if manager.ConsumeRDPConnectGrant(old.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("fresh login reactivated old token")
	}
	if !manager.ConsumeRDPConnectGrant(fresh.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("fresh login token did not authorize")
	}
}

func TestConsumeRDPConnectGrantConcurrentConnections(t *testing.T) {
	manager := New()
	grant := commitTestRDPGrant(t, manager, "alice")
	start := make(chan struct{})
	var consumers sync.WaitGroup
	var allowed atomic.Int32
	for range 32 {
		consumers.Go(func() {
			<-start
			if manager.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
				allowed.Add(1)
			}
		})
	}
	close(start)
	consumers.Wait()
	if allowed.Load() != 1 {
		t.Fatalf("token consumed %d times, want exactly once", allowed.Load())
	}
}

type grantCommitFailingStore struct {
	scs.Store
	scs.IterableStore
}

func (grantCommitFailingStore) Commit(string, []byte, time.Time) error {
	return errors.New("session store unavailable")
}

type grantEncodeFailingCodec struct {
	scs.Codec
}

func (grantEncodeFailingCodec) Encode(time.Time, map[string]interface{}) ([]byte, error) {
	return nil, errors.New("session encoding failed")
}

func TestConsumeRDPConnectGrantFailsClosedOnPersistenceError(t *testing.T) {
	tests := []struct {
		name string
		fail func(*Manager)
	}{
		{
			name: "encode",
			fail: func(manager *Manager) {
				manager.Codec = grantEncodeFailingCodec{Codec: manager.Codec}
			},
		},
		{
			name: "commit",
			fail: func(manager *Manager) {
				manager.Store = grantCommitFailingStore{
					Store:         manager.Store,
					IterableStore: manager.Store.(scs.IterableStore),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := New()
			grant := commitTestRDPGrant(t, manager, "alice")
			store, codec := manager.Store, manager.Codec
			tt.fail(manager)
			if manager.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
				t.Error("RDP authorized despite failing to persist grant consumption")
			}
			manager.Store, manager.Codec = store, codec
			if !manager.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
				t.Error("grant was lost despite failed persistence")
			}
		})
	}
}

type pausedGrantCommitStore struct {
	scs.Store
	scs.IterableStore

	paused  atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (s *pausedGrantCommitStore) Commit(token string, data []byte, expiry time.Time) error {
	if s.paused.CompareAndSwap(false, true) {
		close(s.entered)
		<-s.resume
	}
	return s.Store.Commit(token, data, expiry)
}

func TestConsumeRDPConnectGrantCommitCannotUndoLogout(t *testing.T) {
	manager := New()
	grant := commitTestRDPGrant(t, manager, "alice")
	checkGrantCommitCannotUndoLogout(t, manager, grant, func() bool {
		return manager.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop")
	})
}

func TestGrantRDPConnectCommitCannotUndoLogout(t *testing.T) {
	manager := New()
	grant := commitTestRDPGrant(t, manager, "alice")
	ctx, err := manager.Load(t.Context(), grant.sessionToken)
	if err != nil {
		t.Fatalf("load session for Connect: %v", err)
	}
	checkGrantCommitCannotUndoLogout(t, manager, grant, func() bool {
		_, err := manager.GrantRDPConnect(ctx, "alice.desktop")
		return err == nil
	})
}

func checkGrantCommitCannotUndoLogout(t *testing.T, manager *Manager, grant testRDPGrant, update func() bool) {
	t.Helper()
	store := &pausedGrantCommitStore{
		Store:         manager.Store,
		IterableStore: manager.Store.(scs.IterableStore),
		entered:       make(chan struct{}),
		resume:        make(chan struct{}),
	}
	manager.Store = store
	resume := sync.OnceFunc(func() { close(store.resume) })
	rdpDone := make(chan struct{})
	updateResult := make(chan bool, 1)
	logoutDone := make(chan struct{})
	logoutResult := make(chan error, 1)
	t.Cleanup(func() {
		resume()
		<-rdpDone
		<-logoutDone
	})
	go func() {
		defer close(rdpDone)
		updateResult <- update()
	}()
	<-store.entered
	go func() {
		defer close(logoutDone)
		logoutResult <- manager.DestroyAllSessionsForUser("alice")
	}()

	// Let logout finish if the implementation permits it; otherwise release
	// the pending write after a bounded wait. Both orderings are valid, but
	// neither may leave a session behind after logout and consumption finish.
	// Mutex waits are not durably blocking in testing/synctest.
	select {
	case <-logoutDone:
	case <-time.After(100 * time.Millisecond):
	}
	resume()
	<-rdpDone
	<-logoutDone
	if !<-updateResult {
		t.Error("grant update failed despite successful persistence")
	}
	if err := <-logoutResult; err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, exists, err := manager.Store.Find(grant.sessionToken); err != nil || exists {
		t.Errorf("pending RDP commit restored a logged-out session: exists=%v, err=%v", exists, err)
	}
	if manager.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Error("logged-out session still authorizes RDP")
	}
}
