package session

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/identity"

	"github.com/alexedwards/scs/v2"
)

// pausedSessionSnapshotStore lets an RDP connection retain the result of All
// while another request revokes its session. Later All calls continue normally
// so user-wide logout can enumerate and delete sessions before RDP resumes.
type pausedSessionSnapshotStore struct {
	scs.Store
	scs.IterableStore

	paused   atomic.Bool
	captured chan struct{}
	resume   chan struct{}
}

func (s *pausedSessionSnapshotStore) All() (map[string][]byte, error) {
	snapshot, err := s.IterableStore.All()
	if s.paused.CompareAndSwap(false, true) {
		close(s.captured)
		<-s.resume
	}
	return snapshot, err
}

func commitTestRDPGrant(t *testing.T, manager *Manager, username string) string {
	t.Helper()
	ctx, err := manager.Load(t.Context(), "")
	if err != nil {
		t.Fatalf("load new session: %v", err)
	}
	if err := manager.CreateSession(ctx, &identity.User{Name: username}, testSessionRemoteAddr, testLoginPasswordHash); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := manager.GrantRDPConnect(ctx, username+".desktop"); err != nil {
		t.Fatalf("grant RDP access: %v", err)
	}
	token, _, err := manager.Commit(ctx)
	if err != nil {
		t.Fatalf("commit session: %v", err)
	}
	return token
}

func consumeWithPausedSnapshot(t *testing.T, manager *Manager) (<-chan bool, func()) {
	t.Helper()
	store := &pausedSessionSnapshotStore{
		Store:         manager.Store,
		IterableStore: manager.Store.(scs.IterableStore),
		captured:      make(chan struct{}),
		resume:        make(chan struct{}),
	}
	manager.Store = store
	resume := sync.OnceFunc(func() { close(store.resume) })
	result := make(chan bool, 1)
	done := make(chan struct{})
	t.Cleanup(func() {
		resume()
		<-done
	})
	go func() {
		defer close(done)
		result <- manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop")
	}()
	<-store.captured
	return result, resume
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
	oldToken := commitTestRDPGrant(t, manager, "alice")
	commitTestRDPGrant(t, manager, "bob")
	ctx, err := manager.Load(t.Context(), oldToken)
	if err != nil {
		t.Fatalf("load session for revocation: %v", err)
	}

	result, resume := consumeWithPausedSnapshot(t, manager)

	// Revocation completes while RDP still holds the old enumeration.
	if err := revoke(manager, ctx); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, exists, err := manager.Store.Find(oldToken); err != nil || exists {
		t.Fatalf("token was not revoked: exists=%v, err=%v", exists, err)
	}
	resume()
	if <-result {
		t.Error("stale RDP enumeration authorized a revoked session")
	}
	if _, exists, err := manager.Store.Find(oldToken); err != nil || exists {
		t.Errorf("RDP consumption restored the old session: exists=%v, err=%v", exists, err)
	}
	if !manager.UserHasActiveSessionFromIP("bob", "192.0.2.10") {
		t.Error("revoking Alice's session invalidated Bob's session")
	}
	if !manager.ConsumeRDPConnectGrant("bob", "192.0.2.10", "bob.desktop") {
		t.Error("revoking Alice's session invalidated Bob's grant")
	}

	freshToken := commitTestRDPGrant(t, manager, "alice")
	if freshToken == oldToken {
		t.Error("fresh login reused the revoked token")
	}
	if !manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop") {
		t.Error("fresh login and Connect did not authorize RDP")
	}
}

func TestConsumeRDPConnectGrantConcurrentConnections(t *testing.T) {
	manager := New()
	commitTestRDPGrant(t, manager, "alice")
	first, resume := consumeWithPausedSnapshot(t, manager)
	// A second connection consumes the grant while the first still holds an
	// enumeration in which that grant was unused.
	if !manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("second connection did not consume the available grant")
	}
	resume()
	if <-first {
		t.Error("both concurrent connections consumed the same grant")
	}
	if manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop") {
		t.Error("consumed grant still authorizes another connection")
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
			commitTestRDPGrant(t, manager, "alice")
			store, codec := manager.Store, manager.Codec
			tt.fail(manager)
			if manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop") {
				t.Error("RDP authorized despite failing to persist grant consumption")
			}
			manager.Store, manager.Codec = store, codec
			if !manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop") {
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
	oldToken := commitTestRDPGrant(t, manager, "alice")
	store := &pausedGrantCommitStore{
		Store:         manager.Store,
		IterableStore: manager.Store.(scs.IterableStore),
		entered:       make(chan struct{}),
		resume:        make(chan struct{}),
	}
	manager.Store = store
	resume := sync.OnceFunc(func() { close(store.resume) })
	rdpDone := make(chan struct{})
	logoutDone := make(chan struct{})
	logoutResult := make(chan error, 1)
	t.Cleanup(func() {
		resume()
		<-rdpDone
		<-logoutDone
	})
	go func() {
		defer close(rdpDone)
		manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop")
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
	if err := <-logoutResult; err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, exists, err := manager.Store.Find(oldToken); err != nil || exists {
		t.Errorf("pending RDP commit restored a logged-out session: exists=%v, err=%v", exists, err)
	}
	if manager.ConsumeRDPConnectGrant("alice", "192.0.2.10", "alice.desktop") {
		t.Error("logged-out session still authorizes RDP")
	}
}
