package session

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/identity"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
)

const (
	benchmarkGrantUsername = "benchmark-grant-user"
	benchmarkGrantClientIP = "192.0.2.10"
	benchmarkGrantVMName   = "benchmark-grant-vm"
	benchmarkGrantToken    = "0123456789abcdef0123456789abcdef"
)

// discardCommitIterableStore keeps the benchmark fixture immutable while
// delegating session enumeration to the production in-memory store. A
// successful grant consumption still performs the real decode, delete, and
// encode work; only the final commit is discarded so every iteration is a hit.
type discardCommitIterableStore struct {
	scs.Store
	scs.IterableStore
}

func (*discardCommitIterableStore) Commit(_ string, _ []byte, _ time.Time) error {
	return nil
}

func BenchmarkManagerConsumeRDPConnectGrant(b *testing.B) {
	for _, sessionCount := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("sessions=%d", sessionCount), func(b *testing.B) {
			manager := newConsumeRDPConnectGrantBenchmarkManager(b, sessionCount)

			verifier := sha256.Sum256([]byte(benchmarkGrantToken))
			ref := manager.rdpTokens[verifier]
			b.ReportAllocs()
			for b.Loop() {
				if !manager.ConsumeRDPConnectGrant(
					benchmarkGrantToken,
					benchmarkGrantUsername,
					benchmarkGrantClientIP,
					benchmarkGrantVMName,
				) {
					b.Fatal("expected benchmark grant consumption to succeed")
				}
				// Restore the fixture's index entry alongside the discarded commit.
				manager.rdpTokens[verifier] = ref
			}
		})
	}
}

func newConsumeRDPConnectGrantBenchmarkManager(b *testing.B, sessionCount int) *Manager {
	b.Helper()

	registerSessionTypes()
	store := memstore.NewWithCleanupInterval(0)
	manager := &Manager{
		SessionManager: &scs.SessionManager{
			Store: store,
			Codec: scs.GobCodec{},
		},
	}

	createdAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	deadline := time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
	for i := range sessionCount {
		username := fmt.Sprintf("benchmark-user-%04d", i)
		grants := map[string]rdpConnectGrant(nil)
		if i == sessionCount-1 {
			username = benchmarkGrantUsername
			grants = map[string]rdpConnectGrant{benchmarkGrantVMName: {Verifier: sha256.Sum256([]byte(benchmarkGrantToken)), ExpiresAt: deadline}}
		}

		user, err := identity.New(username)
		if err != nil {
			b.Fatalf("create benchmark user %d: %v", i, err)
		}
		values := map[string]interface{}{
			sessionKey: sessionData{
				User:             user,
				CreatedAt:        createdAt,
				ClientIP:         benchmarkGrantClientIP,
				RDPConnectGrants: grants,
			},
		}
		encoded, err := manager.Codec.Encode(deadline, values)
		if err != nil {
			b.Fatalf("encode benchmark session %d: %v", i, err)
		}
		sessionToken := fmt.Sprintf("benchmark-token-%04d", i)
		if grants != nil {
			manager.indexRDPConnectGrant(sessionToken, values[sessionKey].(sessionData), benchmarkGrantVMName, grants[benchmarkGrantVMName], time.Now())
		}
		if err := store.Commit(sessionToken, encoded, deadline); err != nil {
			b.Fatalf("commit benchmark session %d: %v", i, err)
		}
	}

	manager.Store = &discardCommitIterableStore{
		Store:         store,
		IterableStore: store,
	}
	return manager
}
