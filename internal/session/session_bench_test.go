package session

import (
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

			b.ReportAllocs()
			for b.Loop() {
				if !manager.ConsumeRDPConnectGrant(
					benchmarkGrantUsername,
					benchmarkGrantClientIP,
					benchmarkGrantVMName,
				) {
					b.Fatal("expected benchmark grant consumption to succeed")
				}
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
		grants := map[string]time.Time(nil)
		if i == sessionCount-1 {
			username = benchmarkGrantUsername
			grants = map[string]time.Time{benchmarkGrantVMName: deadline}
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
		if err := store.Commit(fmt.Sprintf("benchmark-token-%04d", i), encoded, deadline); err != nil {
			b.Fatalf("commit benchmark session %d: %v", i, err)
		}
	}

	manager.Store = &discardCommitIterableStore{
		Store:         store,
		IterableStore: store,
	}
	return manager
}
