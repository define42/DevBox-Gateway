package host

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

func TestEventWriteGateSerializesPeerAndTrustedVM(t *testing.T) {
	for _, tc := range []struct {
		name string
		cid  uint32
		uuid string
	}{
		{name: "same peer with another boot or identity", cid: 7, uuid: "other-vm"},
		{name: "same VM after CID reassignment", cid: 8, uuid: "vm-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newDedup(64, 10)
			first := writeGateSession(t, d, 7, "vm-a")
			unlock, err := first.lockEventWrite()
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			second := writeGateSession(t, d, tc.cid, tc.uuid)
			second.writeTimeout = 10 * time.Millisecond
			if release, err := second.lockEventWrite(); !errors.Is(err, context.DeadlineExceeded) {
				if release != nil {
					release()
				}
				t.Fatalf("concurrent acceptance was not bounded: %v", err)
			}
			// A blocked guest must not stall a different VM.
			other := writeGateSession(t, d, 9, "vm-b")
			release, err := other.lockEventWrite()
			if err != nil {
				t.Fatal(err)
			}
			release()
			d.mu.Lock()
			defer d.mu.Unlock()
			if len(d.writes) != 2 {
				t.Fatalf("canceled waiter leaked gates: %d", len(d.writes))
			}
		})
	}
}

func writeGateSession(t *testing.T, d *dedup, cid uint32, uuid string) *session {
	t.Helper()
	return &session{
		srv: &Server{dedup: d}, peer: peer{cid: cid, vsock: true},
		src: output.Source{Known: true, UUID: uuid}, writeCtx: t.Context(), writeTimeout: testTimeout,
	}
}

func TestWriteGateHandsOffWithoutOverlappingOrRetainingIdleKeys(t *testing.T) {
	d := newDedup(64, 10)
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	start := make(chan struct{})
	var workers sync.WaitGroup
	var active, overlaps, completed atomic.Int32
	for range 100 {
		workers.Go(func() {
			<-start
			for range 10 {
				unlock, err := d.lockWrite(ctx, "peer:test")
				if err != nil {
					return
				}
				if active.Add(1) != 1 {
					overlaps.Add(1)
				}
				active.Add(-1)
				completed.Add(1)
				unlock()
			}
		})
	}
	close(start)
	workers.Wait()
	if overlaps.Load() != 0 || completed.Load() != 1000 {
		t.Fatalf("overlapping writes = %d, completed = %d", overlaps.Load(), completed.Load())
	}
	if len(d.writes) != 0 {
		t.Fatalf("idle gates retained = %d", len(d.writes))
	}
	cancel()
	if unlock, err := d.lockWrite(ctx, "peer:canceled"); !errors.Is(err, context.Canceled) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("canceled acquisition = %v", err)
	}
}
