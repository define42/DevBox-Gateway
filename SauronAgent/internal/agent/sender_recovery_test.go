package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
	"github.com/define42/devbox-gateway/SauronAgent/internal/event"
	"github.com/define42/devbox-gateway/SauronAgent/internal/logging"
	"github.com/define42/devbox-gateway/SauronAgent/internal/metrics"
	"github.com/define42/devbox-gateway/SauronAgent/internal/protocol"
	"github.com/define42/devbox-gateway/SauronAgent/internal/spool"
)

func TestCheckpointFailureRestartPreservesFreshEvents(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, SyncOnWrite: true}
	original, err := spool.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { original.Close() })
	for n := uint64(1); n <= 3; n++ {
		if err := original.Append(numbered(n, "same-boot")); err != nil {
			t.Fatal(err)
		}
	}
	blocker := filepath.Join(dir, "checkpoint.tmp")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	// The collector holds 1..3, but the agent cannot persist that ACK.
	firstSender := newSender(senderOptions{
		cfg: config.DefaultAgent(), spool: original, log: logging.Discard(), metrics: &metrics.Agent{},
	})
	firstSender.applyAck(3)
	if original.PendingCount() != 3 {
		t.Fatal("failed checkpoint discarded the sequence recovery records")
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := spool.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recovered.Close() })
	if got := recovered.LastSequence(); got != 3 {
		t.Fatalf("recovered sequence = %d, want 3", got)
	}
	// Startup can produce events before READY arrives. They must be numbered
	// above the collector's previous ACK even within the same guest boot.
	seq := newSequencer(recovered.LastSequence()+1, "same-boot")
	fresh := &event.Event{Type: "fresh-never-delivered"}
	seq.assign(fresh)
	if err := recovered.Append(fresh); err != nil {
		t.Fatal(err)
	}
	s := newSender(senderOptions{
		cfg: config.DefaultAgent(), spool: recovered, log: logging.Discard(), metrics: &metrics.Agent{},
		resume: func(n uint64) { seq.advanceTo(n + 1) },
	})
	s.applyAck(3) // READY.resume_from from the collector that still holds 1..3.
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	// No new ACK is required after storage recovers: the sender's existing
	// reconciliation retries the remembered cumulative position.
	s.reconcile()
	retained, err := recovered.Next(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(retained) != 1 || retained[0].Sequence != 4 || retained[0].Type != fresh.Type {
		t.Fatalf("fresh event was not retained after READY: %+v", retained)
	}

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })
	result := make(chan error, 1)
	go func() {
		frame, receiveErr := protocol.NewConn(server, 4096).Receive(time.Second)
		if receiveErr == nil && (frame.Type != protocol.MsgEvent || frame.Sequence != 4) {
			t.Errorf("sent frame = type %v, sequence %d; want EVENT sequence 4", frame.Type, frame.Sequence)
		}
		result <- receiveErr
	}()
	var inflight []uint64
	var sentThrough uint64
	if sent, err := s.dispatch(protocol.NewConn(client, 4096), &inflight, &sentThrough); err != nil || sent != 1 {
		t.Fatalf("dispatch fresh event: sent=%d err=%v", sent, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	s.applyAck(4)
	if recovered.PendingCount() != 0 {
		t.Fatal("successfully delivered fresh event was not released")
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	empty, err := spool.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if got := empty.LastSequence(); got != 4 {
		t.Fatalf("empty spool recovered sequence = %d, want 4", got)
	}
}
