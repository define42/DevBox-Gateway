package sauron

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

func TestForwardingKeepsUnacknowledgedEventsAcrossRestart(t *testing.T) {
	var confirmed atomic.Bool
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/ack" {
			_, _ = io.WriteString(w, `{"code":0,"ackId":0}`)
			return
		}
		if confirmed.Load() {
			_, _ = io.WriteString(w, `{"acks":{"0":true}}`)
			return
		}
		_, _ = io.WriteString(w, `{"acks":{"0":false}}`)
		cancel()
	}))
	t.Cleanup(server.Close)
	verifyGuestACKReplay(ctx, t, server.URL, &confirmed)
}

func verifyGuestACKReplay(ctx context.Context, t *testing.T, endpoint string, confirmed *atomic.Bool) {
	t.Helper()
	dir := t.TempDir()
	first := openACKForwarding(t, endpoint, dir)
	write(t, first, "alice-dev", 1)
	records := pendingRecords(t, first)
	checkpoint := first.position
	if err := first.deliverAndAdvance(ctx, records); !errors.Is(err, context.Canceled) {
		t.Fatalf("delivery without ACK = %v, want cancellation", err)
	}
	if first.position != checkpoint || first.spool.loadCheckpoint() != checkpoint {
		t.Fatal("unacknowledged batch advanced the guest spool checkpoint")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := openACKForwarding(t, endpoint, dir)
	replayed := pendingRecords(t, second)
	if len(replayed) != 1 || !bytes.Equal(replayed[0].data, records[0].data) {
		t.Fatal("restart lost or changed the unacknowledged guest event")
	}
	confirmed.Store(true)
	if err := second.deliverAndAdvance(t.Context(), replayed); err != nil {
		t.Fatal(err)
	}
	if len(pendingRecords(t, second)) != 0 || second.spool.loadCheckpoint() != replayed[0].end {
		t.Fatal("acknowledged guest event did not advance the durable checkpoint")
	}
}

func openACKForwarding(t *testing.T, endpoint, dir string) *hecForwarding {
	t.Helper()
	forwarder, err := newHECForwarding(splunkhec.Config{Endpoint: endpoint, Token: "test-token", ACKEnabled: true}, dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })
	return forwarder
}
