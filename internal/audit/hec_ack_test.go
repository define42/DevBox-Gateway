package audit

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHECForwarderKeepsUnacknowledgedBatchAcrossRestart(t *testing.T) {
	var confirmed atomic.Bool
	var submissions atomic.Int32
	polled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/ack" {
			submissions.Add(1)
			_, _ = io.WriteString(w, `{"code":0,"ackId":0}`)
			return
		}
		select {
		case polled <- struct{}{}:
		default:
		}
		if confirmed.Load() {
			_, _ = io.WriteString(w, `{"acks":{"0":true}}`)
			return
		}
		_, _ = io.WriteString(w, `{"acks":{"0":false}}`)
	}))
	t.Cleanup(server.Close)
	verifyAuditACKReplay(t, server.URL, &confirmed, &submissions, polled)
}

func verifyAuditACKReplay(t *testing.T, endpoint string, confirmed *atomic.Bool, submissions *atomic.Int32, polled <-chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	cfg := HECConfig{Endpoint: endpoint, Token: "token", ACKEnabled: true}
	first := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	first.shutdownTimeout = 20 * time.Millisecond
	writeRecord(t, first, `{"user":"ack-pending"}`)
	first.start()
	select {
	case <-polled:
	case <-time.After(3 * time.Second):
		t.Fatal("forwarder did not poll for acknowledgement")
	}
	want := pendingACKAudit(t, first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	if got := pendingACKAudit(t, second); !bytes.Equal(got, want) {
		t.Fatal("restart changed the unacknowledged envelope")
	}
	confirmed.Store(true)
	second.start()
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	third := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	pending, err := third.spool.ReadBatch(third.spool.Checkpoint(), 10, 1<<20)
	if err != nil || len(pending) != 0 {
		t.Fatalf("acknowledged batch not checkpointed: records=%v, error=%v", pending, err)
	}
	if got := submissions.Load(); got != 2 {
		t.Fatalf("submissions=%d, want initial attempt plus restart replay", got)
	}
}

func pendingACKAudit(t *testing.T, forwarder *hecForwarder) []byte {
	t.Helper()
	records, err := forwarder.spool.ReadBatch(forwarder.spool.Checkpoint(), 10, 1<<20)
	if err != nil || len(records) != 1 {
		t.Fatalf("unacknowledged audit not retained: records=%v, error=%v", records, err)
	}
	return records[0].Data
}
