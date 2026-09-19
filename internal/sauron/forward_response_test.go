package sauron

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

func TestForwardingRetainsUnconfirmedEventsAcrossRestart(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "redirect", status: http.StatusFound, body: `<html>Please sign in</html>`},
		{name: "malformed success", status: http.StatusOK, body: `{"code":0`},
		{name: "missing code", status: http.StatusOK, body: `{"text":"Success"}`},
		{name: "nonzero code", status: http.StatusOK, body: `{"text":"Invalid data format","code":6}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var accept atomic.Bool
			accept.Store(true)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if accept.Load() || r.URL.Path == "/login" {
					_, _ = io.WriteString(w, `{"code":0}`)
					return
				}
				w.Header().Set("Location", "/login")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			testForwardingConfirmation(t, server.URL, &accept)
		})
	}
}

func testForwardingConfirmation(t *testing.T, endpoint string, accept *atomic.Bool) {
	t.Helper()
	dir := t.TempDir()
	forwarding := openManualForwarding(t, endpoint, dir)
	write(t, forwarding, "alice-dev", 1)
	if err := forwarding.deliverAndAdvance(context.Background(), pendingRecords(t, forwarding)); err != nil {
		t.Fatal(err)
	}
	confirmed := forwarding.position
	write(t, forwarding, "alice-dev", 2)
	records := pendingRecords(t, forwarding)
	accept.Store(false)
	if err := forwarding.deliverAndAdvance(context.Background(), records); err == nil {
		t.Fatal("delivery succeeded without HEC confirmation")
	}
	if forwarding.position != confirmed || forwarding.spool.loadCheckpoint() != confirmed {
		t.Fatal("unconfirmed delivery advanced the memory or disk checkpoint")
	}
	if err := forwarding.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openManualForwarding(t, endpoint, dir)
	pending := pendingRecords(t, reopened)
	if len(pending) != 1 || !bytes.Equal(pending[0].data, records[0].data) {
		t.Fatalf("restart did not preserve the unconfirmed event: %v", pending)
	}
	accept.Store(true)
	if err := reopened.deliverAndAdvance(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if reopened.position != pending[0].end || reopened.spool.loadCheckpoint() != pending[0].end {
		t.Fatal("confirmed delivery did not persist the new checkpoint")
	}
	if got := pendingRecords(t, reopened); len(got) != 0 {
		t.Fatalf("confirmed delivery left %d pending events", len(got))
	}
}

func openManualForwarding(t *testing.T, endpoint, dir string) *hecForwarding {
	t.Helper()
	forwarding, err := newHECForwarding(splunkhec.Config{Endpoint: endpoint, Token: "test-token"}, dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarding.Close() })
	return forwarding
}

func pendingRecords(t *testing.T, forwarding *hecForwarding) []spoolRecord {
	t.Helper()
	records, err := forwarding.spool.readBatch(forwarding.position, hecBatchSize, hecBatchBytes)
	if err != nil {
		t.Fatal(err)
	}
	return records
}
