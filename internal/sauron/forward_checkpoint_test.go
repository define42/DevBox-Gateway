package sauron

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestForwardingRetriesCheckpointWhileSpoolIsFull(t *testing.T) {
	hec := newFakeHEC(t)
	dir := t.TempDir()
	record, err := json.Marshal(testEnvelope("alice-dev", 1))
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHECForwarding(hec.config("sauron"), dir, int64(len(record)+1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if err := h.spool.Append(record); err != nil {
		t.Fatal(err)
	}
	initial := h.position
	records := pendingRecords(t, h)
	blocker := blockCheckpoint(t, dir)
	if err := h.deliverAndAdvance(t.Context(), records); err == nil {
		t.Fatal("delivery did not report the checkpoint failure")
	}
	if h.position != initial || h.spool.checkpoint != initial || h.pendingCheckpoint == nil {
		t.Fatal("checkpoint failure lost the pending settlement or advanced the delivery position")
	}
	if err := h.spool.Append(record); !errors.Is(err, errSpoolFull) {
		t.Fatalf("Append() = %v, want the spool to remain full", err)
	}
	startCheckpointRetry(h)
	// Several persistence retries must not send the accepted event again.
	time.Sleep(30 * time.Millisecond)
	if requests, accepted := hec.snapshot(); requests != 1 || len(accepted) != 1 {
		t.Fatalf("checkpoint retries sent events again: %d requests, %d accepted", requests, len(accepted))
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	// No append wakes the forwarder: it must retry this checkpoint itself.
	waitForCheckpoint(t, h, records[0].end)
	write(t, h, "alice-dev", 2)
	assertSequences(t, hec.waitAccepted(t, 2), 1, 2)
}

func TestForwardingRetriesPartialSettlementBeforeRemainingEvents(t *testing.T) {
	hec := newFakeHEC(t)
	hec.set(func(events []map[string]any) hecReply {
		if len(events) > 1 {
			return hecInvalidFormat // Split the batch into individual events.
		}
		if sequenceOf(events[0]) == 2 {
			return hecBusy
		}
		return hecOK
	})
	dir := t.TempDir()
	h := openManualForwarding(t, hec.server.URL, dir)
	write(t, h, "alice-dev", 1, 2, 3)
	records := pendingRecords(t, h)
	initial := h.position
	blocker := blockCheckpoint(t, dir)
	if err := h.deliverAndAdvance(t.Context(), records); err == nil {
		t.Fatal("partially delivered batch unexpectedly succeeded")
	}
	if h.position != initial || h.pendingCheckpoint == nil || *h.pendingCheckpoint != records[0].end {
		t.Fatal("partial delivery did not preserve the accepted prefix for checkpoint retry")
	}
	assertSequences(t, hec.waitAccepted(t, 1), 1)
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	hec.set(nil)
	startCheckpointRetry(h)
	waitForCheckpoint(t, h, records[2].end)
	requests, accepted := hec.snapshot()
	assertSequences(t, accepted, 1, 2, 3)
	if requests != 4 {
		t.Fatalf("got %d requests, want rejected batch, accepted prefix, rejected second event and remaining batch", requests)
	}
}

func TestForwardingCheckpointFailureRetainsRecordsAcrossRestart(t *testing.T) {
	hec := newFakeHEC(t)
	dir := t.TempDir()
	h := openManualForwarding(t, hec.server.URL, dir)
	write(t, h, "alice-dev", 1)
	blocker := blockCheckpoint(t, dir)
	if err := h.deliverAndAdvance(context.Background(), pendingRecords(t, h)); err == nil {
		t.Fatal("delivery did not report the checkpoint failure")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	reopened := openManualForwarding(t, hec.server.URL, dir)
	if records := pendingRecords(t, reopened); len(records) != 1 {
		t.Fatalf("restart recovered %d events, want the unsettled event", len(records))
	}
}

func blockCheckpoint(t *testing.T, dir string) string {
	t.Helper()
	blocker := filepath.Join(dir, spoolCheckpointName+".tmp")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	return blocker
}

func startCheckpointRetry(h *hecForwarding) {
	h.retryInitial = time.Millisecond
	h.retryLimit = 5 * time.Millisecond
	h.start()
}

func waitForCheckpoint(t *testing.T, h *hecForwarding, want spoolPosition) {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		h.spool.mu.Lock()
		got := h.spool.checkpoint
		h.spool.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("checkpoint = %s, want %s", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}
