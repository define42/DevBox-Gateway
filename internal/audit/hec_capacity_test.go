package audit

import (
	"strings"
	"testing"
)

func TestHECSpoolPressureFailsReadinessBeforeRejectedWriteAndRecovers(t *testing.T) {
	f := newTestForwarderWithSpool(t, HECConfig{Endpoint: "http://127.0.0.1:1", Token: "token"}, t.TempDir(), 1024)
	f.host = "test-host"
	// Write enough to cross 90% without exhausting the hard limit. No delivery
	// worker runs: advancement below represents confirmed remote acceptance.
	writeRecord(t, f, `{"user":"`+strings.Repeat("a", 800)+`"}`)
	sink := &configuredSink{forwarder: f, health: &auditHealth{}}
	if sink.health.status() != nil {
		t.Fatal("accepted record was marked lost")
	}
	if sink.Readiness() == nil || sink.Admission() == nil {
		t.Fatal("spool pressure was hidden until a record failed")
	}
	batch, err := f.spool.ReadBatch(f.spool.Checkpoint(), 10, 2048)
	if err != nil || len(batch) != 1 {
		t.Fatalf("pending records: %v, %v", batch, err)
	}
	if err := f.spool.Acknowledge(batch[0].End); err != nil {
		t.Fatal(err)
	}
	if err := sink.Readiness(); err != nil {
		t.Fatalf("readiness did not recover without another write: %v", err)
	}
	if err := sink.Admission(); err != nil {
		t.Fatalf("admission did not recover: %v", err)
	}
}
