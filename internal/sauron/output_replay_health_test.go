package sauron

import (
	"errors"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

func TestOutputHealthSmallReportCannotMaskFullGuestSpool(t *testing.T) {
	store := openTestSpool(t, t.TempDir(), 1<<20)
	observed := &observedSink{Sink: &hecForwarding{spool: store}}
	original := healthGuestEnvelope("vm-a", 1)
	original.Event.Command = strings.Repeat("x", 600<<10)
	if err := observed.Write(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	original.Event.Sequence = 2
	if err := observed.Write(t.Context(), original); !errors.Is(err, errSpoolFull) {
		t.Fatalf("guest rejection = %v, want full spool", err)
	}
	report := &collector.Envelope{Source: original.Source, Event: &collector.Event{Type: "sauron.output.failed"}}
	if err := observed.Write(t.Context(), report); err != nil {
		t.Fatal(err)
	}
	if observed.readiness() == nil {
		t.Fatal("small diagnostic report hid an unaccepted guest event")
	}
	if err := observed.Write(t.Context(), original); !errors.Is(err, errSpoolFull) {
		t.Fatalf("rejected guest event unexpectedly fits: %v", err)
	}
}

func TestOutputHealthRequiresExactRejectedEventReplay(t *testing.T) {
	sink := &healthTestSink{writeErr: errors.New("full output")}
	observed := &observedSink{Sink: sink}
	rejected := healthGuestEnvelope("vm-a", 2)
	if err := observed.Write(t.Context(), rejected); err == nil {
		t.Fatal("expected output failure")
	}
	sink.writeErr = nil
	for _, unrelated := range []*collector.Envelope{
		healthGuestEnvelope("vm-b", 2), // Another guest cannot cover the gap.
		healthGuestEnvelope("vm-a", 3), // Nor can a later sequence in this stream.
		{Source: rejected.Source, Event: &collector.Event{Type: "sauron.output.failed"}},
	} {
		if err := observed.Write(t.Context(), unrelated); err != nil {
			t.Fatal(err)
		}
		if observed.readiness() == nil {
			t.Fatal("unrelated event cleared a rejected guest event")
		}
	}
	// The same durable record may be replayed after a VM reboot changes its
	// CID and HELLO boot ID. Its trusted UUID and original event identity stay.
	rejected.Source.CID = 500
	rejected.Source.Reported = &collector.Reported{BootID: "new-connection-boot"}
	if err := observed.Write(t.Context(), rejected); err != nil || observed.readiness() != nil {
		t.Fatalf("exact accepted replay did not recover readiness: %v", err)
	}
}

func TestOutputHealthUnknownGuestFailureIsNotMaskedByNewAttribution(t *testing.T) {
	sink := &healthTestSink{writeErr: errors.New("output unavailable")}
	observed := &observedSink{Sink: sink}
	unknown := healthGuestEnvelope("", 1)
	unknown.Source.Known = false
	if err := observed.Write(t.Context(), unknown); err == nil {
		t.Fatal("expected output failure")
	}
	sink.writeErr = nil
	known := healthGuestEnvelope("vm-a", 1)
	if err := observed.Write(t.Context(), known); err != nil {
		t.Fatal(err)
	}
	if observed.readiness() == nil {
		t.Fatal("changed identity cleared an unattributed rejection")
	}
	if err := observed.Write(t.Context(), unknown); err != nil || observed.readiness() != nil {
		t.Fatalf("matching unattributed replay did not recover: %v", err)
	}
}

func TestOutputHealthRejectedGuestTrackingIsBoundedAndOverflowIsSticky(t *testing.T) {
	sink := &healthTestSink{writeErr: errors.New("output unavailable")}
	observed := &observedSink{Sink: sink}
	for seq := uint64(1); seq <= maxRejectedGuestEvents+1; seq++ {
		if err := observed.Write(t.Context(), healthGuestEnvelope("vm-a", seq)); err == nil {
			t.Fatal("expected output failure")
		}
	}
	if len(observed.rejected) != maxRejectedGuestEvents {
		t.Fatalf("rejection tracking grew beyond its bound: %d", len(observed.rejected))
	}
	sink.writeErr = nil
	for seq := uint64(1); seq <= maxRejectedGuestEvents+1; seq++ {
		if err := observed.Write(t.Context(), healthGuestEnvelope("vm-a", seq)); err != nil {
			t.Fatal(err)
		}
	}
	if len(observed.rejected) != 0 || observed.readiness() == nil {
		t.Fatal("overflow must remain observable after tracked failures drain")
	}
}

func healthGuestEnvelope(uuid string, sequence uint64) *collector.Envelope {
	return &collector.Envelope{
		Source: collector.Source{CID: 42, VM: "desktop", UUID: uuid, Known: true},
		Event:  &collector.Event{Sequence: sequence, BootID: "original-boot", Type: "process.exec"},
	}
}
