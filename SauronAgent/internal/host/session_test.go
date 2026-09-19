package host

import (
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/protocol"
)

func TestFullExchangeAcknowledgesCumulatively(t *testing.T) {
	h := newHarness(t, func(c *config.Host) { c.Limits.AckInterval = 3 })
	g := h.dial(102, true)

	ready := g.handshake(&protocol.Hello{
		AgentVersion: "sauronagent/test",
		Hostname:     "transfer-vm-03",
		BootID:       "boot-a",
		MachineID:    "9d4a1f0c8b7e4d2a91f3c6b5a8e07d14",
		Kernel:       "6.12.9",
	})
	if ready.ProtocolVersion != protocol.Version {
		t.Fatalf("READY protocol_version = %d, want %d", ready.ProtocolVersion, protocol.Version)
	}
	if ready.ResumeFrom != 0 {
		t.Errorf("ResumeFrom = %d, want 0 for a stream the host has never seen", ready.ResumeFrom)
	}
	if ready.MaxPayloadSize != h.srv.maxPayload {
		t.Errorf("READY max_payload_size = %d, want the enforced limit %d",
			ready.MaxPayloadSize, h.srv.maxPayload)
	}

	for seq := uint64(1); seq <= 3; seq++ {
		g.sendEvent(seq, "boot-a")
	}
	// One acknowledgement for the batch, naming the highest sequence: ACK is
	// cumulative, so 3 covers 1 and 2.
	if ack := g.expectAck(); ack != 3 {
		t.Fatalf("ACK = %d, want a single cumulative 3", ack)
	}
	// A PONG proves the collector processed everything before it, so the absence
	// of a second ACK is a fact and not a race.
	if pong := g.ping(); pong.EchoUptime != 42 {
		t.Errorf("PONG echo = %d, want the uptime from the PING", pong.EchoUptime)
	}

	envs := h.sink.events()
	if len(envs) != 3 {
		t.Fatalf("sink received %d events, want 3", len(envs))
	}
	for i, env := range envs {
		if env.Event.Sequence != uint64(i+1) {
			t.Errorf("event %d has sequence %d", i, env.Event.Sequence)
		}
	}
	if got := h.counters.EventsOutput.Load(); got != 3 {
		t.Errorf("EventsOutput = %d, want 3", got)
	}
}

func TestAckMaxDelayReleasesASlowTrickle(t *testing.T) {
	h := newHarness(t, func(c *config.Host) {
		// Far more events than the test sends, so only the delay can trigger it.
		c.Limits.AckInterval = 1000
		c.Limits.AckMaxDelay = config.Duration(20 * time.Millisecond)
	})
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	g.sendEvent(7, "boot-a")
	if ack := g.expectAck(); ack != 7 {
		t.Fatalf("ACK = %d, want 7", ack)
	}
}

func TestEventSequenceMismatchIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	// The header says 9, the payload says 10. The host acknowledges and
	// deduplicates on the header, so a peer where the two disagree is either
	// broken or trying to have one event acknowledged under another's number.
	g.send(protocol.MsgEvent, 9, &protocol.EventMessage{Event: testEvent(10, "boot-a")})

	em := g.expectError()
	if em.Code != protocol.ErrCodeBadSequence || !em.Fatal {
		t.Fatalf("ERROR = %+v, want a fatal %s", em, protocol.ErrCodeBadSequence)
	}
	g.wantClosed()

	env := h.waitInternal(event.TypeProtocolViolation)
	if got := env.Event.Fields["code"]; got != string(protocol.ErrCodeBadSequence) {
		t.Errorf("violation code = %v, want %s", got, protocol.ErrCodeBadSequence)
	}
	if len(h.sink.events()) != 0 {
		t.Errorf("a rejected event was written to the sink")
	}
	if got := h.counters.FrameErrors.Load(); got != 1 {
		t.Errorf("FrameErrors = %d, want 1", got)
	}
}

func TestZeroSequenceIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	// Sequence 0 means "no sequence" in READY's resume_from and is never
	// assigned to an event.
	g.send(protocol.MsgEvent, 0, &protocol.EventMessage{Event: testEvent(0, "boot-a")})
	if em := g.expectError(); em.Code != protocol.ErrCodeBadSequence {
		t.Fatalf("ERROR = %+v, want %s", em, protocol.ErrCodeBadSequence)
	}
	g.wantClosed()
}

func TestNilEventIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	g.send(protocol.MsgEvent, 1, &protocol.EventMessage{Event: nil})
	if em := g.expectError(); em.Code != protocol.ErrCodeBadPayload {
		t.Fatalf("ERROR = %+v, want %s", em, protocol.ErrCodeBadPayload)
	}
	g.wantClosed()
}

func TestSinkFailureStopsAcknowledgement(t *testing.T) {
	h := newHarness(t, nil) // AckInterval 1: every event would normally be acked
	h.sink.fail(2, true)

	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}

	// Event 2 cannot be written. Event 3 can, but acknowledging it would
	// cumulatively acknowledge 2 as well, and the guest would delete the only
	// copy of an event the collector never wrote.
	g.sendEvent(2, "boot-a")
	g.sendEvent(3, "boot-a")
	g.ping() // barrier: everything above has been processed

	select {
	case f := <-g.frames:
		t.Fatalf("collector sent a %s after a failed write; nothing may be acknowledged past sequence 2", f.Type)
	default:
	}

	env := h.waitInternal(typeOutputFailed)
	if got := env.Event.Fields["sequence"]; got != uint64(2) {
		t.Errorf("output failure reported sequence %v, want 2", got)
	}

	// The guest retries. Now the hole closes and the acknowledgement jumps to 3,
	// which is exactly what "cumulative" is for.
	h.sink.fail(2, false)
	g.sendEvent(2, "boot-a")
	if ack := g.expectAck(); ack != 3 {
		t.Fatalf("ACK = %d, want 3 once the retry closed the hole", ack)
	}

	var seqs []uint64
	for _, e := range h.sink.events() {
		seqs = append(seqs, e.Event.Sequence)
	}
	if len(seqs) != 3 || seqs[0] != 1 || seqs[1] != 3 || seqs[2] != 2 {
		t.Fatalf("written sequences = %v, want [1 3 2]", seqs)
	}
	if got := h.counters.OutputErrors.Load(); got != 1 {
		t.Errorf("OutputErrors = %d, want 1", got)
	}
}

func TestDuplicateSuppressionAcrossReconnect(t *testing.T) {
	h := newHarness(t, func(c *config.Host) { c.Limits.AckInterval = 3 })

	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	for seq := uint64(1); seq <= 3; seq++ {
		first.sendEvent(seq, "boot-a")
	}
	if ack := first.expectAck(); ack != 3 {
		t.Fatalf("ACK = %d, want 3", ack)
	}
	first.close()

	// Same boot id: the agent re-sends what it had in flight. At-least-once
	// delivery makes that normal, and the host must not write it twice.
	second := h.dial(102, true)
	ready := second.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a", FirstSequence: 2})
	if ready.ResumeFrom != 3 {
		t.Fatalf("ResumeFrom = %d, want 3", ready.ResumeFrom)
	}
	for _, seq := range []uint64{2, 3, 4} {
		second.sendEvent(seq, "boot-a")
	}
	if ack := second.expectAck(); ack != 4 {
		t.Fatalf("ACK = %d, want 4: a suppressed duplicate is still acknowledgeable", ack)
	}
	if got := len(h.sink.events()); got != 4 {
		t.Fatalf("sink holds %d events, want 4: sequences 2 and 3 were replays", got)
	}
	if got := h.counters.EventsDuplicate.Load(); got != 2 {
		t.Errorf("EventsDuplicate = %d, want 2", got)
	}
	second.close()

	// A different boot id is a different stream: the guest rebooted and its
	// sequence numbers restarted, so nothing here is a duplicate.
	third := h.dial(102, true)
	ready = third.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-b"})
	if ready.ResumeFrom != 0 {
		t.Fatalf("ResumeFrom = %d, want 0 after a reboot", ready.ResumeFrom)
	}
	for seq := uint64(1); seq <= 3; seq++ {
		third.sendEvent(seq, "boot-b")
	}
	if ack := third.expectAck(); ack != 3 {
		t.Fatalf("ACK = %d, want 3", ack)
	}
	if got := len(h.sink.events()); got != 7 {
		t.Fatalf("sink holds %d events, want 7: a new boot id must not be suppressed", got)
	}
	if got := h.counters.EventsDuplicate.Load(); got != 2 {
		t.Errorf("EventsDuplicate = %d, want 2", got)
	}
}

func TestGapIsDetectedAndReported(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}
	g.sendEvent(2, "boot-a")
	if ack := g.expectAck(); ack != 2 {
		t.Fatalf("ACK = %d, want 2", ack)
	}

	// 3 and 4 never arrive. Either the agent reported the loss itself or nobody
	// did, and the second case is the finding.
	g.sendEvent(5, "boot-a")

	env := h.waitInternal(typeStreamGap)
	if got := env.Event.Fields["first_missing_sequence"]; got != uint64(3) {
		t.Errorf("first_missing_sequence = %v, want 3", got)
	}
	if got := env.Event.Fields["last_missing_sequence"]; got != uint64(4) {
		t.Errorf("last_missing_sequence = %v, want 4", got)
	}
	if got := env.Event.Fields["events_missing"]; got != uint64(2) {
		t.Errorf("events_missing = %v, want 2", got)
	}
	if env.Event.Severity != event.SeverityCritical {
		t.Errorf("severity = %q, want %q", env.Event.Severity, event.SeverityCritical)
	}
	if env.Source.VM != "transfer-vm-03" {
		t.Errorf("gap reported against VM %q", env.Source.VM)
	}

	// The acknowledgement moves past the reported hole. Refusing to would park
	// the guest's spool behind events that no longer exist anywhere, turning one
	// recorded loss into a second, unrecorded one.
	if ack := g.expectAck(); ack != 5 {
		t.Fatalf("ACK = %d, want 5 once the hole was reported", ack)
	}
}

func TestGapDoesNotAcknowledgePastAFailedWrite(t *testing.T) {
	h := newHarness(t, nil)
	h.sink.fail(2, true)

	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}
	g.sendEvent(2, "boot-a") // rejected by the sink; the guest still holds it
	g.sendEvent(3, "boot-a")
	// 4 and 5 are missing from the guest's own numbering.
	g.sendEvent(6, "boot-a")

	h.waitInternal(typeStreamGap)
	g.ping()
	select {
	case f := <-g.frames:
		t.Fatalf("collector sent a %s; sequence 2 was never written and must not be acknowledged", f.Type)
	default:
	}

	// The retry closes the only hole the collector is still waiting for; the
	// reported one it may pass.
	h.sink.fail(2, false)
	g.sendEvent(2, "boot-a")
	if ack := g.expectAck(); ack != 6 {
		t.Fatalf("ACK = %d, want 6", ack)
	}
}

func TestEnrichmentKeepsHostDataAndGuestClaimsApart(t *testing.T) {
	h := newHarness(t, nil)
	received := time.Date(2026, 9, 18, 18, 0, 0, 0, time.UTC)
	h.setNow(received)

	g := h.dial(102, true)
	// The guest claims to be a different machine. CID 102 is transfer-vm-03 and
	// nothing the guest says changes that.
	g.handshake(&protocol.Hello{
		AgentVersion: "sauronagent/9.9.9",
		Hostname:     "db-primary-01",
		BootID:       "boot-a",
		MachineID:    "deadbeef",
		Kernel:       "6.1.0-evil",
	})
	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}

	envs := h.sink.events()
	if len(envs) != 1 {
		t.Fatalf("got %d events, want 1", len(envs))
	}
	env := envs[0]

	if env.Source.VM != "transfer-vm-03" {
		t.Errorf("Source.VM = %q; a guest's hostname claim must not rename it", env.Source.VM)
	}
	if !env.Source.Known || env.Source.CID != 102 {
		t.Errorf("Source = %+v, want the mapped CID 102 marked known", env.Source)
	}
	if env.Source.Host != "hypervisor-test" {
		t.Errorf("Source.Host = %q, want the configured hypervisor name", env.Source.Host)
	}
	if env.Source.Environment != "production" || env.Source.SecurityDomain != "restricted" ||
		env.Source.VLAN != "310" || env.Source.Labels["owner"] != "data-team" {
		t.Errorf("trusted asset metadata was not attached: %+v", env.Source)
	}
	if env.Source.Reported == nil {
		t.Fatal("the guest's claims were dropped instead of recorded under Reported")
	}
	if env.Source.Reported.Hostname != "db-primary-01" ||
		env.Source.Reported.MachineID != "deadbeef" ||
		env.Source.Reported.BootID != "boot-a" ||
		env.Source.Reported.Kernel != "6.1.0-evil" ||
		env.Source.Reported.AgentVersion != "sauronagent/9.9.9" {
		t.Errorf("Reported = %+v, want the guest's own claims verbatim", env.Source.Reported)
	}
	if !env.ReceivedAt.Equal(received) {
		t.Errorf("ReceivedAt = %s, want the host clock %s", env.ReceivedAt, received)
	}
	if env.Event.Timestamp.Equal(received) {
		t.Error("ReceivedAt was taken from the guest's timestamp")
	}
}

func TestUnmappedCIDAcceptedAsUnknown(t *testing.T) {
	h := newHarness(t, func(c *config.Host) { c.Limits.AllowUnknownCIDs = true })

	g := h.dial(777, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", Hostname: "who-am-i", BootID: "boot-z"})
	g.sendEvent(1, "boot-z")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}

	envs := h.sink.events()
	if len(envs) != 1 {
		t.Fatalf("got %d events, want 1", len(envs))
	}
	src := envs[0].Source
	if src.Known {
		t.Error("an unmapped CID was recorded as known")
	}
	if src.CID != 777 || src.VM != "unknown-cid-777" {
		t.Errorf("Source = %+v, want cid 777 under a synthetic name", src)
	}
	if src.Host != "hypervisor-test" {
		t.Errorf("Source.Host = %q, want the hypervisor name even for an unknown guest", src.Host)
	}
}

func TestHandshakeTimeoutClosesASilentConnection(t *testing.T) {
	h := newHarness(t, func(c *config.Host) {
		c.Limits.HandshakeTimeout = config.Duration(30 * time.Millisecond)
	})

	g := h.dial(102, true)
	g.wantClosed() // never sends HELLO
	if len(h.sink.events()) != 0 {
		t.Error("a connection that never spoke produced events")
	}
}

func TestIdleTimeoutClosesASilentSession(t *testing.T) {
	h := newHarness(t, func(c *config.Host) {
		c.Limits.IdleTimeout = config.Duration(30 * time.Millisecond)
	})

	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	// A guest that sends nothing at all, not even a heartbeat, is gone.
	g.wantClosed()
}

func TestOversizedFrameIsRejected(t *testing.T) {
	h := newHarness(t, func(c *config.Host) { c.Limits.MaxPayloadSize = config.Size(1024) })

	g := h.dial(102, true)
	ready := g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	if ready.MaxPayloadSize != 1024 {
		t.Fatalf("READY max_payload_size = %d, want the host's 1024", ready.MaxPayloadSize)
	}

	// The guest ignores the announced limit and declares a 4 KiB payload. Only
	// the header is written: the host must reject the frame on the declared
	// length alone, without reserving a buffer for a payload that never comes.
	// The length field is the one place where a peer chooses the size of an
	// allocation on the other end.
	hdr := make([]byte, protocol.HeaderSize)
	if err := protocol.MarshalHeader(hdr, protocol.Header{
		Version:    protocol.Version,
		Type:       protocol.MsgEvent,
		Sequence:   1,
		PayloadLen: 4096,
	}); err != nil {
		t.Fatalf("marshalling header: %v", err)
	}
	if _, err := g.raw.Write(hdr); err != nil {
		t.Fatalf("writing header: %v", err)
	}

	em := g.expectError()
	if em.Code != protocol.ErrCodeBadFrame || !em.Fatal {
		t.Fatalf("ERROR = %+v, want a fatal %s", em, protocol.ErrCodeBadFrame)
	}
	g.wantClosed()
	h.waitInternal(event.TypeProtocolViolation)
	if len(h.sink.events()) != 0 {
		t.Error("an oversized frame produced an event")
	}
}

func TestMalformedFrameIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	// A header that is not a Sauron frame at all: the stream is no longer
	// parseable, so the connection cannot be kept.
	junk := make([]byte, protocol.HeaderSize)
	copy(junk, "XXXX")
	if _, err := g.raw.Write(junk); err != nil {
		t.Fatalf("writing junk: %v", err)
	}

	em := g.expectError()
	if em.Code != protocol.ErrCodeBadFrame {
		t.Fatalf("ERROR = %+v, want %s", em, protocol.ErrCodeBadFrame)
	}
	g.wantClosed()

	env := h.waitInternal(event.TypeProtocolViolation)
	if got, _ := env.Event.Fields["cid"].(uint32); got != 102 {
		t.Errorf("violation reported cid %v, want 102", env.Event.Fields["cid"])
	}
}

func TestUnexpectedMessageTypesAreRejected(t *testing.T) {
	cases := []struct {
		name string
		send func(*guest)
	}{
		{"ACK from a guest", func(g *guest) { g.send(protocol.MsgAck, 0, &protocol.Ack{Sequence: 1}) }},
		{"READY from a guest", func(g *guest) {
			g.send(protocol.MsgReady, 0, &protocol.Ready{ProtocolVersion: protocol.Version})
		}},
		{"PONG from a guest", func(g *guest) { g.send(protocol.MsgPong, 0, &protocol.Pong{}) }},
		{"a second HELLO", func(g *guest) {
			g.send(protocol.MsgHello, 0, &protocol.Hello{ProtocolVersion: protocol.Version})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			g := h.dial(102, true)
			g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

			tc.send(g)
			em := g.expectError()
			if em.Code != protocol.ErrCodeUnexpectedType || !em.Fatal {
				t.Fatalf("ERROR = %+v, want a fatal %s", em, protocol.ErrCodeUnexpectedType)
			}
			g.wantClosed()
			h.waitInternal(event.TypeProtocolViolation)
		})
	}
}

func TestEventBeforeReadyIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)

	g.send(protocol.MsgEvent, 1, &protocol.EventMessage{Event: testEvent(1, "boot-a")})
	em := g.expectError()
	if em.Code != protocol.ErrCodeUnexpectedType {
		t.Fatalf("ERROR = %+v, want %s", em, protocol.ErrCodeUnexpectedType)
	}
	g.wantClosed()
}

func TestUnsupportedProtocolVersionIsRejected(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)

	g.send(protocol.MsgHello, 0, &protocol.Hello{ProtocolVersion: 99, AgentVersion: "from-the-future"})
	em := g.expectError()
	if em.Code != protocol.ErrCodeBadPayload || !em.Fatal {
		t.Fatalf("ERROR = %+v, want a fatal %s", em, protocol.ErrCodeBadPayload)
	}
	g.wantClosed()
}

func TestShutdownEndsTheSessionOrderly(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}

	g.send(protocol.MsgShutdown, 0, &protocol.Shutdown{Reason: "systemd stop", LastSequence: 1})
	g.wantClosed()

	// An orderly stop is not a protocol violation and not a stream loss.
	for _, env := range h.sink.internals() {
		if env.Event.Type == event.TypeProtocolViolation {
			t.Fatalf("an orderly SHUTDOWN was reported as %s", env.Event.Type)
		}
	}
	if got := h.counters.FrameErrors.Load(); got != 0 {
		t.Errorf("FrameErrors = %d, want 0", got)
	}
}

func TestHelloFirstSequenceAboveResumeReportsAGap(t *testing.T) {
	h := newHarness(t, nil)

	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	first.sendEvent(1, "boot-a")
	if ack := first.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}
	first.close()

	// The agent comes back having already discarded 2..9: they are gone from
	// both ends, which is only visible here, at the handshake.
	second := h.dial(102, true)
	ready := second.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a", FirstSequence: 10})
	if ready.ResumeFrom != 1 {
		t.Fatalf("ResumeFrom = %d, want 1", ready.ResumeFrom)
	}

	env := h.waitInternal(typeStreamGap)
	if got := env.Event.Fields["first_missing_sequence"]; got != uint64(2) {
		t.Errorf("first_missing_sequence = %v, want 2", got)
	}
	if got := env.Event.Fields["last_missing_sequence"]; got != uint64(9) {
		t.Errorf("last_missing_sequence = %v, want 9", got)
	}

	// The reported hole does not stall the stream, and it is not reported twice.
	second.sendEvent(10, "boot-a")
	if ack := second.expectAck(); ack != 10 {
		t.Fatalf("ACK = %d, want 10", ack)
	}
	gaps := 0
	for _, e := range h.sink.internals() {
		if e.Event.Type == typeStreamGap {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("reported %d gaps, want exactly 1", gaps)
	}
}
