package host

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/protocol"
)

// firstGapFailureSink holds the first gap publication until the test has tried
// every competing path, then rejects it. Later writes reach the ordinary sink.
type firstGapFailureSink struct {
	output.Sink
	entered  chan struct{}
	release  chan struct{}
	attempts atomic.Int64
	once     sync.Once
}

func (s *firstGapFailureSink) Write(ctx context.Context, envelope *output.Envelope) error {
	if envelope.Event == nil || envelope.Event.Type != typeStreamGap {
		return s.Sink.Write(ctx, envelope)
	}
	if s.attempts.Add(1) != 1 {
		return s.Sink.Write(ctx, envelope)
	}
	close(s.entered)
	select {
	case <-s.release:
		return errors.New("first gap publication rejected")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *firstGapFailureSink) unblock() {
	s.once.Do(func() { close(s.release) })
}

func TestFailedGapReportRecoversAfterGuestReboot(t *testing.T) {
	var replaced atomic.Bool
	h := newHarnessWithOptions(t, nil, func(options *Options) {
		options.Resolve = func(cid uint32) (config.VMMapping, bool) {
			if replaced.Load() {
				return config.VMMapping{CID: cid, Name: "replacement-vm", UUID: "replacement-id"}, true
			}
			return config.VMMapping{CID: cid, Name: "original-vm", UUID: "original-id"}, true
		}
	})
	h.srv.dedup.mu.Lock()
	h.srv.dedup.maxStreams = 1
	h.srv.dedup.mu.Unlock()
	h.sink.failInternal(typeStreamGap, true)
	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a", Hostname: "original-guest"})
	first.sendEvent(1, "boot-a")
	if ack := first.expectAck(); ack != 1 {
		t.Fatalf("initial ACK = %d, want 1", ack)
	}
	first.sendEvent(3, "boot-a")
	first.ping()
	first.close()

	// Neither this replacement VM nor its new boot can clear the old stream's
	// pin until its retained loss evidence has actually reached the sink.
	replaced.Store(true)
	second := h.dial(102, true)
	second.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-b", Hostname: "replacement-guest"})
	second.sendEvent(1, "boot-b")
	second.wantClosed()
	assertGapReportUnacknowledged(t, h, 1)
	if got := len(h.sink.events()); got != 2 {
		t.Fatalf("failed recovery admitted new guest data: %d events, want 2", got)
	}

	h.sink.failInternal(typeStreamGap, false)
	third := h.dial(102, true)
	third.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-b", Hostname: "replacement-guest"})
	third.sendEvent(1, "boot-b")
	if ack := third.expectAck(); ack != 1 {
		t.Fatalf("new boot ACK after output recovery = %d, want 1", ack)
	}
	assertOneDurableGap(t, h, 2, 2)
	for _, envelope := range h.sink.internals() {
		if envelope.Event.Type != typeStreamGap {
			continue
		}
		if envelope.Source.VM != "original-vm" || envelope.Source.UUID != "original-id" || envelope.Source.CID != 102 {
			t.Fatalf("retained gap acquired the replacement VM's attribution: %+v", envelope.Source)
		}
		if envelope.Event.Fields["boot_id"] != "boot-a" || envelope.Source.Reported == nil ||
			envelope.Source.Reported.BootID != "boot-a" || envelope.Source.Reported.Hostname != "original-guest" {
			t.Fatalf("retained gap acquired the replacement boot's claims: %+v", envelope)
		}
	}
}

func TestFailedGapReportRetriedBeforeAcknowledgement(t *testing.T) {
	h := newHarness(t, nil)
	h.sink.failInternal(typeStreamGap, true)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}
	g.sendEvent(3, "boot-a")
	g.sendEvent(4, "boot-a")
	g.ping()
	assertGapReportUnacknowledged(t, h, 1)
	if got := len(h.sink.events()); got != 3 {
		t.Fatalf("guest events written = %d, want 3 while gap report is failing", got)
	}

	h.sink.failInternal(typeStreamGap, false)
	g.sendEvent(3, "boot-a")
	if ack := g.expectAck(); ack != 4 {
		t.Fatalf("ACK after loss evidence retry = %d, want 4", ack)
	}
	assertOneDurableGap(t, h, 2, 2)
	if got := len(h.sink.events()); got != 3 {
		t.Fatalf("already durable guest event was written again: count=%d", got)
	}
}

func TestFailedGapReportSurvivesReconnect(t *testing.T) {
	h := newHarness(t, nil)
	h.sink.failInternal(typeStreamGap, true)
	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	first.sendEvent(1, "boot-a")
	if ack := first.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}
	first.sendEvent(3, "boot-a")
	first.ping()
	first.close()

	second := h.dial(102, true)
	ready := second.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a", FirstSequence: 1})
	if ready.ResumeFrom != 1 {
		t.Fatalf("READY crossed failed gap evidence: ResumeFrom=%d", ready.ResumeFrom)
	}
	second.ping()
	assertGapReportUnacknowledged(t, h, 1)
	h.sink.failInternal(typeStreamGap, false)
	second.sendEvent(3, "boot-a")
	if ack := second.expectAck(); ack != 3 {
		t.Fatalf("ACK after reconnect and report retry = %d, want 3", ack)
	}
	assertOneDurableGap(t, h, 2, 2)
}

func TestRecoveredEventFailureRemainsReplayableAcrossReconnect(t *testing.T) {
	h := newHarness(t, nil)
	h.sink.failInternal(typeStreamGap, true)
	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	first.sendEvent(1, "boot-a")
	if ack := first.expectAck(); ack != 1 {
		t.Fatalf("initial ACK = %d, want 1", ack)
	}

	// Sequence 3 reaches the event sink, but the report for the apparent gap at
	// sequence 2 does not. Sequence 2 then arrives, proving that it was delayed
	// rather than lost, but its own sink write fails.
	first.sendEvent(3, "boot-a")
	first.ping()
	h.sink.failInternal(typeStreamGap, false)
	h.sink.fail(2, true)
	first.sendEvent(2, "boot-a")
	first.ping()
	if resume := h.srv.dedup.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("ResumeFrom after failed recovery = %d, want 1", resume)
	}
	first.close()

	second := h.dial(102, true)
	ready := second.handshake(&protocol.Hello{
		AgentVersion:  "test",
		BootID:        "boot-a",
		FirstSequence: 2,
	})
	if ready.ResumeFrom != 1 {
		t.Fatalf("READY.ResumeFrom = %d, want 1 while sequence 2 remains replayable", ready.ResumeFrom)
	}

	// Once output recovers, the guest's retained copy must still reach the sink.
	h.sink.fail(2, false)
	second.sendEvent(2, "boot-a")
	if ack := second.expectAck(); ack != 3 {
		t.Fatalf("ACK after recovered write = %d, want 3", ack)
	}
	var sequences []uint64
	for _, envelope := range h.sink.events() {
		sequences = append(sequences, envelope.Event.Sequence)
	}
	if len(sequences) != 3 || sequences[0] != 1 || sequences[1] != 3 || sequences[2] != 2 {
		t.Fatalf("written sequences = %v, want [1 3 2]", sequences)
	}
	for _, envelope := range h.sink.internals() {
		if envelope.Event.Type == typeStreamGap {
			t.Fatalf("recovered sequence 2 was reported missing: %+v", envelope.Event.Fields)
		}
	}
}

func TestConcurrentGapPublishersShareOneClaimAndFailureRemainsRetryable(t *testing.T) {
	var blocking *firstGapFailureSink
	h := newHarnessWithOptions(t, nil, func(options *Options) {
		blocking = &firstGapFailureSink{
			Sink: options.Sink, entered: make(chan struct{}), release: make(chan struct{}),
		}
		options.Sink = blocking
	})
	t.Cleanup(blocking.unblock)
	accept(t, h.srv.dedup, testStream, 1)
	gap := h.srv.dedup.Check(testStream, 3)
	h.srv.dedup.Commit(testStream, 3)
	source := output.Source{VM: "vm", Reported: &output.Reported{BootID: "boot-a"}}
	first := &session{srv: h.srv, key: testStream, src: source, writeCtx: context.Background()}
	second := &session{srv: h.srv, key: testStream, src: source, writeCtx: context.Background()}

	done := make(chan struct{})
	go func() {
		first.reportGap(gap.GapFirst, gap.GapLast, gap.GapVersion, "first publisher")
		close(done)
	}()
	select {
	case <-blocking.entered:
	case <-time.After(testTimeout):
		t.Fatal("first gap publication did not reach the sink")
	}

	// Neither another live session nor retained-evidence recovery may bypass the
	// active claim while its sink result is unknown.
	second.reportGap(gap.GapFirst, gap.GapLast, gap.GapVersion, "second publisher")
	h.srv.retryPendingGaps(context.Background())
	if attempts := blocking.attempts.Load(); attempts != 1 {
		t.Fatalf("concurrent gap writes = %d, want one claimed write", attempts)
	}

	blocking.unblock()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("failed gap publication did not release its claim")
	}
	if resume := h.srv.dedup.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("failed publication advanced ResumeFrom to %d, want 1", resume)
	}

	// The failure releases ownership but preserves evidence and its source. One
	// retry can now publish it and release the durable event above the hole.
	h.srv.retryPendingGaps(context.Background())
	if attempts := blocking.attempts.Load(); attempts != 2 {
		t.Fatalf("gap writes after recovery = %d, want one failure and one retry", attempts)
	}
	if resume := h.srv.dedup.ResumeFrom(testStream); resume != 3 {
		t.Fatalf("successful retry left ResumeFrom at %d, want 3", resume)
	}
	assertOneDurableGap(t, h, 2, 2)
}

func TestFailedHelloGapReportWithZeroResumeRetried(t *testing.T) {
	h := newHarness(t, nil)
	h.sink.fail(1, true)
	h.sink.failInternal(typeStreamGap, true)
	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	first.sendEvent(1, "boot-a")
	first.ping()
	first.close()

	second := h.dial(102, true)
	ready := second.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a", FirstSequence: 3})
	if ready.ResumeFrom != 0 {
		t.Fatalf("READY acknowledged failed first event: ResumeFrom=%d", ready.ResumeFrom)
	}
	second.sendEvent(3, "boot-a")
	second.ping()
	assertGapReportUnacknowledged(t, h, 0)
	second.close()

	h.sink.failInternal(typeStreamGap, false)
	third := h.dial(102, true)
	ready = third.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a", FirstSequence: 3})
	if ready.ResumeFrom != 0 {
		t.Fatalf("READY moved before retrying HELLO loss evidence: ResumeFrom=%d", ready.ResumeFrom)
	}
	third.sendEvent(3, "boot-a")
	if ack := third.expectAck(); ack != 3 {
		t.Fatalf("ACK after accepted HELLO report = %d, want 3", ack)
	}
	assertOneDurableGap(t, h, 1, 2)
}

func assertGapReportUnacknowledged(t *testing.T, h *harness, wantResume uint64) {
	t.Helper()
	if resume := h.srv.dedup.ResumeFrom(testStream); resume != wantResume {
		t.Fatalf("unpersisted gap advanced ResumeFrom to %d, want %d", resume, wantResume)
	}
	for _, env := range h.sink.internals() {
		if env.Event.Type == typeStreamGap {
			t.Fatal("failure fixture unexpectedly persisted a gap report")
		}
	}
}

func assertOneDurableGap(t *testing.T, h *harness, first, last uint64) {
	t.Helper()
	count := 0
	for _, env := range h.sink.internals() {
		if env.Event.Type != typeStreamGap {
			continue
		}
		count++
		if env.Event.Fields["first_missing_sequence"] != first || env.Event.Fields["last_missing_sequence"] != last {
			t.Fatalf("gap fields = %v, want %d..%d", env.Event.Fields, first, last)
		}
	}
	if count != 1 {
		t.Fatalf("durable gap reports = %d, want one", count)
	}
}
