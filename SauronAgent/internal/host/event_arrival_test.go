package host

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
	"github.com/define42/devbox-gateway/SauronAgent/internal/protocol"
)

// heldArrivalGapSink pauses a missing-sequence report after the collector has
// claimed it, allowing the original event to arrive before that report finishes.
type heldArrivalGapSink struct {
	output.Sink

	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *heldArrivalGapSink) Write(ctx context.Context, env *output.Envelope) error {
	if env.Event != nil && env.Event.Type == typeStreamGap {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Sink.Write(ctx, env)
}

func TestReceivedEventSurvivesConcurrentGapPublication(t *testing.T) {
	for _, failArrival := range []bool{false, true} {
		name := "accepted arrival"
		if failArrival {
			name = "rejected arrival remains replayable"
		}
		t.Run(name, func(t *testing.T) { testReceivedEventAgainstGap(t, failArrival) })
	}
}

func testReceivedEventAgainstGap(t *testing.T, failArrival bool) {
	t.Helper()
	var sink *heldArrivalGapSink
	h := newHarnessWithOptions(t, nil, func(opts *Options) {
		sink = &heldArrivalGapSink{
			Sink: opts.Sink, entered: make(chan struct{}), release: make(chan struct{}),
		}
		opts.Sink = sink
	})
	release := sync.OnceFunc(func() { close(sink.release) })
	t.Cleanup(release)
	first := h.dial(102, true)
	first.handshake(&protocol.Hello{BootID: "boot-a"})
	first.sendEvent(1, "boot-a")
	if ack := first.expectAck(); ack != 1 {
		t.Fatalf("initial ACK = %d, want 1", ack)
	}
	second := h.dial(102, true)
	second.handshake(&protocol.Hello{BootID: "boot-a"})
	// READY precedes replay checks; finish the handshake before creating the gap.
	second.ping()
	first.sendEvent(3, "boot-a")
	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("gap report did not reach the output")
	}
	h.sink.fail(2, failArrival)
	second.sendEvent(2, "boot-a")
	waitArrivalAtWriteGate(t, h.srv.dedup)
	release()
	if failArrival {
		// The heartbeat is a barrier after the rejected write. If the gap
		// wrongly accounted for sequence 2, an ACK arrives here instead.
		second.ping()
		if resume := h.srv.dedup.ResumeFrom(testStream); resume != 1 {
			t.Fatalf("rejected original advanced ResumeFrom to %d, want 1", resume)
		}
		h.sink.fail(2, false)
		second.sendEvent(2, "boot-a")
	}
	if ack := second.expectAck(); ack != 3 {
		t.Fatalf("accepted original ACK = %d, want 3", ack)
	}
	count := 0
	for _, env := range h.sink.events() {
		if env.Event.Sequence == 2 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("original sequence 2 reached output %d times, want once before its ACK", count)
	}
}

func waitArrivalAtWriteGate(t *testing.T, d *dedup) {
	t.Helper()
	deadline := time.NewTimer(testTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		d.mu.Lock()
		gate := d.writes["peer:cid:102"]
		waiting := gate != nil && gate.refs == 2
		d.mu.Unlock()
		if waiting {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("received original did not reach the event write gate")
		}
	}
}

type heldArrivalEventSink struct {
	output.Sink

	entered chan struct{}
	release chan struct{}
	held    atomic.Bool
}

func (s *heldArrivalEventSink) Write(ctx context.Context, env *output.Envelope) error {
	if env.Event != nil && env.Event.Sequence == 2 && s.held.CompareAndSwap(false, true) {
		close(s.entered)
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Sink.Write(ctx, env)
}

func TestHelloCannotReportAnInflightOriginalMissing(t *testing.T) {
	var sink *heldArrivalEventSink
	h := newHarnessWithOptions(t, nil, func(opts *Options) {
		sink = &heldArrivalEventSink{
			Sink: opts.Sink, entered: make(chan struct{}), release: make(chan struct{}),
		}
		opts.Sink = sink
	})
	release := sync.OnceFunc(func() { close(sink.release) })
	t.Cleanup(release)
	first := h.dial(102, true)
	first.handshake(&protocol.Hello{BootID: "boot-a"})
	first.sendEvent(1, "boot-a")
	if ack := first.expectAck(); ack != 1 {
		t.Fatalf("initial ACK = %d, want 1", ack)
	}
	h.sink.fail(2, true)
	first.sendEvent(2, "boot-a")
	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("original event did not reach output")
	}
	second := h.dial(102, true)
	second.handshake(&protocol.Hello{BootID: "boot-a", FirstSequence: 4})
	second.ping()
	if resume := h.srv.dedup.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("HELLO advanced ResumeFrom to %d while original sequence 2 was still writing", resume)
	}
	release()
	first.ping()
	if resume := h.srv.dedup.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("rejected original advanced ResumeFrom to %d, want 1", resume)
	}
	h.sink.fail(2, false)
	first.sendEvent(2, "boot-a")
	if ack := first.expectAck(); ack != 3 {
		t.Fatalf("accepted replay ACK = %d, want 3", ack)
	}
	if events := h.sink.events(); len(events) != 2 || events[1].Event.Sequence != 2 {
		t.Fatalf("original was not preserved for output after concurrent HELLO: %+v", events)
	}
}

func TestInflightOriginalPinsDeduplicationStream(t *testing.T) {
	var sink *heldArrivalEventSink
	h := newHarnessWithOptions(t, nil, func(opts *Options) {
		sink = &heldArrivalEventSink{
			Sink: opts.Sink, entered: make(chan struct{}), release: make(chan struct{}),
		}
		opts.Sink = sink
	})
	release := sync.OnceFunc(func() { close(sink.release) })
	t.Cleanup(release)
	h.srv.dedup.mu.Lock()
	h.srv.dedup.maxStreams = 1
	h.srv.dedup.mu.Unlock()
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{BootID: "boot-a"})
	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("initial ACK = %d, want 1", ack)
	}
	g.sendEvent(2, "boot-a")
	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("original event did not reach output")
	}
	other := streamKey{peer: "cid:103", boot: "boot-b"}
	if res := h.srv.dedup.Check(other, 1); !res.Blocked {
		t.Fatal("another stream evicted the original while its output was pending")
	}
	release()
	if ack := g.expectAck(); ack != 2 {
		t.Fatalf("accepted original ACK = %d, want 2", ack)
	}
	g.ping()
	if res := h.srv.dedup.Check(other, 1); res.Blocked {
		t.Fatal("completed original retained its deduplication stream reservation")
	}
}
