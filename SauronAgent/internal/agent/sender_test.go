package agent

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/protocol"
	"github.com/define42/SauronAgent/internal/spool"
)

// TestMaxUnackedCapsOutstanding checks the flow-control bound. Without it a
// host that accepts frames and never acknowledges would pull the agent's whole
// spool onto the wire, and the events would then have to be sent a second time
// because none of them was ever released.
func TestMaxUnackedCapsOutstanding(t *testing.T) {
	c := newCollector(t, collectorOptions{})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	cfg.Transport.MaxUnacked = 4
	// Long enough that the acknowledgement timeout cannot be what stops the
	// sender: this test is about the cap and nothing else.
	cfg.Transport.AckTimeout = config.Duration(time.Minute)
	h := startAgent(t, cfg)

	for i := uint64(1); i <= 20; i++ {
		h.src.exec(t, i, "/usr/bin/capped", "-c")
	}
	waitEvents(t, c, 4)

	evs := c.events()
	if len(evs) > cfg.Transport.MaxUnacked {
		t.Fatalf("%d events were outstanding at once, above max_unacked %d",
			len(evs), cfg.Transport.MaxUnacked)
	}
	for i, r := range evs {
		if r.acksBefore != 0 {
			t.Fatalf("event %d arrived after %d acknowledgements; the test acknowledged nothing yet",
				i, r.acksBefore)
		}
	}

	// One acknowledgement releases exactly one slot, and the next event may
	// only appear after it.
	c.ack(evs[0].headerSeq)
	waitEvents(t, c, 5)
	fifth := c.events()[4]
	if fifth.acksBefore == 0 {
		t.Error("the fifth event went out before any acknowledgement: max_unacked was not enforced")
	}

	c.setAutoAck(true)
	c.ack(assertHighest(t, c))
	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestAckTimeoutForcesReconnect covers the host that reads happily and never
// acknowledges. It looks healthy from the guest -- bytes keep leaving -- while
// nothing is ever released, so the sender has to give up on the connection.
func TestAckTimeoutForcesReconnect(t *testing.T) {
	c := newCollector(t, collectorOptions{})
	// No spool: this also exercises the in-memory backlog's replay, since
	// everything unacknowledged has to be sent again on the new connection.
	cfg := testConfig(c.addr)
	cfg.Transport.AckTimeout = config.Duration(150 * time.Millisecond)
	h := startAgent(t, cfg)

	h.src.exec(t, 1, "/usr/bin/stalled", "-s")
	waitEvents(t, c, 1)

	// The counter is what an operator sees, so it is part of the assertion:
	// the reconnect is only complete once the new session has been accepted.
	waitFor(t, "the stalled connection to be abandoned and remade", func() bool {
		return c.connCount() >= 2 && h.metrics.VSOCKReconnects.Load() > 0
	})

	// Once the host starts acknowledging, everything it never released is
	// delivered again and the stream catches up.
	c.setAutoAck(true)
	waitFor(t, "the events to be delivered after the reconnect", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 1 && c.count() >= 3
	})
	waitType(t, c, event.TypeTransportDisconnect)

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestResumeFromSkipsReplay checks READY.resume_from. It is an optimisation --
// the host deduplicates either way -- but it is also the host stating that it
// holds those events durably, so the spool may release them.
func TestResumeFromSkipsReplay(t *testing.T) {
	c := newCollector(t, collectorOptions{dropAfter: 3, resumeFromHighest: true})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	for i := uint64(1); i <= 4; i++ {
		h.src.exec(t, i, "/usr/bin/resume", "-r")
	}
	waitFor(t, "the connection to be dropped and remade", func() bool { return c.connCount() >= 2 })

	firstConn := c.events()
	if len(firstConn) == 0 {
		t.Fatal("nothing arrived on the first connection")
	}
	resumeFrom := firstConn[len(firstConn)-1].headerSeq

	c.setAutoAck(true)
	waitFor(t, "every collected event to be delivered", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 4
	})

	for seq, n := range c.delivered() {
		if n > 1 {
			t.Errorf("sequence %d was delivered %d times although the host resumed from %d",
				seq, n, resumeFrom)
		}
	}
	waitFor(t, "the spool to release what resume_from covered", func() bool {
		return h.agent.spool.FirstUnacked() > resumeFrom
	})

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	assertNoGaps(t, c)
	c.checkClean(t)
}

// TestProtocolViolationIsReported points the agent at a host that answers the
// handshake with the wrong frame. That is a statement about the peer, not about
// the link, and it has to reach the collector as its own event.
func TestProtocolViolationIsReported(t *testing.T) {
	c := newCollector(t, collectorOptions{badHandshake: true, autoAck: true})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	h.src.exec(t, 1, "/usr/bin/violated", "-v")

	violation := waitType(t, c, event.TypeProtocolViolation)
	if got := stringField(t, violation, "reason"); got == "" {
		t.Error("sauron.protocol.violation carries no reason")
	}
	if got := stringField(t, violation, "peer"); got == "" {
		t.Error("sauron.protocol.violation does not say which peer misbehaved")
	}
	// A malformed host is still a lost connection, and the events survive it.
	waitType(t, c, event.TypeTransportDisconnect)
	waitFor(t, "the collected event to be delivered by the second attempt", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 1
	})

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	assertNoGaps(t, c)
	c.checkClean(t)
}

// TestSenderRefusesOversizedEvents checks the one case where the sender itself
// must drop an event: a frame the host has told it it will not accept. Retrying
// it forever would block everything behind it, so it is reported as the loss it
// is and skipped.
func TestSenderRefusesOversizedEvents(t *testing.T) {
	// The host announces a 4 KiB limit in READY, which an ordinary event fits
	// inside and an execve with a 16 KiB argument does not.
	c := newCollector(t, collectorOptions{autoAck: true, maxPayload: 4096})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	h.src.exec(t, 1, "/usr/bin/small", "-s")
	h.src.exec(t, 2, "/usr/bin/enormous", strings.Repeat("A", 16<<10))
	h.src.exec(t, 3, "/usr/bin/small", "-s")

	violation := waitType(t, c, event.TypeProtocolViolation)
	if got := numberField(t, violation, "events_dropped"); got != 1 {
		t.Errorf("events_dropped = %d, want 1", got)
	}
	first := numberField(t, violation, "first_missing_sequence")
	last := numberField(t, violation, "last_missing_sequence")
	if first == 0 || first != last {
		t.Errorf("missing range is [%d,%d], want one sequence", first, last)
	}
	for seq := range c.delivered() {
		if seq == first {
			t.Errorf("sequence %d was reported as undeliverable but arrived anyway", seq)
		}
	}
	if h.metrics.EventsDropped.Load() == 0 {
		t.Error("events_dropped_total was not incremented for the undeliverable event")
	}

	// One event that cannot be carried must not stop the ones behind it.
	waitFor(t, "the events either side of the oversized one", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 2
	})

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

func TestDispatchAdvancesPastOversizedBacklog(t *testing.T) {
	for _, name := range []string{"memory", "spool"} {
		t.Run(name, func(t *testing.T) {
			const oversizedCount = 2*maxSendBatch + 1
			cfg := testConfig("")
			cfg.Transport.MaxUnacked = oversizedCount + 1
			opts := senderOptions{
				cfg: cfg, metrics: &metrics.Agent{}, log: logging.Discard(),
				emit: func(*event.Event) {},
			}
			if name == "spool" {
				sp, err := spool.Open(spool.Options{Dir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sp.Close() })
				opts.spool = sp
			}
			s := newSender(opts)
			for seq := uint64(1); seq <= oversizedCount+1; seq++ {
				e := &event.Event{Sequence: seq, Type: event.TypeProcessExec}
				if seq <= oversizedCount {
					e.Command = strings.Repeat("A", 8192)
				}
				if err := s.backlog.Reserve(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := s.backlog.Append(e); err != nil {
					t.Fatal(err)
				}
			}

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			conn := protocol.NewConn(client, 4096)
			received := make(chan protocol.Frame, 2)
			go func() {
				peer := protocol.NewConn(server, 4096)
				for {
					f, err := peer.Receive(0)
					if err != nil {
						return
					}
					received <- *f
				}
			}()

			// Reset only the session cursor to simulate a reconnect. Valid
			// unacknowledged events must replay, and losses must not be recounted.
			for session := 0; session < 2; session++ {
				var inflight []uint64
				var sentThrough uint64
				sent := 0
				for pass := 0; pass < 4; pass++ {
					n, err := s.dispatch(conn, &inflight, &sentThrough)
					if err != nil {
						t.Fatal(err)
					}
					sent += n
				}
				if sent != 1 {
					t.Fatalf("session %d sent %d events after an oversized prefix, want 1", session, sent)
				}
				select {
				case f := <-received:
					if f.Type != protocol.MsgEvent || f.Sequence != oversizedCount+1 {
						t.Fatalf("received %s sequence %d, want valid event %d", f.Type, f.Sequence, oversizedCount+1)
					}
				case <-time.After(time.Second):
					t.Fatal("valid event did not reach the collector")
				}
			}
			if got := s.metrics.EventsDropped.Load(); got != oversizedCount {
				t.Errorf("reported %d losses, want %d", got, oversizedCount)
			}
			if s.ackedThrough.Load() != 0 || s.backlog.PendingCount() == 0 {
				t.Fatal("sending consumed an event without a host acknowledgement")
			}
		})
	}
}

func TestOversizedMemoryEventsReleaseOnlyTheirSlots(t *testing.T) {
	cfg := testConfig("")
	cfg.Transport.MaxUnacked = 3
	var losses []*event.Event
	s := newSender(senderOptions{
		cfg: cfg, metrics: &metrics.Agent{}, log: logging.Discard(),
		emit: func(e *event.Event) { losses = append(losses, e) },
	})
	b := s.backlog.(*memBacklog)
	appendEvent := func(seq uint64, command string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := b.Reserve(ctx); err != nil {
			t.Fatalf("reserving slot for sequence %d: %v", seq, err)
		}
		if err := b.Append(&event.Event{Sequence: seq, Type: event.TypeProcessExec, Command: command}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent(1, "valid but unacknowledged")
	appendEvent(2, strings.Repeat("A", 8192))
	appendEvent(3, strings.Repeat("A", 8192))
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() {
		peer := protocol.NewConn(server, 4096)
		for {
			if _, err := peer.Receive(0); err != nil {
				return
			}
		}
	}()
	conn := protocol.NewConn(client, 4096)
	var inflight []uint64
	var through uint64
	if sent, err := s.dispatch(conn, &inflight, &through); err != nil || sent != 1 {
		t.Fatalf("first dispatch sent %d: %v", sent, err)
	}
	if len(losses) != 2 || s.metrics.EventsDropped.Load() != 2 {
		t.Fatal("oversized events were released without recording both losses")
	}
	appendEvent(4, "later valid event")
	if sent, err := s.dispatch(conn, &inflight, &through); err != nil || sent != 1 {
		t.Fatalf("second dispatch sent %d: %v", sent, err)
	}
	retained, err := b.Next(3)
	if err != nil || len(retained) != 2 || retained[0].Sequence != 1 || retained[1].Sequence != 4 {
		t.Fatalf("valid events were not retained for replay: %v, %v", retained, err)
	}
	if s.ackedThrough.Load() != 0 || b.FirstUnacked() != 1 {
		t.Fatal("skipping oversized events acknowledged the earlier valid event")
	}
}

func TestOversizedLossReportDoesNotRecurse(t *testing.T) {
	for _, name := range []string{"memory", "spool"} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			cfg := testConfig("")
			cfg.Transport.MaxUnacked = 4
			opts := senderOptions{
				cfg: cfg, metrics: &metrics.Agent{},
				log: slog.New(slog.NewJSONHandler(&logs, nil)),
			}
			if name == "spool" {
				sp, err := spool.Open(spool.Options{Dir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sp.Close() })
				opts.spool = sp
			}
			s := newSender(opts)
			next := uint64(1)
			appendEvent := func(e *event.Event) {
				t.Helper()
				e.Sequence = next
				next++
				if err := s.backlog.Reserve(t.Context()); err != nil {
					t.Fatal(err)
				}
				if err := s.backlog.Append(e); err != nil {
					t.Fatal(err)
				}
			}
			emitted := 0
			s.emit = func(e *event.Event) { emitted++; appendEvent(e) }
			appendEvent(&event.Event{Type: event.TypeProcessExec, Command: strings.Repeat("A", 8192)})

			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			conn := protocol.NewConn(client, 300)
			var inflight []uint64
			var through uint64
			for pass := 0; pass < 8; pass++ {
				if sent, err := s.dispatch(conn, &inflight, &through); err != nil || sent != 0 {
					t.Fatalf("oversized dispatch sent %d: %v", sent, err)
				}
			}
			if emitted != 1 || s.metrics.EventsDropped.Load() != 2 {
				t.Fatalf("one oversized event generated %d reports and %d drops, want 1 report and 2 drops",
					emitted, s.metrics.EventsDropped.Load())
			}
			if !strings.Contains(logs.String(), "payload limit cannot carry its loss report") ||
				!strings.Contains(logs.String(), "first_missing_sequence") {
				t.Fatal("undeliverable loss report and its original range were not preserved in local logs")
			}
			if name == "memory" && len(s.oversized) != 0 {
				t.Fatalf("%d oversized markers retained for discarded memory events", len(s.oversized))
			}

			appendEvent(&event.Event{Type: event.TypeProcessExec})
			received := make(chan uint64, 1)
			go func() {
				f, err := protocol.NewConn(server, 300).Receive(time.Second)
				if err == nil {
					received <- f.Sequence
				}
			}()
			if sent, err := s.dispatch(conn, &inflight, &through); err != nil || sent != 1 {
				t.Fatalf("later small event sent %d: %v", sent, err)
			}
			select {
			case seq := <-received:
				if seq != 3 {
					t.Fatalf("received sequence %d, want later small event 3", seq)
				}
			case <-time.After(time.Second):
				t.Fatal("later small event did not reach collector")
			}
		})
	}
}

func TestOversizedSpoolMarkersFollowRetention(t *testing.T) {
	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), SegmentSize: 4096, MaxSize: 8192})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	s := newSender(senderOptions{
		cfg: testConfig(""), spool: sp, metrics: &metrics.Agent{}, log: logging.Discard(),
		emit: func(*event.Event) {},
	})
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	conn := protocol.NewConn(client, 300)
	for seq := uint64(1); seq <= 8; seq++ {
		if err := sp.Append(&event.Event{Sequence: seq, Command: strings.Repeat("A", 4096)}); err != nil {
			t.Fatal(err)
		}
		s.reconcile()
		// Replay the retained backlog twice; eviction should forget only old
		// markers, leaving once-only loss accounting for the surviving record.
		for replay := 0; replay < 2; replay++ {
			var through uint64
			var inflight []uint64
			if sent, err := s.dispatch(conn, &inflight, &through); err != nil || sent != 0 {
				t.Fatalf("oversized dispatch sent %d: %v", sent, err)
			}
		}
		if sp.FirstUnacked() != seq || len(s.oversized) != 1 || !s.isOversized(seq) {
			t.Fatalf("markers do not match retained sequence %d: first=%d, markers=%v", seq, sp.FirstUnacked(), s.oversized)
		}
		if got := s.metrics.EventsDropped.Load(); got != seq {
			t.Fatalf("replay recounted loss: got %d dropped events, want %d", got, seq)
		}
	}
}

func TestOversizedProgressDoesNotExtendAckTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := testConfig("")
		cfg.Transport.MaxUnacked = 4
		cfg.Transport.AckTimeout = config.Duration(100 * time.Millisecond)
		s := newSender(senderOptions{
			cfg: cfg, metrics: &metrics.Agent{}, log: logging.Discard(),
		})
		appendEvent := func(seq uint64, oversized bool) {
			t.Helper()
			e := &event.Event{Sequence: seq, Type: event.TypeProcessExec}
			if oversized {
				e.Command = strings.Repeat("A", 8192)
			}
			if err := s.backlog.Reserve(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := s.backlog.Append(e); err != nil {
				t.Fatal(err)
			}
		}
		appendEvent(1, false)
		appendEvent(2, true)
		appendEvent(3, true)
		next := uint64(4)
		s.emit = func(*event.Event) {
			// Keep the backlog nonempty and advance the clock as losses are
			// processed, while the first valid event remains unacknowledged.
			time.Sleep(10 * time.Millisecond)
			appendEvent(next, true)
			next++
		}
		client, server := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		go func() {
			peer := protocol.NewConn(server, 4096)
			for {
				if _, err := peer.Receive(0); err != nil {
					return
				}
			}
		}()
		sctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		err := s.sendLoop(t.Context(), sctx, protocol.NewConn(client, 4096))
		if err == nil || !strings.Contains(err.Error(), "unacknowledged") {
			t.Fatalf("sendLoop returned %v, want acknowledgement timeout despite skipped-event progress", err)
		}
	})
}

// ---------------------------------------------------------------------------
// unit tests for the sender's parts
// ---------------------------------------------------------------------------

func TestTrimInflight(t *testing.T) {
	cases := []struct {
		name     string
		inflight []uint64
		through  uint64
		wantN    int
		wantLeft []uint64
	}{
		{"nothing acknowledged", []uint64{4, 5, 6}, 0, 0, []uint64{4, 5, 6}},
		{"cumulative ack covers a prefix", []uint64{4, 5, 6}, 5, 2, []uint64{6}},
		{"ack covers everything", []uint64{4, 5, 6}, 9, 3, nil},
		{"ack below the window", []uint64{4, 5, 6}, 3, 0, []uint64{4, 5, 6}},
		{"empty", nil, 7, 0, nil},
		// Sequences can have holes where the queue dropped events; a
		// cumulative ack still covers the whole range below it.
		{"gaps in the window", []uint64{4, 9, 11}, 9, 2, []uint64{11}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inflight := append([]uint64(nil), tc.inflight...)
			got := trimInflight(&inflight, tc.through)
			if got != tc.wantN {
				t.Errorf("trimInflight = %d, want %d", got, tc.wantN)
			}
			if len(inflight) != len(tc.wantLeft) {
				t.Fatalf("left %v, want %v", inflight, tc.wantLeft)
			}
			for i := range inflight {
				if inflight[i] != tc.wantLeft[i] {
					t.Fatalf("left %v, want %v", inflight, tc.wantLeft)
				}
			}
		})
	}
}

func TestPayloadLimit(t *testing.T) {
	cases := []struct {
		name string
		in   config.Size
		want uint32
	}{
		{"unset falls back to the default", 0, protocol.DefaultMaxPayloadSize},
		{"negative falls back to the default", -1, protocol.DefaultMaxPayloadSize},
		{"configured value is kept", config.Size(64 << 10), 64 << 10},
		// Clamped, not truncated: a value that wrapped into a tiny limit would
		// refuse every event instead of protecting anything.
		{"above the ceiling is clamped", config.Size(1) << 40, protocol.MaxPayloadCeiling},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadLimit(tc.in); got != tc.want {
				t.Errorf("payloadLimit(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// The memory backlog is what an agent without a spool delivers from. It must
// be bounded, or an unreachable host would move the whole backlog into a place
// with no capacity limit, no accounting and no durability.
func TestMemBacklogIsBounded(t *testing.T) {
	b := newMemBacklog(2)
	ctx := context.Background()

	for seq := uint64(1); seq <= 2; seq++ {
		if err := b.Reserve(ctx); err != nil {
			t.Fatalf("Reserve(%d): %v", seq, err)
		}
		if err := b.Append(numbered(seq, "boot-a")); err != nil {
			t.Fatalf("Append(%d): %v", seq, err)
		}
	}
	if got := b.PendingCount(); got != 2 {
		t.Fatalf("PendingCount = %d, want 2", got)
	}
	if got := b.FirstUnacked(); got != 1 {
		t.Errorf("FirstUnacked = %d, want 1", got)
	}
	if got := b.LastSequence(); got != 2 {
		t.Errorf("LastSequence = %d, want 2", got)
	}

	// The third reservation has to wait. The short wait below is checking that
	// it does not return, which is the one thing a channel cannot be used to
	// observe.
	blocked := make(chan error, 1)
	go func() { blocked <- b.Reserve(ctx) }()
	select {
	case err := <-blocked:
		t.Fatalf("Reserve returned %v with a full backlog; it must wait", err)
	case <-time.After(50 * time.Millisecond):
	}

	// An acknowledgement releases the slot.
	if err := b.Ack(1); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("Reserve after Ack: %v", err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("Reserve did not return after an acknowledgement freed a slot")
	}

	if got := b.PendingCount(); got != 1 {
		t.Errorf("PendingCount after Ack = %d, want 1", got)
	}
	if got := b.FirstUnacked(); got != 2 {
		t.Errorf("FirstUnacked after Ack = %d, want 2", got)
	}

	// Release hands back a reservation whose event was never appended.
	b.Release()
	if err := b.Reserve(ctx); err != nil {
		t.Errorf("Reserve after Release: %v", err)
	}
}

// Next is a read, not a consume: the same events come back until an
// acknowledgement moves the cursor. The sender relies on that to replay after
// a reconnect.
func TestMemBacklogNextIsIdempotent(t *testing.T) {
	b := newMemBacklog(8)
	ctx := context.Background()
	for seq := uint64(1); seq <= 4; seq++ {
		if err := b.Reserve(ctx); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if err := b.Append(numbered(seq, "boot-a")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	first, err := b.Next(3)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	again, err := b.Next(3)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(first) != 3 || len(again) != 3 {
		t.Fatalf("Next returned %d and %d events, want 3 each", len(first), len(again))
	}
	for i := range first {
		if first[i].Sequence != again[i].Sequence {
			t.Fatalf("Next is not idempotent: %d then %d", first[i].Sequence, again[i].Sequence)
		}
		if first[i].Sequence != uint64(i+1) {
			t.Errorf("Next returned sequence %d at index %d, want %d", first[i].Sequence, i, i+1)
		}
	}

	if err := b.Ack(2); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	after, err := b.Next(3)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(after) != 2 || after[0].Sequence != 3 {
		t.Fatalf("after Ack(2) Next returned %d events starting at %d, want 2 starting at 3",
			len(after), after[0].Sequence)
	}
}

// A sequence that is not greater than the last one held is refused, exactly as
// the spool refuses it: a backlog whose ordering cannot be trusted turns a
// cumulative acknowledgement into silent data loss.
func TestMemBacklogRefusesBackwardsSequences(t *testing.T) {
	b := newMemBacklog(4)
	ctx := context.Background()
	if err := b.Reserve(ctx); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := b.Append(numbered(5, "boot-a")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := b.Reserve(ctx); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := b.Append(numbered(5, "boot-a")); err == nil {
		t.Error("the backlog accepted a repeated sequence")
	}
	if err := b.Append(nil); err == nil {
		t.Error("the backlog accepted a nil event")
	}
}

// Reserve must give up when the agent is shutting down, or the pump would
// never stop.
func TestMemBacklogReserveHonoursContext(t *testing.T) {
	b := newMemBacklog(1)
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.Reserve(ctx); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	cancel()
	if err := b.Reserve(ctx); err == nil {
		t.Error("Reserve ignored a cancelled context")
	}
}

func TestFlushTimeoutIsBounded(t *testing.T) {
	cases := []struct {
		name string
		ack  time.Duration
		want time.Duration
	}{
		{"short acknowledgement timeout is used as is", time.Second, time.Second},
		{"a long one is capped", time.Hour, maxShutdownFlush},
		{"unset is capped", 0, maxShutdownFlush},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &sender{}
			s.cfg.Transport.AckTimeout = config.Duration(tc.ack)
			if got := s.flushTimeout(); got != tc.want {
				t.Errorf("flushTimeout = %s, want %s", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the host is ahead of the agent's numbering
// ---------------------------------------------------------------------------
//
// The host keeps its deduplication watermark per (CID, boot id) and the boot
// id is the machine's, so it outlives an agent restart. Any restart that loses
// the agent's own record of where it had got to -- a spool that was reset,
// rotated away, moved, or never enabled -- therefore meets a host that holds
// sequences the fresh agent is about to hand out again from 1.
//
// That combination used to put the sender in a hot loop: the position above
// our numbering emptied the in-flight list as fast as events were sent, the
// backlog handed the same events back (Next is idempotent until an Ack moves
// the cursor) and the loop never reached its wait. Three events became
// hundreds of thousands of frames in seconds.
//
// The assertion that pins it is the frame count at the collector. A spinning
// sender produces frames by the thousand in the window these tests measure.

// assertQuiet measures every frame the agent puts on the wire over a fixed
// window, with nothing new to send, and fails if there are more than max.
func assertQuiet(t *testing.T, c *collector, window time.Duration, max int) {
	t.Helper()
	before := c.framesSeen()
	time.Sleep(window)
	if got := c.framesSeen() - before; got > max {
		t.Errorf("the agent sent %d frames in %s with nothing new to send, want at most %d: the send loop is spinning",
			got, window, max)
	}
}

// assertDeliveredOnce fails if any sequence arrived more than once.
func assertDeliveredOnce(t *testing.T, c *collector) {
	t.Helper()
	for seq, n := range c.delivered() {
		if n > 1 {
			t.Errorf("sequence %d was delivered %d times, want once", seq, n)
		}
	}
}

// assertSendProportionate fails if the agent put far more events on the wire
// than it ever created. It is the counter an operator sees, and it is what the
// reproduction of the hot loop measured: events_created=3, events_sent=422644.
func assertSendProportionate(t *testing.T, h *harness) {
	t.Helper()
	created := h.metrics.EventsCreated.Load()
	sent := h.metrics.EventsSent.Load()
	if sent > created {
		t.Errorf("events_sent=%d for events_created=%d: the sender re-sent events nobody asked for",
			sent, created)
	}
}

// TestResumeFromAboveOurSequence is the reproduction. The host answers the
// handshake with a position far above anything this agent can hold, which is
// what a real collector does when it still has the watermark for this boot id
// and the agent's spool was reset.
func TestResumeFromAboveOurSequence(t *testing.T) {
	const hostThrough = 1000

	c := newCollector(t, collectorOptions{autoAck: true, resumeFrom: hostThrough})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	// Numbering starts at 1 in the new spool, so everything collected before
	// the handshake is numbered below the host's position. The host holds
	// those numbers already: it suppresses anything sent under them as a
	// duplicate and its acknowledgement point does not move, so nothing comes
	// back to release them. That is what the hot loop fed on -- the backlog
	// kept handing the same events back while the acknowledged position
	// cleared the in-flight list as fast as they were sent.
	//
	// Wait for the sender to have taken the host's position in, which happens
	// either way, and only then collect the events that have to be delivered.
	waitFor(t, "the host's position to reach the sender", func() bool {
		return h.agent.send.ackedThrough.Load() >= hostThrough
	})
	for i := uint64(1); i <= 3; i++ {
		h.src.exec(t, i, "/usr/bin/resumed", "-r")
	}
	waitFor(t, "the events produced after the host's position to be delivered", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 3
	})

	// The stream has caught up, and nothing more should leave the guest until
	// something new is collected. This is the assertion that pins the bug: a
	// spinning sender put hundreds of thousands of frames on the wire in
	// seconds.
	assertQuiet(t, c, 500*time.Millisecond, 1)

	// Numbering was lifted above the host's position, so what the agent issues
	// from here is new to the host and a cumulative ACK still means what it
	// says.
	if next := h.agent.seq.peek(); next <= hostThrough {
		t.Fatalf("the next sequence to be issued is %d, at or below the host's position %d",
			next, hostThrough)
	}
	assertDeliveredOnce(t, c)
	assertSendProportionate(t, h)

	// Nothing below the host's position was re-sent: the host would only
	// suppress it, and it is what the loop used to do for ever.
	for _, r := range c.events() {
		if r.headerSeq <= hostThrough {
			t.Errorf("sequence %d was sent although the host said it holds everything through %d",
				r.headerSeq, hostThrough)
		}
	}

	// A handful of frames for a handful of events, not hundreds of thousands.
	if frames := c.framesSeen(); frames > 12 {
		t.Errorf("the collector saw %d frames for %d events, want single digits",
			frames, h.metrics.EventsCreated.Load())
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestAckAboveOurSequence is the same reconciliation reached through an ACK in
// mid-session rather than through READY: a host whose watermark moves ahead of
// the agent while the connection is up.
func TestAckAboveOurSequence(t *testing.T) {
	const hostThrough = 5000

	c := newCollector(t, collectorOptions{autoAck: true, ackAhead: hostThrough})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	// The collector acknowledges 5000 as soon as the first event arrives, so
	// the reconciliation happens in mid-session, through the receive loop
	// rather than through the handshake. Wait for the sender to have taken the
	// acknowledgement in -- that much happens either way -- and only then
	// collect the events that have to be delivered above it.
	waitEvents(t, c, 1)
	waitFor(t, "the acknowledgement above the agent's numbering to reach the sender", func() bool {
		return h.agent.send.ackedThrough.Load() >= hostThrough
	})
	for i := uint64(1); i <= 3; i++ {
		h.src.exec(t, i, "/usr/bin/acked", "-a")
	}
	waitFor(t, "the events produced after the acknowledgement to be delivered", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 3
	})

	// Events the host will not acknowledge again -- it holds their numbers
	// already -- must not be re-sent for ever. This is the assertion that pins
	// the bug.
	assertQuiet(t, c, 500*time.Millisecond, 1)

	if next := h.agent.seq.peek(); next <= hostThrough {
		t.Fatalf("the next sequence to be issued is %d, at or below the sequence the host acknowledged (%d)",
			next, hostThrough)
	}
	assertDeliveredOnce(t, c)
	assertSendProportionate(t, h)

	for _, r := range c.eventsOfType(event.TypeProcessExec) {
		if r.Sequence <= hostThrough {
			t.Errorf("event %s was numbered %d, at or below the sequence the host acknowledged (%d)",
				r.Type, r.Sequence, hostThrough)
		}
	}
	if frames := c.framesSeen(); frames > 12 {
		t.Errorf("the collector saw %d frames for %d events, want single digits",
			frames, h.metrics.EventsCreated.Load())
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestIdleAgentDoesNotSpin is the general form of the defect: a send loop that
// finds nothing to send must wait for something, not poll. The backstop timer
// is one second and an append or an acknowledgement wakes the loop, so a guest
// with nothing to report costs no frames at all.
func TestIdleAgentDoesNotSpin(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	// The two startup events -- agent.started and transport.connected -- are
	// everything an agent with no audit records to report ever produces.
	waitEvents(t, c, 2)
	waitFor(t, "the startup events to be acknowledged", func() bool {
		return h.agent.spool.PendingCount() == 0
	})

	assertQuiet(t, c, 750*time.Millisecond, 0)
	assertDeliveredOnce(t, c)
	assertSendProportionate(t, h)

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}
