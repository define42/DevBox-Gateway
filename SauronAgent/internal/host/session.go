package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/protocol"
)

// defaultWriteTimeout bounds a write to a guest when configuration gives no
// better bound. A guest that stops reading must not be able to pin a collector
// goroutine and its buffers indefinitely.
const defaultWriteTimeout = 10 * time.Second

// errProtocolViolation marks a session that ended because the peer sent
// something the protocol does not allow, as opposed to the connection failing
// underneath it. The two call for opposite reactions: a violation is a
// statement about the guest and is reported as a security event, while a
// transport failure says nothing about it and is simply waited out.
var errProtocolViolation = errors.New("host: protocol violation")

// session is one guest connection.
//
// Everything on it is single-goroutine except the acknowledgement state and the
// frame writer: one goroutine reads frames and decides what may be
// acknowledged, and a second sends the acknowledgements on a timer.
// protocol.Conn.Send is mutex-protected, which is what makes that safe; Receive
// is not, so there is exactly one reader.
type session struct {
	srv  *Server
	conn *protocol.Conn
	peer peer
	id   string
	log  *slog.Logger

	// writeCtx is used for sink writes. It deliberately ignores cancellation:
	// an event already accepted from a guest must be written or explicitly
	// reported as failed, and shutting the collector down is a reason to stop
	// taking new work rather than to drop evidence already in hand.
	writeCtx context.Context

	src          output.Source
	key          streamKey
	ackInterval  int
	writeTimeout time.Duration
	idleTimeout  time.Duration

	// violationCode records the ERROR code already sent to the peer, so the
	// session's postmortem does not send a second one.
	violationCode protocol.ErrorCode

	// endReason describes an orderly end of the session, for the postmortem.
	endReason string

	mu       sync.Mutex
	ackPoint uint64 // highest contiguous sequence durably written
	acked    uint64 // highest sequence already sent in an ACK
	pending  int    // events since the last ACK
	signal   chan struct{}
}

// newSession prepares a session for an admitted connection.
func (s *Server) newSession(conn net.Conn, p peer, src output.Source) *session {
	id := fmt.Sprintf("%s-%06d", p.bucket(), s.seq.Add(1))
	interval := s.cfg.Limits.AckInterval
	if interval < 1 {
		// Zero means acknowledge every event.
		interval = 1
	}
	return &session{
		srv:          s,
		conn:         protocol.NewConn(conn, s.maxPayload),
		peer:         p,
		id:           id,
		log:          s.log.With("session", id, "cid", p.logCID(), "vm", src.VM),
		src:          src,
		ackInterval:  interval,
		writeTimeout: s.writeTimeout(),
		idleTimeout:  s.cfg.Limits.IdleTimeout.Duration(),
		signal:       make(chan struct{}, 1),
	}
}

// run drives the session to completion.
func (s *session) run(ctx context.Context) {
	s.writeCtx = context.WithoutCancel(ctx)

	// The reader is blocked in Receive with a timeout measured in minutes, so
	// shutdown has to reach into the connection. Doing it here rather than by
	// closing the socket outright lets the guest keep the last acknowledgement
	// and learn that the stop was planned.
	stop := context.AfterFunc(ctx, s.drain)
	defer stop()
	defer func() { _ = s.conn.Close() }()

	err := s.handshake()
	if err == nil {
		ackDone := make(chan struct{})
		ackStopped := make(chan struct{})
		go func() {
			defer close(ackStopped)
			s.ackLoop(ackDone)
		}()

		err = s.serve()

		close(ackDone)
		<-ackStopped
		// One last acknowledgement releases everything the host durably holds
		// from the guest's spool, so a clean disconnect does not force the
		// whole batch to be re-sent after the reconnect.
		if ferr := s.flushAck(); ferr != nil {
			s.log.Debug("final acknowledgement not delivered", "error", ferr)
		}
	}
	s.finish(ctx, err)
}

// drain is the collector's orderly end of a session: acknowledge what is held,
// tell the guest the stop was planned, and break the read so the session
// goroutine wakes up.
func (s *session) drain() {
	_ = s.flushAck()
	_ = s.conn.Send(protocol.MsgShutdown, 0, &protocol.Shutdown{
		Reason: "collector shutting down",
	}, s.writeTimeout)
	_ = s.conn.Close()
}

// handshake performs the HELLO/READY exchange.
//
// It is bounded by limits.handshake_timeout: a connection that is opened and
// then stays silent costs a goroutine, a socket and a decode buffer, and a
// guest that never speaks must not be able to hold them.
func (s *session) handshake() error {
	f, err := s.conn.Receive(s.srv.cfg.Limits.HandshakeTimeout.Duration())
	if err != nil {
		return err
	}
	s.srv.metrics.FramesReceived.Add(1)

	if f.Type != protocol.MsgHello {
		return s.violation(protocol.ErrCodeUnexpectedType,
			"first frame was %s, expected HELLO", f.Type)
	}
	var hello protocol.Hello
	if err := protocol.DecodePayload(f, &hello); err != nil {
		return s.violation(protocol.ErrCodeBadPayload, "decoding HELLO: %v", err)
	}
	if hello.ProtocolVersion != protocol.Version {
		return s.violation(protocol.ErrCodeBadPayload,
			"protocol_version %d is not supported, this collector speaks %d",
			hello.ProtocolVersion, protocol.Version)
	}

	// Everything the guest just claimed is recorded as a claim. The trusted
	// half of Source was fixed from the CID before a byte was read.
	s.src.Reported = reportedFrom(&hello)
	s.key = streamKey{peer: s.peer.bucket(), boot: hello.BootID}

	resume := s.srv.dedup.ResumeFrom(s.key)
	if err := s.conn.Send(protocol.MsgReady, 0, &protocol.Ready{
		ProtocolVersion: protocol.Version,
		HostVersion:     identity.Version,
		SessionID:       s.id,
		ResumeFrom:      resume,
		MaxPayloadSize:  s.srv.maxPayload,
	}, s.writeTimeout); err != nil {
		return err
	}

	s.log.Info("guest connected",
		"known", s.src.Known,
		"hypervisor_backed", s.peer.vsock,
		"reported_hostname", hello.Hostname,
		"boot_id", hello.BootID,
		"agent_version", hello.AgentVersion,
		"resume_from", resume,
		"first_sequence", hello.FirstSequence)
	s.srv.monitor.seen(s.peer, s.srv.now())

	// first_sequence is the lowest sequence the agent can still replay. If it
	// starts above what the host holds, the events in between exist nowhere any
	// more: the agent has already discarded them and the host never got them.
	// That is the difference between "100-200 were lost" and "100-200 were
	// acknowledged and deleted", and it is only detectable here.
	if resume > 0 && hello.FirstSequence > resume+1 {
		first, last := resume+1, hello.FirstSequence-1
		s.srv.dedup.NoteMissing(s.key, first, last)
		s.reportGap(first, last, "agent cannot replay below its first_sequence")
	}
	return nil
}

// serve is the steady-state frame loop.
func (s *session) serve() error {
	for {
		f, err := s.conn.Receive(s.idleTimeout)
		if err != nil {
			return err
		}
		s.srv.metrics.FramesReceived.Add(1)

		switch f.Type {
		case protocol.MsgEvent:
			if err := s.handleEvent(f); err != nil {
				return err
			}
		case protocol.MsgPing:
			if err := s.handlePing(f); err != nil {
				return err
			}
		case protocol.MsgShutdown:
			var sd protocol.Shutdown
			if err := protocol.DecodePayload(f, &sd); err != nil {
				return s.violation(protocol.ErrCodeBadPayload, "decoding SHUTDOWN: %v", err)
			}
			// An orderly stop, not a stream loss. It is still recorded: the
			// stream monitor keeps counting, because a compromised guest can
			// send SHUTDOWN just as easily as a service manager can, and
			// "planned" is a claim like any other the guest makes.
			s.log.Info("guest disconnecting",
				"reason", sd.Reason, "last_sequence", sd.LastSequence, "acknowledged", s.ackedSequence())
			s.endReason = "guest sent SHUTDOWN"
			return nil
		case protocol.MsgError:
			var em protocol.ErrorMessage
			if err := protocol.DecodePayload(f, &em); err != nil {
				return s.violation(protocol.ErrCodeBadPayload, "decoding ERROR: %v", err)
			}
			s.log.Warn("guest reported an error",
				"code", string(em.Code), "message", em.Message, "fatal", em.Fatal)
			if em.Fatal {
				s.endReason = "guest reported a fatal error"
				return nil
			}
		default:
			// HELLO after the handshake, and READY, ACK or PONG from a guest:
			// host-to-guest or once-only messages. A peer sending them is not
			// speaking this protocol, and continuing to read from it would mean
			// trusting a parser state the peer has already contradicted.
			return s.violation(protocol.ErrCodeUnexpectedType,
				"%s is not a message a guest may send", f.Type)
		}
	}
}

// handleEvent validates, deduplicates, enriches and outputs one event.
func (s *session) handleEvent(f *protocol.Frame) error {
	var msg protocol.EventMessage
	if err := protocol.DecodePayload(f, &msg); err != nil {
		return s.violation(protocol.ErrCodeBadPayload, "decoding EVENT: %v", err)
	}
	ev := msg.Event
	if ev == nil {
		return s.violation(protocol.ErrCodeBadPayload, "EVENT carried no event object")
	}
	if ev.Sequence == 0 {
		return s.violation(protocol.ErrCodeBadSequence,
			"sequence 0 is reserved and is never assigned to an event")
	}
	// The header sequence is what the host acknowledges and deduplicates on, so
	// it must be the same number the payload carries. A peer where the two
	// disagree is either broken or trying to have one event acknowledged under
	// another's number.
	if f.Sequence != ev.Sequence {
		return s.violation(protocol.ErrCodeBadSequence,
			"event sequence %d does not match frame sequence %d", ev.Sequence, f.Sequence)
	}

	s.srv.metrics.EventsReceived.Add(1)
	s.srv.monitor.seen(s.peer, s.srv.now())

	res := s.srv.dedup.Check(s.key, ev.Sequence)
	if res.Gap {
		s.reportGap(res.GapFirst, res.GapLast, "sequence numbers skipped")
	}
	if res.Duplicate {
		// A replay after a reconnect is normal: delivery is at-least-once. It
		// still counts as acknowledgeable, because the host does hold it --
		// leaving it unacknowledged would wedge the guest's spool forever.
		s.srv.metrics.EventsDuplicate.Add(1)
		s.log.Debug("duplicate suppressed", "sequence", ev.Sequence, "boot_id", s.key.boot)
		s.advanceAck(s.srv.dedup.ResumeFrom(s.key))
		return nil
	}

	env := envelopeFor(s.srv.now(), s.src, ev)
	if err := s.srv.sink.Write(s.writeCtx, env); err != nil {
		// The acknowledgement point does not move. An ACK tells the guest it
		// may delete the event from its spool, so acknowledging one the sinks
		// refused would destroy the only remaining copy. The guest keeps it and
		// sends it again.
		s.srv.metrics.OutputErrors.Add(1)
		s.log.Error("writing event failed, not acknowledged",
			"sequence", ev.Sequence, "type", ev.Type, "error", err)
		s.report(event.NewInternal(typeOutputFailed, event.SeverityCritical, map[string]any{
			"reason":                  err.Error(),
			"sequence":                ev.Sequence,
			"event_type":              ev.Type,
			"boot_id":                 s.key.boot,
			"acknowledged_through":    s.ackPointSequence(),
			"held_by_guest_for_retry": true,
		}))
		return nil
	}

	s.srv.metrics.EventsOutput.Add(1)
	ack, forgotten := s.srv.dedup.Commit(s.key, ev.Sequence)
	if forgotten > 0 {
		// The window is full because the watermark is stuck behind a hole. The
		// forgotten sequences can no longer be recognised as duplicates, so a
		// replay of them will be written twice; that is preferred to growing
		// without bound or to suppressing an original.
		s.log.Warn("deduplication window exceeded, older sequences forgotten",
			"forgotten", forgotten, "acknowledged_through", ack,
			"window", s.srv.dedup.window, "boot_id", s.key.boot)
	}
	s.advanceAck(ack)
	return nil
}

// handlePing answers a heartbeat.
//
// The counters are advisory -- they come from the guest and are exactly as
// trustworthy as it is -- but they are the only way to tell a healthy quiet
// guest from one whose audit subsystem has been switched off, because neither
// produces audit events.
func (s *session) handlePing(f *protocol.Frame) error {
	var ping protocol.Ping
	if err := protocol.DecodePayload(f, &ping); err != nil {
		return s.violation(protocol.ErrCodeBadPayload, "decoding PING: %v", err)
	}
	s.srv.monitor.seen(s.peer, s.srv.now())

	attrs := []any{
		"uptime", ping.UptimeSeconds,
		"audit_enabled", ping.AuditEnabled,
		"events_received", ping.EventsReceived,
		"events_sent", ping.EventsSent,
		"events_spooled", ping.EventsSpooled,
		"events_dropped", ping.EventsDropped,
		"queue_depth", ping.QueueDepth,
		"spool_bytes", ping.SpoolBytes,
	}
	if !ping.AuditEnabled || ping.EventsDropped > 0 {
		s.log.Warn("guest heartbeat reports degraded collection", attrs...)
	} else {
		s.log.Debug("guest heartbeat", attrs...)
	}

	return s.conn.Send(protocol.MsgPong, 0, &protocol.Pong{
		EchoUptime: ping.UptimeSeconds,
		// The host's clock, so the guest can measure its own drift against a
		// clock it does not control.
		UnixNano: s.srv.now().UnixNano(),
	}, s.writeTimeout)
}

// ackLoop sends acknowledgements. It wakes when limits.ack_interval events have
// been accepted and, independently, every limits.ack_max_delay, so that a slow
// trickle of events is still released from the guest's spool promptly.
func (s *session) ackLoop(done <-chan struct{}) {
	var tick <-chan time.Time
	if d := s.srv.cfg.Limits.AckMaxDelay.Duration(); d > 0 {
		t := time.NewTicker(d)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-done:
			return
		case <-s.signal:
		case <-tick:
		}
		if err := s.flushAck(); err != nil {
			// The connection is torn. Accepting more events on it would mean
			// taking evidence the guest can never be told is safe.
			s.log.Warn("sending acknowledgement failed", "error", err)
			_ = s.conn.Close()
			return
		}
	}
}

// advanceAck records that everything up to point is durably held, and wakes the
// acknowledgement loop once a batch has accumulated.
func (s *session) advanceAck(point uint64) {
	s.mu.Lock()
	if point > s.ackPoint {
		s.ackPoint = point
	}
	s.pending++
	due := s.pending >= s.ackInterval && s.ackPoint > s.acked
	s.mu.Unlock()

	if due {
		select {
		case s.signal <- struct{}{}:
		default:
		}
	}
}

// flushAck sends the cumulative acknowledgement if it has moved.
//
// A failed send is reported to the caller but the local position still
// advances: the guest did not receive the ACK, will re-send, and the
// deduplication window will recognise the replay. The alternative -- retrying
// the same ACK on a torn connection -- cannot work, because a torn connection
// is never reused.
func (s *session) flushAck() error {
	s.mu.Lock()
	seq := s.ackPoint
	if seq <= s.acked {
		s.mu.Unlock()
		return nil
	}
	s.acked = seq
	s.pending = 0
	s.mu.Unlock()

	// The header sequence is meaningless on an ACK: the value is in the
	// payload, and protocol.md documents senders writing 0 here.
	return s.conn.Send(protocol.MsgAck, 0, &protocol.Ack{Sequence: seq}, s.writeTimeout)
}

// ackedSequence is the last sequence acknowledged to the guest.
func (s *session) ackedSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acked
}

// ackPointSequence is the highest sequence durably held.
func (s *session) ackPointSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackPoint
}

// violation sends a fatal ERROR to the peer and returns the error that ends the
// session. The peer is told which rule it broke so that a buggy agent can be
// fixed rather than merely disconnected.
func (s *session) violation(code protocol.ErrorCode, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	s.violationCode = code
	_ = s.conn.Send(protocol.MsgError, 0, &protocol.ErrorMessage{
		Code: code, Message: msg, Fatal: true,
	}, s.writeTimeout)
	return fmt.Errorf("%w: %s", errProtocolViolation, msg)
}

// finish classifies how the session ended and records it.
//
// The classification is the point of the function: a malformed peer is a
// security finding about a guest, a broken connection is not, and a collector
// that logged them alike would either hide the first among the second or cry
// wolf on every network blip.
func (s *session) finish(ctx context.Context, err error) {
	switch {
	case err == nil:
		reason := s.endReason
		if reason == "" {
			reason = "peer closed"
		}
		s.log.Info("session ended", "reason", reason, "acknowledged", s.ackedSequence())

	case s.isViolation(err):
		s.srv.metrics.FrameErrors.Add(1)
		code := s.violationCode
		if code == "" {
			// The decoder rejected the frame itself -- magic, version, type,
			// flags or length -- so the peer has not been told yet.
			code = protocol.ErrCodeBadFrame
			_ = s.conn.Send(protocol.MsgError, 0, &protocol.ErrorMessage{
				Code: code, Message: err.Error(), Fatal: true,
			}, s.writeTimeout)
		}
		s.log.Warn("session ended on a protocol violation",
			"code", string(code), "error", err, "acknowledged", s.ackedSequence())
		s.report(event.NewInternal(event.TypeProtocolViolation, event.SeverityWarning,
			map[string]any{
				"reason":            err.Error(),
				"code":              string(code),
				"cid":               s.peer.logCID(),
				"peer":              s.peer.addr,
				"hypervisor_backed": s.peer.vsock,
				"session":           s.id,
			}))

	case ctx.Err() != nil:
		s.log.Info("session ended", "reason", "collector shutting down",
			"acknowledged", s.ackedSequence())

	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, io.ErrClosedPipe), errors.Is(err, net.ErrClosed):
		// protocol.md section 4.7: a stream that simply stops is the one worth
		// investigating, as opposed to one that ended with SHUTDOWN.
		s.log.Warn("session ended without SHUTDOWN", "error", err,
			"acknowledged", s.ackedSequence())

	case isTimeout(err):
		s.log.Warn("session ended", "reason", "idle timeout",
			"idle_timeout", s.idleTimeout, "acknowledged", s.ackedSequence())

	default:
		s.log.Info("session ended", "reason", "transport error", "error", err,
			"acknowledged", s.ackedSequence())
	}
}

// isViolation reports whether err means the peer misbehaved, covering both the
// rules this package enforces and the framing rules the codec enforces.
func (s *session) isViolation(err error) bool {
	return errors.Is(err, errProtocolViolation) || protocol.IsProtocolError(err)
}

// isTimeout reports whether err is a deadline rather than a failure.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// report publishes a host-generated internal event for this session.
func (s *session) report(ev *event.Event) {
	s.srv.report.publish(s.writeCtx, s.src, ev)
}

// reportGap reports missing events.
//
// A gap is not a duplicate and must not be absorbed quietly: either the agent
// explained it with a sauron.queue.overflow or sauron.spool.full event naming
// the same range, or nobody did -- and an unexplained hole in an audit stream is
// exactly the finding DESIGN section 17 asks the collector to be able to
// produce.
//
// The report is published before the acknowledgement point is allowed past the
// hole, which is what makes advancing over it defensible: the events are gone
// either way, and the record of their absence is written first.
func (s *session) reportGap(first, last uint64, reason string) {
	missing := last - first + 1
	s.log.Warn("gap in guest sequence numbers",
		"first_missing_sequence", first, "last_missing_sequence", last,
		"events_missing", missing, "boot_id", s.key.boot, "reason", reason)
	s.report(event.NewInternal(typeStreamGap, event.SeverityCritical, map[string]any{
		"first_missing_sequence": first,
		"last_missing_sequence":  last,
		"events_missing":         missing,
		"boot_id":                s.key.boot,
		"reason":                 reason,
	}))
}
