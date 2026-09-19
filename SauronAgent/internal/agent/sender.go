package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/protocol"
	"github.com/define42/SauronAgent/internal/queue"
	"github.com/define42/SauronAgent/internal/spool"
	"github.com/define42/SauronAgent/internal/transport"
)

// Sender tuning that is not configurable.
const (
	// maxSendBatch bounds one read of the backlog. It keeps a huge spool
	// backlog from being pulled into memory in one go after a long outage;
	// transport.max_unacked bounds what is in flight, this bounds what is read
	// to find it.
	maxSendBatch = 256

	// idleWait is how long the send loop parks when there is nothing to send
	// and nothing outstanding. It is only a backstop -- an append or an
	// acknowledgement wakes the loop immediately -- so it costs one wakeup per
	// second on a silent guest.
	idleWait = time.Second

	// flushPoll is how often the shutdown flush re-checks for progress while
	// waiting for the host to acknowledge the last events.
	flushPoll = 20 * time.Millisecond
)

// errHostFatal marks a session that ended because the host said it was ending
// it. Reconnecting immediately against a collector that has just rejected the
// session turns one bug into a denial of service, so it is treated like a
// protocol violation for backoff purposes: the schedule keeps growing instead
// of being reset by the next successful dial.
var errHostFatal = errors.New("agent: host reported a fatal error")

// errSenderClosed means Close was called while a connection was being set up.
var errSenderClosed = errors.New("agent: sender is closed")

// backlog is the buffer the sender delivers from: the disk spool when one is
// configured, and an in-memory list of unacknowledged events when it is not.
//
// The interface exists because the two differ in exactly one interesting way.
// The spool is unbounded from the sender's point of view (its size cap is
// enforced inside it, and what it discards is reported through DrainDropped),
// so it accepts every event immediately. The memory backlog is bounded by
// transport.max_unacked, so it makes the pump wait -- which leaves the events
// in the queue, where an overflow is counted and named. Neither ever drops an
// event without accounting for it.
type backlog interface {
	// Reserve blocks until the backlog can accept one more event.
	Reserve(ctx context.Context) error
	// Release gives back a reservation whose event was never appended.
	Release()
	// Append records an event that already carries a sequence number.
	Append(e *event.Event) error
	// Next returns up to max unacknowledged events in sequence order. It is
	// idempotent: only Ack advances anything, so the caller must track what it
	// has already sent.
	Next(max int) ([]*event.Event, error)
	// Ack discards every event up to and including seq.
	Ack(seq uint64) error
	// FirstUnacked is the lowest sequence still held.
	FirstUnacked() uint64
	// LastSequence is the highest sequence ever appended.
	LastSequence() uint64
	// PendingCount is how many events are held but not acknowledged.
	PendingCount() int
	// Bytes is how much disk the backlog occupies, or 0 for memory.
	Bytes() int64
}

// senderOptions configures a sender. It is unexported: the sender is an
// implementation detail of Agent, not a second public API.
type senderOptions struct {
	cfg          config.Agent
	id           identity.Identity
	metrics      *metrics.Agent
	log          *slog.Logger
	dialer       transport.Dialer
	queue        *queue.Queue
	spool        *spool.Spool
	emit         func(*event.Event)
	auditEnabled bool
	// resume lifts the agent's sequence numbering above a position the host
	// already holds for this boot id. See adoptHostPosition. It may be nil,
	// which only costs the numbering lift: the rest of the reconciliation is
	// the sender's own.
	resume func(hostThrough uint64)
}

// sender owns the connection to the host collector.
//
// It is the only part of the agent that talks to the host, and the only part
// that is allowed to be slow: everything upstream of the queue keeps running
// while it dials, backs off, retries and replays. Three goroutines share one
// connection during a session -- the send loop, one receive loop and the
// heartbeat -- which is safe because protocol.Conn.Send is mutex-protected.
// Receive is not, so there is exactly one reader.
type sender struct {
	cfg          config.Agent
	id           identity.Identity
	metrics      *metrics.Agent
	log          *slog.Logger
	dialer       transport.Dialer
	queue        *queue.Queue
	backlog      backlog
	emit         func(*event.Event)
	auditEnabled bool
	resume       func(hostThrough uint64)
	started      time.Time

	// wake is a one-slot doorbell: the pump rings it after an append and the
	// receive loop after an acknowledgement, so the send loop reacts at once
	// instead of waiting for its backstop timer.
	wake chan struct{}

	// ackedThrough is the highest cumulative acknowledgement applied. The
	// receive goroutine publishes it and the send loop consumes it.
	ackedThrough atomic.Uint64
	// highestSent is the highest sequence ever put on the wire, across
	// sessions, which is what distinguishes a first delivery from a replay.
	highestSent atomic.Uint64
	// hostAhead is the highest host position already reconciled by
	// adoptHostPosition. It keeps the report of a host that is ahead of this
	// agent's numbering to one line per occurrence instead of one per
	// acknowledgement.
	hostAhead atomic.Uint64
	// lastPong is the Unix nanosecond time of the last PONG, for the
	// heartbeat's liveness check.
	lastPong atomic.Int64

	// oversized holds sequences the host's payload limit refuses. Retrying one
	// forever would wedge delivery of everything behind it, so it is reported
	// as a loss once and then skipped; the entries are pruned as
	// acknowledgements pass them.
	oversizedMu sync.Mutex
	oversized   map[uint64]bool

	// Accounting for events the spool would not accept. It is drained by the
	// agent's loss poller, which turns it into a sauron.spool.error event;
	// bounding it to one event per tick is what keeps an append failure from
	// generating an event that fails to append in the same way.
	failMu     sync.Mutex
	failed     uint64
	failedLow  uint64
	failedHigh uint64

	// pumpDone is closed when the queue has been drained into the backlog for
	// the last time. The shutdown flush waits for it so that a planned stop
	// delivers what was collected rather than truncating it.
	pumpDone chan struct{}

	mu     sync.Mutex
	conn   *protocol.Conn
	closed bool
}

// newSender builds the transport loop.
func newSender(opts senderOptions) *sender {
	s := &sender{
		cfg:          opts.cfg,
		id:           opts.id,
		metrics:      opts.metrics,
		log:          opts.log,
		dialer:       opts.dialer,
		queue:        opts.queue,
		emit:         opts.emit,
		auditEnabled: opts.auditEnabled,
		resume:       opts.resume,
		started:      time.Now(),
		wake:         make(chan struct{}, 1),
		oversized:    make(map[uint64]bool),
		pumpDone:     make(chan struct{}),
	}
	if opts.spool != nil {
		s.backlog = &spoolBacklog{Spool: opts.spool}
	} else {
		s.backlog = newMemBacklog(opts.cfg.Transport.MaxUnacked)
	}
	return s
}

// run connects, delivers and reconnects until ctx is cancelled.
//
// Cancellation is an orderly shutdown and returns nil. Every other failure is
// answered by reconnecting with backoff rather than by returning: the whole
// point of the spool is that a host outage is a delay and not a reason for the
// guest to stop collecting.
func (s *sender) run(ctx context.Context) error {
	go func() {
		defer close(s.pumpDone)
		s.pump(ctx)
	}()
	// The pump is the only writer to the spool, so it has to be finished
	// before Close can release it.
	defer func() { <-s.pumpDone }()

	bo := transport.NewBackoff(transport.BackoffOptions{
		Initial:    s.cfg.Reconnect.InitialDelay.Duration(),
		Max:        s.cfg.Reconnect.MaxDelay.Duration(),
		Multiplier: s.cfg.Reconnect.Multiplier,
		Jitter:     s.cfg.Reconnect.Jitter,
	})

	var (
		everConnected bool
		// misbehaved records that the last failure was the host's fault. Such
		// a host does not get its backoff reset by the next successful dial:
		// reconnecting at full speed against a collector that answers with
		// garbage is how one bug becomes an outage for everyone.
		misbehaved bool
	)

	for {
		if ctx.Err() != nil {
			return nil
		}

		attempt := bo.Attempts() + 1
		conn, ready, err := s.connect(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, errSenderClosed) {
				// Close was called. Retrying would only build connections for
				// it to close again.
				return nil
			}
			misbehaved = s.reportFailure(err, attempt)
			if bo.Wait(ctx) != nil {
				return nil
			}
			continue
		}

		if everConnected {
			s.metrics.VSOCKReconnects.Add(1)
		}
		if !misbehaved {
			bo.Reset()
		}
		misbehaved = false
		everConnected = true
		s.log.Info("connected to the host collector",
			"peer", s.dialer.String(),
			"attempt", attempt,
			"session_id", ready.SessionID,
			"resume_from", ready.ResumeFrom)
		s.emit(event.NewTransportConnected(s.dialer.String(), attempt))

		serr := s.session(ctx, conn, ready)
		s.dropConn(conn)
		if ctx.Err() != nil {
			// The session already sent SHUTDOWN if it could. Nothing that
			// happens after cancellation is a failure worth reporting.
			return nil
		}
		misbehaved = s.reportFailure(serr, bo.Attempts()+1)
		if bo.Wait(ctx) != nil {
			return nil
		}
	}
}

// reportFailure turns a lost session into telemetry and reports whether the
// host was at fault.
//
// A transport failure is a warning: the spool still holds everything. A
// protocol violation is a statement about the peer and is reported separately
// and loudly, because a collector that sends frames this protocol does not
// define is either broken or not the collector.
func (s *sender) reportFailure(err error, attempt int) bool {
	reason := "connection closed by the host"
	if err != nil {
		reason = err.Error()
	}
	s.metrics.SendErrors.Add(1)

	violation := protocol.IsProtocolError(err)
	if violation {
		s.log.Error("the host collector violated the protocol", "error", err, "peer", s.dialer.String())
		s.emit(event.NewInternal(event.TypeProtocolViolation, "", map[string]any{
			"reason": reason,
			"peer":   s.dialer.String(),
		}))
	} else {
		s.log.Warn("lost the connection to the host collector", "error", err, "attempt", attempt)
	}
	s.emit(event.NewTransportDisconnected(reason, attempt))
	return violation || errors.Is(err, errHostFatal)
}

// connect dials the collector and completes the handshake.
func (s *sender) connect(ctx context.Context) (*protocol.Conn, protocol.Ready, error) {
	var ready protocol.Ready

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	nc, err := s.dialer.Dial(dialCtx)
	if err != nil {
		return nil, ready, err
	}

	limit := payloadLimit(s.cfg.Transport.MaxPayloadSize)
	conn := protocol.NewConn(nc, limit)
	if !s.adoptConn(conn) {
		conn.Close()
		return nil, ready, errSenderClosed
	}

	// Every field here is informational and the host treats it as such: the
	// CID of this connection is the identity, not anything the guest says
	// about itself. first_sequence is the exception that earns its place -- it
	// is what lets the host tell "events 100-200 were lost" from "the agent
	// had them acknowledged and discarded".
	hello := protocol.Hello{
		ProtocolVersion: protocol.Version,
		AgentVersion:    s.id.Version,
		Hostname:        s.id.Hostname,
		BootID:          s.id.BootID,
		MachineID:       s.id.MachineID,
		Kernel:          s.id.Kernel,
		FirstSequence:   s.backlog.FirstUnacked(),
	}
	if err := conn.Send(protocol.MsgHello, 0, hello, s.writeTimeout()); err != nil {
		s.dropConn(conn)
		return nil, ready, err
	}

	f, err := conn.Receive(handshakeTimeout)
	if err != nil {
		s.dropConn(conn)
		return nil, ready, err
	}
	switch f.Type {
	case protocol.MsgReady:
		if err := protocol.DecodePayload(f, &ready); err != nil {
			s.dropConn(conn)
			return nil, ready, err
		}
	case protocol.MsgError:
		var em protocol.ErrorMessage
		if derr := protocol.DecodePayload(f, &em); derr != nil {
			s.dropConn(conn)
			return nil, ready, derr
		}
		s.dropConn(conn)
		return nil, ready, fmt.Errorf("%w: %s: %s", errHostFatal, em.Code, em.Message)
	default:
		s.dropConn(conn)
		// Wrapping a framing error is what classifies this as the peer's
		// fault rather than the link's: a frame that is legal but not allowed
		// in this state is still a statement about the peer.
		return nil, ready, fmt.Errorf("%w: expected READY, got %s", protocol.ErrBadType, f.Type)
	}

	if ready.ProtocolVersion != protocol.Version {
		s.dropConn(conn)
		return nil, ready, fmt.Errorf("%w: host speaks version %d", protocol.ErrBadVersion, ready.ProtocolVersion)
	}

	if ready.MaxPayloadSize > 0 && ready.MaxPayloadSize < limit {
		// The host will reject and close on a frame larger than its own limit,
		// so the codec is rebuilt with the smaller of the two and an oversized
		// event fails locally instead. This is safe here and nowhere else: the
		// handshake ended on a frame boundary and the decoder never reads
		// ahead of one.
		conn = protocol.NewConn(nc, ready.MaxPayloadSize)
		if !s.adoptConn(conn) {
			conn.Close()
			return nil, ready, errSenderClosed
		}
	}
	return conn, ready, nil
}

// session runs one connection until it fails or the agent is shut down.
func (s *sender) session(ctx context.Context, conn *protocol.Conn, ready protocol.Ready) error {
	// READY.resume_from is the host stating that it durably holds everything
	// through that sequence -- exactly what an ACK states -- so it is applied
	// as one. Merely skipping the send without releasing the backlog would
	// leave events pinned in the spool forever whenever no newer event ever
	// arrives to be acknowledged. It may legitimately name a sequence this
	// agent never produced; applyAck's adoptHostPosition is where that is
	// reconciled.
	if ready.ResumeFrom > 0 {
		s.applyAck(ready.ResumeFrom)
	}
	s.lastPong.Store(time.Now().UnixNano())

	// The session's own context is deliberately not derived from the agent's.
	// An orderly shutdown cancels the agent context and then needs the receive
	// goroutine to keep applying acknowledgements while the flush finishes; a
	// derived context would tear the session down at exactly that moment and
	// turn a planned stop into an unacknowledged backlog.
	sctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		once sync.Once
		fail error
		wg   sync.WaitGroup
	)
	setFail := func(err error) {
		if err == nil || sctx.Err() != nil {
			// A read that failed because we closed the connection on the way
			// out is not the reason the session ended.
			return
		}
		once.Do(func() { fail = err })
		cancel()
	}

	wg.Add(2)
	go func() { defer wg.Done(); setFail(s.recvLoop(conn)) }()
	go func() { defer wg.Done(); setFail(s.heartbeatLoop(sctx, conn)) }()

	err := s.sendLoop(ctx, sctx, conn)
	cancel()
	// Closing is what unblocks the receive goroutine: it is parked in a read
	// with no deadline, which is exactly what a quiet host should cost.
	conn.Close()
	wg.Wait()

	if err == nil {
		err = fail
	}
	return err
}

// sendLoop delivers events from the backlog until the session or the agent
// ends.
//
// Outstanding events are tracked here and nowhere else. spool.Next is
// idempotent -- it returns the same events until an Ack moves the cursor -- so
// without an in-flight list the sender would re-send the whole backlog on
// every pass. The list is also what caps outstanding events at
// transport.max_unacked, and it is deliberately discarded on reconnect:
// anything that was in flight when the connection died may never have arrived,
// so it is sent again. That is the at-least-once guarantee.
func (s *sender) sendLoop(ctx, sctx context.Context, conn *protocol.Conn) error {
	var (
		inflight []uint64
		// sentThrough is the highest sequence this session has already put on
		// the wire or permanently skipped. It only ever moves forward, so one
		// session cannot send the same sequence twice however the host
		// behaves, and every pass that sends something makes strict progress
		// through a finite backlog. It starts at zero on a new session on
		// purpose: whatever was in flight when the last connection died may
		// never have arrived and is sent again.
		//
		// Deriving this from the tail of the in-flight list instead is what
		// made the loop hot. A cumulative acknowledgement ahead of our own
		// numbering empties the in-flight list the moment anything is sent,
		// which reset the watermark to zero, and the same events were read
		// back and sent again without the loop ever reaching its wait. See
		// adoptHostPosition.
		sentThrough  uint64
		lastProgress = time.Now()
		ackTimeout   = s.cfg.Transport.AckTimeout.Duration()
	)

	for {
		s.reconcile()
		if n := trimInflight(&inflight, s.ackedThrough.Load()); n > 0 {
			s.metrics.EventsAcknowledged.Add(uint64(n))
			lastProgress = time.Now()
		}

		sent, err := s.dispatch(conn, &inflight, &sentThrough)
		if err != nil {
			return err
		}
		if sent > 0 {
			continue
		}

		wait := idleWait
		if len(inflight) > 0 && ackTimeout > 0 {
			// A host that accepts bytes and never acknowledges is worse than
			// one that is down: the spool grows, nothing is released, and
			// from the guest the link looks healthy. Treat the silence as a
			// dead connection and reconnect.
			remaining := ackTimeout - time.Since(lastProgress)
			if remaining <= 0 {
				return fmt.Errorf("agent: %d events unacknowledged for %s", len(inflight), ackTimeout)
			}
			if remaining < wait {
				wait = remaining
			}
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return s.flush(sctx, conn, inflight, sentThrough)
		case <-sctx.Done():
			timer.Stop()
			return nil
		case <-s.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// dispatch sends whatever the backlog holds that this session has not already
// put on the wire, and reports how many events went out.
//
// sentThrough is this session's high-water mark and dispatch only ever moves
// it forward -- for an event it sent, and for one it will never send on this
// connection (one the host already holds, or one too large for the link).
// Every event is therefore disposed of exactly once per session, which is what
// bounds the send loop.
func (s *sender) dispatch(conn *protocol.Conn, inflight *[]uint64, sentThrough *uint64) (int, error) {
	room := s.cfg.Transport.MaxUnacked - len(*inflight)
	if room <= 0 {
		return 0, nil
	}
	if room > maxSendBatch {
		room = maxSendBatch
	}

	if !s.unsent(*sentThrough) {
		// Everything the backlog holds has already been sent or released.
		// Skipping the read keeps the steady state off the disk entirely and
		// is what sends the loop to its wait instead of round again.
		return 0, nil
	}

	// Next starts at FirstUnacked, which still includes what is in flight, so
	// the batch has to be large enough to reach past it.
	events, err := s.backlog.Next(len(*inflight) + room)
	if err != nil {
		// Nothing is lost: the events stay in the backlog and the next
		// attempt reads them again.
		return 0, fmt.Errorf("agent: reading the backlog: %w", err)
	}

	acked := s.ackedThrough.Load()
	sent := 0
	for _, e := range events {
		if e == nil || e.Sequence <= *sentThrough {
			continue
		}
		if e.Sequence <= acked {
			// The host has already told us it durably holds this sequence, so
			// sending it would be a duplicate it is certain to suppress. That
			// normally cannot happen -- an acknowledged event has been
			// released from the backlog -- but it does when the host's
			// position is ahead of our numbering and the event was numbered
			// before we reconciled with it. reconcile releases it; here it is
			// simply stepped over.
			*sentThrough = e.Sequence
			continue
		}
		if s.isOversized(e.Sequence) {
			*sentThrough = e.Sequence
			continue
		}
		if err := conn.Send(protocol.MsgEvent, e.Sequence, protocol.EventMessage{Event: e}, s.writeTimeout()); err != nil {
			if errors.Is(err, protocol.ErrPayloadTooLarge) {
				// Nothing was written -- the encoder checks the size before it
				// touches the wire -- so the connection is still usable. The
				// event never can be, though, and retrying it forever would
				// block everything behind it.
				s.reportOversized(e, err)
				*sentThrough = e.Sequence
				continue
			}
			return sent, err
		}
		*inflight = append(*inflight, e.Sequence)
		*sentThrough = e.Sequence
		sent++
		s.metrics.EventsSent.Add(1)
		if e.Sequence <= s.highestSent.Load() {
			s.metrics.EventsResent.Add(1)
		} else {
			s.highestSent.Store(e.Sequence)
		}
		if len(*inflight) >= s.cfg.Transport.MaxUnacked {
			break
		}
	}
	return sent, nil
}

// flush is the orderly stop: deliver what is left, then say goodbye.
//
// The SHUTDOWN frame is the point of it. A collector that sees a stream end
// with SHUTDOWN is watching maintenance; one that sees it stop is watching
// something worth investigating, and the difference has to survive a slow
// flush. So the flush is bounded and SHUTDOWN is sent either way.
func (s *sender) flush(sctx context.Context, conn *protocol.Conn, inflight []uint64, sentThrough uint64) error {
	deadline := time.Now().Add(s.flushTimeout())

	// Wait for collection to hand its last events over. Until the pump has
	// finished, the backlog does not yet hold everything that was collected.
	wait := time.NewTimer(time.Until(deadline))
	select {
	case <-s.pumpDone:
	case <-sctx.Done():
	case <-wait.C:
	}
	wait.Stop()

	for time.Now().Before(deadline) && sctx.Err() == nil {
		s.reconcile()
		trimInflight(&inflight, s.ackedThrough.Load())
		sent, err := s.dispatch(conn, &inflight, &sentThrough)
		if err != nil {
			return err
		}
		if sent > 0 {
			continue
		}
		// Nothing outstanding and nothing left this session has not already
		// disposed of. Testing for an empty backlog instead would keep polling
		// for the whole deadline over events that can never go out on this
		// connection -- ones the host already holds, or ones too large for it.
		if len(inflight) == 0 && !s.unsent(sentThrough) {
			break
		}
		poll := time.NewTimer(flushPoll)
		select {
		case <-s.wake:
		case <-poll.C:
		case <-sctx.Done():
		}
		poll.Stop()
	}

	if pending := s.backlog.PendingCount(); pending > 0 {
		s.log.Warn("shutting down with events the host has not acknowledged",
			"events", pending, "first_unacked", s.backlog.FirstUnacked())
	}

	sd := protocol.Shutdown{
		Reason:       "agent shutting down",
		LastSequence: s.highestSent.Load(),
	}
	if err := conn.Send(protocol.MsgShutdown, 0, sd, s.writeTimeout()); err != nil {
		s.log.Warn("could not tell the host this was a planned stop", "error", err)
	}
	return nil
}

// recvLoop is the session's single reader.
//
// It applies acknowledgements as they arrive rather than handing them to the
// send loop, so that a spool truncation is never delayed by a busy sender.
func (s *sender) recvLoop(conn *protocol.Conn) error {
	for {
		// No read deadline: a quiet host is normal, and liveness is the
		// heartbeat's and the acknowledgement timeout's job. The connection is
		// closed to unblock this when the session ends.
		f, err := conn.Receive(0)
		if err != nil {
			return err
		}

		switch f.Type {
		case protocol.MsgAck:
			var ack protocol.Ack
			if err := protocol.DecodePayload(f, &ack); err != nil {
				return err
			}
			// The sequence of an ACK is in its payload; the header's is
			// meaningless for everything but an EVENT and is ignored.
			s.applyAck(ack.Sequence)
			s.signal()

		case protocol.MsgPong:
			var pong protocol.Pong
			if err := protocol.DecodePayload(f, &pong); err != nil {
				return err
			}
			s.lastPong.Store(time.Now().UnixNano())

		case protocol.MsgError:
			var em protocol.ErrorMessage
			if err := protocol.DecodePayload(f, &em); err != nil {
				return err
			}
			s.log.Error("the host collector reported an error",
				"code", em.Code, "message", em.Message, "fatal", em.Fatal)
			if em.Fatal {
				return fmt.Errorf("%w: %s: %s", errHostFatal, em.Code, em.Message)
			}

		case protocol.MsgShutdown:
			var sd protocol.Shutdown
			if err := protocol.DecodePayload(f, &sd); err != nil {
				return err
			}
			s.log.Info("the host collector is shutting down", "reason", sd.Reason)
			// Not a fault: the collector said it was stopping, so reconnect on
			// the ordinary schedule and keep spooling meanwhile.
			return fmt.Errorf("agent: the host collector closed the session: %s", sd.Reason)

		default:
			// HELLO, READY, EVENT and PING are the agent's own messages. A
			// host sending one is not a collector this agent can talk to.
			s.sendError(conn, protocol.ErrCodeUnexpectedType,
				fmt.Sprintf("%s is not a message the host may send", f.Type))
			return fmt.Errorf("%w: the host sent %s", protocol.ErrBadType, f.Type)
		}
	}
}

// heartbeatLoop sends PING with the counters that let the host tell a healthy
// quiet guest from a wedged one (DESIGN.md section 29).
func (s *sender) heartbeatLoop(sctx context.Context, conn *protocol.Conn) error {
	interval := s.cfg.Heartbeat.Interval.Duration()
	if interval <= 0 {
		return nil
	}
	timeout := s.cfg.Heartbeat.Timeout.Duration()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-sctx.Done():
			return nil
		case <-t.C:
		}

		if err := conn.Send(protocol.MsgPing, 0, s.ping(), s.writeTimeout()); err != nil {
			return err
		}
		// A host that takes the bytes but never answers is a half-open link;
		// the events are piling up in the spool either way, so it is better to
		// reconnect than to keep talking into it.
		if timeout > 0 {
			if silent := time.Since(time.Unix(0, s.lastPong.Load())); silent > timeout {
				return fmt.Errorf("agent: no PONG from the host for %s", silent.Truncate(time.Millisecond))
			}
		}
	}
}

// ping snapshots the counters the host uses to judge this guest.
//
// They are advisory by definition -- they come from the guest -- but they are
// what makes a disabled audit subsystem or a queue that never drains visible
// without a single audit event arriving.
func (s *sender) ping() protocol.Ping {
	m := s.metrics.Snapshot()
	spoolBytes := s.backlog.Bytes()
	if spoolBytes < 0 {
		spoolBytes = 0
	}
	return protocol.Ping{
		UptimeSeconds:  uint64(time.Since(s.started) / time.Second),
		EventsReceived: m.EventsCreated,
		EventsSent:     m.EventsSent,
		EventsSpooled:  uint64(s.backlog.PendingCount()),
		EventsDropped:  m.EventsDropped,
		AuditEnabled:   s.auditEnabled,
		QueueDepth:     uint64(s.queue.Len()),
		SpoolBytes:     uint64(spoolBytes),
	}
}

// pump moves events from the queue into the backlog.
//
// This is the stage that makes a host outage a delay instead of a loss: it
// runs whether or not a connection exists, so the bounded queue keeps emptying
// into the spool while the sender is dialling. With no spool it is the
// backlog's Reserve that blocks instead, which leaves the events in the queue
// where an overflow is counted and named.
func (s *sender) pump(ctx context.Context) {
	for {
		if err := s.backlog.Reserve(ctx); err != nil {
			// Only the memory backlog blocks, and only shutdown unblocks it.
			// Whatever is still queued has nowhere durable to go, so it is at
			// least counted and logged rather than vanishing quietly.
			if n := s.queue.Len(); n > 0 {
				s.metrics.EventsDropped.Add(uint64(n))
				s.log.Error("stopping with events in the queue and no spool to put them in",
					"events", n)
			}
			return
		}

		// A background context on purpose: the queue reports ErrClosed only
		// once it has been closed AND drained, and that is what makes a
		// shutdown flush the backlog instead of truncating it. The agent
		// always closes the queue, so this cannot park forever.
		e, err := s.queue.Get(context.Background())
		if err != nil {
			return
		}
		if err := s.backlog.Append(e); err != nil {
			// The reservation is handed back explicitly: a refused append that
			// kept its slot would shrink the bound on every failure until the
			// pump stopped for good.
			s.backlog.Release()
			s.recordAppendFailure(e, err)
			continue
		}
		s.signal()
	}
}

// applyAck releases everything through seq from the backlog.
//
// seq is the host's cumulative position, and it reaches here from the two
// places that state the same thing: an ACK frame, and READY.resume_from at the
// start of a session. Both mean "everything up to and including seq is durably
// held by the host", which is exactly what entitles the agent to delete those
// events.
func (s *sender) applyAck(seq uint64) {
	if seq == 0 {
		return
	}
	s.adoptHostPosition(seq)
	if err := s.backlog.Ack(seq); err != nil {
		s.log.Error("acknowledged events could not be released from the backlog",
			"sequence", seq, "error", err)
	}
	for {
		cur := s.ackedThrough.Load()
		if seq <= cur || s.ackedThrough.CompareAndSwap(cur, seq) {
			break
		}
	}
	s.pruneOversized(seq)
}

// adoptHostPosition reconciles a host position that is ahead of every sequence
// this agent has produced.
//
// This is not exotic and it is not the host misbehaving. The host keeps its
// deduplication watermark per (CID, boot id), and the boot id is the machine's
// -- it survives an agent restart. So any restart that loses the agent's own
// record of where it had got to leaves the host holding sequences the fresh
// agent is about to hand out again from 1: a spool that was reset, rotated
// away or moved, a spool directory on a volume that did not come back, or an
// agent configured without a spool at all.
//
// Three components have to agree about what such a position means, and the hot
// loop this guards against came from them disagreeing:
//
//   - The spool clamps Ack(seq) to what it actually holds, on the sound ground
//     that the host cannot have acknowledged what was never sent to it. A
//     position above our numbering therefore releases nothing and is forgotten
//     by the spool.
//   - The sender's in-flight list is the only thing that stops the idempotent
//     backlog.Next from handing the same events back on the next pass, and it
//     is trimmed against the acknowledged position. A position above every
//     sequence we will ever number empties that list the instant anything is
//     sent.
//   - The send loop only waits when it sent nothing.
//
// Together: every event was sent, immediately treated as acknowledged, read
// back out of the backlog and sent again, as fast as the CPU allowed.
//
// The reconciliation is to believe the host. It genuinely holds those
// sequences for this boot id -- either our own earlier events, whose record we
// have lost, or events we can never tell apart from ours, because the
// deduplication key is (CID, boot id, sequence) and anything we send under
// those numbers is suppressed as a duplicate. So nothing below the position is
// re-sent, reconcile releases whatever the backlog still holds below it, and
// the agent's own numbering is lifted above it. Lifting the numbering is the
// part that matters beyond this connection: it keeps sequence numbers from
// going backwards within a boot, so the numbers issued from here on are new to
// the host and a cumulative ACK goes on meaning what it says.
//
// It is reported once per occurrence, at WARN. It says the agent's record of
// its own position was lost, which an operator should see -- but once, not on
// every acknowledgement that follows.
func (s *sender) adoptHostPosition(seq uint64) {
	if seq <= s.backlog.LastSequence() {
		// The ordinary case: the host is acknowledging events we hold.
		return
	}
	for {
		prev := s.hostAhead.Load()
		if seq <= prev {
			// Already reconciled at least this far.
			return
		}
		if s.hostAhead.CompareAndSwap(prev, seq) {
			break
		}
	}

	// backlog_pending is what this costs: those events carry numbers the host
	// says it already holds, so they are released rather than delivered. The
	// host would suppress them as duplicates whatever the agent did with them,
	// and this line is where an operator sees that the guest's numbering was
	// reset under a host that had not forgotten the boot.
	s.log.Warn("the host holds sequences this agent never produced; continuing above them",
		"host_through", seq,
		"highest_sent", s.highestSent.Load(),
		"backlog_last_sequence", s.backlog.LastSequence(),
		"backlog_pending", s.backlog.PendingCount())

	// The guard is the end of the sequence space: at the maximum there is no
	// number left to continue from, and the wrap would restart numbering at 1
	// under a host that holds everything -- the very state being reconciled.
	if s.resume != nil && seq < ^uint64(0) {
		s.resume(seq)
	}
}

// reconcile releases anything the backlog still holds at or below the host's
// cumulative position.
//
// applyAck already does this the moment the position arrives, but the backlog
// can only release what it holds at that moment, and two things arrive out of
// order. READY.resume_from and an ACK can name a sequence the pump has not
// appended yet, and the spool answers such an acknowledgement by clamping it
// to what it holds rather than remembering it. Without this second pass those
// events stay pending for good -- the host will not acknowledge them again,
// because it suppresses them as duplicates -- and the send loop reads them
// back on every pass.
//
// In steady state it is two cheap accessors and no work at all.
func (s *sender) reconcile() {
	through := s.ackedThrough.Load()
	if through == 0 || s.backlog.PendingCount() == 0 || s.backlog.FirstUnacked() > through {
		return
	}
	if err := s.backlog.Ack(through); err != nil {
		s.log.Error("acknowledged events could not be released from the backlog",
			"sequence", through, "error", err)
	}
}

// unsent reports whether the backlog holds anything above sentThrough, i.e.
// whether there is work this session has not already disposed of. It is the
// test that decides whether the send loop has something to do or has to wait.
func (s *sender) unsent(sentThrough uint64) bool {
	return s.backlog.PendingCount() > 0 && s.backlog.LastSequence() > sentThrough
}

// sendError tells the peer why the session is ending. A failure to send it is
// ignored: the connection is being abandoned anyway.
func (s *sender) sendError(conn *protocol.Conn, code protocol.ErrorCode, msg string) {
	_ = conn.Send(protocol.MsgError, 0, protocol.ErrorMessage{
		Code:    code,
		Message: msg,
		Fatal:   true,
	}, s.writeTimeout())
}

// reportOversized records an event that cannot be represented on this
// connection and reports it as the evidence loss it is.
func (s *sender) reportOversized(e *event.Event, err error) {
	s.oversizedMu.Lock()
	already := s.oversized[e.Sequence]
	s.oversized[e.Sequence] = true
	s.oversizedMu.Unlock()
	if already {
		return
	}

	s.metrics.EventsDropped.Add(1)
	s.log.Error("event is too large for the transport and will not be delivered",
		"sequence", e.Sequence, "type", e.Type, "error", err)
	// There is no more specific internal type for "this agent built a frame
	// the protocol cannot carry", and it is a protocol-level failure: the
	// event exists, is numbered, and can never be delivered on this link.
	s.emit(event.NewInternal(event.TypeProtocolViolation, event.SeverityCritical, map[string]any{
		"reason":                 "event exceeds the maximum payload size and cannot be delivered",
		"events_dropped":         uint64(1),
		"first_missing_sequence": e.Sequence,
		"last_missing_sequence":  e.Sequence,
		"event_type":             e.Type,
	}))
}

func (s *sender) isOversized(seq uint64) bool {
	s.oversizedMu.Lock()
	defer s.oversizedMu.Unlock()
	return s.oversized[seq]
}

// pruneOversized forgets skipped sequences the host has now acknowledged past.
func (s *sender) pruneOversized(through uint64) {
	s.oversizedMu.Lock()
	defer s.oversizedMu.Unlock()
	for seq := range s.oversized {
		if seq <= through {
			delete(s.oversized, seq)
		}
	}
}

// recordAppendFailure accounts for an event the backlog refused.
func (s *sender) recordAppendFailure(e *event.Event, err error) {
	s.metrics.EventsDropped.Add(1)
	s.log.Error("the spool refused an event", "sequence", e.Sequence, "error", err)

	s.failMu.Lock()
	defer s.failMu.Unlock()
	s.failed++
	if s.failedLow == 0 || e.Sequence < s.failedLow {
		s.failedLow = e.Sequence
	}
	if e.Sequence > s.failedHigh {
		s.failedHigh = e.Sequence
	}
}

// drainAppendFailures returns and clears the append-failure accounting, in the
// shape the other loss reports use.
func (s *sender) drainAppendFailures() (dropped uint64, firstMissing, lastMissing uint64, ok bool) {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if s.failed == 0 {
		return 0, 0, 0, false
	}
	dropped, firstMissing, lastMissing = s.failed, s.failedLow, s.failedHigh
	s.failed, s.failedLow, s.failedHigh = 0, 0, 0
	return dropped, firstMissing, lastMissing, true
}

// signal rings the send loop's doorbell without ever blocking the ringer.
func (s *sender) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// adoptConn publishes the connection so Close can tear it down, reporting
// false when the sender has already been closed.
func (s *sender) adoptConn(c *protocol.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conn = c
	return true
}

// dropConn closes c and forgets it.
func (s *sender) dropConn(c *protocol.Conn) {
	s.mu.Lock()
	if s.conn == c {
		s.conn = nil
	}
	s.mu.Unlock()
	c.Close()
}

// close releases the current connection and refuses any further one. It is
// idempotent and safe to call while run is in flight.
func (s *sender) close() error {
	s.mu.Lock()
	s.closed = true
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// writeTimeout bounds one frame write, so a host that stops reading cannot
// wedge the sender.
func (s *sender) writeTimeout() time.Duration { return s.cfg.Transport.WriteTimeout.Duration() }

// flushTimeout bounds the orderly shutdown. It never exceeds maxShutdownFlush:
// stopping the agent must not wait out an acknowledgement timeout measured in
// minutes.
func (s *sender) flushTimeout() time.Duration {
	d := s.cfg.Transport.AckTimeout.Duration()
	if d <= 0 || d > maxShutdownFlush {
		return maxShutdownFlush
	}
	return d
}

// payloadLimit converts the configured maximum payload into the codec's
// uint32, clamping rather than truncating: a configuration mistake must not
// wrap into a tiny limit that refuses every event.
func payloadLimit(size config.Size) uint32 {
	n := size.Bytes()
	if n <= 0 {
		return protocol.DefaultMaxPayloadSize
	}
	if n > int64(protocol.MaxPayloadCeiling) {
		return protocol.MaxPayloadCeiling
	}
	return uint32(n)
}

// trimInflight drops the acknowledged prefix of the in-flight list and reports
// how many entries went. Acknowledgement is cumulative, so everything at or
// below through is covered whether or not it was acknowledged individually.
func trimInflight(inflight *[]uint64, through uint64) int {
	if through == 0 || len(*inflight) == 0 {
		return 0
	}
	n := 0
	for n < len(*inflight) && (*inflight)[n] <= through {
		n++
	}
	if n == 0 {
		return 0
	}
	*inflight = append((*inflight)[:0], (*inflight)[n:]...)
	return n
}

// spoolBacklog adapts the disk spool to the backlog interface.
type spoolBacklog struct{ *spool.Spool }

// Reserve is immediate: the spool's size cap is enforced inside it, and what
// it discards to stay under the cap is reported through DrainDropped rather
// than by refusing the append. Blocking here instead would push the backlog
// into the queue, which has less room and worse durability.
func (b *spoolBacklog) Reserve(context.Context) error { return nil }

// Release has nothing to give back; Reserve took nothing.
func (b *spoolBacklog) Release() {}

// memBacklog holds unacknowledged events in memory for an agent configured
// without a spool.
//
// It is bounded by transport.max_unacked and makes the pump wait rather than
// growing: with no spool the queue is the only buffer, and an unbounded list
// here would quietly move the guest's audit backlog into a place with no
// capacity limit, no overflow accounting and no durability.
type memBacklog struct {
	// slots is the bound. A token is taken before an event is pulled from the
	// queue and returned when an acknowledgement releases it.
	slots chan struct{}

	mu      sync.Mutex
	events  []*event.Event
	lastSeq uint64
}

func newMemBacklog(maxUnacked int) *memBacklog {
	if maxUnacked <= 0 {
		maxUnacked = 1
	}
	return &memBacklog{slots: make(chan struct{}, maxUnacked)}
}

// Reserve waits for room, or for ctx to end.
func (b *memBacklog) Reserve(ctx context.Context) error {
	select {
	case b.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release returns one unused slot.
func (b *memBacklog) Release() {
	select {
	case <-b.slots:
	default:
	}
}

// Append adds an event that already carries a sequence number.
func (b *memBacklog) Append(e *event.Event) error {
	if e == nil {
		return errors.New("agent: nil event")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e.Sequence <= b.lastSeq {
		return fmt.Errorf("agent: sequence %d is not greater than the last held sequence %d",
			e.Sequence, b.lastSeq)
	}
	b.events = append(b.events, e)
	b.lastSeq = e.Sequence
	return nil
}

// Next returns up to max unacknowledged events, oldest first, without
// consuming them.
func (b *memBacklog) Next(max int) ([]*event.Event, error) {
	if max <= 0 {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if max > len(b.events) {
		max = len(b.events)
	}
	out := make([]*event.Event, max)
	copy(out, b.events[:max])
	return out, nil
}

// Ack discards every event through seq and returns the slots they held.
func (b *memBacklog) Ack(seq uint64) error {
	b.mu.Lock()
	n := 0
	for n < len(b.events) && b.events[n].Sequence <= seq {
		n++
	}
	if n > 0 {
		b.events = append(b.events[:0], b.events[n:]...)
	}
	b.mu.Unlock()

	for i := 0; i < n; i++ {
		select {
		case <-b.slots:
		default:
		}
	}
	return nil
}

// FirstUnacked is the lowest sequence still held, or the next one expected.
func (b *memBacklog) FirstUnacked() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.events) > 0 {
		return b.events[0].Sequence
	}
	return b.lastSeq + 1
}

// LastSequence is the highest sequence ever held.
func (b *memBacklog) LastSequence() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastSeq
}

// PendingCount is how many events are waiting for acknowledgement.
func (b *memBacklog) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// Bytes is zero: nothing here is on disk, which is the whole caveat of running
// without a spool.
func (b *memBacklog) Bytes() int64 { return 0 }
