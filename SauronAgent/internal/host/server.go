// Package host implements SauronHost: the hypervisor-side collector that
// accepts guest connections, validates what arrives on them, enriches events
// with trusted host metadata and hands them to the configured outputs.
//
// The collector is the only component of the system that does not run inside
// the machine it is auditing, which is the whole point of the design and also
// the reason this package treats every connection as hostile input:
//
//   - A guest's identity is the VSOCK CID of its connection, established by the
//     hypervisor (transport.PeerCID). Everything the guest says about itself
//     arrives separately under source.reported and never decides what a VM is.
//   - Every read is bounded by limits.max_payload_size before a byte of payload
//     is allocated, and every wait is bounded by a timeout, so one guest cannot
//     consume the collector on behalf of all the others.
//   - An event is acknowledged only after every sink has accepted it. An
//     acknowledgement tells the agent it may delete its only copy, so a
//     premature ACK destroys evidence.
//   - Nothing is dropped quietly. A refused connection, a malformed peer, a
//     failed output, a gap in the sequence and a silent VM each produce a
//     sauron.* event in the same stream as the audit data, because a collector
//     that fails invisibly is worse than one that is plainly down.
package host

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/protocol"
	"github.com/define42/SauronAgent/internal/transport"
)

// Host-generated event types.
//
// The agent-side types live in internal/event/categories.go. These three
// describe failures only the collector can observe, so they are named here
// rather than in the shared event vocabulary; they follow the same "sauron."
// convention and are built with event.NewInternal like every other internal
// event.
const (
	// typeStreamGap reports a hole in a guest's sequence numbers: events the
	// guest numbered and the collector never received. Either the agent
	// reported the loss itself with sauron.queue.overflow or sauron.spool.full,
	// or nobody did -- and that is a finding (protocol.md section 6).
	typeStreamGap = "sauron.stream.gap"

	// typeConnectionRejected reports a guest the collector refused: an unmapped
	// CID under allow_unknown_cids: false, or a connection limit. A refused
	// connection is a VM whose audit stream is not being collected, so it is
	// reported rather than merely counted.
	typeConnectionRejected = "sauron.connection.rejected"

	// typeOutputFailed reports an event no sink accepted. The event is not
	// acknowledged and the guest still holds it, but an output that keeps
	// failing is a silent collector, which is the failure this design exists to
	// prevent.
	typeOutputFailed = "sauron.output.failed"
)

// Options configures a collector Server.
type Options struct {
	Config  config.Host
	Sink    output.Sink
	Metrics *metrics.Host
	Logger  *slog.Logger
	// Listener overrides transport construction in tests.
	Listener transport.Listener
	// OnInternalEvent receives host-generated events such as stream loss.
	OnInternalEvent func(*output.Envelope)
	// Resolve maps a hypervisor-assigned CID to the VM it belongs to at the
	// moment a connection arrives. It lets a program whose VMs come and go --
	// and whose CIDs the hypervisor hands out as they start -- supply the
	// trusted mapping live instead of through the static vms list.
	//
	// It is consulted once per connection, only for VSOCK peers, and before
	// the vms list; ok=false falls through to that list and then to
	// limits.allow_unknown_cids. Whatever it returns is trusted exactly like a
	// vms entry, so it must derive the answer from the hypervisor and never
	// from anything the guest says. The expected flag of a resolved VM is
	// ignored: stream monitoring covers the vms list only.
	Resolve func(cid uint32) (config.VMMapping, bool)
}

// Server is the collector. It accepts guest connections on one listener and
// runs each of them as an independent session.
type Server struct {
	cfg        config.Host
	sink       output.Sink
	metrics    *metrics.Host
	log        *slog.Logger
	listener   transport.Listener
	maxPayload uint32

	enrich  *enricher
	dedup   *dedup
	report  *reporter
	monitor *monitor

	// now is the host's clock. Every ReceivedAt comes from here and never from
	// the guest, whose clock is as trustworthy as the guest is. Tests replace
	// it to make enrichment deterministic.
	now func() time.Time

	// peerCID resolves the authoritative peer identity. Production always uses
	// transport.PeerCID; tests replace it to exercise CID-dependent behaviour
	// over net.Pipe, which carries no CID of its own.
	peerCID func(net.Conn) (uint32, bool)

	mu       sync.Mutex
	perPeer  map[string]int // live connections per peer bucket
	total    int            // live connections in total
	sessions sync.WaitGroup
	seq      atomic.Uint64 // session id counter

	running      atomic.Bool
	quit         chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	listenerOnce sync.Once
	listenerErr  error
	teardownOnce sync.Once
	teardownErr  error
}

// New builds a collector.
//
// The listening socket is bound here rather than in Run so that a collector
// which cannot bind fails at startup, before anything else reports it as
// healthy. Close releases it even if Run is never called.
func New(opts Options) (*Server, error) {
	if opts.Sink == nil {
		return nil, errors.New("host: Options.Sink must be set: a collector with no sink " +
			"accepts every event, acknowledges it and discards it, which looks exactly like a " +
			"healthy deployment until the evidence is needed")
	}
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("host: invalid configuration: %w", err)
	}

	logger := opts.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	counters := opts.Metrics
	if counters == nil {
		counters = &metrics.Host{}
	}

	listener := opts.Listener
	if listener == nil {
		var err error
		switch cfg.Listen.Kind {
		case config.TransportVSOCK:
			listener, err = transport.ListenVSOCK(cfg.Listen.CID, cfg.Listen.Port)
		case config.TransportTCP:
			listener, err = transport.ListenTCP(cfg.Listen.TCPAddress)
		default:
			err = fmt.Errorf("unsupported listen.kind %q", cfg.Listen.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("host: listen: %w", err)
		}
	}

	s := &Server{
		cfg:        cfg,
		sink:       opts.Sink,
		metrics:    counters,
		log:        logger,
		listener:   listener,
		maxPayload: effectiveMaxPayload(cfg),
		enrich:     newEnricher(cfg, opts.Resolve),
		dedup:      newDedup(cfg.Limits.DedupWindow, maxTrackedStreams(cfg)),
		now:        time.Now,
		peerCID:    transport.PeerCID,
		perPeer:    make(map[string]int),
		quit:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	s.report = &reporter{
		sink:    opts.Sink,
		onEvent: opts.OnInternalEvent,
		log:     logger,
		now:     func() time.Time { return s.now() },
	}
	s.monitor = newMonitor(cfg, s.report, counters, logger, func() time.Time { return s.now() })
	return s, nil
}

// Run accepts connections until ctx is cancelled or Close is called, then
// stops accepting, lets the live sessions drain and closes the sink.
//
// Like the agent-side loops, an orderly shutdown returns nil: a collector that
// was asked to stop has not failed. Run may be called once.
func (s *Server) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("host: Run called more than once")
	}
	defer close(s.done)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Close stops Run through the same path as a cancelled context, so there
	// is one shutdown sequence rather than two.
	go func() {
		select {
		case <-ctx.Done():
		case <-s.quit:
			cancel()
		}
	}()

	// Accept blocks with no way to observe a context, so closing the listener
	// is what wakes it. teardown closes it exactly once.
	stopAccept := context.AfterFunc(ctx, func() { _ = s.closeListener() })
	defer stopAccept()

	var monitorDone chan struct{}
	if s.cfg.Monitor.Enabled {
		monitorDone = make(chan struct{})
		go func() {
			defer close(monitorDone)
			s.monitor.run(ctx)
		}()
	}

	s.log.Info("collector listening",
		"address", s.listener.Addr(),
		"kind", string(s.cfg.Listen.Kind),
		"hypervisor", s.cfg.Host.Name)

	runErr := s.accept(ctx)
	// A fatal listener error ends acceptance without cancelling the parent.
	// Stop the sessions and monitor before waiting for either to finish.
	cancel()

	// Sessions are woken by the same context and finish what they were doing;
	// the sink must stay open until the last of them has stopped writing to it.
	s.sessions.Wait()
	if monitorDone != nil {
		<-monitorDone
	}

	if err := s.teardown(); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

// accept is the accept loop. It returns nil when the listener was closed as
// part of an orderly shutdown.
func (s *Server) accept(ctx context.Context) error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// A deadline on the listener is not a reason to stop serving
				// every other guest.
				s.log.Warn("accept timed out", "error", err)
				continue
			}
			// Anything else means the listening socket is gone. Continuing
			// would spin on the same error and the collector would look alive
			// while accepting nothing.
			return fmt.Errorf("host: accept: %w", err)
		}
		s.serve(ctx, conn)
	}
}

// serve admits a connection and starts its session.
func (s *Server) serve(ctx context.Context, conn net.Conn) {
	p := s.peerOf(conn)
	// The identity is resolved exactly once, before a byte is read, and every
	// later decision about this connection -- admission, the rejection report,
	// the source of each event -- uses this one answer. Resolving again could
	// give a different one if the hypervisor reassigned the CID in between.
	src := s.enrich.source(p)

	release, reason, ok := s.admit(p, src)
	if !ok {
		s.reject(ctx, conn, p, src, reason)
		return
	}

	s.metrics.ConnectionsAccepted.Add(1)
	s.metrics.ConnectionsActive.Add(1)
	sess := s.newSession(conn, p, src)

	s.sessions.Add(1)
	go func() {
		defer func() {
			s.metrics.ConnectionsActive.Add(-1)
			release()
			s.sessions.Done()
		}()
		sess.run(ctx)
	}()
}

// rejection reasons, reported as the "reason" field of
// sauron.connection.rejected and named in the log line.
const (
	reasonUnauthorized = "unauthorized"
	reasonMaxConns     = "max_connections"
	reasonMaxConnsCID  = "max_connections_per_cid"
)

// admit applies the connection limits and the CID policy.
//
// The limits are keyed on the peer bucket -- the CID for a VSOCK guest -- so
// that one guest reconnecting in a loop exhausts its own allowance and not the
// collector's. A connection that is admitted returns a release function that
// must be called exactly once when its session ends.
func (s *Server) admit(p peer, src output.Source) (release func(), reason string, ok bool) {
	if !s.enrich.authorized(src) {
		return nil, reasonUnauthorized, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Limits.MaxConnections > 0 && s.total >= s.cfg.Limits.MaxConnections {
		return nil, reasonMaxConns, false
	}
	bucket := p.bucket()
	if s.cfg.Limits.MaxConnectionsPerCID > 0 && s.perPeer[bucket] >= s.cfg.Limits.MaxConnectionsPerCID {
		return nil, reasonMaxConnsCID, false
	}
	s.total++
	s.perPeer[bucket]++

	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.total--
			if n := s.perPeer[bucket] - 1; n > 0 {
				s.perPeer[bucket] = n
			} else {
				delete(s.perPeer, bucket)
			}
		})
	}, "", true
}

// reject refuses a connection, tells the peer why and records it.
//
// A refused connection is not a non-event: it is a VM whose audit stream the
// collector is not receiving. It is counted, logged with the CID and reported
// as sauron.connection.rejected so that a guest being locked out is as visible
// as one that goes quiet.
func (s *Server) reject(ctx context.Context, conn net.Conn, p peer, src output.Source, reason string) {
	s.metrics.ConnectionsRejected.Add(1)

	code := protocol.ErrCodeOverloaded
	msg := fmt.Sprintf("connection refused: %s limit reached", reason)
	if reason == reasonUnauthorized {
		code = protocol.ErrCodeUnauthorized
		msg = "connection refused: this CID has no entry in the collector's vms list and " +
			"limits.allow_unknown_cids is false"
	}

	s.log.Warn("connection rejected",
		"cid", p.logCID(), "peer", p.addr, "hypervisor_backed", p.vsock,
		"reason", reason, "limit_max_connections", s.cfg.Limits.MaxConnections,
		"limit_max_connections_per_cid", s.cfg.Limits.MaxConnectionsPerCID)

	// Best effort: telling the peer why lets a well-behaved agent back off
	// instead of reconnecting in a tight loop, which would turn a limit into a
	// denial of service against the collector.
	pc := protocol.NewConn(conn, s.maxPayload)
	_ = pc.Send(protocol.MsgError, 0, &protocol.ErrorMessage{
		Code: code, Message: msg, Fatal: true,
	}, s.writeTimeout())
	_ = pc.Close()

	s.report.publish(ctx, src, event.NewInternal(typeConnectionRejected,
		event.SeverityWarning, map[string]any{
			"reason":            reason,
			"cid":               p.logCID(),
			"peer":              p.addr,
			"hypervisor_backed": p.vsock,
		}))
}

// Close stops the collector and releases its resources. It is idempotent and
// safe to call while Run is in flight, in which case it waits for Run to finish
// draining the sessions rather than closing the sink underneath them.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.quit)
	})
	if s.running.Load() {
		<-s.done
	}
	return s.teardown()
}

// teardown closes the listener and the sink exactly once, whichever of Run and
// Close reaches it first.
func (s *Server) teardown() error {
	s.teardownOnce.Do(func() {
		var errs []error
		if err := s.closeListener(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("closing listener: %w", err))
		}
		// The sink is closed last: it is what makes the events already written
		// durable, so it must outlive every session that can still write to it.
		if err := s.sink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing sink: %w", err))
		}
		s.teardownErr = errors.Join(errs...)
	})
	return s.teardownErr
}

// closeListener closes the listening socket once, so that the shutdown path and
// the context watcher can both reach for it. Accept wakes with an error.
//
// The listener field itself is never reassigned: the accept loop reads it
// without a lock, and swapping it out from another goroutine would be a data
// race on the one thing the collector cannot afford to get wrong.
func (s *Server) closeListener() error {
	s.listenerOnce.Do(func() {
		if s.listener != nil {
			s.listenerErr = s.listener.Close()
		}
	})
	return s.listenerErr
}

// writeTimeout bounds a write to a guest.
//
// A guest that stops reading must not be able to pin a collector goroutine and
// its buffers indefinitely; the handshake timeout is the operator's own
// statement of how long a silent peer is tolerated.
func (s *Server) writeTimeout() time.Duration {
	if d := s.cfg.Limits.HandshakeTimeout.Duration(); d > 0 {
		return d
	}
	return defaultWriteTimeout
}

// effectiveMaxPayload resolves the configured frame limit the way the decoder
// will, so that the value announced in READY is the one actually enforced.
func effectiveMaxPayload(cfg config.Host) uint32 {
	n := cfg.Limits.MaxPayloadSize.Bytes()
	switch {
	case n <= 0:
		return protocol.DefaultMaxPayloadSize
	case n > int64(protocol.MaxPayloadCeiling):
		return protocol.MaxPayloadCeiling
	default:
		return uint32(n)
	}
}

// maxTrackedStreams bounds how many (peer, boot id) streams the deduplication
// table remembers. The boot id comes from the guest, so a guest that invents a
// new one on every reconnect must not be able to grow the table without bound.
func maxTrackedStreams(cfg config.Host) int {
	n := 4 * cfg.Limits.MaxConnections
	if n < 64 {
		n = 64
	}
	return n
}
