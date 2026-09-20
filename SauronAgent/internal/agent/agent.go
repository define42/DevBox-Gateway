// Package agent is SauronAgent's guest pipeline: it wires the audit reader,
// the correlator, the normalizer, the sequence assignment, the bounded queue,
// the disk spool and the host transport into one running agent.
//
// The structure is the design's central reliability decision (DESIGN.md
// sections 18-22 and 39): collection and transport are separate goroutines
// with bounded channels between them.
//
//	netlink reader -> correlator -> normalizer -> assign sequence -> queue -> spool -> sender
//
// Nothing downstream of the queue can make the netlink reader wait. A host
// that is unreachable, a disk that is slow, a collector that stops
// acknowledging -- each of those costs a growing backlog, not a stalled
// reader, because a stalled reader pushes the loss back into the kernel's
// audit backlog where SauronAgent cannot see it and cannot report it.
//
// The second rule the package is built around is that failure is visible
// (DESIGN.md section 40). Every path that can lose an event -- a record the
// parser could not read, a full queue, a full spool, records the kernel itself
// discarded -- produces a sauron.* event that is numbered, spooled and
// delivered exactly like the audit events around it. A collector that only
// ever sees audit events cannot tell a quiet guest from a blind one.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/define42/SauronAgent/internal/audit"
	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/queue"
	"github.com/define42/SauronAgent/internal/spool"
	"github.com/define42/SauronAgent/internal/transport"
)

// Channel capacities between the collection stages.
//
// These are hand-off buffers, not the agent's event buffer: the queue is that,
// and it is the only stage with a configured capacity and explicit overflow
// accounting. They exist so that a burst of kernel records does not have to be
// consumed in lockstep by the correlator, and they are deliberately small
// enough that a sustained overload reaches the queue -- where a drop can be
// counted and named -- instead of accumulating invisibly in a channel.
const (
	recordChanCap = 1024
	groupChanCap  = 256
)

// Timeouts that are not configurable.
const (
	// dialTimeout bounds one connection attempt. Without it a dial to a host
	// that answers nothing would sit outside the backoff schedule entirely.
	dialTimeout = 30 * time.Second

	// handshakeTimeout bounds the wait for READY. It matches the collector's
	// own default handshake timeout (limits.handshake_timeout, 10s).
	handshakeTimeout = 10 * time.Second

	// maxShutdownFlush bounds how long an orderly stop spends delivering what
	// is still unacknowledged. A guest being shut down must not be held up by
	// a collector that has stopped answering; anything not delivered is still
	// in the spool and goes out after the restart.
	maxShutdownFlush = 5 * time.Second
)

// lossPollInterval is how often the queue's and the spool's loss accounting is
// turned into events, and how often the spool is flushed to disk.
//
// It is a variable so the tests can shorten it (they set it once, before any
// agent is built); nothing outside this package can reach it.
var lossPollInterval = 500 * time.Millisecond

// Options configures an Agent.
type Options struct {
	Config   config.Agent
	Identity identity.Identity
	Metrics  *metrics.Agent
	Logger   *slog.Logger
	// Dialer overrides transport construction in tests.
	Dialer transport.Dialer
	// Source overrides the audit record source in tests. An injected source
	// skips kernel rule setup unless ConfigureRules is also provided.
	Source func(ctx context.Context, out chan<- *audit.Record) error
	// ConfigureRules overrides kernel rule setup in tests.
	ConfigureRules func(context.Context) error
}

// Agent is the guest pipeline.
//
// New builds it, Run drives it until its context is cancelled, and Close
// releases the resources it holds. An Agent runs once: Run may not be called a
// second time.
type Agent struct {
	cfg     config.Agent
	id      identity.Identity
	metrics *metrics.Agent
	log     *slog.Logger

	// source produces raw audit records. It is the netlink listener in a
	// deployment and an injected function in tests, and is nil when audit
	// collection is disabled.
	source         func(ctx context.Context, out chan<- *audit.Record) error
	listener       *audit.Listener
	correlator     *audit.Correlator
	configureRules func(context.Context) error

	seq   *sequencer
	queue *queue.Queue
	spool *spool.Spool
	send  *sender

	// submitMu makes "take a sequence number" and "hand the event to the
	// queue" one step. Without it two producers could number events 5 and 6
	// and enqueue them in the order 6, 5; the spool refuses a sequence that is
	// not greater than the last one it stored, so the queue's order has to be
	// the sequence order.
	submitMu sync.Mutex

	started time.Time
	running atomic.Bool
	// streamClosed marks the point after which no event can reach the host:
	// the queue has been closed and its backlog handed to the spool.
	streamClosed atomic.Bool

	closeOnce sync.Once
	closeErr  error
}

// New builds an agent from opts. It opens the spool and, unless a Source is
// injected, the netlink socket, so that a missing CAP_AUDIT_READ or an
// unwritable spool directory fails at startup where an operator will see it
// rather than becoming an agent that silently never delivers an event.
func New(opts Options) (*Agent, error) {
	cfg := opts.Config
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("agent: %w", err)
	}

	a := &Agent{
		cfg:     cfg,
		id:      opts.Identity,
		metrics: opts.Metrics,
		log:     opts.Logger,
	}
	if a.metrics == nil {
		a.metrics = &metrics.Agent{}
	}
	if a.log == nil {
		a.log = logging.Discard()
	}

	a.queue = queue.New(queue.Options{
		Capacity: cfg.Queue.Capacity,
		Metrics:  a.metrics,
	})

	if cfg.Spool.Enabled {
		sp, err := spool.Open(spool.Options{
			Dir:          cfg.Spool.Path,
			MaxSize:      cfg.Spool.MaxSize.Bytes(),
			SegmentSize:  cfg.Spool.SegmentSize.Bytes(),
			SyncOnWrite:  cfg.Spool.SyncOnWrite,
			SyncInterval: cfg.Spool.SyncInterval.Duration(),
			Metrics:      a.metrics,
			Logger:       a.log,
		})
		if err != nil {
			return nil, err
		}
		a.spool = sp
	}

	// Numbering resumes above whatever the spool already holds, so a restart
	// within one boot never reissues a sequence number. With no spool there is
	// nothing to recover and numbering starts at 1.
	start := uint64(1)
	if a.spool != nil {
		start = a.spool.LastSequence() + 1
	}
	a.seq = newSequencer(start, a.id.BootID)

	if cfg.Audit.Enabled {
		switch {
		case opts.Source != nil:
			a.source = opts.Source
		default:
			l, err := audit.NewListener(a.listenerOptions())
			if err != nil {
				a.closeResources()
				return nil, err
			}
			a.listener = l
			a.source = l.Run
		}
		a.correlator = audit.NewCorrelator(audit.CorrelatorOptions{
			Timeout:          cfg.Audit.CorrelationTimeout.Duration(),
			MaxPendingEvents: cfg.Audit.MaxPendingEvents,
			Metrics:          a.metrics,
			Logger:           a.log,
		})
		if cfg.Audit.ManageRules {
			a.configureRules = opts.ConfigureRules
			if a.configureRules == nil && opts.Source == nil {
				a.configureRules = func(ctx context.Context) error {
					return audit.EnsureManagedRulesWithLogger(ctx, a.log)
				}
			}
		}
	}

	dialer := opts.Dialer
	if dialer == nil {
		d, err := buildDialer(cfg)
		if err != nil {
			a.closeResources()
			return nil, err
		}
		dialer = d
	}

	a.send = newSender(senderOptions{
		cfg:          cfg,
		id:           opts.Identity,
		metrics:      a.metrics,
		log:          a.log,
		dialer:       dialer,
		queue:        a.queue,
		spool:        a.spool,
		emit:         a.submit,
		auditEnabled: cfg.Audit.Enabled,
		resume:       a.resumeNumbering,
	})
	return a, nil
}

// buildDialer turns the configured transport into a Dialer. VSOCK is the
// compiled production transport; TCP exists only for development and tests and
// is never selected as a silent fallback.
func buildDialer(cfg config.Agent) (transport.Dialer, error) {
	switch cfg.Transport.Kind {
	case config.TransportVSOCK:
		return transport.NewVSOCKDialer(cfg.VSOCK.CID, cfg.VSOCK.Port), nil
	case config.TransportTCP:
		return transport.NewTCPDialer(cfg.Transport.TCPAddress), nil
	default:
		return nil, fmt.Errorf("agent: unknown transport kind %q", cfg.Transport.Kind)
	}
}

// listenerOptions is the netlink listener's configuration, including the two
// callbacks that turn collection failures into events.
//
// It is a method rather than an inline literal so that the callbacks can be
// exercised without a netlink socket: the wiring of a loss into the event
// stream is the part worth testing, not the socket.
func (a *Agent) listenerOptions() audit.ListenerOptions {
	return audit.ListenerOptions{
		ReceiveBuffer: int(a.cfg.Audit.SocketReceiveBuffer.Bytes()),
		ExcludeTypes:  excludedTypes(a.cfg.Audit.ExcludeTypes, a.log),
		Metrics:       a.metrics,
		Logger:        a.log,
		// A record the parser could not read is evidence that still exists:
		// the raw text travels to the collector inside the failure event, so
		// the parser can be fixed against real input.
		OnParseError: func(raw audit.RawMessage, err error) {
			a.submit(event.NewParseFailure(string(raw.Data), err.Error()))
		},
		// A kernel overrun is evidence that no longer exists. lost counts
		// overrun occurrences, not records: the kernel does not say how many
		// records it discarded, only that it discarded some.
		OnKernelLoss: func(lost uint64) {
			a.submit(event.NewKernelRecordsLost(lost))
		},
	}
}

// excludedTypes resolves the configured record type names. An unknown name is
// dropped with a warning rather than failing startup: refusing to run would
// stop collection entirely over a typo in a filter.
func excludedTypes(names []string, log *slog.Logger) []audit.RecordType {
	out := make([]audit.RecordType, 0, len(names))
	for _, n := range names {
		t, ok := audit.RecordTypeByName(n)
		if !ok {
			log.Warn("ignoring unknown audit record type in audit.exclude_types", "name", n)
			continue
		}
		out = append(out, t)
	}
	return out
}

// Run starts every stage and returns when they have all stopped.
//
// Cancelling ctx is an orderly shutdown and returns nil: collection stops, the
// queue is drained into the spool, whatever is still unacknowledged is
// delivered if the host is reachable, and the session ends with a SHUTDOWN
// frame so the collector can tell a planned stop from a crash. A stage that
// fails for any other reason takes the pipeline down with it and its error is
// returned.
func (a *Agent) Run(ctx context.Context) error {
	if !a.running.CompareAndSwap(false, true) {
		return errors.New("agent: Run has already been called")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.started = time.Now()
	a.send.started = a.started

	// Close the queue on every exit path. The sender's pump stops when the
	// queue reports that it is closed and drained, so an early failure must
	// not leave it parked waiting for an event that will never come.
	defer a.queue.Close()

	// Subscribe before enabling syscall auditing (New opened the listener),
	// and configure before claiming a started stream or launching the sender.
	if a.configureRules != nil {
		if err := a.configureRules(ctx); err != nil {
			if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				return nil
			}
			return fmt.Errorf("agent: configure kernel audit rules: %w", err)
		}
		a.log.Info("kernel audit managed rules are active")
	}

	records := make(chan *audit.Record, recordChanCap)
	groups := make(chan *audit.Group, groupChanCap)
	// collected is closed once the last normalized event has been submitted,
	// which is what tells the loss poller that its final accounting will not
	// be overtaken by another event.
	collected := make(chan struct{})

	st := &stages{cancel: cancel, log: a.log}

	// The started event is submitted before any stage runs, so it takes the
	// first sequence number of the run. A collector that sees a stream resume
	// without it is looking at a spool replay, not a restarted agent.
	a.submit(event.NewInternal(event.TypeAgentStarted, "", map[string]any{
		"agent_version":  a.id.Version,
		"hostname":       a.id.Hostname,
		"kernel":         a.id.Kernel,
		"audit_enabled":  a.cfg.Audit.Enabled,
		"spool_enabled":  a.cfg.Spool.Enabled,
		"first_sequence": a.seq.peek(),
	}))

	st.run("source", func() error {
		defer close(records)
		if a.source == nil {
			// audit.enabled is false: the transport runs on its own, which is
			// how the delivery path is exercised in isolation. The collection
			// stages fall straight through on the closed channel.
			<-ctx.Done()
			return nil
		}
		return a.source(ctx, records)
	})

	st.run("correlator", func() error {
		defer close(groups)
		if a.correlator == nil {
			// Nothing produces records when audit collection is off, but the
			// channel is still drained so that no producer can park on it.
			for range records {
			}
			return nil
		}
		return a.correlator.Run(ctx, records, groups)
	})

	st.run("normalizer", func() error {
		defer close(collected)
		for g := range groups {
			a.submit(event.Normalize(g, event.NormalizeOptions{
				PreserveRaw: a.cfg.Audit.PreserveRaw,
				BootID:      a.id.BootID,
			}))
		}
		return nil
	})

	st.run("loss-poller", func() error { return a.pollLosses(ctx, collected) })

	st.run("sender", func() error { return a.send.run(ctx) })

	err := st.wait()

	// The spool's own sync policy is driven by appends; a final flush makes
	// the last events durable even if Close is never reached.
	if a.spool != nil {
		if serr := a.spool.Sync(); serr != nil && err == nil {
			err = serr
		}
	}
	return err
}

// pollLosses turns the queue's and the spool's loss accounting into events on
// a ticker, and once more after collection has finished.
//
// A drop that is counted but never drained is a silent loss: the accounting
// sits in the queue and nobody is told. This is the only thing that drains it.
func (a *Agent) pollLosses(ctx context.Context, collected <-chan struct{}) error {
	t := time.NewTicker(lossPollInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			a.drainLosses(false)
			if a.spool != nil {
				if err := a.spool.Sync(); err != nil {
					a.log.Error("spool sync failed", "error", err)
				}
			}

		case <-ctx.Done():
			// Collection stops on the same cancellation. Waiting for it means
			// the final accounting covers every event that was ever submitted,
			// and that the stopping event is the last one in the stream.
			<-collected
			a.drainLosses(true)
			a.submit(event.NewInternal(event.TypeAgentStopping, "", map[string]any{
				"uptime_seconds":  uint64(time.Since(a.started) / time.Second),
				"events_created":  a.metrics.EventsCreated.Load(),
				"events_sent":     a.metrics.EventsSent.Load(),
				"events_dropped":  a.metrics.EventsDropped.Load(),
				"queue_depth":     a.queue.Len(),
				"last_sequence":   a.seq.peek() - 1,
				"spool_remaining": a.spoolPending(),
			}))
			// No further events can be produced, so the queue can be closed.
			// The sender's pump drains it and then stops, which is what makes
			// a shutdown flush instead of truncate.
			a.streamClosed.Store(true)
			a.queue.Close()
			return nil
		}
	}
}

// drainLosses converts pending loss accounting into events.
//
// Reporting a loss costs a queue slot, and a report that had to evict another
// event to fit would be a loss that causes a loss -- the feedback loop that
// turns one overflow into an endless cascade of overflow events, each
// displacing a real one. So nothing is drained at all while the queue is full:
// the accounting stays in the queue, keeps accumulating, and is reported as
// one wider range as soon as there is room. The counters are cumulative until
// drained, so waiting costs detail, never the report itself. Together with the
// ticker that drives this, that bounds internal loss events to one per kind
// per tick.
//
// final marks the last call of the run. There is no later tick to defer to
// then, so the accounting is drained whatever the queue looks like.
func (a *Agent) drainLosses(final bool) {
	if !final && a.queue.Len() >= a.queue.Cap() {
		return
	}

	if dropped, first, last, ok := a.queue.DrainOverflow(); ok {
		a.reportLoss(event.NewQueueOverflow(dropped, first, last),
			"queue overflow", dropped, first, last)
	}
	if a.spool != nil {
		if dropped, first, last, ok := a.spool.DrainDropped(); ok {
			a.reportLoss(event.NewSpoolFull(dropped, first, last),
				"spool discarded events", dropped, first, last)
		}
	}
	if dropped, first, last, ok := a.send.drainAppendFailures(); ok {
		a.reportLoss(event.NewInternal(event.TypeSpoolError, "", map[string]any{
			"events_dropped":         dropped,
			"first_missing_sequence": first,
			"last_missing_sequence":  last,
			"reason":                 "the spool refused the event",
		}), "spool rejected events", dropped, first, last)
	}
}

// reportLoss submits one loss report, or logs it if the queue filled up in the
// meantime.
//
// The accounting has already been drained by the time this is called, so the
// report cannot be deferred to a later tick; a full queue at this point means
// the choice is between evicting a real event to describe an older loss and
// recording the loss locally. It goes to the log, where it is at least not
// silent, and the counters in the heartbeat still show it.
func (a *Agent) reportLoss(e *event.Event, what string, dropped, first, last uint64) {
	if a.queue.Len() >= a.queue.Cap() {
		a.log.Error("loss could not be reported to the host: the queue is full",
			"loss", what,
			"events_dropped", dropped,
			"first_missing_sequence", first,
			"last_missing_sequence", last)
		return
	}
	a.log.Warn("reporting evidence loss to the host",
		"loss", what,
		"events_dropped", dropped,
		"first_missing_sequence", first,
		"last_missing_sequence", last)
	a.submit(e)
}

// submit numbers an event and hands it to the queue.
//
// This is the single entrance to the event stream: normalized audit events and
// the agent's own reports about itself go through it alike, so an internal
// event is numbered, spooled, sent and acknowledged exactly like an audit
// event. Put never blocks, which is what keeps this callable from the netlink
// callbacks without giving the host a way to stall collection.
func (a *Agent) submit(e *event.Event) {
	if e == nil {
		return
	}
	a.submitMu.Lock()
	a.seq.assign(e)
	a.metrics.EventsCreated.Add(1)
	closed := a.streamClosed.Load()
	a.queue.Put(e)
	a.submitMu.Unlock()

	if closed {
		// The stream was closed while this event was being produced -- a
		// connection that came up during shutdown reporting itself, for
		// instance. The queue counts it as a drop, but no later tick can turn
		// that count into an event any more, so it is logged here instead of
		// disappearing.
		a.log.Error("event produced after the stream was closed; it cannot be delivered",
			"type", e.Type, "sequence", e.Sequence)
	}
}

// resumeNumbering lifts the sequence counter above a position the host already
// holds for this boot id, so that the next event issued is one the host has
// never seen under that (boot id, sequence).
//
// The sender calls this when the host's cumulative position turns out to be
// ahead of everything this agent has produced -- a spool that was reset,
// rotated away or never enabled, against a host that kept its watermark for
// the same boot id. sender.adoptHostPosition explains why that has to be
// believed rather than argued with; this is the half of the answer that has to
// happen in the pipeline, because the sender does not own the numbering.
//
// submitMu is held so that the lift is atomic with respect to "number an event
// and hand it to the queue". The spool refuses a sequence that is not greater
// than the last one it stored, so the order of the queue has to stay the order
// of the sequence numbers across the jump.
//
// Events already numbered below the new start keep their numbers: renumbering
// one would break the (boot id, sequence) identity the host deduplicates on.
// The host holds those numbers already, so it suppresses them; they are
// released from the backlog rather than sent, and the WARN the sender logs is
// what makes that visible.
func (a *Agent) resumeNumbering(hostThrough uint64) {
	a.submitMu.Lock()
	defer a.submitMu.Unlock()
	a.seq.advanceTo(hostThrough + 1)
}

// spoolPending reports how many events the spool still holds.
func (a *Agent) spoolPending() int {
	if a.spool == nil {
		return 0
	}
	return a.spool.PendingCount()
}

// Close releases the spool, the netlink socket and the connection to the host.
//
// It is idempotent and safe after a failed Run, and safe to call while Run is
// still in flight: closing the connection and the netlink socket is how a
// blocked Run is unwedged. Events still in the queue at that point have not
// been delivered; with a spool they are on disk and go out after a restart.
func (a *Agent) Close() error {
	a.closeOnce.Do(func() { a.closeErr = a.closeResources() })
	return a.closeErr
}

// closeResources is Close's body, also used to unwind a partially built agent.
func (a *Agent) closeResources() error {
	var err error
	if a.send != nil {
		if cerr := a.send.close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if a.listener != nil {
		if cerr := a.listener.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if a.queue != nil {
		a.queue.Close()
	}
	// The spool is closed last: the sender's pump may still be appending to it
	// until the queue it reads from is closed and drained.
	if a.spool != nil {
		if cerr := a.spool.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

// stages runs the pipeline's goroutines, keeps the first error and cancels the
// rest.
//
// It is errgroup.WithContext in miniature. The agent needs nothing else from
// such a dependency, and a stage that fails must take the pipeline down rather
// than leave a half-running agent that still looks alive to the host.
type stages struct {
	wg     sync.WaitGroup
	cancel context.CancelFunc
	log    *slog.Logger

	mu  sync.Mutex
	err error
}

// run starts one stage under the given name, which appears in the error and in
// the log line if it fails.
func (s *stages) run(name string, fn func() error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := fn()
		if err == nil {
			return
		}
		s.mu.Lock()
		if s.err == nil {
			s.err = fmt.Errorf("agent: %s stage: %w", name, err)
		}
		s.mu.Unlock()
		s.log.Error("pipeline stage failed", "stage", name, "error", err)
		s.cancel()
	}()
}

// wait blocks until every stage has returned and reports the first error.
func (s *stages) wait() error {
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
