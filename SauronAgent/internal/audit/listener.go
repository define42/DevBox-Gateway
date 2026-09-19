package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/define42/SauronAgent/internal/metrics"
)

// ListenerOptions configures a Listener.
type ListenerOptions struct {
	// ReceiveBuffer is the netlink socket receive buffer in bytes. Zero
	// selects a built-in default.
	ReceiveBuffer int

	// ExcludeTypes lists record types to discard before parsing. Anything
	// excluded here never reaches the collector, so it is a policy decision
	// rather than an optimisation.
	ExcludeTypes []RecordType

	// Metrics is optional.
	Metrics *metrics.Agent

	// Logger is optional; nil discards.
	Logger *slog.Logger

	// OnParseError is called for every record that could not be parsed, with
	// the raw message, so the caller can emit a sauron.parse.failure event.
	// The record is not delivered downstream.
	OnParseError func(raw RawMessage, err error)

	// OnKernelLoss is called when the kernel dropped multicast records because
	// our receive buffer was full, so the caller can emit a records-lost
	// event. The kernel does not say how many records went missing, so lost is
	// the number of overruns observed, each of which lost at least one record.
	OnKernelLoss func(lost uint64)
}

// Listener reads audit records off the NETLINK_AUDIT multicast socket, parses
// them and emits them on a channel.
//
// It deliberately does no disk or network I/O: everything expensive happens
// further down the pipeline, because anything that blocks this loop is time
// the kernel spends filling a finite socket buffer whose overflow it discards.
type Listener struct {
	conn    *NetlinkConn
	exclude map[RecordType]bool
	metrics *metrics.Agent
	log     *slog.Logger

	onParseError func(raw RawMessage, err error)
	onKernelLoss func(lost uint64)

	// lastRejected is the rejection count already reported; only Run touches it.
	lastRejected uint64

	closeOnce sync.Once
	closeErr  error
}

// NewListener opens the netlink socket and returns a Listener.
//
// The socket is opened here rather than in Run so that a missing
// CAP_AUDIT_READ is reported at startup, when an operator is watching, instead
// of turning into a collector that silently never produces an event.
func NewListener(opts ListenerOptions) (*Listener, error) {
	conn, err := Dial(opts.ReceiveBuffer)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		conn:         conn,
		exclude:      make(map[RecordType]bool, len(opts.ExcludeTypes)),
		metrics:      opts.Metrics,
		log:          opts.Logger,
		onParseError: opts.OnParseError,
		onKernelLoss: opts.OnKernelLoss,
	}
	for _, t := range opts.ExcludeTypes {
		l.exclude[t] = true
	}
	if l.metrics == nil {
		l.metrics = &metrics.Agent{}
	}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	return l, nil
}

// Run reads records until ctx is cancelled or the socket fails.
//
// Cancellation is an orderly shutdown and returns nil. A blocked send on out
// is ordinary backpressure and is allowed, but cancellation always wins over
// it, so a stalled consumer can never keep the agent from stopping.
func (l *Listener) Run(ctx context.Context, out chan<- *Record) error {
	// Receive blocks in recvfrom; setting a deadline in the past is how it is
	// woken. Closing the socket here instead would race with the reader.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.conn.SetReceiveDeadline(time.Now())
		case <-stop:
		}
	}()

	for {
		if ctx.Err() != nil {
			return nil
		}

		msgs, err := l.conn.Receive()
		l.reportRejections()

		// Records decoded before an error are still delivered: a framing
		// problem at the end of a datagram must not take the good records at
		// the front of it with it.
		for _, m := range msgs {
			if !l.deliver(ctx, m, out) {
				return nil
			}
		}

		switch {
		case err == nil:
		case errors.Is(err, ErrKernelOverrun):
			// Not fatal, and not an ordinary error either: the audit trail now
			// has a hole in it and the collector has to be told.
			l.metrics.KernelRecordsLost.Add(1)
			l.log.Warn("kernel discarded audit records: receive buffer overrun")
			if l.onKernelLoss != nil {
				l.onKernelLoss(1)
			}
		case errors.Is(err, os.ErrDeadlineExceeded):
			// A poll expired, or ctx cancellation woke us. Loop and re-check.
		case errors.Is(err, net.ErrClosed):
			return nil
		case errors.Is(err, errBadDatagram):
			// One unusable datagram is not a reason to stop collecting.
			l.metrics.ParseErrors.Add(1)
			l.log.Warn("discarding malformed netlink datagram", "error", err)
		default:
			return fmt.Errorf("audit: reading netlink: %w", err)
		}
	}
}

// deliver filters, parses and forwards one raw message. It returns false when
// ctx was cancelled while waiting for room on out.
func (l *Listener) deliver(ctx context.Context, m RawMessage, out chan<- *Record) bool {
	l.metrics.AuditMessagesReceived.Add(1)

	if l.exclude[m.Type] {
		// Excluded by configuration, so not counted as a loss: it is a choice
		// the operator made, recorded in the configuration, not a failure.
		l.log.Debug("excluding audit record type", "type", m.Type.String())
		return true
	}

	rec, err := ParseRecord(m)
	if err != nil {
		l.metrics.ParseErrors.Add(1)
		l.log.Warn("discarding unparsable audit record", "type", m.Type.String(), "error", err)
		if l.onParseError != nil {
			l.onParseError(m, err)
		}
		return true
	}

	select {
	case out <- rec:
		return true
	case <-ctx.Done():
		return false
	}
}

// reportRejections surfaces messages the netlink layer refused. They are
// counted rather than fatal, because the socket is reachable from inside the
// guest and a local process must not be able to stop collection by writing to
// it -- but a non-zero count is itself worth investigating.
func (l *Listener) reportRejections() {
	total := l.conn.Rejected()
	if total <= l.lastRejected {
		return
	}
	delta := total - l.lastRejected
	l.lastRejected = total
	l.metrics.AuditMessagesDropped.Add(delta)
	l.log.Warn("rejected netlink messages that were not kernel audit records", "count", delta)
}

// Close releases the netlink socket. It is safe to call more than once and
// while Run is still in flight.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { l.closeErr = l.conn.Close() })
	return l.closeErr
}
