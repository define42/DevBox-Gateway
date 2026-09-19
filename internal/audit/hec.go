package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

// HECConfig configures forwarding of audit records to a Splunk HTTP Event
// Collector. An empty Endpoint disables forwarding.
type HECConfig = splunkhec.Config

const (
	// hecSource and hecSourcetype label every forwarded event. The dedicated
	// sourcetype needs no props.conf stanza: Splunk's default KV_MODE=auto
	// extracts the JSON event fields at search time.
	hecSource     = "devbox-gateway"
	hecSourcetype = "devbox-gateway:audit"

	// hecQueueCapacity bounds the events held in memory while the collector is
	// slow or unreachable; newer events are dropped (and counted) beyond it.
	hecQueueCapacity = 10000
	hecBatchSize     = 100
	hecRetryInitial  = time.Second
	hecRetryLimit    = 30 * time.Second
	// hecShutdownTimeout bounds how long Close waits for queued events to be
	// delivered before abandoning them.
	hecShutdownTimeout = 5 * time.Second
)

// hecForwarder is an io.Writer that ships each audit record it receives to a
// Splunk HEC from a background goroutine. It must never log through slog: the
// default slog logger is the audit logger, so doing so would feed its own
// diagnostics back into the audit stream. Operational messages use the
// standard log package instead.
type hecForwarder struct {
	client *splunkhec.Client
	host   string

	queue   chan []byte
	dropped atomic.Uint64

	retryInitial    time.Duration
	retryLimit      time.Duration
	shutdownTimeout time.Duration

	cancel    context.CancelFunc
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// newHECForwarder validates config and builds a forwarder that is not yet
// running; call start before use.
func newHECForwarder(config HECConfig) (*hecForwarder, error) {
	client, err := splunkhec.New(config)
	if err != nil {
		return nil, err
	}
	if client.PlainHTTP() {
		log.Printf("audit: splunk hec endpoint uses plain http; the hec token and audit events are sent unencrypted")
	}
	log.Printf("audit: forwarding audit events to splunk hec at %s (index %q)", client.Endpoint(), client.Index())

	host, _ := os.Hostname()
	return &hecForwarder{
		client:          client,
		host:            host,
		queue:           make(chan []byte, hecQueueCapacity),
		retryInitial:    hecRetryInitial,
		retryLimit:      hecRetryLimit,
		shutdownTimeout: hecShutdownTimeout,
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}, nil
}

func (f *hecForwarder) start() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go f.run(ctx)
}

// Write enqueues one audit record for delivery. slog's JSON handler passes
// exactly one complete, newline-terminated record per call. Write never blocks
// and never fails, so a slow or unreachable collector cannot stall audit
// logging: when the queue is full the record is dropped and counted for the
// next drop report. The local audit file is unaffected.
func (f *hecForwarder) Write(record []byte) (int, error) {
	// Marshal copies the record, which slog reuses once Write returns.
	payload, err := json.Marshal(splunkhec.Envelope{
		Time:       splunkhec.Time(time.Now()),
		Host:       f.host,
		Source:     hecSource,
		Sourcetype: hecSourcetype,
		Index:      f.client.Index(),
		Event:      json.RawMessage(bytes.TrimSpace(record)),
	})
	if err != nil {
		f.dropped.Add(1)
		return len(record), nil
	}

	select {
	case f.queue <- payload:
	default:
		f.dropped.Add(1)
	}
	return len(record), nil
}

func (f *hecForwarder) run(ctx context.Context) {
	defer close(f.done)
	for {
		select {
		case first := <-f.queue:
			f.deliver(ctx, f.collectBatch(first))
			f.reportDropped()
		case <-f.stop:
			f.flush(ctx)
			return
		}
	}
}

// collectBatch extends first with whatever is already queued, up to
// hecBatchSize, without waiting for more events to arrive.
func (f *hecForwarder) collectBatch(first []byte) [][]byte {
	batch := [][]byte{first}
	for len(batch) < hecBatchSize {
		select {
		case payload := <-f.queue:
			batch = append(batch, payload)
		default:
			return batch
		}
	}
	return batch
}

// flush delivers everything still queued at shutdown. Once ctx is canceled at
// the shutdown deadline, deliver abandons each remaining batch immediately.
func (f *hecForwarder) flush(ctx context.Context) {
	for {
		select {
		case first := <-f.queue:
			f.deliver(ctx, f.collectBatch(first))
		default:
			f.reportDropped()
			return
		}
	}
}

// deliver sends batch, retrying transient failures with exponential backoff
// until it succeeds, the collector rejects it outright, or ctx is canceled.
func (f *hecForwarder) deliver(ctx context.Context, batch [][]byte) {
	body := bytes.Join(batch, nil)
	backoff := f.retryInitial
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			f.dropped.Add(uint64(len(batch)))
			return
		}

		err := f.client.Post(ctx, body)
		if err == nil {
			if attempt > 1 {
				log.Printf("audit: splunk hec delivery recovered after %d attempts", attempt)
			}
			return
		}
		if splunkhec.IsRejected(err) {
			log.Printf("audit: splunk hec rejected %d audit event(s), dropping them: %v", len(batch), err)
			return
		}
		if ctx.Err() != nil {
			continue // shutdown deadline: the check above drops the batch
		}

		log.Printf("audit: splunk hec delivery of %d audit event(s) failed (attempt %d), retrying in %s: %v", len(batch), attempt, backoff, err)
		f.reportDropped()
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		backoff = min(2*backoff, f.retryLimit)
	}
}

func (f *hecForwarder) reportDropped() {
	if dropped := f.dropped.Swap(0); dropped > 0 {
		log.Printf("audit: %d audit event(s) could not be forwarded to splunk hec and were dropped; the local audit file is unaffected", dropped)
	}
}

// Close stops accepting work and waits up to shutdownTimeout for queued events
// to be delivered, then abandons the rest.
func (f *hecForwarder) Close() error {
	f.closeOnce.Do(func() {
		close(f.stop)
		timer := time.NewTimer(f.shutdownTimeout)
		defer timer.Stop()
		select {
		case <-f.done:
		case <-timer.C:
			f.closeErr = fmt.Errorf("splunk hec: queued audit events were not delivered within %s", f.shutdownTimeout)
		}
		f.cancel()
		<-f.done
		f.client.CloseIdleConnections()
	})
	return f.closeErr
}
