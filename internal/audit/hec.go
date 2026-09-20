package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/sauron"
	"github.com/define42/devbox-gateway/internal/splunkhec"
)

// HECConfig configures forwarding of audit records to a Splunk HTTP Event
// Collector. An empty Endpoint disables forwarding.
type HECConfig = splunkhec.Config

const (
	hecSource          = "devbox-gateway"
	hecSourcetype      = "devbox-gateway:audit"
	hecBatchSize       = 100
	hecBatchBytes      = 1024 * 1024
	hecRetryInitial    = time.Second
	hecRetryLimit      = 30 * time.Second
	hecShutdownTimeout = 5 * time.Second
)

// hecForwarder persists each audit record before delivering it in the
// background. Diagnostics must use log, not slog, to avoid recursively writing
// to the audit sink when storage or delivery fails.
type hecForwarder struct {
	client *splunkhec.Client
	host   string
	spool  *sauron.DeliverySpool

	retryInitial    time.Duration
	retryLimit      time.Duration
	shutdownTimeout time.Duration

	// appendRecord captures the writer-lifetime context: request cancellation
	// must not discard an audit event, but shutdown must release capacity waits.
	appendRecord func([]byte) error
	cancelWrites context.CancelFunc
	cancel       context.CancelFunc
	stop         chan struct{}
	done         chan struct{}
	mu           sync.Mutex
	closing      bool
	writes       sync.WaitGroup
	startOnce    sync.Once
	shutdownOnce sync.Once
	shutdownWait *time.Timer
	closeOnce    sync.Once
	closeErr     error
}

// newHECForwarder opens a durable spool without starting delivery. Its caller
// must call Close even if start is never called.
func newHECForwarder(config HECConfig, spoolDir string, spoolMaxBytes int64) (*hecForwarder, error) {
	client, err := splunkhec.New(config)
	if err != nil {
		return nil, err
	}
	spool, err := sauron.OpenDeliverySpool(spoolDir, spoolMaxBytes)
	if err != nil {
		client.CloseIdleConnections()
		return nil, fmt.Errorf("open application audit spool: %w", err)
	}
	if client.PlainHTTP() {
		log.Printf("audit: splunk hec endpoint uses plain http; the hec token and audit events are sent unencrypted")
	}
	log.Printf("audit: forwarding to splunk hec at %s (index %q) using durable spool %q (limit %d bytes); permanent audit file is disabled", client.Endpoint(), client.Index(), spoolDir, spoolMaxBytes)

	ctx, cancelWrites := context.WithCancel(context.Background())
	host, _ := os.Hostname()
	return &hecForwarder{
		client:          client,
		host:            host,
		spool:           spool,
		appendRecord:    func(record []byte) error { return spool.Append(ctx, record) },
		cancelWrites:    cancelWrites,
		retryInitial:    hecRetryInitial,
		retryLimit:      hecRetryLimit,
		shutdownTimeout: hecShutdownTimeout,
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}, nil
}

func (f *hecForwarder) start() {
	f.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		f.cancel = cancel
		go f.run(ctx)
	})
}

// Write returns success only after the complete HEC envelope is on stable
// storage. A full spool blocks until delivered segments can be reclaimed or
// shutdown interrupts the wait; it never evicts undelivered events.
func (f *hecForwarder) Write(record []byte) (int, error) {
	f.mu.Lock()
	if f.closing {
		f.mu.Unlock()
		return f.writeFailure(os.ErrClosed)
	}
	f.writes.Add(1)
	f.mu.Unlock()
	defer f.writes.Done()

	// Persist routing and timestamp along with the event so replay retains the
	// original metadata even if configuration changes across restarts.
	payload, err := json.Marshal(splunkhec.Envelope{
		Time:       splunkhec.Time(time.Now()),
		Host:       f.host,
		Source:     hecSource,
		Sourcetype: hecSourcetype,
		Index:      f.client.Index(),
		Event:      json.RawMessage(bytes.TrimSpace(record)),
	})
	if err != nil {
		return f.writeFailure(fmt.Errorf("encode audit envelope: %w", err))
	}
	if err := f.appendRecord(payload); err != nil {
		return f.writeFailure(fmt.Errorf("persist audit envelope: %w", err))
	}
	return len(record), nil
}

func (f *hecForwarder) writeFailure(err error) (int, error) {
	// slog does not return Handler errors to callers. Surface failures here,
	// without including event contents or credentials in operational logs.
	log.Printf("audit: application audit event was not accepted into the durable spool: %v", err)
	return 0, err
}

func (f *hecForwarder) run(ctx context.Context) {
	defer close(f.done)
	for ctx.Err() == nil {
		batch, err := f.spool.ReadBatch(f.spool.Checkpoint(), hecBatchSize, hecBatchBytes)
		if err != nil {
			log.Printf("audit: read application audit spool; records retained for retry: %v", err)
			if !waitHECRetry(ctx, f.retryLimit) {
				return
			}
			continue
		}
		if len(batch) == 0 {
			select {
			case <-f.spool.Ready():
			case <-f.stop:
				return
			case <-ctx.Done():
				return
			}
			continue
		}
		if !f.deliver(ctx, batch) {
			return
		}
		if !f.checkpoint(ctx, batch[len(batch)-1].End) {
			return
		}
	}
}

// checkpoint retries storage failures without resending an accepted batch.
// If shutdown wins, replay may duplicate the batch, but cannot lose it.
func (f *hecForwarder) checkpoint(ctx context.Context, position sauron.DeliveryPosition) bool {
	for {
		err := f.spool.Acknowledge(position)
		if err == nil {
			return true
		}
		log.Printf("audit: checkpoint application audit spool; records retained: %v", err)
		if !waitHECRetry(ctx, f.retryInitial) {
			return false
		}
	}
}

// deliver retries all errors, including rejected credentials or events. These
// require operator intervention, not deleting security evidence from the spool.
func (f *hecForwarder) deliver(ctx context.Context, batch []sauron.DeliveryRecord) bool {
	var body bytes.Buffer
	for _, record := range batch {
		body.Write(record.Data)
	}
	backoff := f.retryInitial
	for attempt := 1; ctx.Err() == nil; attempt++ {
		err := f.client.Post(ctx, body.Bytes())
		if err == nil {
			if attempt > 1 {
				log.Printf("audit: splunk hec delivery recovered after %d attempts", attempt)
			}
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		log.Printf("audit: splunk hec delivery of %d event(s) failed (attempt %d); retained on disk, retrying in %s: %v", len(batch), attempt, backoff, err)
		if !waitHECRetry(ctx, backoff) {
			return false
		}
		backoff = min(2*backoff, f.retryLimit)
	}
	return false
}

func waitHECRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// beginShutdown bounds capacity waits before the gateway waits for workers
// that may themselves be logging. Ordinary shutdown auditing can continue
// until this deadline; unpersisted writes interrupted by it report an error.
func (f *hecForwarder) beginShutdown() {
	f.shutdownOnce.Do(func() {
		f.shutdownWait = time.AfterFunc(f.shutdownTimeout, f.cancelWrites)
	})
}

// Close stops new writes and attempts a bounded delivery drain. Undelivered
// records remain on disk for replay; an offline collector is not a close error.
func (f *hecForwarder) Close() error {
	f.closeOnce.Do(func() {
		f.beginShutdown()
		f.shutdownWait.Stop()
		f.mu.Lock()
		f.closing = true
		f.cancelWrites()
		f.mu.Unlock()
		f.writes.Wait()
		f.start()
		close(f.stop)
		timer := time.NewTimer(f.shutdownTimeout)
		defer timer.Stop()
		select {
		case <-f.done:
		case <-timer.C:
			log.Printf("audit: splunk hec shutdown delivery deadline reached; pending events remain in the durable spool")
		}
		f.cancel()
		<-f.done
		f.client.CloseIdleConnections()
		f.closeErr = f.spool.Close()
	})
	return f.closeErr
}
