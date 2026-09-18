package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HECConfig configures forwarding of audit records to a Splunk HTTP Event
// Collector. An empty Endpoint disables forwarding.
type HECConfig struct {
	// Endpoint is the collector URL. A URL without a path, such as
	// https://splunk.example.com:8088, is completed with the JSON event
	// endpoint /services/collector/event.
	Endpoint string
	// Token is the HEC token, sent as "Authorization: Splunk <token>".
	Token string
	// Index is the destination index; empty uses the token's default index.
	Index string
	// InsecureSkipVerify disables verification of the collector's TLS certificate.
	InsecureSkipVerify bool
}

const (
	hecEventPath = "/services/collector/event"
	// hecSource and hecSourcetype label every forwarded event. The dedicated
	// sourcetype needs no props.conf stanza: Splunk's default KV_MODE=auto
	// extracts the JSON event fields at search time.
	hecSource     = "devbox-gateway"
	hecSourcetype = "devbox-gateway:audit"

	// hecQueueCapacity bounds the events held in memory while the collector is
	// slow or unreachable; newer events are dropped (and counted) beyond it.
	hecQueueCapacity  = 10000
	hecBatchSize      = 100
	hecRequestTimeout = 10 * time.Second
	hecRetryInitial   = time.Second
	hecRetryLimit     = 30 * time.Second
	// hecShutdownTimeout bounds how long Close waits for queued events to be
	// delivered before abandoning them.
	hecShutdownTimeout = 5 * time.Second
	hecErrorBodyLimit  = 512
)

// hecEnvelope is the HEC JSON event format. Several envelopes are concatenated
// into one request body to send a batch.
type hecEnvelope struct {
	Time       json.Number     `json:"time"`
	Host       string          `json:"host,omitempty"`
	Source     string          `json:"source"`
	Sourcetype string          `json:"sourcetype"`
	Index      string          `json:"index,omitempty"`
	Event      json.RawMessage `json:"event"`
}

// hecForwarder is an io.Writer that ships each audit record it receives to a
// Splunk HEC from a background goroutine. It must never log through slog: the
// default slog logger is the audit logger, so doing so would feed its own
// diagnostics back into the audit stream. Operational messages use the
// standard log package instead.
type hecForwarder struct {
	endpoint      string
	authorization string
	index         string
	host          string
	client        *http.Client

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

// hecRejectedError marks a collector response that retrying cannot fix.
type hecRejectedError struct {
	err error
}

func (e *hecRejectedError) Error() string { return e.err.Error() }

func (e *hecRejectedError) Unwrap() error { return e.err }

// newHECForwarder validates config and builds a forwarder that is not yet
// running; call start before use.
func newHECForwarder(config HECConfig) (*hecForwarder, error) {
	endpoint, err := hecEventURL(config.Endpoint)
	if err != nil {
		return nil, err
	}
	index := strings.TrimSpace(config.Index)
	token := strings.TrimSpace(config.Token)
	if token == "" {
		return nil, fmt.Errorf("splunk hec token is empty")
	}
	if endpoint.Scheme == "http" {
		log.Printf("audit: splunk hec endpoint uses plain http; the hec token and audit events are sent unencrypted")
	}
	log.Printf("audit: forwarding audit events to splunk hec at %s (index %q)", endpoint.Redacted(), index)

	host, _ := os.Hostname()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- InsecureSkipVerify is an explicit operator opt-in via SPLUNK_HEC_SKIP_TLS_VERIFY (default off).
		InsecureSkipVerify: config.InsecureSkipVerify,
	}

	return &hecForwarder{
		endpoint:        endpoint.String(),
		authorization:   "Splunk " + token,
		index:           index,
		host:            host,
		client:          &http.Client{Transport: transport, Timeout: hecRequestTimeout},
		queue:           make(chan []byte, hecQueueCapacity),
		retryInitial:    hecRetryInitial,
		retryLimit:      hecRetryLimit,
		shutdownTimeout: hecShutdownTimeout,
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}, nil
}

// hecEventURL resolves the configured endpoint to the JSON event endpoint URL.
func hecEventURL(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil {
		return nil, fmt.Errorf("parse splunk hec endpoint: %w", err)
	}
	if (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return nil, fmt.Errorf("splunk hec endpoint %q must be an absolute http or https url", parsed.Redacted())
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = hecEventPath
	}
	return parsed, nil
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
	payload, err := json.Marshal(hecEnvelope{
		Time:       hecTime(time.Now()),
		Host:       f.host,
		Source:     hecSource,
		Sourcetype: hecSourcetype,
		Index:      f.index,
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

// hecTime formats t as the epoch seconds, with millisecond precision, that HEC
// expects in an event's time field.
func hecTime(t time.Time) json.Number {
	return json.Number(fmt.Sprintf("%d.%03d", t.Unix(), t.Nanosecond()/int(time.Millisecond)))
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

		err := f.post(ctx, body)
		if err == nil {
			if attempt > 1 {
				log.Printf("audit: splunk hec delivery recovered after %d attempts", attempt)
			}
			return
		}
		var rejected *hecRejectedError
		if errors.As(err, &rejected) {
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

func (f *hecForwarder) post(ctx context.Context, body []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build splunk hec request: %w", err)
	}
	request.Header.Set("Authorization", f.authorization)
	request.Header.Set("Content-Type", "application/json")

	response, err := f.client.Do(request)
	if err != nil {
		return fmt.Errorf("post to splunk hec: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		// Drain the acknowledgement so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil
	}

	detail, _ := io.ReadAll(io.LimitReader(response.Body, hecErrorBodyLimit))
	statusErr := fmt.Errorf("splunk hec responded %s: %s", response.Status, strings.TrimSpace(string(detail)))
	if hecRetryableStatus(response.StatusCode) {
		return statusErr
	}
	return &hecRejectedError{err: statusErr}
}

// hecRetryableStatus reports whether a failed request may succeed later
// without a gateway restart. Besides throttling and server errors this covers
// authentication failures, because a disabled token can be re-enabled on the
// Splunk side. Other client errors (bad request, incorrect index, wrong path)
// reject the batch itself, so retrying would block every later event.
func hecRetryableStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return true
	default:
		return status >= http.StatusInternalServerError
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
