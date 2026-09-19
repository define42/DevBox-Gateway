package sauron

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/define42/SauronAgent/collector"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

const (
	// hecSource and hecSourcetype label every forwarded event. The sourcetype
	// needs no props.conf stanza: Splunk's default KV_MODE=auto extracts the
	// JSON envelope fields at search time.
	hecSource     = "sauronagent"
	hecSourcetype = "devbox-gateway:sauron"

	// hecBatchSize and hecBatchBytes bound one request to the collector.
	hecBatchSize  = 100
	hecBatchBytes = 1 << 20
	// hecRetryInitial and hecRetryLimit pace requests while the collector is
	// unreachable or refusing events.
	hecRetryInitial = time.Second
	hecRetryLimit   = 30 * time.Second
	// hecFailureReportInterval spaces out the log lines of a long outage.
	hecFailureReportInterval = 5 * time.Minute
)

// hecForwarding delivers guest events to Splunk HEC by store and forward. As
// a collector sink, Write accepts an event once it is on stable storage in the
// gateway's spool -- which is what the guest is then told -- so a guest never
// waits for Splunk, and deleting the VM loses nothing. A background forwarder
// delivers the spool to Splunk in order, whenever it is reachable, and resumes
// from its checkpoint after a gateway restart.
type hecForwarding struct {
	spool          *spool
	client         *splunkhec.Client
	retryInitial   time.Duration
	retryLimit     time.Duration
	reportInterval time.Duration

	// position is the next record to deliver. Only the forwarder uses it.
	position spoolPosition

	cancel    context.CancelFunc
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// newHECForwarding validates config and opens the spool; call start to begin
// delivering.
func newHECForwarding(config splunkhec.Config, spoolDir string, spoolMaxBytes int64) (*hecForwarding, error) {
	client, err := splunkhec.New(config)
	if err != nil {
		return nil, err
	}
	store, err := openSpool(spoolDir, spoolMaxBytes)
	if err != nil {
		return nil, err
	}
	if client.PlainHTTP() {
		log.Printf("sauron: splunk hec endpoint uses plain http; the hec token and guest events are sent unencrypted")
	}
	log.Printf("sauron: forwarding guest events to splunk hec at %s (index %q) through the spool in %s (%d MiB used of %d MiB)",
		client.Endpoint(), client.Index(), spoolDir, store.usage()>>20, spoolMaxBytes>>20)

	return &hecForwarding{
		spool:          store,
		client:         client,
		retryInitial:   hecRetryInitial,
		retryLimit:     hecRetryLimit,
		reportInterval: hecFailureReportInterval,
		position:       store.checkpoint,
		stop:           make(chan struct{}),
		done:           make(chan struct{}),
	}, nil
}

// start launches the forwarder.
func (h *hecForwarding) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go h.run(ctx)
}

// Name identifies the sink in the collector's logs.
func (h *hecForwarding) Name() string { return "splunk-hec-spool" }

// Flush has nothing to do: Write returns only once the event is durable.
func (h *hecForwarding) Flush(context.Context) error { return nil }

// Write spools env. A nil result means the event is on stable storage.
func (h *hecForwarding) Write(ctx context.Context, env *collector.Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var record bytes.Buffer
	encoder := json.NewEncoder(&record)
	// Command lines and paths are full of <, > and &; keep them readable, as
	// the event log does.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(env); err != nil {
		return fmt.Errorf("encode guest event for the splunk hec spool: %w", err)
	}
	return h.spool.Append(bytes.TrimSuffix(record.Bytes(), []byte("\n")))
}

// Close stops the forwarder, aborting a request in flight, and closes the
// spool. Undelivered events stay spooled for the next start.
func (h *hecForwarding) Close() error {
	h.closeOnce.Do(func() {
		close(h.stop)
		if h.cancel != nil {
			h.cancel()
			<-h.done
		}
		h.closeErr = h.spool.Close()
		h.client.CloseIdleConnections()
	})
	return h.closeErr
}

func (h *hecForwarding) run(ctx context.Context) {
	defer close(h.done)
	outage := outage{backoff: h.retryInitial}
	for {
		records, err := h.spool.readBatch(h.position, hecBatchSize, hecBatchBytes)
		if err == nil && len(records) == 0 {
			if !h.waitForRecords() {
				return
			}
			continue
		}
		if err == nil {
			err = h.deliverAndAdvance(ctx, records)
		}
		if !h.pace(&outage, err) {
			return
		}
	}
}

// waitForRecords blocks until the spool has new records, and reports false
// once the forwarder is stopping.
func (h *hecForwarding) waitForRecords() bool {
	select {
	case <-h.spool.ready:
		return true
	case <-h.stop:
		return false
	}
}

// outage tracks consecutive delivery failures.
type outage struct {
	failures   int
	backoff    time.Duration
	lastReport time.Time
}

// pace records the outcome of a delivery attempt. After a failure it logs --
// at the first failure, then every reportInterval -- and waits out the
// backoff; it reports false once the forwarder is stopping.
func (h *hecForwarding) pace(o *outage, err error) bool {
	if err == nil {
		if o.failures > 0 {
			log.Printf("sauron: splunk hec is accepting guest events again after %d failed attempt(s); delivering the spooled backlog", o.failures)
		}
		*o = outage{backoff: h.retryInitial}
		return true
	}

	o.failures++
	if now := time.Now(); o.failures == 1 || now.Sub(o.lastReport) >= h.reportInterval {
		o.lastReport = now
		log.Printf("sauron: splunk hec did not accept guest events (%d failed attempt(s)); they stay in the gateway spool (%d MiB used) and are retried at least every %s: %v",
			o.failures, h.spool.usage()>>20, h.retryLimit, err)
	}
	timer := time.NewTimer(o.backoff)
	defer timer.Stop()
	o.backoff = min(2*o.backoff, h.retryLimit)
	select {
	case <-timer.C:
		return true
	case <-h.stop:
		return false
	}
}

// deliverAndAdvance delivers records and moves the checkpoint past those
// that are settled.
func (h *hecForwarding) deliverAndAdvance(ctx context.Context, records []spoolRecord) error {
	settled, err := h.deliver(ctx, records)
	if settled > 0 {
		h.position = records[settled-1].end
		if ackErr := h.spool.acknowledge(h.position); ackErr != nil {
			log.Printf("sauron: %v", ackErr)
		}
	}
	return err
}

// spoolMeta is the part of a spooled envelope the HEC event metadata needs.
type spoolMeta struct {
	ReceivedAt time.Time `json:"received_at"`
	Source     struct {
		VM string `json:"vm"`
	} `json:"source"`
	Event struct {
		Type     string `json:"type"`
		Sequence uint64 `json:"sequence"`
	} `json:"event"`
}

// envelope wraps one spooled record in an HEC event. The event time is the
// gateway's receive time, not the guest's own timestamp: a guest's clock is as
// trustworthy as the guest, and a guest that set it far into the past could
// otherwise file its events where no search looks. The guest's time stays in
// the envelope as event.timestamp. The HEC host is the VM name, which the
// gateway derived from the connection's CID.
func (h *hecForwarding) envelope(record []byte) ([]byte, spoolMeta, error) {
	var meta spoolMeta
	if err := json.Unmarshal(record, &meta); err != nil {
		return nil, meta, err
	}
	received := meta.ReceivedAt
	if received.IsZero() {
		received = time.Now()
	}
	payload, err := json.Marshal(splunkhec.Envelope{
		Time:       splunkhec.Time(received),
		Host:       meta.Source.VM,
		Source:     hecSource,
		Sourcetype: hecSourcetype,
		Index:      h.client.Index(),
		Event:      record,
	})
	return payload, meta, err
}

// deliver sends records as one request and reports how many leading records
// are settled: delivered, or dropped because they can never be delivered.
func (h *hecForwarding) deliver(ctx context.Context, records []spoolRecord) (int, error) {
	payloads := make([][]byte, len(records))
	metas := make([]spoolMeta, len(records))
	var body []byte
	for i, record := range records {
		payload, meta, err := h.envelope(record.data)
		if err != nil {
			log.Printf("sauron: dropping an unreadable record from the splunk hec spool before %s: %v", record.end, err)
			continue
		}
		payloads[i], metas[i] = payload, meta
		body = append(body, payload...)
	}
	if len(body) == 0 {
		return len(records), nil
	}

	err := h.client.Post(ctx, body)
	switch {
	case err == nil:
		return len(records), nil
	case splunkhec.IsInvalidEvent(err):
		return h.isolate(ctx, payloads, metas)
	default:
		// Unreachable, overloaded, or refusing for a reason of its own
		// configuration: every event stays spooled for the next attempt.
		return 0, err
	}
}

// isolate sends the events of a batch the collector found invalid one at a
// time, to find the ones it will never accept -- malformed, or too large to
// index -- and drop them with a log line, so that one of them cannot hold up
// the backlog behind it for good. The decision rests on the collector's own
// verdict on each event, never on how other events fared, so a collector whose
// configuration is fixed mid-way cannot cause an event to be dropped.
func (h *hecForwarding) isolate(ctx context.Context, payloads [][]byte, metas []spoolMeta) (int, error) {
	for i, payload := range payloads {
		if payload == nil {
			continue
		}
		err := h.client.Post(ctx, payload)
		switch {
		case err == nil:
		case splunkhec.IsInvalidEvent(err):
			log.Printf("sauron: splunk hec rejected %s event %d from vm %s as invalid; dropping it from the spool: %v",
				metas[i].Event.Type, metas[i].Event.Sequence, metas[i].Source.VM, err)
		default:
			// Settle what came before; retry from here on the next attempt.
			return i, err
		}
	}
	return len(payloads), nil
}
