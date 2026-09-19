package host

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/output"
)

// tickerFunc produces the monitor's check ticker. Tests replace it so that
// stream-loss detection is driven deterministically instead of by sleeping.
type tickerFunc func(d time.Duration) (<-chan time.Time, func())

// realTicker is the production ticker.
func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// monitor tracks the health of each VM's audit stream.
//
// This exists because of DESIGN section 28: a missing audit stream is itself a
// security event. A fully compromised guest can disable auditing, kill the
// agent or block the VSOCK path, and silencing the telemetry is the first thing
// an intruder does -- so the absence of events has to be as loud as the events
// themselves. Nothing inside the guest can suppress this: the timer runs on the
// hypervisor and fires on silence.
//
// Only VMs configured with expected: true are watched. A VM that is rebuilt
// several times a day would otherwise produce an alert an operator learns to
// ignore, which is worse than no alert at all.
type monitor struct {
	enabled  bool
	timeout  time.Duration
	interval time.Duration

	report  *reporter
	metrics *metrics.Host
	log     *slog.Logger
	now     func() time.Time
	ticker  tickerFunc

	mu  sync.Mutex
	vms map[uint32]*vmHealth
}

// vmHealth is the per-VM state.
type vmHealth struct {
	mapping  config.VMMapping
	source   output.Source
	lastSeen time.Time
	lost     bool
}

// newMonitor builds the stream-health tracker for the expected VMs in cfg.
func newMonitor(cfg config.Host, rep *reporter, counters *metrics.Host, log *slog.Logger, now func() time.Time) *monitor {
	m := &monitor{
		enabled:  cfg.Monitor.Enabled,
		timeout:  cfg.Monitor.Timeout.Duration(),
		interval: cfg.Monitor.CheckInterval.Duration(),
		report:   rep,
		metrics:  counters,
		log:      log,
		now:      now,
		ticker:   realTicker,
		vms:      make(map[uint32]*vmHealth),
	}
	enrich := newEnricher(cfg, nil)
	for _, vm := range cfg.VMs {
		if !vm.Expected {
			continue
		}
		m.vms[vm.CID] = &vmHealth{
			mapping: vm,
			// The source of a stream-loss event is the configured mapping: the
			// event is about a VM the operator declared, and there is no
			// connection to take an identity from.
			source: enrich.source(peer{cid: vm.CID, vsock: true}),
		}
	}
	return m
}

// run evaluates stream health every check interval until ctx is cancelled.
func (m *monitor) run(ctx context.Context) {
	if !m.enabled || m.interval <= 0 || len(m.vms) == 0 {
		return
	}

	// Silence is measured from the moment the collector started watching, not
	// from process start or from the zero time: a collector restart must not
	// report every expected VM as lost before its agent has had a chance to
	// reconnect.
	start := m.now()
	m.mu.Lock()
	for _, h := range m.vms {
		h.lastSeen = start
	}
	m.mu.Unlock()

	tick, stop := m.ticker(m.interval)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			m.check(m.now())
		}
	}
}

// seen records that a guest was heard from: a connection, an event or a
// heartbeat all count, because any of them proves the agent is alive and the
// path to it is open.
func (m *monitor) seen(p peer, at time.Time) {
	if !p.vsock {
		// An unidentified peer cannot be attributed to a configured VM, and
		// letting one refresh a VM's health would mean a peer with no
		// hypervisor-backed identity could silence that VM's alert.
		return
	}

	m.mu.Lock()
	h, tracked := m.vms[p.cid]
	if !tracked {
		m.mu.Unlock()
		return
	}
	silence := at.Sub(h.lastSeen)
	if at.After(h.lastSeen) {
		h.lastSeen = at
	}
	resumed := h.lost
	if resumed {
		h.lost = false
	}
	src := h.source
	name := h.mapping.Name
	m.mu.Unlock()

	if !resumed {
		return
	}
	m.log.Warn("audit stream resumed", "vm", name, "cid", p.cid,
		"silent_for", silence.String())
	// Published outside the lock: a sink write is not something to hold a
	// mutex across when every session goroutine needs this map.
	m.report.publish(context.Background(), src,
		event.NewInternal(event.TypeStreamResumed, event.SeverityNotice, map[string]any{
			"vm":              name,
			"cid":             p.cid,
			"silent_seconds":  silence.Seconds(),
			"monitor_timeout": m.timeout.String(),
		}))
}

// check reports every expected VM that has gone silent for longer than the
// configured timeout.
func (m *monitor) check(now time.Time) {
	type lostVM struct {
		src     output.Source
		name    string
		cid     uint32
		last    time.Time
		silence time.Duration
	}
	var lost []lostVM

	m.mu.Lock()
	for cid, h := range m.vms {
		if h.lost {
			continue
		}
		silence := now.Sub(h.lastSeen)
		if silence <= m.timeout {
			continue
		}
		h.lost = true
		lost = append(lost, lostVM{
			src: h.source, name: h.mapping.Name, cid: cid,
			last: h.lastSeen, silence: silence,
		})
	}
	m.mu.Unlock()

	for _, v := range lost {
		m.metrics.StreamsLost.Add(1)
		m.log.Error("audit stream lost", "vm", v.name, "cid", v.cid,
			"last_seen", v.last.UTC().Format(time.RFC3339Nano),
			"silent_for", v.silence.String(), "monitor_timeout", m.timeout.String())
		m.report.publish(context.Background(), v.src,
			event.NewInternal(event.TypeStreamLost, event.SeverityCritical, map[string]any{
				"vm":              v.name,
				"cid":             v.cid,
				"last_seen":       v.last.UTC().Format(time.RFC3339Nano),
				"silent_seconds":  v.silence.Seconds(),
				"monitor_timeout": m.timeout.String(),
			}))
	}
}
