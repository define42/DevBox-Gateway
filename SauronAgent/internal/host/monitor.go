package host

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
	"github.com/define42/devbox-gateway/SauronAgent/internal/event"
	"github.com/define42/devbox-gateway/SauronAgent/internal/metrics"
	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

// tickerFunc lets tests drive health checks without wall-clock sleeps.
type tickerFunc func(d time.Duration) (<-chan time.Time, func())

func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// monitor watches trusted expected VMs, independently of whether their agents
// ever connect. Guest-supplied names cannot refresh another VM's health.
type monitor struct {
	enabled      bool
	timeout      time.Duration
	startupGrace time.Duration
	interval     time.Duration
	hostName     string
	expected     func() ([]config.VMMapping, error)

	report  *reporter
	metrics *metrics.Host
	log     *slog.Logger
	now     func() time.Time
	ticker  tickerFunc

	mu          sync.Mutex
	vms         map[uint32]*vmHealth
	lastRefresh time.Time
	refreshErr  error
	pending     []*streamAlert
	publishing  bool
	overflow    bool
}

type vmHealth struct {
	mapping  config.VMMapping
	source   output.Source
	lastSeen time.Time
	observed bool
	lost     bool
}

type streamAlert struct {
	source output.Source
	event  *event.Event
}

// A failed output must not allow a flapping guest to grow memory indefinitely.
// Saturation is a sticky readiness failure and is logged explicitly.
const maxPendingStreamAlerts = 4096

func newMonitor(cfg config.Host, rep *reporter, counters *metrics.Host, log *slog.Logger, now func() time.Time) *monitor {
	m := &monitor{
		enabled: cfg.Monitor.Enabled, timeout: cfg.Monitor.Timeout.Duration(),
		startupGrace: cfg.Monitor.Timeout.Duration(), interval: cfg.Monitor.CheckInterval.Duration(),
		hostName: cfg.Host.Name, report: rep, metrics: counters, log: log,
		now: now, ticker: realTicker, vms: make(map[uint32]*vmHealth),
	}
	for _, vm := range cfg.VMs {
		if vm.Expected {
			m.vms[vm.CID] = m.newVMHealth(vm, now())
		}
	}
	return m
}

func (m *monitor) newVMHealth(vm config.VMMapping, now time.Time) *vmHealth {
	vm.Labels = cloneGapSource(output.Source{Labels: vm.Labels}).Labels
	return &vmHealth{
		mapping: vm, lastSeen: now,
		source: output.Source{
			CID: vm.CID, VM: vm.Name, UUID: vm.UUID, Host: m.hostName, Known: true,
			Environment: vm.Environment, SecurityDomain: vm.SecurityDomain,
			VLAN: vm.VLAN, Labels: vm.Labels,
		},
	}
}

// run refreshes dynamic expectations and evaluates stream health until stopped.
func (m *monitor) run(ctx context.Context) {
	if !m.enabled || m.interval <= 0 {
		return
	}
	m.mu.Lock()
	for _, h := range m.vms {
		if !h.observed {
			h.lastSeen = m.now()
		}
	}
	m.mu.Unlock()
	m.refresh(m.now())
	tick, stop := m.ticker(m.interval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			m.refresh(m.now())
			m.checkContext(ctx, m.now())
		}
	}
}

// seen records a completed handshake, event or heartbeat. The source was pinned
// at connection admission: an old connection cannot refresh a replacement VM
// after its CID has been reused by the hypervisor.
func (m *monitor) seen(p peer, src output.Source, at time.Time) {
	if !m.enabled || !p.vsock {
		return
	}
	m.mu.Lock()
	h := m.vms[p.cid]
	if h == nil || !src.Known || h.mapping.Name != src.VM || h.mapping.UUID != src.UUID {
		m.mu.Unlock()
		return
	}
	silence := at.Sub(h.lastSeen)
	if at.After(h.lastSeen) {
		h.lastSeen = at
	}
	h.observed = true
	if h.lost {
		m.resumeLocked(h, silence)
	}
	m.mu.Unlock()
	m.publishPending(context.Background())
}

func (m *monitor) resumeLocked(h *vmHealth, silence time.Duration) {
	ev := event.NewInternal(event.TypeStreamResumed, event.SeverityNotice, map[string]any{
		"vm": h.mapping.Name, "cid": h.mapping.CID,
		"silent_seconds": silence.Seconds(), "monitor_timeout": m.timeout.String(),
	})
	if m.queueLocked(h.source, ev) {
		h.lost = false
		m.log.Warn("audit stream resumed", "vm", h.mapping.Name, "cid", h.mapping.CID)
	}
}

func (m *monitor) check(now time.Time) {
	m.checkContext(context.Background(), now)
}

func (m *monitor) checkContext(ctx context.Context, now time.Time) {
	m.mu.Lock()
	for _, h := range m.vms {
		silence := now.Sub(h.lastSeen)
		if silence <= m.allowedSilence(h) {
			if h.lost && h.observed {
				m.resumeLocked(h, silence)
			}
			continue
		}
		if !h.lost {
			m.loseLocked(h, silence)
		}
	}
	m.mu.Unlock()
	m.publishPending(ctx)
}

func (m *monitor) allowedSilence(h *vmHealth) time.Duration {
	if !h.observed {
		return m.startupGrace
	}
	return m.timeout
}

func (m *monitor) loseLocked(h *vmHealth, silence time.Duration) {
	ev := event.NewInternal(event.TypeStreamLost, event.SeverityCritical, map[string]any{
		"vm": h.mapping.Name, "cid": h.mapping.CID,
		"last_seen":      h.lastSeen.UTC().Format(time.RFC3339Nano),
		"silent_seconds": silence.Seconds(), "monitor_timeout": m.timeout.String(),
		"never_connected": !h.observed,
	})
	if m.queueLocked(h.source, ev) {
		h.lost = true
		m.metrics.StreamsLost.Add(1)
		m.log.Error("audit stream lost", "vm", h.mapping.Name, "cid", h.mapping.CID,
			"silent_for", silence.String(), "never_connected", !h.observed)
	}
}

func (m *monitor) queueLocked(src output.Source, ev *event.Event) bool {
	if len(m.pending) >= maxPendingStreamAlerts {
		if !m.overflow {
			m.log.Error("stream alert backlog full; collector readiness requires operator recovery")
		}
		m.overflow = true
		return false
	}
	m.pending = append(m.pending, &streamAlert{source: cloneGapSource(src), event: ev})
	return true
}

// publishPending serializes publication without holding the health lock over
// I/O. Failed writes retain the same event; later checks retry even after the
// VM resumes or is removed from the expected set. Recovery follows loss in FIFO
// order. A multi-sink partial failure can duplicate alerts on retry.
func (m *monitor) publishPending(ctx context.Context) {
	m.mu.Lock()
	if m.publishing {
		m.mu.Unlock()
		return
	}
	m.publishing = true
	attempts := len(m.pending)
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.publishing = false; m.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for range attempts {
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		pending := m.pending[0]
		m.mu.Unlock()
		if err := m.report.publish(ctx, pending.source, pending.event); err != nil {
			return
		}
		m.mu.Lock()
		m.pending[0] = nil
		m.pending = m.pending[1:]
		m.mu.Unlock()
	}
}
