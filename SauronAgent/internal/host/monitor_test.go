package host

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/output"
)

// testClock is the monitor's injected clock. Stream loss is a timeout, and a
// test that waited for a real one would either be slow or flaky.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// monitorFixture wires a monitor to a fake sink, a driven ticker and a clock.
type monitorFixture struct {
	m        *monitor
	sink     *fakeSink
	counters *metrics.Host
	clock    *testClock
	ticks    chan time.Time
	internal chan *output.Envelope
	stopped  chan struct{}
}

func newMonitorFixture(t *testing.T) *monitorFixture {
	t.Helper()

	cfg := config.DefaultHost()
	cfg.Host.Name = "hypervisor-test"
	cfg.Monitor.Enabled = true
	cfg.Monitor.Timeout = config.Duration(90 * time.Second)
	cfg.Monitor.CheckInterval = config.Duration(15 * time.Second)
	cfg.VMs = []config.VMMapping{
		{CID: 102, Name: "transfer-vm-03", Environment: "production", Expected: true},
		// Rebuilt several times a day: a gap in its stream is routine, and an
		// alert nobody can act on is worse than none.
		{CID: 200, Name: "build-runner-07", Expected: false},
	}

	f := &monitorFixture{
		sink:     newFakeSink(),
		counters: &metrics.Host{},
		clock:    &testClock{t: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)},
		ticks:    make(chan time.Time),
		internal: make(chan *output.Envelope, 16),
		stopped:  make(chan struct{}),
	}
	rep := &reporter{
		sink:    f.sink,
		onEvent: func(env *output.Envelope) { f.internal <- env },
		log:     logging.Discard(),
		now:     f.clock.Now,
	}
	f.m = newMonitor(cfg, rep, f.counters, logging.Discard(), f.clock.Now)
	f.m.ticker = func(time.Duration) (<-chan time.Time, func()) { return f.ticks, func() {} }

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(f.stopped)
		f.m.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-f.stopped:
		case <-time.After(testTimeout):
			t.Fatal("the monitor did not stop")
		}
	})
	return f
}

// tick drives one health check. The send completes only once run has received
// it, so the monitor's start-up state is settled by the time it returns.
func (f *monitorFixture) tick() {
	f.ticks <- f.clock.Now()
}

func (f *monitorFixture) waitInternal(t *testing.T, typ string) *output.Envelope {
	t.Helper()
	select {
	case env := <-f.internal:
		if env.Event.Type != typ {
			t.Fatalf("got a %s event, want %s", env.Event.Type, typ)
		}
		return env
	case <-time.After(testTimeout):
		t.Fatalf("no %s event was reported", typ)
		return nil
	}
}

func TestMonitorReportsAndResumesAnExpectedStream(t *testing.T) {
	f := newMonitorFixture(t)

	// Silence is measured from the moment the collector started watching, so a
	// restart does not alarm before the agents have reconnected.
	f.tick()
	select {
	case env := <-f.internal:
		t.Fatalf("a %s event was reported before the timeout elapsed", env.Event.Type)
	default:
	}

	f.clock.advance(91 * time.Second)
	f.tick()

	env := f.waitInternal(t, event.TypeStreamLost)
	if env.Event.Severity != event.SeverityCritical {
		t.Errorf("severity = %q, want %q: a silenced stream is a security event",
			env.Event.Severity, event.SeverityCritical)
	}
	if env.Source.VM != "transfer-vm-03" || !env.Source.Known || env.Source.CID != 102 {
		t.Errorf("Source = %+v, want the configured mapping for CID 102", env.Source)
	}
	if env.Source.Host != "hypervisor-test" {
		t.Errorf("Source.Host = %q, want the hypervisor name", env.Source.Host)
	}
	if got := env.Event.Fields["vm"]; got != "transfer-vm-03" {
		t.Errorf("vm field = %v", got)
	}
	if got := env.Event.Fields["cid"]; got != uint32(102) {
		t.Errorf("cid field = %v, want 102", got)
	}
	if !env.ReceivedAt.Equal(f.clock.Now()) {
		t.Errorf("ReceivedAt = %s, want the host clock", env.ReceivedAt)
	}
	if got := f.counters.StreamsLost.Load(); got != 1 {
		t.Errorf("StreamsLost = %d, want 1", got)
	}

	// A second check while it is still silent must not repeat the alert.
	f.clock.advance(91 * time.Second)
	f.tick()
	select {
	case env := <-f.internal:
		t.Fatalf("stream loss was reported twice: %s", env.Event.Type)
	default:
	}

	// The agent comes back.
	f.m.seen(peer{cid: 102, vsock: true}, f.clock.Now())
	resumed := f.waitInternal(t, event.TypeStreamResumed)
	if resumed.Source.VM != "transfer-vm-03" {
		t.Errorf("resume reported for %q", resumed.Source.VM)
	}
	if resumed.Event.Severity != event.SeverityNotice {
		t.Errorf("severity = %q, want %q", resumed.Event.Severity, event.SeverityNotice)
	}

	// Both events reached the sink, not only the callback: they belong in the
	// same stream as the audit data an analyst is already watching.
	var lost, back int
	for _, env := range f.sink.internals() {
		switch env.Event.Type {
		case event.TypeStreamLost:
			lost++
		case event.TypeStreamResumed:
			back++
		}
	}
	if lost != 1 || back != 1 {
		t.Errorf("sink holds %d lost and %d resumed events, want 1 and 1", lost, back)
	}
}

func TestMonitorIgnoresVMsThatAreNotExpected(t *testing.T) {
	f := newMonitorFixture(t)
	f.tick() // settle the start time before moving the clock

	f.clock.advance(10 * time.Minute)
	f.tick()

	env := f.waitInternal(t, event.TypeStreamLost)
	if env.Source.CID != 102 {
		t.Fatalf("stream loss reported for CID %d", env.Source.CID)
	}
	select {
	case other := <-f.internal:
		t.Fatalf("a VM that is not expected produced %s for CID %d",
			other.Event.Type, other.Source.CID)
	default:
	}
}

func TestMonitorIgnoresPeersWithNoHypervisorIdentity(t *testing.T) {
	f := newMonitorFixture(t)
	f.tick() // settle the start time

	// A peer with no hypervisor-backed identity claims nothing that can refresh
	// a configured VM's health. Otherwise anything that could reach the
	// collector could silence a VM's alert by connecting.
	f.m.seen(peer{cid: 102, vsock: false}, f.clock.Now().Add(10*time.Minute))

	f.clock.advance(91 * time.Second)
	f.tick()
	if env := f.waitInternal(t, event.TypeStreamLost); env.Source.CID != 102 {
		t.Fatalf("stream loss reported for CID %d, want 102", env.Source.CID)
	}
}

func TestMonitorDisabledDoesNothing(t *testing.T) {
	cfg := config.DefaultHost()
	cfg.Monitor.Enabled = false
	cfg.VMs = []config.VMMapping{{CID: 102, Name: "transfer-vm-03", Expected: true}}

	clock := &testClock{t: time.Now()}
	rep := &reporter{sink: newFakeSink(), log: logging.Discard(), now: clock.Now}
	m := newMonitor(cfg, rep, &metrics.Host{}, logging.Discard(), clock.Now)
	m.ticker = func(time.Duration) (<-chan time.Time, func()) {
		t.Fatal("a disabled monitor started a ticker")
		return nil, func() {}
	}

	done := make(chan struct{})
	go func() { defer close(done); m.run(context.Background()) }()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("a disabled monitor did not return immediately")
	}
}
