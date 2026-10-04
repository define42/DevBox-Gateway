package host

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
	"github.com/define42/devbox-gateway/SauronAgent/internal/event"
	"github.com/define42/devbox-gateway/SauronAgent/internal/logging"
	"github.com/define42/devbox-gateway/SauronAgent/internal/metrics"
	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

func newDynamicMonitor(t *testing.T) (*monitor, *testClock, *fakeSink) {
	t.Helper()
	clock := &testClock{t: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	sink := newFakeSink()
	rep := &reporter{sink: sink, log: logging.Discard(), now: clock.Now}
	m := newMonitor(config.DefaultHost(), rep, &metrics.Host{}, logging.Discard(), clock.Now)
	m.startupGrace = 5 * time.Minute
	return m, clock, sink
}

func TestDynamicMonitorReportsNeverConnectedAndStoppedAgent(t *testing.T) {
	m, clock, sink := newDynamicMonitor(t)
	m.expected = func() ([]config.VMMapping, error) {
		return []config.VMMapping{{CID: 102, Name: "alice.desktop", UUID: "vm-a"}}, nil
	}
	m.refresh(clock.Now())
	clock.advance(4 * time.Minute)
	m.refresh(clock.Now())
	m.check(clock.Now())
	if err := m.readiness(clock.Now()); err != nil || len(sink.internals()) != 0 {
		t.Fatalf("new VM did not receive its boot grace: readiness=%v", err)
	}
	clock.advance(61 * time.Second)
	m.refresh(clock.Now())
	m.check(clock.Now())
	assertMonitorAlertTypes(t, sink, event.TypeStreamLost)
	if err := m.readiness(clock.Now()); err == nil {
		t.Fatal("never-connected agent remained ready")
	}
	if got := sink.internals()[0].Event.Fields["never_connected"]; got != true {
		t.Fatalf("never_connected = %v, want true", got)
	}
	m.seen(peer{cid: 102, vsock: true}, output.Source{Known: true, VM: "alice.desktop", UUID: "vm-a"}, clock.Now())
	if err := m.readiness(clock.Now()); err != nil {
		t.Fatalf("reconnected agent not ready: %v", err)
	}
	clock.advance(91 * time.Second)
	m.refresh(clock.Now())
	m.check(clock.Now())
	assertMonitorAlertTypes(t, sink, event.TypeStreamLost, event.TypeStreamResumed, event.TypeStreamLost)
	if got := sink.internals()[2].Event.Fields["never_connected"]; got != false {
		t.Fatalf("stopped agent marked never-connected: %v", got)
	}
}

func TestDynamicMonitorRetainsExpectationsOnLookupFailure(t *testing.T) {
	m, clock, _ := newDynamicMonitor(t)
	lookupErr := error(nil)
	vms := []config.VMMapping{{CID: 102, Name: "desktop"}}
	m.expected = func() ([]config.VMMapping, error) { return vms, lookupErr }
	m.refresh(clock.Now())
	lookupErr = errors.New("hypervisor unavailable")
	vms = nil
	m.refresh(clock.Now())
	if !errors.Is(m.readiness(clock.Now()), lookupErr) || len(m.vms) != 1 {
		t.Fatal("failed lookup discarded expectations or remained ready")
	}
	lookupErr = nil
	m.refresh(clock.Now())
	if err := m.readiness(clock.Now()); err != nil || len(m.vms) != 0 {
		t.Fatalf("successful empty inventory did not retire stopped VMs: %v", err)
	}
	clock.advance(46 * time.Second)
	if err := m.readiness(clock.Now()); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stalled expectation refresh remained ready: %v", err)
	}
}

func TestDynamicMonitorDoesNotTrustOldConnectionAfterCIDReuse(t *testing.T) {
	m, clock, sink := newDynamicMonitor(t)
	vm := config.VMMapping{CID: 102, Name: "desktop", UUID: "old"}
	m.expected = func() ([]config.VMMapping, error) { return []config.VMMapping{vm}, nil }
	m.refresh(clock.Now())
	m.seen(peer{cid: 102, vsock: true}, output.Source{Known: true, VM: "desktop", UUID: "old"}, clock.Now())
	vm.UUID = "replacement"
	m.refresh(clock.Now())
	clock.advance(6 * time.Minute)
	m.seen(peer{cid: 102, vsock: true}, output.Source{Known: true, VM: "desktop", UUID: "old"}, clock.Now())
	m.refresh(clock.Now())
	m.check(clock.Now())
	assertMonitorAlertTypes(t, sink, event.TypeStreamLost)
	if sink.internals()[0].Source.UUID != "replacement" {
		t.Fatal("CID reuse retained the old VM attribution")
	}
}

func TestMonitorRetriesLostAndResumedAlertsAfterOutputRecovery(t *testing.T) {
	m, clock, sink := newDynamicMonitor(t)
	vms := []config.VMMapping{{CID: 102, Name: "desktop", UUID: "vm-a"}}
	m.expected = func() ([]config.VMMapping, error) { return vms, nil }
	m.refresh(clock.Now())
	sink.failInternal(event.TypeStreamLost, true)
	clock.advance(6 * time.Minute)
	m.refresh(clock.Now())
	m.check(clock.Now())
	m.check(clock.Now())
	if len(sink.internals()) != 0 || m.metrics.StreamsLost.Load() != 1 {
		t.Fatal("failed alert was accepted or counted repeatedly")
	}
	m.seen(peer{cid: 102, vsock: true}, output.Source{Known: true, VM: "desktop", UUID: "vm-a"}, clock.Now())
	vms = nil // Even removing the VM must not discard its undelivered alert.
	m.refresh(clock.Now())
	if err := m.readiness(clock.Now()); err == nil {
		t.Fatal("pending stream alerts did not degrade readiness")
	}
	sink.failInternal(event.TypeStreamLost, false)
	m.check(clock.Now())
	assertMonitorAlertTypes(t, sink, event.TypeStreamLost, event.TypeStreamResumed)
	if err := m.readiness(clock.Now()); err != nil {
		t.Fatalf("monitor did not recover with its output: %v", err)
	}
	m.check(clock.Now())
	assertMonitorAlertTypes(t, sink, event.TypeStreamLost, event.TypeStreamResumed)
}

func TestMonitorRetriesRejectedResumeAlert(t *testing.T) {
	m, clock, sink := newDynamicMonitor(t)
	m.expected = func() ([]config.VMMapping, error) {
		return []config.VMMapping{{CID: 102, Name: "desktop"}}, nil
	}
	m.refresh(clock.Now())
	clock.advance(6 * time.Minute)
	m.refresh(clock.Now())
	m.check(clock.Now())
	sink.failInternal(event.TypeStreamResumed, true)
	m.seen(peer{cid: 102, vsock: true}, output.Source{Known: true, VM: "desktop"}, clock.Now())
	if err := m.readiness(clock.Now()); err == nil {
		t.Fatal("rejected resume alert remained ready")
	}
	sink.failInternal(event.TypeStreamResumed, false)
	m.check(clock.Now())
	assertMonitorAlertTypes(t, sink, event.TypeStreamLost, event.TypeStreamResumed)
}

func TestDynamicMonitorRejectsInvalidInventory(t *testing.T) {
	for _, vms := range [][]config.VMMapping{
		{{CID: 0, Name: "missing-vsock"}},
		{{CID: 102}},
		{{CID: 102, Name: "one"}, {CID: 102, Name: "two"}},
	} {
		m, clock, _ := newDynamicMonitor(t)
		m.expected = func() ([]config.VMMapping, error) { return vms, nil }
		m.refresh(clock.Now())
		if err := m.readiness(clock.Now()); err == nil {
			t.Fatalf("invalid inventory reported ready: %+v", vms)
		}
	}
}

func assertMonitorAlertTypes(t *testing.T, sink *fakeSink, want ...string) {
	t.Helper()
	events := sink.internals()
	if len(events) != len(want) {
		t.Fatalf("got %d alerts, want %d: %+v", len(events), len(want), events)
	}
	for i, env := range events {
		if env.Event.Type != want[i] {
			t.Fatalf("alert %d = %s, want %s", i, env.Event.Type, want[i])
		}
	}
}
