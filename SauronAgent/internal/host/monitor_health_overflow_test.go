package host

import (
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
	"github.com/define42/devbox-gateway/SauronAgent/internal/event"
	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

func TestMonitorAlertOverflowRemainsUnhealthyAfterDrain(t *testing.T) {
	m, clock, sink := newDynamicMonitor(t)
	vms := []config.VMMapping{{CID: 102, Name: "desktop", UUID: "vm-a"}}
	m.expected = func() ([]config.VMMapping, error) { return vms, nil }
	m.refresh(clock.Now())
	p := peer{cid: 102, vsock: true}
	src := output.Source{Known: true, VM: "desktop", UUID: "vm-a"}
	m.seen(p, src, clock.Now())
	sink.failInternal(event.TypeStreamLost, true)

	// A repeatedly disconnecting guest cannot grow the undelivered alert
	// queue indefinitely while the output rejects its first loss report.
	for i := 0; i < maxPendingStreamAlerts/2+3; i++ {
		clock.advance(m.timeout + time.Second)
		m.refresh(clock.Now())
		m.check(clock.Now())
		m.seen(p, src, clock.Now())
		if len(m.pending) > maxPendingStreamAlerts {
			t.Fatalf("alert queue grew beyond its cap: %d", len(m.pending))
		}
	}
	if len(m.pending) != maxPendingStreamAlerts || !m.overflow {
		t.Fatalf("overflow not recorded at the bound: pending=%d overflow=%v", len(m.pending), m.overflow)
	}
	if err := m.readiness(clock.Now()); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("overflow did not require operator recovery: %v", err)
	}

	// Removing the guest and recovering the output drains retained reports,
	// but cannot restore alerts rejected while the bounded queue was full.
	vms = nil
	m.refresh(clock.Now())
	sink.failInternal(event.TypeStreamLost, false)
	m.check(clock.Now())
	if len(m.pending) != 0 || len(sink.internals()) != maxPendingStreamAlerts {
		t.Fatalf("retained alerts did not drain: pending=%d delivered=%d", len(m.pending), len(sink.internals()))
	}
	if err := m.readiness(clock.Now()); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("draining alerts erased the earlier loss signal: %v", err)
	}
}
