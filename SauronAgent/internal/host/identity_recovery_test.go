package host

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
	"github.com/define42/devbox-gateway/SauronAgent/internal/protocol"
)

func TestIdentityRecoveryReconnectsIncompleteSessions(t *testing.T) {
	for _, identity := range []string{"unknown", "empty UUID"} {
		for _, trigger := range []string{"event", "heartbeat"} {
			t.Run(identity+"/"+trigger, func(t *testing.T) {
				vm := config.VMMapping{CID: 7, Name: "alice.desktop", UUID: "vm-a"}
				healthyVM := config.VMMapping{CID: 8, Name: "bob.desktop", UUID: "vm-b"}
				resolver := newFakeResolver(healthyVM)
				if identity == "empty UUID" {
					resolver.vms[vm.CID] = config.VMMapping{CID: vm.CID, Name: vm.Name}
				}
				expected := []config.VMMapping{healthyVM}
				h := newHarnessWithOptions(t, func(c *config.Host) { c.VMs = nil }, func(o *Options) {
					o.Resolve = resolver.resolve
					o.ExpectedVMs = func() ([]config.VMMapping, error) { return expected, nil }
					o.StartupGrace = 5 * time.Minute
				})
				// Drive inventory explicitly; the harness disables the background
				// monitor so these transitions need no polling or wall-clock wait.
				h.setNow(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
				h.srv.monitor.enabled = true
				h.srv.monitor.refresh(h.now())
				g := h.dial(vm.CID, true)
				deliverOne(t, g, "boot-a")
				original := h.sink.events()[0].Source
				if original.UUID != "" || original.Known != (identity == "empty UUID") {
					t.Fatalf("unexpected initial attribution: %+v", original)
				}
				healthy := h.dial(healthyVM.CID, true)
				deliverOne(t, healthy, "boot-b")

				resolver.mu.Lock()
				resolver.vms[vm.CID] = vm
				resolver.mu.Unlock()
				expected = append(expected, vm)
				h.srv.monitor.refresh(h.now())
				h.setNow(h.now().Add(6 * time.Minute))
				h.srv.monitor.refresh(h.now())
				healthy.ping()
				h.srv.monitor.check(h.now())
				if h.srv.Readiness() == nil {
					t.Fatal("incompletely attributed agent should still be overdue")
				}

				if trigger == "event" {
					g.sendEvent(2, "boot-a")
				} else {
					g.send(protocol.MsgPing, 0, &protocol.Ping{AuditEnabled: true})
				}
				if reply := g.expectError(); reply.Code != protocol.ErrCodeInternal || !reply.Fatal || !strings.Contains(reply.Message, "reconnect") {
					t.Fatalf("identity recovery did not request reconnection: %+v", reply)
				}
				g.wantClosed()
				if len(h.sink.events()) != 2 {
					t.Fatal("the reconnect-triggering frame was written under the old identity")
				}
				if calls := resolver.callsFor(vm.CID); calls != 1 {
					t.Fatalf("identity recovery performed another lookup inside the session: %d", calls)
				}

				fresh := h.dial(vm.CID, true)
				ready := fresh.handshake(&protocol.Hello{BootID: "boot-a"})
				if ready.ResumeFrom != 1 {
					t.Fatalf("unaccepted frame advanced the checkpoint: %d", ready.ResumeFrom)
				}
				fresh.sendEvent(2, "boot-a")
				if ack := fresh.expectAck(); ack != 2 {
					t.Fatalf("replayed event ACK = %d, want 2", ack)
				}
				fresh.ping()
				last := h.sink.events()[2]
				if !last.Source.Known || last.Source.UUID != vm.UUID || last.Source.VM != vm.Name {
					t.Fatalf("reconnected event did not receive the trusted identity: %+v", last.Source)
				}
				if err := h.srv.Readiness(); err != nil {
					t.Fatalf("reconnection did not restore readiness: %v", err)
				}
				// The other VM's existing connection was never interrupted.
				healthy.sendEvent(2, "boot-b")
				if ack := healthy.expectAck(); ack != 2 {
					t.Fatalf("healthy guest ACK = %d, want 2", ack)
				}
				if got := h.sink.events()[0].Source; got.CID != original.CID || got.VM != original.VM || got.UUID != original.UUID || got.Known != original.Known {
					t.Fatal("the old connection's recorded attribution was changed")
				}
			})
		}
	}
}

func TestIdentityRecoveryKeepsResolvedConnectionPinnedAfterCIDReuse(t *testing.T) {
	vm := config.VMMapping{CID: 7, Name: "desktop", UUID: "original-vm"}
	resolver := newFakeResolver(vm)
	h := newHarnessWithOptions(t, func(c *config.Host) { c.VMs = nil }, func(o *Options) {
		o.Resolve = resolver.resolve
		o.ExpectedVMs = func() ([]config.VMMapping, error) { return []config.VMMapping{vm}, nil }
	})
	h.setNow(time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC))
	h.srv.monitor.enabled = true
	h.srv.monitor.refresh(h.now())
	g := h.dial(vm.CID, true)
	deliverOne(t, g, "old-boot")
	vm.UUID = "replacement-vm"
	resolver.mu.Lock()
	resolver.vms[vm.CID] = vm
	resolver.mu.Unlock()
	h.srv.monitor.refresh(h.now())
	h.setNow(h.now().Add(6 * time.Minute))
	h.srv.monitor.refresh(h.now())
	g.sendEvent(2, "old-boot")
	if ack := g.expectAck(); ack != 2 {
		t.Fatalf("old connection ACK = %d, want 2", ack)
	}
	g.ping()
	if got := h.sink.events()[1].Source.UUID; got != "original-vm" {
		t.Fatalf("old connection was relabeled as %q", got)
	}
	if calls := resolver.callsFor(vm.CID); calls != 1 {
		t.Fatalf("pinned connection triggered another lookup: %d", calls)
	}
	if h.srv.Readiness() == nil {
		t.Fatal("old connection refreshed the replacement VM's health")
	}
	deliverOne(t, h.dial(vm.CID, true), "replacement-boot")
	if err := h.srv.Readiness(); err != nil {
		t.Fatalf("replacement VM did not restore its own health: %v", err)
	}
}

func TestIdentityRecoveryRequiresFreshAuthoritativeInventory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*monitor, *peer, *output.Source, *testClock)
	}{
		{name: "no dynamic inventory", change: func(m *monitor, _ *peer, _ *output.Source, _ *testClock) { m.expected = nil }},
		{name: "monitor disabled", change: func(m *monitor, _ *peer, _ *output.Source, _ *testClock) { m.enabled = false }},
		{name: "non-vsock peer", change: func(_ *monitor, p *peer, _ *output.Source, _ *testClock) { p.vsock = false }},
		{name: "unmatched CID", change: func(_ *monitor, p *peer, _ *output.Source, _ *testClock) { p.cid++ }},
		{name: "missing expected UUID", change: func(m *monitor, p *peer, _ *output.Source, _ *testClock) { m.vms[p.cid].mapping.UUID = "" }},
		{name: "failed inventory", change: func(m *monitor, _ *peer, _ *output.Source, _ *testClock) {
			m.refreshErr = errors.New("libvirt unavailable")
		}},
		{name: "no successful refresh", change: func(m *monitor, _ *peer, _ *output.Source, _ *testClock) { m.lastRefresh = time.Time{} }},
		{name: "stale inventory", change: func(m *monitor, _ *peer, _ *output.Source, c *testClock) { c.advance(3*m.interval + time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, clock, _ := newDynamicMonitor(t)
			m.expected = func() ([]config.VMMapping, error) {
				return []config.VMMapping{{CID: 7, Name: "desktop", UUID: "vm-a"}}, nil
			}
			m.refresh(clock.Now())
			p := peer{cid: 7, vsock: true}
			src := output.Source{CID: 7, VM: "unknown-cid-7"}
			if !m.identityAvailable(p, src, clock.Now()) {
				t.Fatal("complete recovered identity was not available")
			}
			tc.change(m, &p, &src, clock)
			if m.identityAvailable(p, src, clock.Now()) {
				t.Fatal("session would reconnect without a fresh authoritative identity")
			}
		})
	}
}
