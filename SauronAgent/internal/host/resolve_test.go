package host

import (
	"sync"
	"testing"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/protocol"
)

// fakeResolver stands in for Options.Resolve: a live CID-to-VM mapping such as
// an embedding program derives from its hypervisor. It counts lookups per CID.
type fakeResolver struct {
	mu    sync.Mutex
	vms   map[uint32]config.VMMapping
	calls map[uint32]int
}

func newFakeResolver(vms ...config.VMMapping) *fakeResolver {
	r := &fakeResolver{vms: make(map[uint32]config.VMMapping), calls: make(map[uint32]int)}
	for _, vm := range vms {
		r.vms[vm.CID] = vm
	}
	return r
}

func (r *fakeResolver) resolve(cid uint32) (config.VMMapping, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[cid]++
	vm, ok := r.vms[cid]
	return vm, ok
}

func (r *fakeResolver) callsFor(cid uint32) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[cid]
}

func (r *fakeResolver) totalCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, n := range r.calls {
		total += n
	}
	return total
}

func newResolvingHarness(t *testing.T, r *fakeResolver, tweak func(*config.Host)) *harness {
	t.Helper()
	return newHarnessWithOptions(t, tweak, func(o *Options) { o.Resolve = r.resolve })
}

// deliverOne runs a guest through the handshake and one acknowledged event.
func deliverOne(t *testing.T, g *guest, boot string) {
	t.Helper()
	g.handshake(&protocol.Hello{AgentVersion: "test", Hostname: "guest-claim", BootID: boot})
	g.sendEvent(1, boot)
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}
}

func TestResolveSuppliesTheTrustedSource(t *testing.T) {
	r := newFakeResolver(config.VMMapping{
		CID:    7,
		Name:   "alice-dev",
		UUID:   "4f7c1b9e-0d52-4c55-9b8a-3e1f2a6d7c80",
		Labels: map[string]string{"owner": "alice"},
	})
	h := newResolvingHarness(t, r, nil)

	deliverOne(t, h.dial(7, true), "boot-a")

	envs := h.sink.events()
	if len(envs) != 1 {
		t.Fatalf("got %d events, want 1", len(envs))
	}
	src := envs[0].Source
	if !src.Known || src.CID != 7 || src.VM != "alice-dev" {
		t.Fatalf("Source = %+v, want the resolved VM alice-dev on CID 7, known", src)
	}
	if src.UUID != "4f7c1b9e-0d52-4c55-9b8a-3e1f2a6d7c80" || src.Labels["owner"] != "alice" {
		t.Errorf("resolved metadata not attached: uuid=%q labels=%v", src.UUID, src.Labels)
	}
	if src.Host != "hypervisor-test" {
		t.Errorf("Source.Host = %q, want the configured hypervisor name", src.Host)
	}
	if src.Reported == nil || src.Reported.Hostname != "guest-claim" {
		t.Errorf("the guest's claim was not kept under Reported: %+v", src.Reported)
	}
}

func TestResolveIsConsultedOncePerConnection(t *testing.T) {
	r := newFakeResolver(config.VMMapping{CID: 7, Name: "alice-dev"})
	h := newResolvingHarness(t, r, nil)

	g := h.dial(7, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	for seq := uint64(1); seq <= 3; seq++ {
		g.sendEvent(seq, "boot-a")
		if ack := g.expectAck(); ack != seq {
			t.Fatalf("ACK = %d, want %d", ack, seq)
		}
	}

	// Admission and every event of the session share one answer: resolving
	// again mid-session could relabel the stream if the CID were reassigned.
	if got := r.callsFor(7); got != 1 {
		t.Errorf("Resolve called %d times for one connection, want 1", got)
	}

	// A new connection is a new question.
	deliverOne(t, h.dial(7, true), "boot-b")
	if got := r.callsFor(7); got != 2 {
		t.Errorf("Resolve called %d times for two connections, want 2", got)
	}
}

func TestResolveTakesPrecedenceOverConfiguredVMs(t *testing.T) {
	// The harness configures CID 102 as transfer-vm-03. The resolver reflects
	// what is running now, so it wins.
	r := newFakeResolver(config.VMMapping{CID: 102, Name: "live-name"})
	h := newResolvingHarness(t, r, nil)

	deliverOne(t, h.dial(102, true), "boot-a")

	envs := h.sink.events()
	if len(envs) != 1 || envs[0].Source.VM != "live-name" {
		t.Fatalf("events = %+v, want one from the resolved name live-name", envs)
	}
}

func TestResolveMissFallsBackToConfiguredVMs(t *testing.T) {
	r := newFakeResolver()
	h := newResolvingHarness(t, r, nil)

	deliverOne(t, h.dial(102, true), "boot-a")

	envs := h.sink.events()
	if len(envs) != 1 {
		t.Fatalf("got %d events, want 1", len(envs))
	}
	if src := envs[0].Source; !src.Known || src.VM != "transfer-vm-03" {
		t.Errorf("Source = %+v, want the configured transfer-vm-03", src)
	}
	if got := r.callsFor(102); got != 1 {
		t.Errorf("Resolve called %d times, want 1 before falling back", got)
	}
}

func TestResolveIsNotConsultedForUnidentifiedPeers(t *testing.T) {
	r := newFakeResolver(config.VMMapping{CID: cidUnidentified, Name: "must-not-be-used"})
	h := newResolvingHarness(t, r, func(c *config.Host) { c.Limits.AllowUnknownCIDs = true })

	// vsock=false: a TCP development peer has no hypervisor-backed CID, so
	// there is nothing to resolve and nothing a resolver may attach to it.
	deliverOne(t, h.dial(0, false), "boot-a")

	envs := h.sink.events()
	if len(envs) != 1 {
		t.Fatalf("got %d events, want 1", len(envs))
	}
	if src := envs[0].Source; src.Known || src.VM == "must-not-be-used" {
		t.Errorf("an unidentified peer was given a resolved identity: %+v", src)
	}
	if got := r.totalCalls(); got != 0 {
		t.Errorf("Resolve called %d times for a peer with no CID, want 0", got)
	}
}

func TestResolvedCIDIsAdmittedWhenUnknownCIDsAreRefused(t *testing.T) {
	r := newFakeResolver(config.VMMapping{CID: 7, Name: "alice-dev"})
	h := newResolvingHarness(t, r, func(c *config.Host) { c.Limits.AllowUnknownCIDs = false })

	deliverOne(t, h.dial(7, true), "boot-a")

	g := h.dial(8, true)
	if em := g.expectError(); em.Code != protocol.ErrCodeUnauthorized || !em.Fatal {
		t.Fatalf("ERROR = %+v, want a fatal %s for an unresolved CID", em, protocol.ErrCodeUnauthorized)
	}
	g.wantClosed()

	env := h.waitInternal(typeConnectionRejected)
	if src := env.Source; src.Known || src.VM != "unknown-cid-8" {
		t.Errorf("rejection Source = %+v, want the unresolved unknown-cid-8", src)
	}
	if got := r.callsFor(8); got != 1 {
		t.Errorf("Resolve called %d times for the rejected CID, want 1", got)
	}
}
