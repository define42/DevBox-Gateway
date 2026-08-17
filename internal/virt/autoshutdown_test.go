package virt

import (
	"devboxgateway/internal/config"
	"errors"
	"slices"
	"testing"
	"time"
)

// autoShutdownFixture wires an autoShutdownSweeper to fakes: a controllable
// clock, a mutable VM listing, and recorders for graceful shutdown requests,
// force stops, and metadata loads.
type autoShutdownFixture struct {
	sweeper   *autoShutdownSweeper
	registry  *vmLastUsedRegistry
	now       time.Time
	vms       []VMInfo
	requested []string
	forced    []string
	loadCalls []string
	loaded    map[string]time.Time
}

func newAutoShutdownFixture(idleAfter, gracePeriod time.Duration) *autoShutdownFixture {
	f := &autoShutdownFixture{
		registry: newVMLastUsedRegistry(),
		now:      time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC),
		loaded:   make(map[string]time.Time),
	}
	f.sweeper = &autoShutdownSweeper{
		idleAfter:   idleAfter,
		gracePeriod: gracePeriod,
		now:         func() time.Time { return f.now },
		listVMs:     func() []VMInfo { return f.vms },
		lastUsed:    f.registry,
		loadLastUsed: func(name string) (time.Time, bool) {
			f.loadCalls = append(f.loadCalls, name)
			t, ok := f.loaded[name]
			return t, ok
		},
		requestShutdown: func(name string) error {
			f.requested = append(f.requested, name)
			return nil
		},
		forceShutdown: func(name string) error {
			f.forced = append(f.forced, name)
			return nil
		},
		shutdownRequestedAt: make(map[string]time.Time),
	}
	return f
}

func (f *autoShutdownFixture) pendingEscalation(name string) bool {
	_, ok := f.sweeper.shutdownRequestedAt[name]
	return ok
}

func TestAutoShutdownSweepAsksOnlyIdleOwnedRunningVMs(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("alice-idle", f.now.Add(-2*time.Hour))
	f.registry.set("alice-fresh", f.now.Add(-30*time.Minute))
	f.registry.set("alice-stopped", f.now.Add(-10*time.Hour))
	f.registry.set("operator-vm", f.now.Add(-10*time.Hour))
	f.vms = []VMInfo{
		{Name: "alice-idle", Owner: "alice", State: "running"},
		{Name: "alice-fresh", Owner: "alice", State: "running"},
		{Name: "alice-stopped", Owner: "alice", State: "shut off"},
		{Name: "operator-vm", Owner: "", State: "running"},
	}

	f.sweeper.sweep()

	if !slices.Equal(f.requested, []string{"alice-idle"}) {
		t.Fatalf("graceful requests = %v, want only alice-idle", f.requested)
	}
	if len(f.forced) != 0 {
		t.Fatalf("force stops = %v, want none on the first pass", f.forced)
	}
	if len(f.loadCalls) != 0 {
		t.Fatalf("metadata loads = %v, want none for cached VMs", f.loadCalls)
	}
}

func TestAutoShutdownEscalatesToForceStopAfterGracePeriod(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("alice-idle", f.now.Add(-3*time.Hour))
	f.vms = []VMInfo{{Name: "alice-idle", Owner: "alice", State: "running"}}

	f.sweeper.sweep()
	if !slices.Equal(f.requested, []string{"alice-idle"}) || len(f.forced) != 0 {
		t.Fatalf("after first pass: requested=%v forced=%v, want one graceful request", f.requested, f.forced)
	}

	// Within the grace window the guest gets time to power off on its own.
	f.now = f.now.Add(4 * time.Minute)
	f.sweeper.sweep()
	if len(f.requested) != 1 || len(f.forced) != 0 {
		t.Fatalf("within grace: requested=%v forced=%v, want no new action", f.requested, f.forced)
	}

	// Once the grace period elapses with the VM still running, it is forced.
	f.now = f.now.Add(2 * time.Minute)
	f.sweeper.sweep()
	if !slices.Equal(f.forced, []string{"alice-idle"}) {
		t.Fatalf("after grace: forced=%v, want alice-idle", f.forced)
	}
	if len(f.requested) != 1 {
		t.Fatalf("after grace: requested=%v, want no second graceful request", f.requested)
	}
	if f.pendingEscalation("alice-idle") {
		t.Fatal("expected the escalation record to be cleared after the force stop")
	}
}

func TestAutoShutdownGuestPoweringOffCancelsEscalation(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("alice-idle", f.now.Add(-3*time.Hour))
	f.vms = []VMInfo{{Name: "alice-idle", Owner: "alice", State: "running"}}

	f.sweeper.sweep()

	// The guest honors the ACPI request before the grace period elapses.
	f.vms = []VMInfo{{Name: "alice-idle", Owner: "alice", State: "shut off"}}
	f.now = f.now.Add(10 * time.Minute)
	f.sweeper.sweep()

	if len(f.forced) != 0 {
		t.Fatalf("force stops = %v, want none for a guest that powered off", f.forced)
	}
	if f.pendingEscalation("alice-idle") {
		t.Fatal("expected the escalation record to be cleared once the VM is off")
	}
}

func TestAutoShutdownUseAfterRequestCancelsEscalation(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("alice-idle", f.now.Add(-3*time.Hour))
	f.vms = []VMInfo{{Name: "alice-idle", Owner: "alice", State: "running"}}

	f.sweeper.sweep()

	// The owner opens the VM while the guest is still up: the fresh idle
	// window must cancel the pending force stop.
	f.now = f.now.Add(2 * time.Minute)
	f.registry.set("alice-idle", f.now)
	f.now = f.now.Add(10 * time.Minute)
	f.sweeper.sweep()

	if len(f.forced) != 0 {
		t.Fatalf("force stops = %v, want none after the VM was used again", f.forced)
	}
	if f.pendingEscalation("alice-idle") {
		t.Fatal("expected the escalation record to be cleared after new use")
	}

	// When the VM goes idle again later, a fresh graceful cycle starts.
	f.now = f.now.Add(2 * time.Hour)
	f.sweeper.sweep()
	if !slices.Equal(f.requested, []string{"alice-idle", "alice-idle"}) || len(f.forced) != 0 {
		t.Fatalf("second idle cycle: requested=%v forced=%v, want a second graceful request", f.requested, f.forced)
	}
}

func TestAutoShutdownRetriesFailedGracefulRequest(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("alice-idle", f.now.Add(-3*time.Hour))
	f.vms = []VMInfo{{Name: "alice-idle", Owner: "alice", State: "running"}}

	f.sweeper.requestShutdown = func(name string) error {
		f.requested = append(f.requested, name)
		return errors.New("libvirt unavailable")
	}
	f.sweeper.sweep()
	if f.pendingEscalation("alice-idle") {
		t.Fatal("a failed graceful request must not start the grace clock")
	}

	// Once the request succeeds, the grace period counts from that success —
	// the guest is never force-stopped without having been asked.
	f.sweeper.requestShutdown = func(name string) error {
		f.requested = append(f.requested, name)
		return nil
	}
	f.now = f.now.Add(10 * time.Minute)
	f.sweeper.sweep()
	if !slices.Equal(f.requested, []string{"alice-idle", "alice-idle"}) || len(f.forced) != 0 {
		t.Fatalf("retry pass: requested=%v forced=%v, want a repeated graceful request and no force", f.requested, f.forced)
	}

	f.now = f.now.Add(6 * time.Minute)
	f.sweeper.sweep()
	if !slices.Equal(f.forced, []string{"alice-idle"}) {
		t.Fatalf("forced=%v, want alice-idle after grace from the successful request", f.forced)
	}
}

func TestAutoShutdownRetriesFailedForceStopWithoutNewGrace(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("alice-idle", f.now.Add(-3*time.Hour))
	f.vms = []VMInfo{{Name: "alice-idle", Owner: "alice", State: "running"}}

	f.sweeper.sweep()
	f.now = f.now.Add(6 * time.Minute)
	f.sweeper.forceShutdown = func(name string) error {
		f.forced = append(f.forced, name)
		return errors.New("libvirt unavailable")
	}
	f.sweeper.sweep()
	if !slices.Equal(f.forced, []string{"alice-idle"}) || !f.pendingEscalation("alice-idle") {
		t.Fatalf("failed force stop: forced=%v pending=%v, want a retained escalation record", f.forced, f.pendingEscalation("alice-idle"))
	}

	// The next pass retries the force stop immediately, without asking the
	// guest again or granting another grace period.
	f.sweeper.forceShutdown = func(name string) error {
		f.forced = append(f.forced, name)
		return nil
	}
	f.now = f.now.Add(time.Minute)
	f.sweeper.sweep()
	if !slices.Equal(f.forced, []string{"alice-idle", "alice-idle"}) {
		t.Fatalf("forced=%v, want an immediate retry", f.forced)
	}
	if len(f.requested) != 1 {
		t.Fatalf("requested=%v, want no additional graceful request", f.requested)
	}
	if f.pendingEscalation("alice-idle") {
		t.Fatal("expected the escalation record to be cleared after the successful retry")
	}
}

func TestAutoShutdownContinuesAcrossVMsAfterRequestError(t *testing.T) {
	f := newAutoShutdownFixture(time.Hour, 5*time.Minute)
	f.registry.set("alice-first", f.now.Add(-2*time.Hour))
	f.registry.set("alice-second", f.now.Add(-2*time.Hour))
	f.vms = []VMInfo{
		{Name: "alice-first", Owner: "alice", State: "running"},
		{Name: "alice-second", Owner: "alice", State: "running"},
	}
	f.sweeper.requestShutdown = func(name string) error {
		f.requested = append(f.requested, name)
		return errors.New("libvirt unavailable")
	}

	f.sweeper.sweep()

	if !slices.Equal(f.requested, []string{"alice-first", "alice-second"}) {
		t.Fatalf("requested=%v, want both despite request errors", f.requested)
	}
}

func TestAutoShutdownSweepRecoversPersistedTimestampsOnCacheMiss(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.loaded["alice-old"] = f.now.Add(-5 * time.Hour)
	f.vms = []VMInfo{
		{Name: "alice-old", Owner: "alice", State: "running"},
		{Name: "alice-new", Owner: "alice", State: "running"},
	}

	f.sweeper.sweep()

	// alice-old's persisted timestamp is idle beyond the limit; alice-new has
	// no history and is granted a fresh window seeded at the sweep time.
	if !slices.Equal(f.requested, []string{"alice-old"}) {
		t.Fatalf("graceful requests after first sweep = %v, want only alice-old", f.requested)
	}
	if seeded, ok := f.registry.get("alice-new"); !ok || !seeded.Equal(f.now) {
		t.Fatalf("alice-new seed = %v (present=%v), want %v", seeded, ok, f.now)
	}

	// Once the window elapses without another touch, the seeded VM enters the
	// graceful cycle too — without consulting metadata again.
	f.vms = []VMInfo{{Name: "alice-new", Owner: "alice", State: "running"}}
	f.now = f.now.Add(2 * time.Hour)
	f.sweeper.sweep()

	if !slices.Equal(f.requested, []string{"alice-old", "alice-new"}) {
		t.Fatalf("graceful requests after second sweep = %v", f.requested)
	}
	if !slices.Equal(f.loadCalls, []string{"alice-old", "alice-new"}) {
		t.Fatalf("metadata loads = %v, want exactly one per VM", f.loadCalls)
	}
}

func TestAutoShutdownSweepPrunesDepartedVMsButNotOnEmptyListing(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	f.registry.set("kept", f.now)
	f.registry.set("departed", f.now)
	f.sweeper.shutdownRequestedAt["departed"] = f.now

	f.vms = []VMInfo{{Name: "kept", Owner: "alice", State: "shut off"}}
	f.sweeper.sweep()

	if _, ok := f.registry.get("departed"); ok {
		t.Fatal("expected the departed VM's timestamp to be pruned")
	}
	if f.pendingEscalation("departed") {
		t.Fatal("expected the departed VM's escalation record to be pruned")
	}
	if _, ok := f.registry.get("kept"); !ok {
		t.Fatal("expected the listed VM's timestamp to be retained")
	}

	// An empty listing (no domains, or inventory unavailable) must not prune.
	f.vms = nil
	f.sweeper.sweep()

	if _, ok := f.registry.get("kept"); !ok {
		t.Fatal("expected timestamps to survive an empty listing")
	}
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("requested=%v forced=%v, want no action", f.requested, f.forced)
	}
}

func TestStartAutoShutdownWorkerDisabledByDefault(_ *testing.T) {
	stop := StartAutoShutdownWorker(config.NewSettingType(false))
	// The returned no-op stop must be safe to call, repeatedly.
	stop()
	stop()
}

func TestStartAutoShutdownWorkerStartsAndStops(t *testing.T) {
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestInt(config.VDI_AUTO_SHUTDOWN_HOURS, 4); err != nil {
		t.Fatalf("enable auto-shutdown: %v", err)
	}

	stop := StartAutoShutdownWorker(settings)
	stop()
	// Cancelling twice must be harmless.
	stop()
}
