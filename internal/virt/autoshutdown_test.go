package virt

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
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

func TestAutoShutdownProtectsConnectionsUntilLastDisconnect(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	const name = "alice-active"
	f.vms = []VMInfo{{Name: name, Owner: "alice", State: "running"}}
	first := f.registry.beginUse(name, f.now)
	f.now = f.now.Add(time.Hour)
	second := f.registry.beginUse(name, f.now)

	// An established session remains active even when its opening timestamp
	// is several idle windows old.
	f.now = f.now.Add(6 * time.Hour)
	f.sweeper.sweep()
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("connected VM was stopped: requested=%v forced=%v", f.requested, f.forced)
	}

	if !f.registry.endUse(name, first, f.now) {
		t.Fatal("first connection release was rejected")
	}
	f.now = f.now.Add(3 * time.Hour)
	f.sweeper.sweep()
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("remaining connection lost protection: requested=%v forced=%v", f.requested, f.forced)
	}

	if !f.registry.endUse(name, second, f.now) {
		t.Fatal("final connection release was rejected")
	}
	f.now = f.now.Add(2*time.Hour - time.Nanosecond)
	f.sweeper.sweep()
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("disconnect did not grant a full idle window: requested=%v forced=%v", f.requested, f.forced)
	}

	f.now = f.now.Add(time.Nanosecond)
	f.sweeper.sweep()
	if !slices.Equal(f.requested, []string{name}) || len(f.forced) != 0 {
		t.Fatalf("after idle window: requested=%v forced=%v, want one graceful request", f.requested, f.forced)
	}
}

func TestAutoShutdownActiveConnectionCancelsPendingEscalation(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	const name = "alice-active"
	f.vms = []VMInfo{{Name: name, Owner: "alice", State: "running"}}
	f.registry.set(name, f.now.Add(-3*time.Hour))
	f.sweeper.sweep()
	if !f.pendingEscalation(name) {
		t.Fatal("expected the initial graceful request to arm escalation")
	}

	f.now = f.now.Add(time.Minute)
	connection := f.registry.beginUse(name, f.now)
	// Advance past both the grace period and the new connection's opening
	// timestamp, so protection must come from the connection still being open.
	f.now = f.now.Add(3 * time.Hour)
	f.sweeper.sweep()
	if len(f.forced) != 0 || len(f.requested) != 1 || f.pendingEscalation(name) {
		t.Fatalf("active connection retained escalation: requested=%v forced=%v pending=%v",
			f.requested, f.forced, f.pendingEscalation(name))
	}

	if !f.registry.endUse(name, connection, f.now) {
		t.Fatal("connection release was rejected")
	}
	f.now = f.now.Add(2 * time.Hour)
	f.sweeper.sweep()
	if !slices.Equal(f.requested, []string{name, name}) || len(f.forced) != 0 {
		t.Fatalf("after disconnect and idle: requested=%v forced=%v, want a new graceful cycle",
			f.requested, f.forced)
	}
}

func TestAutoShutdownRetainsActiveVMOmittedFromInventory(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	const name = "alice-active"
	connectedAt := f.now
	connection := f.registry.beginUse(name, connectedAt)
	f.registry.set("departed", connectedAt)

	// A populated but incomplete cached listing must not prune an active VM.
	f.vms = []VMInfo{{Name: "other", Owner: "alice", State: "shut off"}}
	f.now = f.now.Add(3 * time.Hour)
	f.sweeper.sweep()
	if !f.registry.inUse(name) {
		t.Fatal("incomplete inventory discarded an active connection")
	}
	if got, ok := f.registry.get(name); !ok || !got.Equal(connectedAt) {
		t.Fatalf("active timestamp = %v (present=%v), want %v", got, ok, connectedAt)
	}
	if _, ok := f.registry.get("departed"); ok {
		t.Fatal("inactive departed VM should still be pruned")
	}

	f.vms = []VMInfo{{Name: name, Owner: "alice", State: "running"}}
	f.sweeper.sweep()
	if len(f.requested) != 0 || len(f.forced) != 0 || len(f.loadCalls) != 0 {
		t.Fatalf("restored active VM was treated as idle: requested=%v forced=%v loads=%v",
			f.requested, f.forced, f.loadCalls)
	}
	if !f.registry.endUse(name, connection, f.now) {
		t.Fatal("retained connection could not be released")
	}
}

func TestAutoShutdownCheckpointsActiveUseAcrossRestart(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	const name = "alice-active"
	f.vms = []VMInfo{{Name: name, Owner: "alice", State: "running"}}
	f.registry.beginUse(name, f.now)
	f.now = f.now.Add(6 * time.Hour)
	checkpoints := make(map[string]time.Time)
	f.sweeper.persistLastUsed = func(name string, usedAt time.Time) error {
		checkpoints[name] = usedAt
		return nil
	}

	f.sweeper.sweep()
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("checkpoint stopped active VM: requested=%v forced=%v", f.requested, f.forced)
	}
	assertVMActivityTimestamp(t, f.registry, name, f.now)
	if len(checkpoints) != 1 || !checkpoints[name].Equal(f.now) {
		t.Fatalf("persisted checkpoints = %v, want %s at %v", checkpoints, name, f.now)
	}

	// An abrupt restart loses the active connection registry but recovers
	// the recent checkpoint, giving the interrupted user time to reconnect.
	restarted := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	restarted.now = f.now.Add(time.Hour)
	restarted.vms = f.vms
	restarted.loaded = checkpoints
	restarted.sweeper.sweep()
	if len(restarted.requested) != 0 || len(restarted.forced) != 0 {
		t.Fatalf("recently active VM stopped after restart: requested=%v forced=%v",
			restarted.requested, restarted.forced)
	}
	if !slices.Equal(restarted.loadCalls, []string{name}) {
		t.Fatalf("metadata loads = %v, want the active VM checkpoint", restarted.loadCalls)
	}
}

func TestAutoShutdownCheckpointFailurePreservesActiveUse(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	const name = "alice-active"
	f.vms = []VMInfo{{Name: name, Owner: "alice", State: "running"}}
	f.registry.beginUse(name, f.now)
	f.now = f.now.Add(6 * time.Hour)
	persistCalls := 0
	f.sweeper.persistLastUsed = func(string, time.Time) error {
		persistCalls++
		return errors.New("libvirt unavailable")
	}

	f.sweeper.sweep()
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("failed checkpoint stopped active VM: requested=%v forced=%v", f.requested, f.forced)
	}
	assertVMActivityTimestamp(t, f.registry, name, f.now)
	if persistCalls != 1 {
		t.Fatalf("persistence calls = %d, want one failed checkpoint", persistCalls)
	}
}

func TestAutoShutdownWaitsForConnectionAdmission(t *testing.T) {
	for _, stage := range []string{"graceful", "force", "metadata recovery"} {
		t.Run(stage, func(t *testing.T) {
			assertAutoShutdownWaitsForAdmission(t, stage)
		})
	}
}

func assertAutoShutdownWaitsForAdmission(t *testing.T, stage string) {
	t.Helper()
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	name := t.Name()
	vm := VMInfo{Name: name, Owner: "alice", State: "running"}
	if stage != "metadata recovery" {
		f.registry.set(name, f.now.Add(-3*time.Hour))
	}
	f.loaded[name] = f.now.Add(-3 * time.Hour)
	if stage == "force" {
		f.sweeper.shutdownRequestedAt[name] = f.now.Add(-10 * time.Minute)
	}

	unlock := sync.OnceFunc(f.registry.guards.Lock(name))
	defer unlock()
	swept := startVMActivityTask(t, func() { f.sweeper.sweepVM(vm) })
	waitForVMActivityWaiter(t, f.registry.guards, name)
	f.registry.beginUse(name, f.now)
	unlock()
	awaitVMActivityTask(t, swept)

	if len(f.requested) != 0 || len(f.forced) != 0 || len(f.loadCalls) != 0 {
		t.Fatalf("sweep ignored admitted connection: requested=%v forced=%v loads=%v",
			f.requested, f.forced, f.loadCalls)
	}
	if f.pendingEscalation(name) {
		t.Fatal("admitted connection did not cancel pending escalation")
	}
}

func TestAutoShutdownHoldsActivityGuardDuringShutdown(t *testing.T) {
	for _, stage := range []string{"graceful", "force"} {
		t.Run(stage, func(t *testing.T) {
			assertAutoShutdownHoldsGuardDuringShutdown(t, stage)
		})
	}
}

func assertAutoShutdownHoldsGuardDuringShutdown(t *testing.T, stage string) {
	t.Helper()
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	name := t.Name()
	vm := VMInfo{Name: name, Owner: "alice", State: "running"}
	f.registry.set(name, f.now.Add(-3*time.Hour))
	entered := make(chan struct{})
	proceed := make(chan struct{})
	releaseShutdown := sync.OnceFunc(func() { close(proceed) })
	defer releaseShutdown()
	shutdown := func(string) error {
		close(entered)
		<-proceed
		return nil
	}
	if stage == "force" {
		f.sweeper.shutdownRequestedAt[name] = f.now.Add(-10 * time.Minute)
		f.sweeper.forceShutdown = shutdown
	} else {
		f.sweeper.requestShutdown = shutdown
	}
	swept := startVMActivityTask(t, func() { f.sweeper.sweepVM(vm) })
	awaitVMActivityTask(t, entered)
	admitted := startVMActivityTask(t, func() {
		unlock := f.registry.guards.Lock(name)
		defer unlock()
		f.registry.beginUse(name, f.now)
	})
	waitForVMActivityWaiter(t, f.registry.guards, name)
	if f.registry.inUse(name) {
		t.Fatal("connection was admitted while the shutdown RPC was still running")
	}
	releaseShutdown()
	awaitVMActivityTask(t, swept)
	awaitVMActivityTask(t, admitted)

	// The admitted connection must protect all subsequent sweeps. A repeated
	// shutdown would also attempt to close entered twice and fail the test.
	f.sweeper.sweepVM(vm)
	if !f.registry.inUse(name) || f.pendingEscalation(name) {
		t.Fatal("connection admitted after shutdown did not protect the next sweep")
	}
}

func TestAutoShutdownMetadataRecoveryCannotOverwriteConnection(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	name := t.Name()
	vm := VMInfo{Name: name, Owner: "alice", State: "running"}
	entered := make(chan struct{})
	proceed := make(chan struct{})
	releaseLoad := sync.OnceFunc(func() { close(proceed) })
	defer releaseLoad()
	f.sweeper.loadLastUsed = func(string) (time.Time, bool) {
		close(entered)
		<-proceed
		return f.now, true
	}
	swept := startVMActivityTask(t, func() { f.sweeper.sweepVM(vm) })
	awaitVMActivityTask(t, entered)
	connectedAt := f.now.Add(time.Hour)
	admitted := startVMActivityTask(t, func() {
		unlock := f.registry.guards.Lock(name)
		defer unlock()
		f.registry.beginUse(name, connectedAt)
	})
	waitForVMActivityWaiter(t, f.registry.guards, name)
	releaseLoad()
	awaitVMActivityTask(t, swept)
	awaitVMActivityTask(t, admitted)

	assertVMActivityTimestamp(t, f.registry, name, connectedAt)
	if !f.registry.inUse(name) || len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("recovery lost connection activity: requested=%v forced=%v", f.requested, f.forced)
	}
}

func TestAutoShutdownWaitsForVMLifecycleTimestamp(t *testing.T) {
	f := newAutoShutdownFixture(2*time.Hour, 5*time.Minute)
	name := t.Name()
	vm := VMInfo{Name: name, Owner: "alice", State: "running"}
	f.registry.set(name, f.now.Add(-3*time.Hour))
	unlock := sync.OnceFunc(vmNameLocks.Lock(name))
	defer unlock()
	swept := startVMActivityTask(t, func() { f.sweeper.sweepVM(vm) })
	waitForVMActivityWaiter(t, vmNameLocks, name)
	// Model the start path stamping activity before it releases the lifecycle
	// lock, while an inventory snapshot already reports the VM as running.
	f.registry.set(name, f.now)
	unlock()
	awaitVMActivityTask(t, swept)
	if len(f.requested) != 0 || len(f.forced) != 0 {
		t.Fatalf("sweep stopped a freshly started VM: requested=%v forced=%v", f.requested, f.forced)
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
	stop := StartAutoShutdownWorker(config.NewSettings(false))
	// The returned no-op stop must be safe to call, repeatedly.
	stop()
	stop()
}

func TestStartAutoShutdownWorkerStartsAndStops(t *testing.T) {
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestInt(config.VDI_AUTO_SHUTDOWN_HOURS, 4); err != nil {
		t.Fatalf("enable auto-shutdown: %v", err)
	}

	stop := StartAutoShutdownWorker(settings)
	stop()
	// Cancelling twice must be harmless.
	stop()
}
