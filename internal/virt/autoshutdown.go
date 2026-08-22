package virt

import (
	"context"
	"log"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
)

// autoShutdownSweepInterval is how often the auto-shutdown worker examines
// running VDIs. The idle threshold has hour granularity, so a minute between
// passes keeps shutdowns timely at negligible cost: a pass reads only the
// background worker's cached VM snapshot and the in-memory last-used registry,
// touching libvirt once per VM after a gateway restart (to recover persisted
// timestamps) and only for VMs it is actually stopping.
const autoShutdownSweepInterval = time.Minute

// autoShutdownGracePeriod is how long the sweeper waits between asking an idle
// guest to shut down (ACPI power button) and force-stopping it. Long enough
// for a desktop guest to flush and power off cleanly; short enough that a hung
// guest — or one that ignores the power button — still stops promptly once the
// idle limit is reached.
const autoShutdownGracePeriod = 5 * time.Minute

// autoShutdownSweeper decides which VDIs an idle pass stops, gracefully first
// and by force after the grace period. Its collaborators are injectable so the
// policy is testable without libvirt; production wiring lives in
// StartAutoShutdownWorker.
type autoShutdownSweeper struct {
	idleAfter       time.Duration
	gracePeriod     time.Duration
	now             func() time.Time
	listVMs         func() []VMInfo
	lastUsed        *vmLastUsedRegistry
	loadLastUsed    func(name string) (time.Time, bool)
	requestShutdown func(name string) error
	forceShutdown   func(name string) error
	// shutdownRequestedAt records, per VM name, when the sweeper asked the
	// guest to shut down gracefully; once the grace period elapses with the VM
	// still running, the next pass escalates to forceShutdown. Accessed only
	// from the sweep goroutine, so it needs no locking.
	shutdownRequestedAt map[string]time.Time
}

// sweep runs one auto-shutdown pass over the cached VM inventory.
func (s *autoShutdownSweeper) sweep() {
	vms := s.listVMs()
	if len(vms) == 0 {
		// An empty listing either means no domains exist or the inventory cache
		// is unavailable (libvirtd down, host identity change). Skip pruning so
		// a transient outage cannot discard in-memory timestamps whose metadata
		// write had failed; they age out on the next populated listing.
		return
	}

	names := make(map[string]struct{}, len(vms))
	for _, vm := range vms {
		names[vm.Name] = struct{}{}
	}
	s.lastUsed.retainNames(names)
	for name := range s.shutdownRequestedAt {
		if _, ok := names[name]; !ok {
			delete(s.shutdownRequestedAt, name)
		}
	}

	for _, vm := range vms {
		s.sweepVM(vm)
	}
}

func (s *autoShutdownSweeper) sweepVM(vm VMInfo) {
	// Only gateway-managed VDIs are candidates: the inventory lists every
	// persistent domain on the host, and stopping an operator's unrelated VM
	// (no owner metadata) would be destructive. A VM that is not running needs
	// nothing either — and if a graceful request was pending, it has been
	// honored, so the escalation state is complete.
	if vm.Owner == "" || vm.State != "running" {
		delete(s.shutdownRequestedAt, vm.Name)
		return
	}

	lastUsed, ok := s.lastUsed.get(vm.Name)
	if !ok {
		// First sighting since gateway start: recover the persisted timestamp,
		// or grant a full idle window when there is none (a VM created before
		// this feature, or started outside the gateway before it ever recorded
		// a use).
		lastUsed, ok = s.loadLastUsed(vm.Name)
		if !ok {
			lastUsed = s.now()
		}
		s.lastUsed.set(vm.Name, lastUsed)
	}

	idleFor := s.now().Sub(lastUsed)
	if idleFor < s.idleAfter {
		// Used since a pending graceful request (e.g. the owner clicked RDP
		// while the guest was still up): the VM earned a fresh idle window, so
		// cancel the escalation.
		delete(s.shutdownRequestedAt, vm.Name)
		return
	}

	s.stopIdleVM(vm, idleFor)
}

// stopIdleVM stops one VDI that exceeded the idle limit: it first asks the
// guest to power off (ACPI) and, if the VM is still running once the grace
// period elapses, force-stops it on a later pass.
func (s *autoShutdownSweeper) stopIdleVM(vm VMInfo, idleFor time.Duration) {
	requestedAt, pending := s.shutdownRequestedAt[vm.Name]
	if !pending {
		log.Printf("auto-shutdown: VDI %s (owner %s) unused for %s (limit %s); asking the guest to shut down (force-stop in %s if it does not)",
			vm.Name, vm.Owner, idleFor.Round(time.Minute), s.idleAfter, s.gracePeriod)
		if err := s.requestShutdown(vm.Name); err != nil {
			// Not recorded as pending: the next pass repeats the graceful
			// request instead of force-stopping a guest that was never asked.
			log.Printf("auto-shutdown: graceful shutdown request for VDI %s: %v", vm.Name, err)
			return
		}
		s.shutdownRequestedAt[vm.Name] = s.now()
		return
	}

	if s.now().Sub(requestedAt) < s.gracePeriod {
		// Still within the grace window; give the guest time to power off.
		return
	}

	log.Printf("auto-shutdown: VDI %s (owner %s) still running %s after graceful shutdown request; force-stopping it",
		vm.Name, vm.Owner, s.now().Sub(requestedAt).Round(time.Second))
	if err := s.forceShutdown(vm.Name); err != nil {
		// Keep the escalation pending so the next pass retries the force stop
		// immediately rather than granting another grace period.
		log.Printf("auto-shutdown: force stop VDI %s: %v", vm.Name, err)
		return
	}
	delete(s.shutdownRequestedAt, vm.Name)
}

// StartAutoShutdownWorker starts the background loop that stops VDIs unused
// for longer than VDI_AUTO_SHUTDOWN_HOURS, and returns a function that stops
// it. A VDI counts as used when it is created or started and whenever its
// owner opens RDP, serial, or noVNC from the dashboard (see MarkVMUsed). An
// idle VDI is first asked to shut down via an ACPI power button event and is
// force-stopped if still running after autoShutdownGracePeriod. When the
// setting is unset or non-positive the feature is disabled and the returned
// stop function is a no-op.
func StartAutoShutdownWorker(settings *config.Settings) (stop func()) {
	idleAfter := config.VDIAutoShutdownAfter(settings)
	if idleAfter <= 0 {
		return func() {}
	}

	sweeper := &autoShutdownSweeper{
		idleAfter:   idleAfter,
		gracePeriod: autoShutdownGracePeriod,
		now:         time.Now,
		// peekInventory, not NewInventory: consulting the cache must never start
		// the background worker as a side effect. In production the worker is
		// started before settings are even loaded (bootGateway), so ticks
		// always see it running.
		listVMs: func() []VMInfo {
			worker := peekInventory()
			if worker == nil {
				return nil
			}
			return worker.VMs("")
		},
		lastUsed:            vmLastUsed,
		loadLastUsed:        loadVMLastUsedFromMetadata,
		requestShutdown:     GracefulShutdownVM,
		forceShutdown:       ShutdownVM,
		shutdownRequestedAt: make(map[string]time.Time),
	}

	ctx, cancel := context.WithCancel(context.Background())
	go runAutoShutdownWorker(ctx, sweeper, idleAfter)
	return cancel
}

func runAutoShutdownWorker(ctx context.Context, sweeper *autoShutdownSweeper, idleAfter time.Duration) {
	log.Printf("auto-shutdown worker started: VDIs unused for %s will be shut down (gracefully, force-stop after %s)", idleAfter, sweeper.gracePeriod)
	ticker := time.NewTicker(autoShutdownSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sweeper.sweep()
		case <-ctx.Done():
			log.Println("auto-shutdown worker stopped")
			return
		}
	}
}
