package virt

import (
	"sync"
	"testing"
	"time"
)

func TestVMActivityRecordsEachConnectionAndDisconnect(t *testing.T) {
	registry := newVMLastUsedRegistry()
	const name = "alice.desktop"
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	first := registry.beginUse(name, now)
	if !registry.inUse(name) {
		t.Fatal("opening a connection did not mark the VM active")
	}
	assertVMActivityTimestamp(t, registry, name, now)

	now = now.Add(time.Hour)
	second := registry.beginUse(name, now)
	assertVMActivityTimestamp(t, registry, name, now)

	now = now.Add(time.Hour)
	if !registry.endUse(name, first, now) || !registry.inUse(name) {
		t.Fatal("closing one connection lost the other connection's activity")
	}
	assertVMActivityTimestamp(t, registry, name, now)

	now = now.Add(time.Hour)
	if !registry.endUse(name, second, now) || registry.inUse(name) {
		t.Fatal("closing the final connection did not mark the VM inactive")
	}
	assertVMActivityTimestamp(t, registry, name, now)
}

func TestVMActivityDuplicateReleaseDoesNotExtendIdleWindow(t *testing.T) {
	registry := newVMLastUsedRegistry()
	const name = "alice.desktop"
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	connection := registry.beginUse(name, now)
	disconnectedAt := now.Add(time.Hour)
	if !registry.endUse(name, connection, disconnectedAt) {
		t.Fatal("first release was rejected")
	}
	if registry.endUse(name, connection, disconnectedAt.Add(time.Hour)) {
		t.Fatal("duplicate release was accepted")
	}
	assertVMActivityTimestamp(t, registry, name, disconnectedAt)
	if registry.inUse(name) {
		t.Fatal("released connection still marks the VM active")
	}
}

func TestVMActivityStaleReleaseDoesNotRestoreRemovedVM(t *testing.T) {
	registry := newVMLastUsedRegistry()
	const name = "alice.desktop"
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	old := registry.beginUse(name, now)
	registry.remove(name)
	if registry.inUse(name) {
		t.Fatal("removal left the old connection active")
	}
	if registry.endUse(name, old, now.Add(time.Hour)) {
		t.Fatal("release from a deleted VM was accepted")
	}
	if _, ok := registry.get(name); ok {
		t.Fatal("stale release restored the deleted VM's timestamp")
	}
}

func TestVMActivityStaleReleaseDoesNotAffectRecreatedVM(t *testing.T) {
	registry := newVMLastUsedRegistry()
	const name = "alice.desktop"
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	old := registry.beginUse(name, now)
	registry.remove(name)
	recreatedAt := now.Add(time.Hour)
	replacement := registry.beginUse(name, recreatedAt)
	if registry.endUse(name, old, now.Add(2*time.Hour)) {
		t.Fatal("release from a deleted VM was accepted")
	}
	if !registry.inUse(name) {
		t.Fatal("stale release removed the recreated VM's connection")
	}
	assertVMActivityTimestamp(t, registry, name, recreatedAt)
	if !registry.endUse(name, replacement, now.Add(3*time.Hour)) {
		t.Fatal("the recreated VM's connection could not be released")
	}
}

func TestVMActivityRejectsAnotherVMsConnectionToken(t *testing.T) {
	registry := newVMLastUsedRegistry()
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	first := registry.beginUse("alice.first", now)
	second := registry.beginUse("alice.second", now)
	if registry.endUse("alice.second", first, now.Add(time.Hour)) {
		t.Fatal("a different VM's token released a connection")
	}
	if !registry.inUse("alice.first") || !registry.inUse("alice.second") {
		t.Fatal("rejected release changed either VM's active state")
	}
	assertVMActivityTimestamp(t, registry, "alice.second", now)
	if !registry.endUse("alice.first", first, now.Add(2*time.Hour)) {
		t.Fatal("rejected release consumed the first VM's token")
	}
	if !registry.endUse("alice.second", second, now.Add(2*time.Hour)) {
		t.Fatal("the second VM's token could not be released")
	}
}

func TestVMActivityConcurrentReleaseIsIdempotent(t *testing.T) {
	registry := newVMLastUsedRegistry()
	const name = "alice.desktop"
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	connection := registry.beginUse(name, now)
	const callers = 32
	start := make(chan struct{})
	results := make(chan bool, callers)
	var group sync.WaitGroup
	for range callers {
		group.Go(func() {
			<-start
			results <- registry.endUse(name, connection, now.Add(time.Hour))
		})
	}
	close(start)
	group.Wait()
	close(results)

	accepted := 0
	for result := range results {
		if result {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent releases, want exactly one", accepted)
	}
	if registry.inUse(name) {
		t.Fatal("concurrent releases left the connection active")
	}
	assertVMActivityTimestamp(t, registry, name, now.Add(time.Hour))
}

func TestVMActivityBlankNameIsNoop(_ *testing.T) {
	done := TrackVMUse(" \t\n")
	done()
	done()
}

func TestVMActivityInventoryOverlaysConnections(t *testing.T) {
	name := t.Name()
	t.Cleanup(func() { vmLastUsed.remove(name) })
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	inventory := &Inventory{}
	inventory.setVMs([]VMInfo{{Name: name, Owner: "alice", State: "running"}})
	first := vmLastUsed.beginUse(name, now)
	second := vmLastUsed.beginUse(name, now)

	assertVMActivityInventoryUse(t, inventory, true)
	if !vmLastUsed.endUse(name, first, now.Add(time.Hour)) {
		t.Fatal("first release was rejected")
	}
	assertVMActivityInventoryUse(t, inventory, true)
	if !vmLastUsed.endUse(name, second, now.Add(2*time.Hour)) {
		t.Fatal("final release was rejected")
	}
	assertVMActivityInventoryUse(t, inventory, false)
}

func assertVMActivityInventoryUse(t *testing.T, inventory *Inventory, want bool) {
	t.Helper()
	vms := inventory.VMs("alice")
	if len(vms) != 1 {
		t.Fatalf("inventory has %d VMs, want one", len(vms))
	}
	if vms[0].InUse != want {
		t.Fatalf("inventory InUse = %v, want %v", vms[0].InUse, want)
	}
}

func assertVMActivityTimestamp(t *testing.T, registry *vmLastUsedRegistry, name string, want time.Time) {
	t.Helper()
	got, ok := registry.get(name)
	if !ok || !got.Equal(want) {
		t.Fatalf("last-used time for %q = %v (present=%v), want %v", name, got, ok, want)
	}
}

func startVMActivityTask(t *testing.T, run func()) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		run()
	}()
	t.Cleanup(func() { awaitVMActivityTask(t, done) })
	return done
}

func awaitVMActivityTask(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("VM activity operation did not reach the expected synchronization point")
	}
}

func waitForVMActivityWaiter(t *testing.T, locks *keyedMutex, name string) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		locks.mu.Lock()
		entry := locks.locks[name]
		waiting := entry != nil && entry.waiters == 2
		locks.mu.Unlock()
		if waiting {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("VM activity operation did not wait for the held per-VM lock")
		}
	}
}
