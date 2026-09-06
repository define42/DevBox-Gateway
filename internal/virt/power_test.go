package virt

import (
	"errors"
	"sync"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

func TestPowerOperationsWaitForRemoval(t *testing.T) {
	operations := []struct {
		name string
		run  func(string) error
	}{
		{name: "start", run: StartExistingVM},
		{name: "restart", run: RestartVM},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newProvisionTestFixture(t)
			name, err := BootNewVM(fixture.request, fixture.settings)
			if err != nil {
				t.Fatalf("create VM: %v", err)
			}
			if err := ShutdownVM(name); err != nil {
				t.Fatalf("stop VM before removal: %v", err)
			}

			// Queue both public operations at the removal lock. Waiting for their
			// lock entries avoids relying on a sleep to schedule either goroutine.
			unlock := sync.OnceFunc(vmNameLocks.Lock(name))
			defer unlock()
			removed := runVMLifecycleOperation(t, func() error { return RemoveVM(name, fixture.settings) })
			waitForVMLifecycleLock(t, name, 2, removed)
			powered := runVMLifecycleOperation(t, func() error { return operation.run(name) })
			waitForVMLifecycleLock(t, name, 3, powered)
			unlock()

			if err := awaitVMLifecycleOperation(t, removed); err != nil {
				t.Fatalf("remove VM: %v", err)
			}
			// Either operation may acquire the released mutex first. Starting
			// before removal succeeds; starting after it finds no domain.
			if err := awaitVMLifecycleOperation(t, powered); err != nil && !errors.Is(err, libvirt.ERR_NO_DOMAIN) {
				t.Fatalf("power operation after removal: %v", err)
			}
			assertNoProvisionedArtifacts(t, fixture)
		})
	}
}

func runVMLifecycleOperation(t *testing.T, run func() error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- run()
		close(done)
	}()
	// The test releases its held lock before cleanup, including on failure.
	// Drain each operation before the fixture deletes its pool and directory.
	t.Cleanup(func() { _ = awaitVMLifecycleOperation(t, done) })
	return done
}

func awaitVMLifecycleOperation(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("VM lifecycle operation did not finish")
		return nil
	}
}

func waitForVMLifecycleLock(t *testing.T, name string, want int, done <-chan error) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		vmNameLocks.mu.Lock()
		waiters := vmNameLocks.locks[name].waiters
		vmNameLocks.mu.Unlock()
		if waiters == want {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("VM operation bypassed the held removal lock: %v", err)
		case <-timeout.C:
			t.Fatalf("VM operation did not acquire the removal lock: waiters=%d, want %d", waiters, want)
		case <-ticker.C:
		}
	}
}
