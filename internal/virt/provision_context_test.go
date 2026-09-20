package virt

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestBootNewVMWithContextCancelsWhileWaitingForName(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	release := sync.OnceFunc(vmNameLocks.Lock(fixture.spec.vmName))
	defer release()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type result struct {
		name string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		name, err := BootNewVMWithContext(ctx, fixture.request, fixture.settings, nil)
		done <- result{name, err}
	}()
	waitForVMActivityWaiter(t, vmNameLocks, fixture.spec.vmName)
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.name != fixture.spec.vmName {
			t.Fatalf("canceled create = (%q, %v)", got.name, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled create remained blocked on the VM-name lock")
	}
	assertNoProvisionedArtifacts(t, fixture)
}

func TestBootNewVMWithContextCanceledBeforeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// An invalid request and nil settings ensure cancellation precedes planning
	// and any connection or storage activity.
	name, err := BootNewVMWithContext(ctx, VMCreateRequest{}, nil, func(_, _ int64) {
		t.Error("a canceled create reported disk activity")
	})
	if !errors.Is(err, context.Canceled) || name != "" {
		t.Fatalf("canceled create = (%q, %v), want empty name and context.Canceled", name, err)
	}
}

func TestBootNewVMWithContextRollsBackCanceledDiskCopy(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	// Padding the tiny QCOW2 beyond one libvirt chunk provides a deterministic
	// intermediate progress callback without copying a full boot image.
	if err := os.Truncate(fixture.spec.baseImagePath, 2*1024*1024); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var interrupted bool
	name, err := BootNewVMWithContext(ctx, fixture.request, fixture.settings, func(copied, total int64) {
		if copied > 0 && copied < total {
			interrupted = true
			cancel()
		}
	})
	if !interrupted {
		t.Fatal("test did not cancel an in-progress disk copy")
	}
	if !errors.Is(err, context.Canceled) || name != fixture.spec.vmName {
		t.Fatalf("canceled create = (%q, %v), want (%q, context.Canceled)", name, err, fixture.spec.vmName)
	}
	// Keep joined rollback errors visible if an artifact assertion fails. A
	// context cancellation alone does not prove cleanup succeeded.
	t.Logf("canceled create returned: %v", err)
	assertNoProvisionedArtifacts(t, fixture)
}

func TestProvisionAndStartVMRejectsCancellationBeforeProvisioning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// This is also the first operation after obtaining the VM-name lock. A
	// request canceled while waiting must not touch libvirt once admitted.
	err := provisionAndStartVM(ctx, nil, nil, vmProvisionSpec{}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled locked provision = %v, want context.Canceled", err)
	}
}
