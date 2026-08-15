package virt

import (
	"errors"
	"testing"
	"time"
)

// fakeSweepSpawner records sweep launches without opening libvirt connections.
func fakeSweepSpawner(t *testing.T) (*SingletonWorker, chan chan<- sweepOutcome) {
	t.Helper()
	spawned := make(chan chan<- sweepOutcome, 8)
	worker := &SingletonWorker{
		spawnSweep: func(outcome chan<- sweepOutcome) {
			spawned <- outcome
		},
	}
	return worker, spawned
}

func waitForSpawn(t *testing.T, spawned chan chan<- sweepOutcome) {
	t.Helper()
	select {
	case <-spawned:
	case <-time.After(5 * time.Second):
		t.Fatal("expected a sweep to be spawned")
	}
}

func TestStartSweepIfDueStartsWhenIdle(t *testing.T) {
	worker, spawned := fakeSweepSpawner(t)

	inflight := worker.startSweepIfDue(nil)
	if inflight == nil {
		t.Fatal("expected a new in-flight sweep")
	}
	if inflight.outcome == nil {
		t.Fatal("expected the in-flight sweep to carry an outcome channel")
	}
	waitForSpawn(t, spawned)
}

func TestStartSweepIfDueKeepsHealthySweep(t *testing.T) {
	worker, spawned := fakeSweepSpawner(t)

	current := &inflightSweep{outcome: make(chan sweepOutcome, 1), started: time.Now()}
	if got := worker.startSweepIfDue(current); got != current {
		t.Fatalf("expected the healthy in-flight sweep to be kept, got %+v", got)
	}
	select {
	case <-spawned:
		t.Fatal("healthy in-flight sweep must not spawn another")
	default:
	}
}

func TestStartSweepIfDueAbandonsStalledSweep(t *testing.T) {
	worker, spawned := fakeSweepSpawner(t)

	stalled := &inflightSweep{
		outcome: make(chan sweepOutcome, 1),
		started: time.Now().Add(-sweepTimeout - time.Second),
	}
	next := worker.startSweepIfDue(stalled)
	if next == nil || next == stalled {
		t.Fatalf("expected a fresh in-flight sweep after abandoning the stalled one, got %+v", next)
	}
	waitForSpawn(t, spawned)

	// The stalled sweep's late outcome must go nowhere: the worker dropped its
	// channel, so a buffered send simply completes into the void.
	stalled.outcome <- sweepOutcome{vms: []VMInfo{{Name: "stale-vm"}}}
	if vms := worker.GetVMs(""); vms != nil {
		t.Fatalf("abandoned sweep outcome must never be published, got %+v", vms)
	}
}

func TestStartSweepIfDueHoldsAtOutstandingCap(t *testing.T) {
	worker, spawned := fakeSweepSpawner(t)
	worker.outstandingSweeps.Store(maxOutstandingSweeps)

	if got := worker.startSweepIfDue(nil); got != nil {
		t.Fatalf("expected no sweep at the outstanding cap, got %+v", got)
	}
	select {
	case <-spawned:
		t.Fatal("no sweep may be spawned at the outstanding cap")
	default:
	}

	worker.outstandingSweeps.Store(maxOutstandingSweeps - 1)
	if got := worker.startSweepIfDue(nil); got == nil {
		t.Fatal("expected sweeps to resume below the outstanding cap")
	}
	waitForSpawn(t, spawned)
}

func TestInflightSweepDoneIsNilSafe(t *testing.T) {
	var inflight *inflightSweep
	if inflight.done() != nil {
		t.Fatal("expected nil outcome channel for no in-flight sweep")
	}
}

func TestApplySweepPublishesCurrentHostResults(t *testing.T) {
	worker := &SingletonWorker{}
	identity := inventoryHostIdentity{URI: "qemu:///system", HostUUID: "8e6a3f0a-3f3f-4d43-9d3c-2f6d8b7a1c55"}

	worker.applySweep(sweepOutcome{
		identity: identity,
		vms:      []VMInfo{{Name: "alice-desktop", Owner: "alice"}},
		metadata: map[string]domainMetadataSnapshot{"uuid-1": {Owner: "alice"}},
		disks:    map[string]domainDiskSnapshot{"uuid-1": {UsedGB: 1, TotalGB: 2}},
	})

	if vms := worker.GetVMs("alice"); len(vms) != 1 || vms[0].Name != "alice-desktop" {
		t.Fatalf("expected the sweep's VMs to be published, got %+v", vms)
	}
	if count, ok := worker.CountVMsOwnedBy("alice"); !ok || count != 1 {
		t.Fatalf("expected an authoritative owner count of 1, got %d (authoritative=%v)", count, ok)
	}
	if len(worker.metadataByUUID) != 1 || len(worker.diskByUUID) != 1 {
		t.Fatalf("expected the sweep's caches to be installed, got %+v / %+v", worker.metadataByUUID, worker.diskByUUID)
	}
}

func TestApplySweepDiscardsResultsAcrossHostChange(t *testing.T) {
	worker := &SingletonWorker{}
	oldIdentity := inventoryHostIdentity{URI: "qemu:///system", HostUUID: "8e6a3f0a-3f3f-4d43-9d3c-2f6d8b7a1c55"}
	newIdentity := inventoryHostIdentity{URI: "qemu:///system", HostUUID: "1b2c3d4e-5f60-4718-8293-a4b5c6d7e8f9"}

	worker.applySweep(sweepOutcome{
		identity: oldIdentity,
		vms:      []VMInfo{{Name: "alice-desktop", Owner: "alice"}},
		metadata: map[string]domainMetadataSnapshot{"uuid-1": {Owner: "alice"}},
		disks:    map[string]domainDiskSnapshot{"uuid-1": {UsedGB: 1, TotalGB: 2}},
	})

	// A sweep that observed a different host was collected against the old
	// host's cache clones, so nothing from it may be published.
	worker.applySweep(sweepOutcome{
		identity: newIdentity,
		vms:      []VMInfo{{Name: "ghost-vm", Owner: "alice"}},
		metadata: map[string]domainMetadataSnapshot{"uuid-2": {Owner: "alice"}},
		disks:    map[string]domainDiskSnapshot{"uuid-2": {UsedGB: 3, TotalGB: 4}},
	})

	if vms := worker.GetVMs(""); vms != nil {
		t.Fatalf("expected the snapshot to be invalidated on host change, got %+v", vms)
	}
	if _, ok := worker.CountVMsOwnedBy("alice"); ok {
		t.Fatal("expected the owner count to be non-authoritative after a host change")
	}
	if len(worker.metadataByUUID) != 0 || len(worker.diskByUUID) != 0 {
		t.Fatalf("expected the inventory caches to be cleared, got %+v / %+v", worker.metadataByUUID, worker.diskByUUID)
	}

	// The next sweep against the new host is trusted again.
	worker.applySweep(sweepOutcome{
		identity: newIdentity,
		vms:      []VMInfo{{Name: "alice-desktop-2", Owner: "alice"}},
		metadata: map[string]domainMetadataSnapshot{"uuid-2": {Owner: "alice"}},
		disks:    map[string]domainDiskSnapshot{"uuid-2": {UsedGB: 3, TotalGB: 4}},
	})
	if count, ok := worker.CountVMsOwnedBy("alice"); !ok || count != 1 {
		t.Fatalf("expected the new host's sweep to publish, got %d (authoritative=%v)", count, ok)
	}
}

func TestApplySweepIgnoresFailedSweep(t *testing.T) {
	worker := &SingletonWorker{}

	worker.applySweep(sweepOutcome{err: errors.New("libvirt unreachable")})

	if vms := worker.GetVMs(""); vms != nil {
		t.Fatalf("expected no snapshot from a failed sweep, got %+v", vms)
	}
	if _, ok := worker.CountVMsOwnedBy("alice"); ok {
		t.Fatal("expected the owner count to stay non-authoritative after a failed sweep")
	}
	if worker.inventoryHostIdentity != (inventoryHostIdentity{}) {
		t.Fatalf("failed sweep must not record a host identity, got %+v", worker.inventoryHostIdentity)
	}
}
