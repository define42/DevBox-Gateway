package virt

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefreshRDPReadinessProbesOnlyRequestedUsersRunningVMs(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{
		{Name: "alice-desktop", Owner: "alice", State: "running", PrimaryIP: "192.168.122.10"},
		{Name: "alice-stopped", Owner: "alice", State: "shut off", PrimaryIP: "192.168.122.11"},
		{Name: "bob-desktop", Owner: "bob", State: "running", PrimaryIP: "192.168.122.12"},
	})

	var mu sync.Mutex
	var addresses []string
	worker.refreshRDPReadiness(
		context.Background(),
		"alice",
		func(_ context.Context, address string) bool {
			mu.Lock()
			addresses = append(addresses, address)
			mu.Unlock()
			return true
		},
	)

	mu.Lock()
	gotAddresses := append([]string(nil), addresses...)
	mu.Unlock()
	wantAddress := net.JoinHostPort("192.168.122.10", rdpPort)
	if len(gotAddresses) != 1 || gotAddresses[0] != wantAddress {
		t.Fatalf("probed addresses = %v, want [%s]", gotAddresses, wantAddress)
	}

	alice := worker.VMs("alice")
	if len(alice) != 2 || !alice[0].RDPReady || alice[1].RDPReady {
		t.Fatalf("unexpected Alice readiness state: %+v", alice)
	}
	bob := worker.VMs("bob")
	if len(bob) != 1 || bob[0].RDPReady {
		t.Fatalf("Bob VM was probed by Alice's connection: %+v", bob)
	}
}

func TestRefreshRDPReadinessDuplicatesWorkAcrossWebSockets(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{{
		Name:      "alice-desktop",
		Owner:     "alice",
		State:     "running",
		PrimaryIP: "192.168.122.10",
	}})

	var probes atomic.Int32
	probe := func(context.Context, string) bool {
		probes.Add(1)
		return true
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			<-start
			worker.refreshRDPReadiness(context.Background(), "alice", probe)
		}()
	}
	close(start)
	wg.Wait()

	if got := probes.Load(); got != 2 {
		t.Fatalf("two WebSockets caused %d probes, want 2", got)
	}
}

func TestOlderWebSocketObservationCannotOverwriteNewerResult(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{{
		Name:      "alice-desktop",
		Owner:     "alice",
		State:     "running",
		PrimaryIP: "192.168.122.10",
	}})
	jobs := worker.rdpReadinessJobs("alice")
	if len(jobs) != 1 {
		t.Fatalf("expected one readiness job, got %d", len(jobs))
	}

	olderObservation := worker.nextRDPObservation.Add(1)
	newerObservation := worker.nextRDPObservation.Add(1)
	worker.applyRDPReadinessResults([]rdpReadinessResult{{
		job:         jobs[0],
		ready:       false,
		observation: newerObservation,
	}})
	worker.applyRDPReadinessResults([]rdpReadinessResult{{
		job:         jobs[0],
		ready:       true,
		observation: olderObservation,
	}})

	if got := worker.VMs("alice"); len(got) != 1 || got[0].RDPReady {
		t.Fatalf("older WebSocket observation overwrote newer result: %+v", got)
	}
}

func TestRefreshRDPReadinessHasNoGlobalConcurrencyLimit(t *testing.T) {
	const vmCount = 64

	worker := &SingletonWorker{}
	vms := make([]VMInfo, 0, vmCount)
	for i := range vmCount {
		vms = append(vms, VMInfo{
			Name:      fmt.Sprintf("alice-vm-%d", i),
			Owner:     "alice",
			State:     "running",
			PrimaryIP: fmt.Sprintf("192.168.122.%d", i+10),
		})
	}
	worker.setVMs(vms)

	started := make(chan struct{}, vmCount)
	unblock := make(chan struct{})
	var unblockOnce sync.Once
	defer func() { unblockOnce.Do(func() { close(unblock) }) }()

	done := make(chan struct{})
	go func() {
		worker.refreshRDPReadiness(
			context.Background(),
			"alice",
			func(context.Context, string) bool {
				started <- struct{}{}
				<-unblock
				return true
			},
		)
		close(done)
	}()

	for range vmCount {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("fewer than %d probes started concurrently", vmCount)
		}
	}
	unblockOnce.Do(func() { close(unblock) })

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("uncapped readiness round did not complete")
	}
	for _, vm := range worker.VMs("alice") {
		if !vm.RDPReady {
			t.Fatalf("VM %q was not updated after its probe", vm.Name)
		}
	}
}

func TestRDPReadinessSurvivesInventoryRefreshAndRejectsStaleResult(t *testing.T) {
	worker := &SingletonWorker{}
	original := VMInfo{
		Name:      "alice-desktop",
		Owner:     "alice",
		CreatedAt: "2026-08-15T12:00:00Z",
		State:     "running",
		MemoryMiB: 4096,
		PrimaryIP: "192.168.122.10",
	}
	worker.setVMs([]VMInfo{original})

	jobs := worker.rdpReadinessJobs("alice")
	if len(jobs) != 1 {
		t.Fatalf("expected one initial job, got %d", len(jobs))
	}
	staleJob := jobs[0]
	worker.applyRDPReadinessResults([]rdpReadinessResult{{job: staleJob, ready: true}})

	refreshed := original
	refreshed.MemoryMiB = 8192
	worker.setVMs([]VMInfo{refreshed})
	if got := worker.VMs("alice"); len(got) != 1 || !got[0].RDPReady {
		t.Fatalf("unchanged RDP target lost readiness during inventory refresh: %+v", got)
	}

	changedIP := refreshed
	changedIP.PrimaryIP = "192.168.122.20"
	worker.setVMs([]VMInfo{changedIP})
	if got := worker.VMs("alice"); len(got) != 1 || got[0].RDPReady {
		t.Fatalf("changed RDP target retained stale readiness: %+v", got)
	}

	worker.applyRDPReadinessResults([]rdpReadinessResult{{job: staleJob, ready: true}})
	if got := worker.VMs("alice"); len(got) != 1 || got[0].RDPReady {
		t.Fatalf("stale probe result was applied after IP change: %+v", got)
	}

	currentJobs := worker.rdpReadinessJobs("alice")
	if len(currentJobs) != 1 {
		t.Fatalf("expected one current job, got %d", len(currentJobs))
	}
	worker.applyRDPReadinessResults([]rdpReadinessResult{{job: currentJobs[0], ready: true}})
	if got := worker.VMs("alice"); len(got) != 1 || !got[0].RDPReady {
		t.Fatalf("current probe result was not applied: %+v", got)
	}

	worker.setVMs(nil)
	worker.setVMs([]VMInfo{original})
	worker.applyRDPReadinessResults([]rdpReadinessResult{{job: currentJobs[0], ready: true}})
	if got := worker.VMs("alice"); len(got) != 1 || got[0].RDPReady {
		t.Fatalf("pre-removal probe result was applied to a recreated VM: %+v", got)
	}
}

func TestRefreshRDPReadinessCancellationStopsBlockedProbes(t *testing.T) {
	worker := &SingletonWorker{}
	vms := make([]VMInfo, 0, 8)
	for i := range 8 {
		vms = append(vms, VMInfo{
			Name:      fmt.Sprintf("alice-vm-%d", i),
			Owner:     "alice",
			State:     "running",
			PrimaryIP: fmt.Sprintf("192.168.122.%d", i+10),
		})
	}
	worker.setVMs(vms)

	started := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		worker.refreshRDPReadiness(
			ctx,
			"alice",
			func(ctx context.Context, _ string) bool {
				select {
				case started <- struct{}{}:
				default:
				}
				<-ctx.Done()
				return false
			},
		)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("readiness probes did not start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled WebSocket readiness round did not stop")
	}
}
