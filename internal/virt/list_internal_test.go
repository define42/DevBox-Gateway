package virt

import (
	"devboxgateway/internal/hash"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

func TestSingletonWorkerDoWorkNilConn(t *testing.T) {
	worker := &SingletonWorker{}
	if err := worker.doWork(nil); err == nil {
		t.Fatal("expected error for nil libvirt connection")
	}
}

func TestSingletonWorkerCacheConcurrentAccess(t *testing.T) {
	t.Parallel()

	worker := &SingletonWorker{}

	const loops = 500
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			worker.setVMs([]VMInfo{
				{
					Name:      fmt.Sprintf("alice-vm-%d", i),
					Owner:     "alice",
					PrimaryIP: "10.0.0.1",
				},
				{
					Name:      fmt.Sprintf("bob-vm-%d", i),
					Owner:     "bob",
					PrimaryIP: "10.0.0.2",
				},
			})
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < loops; i++ {
			_ = worker.GetVMs("alice")
			_ = worker.GetVMnames()
			_, _ = worker.GetIPOfVM(fmt.Sprintf("alice-vm-%d", i))
		}
	}()

	wg.Wait()
}

func TestFormatState(t *testing.T) {
	tests := []struct {
		state libvirt.DomainState
		want  string
	}{
		{libvirt.DOMAIN_NOSTATE, "unknown"},
		{libvirt.DOMAIN_BLOCKED, "blocked"},
		{libvirt.DOMAIN_RUNNING, "running"},
		{libvirt.DOMAIN_PAUSED, "paused"},
		{libvirt.DOMAIN_SHUTDOWN, "shut off"},
		{libvirt.DOMAIN_SHUTOFF, "shut off"},
		{libvirt.DOMAIN_CRASHED, "crashed"},
		{libvirt.DOMAIN_PMSUSPENDED, "suspended"},
		{libvirt.DomainState(99), "unknown (99)"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := formatState(tc.state); got != tc.want {
				t.Fatalf("formatState(%d) = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
}

func TestTCPEndpointReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	if !tcpEndpointReady(listener.Addr().String(), time.Second) {
		t.Fatal("expected listening TCP endpoint to be ready")
	}
}

func TestTCPEndpointNotReady(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	if tcpEndpointReady(address, 100*time.Millisecond) {
		t.Fatal("expected closed TCP endpoint to be unavailable")
	}
	if domainRDPReady("") {
		t.Fatal("expected a VM without a trusted routing IP to be unavailable")
	}
}

func TestGetVMsFiltersByUser(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{
		{Name: "alice-desktop", Owner: "alice", PrimaryIP: "10.0.0.1"},
		{Name: "alice-dev", Owner: "alice", PrimaryIP: "10.0.0.2"},
		{Name: "bob-desktop", Owner: "bob", PrimaryIP: "10.0.0.3"},
	})

	aliceVMs := worker.GetVMs("alice")
	if len(aliceVMs) != 2 {
		t.Fatalf("expected 2 VMs for alice, got %d", len(aliceVMs))
	}

	bobVMs := worker.GetVMs("bob")
	if len(bobVMs) != 1 {
		t.Fatalf("expected 1 VM for bob, got %d", len(bobVMs))
	}

	allVMs := worker.GetVMs("")
	if len(allVMs) != 3 {
		t.Fatalf("expected 3 VMs for empty user, got %d", len(allVMs))
	}
}

func TestGetVMsSkipsOwnerlessVMsWhenFiltering(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{
		{Name: "legacy-vm"},
		{Name: "alice-desktop", Owner: "alice"},
	})

	aliceVMs := worker.GetVMs("alice")
	if len(aliceVMs) != 1 {
		t.Fatalf("expected 1 VM for alice, got %d", len(aliceVMs))
	}
	if aliceVMs[0].Name != "alice-desktop" {
		t.Fatalf("expected owned VM to be returned, got %q", aliceVMs[0].Name)
	}
}

func TestGetVMnames(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{
		{Name: "vm-a"},
		{Name: "vm-b"},
		{Name: "vm-c"},
	})

	names := worker.GetVMnames()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
}

func TestGetIPOfVM(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{
		{Name: "my-vm", PrimaryIP: "192.168.1.100"},
	})

	ip, err := worker.GetIPOfVM("my-vm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ip != "192.168.1.100" {
		t.Fatalf("expected 192.168.1.100, got %q", ip)
	}

	_, err = worker.GetIPOfVM("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent VM")
	}
}

func TestResolveVMNameByLabel(t *testing.T) {
	secret := []byte("routing-secret")
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{
		{Name: "alice-desktop", PrimaryIP: "192.168.1.10"},
		{Name: "bob-devbox", PrimaryIP: "192.168.1.11"},
	})

	label := hash.RoutingLabel(secret, "bob-devbox")
	name, ok := worker.ResolveVMNameByLabel(secret, label)
	if !ok {
		t.Fatal("expected label to resolve to a VM")
	}
	if name != "bob-devbox" {
		t.Fatalf("expected bob-devbox, got %q", name)
	}

	if _, ok := worker.ResolveVMNameByLabel(secret, "unknownlabel"); ok {
		t.Fatal("expected unknown label to not resolve")
	}
	// The same name under a different secret must not resolve.
	if _, ok := worker.ResolveVMNameByLabel([]byte("other-secret"), label); ok {
		t.Fatal("expected label to be secret-specific")
	}
}

func TestSetVMsNil(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{{Name: "test"}})
	worker.setVMs(nil)

	vms := worker.GetVMs("")
	if len(vms) != 0 {
		t.Fatalf("expected 0 VMs after setting nil, got %d", len(vms))
	}
}

func TestSetVMsEmpty(t *testing.T) {
	worker := &SingletonWorker{}
	worker.setVMs([]VMInfo{{Name: "test"}})
	worker.setVMs([]VMInfo{})

	vms := worker.GetVMs("")
	if len(vms) != 0 {
		t.Fatalf("expected 0 VMs after setting empty, got %d", len(vms))
	}
}

func TestSnapshotVMsEmpty(t *testing.T) {
	worker := &SingletonWorker{}

	snapshot := worker.snapshotVMs()
	if snapshot != nil {
		t.Fatalf("expected nil for empty snapshot, got %v", snapshot)
	}
}

func TestLibvirtURI(t *testing.T) {
	// Default
	t.Setenv("LIBVIRT_URI", "")
	if got := LibvirtURI(); got != defaultLibvirtURI {
		t.Fatalf("expected default URI, got %q", got)
	}

	// Custom
	t.Setenv("LIBVIRT_URI", "qemu:///session")
	if got := LibvirtURI(); got != "qemu:///session" {
		t.Fatalf("expected custom URI, got %q", got)
	}
}
