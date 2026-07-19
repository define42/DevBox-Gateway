package virt

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

func TestViocovConnectErrorsSurfaceFromHelpers(t *testing.T) {
	t.Setenv(libvirtURIEnv, viocovBadLibvirtURI)

	if err := StartExistingVM("cvio-any"); err == nil {
		t.Fatal("StartExistingVM: expected connect error")
	}
	if err := ShutdownVM("cvio-any"); err == nil {
		t.Fatal("ShutdownVM: expected connect error")
	}
	if err := RestartVM("cvio-any"); err == nil {
		t.Fatal("RestartVM: expected connect error")
	}
	if err := UpdateVMResources("cvio-any", 1, 128); err == nil {
		t.Fatal("UpdateVMResources: expected connect error")
	}
	if _, _, err := VMOwner("cvio-any"); err == nil {
		t.Fatal("VMOwner: expected connect error")
	}
	if _, err := UserOwnsVM("cvio-any", "cvio-user"); err == nil {
		t.Fatal("UserOwnsVM: expected connect error")
	}
	if _, err := OpenSerialConsole("cvio-any"); err == nil {
		t.Fatal("OpenSerialConsole: expected connect error")
	}
	if _, err := OpenVNCConn("cvio-any"); err == nil {
		t.Fatal("OpenVNCConn: expected connect error")
	}
}

func TestViocovPowerAndResourcesMissingDomain(t *testing.T) {
	name := viocovUniqueName("absent")
	ops := map[string]func(string) error{
		"start":     StartExistingVM,
		"shutdown":  ShutdownVM,
		"restart":   RestartVM,
		"resources": func(n string) error { return UpdateVMResources(n, 1, 128) },
	}
	for op, fn := range ops {
		if err := fn(name); err == nil || !strings.Contains(err.Error(), "lookup domain") {
			t.Fatalf("%s: expected lookup failure for missing domain, got %v", op, err)
		}
	}
}

func TestViocovUpdateVMResourcesRejectsInvalidValues(t *testing.T) {
	if err := UpdateVMResources("cvio-any", 0, 128); err == nil {
		t.Fatal("expected error for non-positive vcpu count")
	}
	if err := UpdateVMResources("cvio-any", 1, 0); err == nil {
		t.Fatal("expected error for non-positive memory size")
	}
}

func TestViocovUpdateVMResourcesOnInactiveDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("resources")
	dom := viocovDefineDomain(t, conn, name, "")

	// Raising vcpus above the configured maximum takes the raise-maximum branch.
	if err := UpdateVMResources(name, 2, 256); err != nil {
		t.Fatalf("raise resources: %v", err)
	}
	maxVcpus, err := dom.GetVcpusFlags(libvirt.DOMAIN_VCPU_MAXIMUM | libvirt.DOMAIN_VCPU_CONFIG)
	if err != nil {
		t.Fatalf("get max vcpus: %v", err)
	}
	if maxVcpus != 2 {
		t.Fatalf("expected max vcpus 2, got %d", maxVcpus)
	}

	// Lowering the count below the maximum skips the raise-maximum branch.
	if err := UpdateVMResources(name, 1, 256); err != nil {
		t.Fatalf("lower resources: %v", err)
	}
	current, err := dom.GetVcpusFlags(libvirt.DOMAIN_VCPU_CONFIG)
	if err != nil {
		t.Fatalf("get current vcpus: %v", err)
	}
	if current != 1 {
		t.Fatalf("expected current vcpus 1, got %d", current)
	}
	maxMemory, err := dom.GetMaxMemory()
	if err != nil {
		t.Fatalf("get max memory: %v", err)
	}
	if maxMemory != 256*1024 {
		t.Fatalf("expected max memory 262144 KiB, got %d", maxMemory)
	}
}

func TestViocovStartAndRestartSurfaceCreateFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("badboot")
	missingDisk := filepath.Join(t.TempDir(), "missing.raw")
	viocovDefineDomain(t, conn, name, viocovRawDiskXML(missingDisk))

	if err := StartExistingVM(name); err == nil || !strings.Contains(err.Error(), "start domain") {
		t.Fatalf("StartExistingVM: expected start failure, got %v", err)
	}
	if err := RestartVM(name); err == nil || !strings.Contains(err.Error(), "start domain") {
		t.Fatalf("RestartVM: expected start failure, got %v", err)
	}
	// Force-shutdown of an already stopped domain is a no-op.
	if err := ShutdownVM(name); err != nil {
		t.Fatalf("ShutdownVM on inactive domain: %v", err)
	}
}

func TestViocovPowerLifecycleOnRunningDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("power")
	dom := viocovStartDomain(t, conn, name, "")

	if err := StartExistingVM(name); err != nil {
		t.Fatalf("StartExistingVM on active domain: %v", err)
	}
	if err := UpdateVMResources(name, 1, 128); err == nil || !strings.Contains(err.Error(), "must be stopped") {
		t.Fatalf("expected running domain to reject resource update, got %v", err)
	}
	if err := RestartVM(name); err != nil {
		t.Fatalf("RestartVM on active domain: %v", err)
	}
	active, err := dom.IsActive()
	if err != nil {
		t.Fatalf("check active after reboot: %v", err)
	}
	if !active {
		t.Fatal("expected domain to stay active after reboot request")
	}
	if err := ShutdownVM(name); err != nil {
		t.Fatalf("ShutdownVM: %v", err)
	}
	active, err = dom.IsActive()
	if err != nil {
		t.Fatalf("check active after shutdown: %v", err)
	}
	if active {
		t.Fatal("expected domain to be shut off after force shutdown")
	}
}

func TestViocovListVMsAndDoWorkErrors(t *testing.T) {
	if _, err := ListVMs("", &libvirt.Connect{}); err == nil {
		t.Fatal("expected ListVMs error for an invalid connection")
	}
	worker := &SingletonWorker{}
	if err := worker.doWork(&libvirt.Connect{}); err == nil {
		t.Fatal("expected doWork error for an invalid connection")
	}
}

func TestViocovListVMsFiltersByOwnerMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("list")
	dom := viocovDefineDomain(t, conn, name, "")
	owner := viocovUniqueName("listowner")
	if err := setDomainOwnerMetadata(dom, owner); err != nil {
		t.Fatalf("setting owner metadata: %v", err)
	}

	vms, err := ListVMs(owner, conn)
	if err != nil {
		t.Fatalf("ListVMs(owner): %v", err)
	}
	vm := requireListedVM(t, vms, name)
	if vm.Owner != owner {
		t.Fatalf("expected owner %q, got %q", owner, vm.Owner)
	}
	if vm.State != "shut off" {
		t.Fatalf("expected state 'shut off', got %q", vm.State)
	}

	otherVMs, err := ListVMs(viocovUniqueName("nobody"), conn)
	if err != nil {
		t.Fatalf("ListVMs(other user): %v", err)
	}
	assertListExcludesVM(t, otherVMs, name)
}

func TestViocovDomainVMInfoBranches(t *testing.T) {
	if _, ok := domainVMInfo(libvirt.Domain{}, ""); ok {
		t.Fatal("expected invalid domain handle to be skipped")
	}

	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("info")
	dom := viocovDefineDomain(t, conn, name, "")

	info, ok := domainVMInfo(*dom, "")
	if !ok {
		t.Fatal("expected VM info for a defined domain")
	}
	if info.Name != name || info.Owner != "" || info.State != "shut off" {
		t.Fatalf("unexpected VM info: %+v", info)
	}
	if info.TTYReady || info.VNCReady || info.IP != "" || info.PrimaryIP != "" {
		t.Fatalf("expected stopped domain to report no console/IPs, got %+v", info)
	}
}

func TestViocovVMInfoHelperFallbacks(t *testing.T) {
	dom := &libvirt.Domain{}
	if got := domainOwnerForVMInfo("cvio-x", dom); got != "" {
		t.Fatalf("domainOwnerForVMInfo: expected empty owner, got %q", got)
	}
	if got := domainGuestUserForVMInfo("cvio-x", dom); got != "" {
		t.Fatalf("domainGuestUserForVMInfo: expected empty guest user, got %q", got)
	}
	if got := domainBaseImageForVMInfo("cvio-x", dom); got != "" {
		t.Fatalf("domainBaseImageForVMInfo: expected empty base image, got %q", got)
	}
	if got := domainCreatedAtForVMInfo("cvio-x", dom); got != "" {
		t.Fatalf("domainCreatedAtForVMInfo: expected empty created-at, got %q", got)
	}
	if mem, vcpu := domainResources(libvirt.Domain{}); mem != 0 || vcpu != 0 {
		t.Fatalf("domainResources: expected 0/0, got %d/%d", mem, vcpu)
	}
	if domainTTYReady(dom) {
		t.Fatal("domainTTYReady: expected false for invalid domain handle")
	}
	if domainVNCReady(dom) {
		t.Fatal("domainVNCReady: expected false for invalid domain handle")
	}
	seen := map[string]struct{}{}
	if got := appendDomainIPsFromSource(nil, seen, libvirt.Domain{}, libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE); got != nil {
		t.Fatalf("appendDomainIPsFromSource: expected unchanged ips, got %v", got)
	}
}

func TestViocovDomainDiskGB(t *testing.T) {
	conn := newTestLibvirtConn(t)
	dir := newLibvirtAccessibleTempDir(t, "viocov-disk-")

	fullPath := filepath.Join(dir, "full.raw")
	if err := os.WriteFile(fullPath, bytes.Repeat([]byte{0xa5}, 512*1024), 0o666); err != nil {
		t.Fatalf("write disk file: %v", err)
	}
	emptyPath := filepath.Join(dir, "empty.raw")
	if err := os.WriteFile(emptyPath, nil, 0o666); err != nil {
		t.Fatalf("write empty disk file: %v", err)
	}

	full := viocovDefineDomain(t, conn, viocovUniqueName("diskfull"), viocovRawDiskXML(fullPath))
	if used, total := domainDiskGB(*full); used != 1 || total != 1 {
		t.Fatalf("512KiB disk: expected 1/1 GiB (ceil), got %d/%d", used, total)
	}

	// A zero-length raw image leaves capacity and allocation at zero, driving
	// the fallback chain to its zero result.
	empty := viocovDefineDomain(t, conn, viocovUniqueName("diskempty"), viocovRawDiskXML(emptyPath))
	if used, total := domainDiskGB(*empty); used != 0 || total != 0 {
		t.Fatalf("empty disk: expected 0/0 GiB, got %d/%d", used, total)
	}

	none := viocovDefineDomain(t, conn, viocovUniqueName("disknone"), "")
	if used, total := domainDiskGB(*none); used != 0 || total != 0 {
		t.Fatalf("no disk: expected 0/0 GiB, got %d/%d", used, total)
	}
}

func TestViocovBytesToGiBCeil(t *testing.T) {
	cases := map[uint64]int{
		0:         0,
		1:         1,
		1 << 30:   1,
		1<<30 + 1: 2,
		3 << 30:   3,
	}
	for in, want := range cases {
		if got := bytesToGiBCeil(in); got != want {
			t.Errorf("bytesToGiBCeil(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestViocovDomainCanReportIPs(t *testing.T) {
	cases := []struct {
		state libvirt.DomainState
		want  bool
	}{
		{libvirt.DOMAIN_RUNNING, true},
		{libvirt.DOMAIN_PAUSED, true},
		{libvirt.DOMAIN_PMSUSPENDED, true},
		{libvirt.DOMAIN_NOSTATE, false},
		{libvirt.DOMAIN_BLOCKED, false},
		{libvirt.DOMAIN_SHUTDOWN, false},
		{libvirt.DOMAIN_SHUTOFF, false},
		{libvirt.DOMAIN_CRASHED, false},
		{libvirt.DomainState(99), false},
	}
	for _, tc := range cases {
		if got := domainCanReportIPs(tc.state); got != tc.want {
			t.Errorf("domainCanReportIPs(%d) = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestViocovWorkerRunRefreshesCache(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("worker")
	viocovDefineDomain(t, conn, name, "")

	ctx, cancel := context.WithCancel(context.Background())
	worker := &SingletonWorker{ticker: time.NewTicker(25 * time.Millisecond), ctx: ctx, cancel: cancel}

	done := make(chan struct{})
	go func() {
		worker.run()
		close(done)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !slices.Contains(worker.GetVMnames(), name) {
		time.Sleep(25 * time.Millisecond)
	}
	worker.Stop()
	waitForWorkerStop(t, done)

	if !slices.Contains(worker.GetVMnames(), name) {
		t.Fatalf("expected worker cache to list %s", name)
	}
}

func TestViocovWorkerRunSurvivesConnectFailure(t *testing.T) {
	t.Setenv(libvirtURIEnv, viocovBadLibvirtURI)

	ctx, cancel := context.WithCancel(context.Background())
	worker := &SingletonWorker{ticker: time.NewTicker(20 * time.Millisecond), ctx: ctx, cancel: cancel}

	done := make(chan struct{})
	go func() {
		worker.run()
		close(done)
	}()

	// Let a few ticks hit the connect-failure branch, then stop the worker.
	time.Sleep(150 * time.Millisecond)
	worker.Stop()
	waitForWorkerStop(t, done)

	if names := worker.GetVMnames(); names != nil {
		t.Fatalf("expected no cached VMs after connect failures, got %v", names)
	}
}

func TestViocovEnsureLibvirtVersion(t *testing.T) {
	conn := newTestLibvirtConn(t)
	if err := ensureLibvirtVersion(conn); err != nil {
		t.Fatalf("ensureLibvirtVersion on live connection: %v", err)
	}
	if err := ensureLibvirtVersion(&libvirt.Connect{}); err == nil {
		t.Fatal("expected version query error for an invalid connection")
	}
}
