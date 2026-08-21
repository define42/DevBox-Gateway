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
	if err := GracefulShutdownVM("cvio-any"); err == nil {
		t.Fatal("GracefulShutdownVM: expected connect error")
	}
	if err := RestartVM("cvio-any"); err == nil {
		t.Fatal("RestartVM: expected connect error")
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

func TestViocovPowerMissingDomain(t *testing.T) {
	name := viocovUniqueName("absent")
	ops := map[string]func(string) error{
		"start":    StartExistingVM,
		"shutdown": ShutdownVM,
		"graceful": GracefulShutdownVM,
		"restart":  RestartVM,
	}
	for op, fn := range ops {
		if err := fn(name); err == nil || !strings.Contains(err.Error(), "lookup domain") {
			t.Fatalf("%s: expected lookup failure for missing domain, got %v", op, err)
		}
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
	// So is a graceful shutdown request.
	if err := GracefulShutdownVM(name); err != nil {
		t.Fatalf("GracefulShutdownVM on inactive domain: %v", err)
	}
}

func TestViocovPowerLifecycleOnRunningDomain(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("power")
	dom := viocovStartDomain(t, conn, name, "")

	if err := StartExistingVM(name); err != nil {
		t.Fatalf("StartExistingVM on active domain: %v", err)
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
	// The ACPI power-button request is delivered, but this firmware-only guest
	// (SeaBIOS, no OS) ignores it and must stay running — exactly the case the
	// auto-shutdown sweeper escalates on.
	if err := GracefulShutdownVM(name); err != nil {
		t.Fatalf("GracefulShutdownVM on active domain: %v", err)
	}
	active, err = dom.IsActive()
	if err != nil {
		t.Fatalf("check active after graceful shutdown request: %v", err)
	}
	if !active {
		t.Fatal("expected firmware-only domain to ignore the ACPI power button")
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
	worker := &SingletonWorker{metadataByUUID: map[string]domainMetadataSnapshot{
		"cached-domain": {CreatedAt: "2026-08-15T12:00:00Z"},
	}, diskByUUID: map[string]domainDiskSnapshot{
		"cached-domain": {UsedGB: 1, TotalGB: 2},
	}}
	worker.setVMs([]VMInfo{{Name: "cached-vm", Owner: "alice"}})
	if err := worker.doWork(&libvirt.Connect{}); err == nil {
		t.Fatal("expected doWork error for an invalid connection")
	}
	if len(worker.metadataByUUID) != 1 {
		t.Fatalf("failed libvirt listing cleared metadata cache: %+v", worker.metadataByUUID)
	}
	if len(worker.diskByUUID) != 1 {
		t.Fatalf("failed libvirt listing cleared disk cache: %+v", worker.diskByUUID)
	}
	if vms := worker.VMs(""); len(vms) != 1 || vms[0].Name != "cached-vm" {
		t.Fatalf("failed libvirt listing replaced last successful VM snapshot: %+v", vms)
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

func TestViocovListVMsExcludesTransientDomains(t *testing.T) {
	conn := newTestLibvirtConn(t)
	persistentName := viocovUniqueName("persistent-list")
	transientName := viocovUniqueName("transient-list")
	viocovDefineDomain(t, conn, persistentName, "")

	transient, err := conn.DomainCreateXML(viocovDomainXML(transientName, ""), 0)
	if err != nil {
		t.Fatalf("create transient domain %s: %v", transientName, err)
	}
	t.Cleanup(func() {
		_ = transient.Destroy()
		_ = transient.Free()
	})

	vms, err := ListVMs("", conn)
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	requireListedVM(t, vms, persistentName)
	assertListExcludesVM(t, vms, transientName)
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
	if info.IP != "" || info.PrimaryIP != "" {
		t.Fatalf("expected stopped domain to report no console/IPs, got %+v", info)
	}
}

func TestViocovVMInfoHelperFallbacks(t *testing.T) {
	dom := &libvirt.Domain{}
	if got := domainMetadataForVMInfo("cvio-x", dom); got != (domainMetadataSnapshot{}) {
		t.Fatalf("domainMetadataForVMInfo: expected empty metadata, got %+v", got)
	}
	if mem, vcpu := domainResources(libvirt.Domain{}); mem != 0 || vcpu != 0 {
		t.Fatalf("domainResources: expected 0/0, got %d/%d", mem, vcpu)
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

func TestViocovWorkerDiskCacheUsesUUIDLifetimeSnapshot(t *testing.T) {
	fixture, first, firstUUID := newViocovWorkerDiskCacheFixture(t)
	fixture.assertInitialSnapshot(firstUUID)
	fixture.resizeAndAssertSnapshotIsImmutable()

	second, secondUUID := fixture.replaceDomain(first, firstUUID)
	fixture.assertReplacement(firstUUID, secondUUID)
	fixture.removeDomain(second, secondUUID)
}

type viocovWorkerDiskCacheFixture struct {
	t        *testing.T
	conn     *libvirt.Connect
	worker   *SingletonWorker
	name     string
	diskPath string
}

func newViocovWorkerDiskCacheFixture(
	t *testing.T,
) (*viocovWorkerDiskCacheFixture, *libvirt.Domain, string) {
	t.Helper()
	conn := newTestLibvirtConn(t)
	dir := newLibvirtAccessibleTempDir(t, "viocov-worker-disk-")
	diskPath := filepath.Join(dir, "disk.raw")
	if err := os.WriteFile(diskPath, nil, 0o666); err != nil {
		t.Fatalf("write empty disk file: %v", err)
	}

	name := viocovUniqueName("worker-disk-cache")
	first := viocovDefineDomain(t, conn, name, viocovRawDiskXML(diskPath))
	firstUUID, err := first.GetUUIDString()
	if err != nil {
		t.Fatalf("get first domain UUID: %v", err)
	}
	fixture := &viocovWorkerDiskCacheFixture{
		t:        t,
		conn:     conn,
		worker:   &SingletonWorker{},
		name:     name,
		diskPath: diskPath,
	}
	return fixture, first, firstUUID
}

func (fixture *viocovWorkerDiskCacheFixture) assertInitialSnapshot(domainUUID string) {
	fixture.t.Helper()
	if err := fixture.worker.doWork(fixture.conn); err != nil {
		fixture.t.Fatalf("inventory initial zero disk: %v", err)
	}
	if disk, ok := fixture.cachedDisk(domainUUID); !ok || disk != (domainDiskSnapshot{}) {
		fixture.t.Fatalf("initial cached disk = %+v (present=%v), want successful 0/0", disk, ok)
	}
	fixture.worker.inventoryCacheMu.Lock()
	_, metadataCachedWithoutCompletion := fixture.worker.metadataByUUID[domainUUID]
	fixture.worker.inventoryCacheMu.Unlock()
	if metadataCachedWithoutCompletion {
		fixture.t.Fatal("incomplete metadata was cached alongside valid block info")
	}
	if vm := requireListedVM(fixture.t, fixture.worker.VMs(""), fixture.name); vm.VolumeUsedGB != 0 || vm.VolumeGB != 0 {
		fixture.t.Fatalf("initial worker disk = %d/%d, want 0/0", vm.VolumeUsedGB, vm.VolumeGB)
	}
}

func (fixture *viocovWorkerDiskCacheFixture) resizeAndAssertSnapshotIsImmutable() {
	fixture.t.Helper()
	// Change both allocation and capacity without changing the domain UUID.
	// Direct ListVMs must remain fresh while the worker deliberately keeps its
	// first successful UUID-lifetime snapshot.
	if err := os.WriteFile(fixture.diskPath, bytes.Repeat([]byte{0xa5}, 512*1024), 0o666); err != nil {
		fixture.t.Fatalf("allocate disk file: %v", err)
	}
	if err := os.Truncate(fixture.diskPath, 2<<30); err != nil {
		fixture.t.Fatalf("resize disk file: %v", err)
	}
	directVMs, err := ListVMs("", fixture.conn)
	if err != nil {
		fixture.t.Fatalf("direct ListVMs after disk change: %v", err)
	}
	if vm := requireListedVM(fixture.t, directVMs, fixture.name); vm.VolumeUsedGB != 1 || vm.VolumeGB != 2 {
		fixture.t.Fatalf("fresh direct disk = %d/%d, want 1/2", vm.VolumeUsedGB, vm.VolumeGB)
	}
	if err := fixture.worker.doWork(fixture.conn); err != nil {
		fixture.t.Fatalf("inventory cached disk after same-UUID change: %v", err)
	}
	if vm := requireListedVM(fixture.t, fixture.worker.VMs(""), fixture.name); vm.VolumeUsedGB != 0 || vm.VolumeGB != 0 {
		fixture.t.Fatalf("same-UUID worker disk changed to %d/%d, want cached 0/0", vm.VolumeUsedGB, vm.VolumeGB)
	}
}

func (fixture *viocovWorkerDiskCacheFixture) replaceDomain(
	first *libvirt.Domain,
	firstUUID string,
) (*libvirt.Domain, string) {
	fixture.t.Helper()
	if err := first.Undefine(); err != nil {
		fixture.t.Fatalf("undefine first same-name domain: %v", err)
	}
	second := viocovDefineDomain(fixture.t, fixture.conn, fixture.name, viocovRawDiskXML(fixture.diskPath))
	secondUUID, err := second.GetUUIDString()
	if err != nil {
		fixture.t.Fatalf("get replacement domain UUID: %v", err)
	}
	if secondUUID == firstUUID {
		fixture.t.Fatalf("replacement UUID = old UUID %q", firstUUID)
	}
	if err := fixture.worker.doWork(fixture.conn); err != nil {
		fixture.t.Fatalf("inventory same-name disk replacement: %v", err)
	}
	return second, secondUUID
}

func (fixture *viocovWorkerDiskCacheFixture) assertReplacement(firstUUID string, secondUUID string) {
	fixture.t.Helper()
	if _, ok := fixture.cachedDisk(firstUUID); ok {
		fixture.t.Fatalf("old disk UUID %q survived replacement sweep", firstUUID)
	}
	if disk, ok := fixture.cachedDisk(secondUUID); !ok || disk != (domainDiskSnapshot{UsedGB: 1, TotalGB: 2}) {
		fixture.t.Fatalf("replacement cached disk = %+v (present=%v), want 1/2", disk, ok)
	}
	if vm := requireListedVM(fixture.t, fixture.worker.VMs(""), fixture.name); vm.VolumeUsedGB != 1 || vm.VolumeGB != 2 {
		fixture.t.Fatalf("replacement worker disk = %d/%d, want 1/2", vm.VolumeUsedGB, vm.VolumeGB)
	}
}

func (fixture *viocovWorkerDiskCacheFixture) removeDomain(domain *libvirt.Domain, domainUUID string) {
	fixture.t.Helper()
	if err := domain.Undefine(); err != nil {
		fixture.t.Fatalf("undefine replacement domain: %v", err)
	}
	if err := fixture.worker.doWork(fixture.conn); err != nil {
		fixture.t.Fatalf("inventory after disk-domain removal: %v", err)
	}
	if _, ok := fixture.cachedDisk(domainUUID); ok {
		fixture.t.Fatalf("removed disk UUID %q survived pruning sweep", domainUUID)
	}
}

func (fixture *viocovWorkerDiskCacheFixture) cachedDisk(domainUUID string) (domainDiskSnapshot, bool) {
	fixture.t.Helper()
	fixture.worker.inventoryCacheMu.Lock()
	defer fixture.worker.inventoryCacheMu.Unlock()
	disk, ok := fixture.worker.diskByUUID[domainUUID]
	return disk, ok
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
	for time.Now().Before(deadline) && !slices.Contains(worker.VMNames(), name) {
		time.Sleep(25 * time.Millisecond)
	}
	worker.Stop()
	waitForWorkerStop(t, done)

	if !slices.Contains(worker.VMNames(), name) {
		t.Fatalf("expected worker cache to list %s", name)
	}
}

func TestViocovWorkerRunSurvivesConnectFailure(t *testing.T) {
	t.Setenv(libvirtURIEnv, viocovBadLibvirtURI)

	ctx, cancel := context.WithCancel(context.Background())
	worker := &SingletonWorker{
		ticker: time.NewTicker(20 * time.Millisecond),
		ctx:    ctx,
		cancel: cancel,
		metadataByUUID: map[string]domainMetadataSnapshot{
			"cached-domain": {CreatedAt: "2026-08-15T12:00:00Z"},
		},
		diskByUUID: map[string]domainDiskSnapshot{
			"cached-domain": {UsedGB: 1, TotalGB: 2},
		},
	}

	done := make(chan struct{})
	go func() {
		worker.run()
		close(done)
	}()

	// Let a few ticks hit the connect-failure branch, then stop the worker.
	time.Sleep(150 * time.Millisecond)
	worker.Stop()
	waitForWorkerStop(t, done)

	if names := worker.VMNames(); names != nil {
		t.Fatalf("expected no cached VMs after connect failures, got %v", names)
	}
	if len(worker.metadataByUUID) != 1 {
		t.Fatalf("connect failures cleared metadata cache: %+v", worker.metadataByUUID)
	}
	if len(worker.diskByUUID) != 1 {
		t.Fatalf("connect failures cleared disk cache: %+v", worker.diskByUUID)
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
