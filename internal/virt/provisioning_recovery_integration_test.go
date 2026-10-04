package virt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"github.com/define42/devbox-gateway/internal/virt/internal/storage"
	"libvirt.org/go/libvirt"
)

func TestProvisioningCrashRecoveryLibvirt(t *testing.T) {
	for _, point := range []string{"intent before allocation", "reserved network", "partial disk", "both volumes"} {
		t.Run(point, func(t *testing.T) {
			fixture, intent := newPendingProvisioningFixture(t)
			stageProvisioningCrashPoint(t, fixture, intent, point)
			// No original stack/defer or connection is needed to recover. The
			// only operation state available is the persistent libvirt intent.
			restarted := newTestLibvirtConn(t)
			if err := recoverPendingProvisioningName(restarted, intent.Name); err != nil {
				t.Fatalf("recover after %s: %v", point, err)
			}
			assertNoProvisionedArtifacts(t, fixture)
			if err := recoverPendingProvisioningName(restarted, intent.Name); err != nil {
				t.Fatalf("repeat recovery: %v", err)
			}
		})
	}
}

func stageProvisioningCrashPoint(t *testing.T, fixture provisionTestFixture, intent provisioningIntent, point string) {
	t.Helper()
	if point == "intent before allocation" {
		return
	}
	if _, err := reserveNetworkIdentity(fixture.conn, intent.Name); err != nil {
		t.Fatal(err)
	}
	if point == "partial disk" || point == "both volumes" {
		createRecoveryTestVolume(t, fixture.pool, intent.Disk)
	}
	if point == "both volumes" {
		createRecoveryTestVolume(t, fixture.pool, intent.Seed)
	}
}

func TestProvisioningReadyBeforeStartSurvivesRecoveryLibvirt(t *testing.T) {
	fixture, intent := newPendingProvisioningFixture(t)
	spec := fixture.spec
	spec.provisioning = &intent
	var err error
	spec.network, err = reserveNetworkIdentity(fixture.conn, intent.Name)
	if err != nil {
		t.Fatal(err)
	}
	spec.backend, err = backendidentity.Generate(intent.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionBootVolumes(context.Background(), fixture.conn, fixture.settings, spec, nil); err != nil {
		t.Fatal(err)
	}
	doc, err := provisioningStartXML(spec.startConfig())
	if err != nil {
		t.Fatal(err)
	}
	dom, err := fixture.conn.DomainDefineXML(doc)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dom.Free() }()
	if _, err := applyNewDomainMetadata(dom, spec.startConfig()); err != nil {
		t.Fatal(err)
	}
	if err := validateDomainNetwork(fixture.conn, dom); err != nil {
		t.Fatal(err)
	}
	if err := markProvisioningReady(dom, &intent); err != nil {
		t.Fatal(err)
	}
	// This is the exact crash point after durable commit but before Create.
	assertReadyProvisioningPreserved(t, fixture, intent)
	// Later operator owner changes must not turn a completed operation back
	// into a recovery candidate or make startup fail over an old record.
	if err := setDomainOwnerMetadata(dom, "renamed-owner"); err != nil {
		t.Fatal(err)
	}
	assertReadyProvisioningPreserved(t, fixture, intent)
}

func TestProvisioningRecoveryProtectsOtherDiskUsersLibvirt(t *testing.T) {
	fixture, intent := newPendingProvisioningFixture(t)
	createRecoveryTestVolume(t, fixture.pool, intent.Disk)
	other := "recovery-unrelated-" + intent.UUID
	doc := "<domain type='kvm'><name>" + other + "</name><memory unit='MiB'>128</memory><vcpu>1</vcpu>" +
		"<os><type arch='x86_64' machine='q35'>hvm</type></os><devices><disk type='volume' device='disk'>" +
		"<driver name='qemu' type='qcow2'/><source pool='" + xmlValue(intent.Pool) + "' volume='" + xmlValue(intent.Disk) +
		"'/><target dev='vda' bus='virtio'/></disk></devices></domain>"
	dom, err := fixture.conn.DomainDefineXML(doc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dom.Undefine(); _ = dom.Free() })
	if err := recoverPendingProvisioningName(fixture.conn, intent.Name); err == nil || !strings.Contains(err.Error(), "referenced by domain") {
		t.Fatalf("shared disk recovery = %v, want refusal", err)
	}
	assertRecoveryDomainExists(t, fixture.conn, intent.Name, intent.UUID)
	volume, err := fixture.pool.LookupStorageVolByName(intent.Disk)
	if err != nil {
		t.Fatalf("recovery removed referenced disk: %v", err)
	}
	_ = volume.Free()
	if err := recoverPendingProvisioningName(fixture.conn, other); err != nil {
		t.Fatalf("unrelated domain without intent: %v", err)
	}
}

func TestProvisioningRecoveryRejectsPoolReplacementLibvirt(t *testing.T) {
	fixture, intent := newPendingProvisioningFixture(t)
	createRecoveryTestVolume(t, fixture.pool, intent.Disk)
	intent.PoolUUID = "00000000-0000-4000-8000-000000000001"
	dom, err := fixture.conn.LookupDomainByName(intent.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dom.Free() }()
	if err := setProvisioningState(dom, intent, provisioningPending); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingProvisioningName(fixture.conn, intent.Name); err == nil || !strings.Contains(err.Error(), "pool identity changed") {
		t.Fatalf("replaced pool recovery = %v, want refusal", err)
	}
	assertRecoveryDomainExists(t, fixture.conn, intent.Name, intent.UUID)
	volume, err := fixture.pool.LookupStorageVolByName(intent.Disk)
	if err != nil {
		t.Fatalf("recovery removed foreign pool's disk: %v", err)
	}
	_ = volume.Free()
}

func newPendingProvisioningFixture(t *testing.T) (provisionTestFixture, provisioningIntent) {
	t.Helper()
	fixture := newProvisionTestFixture(t)
	intent, err := planProvisioningIntent(fixture.conn, fixture.spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := definePendingProvisioning(fixture.conn, *intent); err != nil {
		t.Fatal(err)
	}
	dom, err := fixture.conn.LookupDomainByName(intent.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dom.Free() }()
	if _, err := verifyProvisioningDomain(dom, *intent); err != nil {
		t.Fatalf("libvirt round-trip lost intent identity: %v", err)
	}
	return fixture, *intent
}

func createRecoveryTestVolume(t *testing.T, pool *libvirt.StoragePool, name string) {
	t.Helper()
	volume, err := storage.CreateQCOW2Volume(nil, pool, name, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	_ = volume.Free()
}

func assertReadyProvisioningPreserved(t *testing.T, fixture provisionTestFixture, intent provisioningIntent) {
	t.Helper()
	if err := recoverPendingProvisioningName(newTestLibvirtConn(t), intent.Name); err != nil {
		t.Fatalf("recover committed VM: %v", err)
	}
	assertRecoveryDomainExists(t, fixture.conn, intent.Name, intent.UUID)
	assertProvisionedVolumes(t, fixture)
}

func assertRecoveryDomainExists(t *testing.T, conn *libvirt.Connect, name, expectedUUID string) {
	t.Helper()
	dom, err := conn.LookupDomainByName(name)
	if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
		t.Fatal("recovery removed a domain it must preserve")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dom.Free() }()
	id, err := dom.GetUUIDString()
	if err != nil || id != expectedUUID {
		t.Fatalf("recovery changed domain UUID: got %s, %v; want %s", id, err, expectedUUID)
	}
}
