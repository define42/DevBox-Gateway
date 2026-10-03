package virt

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"libvirt.org/go/libvirt"
)

func TestRemoveVMRetainsAuthorizationAfterStorageFailure(t *testing.T) {
	f := newDeletionFixture(t)
	if err := f.dom.SetAutostart(true); err != nil {
		t.Fatal(err)
	}
	if err := f.dom.Create(); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Destroy(); err != nil {
		t.Fatal(err)
	}

	if err := RemoveVM(f.name, f.settings); !errors.Is(err, libvirt.ERR_OPERATION_INVALID) {
		t.Fatalf("remove with inactive pool = %v, want storage failure", err)
	}
	assertDeletionRetryable(t, f)
	if active, err := f.dom.IsActive(); err != nil || active {
		t.Fatalf("deleting VM active = %v, error = %v", active, err)
	}
	if autostart, err := f.dom.GetAutostart(); err != nil || autostart {
		t.Fatalf("deleting VM autostart = %v, error = %v", autostart, err)
	}

	if err := f.pool.Create(0); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{f.name, f.name + "_seed.iso"} {
		vol, err := f.pool.LookupStorageVolByName(name)
		if err != nil {
			t.Fatalf("failed removal lost volume %s: %v", name, err)
		}
		_ = vol.Free()
	}
	if err := RemoveVM(f.name, f.settings); err != nil {
		t.Fatalf("retry removal after storage recovery: %v", err)
	}
	assertDeletionComplete(t, f)
	if err := RemoveVM(f.name, f.settings); err != nil {
		t.Fatalf("repeat completed removal: %v", err)
	}
}

func TestRemoveVMRetainsDefinitionAfterVolumesAreRemoved(t *testing.T) {
	f := newDeletionFixture(t)
	// A conflicting network models a reservation-cleanup failure after storage
	// cleanup has already succeeded. No host network is touched by this driver.
	network, err := f.conn.NetworkDefineXML("<network><name>devbox</name></network>")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = network.Undefine()
		_ = network.Free()
	})

	if err := RemoveVM(f.name, f.settings); err == nil || !strings.Contains(err.Error(), "release VM network identity") {
		t.Fatalf("remove with conflicting network = %v, want reservation failure", err)
	}
	assertDeletionRetryable(t, f)
	assertDeletionVolumesAbsent(t, f)

	if err := network.Undefine(); err != nil {
		t.Fatal(err)
	}
	if err := RemoveVM(f.name, f.settings); err != nil {
		t.Fatalf("retry removal with already removed volumes: %v", err)
	}
	assertDeletionComplete(t, f)
}

func TestDeletionMarkerBlocksUnknownStates(t *testing.T) {
	f := newDeletionFixture(t)
	if err := ensureVMNotDeleting(f.dom); err != nil {
		t.Fatalf("fresh domain rejected: %v", err)
	}
	if err := f.dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "<deletion>future-state</deletion>",
		domainDeletionMetadataPrefix, domainDeletionMetadataNamespace, libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
		t.Fatal(err)
	}
	if err := ensureVMNotDeleting(f.dom); !errors.Is(err, ErrVMDeletionPending) {
		t.Fatalf("unknown deletion marker = %v, want ErrVMDeletionPending", err)
	}
	if err := ensureExistingVMNotDeleting(f.conn, f.name); !errors.Is(err, ErrVMDeletionPending) {
		t.Fatalf("existing domain redefine guard = %v, want ErrVMDeletionPending", err)
	}
	if err := ensureExistingVMNotDeleting(f.conn, "deletion-missing-vm"); err != nil {
		t.Fatalf("new domain rejected: %v", err)
	}
}

func TestRemoveVMRequiresPersistentDeletionStateBeforeCleanup(t *testing.T) {
	f := newDeletionFixture(t)
	if err := f.dom.Create(); err != nil {
		t.Fatal(err)
	}
	// Transient domains cannot store the persistent retry marker. Refuse the
	// deletion before stopping the VM or touching its volumes.
	if err := f.dom.Undefine(); err != nil {
		t.Fatal(err)
	}
	if err := RemoveVM(f.name, f.settings); err == nil || !strings.Contains(err.Error(), "persist VM deletion state") {
		t.Fatalf("removal without persistent state = %v, want marker failure", err)
	}
	if active, err := f.dom.IsActive(); err != nil || !active {
		t.Fatalf("marker failure changed running VM: active = %v, error = %v", active, err)
	}
	for _, name := range []string{f.name, f.name + "_seed.iso"} {
		vol, err := f.pool.LookupStorageVolByName(name)
		if err != nil {
			t.Fatalf("marker failure removed volume %s: %v", name, err)
		}
		_ = vol.Free()
	}
}

type deletionFixture struct {
	conn     *libvirt.Connect
	pool     *libvirt.StoragePool
	dom      *libvirt.Domain
	settings *config.Settings
	name     string
	uuid     string
}

func newDeletionFixture(t *testing.T) deletionFixture {
	t.Helper()
	t.Setenv("LIBVIRT_URI", "test:///default")
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	poolName := "deletion-test-pool"
	pool, err := conn.StoragePoolDefineXML(fmt.Sprintf(
		"<pool type='dir'><name>%s</name><target><path>%s</path></target></pool>", poolName, t.TempDir()), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pool.Destroy()
		_ = pool.Undefine()
		_ = pool.Free()
	})
	if err := pool.Create(0); err != nil {
		t.Fatal(err)
	}
	name := "deletion-owner-desktop"
	for _, volumeName := range []string{name, name + "_seed.iso"} {
		vol, err := pool.StorageVolCreateXML("<volume><name>"+volumeName+
			"</name><capacity>4096</capacity><target><format type='raw'/></target></volume>", 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = vol.Free()
	}
	dom, err := conn.DomainDefineXML("<domain type='test'><name>" + name +
		"</name><memory>1024</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if active, _ := dom.IsActive(); active {
			_ = dom.Destroy()
		}
		_ = dom.Undefine()
		_ = dom.Free()
	})
	if err := setDomainOwnerMetadata(dom, "deletion-owner"); err != nil {
		t.Fatal(err)
	}
	uuid, err := dom.GetUUIDString()
	if err != nil {
		t.Fatal(err)
	}
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatal(err)
	}
	return deletionFixture{conn: conn, pool: pool, dom: dom, settings: settings, name: name, uuid: uuid}
}

func assertDeletionRetryable(t *testing.T, f deletionFixture) {
	t.Helper()
	if owned, err := UserOwnsVM(f.name, "deletion-owner"); err != nil || !owned {
		t.Fatalf("owner cannot retry removal: owned = %v, error = %v", owned, err)
	}
	if exists, err := PersistentVMExists(f.name); err != nil || !exists {
		t.Fatalf("administrator cannot retry removal: exists = %v, error = %v", exists, err)
	}
	// Use another connection to ensure retry state is persistent in libvirt,
	// rather than tied to the original request's domain handle.
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.Close() }()
	dom, err := conn.LookupDomainByName(f.name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dom.Free() }()
	if uuid, err := dom.GetUUIDString(); err != nil || uuid != f.uuid {
		t.Fatalf("domain identity changed: UUID = %q, error = %v", uuid, err)
	}
	if err := ensureVMNotDeleting(dom); !errors.Is(err, ErrVMDeletionPending) {
		t.Fatalf("partially removed VM can start: %v", err)
	}
}

func assertDeletionComplete(t *testing.T, f deletionFixture) {
	t.Helper()
	dom, err := f.conn.LookupDomainByName(f.name)
	if err == nil {
		_ = dom.Free()
		t.Fatal("successful removal left domain defined")
	}
	if !errors.Is(err, libvirt.ERR_NO_DOMAIN) {
		t.Fatalf("domain lookup after removal: %v", err)
	}
	assertDeletionVolumesAbsent(t, f)
}

func assertDeletionVolumesAbsent(t *testing.T, f deletionFixture) {
	t.Helper()
	for _, name := range []string{f.name, f.name + "_seed.iso"} {
		vol, err := f.pool.LookupStorageVolByName(name)
		if err == nil {
			_ = vol.Free()
			t.Errorf("removed VM still has volume %s", name)
		} else if !errors.Is(err, libvirt.ERR_NO_STORAGE_VOL) {
			t.Errorf("volume lookup %s: %v", name, err)
		}
	}
}
