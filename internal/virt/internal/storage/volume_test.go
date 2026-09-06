package storage

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"libvirt.org/go/libvirt"
)

func newVolumeRemovalPool(t *testing.T) (*libvirt.Connect, *libvirt.StoragePool, string) {
	t.Helper()
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatalf("connect to libvirt test driver: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	name := strings.ReplaceAll(t.Name(), "/", "-")
	pool, err := conn.StoragePoolDefineXML(PoolDefinitionXML(name, t.TempDir()), 0)
	if err != nil {
		t.Fatalf("define test pool: %v", err)
	}
	t.Cleanup(func() {
		_ = pool.Destroy()
		_ = pool.Undefine()
		_ = pool.Free()
	})
	if err := pool.Create(0); err != nil {
		t.Fatalf("start test pool: %v", err)
	}
	return conn, pool, name
}

func createRemovalTestVolume(t *testing.T, pool *libvirt.StoragePool, name string) {
	t.Helper()
	xml := fmt.Sprintf(`<volume><name>%s</name><capacity unit='bytes'>4096</capacity><target><format type='raw'/></target></volume>`, name)
	volume, err := pool.StorageVolCreateXML(xml, 0)
	if err != nil {
		t.Fatalf("create test volume %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = volume.Delete(0)
		_ = volume.Free()
	})
}

func TestRemoveVolumesContinuesAfterMissingVolume(t *testing.T) {
	conn, pool, poolName := newVolumeRemovalPool(t)
	createRemovalTestVolume(t, pool, "seed.iso")
	if err := RemoveVolumes(conn, poolName, "missing-disk", "seed.iso"); err != nil {
		t.Fatalf("remove volumes: %v", err)
	}
	volume, err := pool.LookupStorageVolByName("seed.iso")
	if volume != nil {
		_ = volume.Free()
	}
	if !errors.Is(err, libvirt.ERR_NO_STORAGE_VOL) {
		t.Fatalf("seed lookup after removal = %v, want missing volume", err)
	}
}

func TestRemoveVolumesReportsLookupFailure(t *testing.T) {
	conn, pool, poolName := newVolumeRemovalPool(t)
	if err := pool.Destroy(); err != nil {
		t.Fatalf("stop test pool: %v", err)
	}
	err := RemoveVolumes(conn, poolName, "disk", "seed.iso")
	if !errors.Is(err, libvirt.ERR_OPERATION_INVALID) {
		t.Fatalf("remove from inactive pool = %v, want invalid operation", err)
	}
	for _, name := range []string{"disk", "seed.iso"} {
		if !strings.Contains(err.Error(), "lookup volume "+name) {
			t.Errorf("lookup failure for %s missing from error: %v", name, err)
		}
	}
}

func TestRemoveVolumesAttemptsEveryDeletion(t *testing.T) {
	_, pool, poolName := newVolumeRemovalPool(t)
	createRemovalTestVolume(t, pool, "disk")
	createRemovalTestVolume(t, pool, "seed.iso")
	// Simultaneous connections to test:///default share fixture state. A
	// read-only connection permits lookup but refuses each volume deletion.
	conn, err := libvirt.NewConnectReadOnly("test:///default")
	if err != nil {
		t.Fatalf("open read-only test connection: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	err = RemoveVolumes(conn, poolName, "disk", "seed.iso")
	if !errors.Is(err, libvirt.ERR_OPERATION_DENIED) {
		t.Fatalf("remove through read-only connection = %v, want denied operation", err)
	}
	for _, name := range []string{"disk", "seed.iso"} {
		if !strings.Contains(err.Error(), "delete volume "+name) {
			t.Errorf("deletion failure for %s missing from error: %v", name, err)
		}
	}
}
