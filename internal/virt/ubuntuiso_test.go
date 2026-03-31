package virt

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"
)

const powerTestTimeout = 30 * time.Second

func TestSeedISOCreate(t *testing.T) {
	t.Run("requires user-data", func(t *testing.T) {

		_, err := CreateSeedISO(nil, &SeedMetaData{InstanceID: "vm"}, nil)
		if err == nil || !strings.Contains(err.Error(), "user-data is required") {
			t.Fatalf("expected missing user-data error, got %v", err)
		}
	})

	t.Run("requires meta-data", func(t *testing.T) {

		_, err := CreateSeedISO(&SeedUserData{Users: []SeedUser{}}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "meta-data is required") {
			t.Fatalf("expected missing meta-data error, got %v", err)
		}
	})

	t.Run("creates iso from yaml documents", func(t *testing.T) {

		data, err := CreateSeedISO(
			&SeedUserData{
				Users: []SeedUser{},
			},
			&SeedMetaData{
				InstanceID:    "vm",
				LocalHostname: "vm",
			},
			&SeedNetworkConfig{
				Network: SeedNetwork{
					Version: 2,
				},
			},
		)
		if err != nil {
			t.Fatalf("SeedISO.CreateSeedISO: %v", err)
		}
		if len(data) == 0 {
			t.Fatal("expected created iso to be non-empty")
		}
	})
}

func TestCreateUbuntuSeedISOToPool(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolPath := t.TempDir()
	settings := newInitVirtSettings(t, poolPath)
	poolName, _ := storagePoolConfig(settings)
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}
	defer func() {
		_ = pool.Free()
	}()

	const volumeName = "ubuntu-seed.iso"
	t.Cleanup(func() {
		_ = RemoveVolumes(conn, poolName, volumeName)
	})

	if err := CreateUbuntuSeedISOToPool(conn, poolName, volumeName, "alice", "$6$hash", "alice-devbox"); err != nil {
		t.Fatalf("CreateUbuntuSeedISOToPool: %v", err)
	}

	vol, err := pool.LookupStorageVolByName(volumeName)
	if err != nil {
		t.Fatalf("lookup seed iso volume: %v", err)
	}
	defer func() {
		_ = vol.Free()
	}()

	info, err := vol.GetInfo()
	if err != nil {
		t.Fatalf("get seed iso volume info: %v", err)
	}
	if info.Capacity == 0 {
		t.Fatal("expected created seed iso volume to have non-zero capacity")
	}
}

func waitForDomainActiveState(t *testing.T, name string, want bool, timeout time.Duration) {
	t.Helper()

	conn := newTestLibvirtConn(t)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		dom, err := conn.LookupDomainByName(name)
		if err == nil {
			active, activeErr := dom.IsActive()
			_ = dom.Free()
			if activeErr == nil && active == want {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("domain %s did not reach active=%t within %s", name, want, timeout)
}

func TestPowerLifecycleAndResourceGuards(t *testing.T) {
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.VIRT_SERIAL_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_SERIAL_SOCKET_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_VNC_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_VNC_SOCKET_DIR: %v", err)
	}

	user, err := types.NewUser("poweruser"+time.Now().Format("150405"), "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	vmName, err := BootNewVM("power-vm", user, settings, 2, 4096)
	if err != nil {
		t.Fatalf("BootNewVM: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveVM(vmName, settings)
	})

	waitForDomainActiveState(t, vmName, true, powerTestTimeout)

	if err := StartExistingVM(vmName); err != nil {
		t.Fatalf("StartExistingVM on active domain: %v", err)
	}

	if err := UpdateVMResources(vmName, 1, 4096); err == nil || !strings.Contains(err.Error(), "must be stopped") {
		t.Fatalf("expected running VM resource update to be rejected, got %v", err)
	}

	if err := ShutdownVM(vmName); err != nil {
		t.Fatalf("ShutdownVM: %v", err)
	}
	waitForDomainActiveState(t, vmName, false, powerTestTimeout)

	if err := ShutdownVM(vmName); err != nil {
		t.Fatalf("ShutdownVM on inactive domain: %v", err)
	}

	if err := RestartVM(vmName); err != nil {
		t.Fatalf("RestartVM on inactive domain: %v", err)
	}
	waitForDomainActiveState(t, vmName, true, powerTestTimeout)
}

func TestBootNewVMRejectsInvalidResources(t *testing.T) {
	user, err := types.NewUser("invaliduser", "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	settings := config.NewSettingType(false)

	if _, err := BootNewVM("bad-vm", user, settings, 0, 4096); err == nil {
		t.Fatal("expected invalid vcpu error")
	}
	if _, err := BootNewVM("bad-vm", user, settings, 2, 0); err == nil {
		t.Fatal("expected invalid memory error")
	}
}

func TestEnsureStoragePoolRejectsInvalidArguments(t *testing.T) {
	conn := newTestLibvirtConn(t)

	if _, err := ensureStoragePool(conn, "", t.TempDir()); err == nil {
		t.Fatal("expected empty pool name error")
	}
	if _, err := ensureStoragePool(conn, uniquePoolName("invalid-pool"), "."); err == nil {
		t.Fatal("expected empty pool path error")
	}
}

func TestStoragePoolConfigUsesImageDirFallback(t *testing.T) {
	settings := config.NewSettingType(false)
	imageDir := filepath.Join(t.TempDir(), "images")
	if err := settings.OverwriteForTestString(config.VDI_IMAGE_DIR, imageDir); err != nil {
		t.Fatalf("overwrite VDI_IMAGE_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_PATH, ""); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_PATH: %v", err)
	}

	_, gotPath := storagePoolConfig(settings)
	if gotPath != filepath.Clean(imageDir) {
		t.Fatalf("expected image dir fallback %q, got %q", filepath.Clean(imageDir), gotPath)
	}
}
