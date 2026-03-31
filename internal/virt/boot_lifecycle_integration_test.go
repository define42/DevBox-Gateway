package virt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"

	"libvirt.org/go/libvirt"
)

const bootLifecycleTimeout = 30 * time.Second

func newBootTestSettings(t *testing.T) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.VIRT_SERIAL_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_SERIAL_SOCKET_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_VNC_SOCKET_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite VIRT_VNC_SOCKET_DIR: %v", err)
	}
	return settings
}

func configureIsolatedBootStorage(t *testing.T, settings *config.SettingsType) {
	t.Helper()

	poolPath := t.TempDir()
	poolName := uniquePoolName("boot-lifecycle-pool")
	baseSettings := config.NewSettingType(false)
	baseImageURL, baseImagePath, err := baseImageURLAndPath(baseSettings)
	if err != nil {
		t.Fatalf("baseImageURLAndPath: %v", err)
	}
	if _, err := os.Stat(baseImagePath); err != nil {
		t.Skipf("skipping boot lifecycle coverage test; base image unavailable at %s: %v", baseImagePath, err)
	}
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	if err := settings.OverwriteForTestString(config.VDI_IMAGE_DIR, filepath.Dir(baseImagePath)); err != nil {
		t.Fatalf("overwrite VDI_IMAGE_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_PATH, poolPath); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_PATH: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, baseImageURL); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}
}

func existingBootBaseImagePath(t *testing.T) string {
	t.Helper()

	settings := config.NewSettingType(false)
	_, baseImagePath, err := baseImageURLAndPath(settings)
	if err != nil {
		t.Fatalf("baseImageURLAndPath: %v", err)
	}
	if _, err := os.Stat(baseImagePath); err != nil {
		t.Skipf("skipping boot lifecycle coverage test; base image unavailable at %s: %v", baseImagePath, err)
	}
	return baseImagePath
}

func newBootTestUser(t *testing.T, prefix string) *types.User {
	t.Helper()

	user, err := types.NewUser(prefix+time.Now().Format("150405"), "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}
	return user
}

func waitForDomainState(t *testing.T, conn *libvirt.Connect, name string, wantActive bool, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		dom, err := conn.LookupDomainByName(name)
		if err == nil {
			active, activeErr := dom.IsActive()
			_ = dom.Free()
			if activeErr == nil && active == wantActive {
				return
			}
			lastErr = activeErr
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("domain %s did not reach active=%t within %s: %v", name, wantActive, timeout, lastErr)
}

func waitForDomainRemoval(t *testing.T, conn *libvirt.Connect, name string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		dom, err := conn.LookupDomainByName(name)
		if err != nil {
			return
		}
		_ = dom.Free()
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("domain %s was not removed within %s", name, timeout)
}

func TestStartVMAndRemoveVMManageArtifacts(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	poolPath := t.TempDir()
	poolName := uniquePoolName("start-remove-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_PATH, poolPath); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_PATH: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}
	defer func() {
		_ = pool.Free()
	}()

	sourceImage := existingBootBaseImagePath(t)

	const (
		vcpu     = 1
		memoryMB = 4096
	)
	vmName := "startvm-lifecycle-" + time.Now().Format("150405")
	seedISO := vmName + "_seed.iso"

	serialPath := serialSocketPath(settings, vmName)
	vncPath := vncSocketPath(settings, vmName)

	if err := CopyAndResizeVolume(conn, poolName, vmName, sourceImage, 2*1024*1024); err != nil {
		t.Fatalf("CopyAndResizeVolume disk: %v", err)
	}
	if err := CreateUbuntuSeedISOToPool(conn, poolName, seedISO, "bootuser", "$6$hash", vmName); err != nil {
		t.Fatalf("CreateUbuntuSeedISOToPool: %v", err)
	}

	if err := os.WriteFile(serialPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale serial socket placeholder: %v", err)
	}
	if err := os.WriteFile(vncPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale vnc socket placeholder: %v", err)
	}

	if err := StartVM(vmName, seedISO, poolName, serialPath, vncPath, vcpu, memoryMB); err != nil {
		t.Fatalf("StartVM: %v", err)
	}

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	owned, err := UserOwnsVM(vmName, "bootuser")
	if err != nil {
		t.Fatalf("UserOwnsVM legacy owner: %v", err)
	}
	if !owned {
		t.Fatalf("expected legacy VM %q to resolve owner from seed ISO", vmName)
	}
	if info, err := os.Lstat(serialPath); err == nil && info.Mode().IsRegular() {
		t.Fatal("expected stale serial placeholder file to be replaced or removed before VM start")
	}
	if info, err := os.Lstat(vncPath); err == nil && info.Mode().IsRegular() {
		t.Fatal("expected stale VNC placeholder file to be replaced or removed before VM start")
	}

	if err := RemoveVM(vmName, settings); err != nil {
		t.Fatalf("RemoveVM: %v", err)
	}

	waitForDomainRemoval(t, conn, vmName, bootLifecycleTimeout)
	if _, err := pool.LookupStorageVolByName(vmName); err == nil {
		t.Fatal("expected VM disk volume to be removed")
	}
	if _, err := pool.LookupStorageVolByName(seedISO); err == nil {
		t.Fatal("expected seed ISO volume to be removed")
	}
}

func TestBootNewVMRecreatesExistingVM(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	configureIsolatedBootStorage(t, settings)
	user := newBootTestUser(t, "recreateuser")
	shortName := "recreate-vm"

	vmName, err := BootNewVM(shortName, user, settings, 2, 4096)
	if err != nil {
		t.Fatalf("BootNewVM initial: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveVM(vmName, settings)
	})

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)

	firstDomain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		t.Fatalf("lookup initial domain: %v", err)
	}
	firstUUID, err := firstDomain.GetUUIDString()
	_ = firstDomain.Free()
	if err != nil {
		t.Fatalf("get initial domain UUID: %v", err)
	}

	recreatedName, err := BootNewVM(shortName, user, settings, 4, 8192)
	if err != nil {
		t.Fatalf("BootNewVM recreate: %v", err)
	}
	if recreatedName != vmName {
		t.Fatalf("expected recreated VM name %q, got %q", vmName, recreatedName)
	}

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)

	recreatedDomain, err := conn.LookupDomainByName(vmName)
	if err != nil {
		t.Fatalf("lookup recreated domain: %v", err)
	}
	recreatedUUID, err := recreatedDomain.GetUUIDString()
	_ = recreatedDomain.Free()
	if err != nil {
		t.Fatalf("get recreated domain UUID: %v", err)
	}
	if recreatedUUID == firstUUID {
		t.Fatal("expected recreated VM to have a new domain UUID")
	}

	vms, err := ListVMs(user.GetName(), conn)
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}

	found := false
	for _, vm := range vms {
		if vm.Name != vmName {
			continue
		}
		found = true
		if vm.State != "running" {
			t.Fatalf("expected recreated VM to be running, got %q", vm.State)
		}
		if vm.VCPU != 4 {
			t.Fatalf("expected recreated VM vcpu 4, got %d", vm.VCPU)
		}
		if vm.MemoryMiB != 8192 {
			t.Fatalf("expected recreated VM memory 8192, got %d", vm.MemoryMiB)
		}
	}
	if !found {
		t.Fatalf("expected recreated VM %q in VM list", vmName)
	}
}

func TestBootNewVMPersistsOwnerMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	configureIsolatedBootStorage(t, settings)

	user, err := types.NewUser("meta-"+time.Now().Format("150405"), "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	vmName, err := BootNewVM("metadata-vm", user, settings, 2, 4096)
	if err != nil {
		t.Fatalf("BootNewVM: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveVM(vmName, settings)
	})

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)

	owned, err := UserOwnsVM(vmName, user.GetName())
	if err != nil {
		t.Fatalf("UserOwnsVM(owner): %v", err)
	}
	if !owned {
		t.Fatalf("expected %q to own %q", user.GetName(), vmName)
	}

	owned, err = UserOwnsVM(vmName, "meta")
	if err != nil {
		t.Fatalf("UserOwnsVM(prefix): %v", err)
	}
	if owned {
		t.Fatalf("did not expect prefix user %q to own %q", "meta", vmName)
	}

	metaVMs, err := ListVMs(user.GetName(), conn)
	if err != nil {
		t.Fatalf("ListVMs(owner): %v", err)
	}
	found := false
	for _, vm := range metaVMs {
		if vm.Name == vmName {
			found = true
			if vm.Owner != user.GetName() {
				t.Fatalf("expected owner %q, got %q", user.GetName(), vm.Owner)
			}
		}
	}
	if !found {
		t.Fatalf("expected VM %q in owner-scoped list", vmName)
	}

	prefixVMs, err := ListVMs("meta", conn)
	if err != nil {
		t.Fatalf("ListVMs(prefix): %v", err)
	}
	for _, vm := range prefixVMs {
		if vm.Name == vmName {
			t.Fatalf("did not expect prefix user list to include %q", vmName)
		}
	}
}

func TestBootNewVMFailsWithoutBaseImageSource(t *testing.T) {
	settings := newBootTestSettings(t)
	user := newBootTestUser(t, "missingbase")
	poolPath := t.TempDir()
	poolName := uniquePoolName("missing-base-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	if err := settings.OverwriteForTestString(config.VDI_IMAGE_DIR, poolPath); err != nil {
		t.Fatalf("overwrite VDI_IMAGE_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_PATH, poolPath); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_PATH: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "https://example.test/"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}

	vmName, err := BootNewVM("vm", user, settings, 2, 4096)
	if err == nil {
		t.Fatal("expected BootNewVM to fail without a valid base image URL")
	}
	if !strings.Contains(err.Error(), "Failed to ensure base image") {
		t.Fatalf("expected base image failure, got %v", err)
	}
	if !strings.HasPrefix(vmName, user.GetName()+"-") {
		t.Fatalf("expected VM name prefix %q, got %q", user.GetName()+"-", vmName)
	}
}
