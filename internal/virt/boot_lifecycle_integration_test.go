package virt

import (
	"io"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"
	"strings"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const bootLifecycleTimeout = 30 * time.Second

func newBootTestSettings(t *testing.T) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, newLibvirtAccessibleTempDir(t, "rdptlsgateway-root-")); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, uniquePoolName("boot-test-pool")); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	return settings
}

func configureIsolatedBootStorage(t *testing.T, settings *config.SettingsType) {
	t.Helper()

	rootDir := newLibvirtAccessibleTempDir(t, "rdptlsgateway-root-")
	poolName := uniquePoolName("boot-lifecycle-pool")
	baseSettings := config.NewSettingType(false)
	baseImageURL, _, err := baseImageURLAndPath(baseSettings)
	if err != nil {
		t.Fatalf("baseImageURLAndPath: %v", err)
	}
	baseImagePath := ensureAccessibleBaseImageSourcePath(t, baseImageURL)
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })
	usePermissiveLibvirtVolumeMode(t)

	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, baseImageURL); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}

	stageBootBaseImage(t, baseImagePath, filepath.Join(config.ImageDir(settings), filepath.Base(baseImagePath)))
}

func existingBootBaseImagePath(t *testing.T) string {
	t.Helper()

	settings := config.NewSettingType(false)
	baseImageURL, _, err := baseImageURLAndPath(settings)
	if err != nil {
		t.Fatalf("baseImageURLAndPath: %v", err)
	}
	return ensureAccessibleBaseImageSourcePath(t, baseImageURL)
}

func stageBootBaseImage(t *testing.T, sourcePath, targetPath string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("create staged base image dir: %v", err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		return
	}
	if err := os.Link(sourcePath, targetPath); err == nil {
		return
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open source base image %s: %v", sourcePath, err)
	}
	defer func() { _ = sourceFile.Close() }()

	targetFile, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("create staged base image %s: %v", targetPath, err)
	}
	defer func() { _ = targetFile.Close() }()

	if _, err := io.Copy(targetFile, sourceFile); err != nil {
		t.Fatalf("copy base image into test root: %v", err)
	}
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

func assertUnownedVM(t *testing.T, vmName string) {
	t.Helper()

	owner, hasOwner, err := VMOwner(vmName)
	if err != nil {
		t.Fatalf("VMOwner without metadata: %v", err)
	}
	if hasOwner || owner != "" {
		t.Fatalf("expected StartVM without metadata owner to report none, got owner=%q hasOwner=%v", owner, hasOwner)
	}
	owned, err := UserOwnsVM(vmName, "bootuser")
	if err != nil {
		t.Fatalf("UserOwnsVM without metadata: %v", err)
	}
	if owned {
		t.Fatalf("did not expect %q to own StartVM-created VM %q without metadata", "bootuser", vmName)
	}
}

func assertSocketPlaceholderRemoved(t *testing.T, path, label string) {
	t.Helper()

	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		t.Fatalf("expected stale %s placeholder file to be replaced or removed before VM start", label)
	}
}

func assertMissingVolumes(t *testing.T, pool *libvirt.StoragePool, volumeNames ...string) {
	t.Helper()

	for _, volumeName := range volumeNames {
		if _, err := pool.LookupStorageVolByName(volumeName); err == nil {
			t.Fatalf("expected volume %s to be removed", volumeName)
		}
	}
}

func lookupDomainUUID(t *testing.T, conn *libvirt.Connect, vmName string) string {
	t.Helper()

	dom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		t.Fatalf("lookup domain %s: %v", vmName, err)
	}
	defer func() { _ = dom.Free() }()

	uuid, err := dom.GetUUIDString()
	if err != nil {
		t.Fatalf("get domain UUID for %s: %v", vmName, err)
	}
	return uuid
}

func requireListedVM(t *testing.T, vms []VMInfo, vmName string) VMInfo {
	t.Helper()

	for _, vm := range vms {
		if vm.Name == vmName {
			return vm
		}
	}
	t.Fatalf("expected VM %q in VM list", vmName)
	return VMInfo{}
}

func assertListedVMOwner(t *testing.T, vms []VMInfo, vmName, owner string) {
	t.Helper()

	vm := requireListedVM(t, vms, vmName)
	if vm.Owner != owner {
		t.Fatalf("expected owner %q, got %q", owner, vm.Owner)
	}
}

func assertListExcludesVM(t *testing.T, vms []VMInfo, vmName string) {
	t.Helper()

	for _, vm := range vms {
		if vm.Name == vmName {
			t.Fatalf("did not expect VM list to include %q", vmName)
		}
	}
}

func writeStaleSocketPlaceholders(t *testing.T, serialPath, vncPath string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(serialPath), 0o755); err != nil {
		t.Fatalf("create stale serial socket dir: %v", err)
	}
	if err := os.Chmod(filepath.Dir(serialPath), 0o777); err != nil {
		t.Fatalf("chmod stale serial socket dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(vncPath), 0o755); err != nil {
		t.Fatalf("create stale vnc socket dir: %v", err)
	}
	if err := os.Chmod(filepath.Dir(vncPath), 0o777); err != nil {
		t.Fatalf("chmod stale vnc socket dir: %v", err)
	}
	if err := os.WriteFile(serialPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale serial socket placeholder: %v", err)
	}
	if err := os.WriteFile(vncPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("write stale vnc socket placeholder: %v", err)
	}
}

func TestStartVMAndRemoveVMManageArtifacts(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	poolName := uniquePoolName("start-remove-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })
	usePermissiveLibvirtVolumeMode(t)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	poolPath := config.VirtStoragePoolPath(settings)

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

	writeStaleSocketPlaceholders(t, serialPath, vncPath)

	if err := StartVM(vmName, seedISO, poolName, serialPath, vncPath, vcpu, memoryMB); err != nil {
		t.Fatalf("StartVM: %v", err)
	}

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	assertUnownedVM(t, vmName)
	assertSocketPlaceholderRemoved(t, serialPath, "serial")
	assertSocketPlaceholderRemoved(t, vncPath, "VNC")

	if err := RemoveVM(vmName, settings); err != nil {
		t.Fatalf("RemoveVM: %v", err)
	}

	waitForDomainRemoval(t, conn, vmName, bootLifecycleTimeout)
	assertMissingVolumes(t, pool, vmName, seedISO)
}

func TestBootNewVMRecreatesExistingVM(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	configureIsolatedBootStorage(t, settings)
	user := newBootTestUser(t, "recreateuser")
	shortName := "recreate-vm"

	vmName, err := BootNewVM(shortName, user, "", "", settings, 2, 4096)
	if err != nil {
		t.Fatalf("BootNewVM initial: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveVM(vmName, settings)
	})

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	firstUUID := lookupDomainUUID(t, conn, vmName)

	recreatedName, err := BootNewVM(shortName, user, "", "", settings, 4, 8192)
	if err != nil {
		t.Fatalf("BootNewVM recreate: %v", err)
	}
	if recreatedName != vmName {
		t.Fatalf("expected recreated VM name %q, got %q", vmName, recreatedName)
	}

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	recreatedUUID := lookupDomainUUID(t, conn, vmName)
	if recreatedUUID == firstUUID {
		t.Fatal("expected recreated VM to have a new domain UUID")
	}

	vms, err := ListVMs(user.GetName(), conn)
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	vm := requireListedVM(t, vms, vmName)
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

func TestBootNewVMPersistsOwnerMetadata(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	configureIsolatedBootStorage(t, settings)

	user, err := types.NewUser("meta-"+time.Now().Format("150405"), "dogood")
	if err != nil {
		t.Fatalf("new user: %v", err)
	}

	vmName, err := BootNewVM("metadata-vm", user, "", "", settings, 2, 4096)
	if err != nil {
		t.Fatalf("BootNewVM: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveVM(vmName, settings)
	})

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	owner, hasOwner, err := VMOwner(vmName)
	if err != nil {
		t.Fatalf("VMOwner(owner): %v", err)
	}
	if !hasOwner || owner != user.GetName() {
		t.Fatalf("expected owner %q, got owner=%q hasOwner=%v", user.GetName(), owner, hasOwner)
	}

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
	assertListedVMOwner(t, metaVMs, vmName, user.GetName())

	prefixVMs, err := ListVMs("meta", conn)
	if err != nil {
		t.Fatalf("ListVMs(prefix): %v", err)
	}
	assertListExcludesVM(t, prefixVMs, vmName)
}

func TestBootNewVMFailsWithoutBaseImageSource(t *testing.T) {
	settings := newBootTestSettings(t)
	user := newBootTestUser(t, "missingbase")
	poolName := uniquePoolName("missing-base-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "https://example.test/"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}

	vmName, err := BootNewVM("vm", user, "", "", settings, 2, 4096)
	if err == nil {
		t.Fatal("expected BootNewVM to fail without a valid base image URL")
	}
	if !strings.Contains(err.Error(), "failed to ensure base image") {
		t.Fatalf("expected base image failure, got %v", err)
	}
	if !strings.HasPrefix(vmName, user.GetName()+"-") {
		t.Fatalf("expected VM name prefix %q, got %q", user.GetName()+"-", vmName)
	}
}
