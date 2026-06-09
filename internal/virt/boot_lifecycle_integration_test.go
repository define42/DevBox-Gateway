package virt

import (
	"errors"
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
	baseImagePath := ensureAccessibleBaseImageSourcePath(t, testBaseImageURL)
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })
	usePermissiveLibvirtVolumeMode(t)

	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}

	stageBootBaseImage(t, baseImagePath, filepath.Join(config.BaseImageDir(settings), testBaseImageName))
}

func existingBootBaseImagePath(t *testing.T) string {
	t.Helper()

	return ensureAccessibleBaseImageSourcePath(t, testBaseImageURL)
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

	if err := CopyAndResizeVolume(conn, poolName, vmName, sourceImage, 2*1024*1024); err != nil {
		t.Fatalf("CopyAndResizeVolume disk: %v", err)
	}
	if err := CreateUbuntuSeedISOToPool(conn, poolName, seedISO, "bootuser", "$6$hash", vmName); err != nil {
		t.Fatalf("CreateUbuntuSeedISOToPool: %v", err)
	}

	// VNC socket and serial PTY are both libvirt-managed; the gateway prepares no
	// console sockets.
	if err := StartVM(vmName, seedISO, poolName, vcpu, memoryMB); err != nil {
		t.Fatalf("StartVM: %v", err)
	}

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	assertUnownedVM(t, vmName)

	if err := RemoveVM(vmName, settings); err != nil {
		t.Fatalf("RemoveVM: %v", err)
	}

	waitForDomainRemoval(t, conn, vmName, bootLifecycleTimeout)
	assertMissingVolumes(t, pool, vmName, seedISO)
}

func TestBootNewVMRejectsExistingName(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	configureIsolatedBootStorage(t, settings)
	user := newBootTestUser(t, "recreateuser")
	shortName := "recreate-vm"

	vmName, err := BootNewVM(shortName, user, "", "", testBaseImageName, settings, 2, 4096)
	if err != nil {
		t.Fatalf("BootNewVM initial: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveVM(vmName, settings)
	})

	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)
	firstUUID := lookupDomainUUID(t, conn, vmName)

	// Creating again with the same name must be refused (no silent recreate) so
	// the existing VM is preserved; the user is expected to delete it first.
	if _, err := BootNewVM(shortName, user, "", "", testBaseImageName, settings, 4, 8192); !errors.Is(err, ErrVMAlreadyExists) {
		t.Fatalf("expected ErrVMAlreadyExists on duplicate create, got %v", err)
	}

	// The original VM must be untouched: same domain (UUID), still running, with
	// its original resources rather than the ones in the second request.
	if got := lookupDomainUUID(t, conn, vmName); got != firstUUID {
		t.Fatalf("existing VM domain UUID changed (was clobbered): was %q, now %q", firstUUID, got)
	}

	vms, err := ListVMs(user.GetName(), conn)
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	vm := requireListedVM(t, vms, vmName)
	if vm.State != "running" {
		t.Fatalf("expected existing VM to still be running, got %q", vm.State)
	}
	if vm.VCPU != 2 || vm.MemoryMiB != 4096 {
		t.Fatalf("expected existing VM resources unchanged (2 vcpu / 4096 MiB), got %d vcpu / %d MiB", vm.VCPU, vm.MemoryMiB)
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

	vmName, err := BootNewVM("metadata-vm", user, "", "", testBaseImageName, settings, 2, 4096)
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
	// The image library under this test's data root is empty, so resolving the
	// selected base image fails fast before any VM is created.
	vmName, err := BootNewVM("vm", user, "", "", testBaseImageName, settings, 2, 4096)
	if err == nil {
		t.Fatal("expected BootNewVM to fail with an empty base image library")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("expected base image resolution failure, got %v", err)
	}
	if !strings.HasPrefix(vmName, user.GetName()+"-") {
		t.Fatalf("expected VM name prefix %q, got %q", user.GetName()+"-", vmName)
	}
}

// TestBootNewVMNameUsesLoginUserNotGuestUser locks the VDI naming invariant: the
// name is always "<login-username>-<chosen-hostname>", taken from the session
// user and the vm_name field. The separately supplied guest account name
// (vm_username) must never leak into the VM name. It uses the same fast-fail
// (empty image library) path as the sibling test so no VM is actually booted.
func TestBootNewVMNameUsesLoginUserNotGuestUser(t *testing.T) {
	settings := newBootTestSettings(t)
	user := newBootTestUser(t, "loginuser")
	poolName := uniquePoolName("login-user-name-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	const chosenName = "web"
	const guestUsername = "differentguest"

	// Empty image library => BootNewVM fails fast at base image resolution, but
	// only after composing the VM name, which is what this test inspects.
	vmName, err := BootNewVM(chosenName, user, guestUsername, "", testBaseImageName, settings, 2, 4096)
	if err == nil {
		t.Fatal("expected BootNewVM to fail with an empty base image library")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Fatalf("expected base image resolution failure (proving the boot logic ran), got %v", err)
	}

	want := user.GetName() + "-" + chosenName
	if vmName != want {
		t.Fatalf("VM name must be <login-username>-<chosen-name>: want %q, got %q", want, vmName)
	}
	if strings.Contains(vmName, guestUsername) {
		t.Fatalf("guest username %q must not appear in VM name %q", guestUsername, vmName)
	}
}
