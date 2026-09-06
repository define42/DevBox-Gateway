package virt

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"libvirt.org/go/libvirt"
)

func TestBootNewVMRollsBackStartFailure(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	if err := fixture.settings.OverwriteForTestInt(config.VM_VCPU_COUNT, 1048576); err != nil {
		t.Fatal(err)
	}

	_, err := BootNewVM(fixture.request, fixture.settings)
	if err == nil || !strings.Contains(err.Error(), "failed to start vm") {
		t.Fatalf("expected domain start failure, got %v", err)
	}
	assertNoProvisionedArtifacts(t, fixture)
}

func TestProvisionAndStartVMRollsBackCopyFailure(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	// Model the image being removed after validation, before its upload opens it.
	if err := os.Remove(fixture.spec.baseImagePath); err != nil {
		t.Fatal(err)
	}
	unlock := vmNameLocks.Lock(fixture.spec.vmName)
	defer unlock()

	err := provisionAndStartVM(fixture.conn, fixture.settings, fixture.spec, nil)
	if err == nil || !strings.Contains(err.Error(), "open source image") {
		t.Fatalf("expected disk upload failure after volume creation, got %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("disk upload error lost its source: %v", err)
	}
	assertNoProvisionedArtifacts(t, fixture)
}

func TestBootNewVMRollsBackSeedFailure(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	// The ISO writer requires a temporary directory; disk upload does not.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	diskCopied := false
	_, err := BootNewVMWithProgress(fixture.request, fixture.settings, func(copied, total int64) {
		diskCopied = total > 0 && copied == total
	})
	if err == nil || !strings.Contains(err.Error(), "failed to create seed iso") {
		t.Fatalf("expected seed creation failure, got %v", err)
	}
	if !diskCopied {
		t.Fatal("seed failure occurred before the disk upload completed")
	}
	assertNoProvisionedArtifacts(t, fixture)
}

func TestBootNewVMReportsRollbackFailure(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	poolStopped := false
	t.Cleanup(func() {
		if poolStopped {
			if err := fixture.pool.Create(0); err != nil {
				t.Errorf("reactivate pool for cleanup: %v", err)
			}
		}
	})
	var stopErr error
	_, err := BootNewVMWithProgress(fixture.request, fixture.settings, func(copied, total int64) {
		if total > 0 && copied == total {
			stopErr = fixture.pool.Destroy()
			poolStopped = stopErr == nil
		}
	})
	if stopErr != nil || !poolStopped {
		t.Fatalf("failed to stop pool after disk upload: %v", stopErr)
	}
	if !errors.Is(err, libvirt.ERR_OPERATION_INVALID) {
		t.Fatalf("expected inactive-pool error, got %v", err)
	}
	for _, detail := range []string{"failed to copy and resize base image", "get volume info", "rollback"} {
		if !strings.Contains(err.Error(), detail) {
			t.Errorf("provisioning error omits %q: %v", detail, err)
		}
	}
}

func TestBootNewVMPreservesSuccessfulArtifacts(t *testing.T) {
	fixture := newProvisionTestFixture(t)
	name, err := BootNewVM(fixture.request, fixture.settings)
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	uuid := lookupDomainUUID(t, fixture.conn, name)
	assertProvisionedVolumes(t, fixture)

	if _, err := BootNewVM(fixture.request, fixture.settings); !errors.Is(err, ErrVMAlreadyExists) {
		t.Fatalf("duplicate create error = %v, want ErrVMAlreadyExists", err)
	}
	if got := lookupDomainUUID(t, fixture.conn, name); got != uuid {
		t.Fatalf("duplicate create changed domain UUID: got %q, want %q", got, uuid)
	}
	assertProvisionedVolumes(t, fixture)
}

type provisionTestFixture struct {
	settings *config.Settings
	conn     *libvirt.Connect
	pool     *libvirt.StoragePool
	request  VMCreateRequest
	spec     vmProvisionSpec
}

func newProvisionTestFixture(t *testing.T) provisionTestFixture {
	t.Helper()
	settings := newBootTestSettings(t)
	for key, value := range map[string]int{config.VM_DISK_SIZE_GB: 1, config.VM_VCPU_COUNT: 1, config.VM_MEMORY_MIB: 128} {
		if err := settings.OverwriteForTestInt(key, value); err != nil {
			t.Fatal(err)
		}
	}
	baseImage := seedDummyBaseImage(t, settings)
	basePath := filepath.Join(config.BaseImageDir(settings), baseImage)
	if output, err := exec.Command("qemu-img", "create", "-f", "qcow2", basePath, "1M").CombinedOutput(); err != nil {
		t.Fatalf("create tiny QCOW2 fixture: %v: %s", err, output)
	}
	owner, err := identity.New("provisiontest")
	if err != nil {
		t.Fatal(err)
	}
	request := VMCreateRequest{
		Name: uniquePoolName("rollback"), Owner: owner,
		GuestUsername: "guest", PasswordHash: testGuestPasswordHash, BaseImage: baseImage,
	}
	spec, err := prepareVMCreation(request, settings)
	if err != nil {
		t.Fatal(err)
	}
	conn := newTestLibvirtConn(t)
	t.Cleanup(func() { cleanupStoragePool(t, spec.poolName) })
	pool, err := ensureStoragePool(conn, spec.poolName, spec.poolPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = DestroyExistingDomain(conn, spec.vmName)
		_ = RemoveVolumes(conn, spec.poolName, spec.vmName, spec.seedISO)
		_ = pool.Free()
	})
	return provisionTestFixture{settings: settings, conn: conn, pool: pool, request: request, spec: spec}
}

func assertNoProvisionedArtifacts(t *testing.T, fixture provisionTestFixture) {
	t.Helper()
	dom, err := fixture.conn.LookupDomainByName(fixture.spec.vmName)
	if err == nil {
		_ = dom.Free()
		t.Error("failed provisioning left a domain")
	} else if !errors.Is(err, libvirt.ERR_NO_DOMAIN) {
		t.Errorf("domain lookup error = %v, want ERR_NO_DOMAIN", err)
	}
	for _, name := range []string{fixture.spec.vmName, fixture.spec.seedISO} {
		vol, err := fixture.pool.LookupStorageVolByName(name)
		if err == nil {
			_ = vol.Free()
			t.Errorf("failed provisioning left volume %s", name)
		} else if !errors.Is(err, libvirt.ERR_NO_STORAGE_VOL) {
			t.Errorf("volume %s lookup error = %v, want ERR_NO_STORAGE_VOL", name, err)
		}
	}
}

func assertProvisionedVolumes(t *testing.T, fixture provisionTestFixture) {
	t.Helper()
	for _, name := range []string{fixture.spec.vmName, fixture.spec.seedISO} {
		vol, err := fixture.pool.LookupStorageVolByName(name)
		if err != nil {
			t.Fatalf("successful VM lost volume %s: %v", name, err)
		}
		_ = vol.Free()
	}
}
