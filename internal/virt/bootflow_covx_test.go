package virt

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"

	"libvirt.org/go/libvirt"
)

func vbtcovNewUser(t *testing.T, name string) *identity.User {
	t.Helper()

	user, err := identity.New(name)
	if err != nil {
		t.Fatalf("new user %s: %v", name, err)
	}
	return user
}

// vbtcovSettingsWithDummyImage returns settings with an isolated data root, a
// unique storage pool name, and a tiny QCOW2-header base image; it returns the
// settings, the data root, and the seeded image name.
func vbtcovSettingsWithDummyImage(t *testing.T) (*config.Settings, string, string) {
	t.Helper()

	rootDir := t.TempDir()
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, uniquePoolName("cvbt-flow-pool")); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	imageName := seedDummyBaseImage(t, settings)
	return settings, rootDir, imageName
}

// vbtcovBlockPoolPathWithFile occupies the settings' storage pool path with a
// regular file so ensureStoragePool fails at MkdirAll, before any libvirt
// domain work.
func vbtcovBlockPoolPathWithFile(t *testing.T, settings *config.Settings) {
	t.Helper()

	poolPath := config.VirtStoragePoolPath(settings)
	if err := os.WriteFile(poolPath, []byte("blocker"), 0o644); err != nil {
		t.Fatalf("write blocker file %s: %v", poolPath, err)
	}
}

func TestVbtcovStartVMRejectsInvalidDomainName(t *testing.T) {
	// A '/' in the domain name is rejected while libvirt parses the XML, before
	// any capability checks, so this fails identically with and without KVM and
	// never defines a domain.
	name := fmt.Sprintf("cvbt/invalid-%d", time.Now().UnixNano())
	err := StartVM(VMStartConfig{
		Name:            name,
		SeedISO:         "cvbt-seed.iso",
		StoragePoolName: "cvbt-unused-pool",
		VCPU:            1,
		MemoryMiB:       512,
	})
	vbtcovRequireErrContains(t, err, "cannot contain", "StartVM with slash in domain name")
}

func TestVbtcovBootNewVMEarlyValidation(t *testing.T) {
	user := vbtcovNewUser(t, "cvbtvaliduser")

	t.Run("nil owner", func(t *testing.T) {
		_, err := BootNewVM(VMCreateRequest{Name: "vm", PasswordHash: testGuestPasswordHash, BaseImage: "img.img"}, nil)
		vbtcovRequireErrContains(t, err, "vm owner is required", "BootNewVM without owner")
	})

	t.Run("invalid hostname", func(t *testing.T) {
		_, err := BootNewVM(VMCreateRequest{Name: "Bad_Name!", Owner: user, PasswordHash: testGuestPasswordHash, BaseImage: "img.img"}, nil)
		vbtcovRequireErrContains(t, err, "vm name", "BootNewVM with invalid hostname")
	})

	t.Run("missing guest password hash", func(t *testing.T) {
		_, err := BootNewVM(VMCreateRequest{Name: "goodname", Owner: user, BaseImage: "img.img"}, nil)
		vbtcovRequireErrContains(t, err, "guest password hash is required", "BootNewVM without guest password hash")
	})

	t.Run("cleartext guest password rejected", func(t *testing.T) {
		_, err := BootNewVM(VMCreateRequest{Name: "goodname", Owner: user, PasswordHash: "not-a-hash", BaseImage: "img.img"}, nil)
		vbtcovRequireErrContains(t, err, "sha512_crypt", "BootNewVM with cleartext guest password")
	})
}

func TestVbtcovBootNewVMStoragePoolFailure(t *testing.T) {
	settings, _, imageName := vbtcovSettingsWithDummyImage(t)
	vbtcovBlockPoolPathWithFile(t, settings)
	user := vbtcovNewUser(t, "cvbtpoolfailuser")

	// All request validation and base-image resolution succeed; the boot then
	// fails while ensuring the storage pool, before any domain is defined.
	_, err := BootNewVM(VMCreateRequest{Name: "poolfail", Owner: user, PasswordHash: testGuestPasswordHash, BaseImage: imageName}, settings)
	vbtcovRequireErrContains(t, err, "failed to ensure storage pool", "BootNewVM with file-blocked pool path")
}

func TestVbtcovRemoveVMMissingPool(t *testing.T) {
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, uniquePoolName("cvbt-rm-pool")); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}

	name := fmt.Sprintf("cvbt-missing-vm-%d", time.Now().UnixNano())
	err := RemoveVM(name, settings)
	vbtcovRequireErrContains(t, err, "lookup storage pool", "RemoveVM with missing storage pool")
}

func vbtcovTransientDomainXML(name string) string {
	return fmt.Sprintf(`<domain type='qemu'>
  <name>%s</name>
  <memory unit='MiB'>32</memory>
  <os><type arch='x86_64'>hvm</type></os>
</domain>`, name)
}

func TestVbtcovDestroyExistingDomainTransient(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := fmt.Sprintf("cvbt-transient-%d", time.Now().UnixNano())

	dom, err := conn.DomainCreateXML(vbtcovTransientDomainXML(name), 0)
	if err != nil {
		t.Fatalf("create transient domain %s: %v", name, err)
	}
	defer func() { _ = dom.Free() }()
	t.Cleanup(func() {
		if leftover, err := conn.LookupDomainByName(name); err == nil {
			_ = leftover.Destroy()
			_ = leftover.Free()
		}
	})

	// Destroying a transient domain removes it entirely, so the subsequent
	// Undefine must fail — covering the undefine error branch.
	err = DestroyExistingDomain(conn, name)
	vbtcovRequireErrContains(t, err, "Domain not found", "DestroyExistingDomain on transient domain")

	if _, err := conn.LookupDomainByName(name); err == nil {
		t.Fatalf("expected transient domain %s to be gone", name)
	}
}

func vbtcovLimitSettings(t *testing.T, limit int) *config.Settings {
	t.Helper()

	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestInt(config.MAX_VDI_PER_USER, limit); err != nil {
		t.Fatalf("overwrite MAX_VDI_PER_USER: %v", err)
	}
	return settings
}

func TestVbtcovReserveUserVMSlotDisabledLimit(t *testing.T) {
	conn := newTestLibvirtConn(t)

	release, err := reserveUserVMSlot(conn, vbtcovLimitSettings(t, 0), "cvbt-nolimit-user")
	if err != nil {
		t.Fatalf("reserveUserVMSlot with disabled limit: %v", err)
	}
	release()
}

func TestVbtcovReserveUserVMSlotCountFailure(t *testing.T) {
	conn := vbtcovClosedConn(t)

	_, err := reserveUserVMSlot(conn, vbtcovLimitSettings(t, 1), "cvbt-count-user")
	vbtcovRequireErrContains(t, err, "count vms owned by", "reserveUserVMSlot on closed connection")
}

func TestVbtcovReleaseUserVMSlotDecrement(t *testing.T) {
	conn := newTestLibvirtConn(t)
	settings := vbtcovLimitSettings(t, 5)
	owner := fmt.Sprintf("cvbt-slot-user-%d", time.Now().UnixNano())

	releaseFirst, err := reserveUserVMSlot(conn, settings, owner)
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	releaseSecond, err := reserveUserVMSlot(conn, settings, owner)
	if err != nil {
		releaseFirst()
		t.Fatalf("second reservation: %v", err)
	}

	// Two in-flight reservations: the first release takes the decrement branch,
	// the second one deletes the entry.
	releaseFirst()
	releaseSecond()

	releaseThird, err := reserveUserVMSlot(conn, settings, owner)
	if err != nil {
		t.Fatalf("reservation after releases: %v", err)
	}
	releaseThird()
}

func TestVbtcovCountDomainsOwnedByListFailure(t *testing.T) {
	_, err := countDomainsOwnedBy(vbtcovClosedConn(t), "cvbt-any-user")
	vbtcovRequireErrContains(t, err, "list domains", "countDomainsOwnedBy on closed connection")
}

func TestVbtcovEnsureVMNameAvailableLookupFailure(t *testing.T) {
	err := ensureVMNameAvailable(vbtcovClosedConn(t), "cvbt-any-vm")
	vbtcovRequireErrContains(t, err, "lookup existing domain", "ensureVMNameAvailable on closed connection")
}

func TestVbtcovResolveGuestCredentials(t *testing.T) {
	user := vbtcovNewUser(t, "cvbtcreduser")

	t.Run("missing password hash", func(t *testing.T) {
		_, _, err := resolveGuestCredentials(user, "guest", "")
		vbtcovRequireErrContains(t, err, "guest password hash is required", "resolveGuestCredentials without password hash")
	})

	t.Run("cleartext password rejected", func(t *testing.T) {
		_, _, err := resolveGuestCredentials(user, "guest", "GuestPass1!")
		vbtcovRequireErrContains(t, err, "sha512_crypt", "resolveGuestCredentials with cleartext password")
	})

	t.Run("blank guest username falls back to owner", func(t *testing.T) {
		name, hash, err := resolveGuestCredentials(user, "   ", testGuestPasswordHash)
		if err != nil {
			t.Fatalf("resolveGuestCredentials: %v", err)
		}
		if name != user.Name {
			t.Fatalf("guest username = %q, want owner %q", name, user.Name)
		}
		if hash != testGuestPasswordHash {
			t.Fatalf("expected the pre-computed hash to pass through unchanged, got %q", hash)
		}
	})

	t.Run("explicit guest username preserved", func(t *testing.T) {
		name, _, err := resolveGuestCredentials(user, "cvbtguest", testGuestPasswordHash)
		if err != nil {
			t.Fatalf("resolveGuestCredentials: %v", err)
		}
		if name != "cvbtguest" {
			t.Fatalf("guest username = %q, want %q", name, "cvbtguest")
		}
	})
}

func TestVbtcovInitStoragePoolFailure(t *testing.T) {
	settings, _, _ := vbtcovSettingsWithDummyImage(t)
	vbtcovBlockPoolPathWithFile(t, settings)

	err := Init(settings)
	vbtcovRequireErrContains(t, err, "failed to ensure storage pool", "Init with file-blocked pool path")
}

func TestVbtcovEnsureBootStoragePoolFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)

	err := ensureBootStoragePool(conn, uniquePoolName("cvbt-bootpool"), vbtcovBlockedDirPath(t))
	vbtcovRequireErrContains(t, err, "failed to ensure storage pool", "ensureBootStoragePool with file-blocked path")
}

func TestVbtcovProvisionBootVolumesCopyFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	source := vbtcovWriteTinyFile(t, "base.img")

	err := provisionBootVolumes(conn, nil, vmProvisionSpec{
		poolName:      uniquePoolName("cvbt-nopool"),
		vmName:        "cvbt-vm",
		seedISO:       "cvbt-vm_seed.iso",
		hostname:      "host",
		guestUsername: "guest",
		passwordHash:  "$6$hash",
		baseImagePath: source,
	}, nil)
	vbtcovRequireErrContains(t, err, "failed to copy and resize base image", "provisionBootVolumes into missing pool")
}

func TestVbtcovProvisionBootVolumesSeedISOFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-provision-pool")

	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestInt(config.VM_DISK_SIZE_GB, 1); err != nil {
		t.Fatalf("overwrite VM_DISK_SIZE_GB: %v", err)
	}

	vmName := fmt.Sprintf("cvbt-provision-%d", time.Now().UnixNano())
	seedISO := vmName + "_seed.iso"
	t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, vmName, seedISO) })

	// Occupy the seed ISO name so the disk copy succeeds but the seed ISO
	// creation fails on the duplicate volume.
	vol, err := createQCOW2Volume(nil, pool, seedISO, vbtcovTinyCapacity)
	if err != nil {
		t.Fatalf("create conflicting seed volume: %v", err)
	}
	_ = vol.Free()

	source := vbtcovWriteTinyFile(t, "base.img")
	err = provisionBootVolumes(conn, settings, vmProvisionSpec{
		poolName:      poolName,
		vmName:        vmName,
		seedISO:       seedISO,
		hostname:      "host",
		guestUsername: "guest",
		passwordHash:  "$6$hash",
		baseImagePath: source,
	}, nil)
	vbtcovRequireErrContains(t, err, "failed to create seed iso", "provisionBootVolumes with occupied seed ISO name")
}

func TestVbtcovEnsureBootStoragePoolAndResetArtifactsSucceed(t *testing.T) {
	conn := newTestLibvirtConn(t)
	_, poolName, poolPath := vbtcovEnsureTestPool(t, conn, "cvbt-bootok-pool")

	if err := ensureBootStoragePool(conn, poolName, poolPath); err != nil {
		t.Fatalf("ensureBootStoragePool on existing pool: %v", err)
	}
	if err := resetExistingVMArtifacts(conn, poolName, "cvbt-none", "cvbt-none_seed.iso"); err != nil {
		t.Fatalf("resetExistingVMArtifacts with nothing to clean: %v", err)
	}
}

func TestVbtcovProvisionBootVolumesSucceeds(t *testing.T) {
	conn := newTestLibvirtConn(t)
	pool, poolName, _ := vbtcovEnsureTestPool(t, conn, "cvbt-provok-pool")

	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestInt(config.VM_DISK_SIZE_GB, 1); err != nil {
		t.Fatalf("overwrite VM_DISK_SIZE_GB: %v", err)
	}

	vmName := fmt.Sprintf("cvbt-provok-%d", time.Now().UnixNano())
	seedISO := vmName + "_seed.iso"
	t.Cleanup(func() { _ = RemoveVolumes(conn, poolName, vmName, seedISO) })

	source := vbtcovWriteTinyFile(t, "base.img")
	if err := provisionBootVolumes(conn, settings, vmProvisionSpec{
		poolName:      poolName,
		vmName:        vmName,
		seedISO:       seedISO,
		hostname:      "cvbt-host",
		guestUsername: "cvbtguest",
		passwordHash:  "$6$hash",
		baseImagePath: source,
	}, nil); err != nil {
		t.Fatalf("provisionBootVolumes: %v", err)
	}

	for _, volumeName := range []string{vmName, seedISO} {
		vol, err := pool.LookupStorageVolByName(volumeName)
		if err != nil {
			t.Fatalf("expected volume %s to exist: %v", volumeName, err)
		}
		_ = vol.Free()
	}
}

func TestVbtcovResetExistingVMArtifactsMissingPool(t *testing.T) {
	conn := newTestLibvirtConn(t)

	err := resetExistingVMArtifacts(conn, uniquePoolName("cvbt-nopool"), "cvbt-novm", "cvbt-noiso")
	vbtcovRequireErrContains(t, err, "failed to remove existing volumes", "resetExistingVMArtifacts with missing pool")
}

func TestVbtcovEnsureDefaultNetworkLookupFailure(t *testing.T) {
	// A closed connection fails the network lookup with an error that is not
	// ERR_NO_NETWORK, so the define fallback (which would touch the shared
	// 'default' network) is never reached.
	err := ensureDefaultNetwork(vbtcovClosedConn(t))
	vbtcovRequireErrContains(t, err, "lookup network", "ensureDefaultNetwork on closed connection")
}

func vbtcovIsolatedNetworkXML(name, bridge string) string {
	return fmt.Sprintf(`<network>
  <name>%s</name>
  <bridge name='%s'/>
</network>`, name, bridge)
}

// vbtcovDefineNetwork defines (but does not start) an isolated test network and
// registers tolerant cleanup that destroys and undefines it.
func vbtcovDefineNetwork(t *testing.T, conn *libvirt.Connect, name, bridge string) *libvirt.Network {
	t.Helper()

	network, err := conn.NetworkDefineXML(vbtcovIsolatedNetworkXML(name, bridge))
	if err != nil {
		t.Fatalf("define network %s: %v", name, err)
	}
	t.Cleanup(func() {
		if leftover, err := conn.LookupNetworkByName(name); err == nil {
			_ = leftover.Destroy()
			_ = leftover.Undefine()
			_ = leftover.Free()
		}
	})
	t.Cleanup(func() { _ = network.Free() })
	return network
}

func TestVbtcovStartNetworkIfNeededAndAutostart(t *testing.T) {
	conn := newTestLibvirtConn(t)
	suffix := time.Now().UnixNano() % 1000000
	network := vbtcovDefineNetwork(t, conn, fmt.Sprintf("cvbt-net-%d", time.Now().UnixNano()), fmt.Sprintf("cvbtb%d", suffix))

	// Inactive defined network: the first call starts it, the second is a no-op.
	if err := startNetworkIfNeeded(network); err != nil {
		t.Fatalf("startNetworkIfNeeded on inactive network: %v", err)
	}
	active, err := network.IsActive()
	if err != nil {
		t.Fatalf("check network active: %v", err)
	}
	if !active {
		t.Fatal("expected test network to be active after start")
	}
	if err := startNetworkIfNeeded(network); err != nil {
		t.Fatalf("startNetworkIfNeeded on active network: %v", err)
	}

	// Freshly defined networks have autostart off, so this takes the
	// SetAutostart(true) branch.
	configureNetworkAutostart(network)
	autostart, err := network.GetAutostart()
	if err != nil {
		t.Fatalf("get network autostart: %v", err)
	}
	if !autostart {
		t.Fatal("expected network autostart to be enabled")
	}
}

func TestVbtcovStartNetworkIfNeededCreateFailure(t *testing.T) {
	conn := newTestLibvirtConn(t)
	// The bridge name collides with the always-present loopback interface, so
	// starting the network fails deterministically.
	network := vbtcovDefineNetwork(t, conn, fmt.Sprintf("cvbt-net-lo-%d", time.Now().UnixNano()), "lo")

	err := startNetworkIfNeeded(network)
	vbtcovRequireErrContains(t, err, "start network", "startNetworkIfNeeded with conflicting bridge")
}

func TestVbtcovStartNetworkIfNeededStaleHandle(t *testing.T) {
	conn := newTestLibvirtConn(t)
	network := vbtcovDefineNetwork(t, conn, fmt.Sprintf("cvbt-net-stale-%d", time.Now().UnixNano()), fmt.Sprintf("cvbts%d", time.Now().UnixNano()%1000000))

	if err := network.Undefine(); err != nil {
		t.Fatalf("undefine network: %v", err)
	}

	err := startNetworkIfNeeded(network)
	vbtcovRequireErrContains(t, err, "is active", "startNetworkIfNeeded on undefined network")

	// GetAutostart fails on the stale handle too; the helper must swallow it.
	configureNetworkAutostart(network)
}

func TestVbtcovConfigureNetworkAutostartTransient(t *testing.T) {
	conn := newTestLibvirtConn(t)
	name := fmt.Sprintf("cvbt-net-tr-%d", time.Now().UnixNano())

	network, err := conn.NetworkCreateXML(vbtcovIsolatedNetworkXML(name, fmt.Sprintf("cvbtt%d", time.Now().UnixNano()%1000000)))
	if err != nil {
		t.Fatalf("create transient network %s: %v", name, err)
	}
	t.Cleanup(func() { _ = network.Free() })
	t.Cleanup(func() { _ = network.Destroy() })

	autostart, err := network.GetAutostart()
	if err != nil {
		t.Fatalf("get transient network autostart: %v", err)
	}
	if autostart {
		t.Fatal("expected transient network autostart to be false")
	}

	// SetAutostart fails for transient networks; the helper must only log it.
	configureNetworkAutostart(network)

	autostart, err = network.GetAutostart()
	if err != nil {
		t.Fatalf("re-get transient network autostart: %v", err)
	}
	if autostart {
		t.Fatal("expected transient network autostart to remain false")
	}
}
