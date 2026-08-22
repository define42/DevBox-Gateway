package virt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/virt/internal/storage"
	"github.com/define42/devbox-gateway/internal/vmname"

	"libvirt.org/go/libvirt"
)

// ErrVMAlreadyExists indicates a domain with the requested name already exists.
// Creation never destroys an existing VM, so the user must delete it first.
var ErrVMAlreadyExists = errors.New("virt: vm with this name already exists")

// vmNameLocks serializes create and remove operations per VDI name. BootNewVM
// checks the name is free (ensureVMNameAvailable) and only defines the domain
// much later (StartVM); between those two steps it destroys any
// leftover artifacts and writes a fresh disk and cloud-init seed (guest user +
// password hash). Without a per-name lock, two concurrent BootNewVM calls for
// the same name could both pass the availability check and then race through
// that region, each clobbering the other's disk and seed — so a domain could
// end up booting one request's disk with another request's credentials. RemoveVM
// takes the same lock so a delete cannot interleave with a create of the same
// name. It is held as the outer lock: reserveUserVMSlot/releaseUserVMSlot take
// vmCreationMu strictly inside this region, so the lock order is always
// vmNameLocks then vmCreationMu, and a goroutine never holds two VDI-name locks
// at once — so neither lock can deadlock. This is process-wide because the
// gateway is the single writer of libvirt state.
var vmNameLocks = newKeyedMutex() //nolint:gochecknoglobals // process-wide per-name serialization for VM create/remove

// ensureVMNameAvailable refuses creation when a domain with the same name already
// exists, so a boot can never destroy or overwrite an existing VM (the user must
// delete it first). A missing domain means the name is free to use.
func ensureVMNameAvailable(conn *libvirt.Connect, vmName string) error {
	dom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
			return nil
		}
		return fmt.Errorf("lookup existing domain %s: %w", vmName, err)
	}
	_ = dom.Free()
	return fmt.Errorf("%w: %s", ErrVMAlreadyExists, vmName)
}

// cloudInitPasswordHashPrefix is the sha512_crypt scheme marker every guest
// password hash must carry. resolveGuestCredentials rejects anything else so a
// cleartext password can never reach the cloud-init seed by mistake.
const cloudInitPasswordHashPrefix = "$6$"

// resolveGuestCredentials returns the guest login name and its cloud-init
// password hash. The name falls back to the owner's name when not set per VM.
// The password hash is required and must already be a salted sha512_crypt
// ($6$) digest: it is the hash of the owner's gateway login password, captured
// at login (see session.PasswordHashFromContext), so no cleartext password is
// ever passed through the VM provisioning path.
func resolveGuestCredentials(user *identity.User, guestUsername, guestPasswordHash string) (string, string, error) {
	guestUsername = strings.TrimSpace(guestUsername)
	if guestUsername == "" {
		guestUsername = user.Name
	}

	if guestPasswordHash == "" {
		return "", "", fmt.Errorf("guest password hash is required")
	}
	if !strings.HasPrefix(guestPasswordHash, cloudInitPasswordHashPrefix) {
		return "", "", fmt.Errorf("guest password hash must be a sha512_crypt (%s) digest", cloudInitPasswordHashPrefix)
	}
	return guestUsername, guestPasswordHash, nil
}

// VMCreateRequest carries the user-supplied inputs for creating a VDI. CPU,
// memory, and disk size are deliberately absent: VM resources are
// operator-defined only (VM_VCPU_COUNT / VM_MEMORY_MIB) and resolved from
// settings during preparation, so no caller can pass user-chosen values.
type VMCreateRequest struct {
	// Name is the requested hostname. The resulting VM (VDI) name is always
	// "<username>-<hostname>", enforced via vmname.Compose; an invalid owner
	// or hostname is rejected before anything is created.
	Name string
	// Owner is the gateway user the VM belongs to; required.
	Owner *identity.User
	// GuestUsername is the login account provisioned inside the guest (and
	// used for RDP); it falls back to Owner's name when empty.
	GuestUsername string
	// PasswordHash is the salted sha512_crypt ($6$) digest of the guest
	// account's password — the hash of the owner's gateway login password
	// stored in the session at login — and is required; cleartext passwords
	// are never accepted here.
	PasswordHash string
	// BaseImage is the file name of the base image to clone, selected from the
	// configured image library; it is validated against that library before use.
	BaseImage string
}

// vmProvisionSpec is the resolved provisioning plan a VMCreateRequest turns
// into during preparation: every field is validated or operator-configured, so
// the locked provision/start phase handles no raw user input.
type vmProvisionSpec struct {
	vmName        string // composed "<username>-<hostname>" VDI name
	hostname      string // requested guest hostname (the request's short name)
	seedISO       string // cloud-init seed volume name
	owner         string // owning user's name
	guestUsername string // guest login account
	passwordHash  string // sha512_crypt digest for the guest account
	baseImage     string // image library file name (recorded as metadata)
	baseImagePath string // resolved absolute path of the base image
	poolName      string
	poolPath      string
	vcpu          int
	memoryMiB     int
}

// startConfig returns the domain define-and-start step of the plan.
func (s vmProvisionSpec) startConfig() VMStartConfig {
	return VMStartConfig{
		Name:            s.vmName,
		SeedISO:         s.seedISO,
		StoragePoolName: s.poolName,
		VCPU:            s.vcpu,
		MemoryMiB:       s.memoryMiB,
		Owner:           s.owner,
		GuestUser:       s.guestUsername,
		BaseImage:       s.baseImage,
	}
}

// prepareVMCreation validates the request and resolves everything the boot
// needs that does not require libvirt: the composed VDI name, the guest
// credentials, operator-defined CPU/memory, the base image path, and the
// storage pool. It takes no locks and reserves nothing. On error the returned
// spec still carries the composed VDI name when composition succeeded, so
// callers can report which VM the failure was about.
func prepareVMCreation(req VMCreateRequest, settings *config.Settings) (vmProvisionSpec, error) {
	var spec vmProvisionSpec
	if req.Owner == nil {
		return spec, fmt.Errorf("vm owner is required")
	}
	spec.owner = req.Owner.Name
	spec.hostname = strings.TrimSpace(req.Name)

	// Enforce the VDI naming invariant ("<username>-<hostname>") at the single
	// construction point so no caller can bypass it.
	vmName, err := vmname.Compose(spec.owner, spec.hostname)
	if err != nil {
		return spec, err
	}
	spec.vmName = vmName
	spec.seedISO = vmName + "_seed.iso"

	spec.guestUsername, spec.passwordHash, err = resolveGuestCredentials(req.Owner, req.GuestUsername, req.PasswordHash)
	if err != nil {
		return spec, err
	}

	spec.vcpu = config.VMVCPUCount(settings)
	spec.memoryMiB = config.VMMemoryMiB(settings)

	// Validate the selected base image against the library and resolve it to an
	// absolute path (the single path-traversal guard) before anything is created.
	spec.baseImage = req.BaseImage
	spec.baseImagePath, err = storage.ResolveBaseImagePath(settings, req.BaseImage)
	if err != nil {
		return spec, err
	}

	spec.poolName, spec.poolPath = storage.PoolConfig(settings)
	return spec, nil
}

// BootNewVM creates or recreates a VM for the requesting user and starts it
// with owner metadata. Preparation (prepareVMCreation) validates the request
// and resolves the provisioning plan without locks; the per-name locked phase
// (provisionAndStartVM) then provisions storage and starts the domain.
func BootNewVM(req VMCreateRequest, settings *config.Settings) (vmName string, err error) {
	return BootNewVMWithProgress(req, settings, nil)
}

// BootNewVMWithProgress behaves like BootNewVM and synchronously reports the
// selected base image's disk-copy byte progress. A nil callback disables
// reporting. The callback is observational: callers should return promptly and
// must not call back into VM create/remove operations.
func BootNewVMWithProgress(req VMCreateRequest, settings *config.Settings, report DiskCopyProgressFunc) (vmName string, err error) {
	spec, err := prepareVMCreation(req, settings)
	if err != nil {
		return spec.vmName, err
	}

	conn, err := connectLibvirt()
	if err != nil {
		return spec.vmName, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	if err := storage.EnsureBootPool(conn, spec.poolName, spec.poolPath); err != nil {
		return spec.vmName, err
	}
	// Serialize the whole check-and-act region for this name: the availability
	// check, the destroy of any leftover artifacts, the disk/seed provisioning,
	// and the domain definition must be atomic with respect to another create or
	// remove of the same VDI name. Held until the boot finishes.
	unlockName := vmNameLocks.Lock(spec.vmName)
	defer unlockName()
	if err := provisionAndStartVM(conn, settings, spec, report); err != nil {
		return spec.vmName, err
	}

	return spec.vmName, nil
}

// provisionAndStartVM runs the locked phase of a VM creation: the caller must
// hold vmNameLocks.Lock(spec.vmName) for the whole call. It checks the name is
// free, reserves the owner's quota slot, clears leftover artifacts, provisions
// the disk and seed volumes, and starts the domain.
func provisionAndStartVM(conn *libvirt.Connect, settings *config.Settings, spec vmProvisionSpec, report DiskCopyProgressFunc) error {
	if err := ensureVMNameAvailable(conn, spec.vmName); err != nil {
		return err
	}
	// The slot stays reserved until this create finishes (or fails), so a
	// concurrent create for the same user cannot pass the limit check before
	// this VM's owner metadata exists.
	releaseVMSlot, err := reserveUserVMSlot(conn, settings, spec.owner)
	if err != nil {
		return err
	}
	defer releaseVMSlot()
	if err := resetExistingVMArtifacts(conn, spec.poolName, spec.vmName, spec.seedISO); err != nil {
		return err
	}
	if err := provisionBootVolumes(conn, settings, spec, report); err != nil {
		return err
	}
	if err := StartVM(spec.startConfig()); err != nil {
		return fmt.Errorf("failed to start vm: %w", err)
	}
	return nil
}

// RemoveVM deletes the named VM, its disks, and any leftover console sockets.
func RemoveVM(name string, settings *config.Settings) error {
	// Take the per-name lock so a remove and a create of the same VDI name
	// cannot interleave (see vmNameLocks): the destroy and volume deletion below
	// must not run against a name another goroutine is mid-provisioning.
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()

	conn, err := connectLibvirt()
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Close()
	}()

	poolName, _ := storage.PoolConfig(settings)

	if err := DestroyExistingDomain(conn, name); err != nil {
		return err
	}
	seedISO := name + "_seed.iso"
	if err := storage.RemoveVolumes(conn, poolName, name, seedISO); err != nil {
		return err
	}
	vmLastUsed.remove(name)
	// The VNC socket and serial PTY are libvirt-managed and removed with the
	// destroyed domain; nothing for the gateway to clean up.
	return nil
}

// resetExistingVMArtifacts destroys any leftover domain and volumes for vmName
// during a create. It runs while BootNewVM already holds vmNameLocks.Lock(vmName),
// so it must NOT be reimplemented in terms of RemoveVM: RemoveVM re-acquires the
// same (non-reentrant) per-name lock and would self-deadlock.
func resetExistingVMArtifacts(conn *libvirt.Connect, poolName, vmName, seedISO string) error {
	if err := DestroyExistingDomain(conn, vmName); err != nil {
		return fmt.Errorf("failed to destroy existing domain: %w", err)
	}
	if err := storage.RemoveVolumes(conn, poolName, vmName, seedISO); err != nil {
		return fmt.Errorf("failed to remove existing volumes: %w", err)
	}
	// The VNC socket and serial PTY are libvirt-managed and removed with the
	// destroyed domain; nothing for the gateway to clean up.
	return nil
}

// provisionBootVolumes creates the VM's disk (cloned from the resolved base
// image) and its cloud-init seed ISO in the storage pool. A nil report
// disables disk-copy progress reporting.
func provisionBootVolumes(conn *libvirt.Connect, settings *config.Settings, spec vmProvisionSpec, report DiskCopyProgressFunc) error {
	if err := storage.CopyAndResizeVolumeWithSettingsAndProgress(
		conn,
		settings,
		spec.poolName,
		spec.vmName,
		spec.baseImagePath,
		config.VMDiskCapacityBytes(settings),
		report,
	); err != nil {
		return fmt.Errorf("failed to copy and resize base image: %w", err)
	}
	if err := storage.CreateUbuntuSeedISOToPoolWithSettings(
		settings,
		conn,
		spec.poolName,
		spec.seedISO,
		spec.guestUsername,
		spec.passwordHash,
		spec.hostname,
	); err != nil {
		return fmt.Errorf("failed to create seed iso: %w", err)
	}
	return nil
}
