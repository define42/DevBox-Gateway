package virt

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

// InitVirt ensures a base image library exists and the libvirt storage pool and
// 'default' NAT network are ready for VM operations. The base image check runs
// first, before any libvirt connection, so an empty image library fails the boot
// fast with a clear error.
func InitVirt(settings *config.SettingsType) error {
	if err := EnsureBaseImagesAvailable(settings); err != nil {
		return err
	}

	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	if err := ensureLibvirtVersion(conn); err != nil {
		return err
	}

	poolName, poolPath := storagePoolConfig(settings)
	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		return fmt.Errorf("failed to ensure storage pool %s: %w", poolName, err)
	}
	defer func() {
		_ = pool.Free()
	}()

	if err := ensureDefaultNetwork(conn); err != nil {
		return fmt.Errorf("failed to ensure network %s: %w", defaultNetworkName, err)
	}

	return nil
}

// VMStartConfig describes the domain define-and-start step of a VM boot: the
// volumes to attach, the operator-defined sizing, and the gateway metadata to
// record on the new domain.
type VMStartConfig struct {
	Name            string // domain (VDI) name
	SeedISO         string // cloud-init seed volume name in the storage pool
	StoragePoolName string
	VCPU            int
	MemoryMiB       int

	// Gateway metadata attached to the new domain; each field is optional and
	// skipped when blank.
	Owner     string // owning gateway user
	GuestUser string // login account provisioned inside the guest
	BaseImage string // image library file name the disk was cloned from
}

// StartVM defines and starts a VM, attaching the configured gateway metadata.
func StartVM(cfg VMStartConfig) (err error) {
	conn, err := connectLibvirt()
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Close()
	}()

	// Both the VNC socket and the serial PTY are libvirt-managed; the gateway
	// owns no console sockets.
	dom, err := conn.DomainDefineXML(UbuntuDomain(cfg.Name, cfg.SeedISO, cfg.StoragePoolName, cfg.VCPU, cfg.MemoryMiB))
	if err != nil {
		return err
	}
	defer func() {
		_ = dom.Free()
	}()

	// Owner metadata (and the guest-user, base-image, and created-at metadata
	// below) is attached AFTER the domain is defined, and dom.Create() runs later
	// still. A failure at any of those steps would otherwise leave the domain
	// defined but half-created; without owner metadata it is orphaned — the
	// dashboard filters its VM listing by owner, so the creator can neither see
	// the VM nor delete it (the ownership check returns 403), and the name stays
	// reserved in libvirt until an admin runs `virsh undefine`. Roll the
	// definition back on any post-define failure so a failed boot is atomic
	// (leaves nothing behind) and the name is free for a clean retry. Registered
	// after the Free above so it runs first (defers are LIFO), while dom is still
	// valid.
	defer func() {
		if err != nil {
			undefinePartialDomain(dom, cfg.Name)
		}
	}()

	var lastUsedAt time.Time
	lastUsedAt, err = applyNewDomainMetadata(dom, cfg)
	if err != nil {
		return err
	}

	if err = dom.Create(); err != nil {
		return err
	}

	vmLastUsed.set(cfg.Name, lastUsedAt)

	return nil
}

// applyNewDomainMetadata attaches the gateway metadata to a freshly defined
// domain and returns the recorded last-used time. Owner, guest-user, and
// base-image are optional and skipped when blank.
func applyNewDomainMetadata(dom *libvirt.Domain, cfg VMStartConfig) (time.Time, error) {
	if strings.TrimSpace(cfg.Owner) != "" {
		if err := setDomainOwnerMetadata(dom, cfg.Owner); err != nil {
			return time.Time{}, fmt.Errorf("set owner metadata for %s: %w", cfg.Name, err)
		}
	}

	if strings.TrimSpace(cfg.GuestUser) != "" {
		if err := setDomainGuestUserMetadata(dom, cfg.GuestUser); err != nil {
			return time.Time{}, fmt.Errorf("set guest user metadata for %s: %w", cfg.Name, err)
		}
	}

	if strings.TrimSpace(cfg.BaseImage) != "" {
		if err := setDomainBaseImageMetadata(dom, cfg.BaseImage); err != nil {
			return time.Time{}, fmt.Errorf("set base image metadata for %s: %w", cfg.Name, err)
		}
	}

	// Creation counts as use for auto-shutdown, so a VDI that is created but
	// never opened still gets a full idle window before being stopped. Written
	// before created-at: created-at must stay the last metadata write, because
	// the inventory cache treats it as the completion marker.
	lastUsedAt := time.Now()
	if err := setDomainLastUsedMetadata(dom, formatLastUsedTimestamp(lastUsedAt)); err != nil {
		return time.Time{}, fmt.Errorf("set last-used metadata for %s: %w", cfg.Name, err)
	}

	// Record creation time once, when the domain is first defined. Starting or
	// restarting an existing VM goes through dom.Create() elsewhere and never
	// redefines the domain, so this timestamp is stable for the VM's lifetime.
	if err := setDomainCreatedAtMetadata(dom, nowCreatedAtTimestamp()); err != nil {
		return time.Time{}, fmt.Errorf("set created-at metadata for %s: %w", cfg.Name, err)
	}

	return lastUsedAt, nil
}

// undefinePartialDomain rolls back a domain that DomainDefineXML created but
// whose remaining setup (owner/guest-user/base-image/created-at metadata, then
// dom.Create) did not complete. Without this rollback a failed boot leaves the
// domain defined but without owner metadata, which orphans it: the dashboard
// filters its VM listing by owner, so the creating user can neither see the VM
// nor delete it (the ownership check returns 403), and the name stays reserved
// in libvirt until an admin runs `virsh undefine`. Cleanup errors are only
// logged — the caller is already returning the original failure and can do
// nothing more about a failed rollback.
func undefinePartialDomain(dom *libvirt.Domain, name string) {
	// On this path the domain is expected to be inactive (rollback only runs when
	// startVM returns an error, i.e. before dom.Create succeeds), but destroy any
	// running instance first so a persistent domain cannot survive Undefine.
	if active, activeErr := dom.IsActive(); activeErr == nil && active {
		if destroyErr := dom.Destroy(); destroyErr != nil {
			log.Printf("rollback: destroy partially created domain %s: %v", name, destroyErr)
		}
	}
	if undefineErr := dom.Undefine(); undefineErr != nil {
		log.Printf("rollback: undefine partially created domain %s: %v", name, undefineErr)
	}
}

// DestroyExistingDomain force-stops and undefines the named domain when it exists.
func DestroyExistingDomain(conn *libvirt.Connect, vmName string) error {
	existingDom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil
	}
	defer func() {
		_ = existingDom.Free()
	}()

	active, err := existingDom.IsActive()
	if err != nil {
		return err
	}
	if active {
		if err := existingDom.Destroy(); err != nil {
			return err
		}
		log.Printf("Destroyed running domain %s", vmName)
	}

	if err := existingDom.Undefine(); err != nil {
		return err
	}
	log.Printf("Undefined domain %s", vmName)
	return nil
}
