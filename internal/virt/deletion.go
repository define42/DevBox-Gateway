package virt

import (
	"errors"
	"fmt"

	"libvirt.org/go/libvirt"
)

const (
	domainDeletionMetadataNamespace = "urn:devboxgateway:domain:deletion"
	domainDeletionMetadataPrefix    = "devboxgatewaydeletion"
)

// ErrVMDeletionPending means removal has begun and must be retried before the
// VM name can be reused. Its remaining resources must not be started again.
var ErrVMDeletionPending = errors.New("VM deletion is pending; retry deletion")

// ensureVMNotDeleting checks persistent metadata, including for a running VM.
// Any element in this namespace blocks power operations: an unknown marker must
// not make a partially deleted VM startable. Metadata errors also fail closed.
func ensureVMNotDeleting(dom *libvirt.Domain) error {
	_, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainDeletionMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read VM deletion state: %w", err)
	}
	return ErrVMDeletionPending
}

// prepareDomainDeletion persists the retry state before changing any resource.
// Keeping the domain defined preserves its owner's authorization after a
// storage or network failure, including across gateway restarts.
func prepareDomainDeletion(dom *libvirt.Domain) error {
	if err := dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		"<deletion>pending</deletion>",
		domainDeletionMetadataPrefix,
		domainDeletionMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	); err != nil {
		return fmt.Errorf("persist VM deletion state: %w", err)
	}
	// The API checks the marker before start/restart. Disable libvirt's own
	// automatic start as well, so a host reboot cannot start a partially removed VM.
	if err := dom.SetAutostart(false); err != nil {
		return fmt.Errorf("disable autostart for deleting VM: %w", err)
	}
	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check deleting VM state: %w", err)
	}
	if active {
		if err := dom.Destroy(); err != nil {
			return fmt.Errorf("stop deleting VM: %w", err)
		}
	}
	return nil
}

// lookupRemovalDomain treats an absent domain as already removed. This keeps
// direct cleanup calls idempotent; HTTP callers authorize against the existing
// persistent domain before entering RemoveVM.
func lookupRemovalDomain(conn *libvirt.Connect, name string) (*libvirt.Domain, error) {
	dom, err := conn.LookupDomainByName(name)
	if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	return dom, nil
}

func ensureExistingVMNotDeleting(conn *libvirt.Connect, name string) error {
	dom, err := lookupRemovalDomain(conn, name)
	if err != nil || dom == nil {
		return err
	}
	defer func() { _ = dom.Free() }()
	return ensureVMNotDeleting(dom)
}
