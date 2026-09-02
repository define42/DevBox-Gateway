package virt

import (
	"fmt"

	"libvirt.org/go/libvirt"
)

// StartExistingVM starts an existing domain when it is currently shut off.
func StartExistingVM(name string) error {
	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if active {
		return nil
	}
	// VNC socket and serial PTY are libvirt-managed; nothing for the gateway to
	// clean up before (re)starting the domain.
	if err := dom.Create(); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	// Starting counts as use for auto-shutdown, so a freshly started VDI gets a
	// full idle window.
	markDomainUsed(dom, name)
	return nil
}

// GracefulShutdownVM asks a running domain to power off via an ACPI power
// button event and returns once the request is delivered. Whether and when the
// guest honors it is the guest's decision — a hung guest, or firmware with no
// OS, ignores it and the domain stays running — so callers that must guarantee
// the domain stops (the auto-shutdown sweeper) escalate to ShutdownVM after a
// grace period. Requesting shutdown of an already stopped domain is a no-op.
func GracefulShutdownVM(name string) error {
	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		return nil
	}
	// ACPI is requested explicitly: gateway VMs carry no qemu-guest-agent
	// channel (see domain.go), so pinning the method keeps the behavior
	// independent of libvirt's default-mode heuristics.
	if err := dom.ShutdownFlags(libvirt.DOMAIN_SHUTDOWN_ACPI_POWER_BTN); err != nil {
		return fmt.Errorf("graceful shutdown domain %s: %w", name, err)
	}
	return nil
}

// ShutdownVM force-stops a running domain.
func ShutdownVM(name string) error {
	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		return nil
	}
	if err := dom.Destroy(); err != nil {
		return fmt.Errorf("force shutdown domain %s: %w", name, err)
	}
	return nil
}

// RestartVM reboots a running domain or starts it when it is shut off.
func RestartVM(name string) error {
	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if active {
		if err := dom.Reboot(0); err != nil {
			return fmt.Errorf("reboot domain %s: %w", name, err)
		}
		markDomainUsed(dom, name)
		return nil
	}
	// VNC socket and serial PTY are libvirt-managed; nothing for the gateway to
	// clean up before (re)starting the domain.
	if err := dom.Create(); err != nil {
		return fmt.Errorf("start domain %s: %w", name, err)
	}
	// Restarting a shut-off VDI is a start: it counts as use for auto-shutdown
	// (as does the reboot above — both are deliberate owner actions on the VM).
	markDomainUsed(dom, name)
	return nil
}
