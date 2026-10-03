package virt

import (
	"fmt"

	"libvirt.org/go/libvirt"
)

// StartExistingVM validates the domain's isolation settings and starts it if
// inactive. An already active domain is left unchanged. This function does not
// check user ownership; callers must authorize the operation.
func StartExistingVM(name string) error {
	// Removal must finish stopping and undefining the domain before a start
	// can look it up, or it could restart a VM whose volumes are being deleted.
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()

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

	if err := ensureVMNotDeleting(dom); err != nil {
		return err
	}
	if err := validateDomainSecurity(conn, dom); err != nil {
		return err
	}
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
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()
	return gracefulShutdownVM(name)
}

// ShutdownVM immediately stops an active domain through libvirt Destroy, without
// waiting for the guest OS to shut down. An inactive domain is left unchanged.
// Callers must authorize the operation; use GracefulShutdownVM to request ACPI shutdown.
func ShutdownVM(name string) error {
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()
	return shutdownVM(name)
}

// The private shutdown helpers require the VM lifecycle lock. The idle sweeper
// holds it across its decision and shutdown request, so it uses these directly.
func gracefulShutdownVM(name string) error {
	return stopVM(name, false)
}

func shutdownVM(name string) error {
	return stopVM(name, true)
}

func stopVM(name string, force bool) error {
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

	if err := ensureVMNotDeleting(dom); err != nil {
		return err
	}
	return stopDomain(dom, name, force)
}

type shutdownDomain interface {
	IsActive() (bool, error)
	ShutdownFlags(libvirt.DomainShutdownFlags) error
	Destroy() error
}

func stopDomain(dom shutdownDomain, name string, force bool) error {
	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("check domain active %s: %w", name, err)
	}
	if !active {
		return nil
	}
	if force {
		if err := dom.Destroy(); err != nil {
			return fmt.Errorf("force shutdown domain %s: %w", name, err)
		}
		return nil
	}
	// Gateway VMs have no guest-agent channel, so explicitly use the ACPI
	// power button instead of libvirt's default shutdown heuristics.
	if err := dom.ShutdownFlags(libvirt.DOMAIN_SHUTDOWN_ACPI_POWER_BTN); err != nil {
		return fmt.Errorf("graceful shutdown domain %s: %w", name, err)
	}
	return nil
}

// RestartVM validates the domain's isolation settings, then requests a reboot of
// an active domain or starts an inactive one. It returns after libvirt accepts
// the operation, without waiting for guest readiness. Callers must authorize it.
func RestartVM(name string) error {
	// A restart can start a stopped domain, so it needs the same exclusion
	// against provisioning and removal as StartExistingVM.
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()

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

	if err := ensureVMNotDeleting(dom); err != nil {
		return err
	}
	if err := validateDomainSecurity(conn, dom); err != nil {
		return err
	}
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
