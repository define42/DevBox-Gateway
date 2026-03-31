package virt

import (
	"fmt"

	"libvirt.org/go/libvirt"
)

func UpdateVMResources(name string, vcpu int, memoryMiB int) error {
	if vcpu <= 0 || memoryMiB <= 0 {
		return fmt.Errorf("invalid resources (vcpu=%d memoryMiB=%d)", vcpu, memoryMiB)
	}

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer conn.Close()

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
		return fmt.Errorf("vm must be stopped before updating resources")
	}

	memoryKiB := uint64(memoryMiB) * 1024
	if err := dom.SetMaxMemory(memoryKiB); err != nil {
		return fmt.Errorf("set max memory for %s: %w", name, err)
	}
	if err := dom.SetMemoryFlags(memoryKiB, libvirt.DOMAIN_MEM_CONFIG); err != nil {
		return fmt.Errorf("set memory for %s: %w", name, err)
	}
	currentMax, err := dom.GetVcpusFlags(libvirt.DOMAIN_VCPU_MAXIMUM)
	if err != nil || int(currentMax) < vcpu {
		if err := dom.SetVcpusFlags(uint(vcpu), libvirt.DOMAIN_VCPU_MAXIMUM|libvirt.DOMAIN_VCPU_CONFIG); err != nil {
			return fmt.Errorf("set max vcpu for %s: %w", name, err)
		}
	}
	if err := dom.SetVcpusFlags(uint(vcpu), libvirt.DOMAIN_VCPU_CONFIG); err != nil {
		return fmt.Errorf("set vcpu for %s: %w", name, err)
	}
	return nil
}
