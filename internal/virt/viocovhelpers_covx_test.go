package virt

import (
	"fmt"
	"os"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

// viocovBadLibvirtURI is a URI no libvirt driver handles, so NewConnect fails
// fast and locally without touching the network.
const viocovBadLibvirtURI = "nosuchdriver:///viocov"

func viocovUniqueName(kind string) string {
	return fmt.Sprintf("cvio-%s-%d", kind, time.Now().UnixNano())
}

// viocovDomainXML renders a minimal TCG (type='qemu') domain so tests can
// exercise libvirt-backed branches without KVM, disks, or a network.
func viocovDomainXML(name, devices string) string {
	return fmt.Sprintf(`<domain type='qemu'>
  <name>%s</name>
  <memory unit='MiB'>128</memory>
  <vcpu>1</vcpu>
  <os><type arch='x86_64'>hvm</type></os>
  <features><acpi/></features>
  <devices>%s</devices>
</domain>`, name, devices)
}

// viocovDefineDomain defines (but does not start) a minimal domain with the
// given extra device XML and registers cleanup that tolerates errors.
func viocovDefineDomain(t *testing.T, conn *libvirt.Connect, name, devices string) *libvirt.Domain {
	t.Helper()

	dom, err := conn.DomainDefineXML(viocovDomainXML(name, devices))
	if err != nil {
		t.Fatalf("define domain %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = dom.Destroy()
		_ = dom.Undefine()
		_ = dom.Free()
	})
	return dom
}

// viocovStartDomain defines and boots a minimal TCG domain (SeaBIOS idles with
// no bootable device, so the domain stays running until destroyed by cleanup).
func viocovStartDomain(t *testing.T, conn *libvirt.Connect, name, devices string) *libvirt.Domain {
	t.Helper()

	dom := viocovDefineDomain(t, conn, name, devices)
	if err := dom.Create(); err != nil {
		t.Fatalf("start domain %s: %v", name, err)
	}
	return dom
}

func viocovRawDiskXML(path string) string {
	return fmt.Sprintf(
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='%s'/><target dev='vda' bus='virtio'/></disk>`,
		path,
	)
}

func viocovWaitForFile(t *testing.T, path string) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("file %s did not appear in time", path)
}
