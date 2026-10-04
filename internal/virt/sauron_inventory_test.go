package virt

import (
	"fmt"
	"strings"
	"testing"

	"libvirt.org/go/libvirt"
)

func TestExpectedAuditGuestsTrackManagedRunningDomains(t *testing.T) {
	conn := newAuditInventoryConnection(t)
	want := defineAuditInventoryVM(t, conn, "managed-running", "alice", 42)
	defineAuditInventoryVM(t, conn, "unmanaged-running", "", 43)
	paused := defineAuditInventoryVM(t, conn, "managed-paused", "alice", 44)
	if err := paused.Suspend(); err != nil {
		t.Fatal(err)
	}
	stopped := defineAuditInventoryVM(t, conn, "managed-stopped", "alice", 45)
	if err := stopped.Destroy(); err != nil {
		t.Fatal(err)
	}
	guests, err := ListExpectedVSockGuests()
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := want.GetUUIDString()
	if err != nil {
		t.Fatal(err)
	}
	if len(guests) != 1 || guests[0] != (VSockGuest{CID: 42, Name: "managed-running", UUID: uuid, Owner: "alice"}) {
		t.Fatalf("unexpected audit inventory: %+v", guests)
	}
}

func TestExpectedAuditGuestsRejectIncompleteInventory(t *testing.T) {
	conn := newAuditInventoryConnection(t)
	defineAuditInventoryVM(t, conn, "missing-vsock", "alice", 0)
	if _, err := ListExpectedVSockGuests(); err == nil || !strings.Contains(err.Error(), "no assigned audit vsock CID") {
		t.Fatalf("missing audit transport disappeared from monitoring: %v", err)
	}
}

func TestExpectedAuditGuestsSurfaceHypervisorFailure(t *testing.T) {
	t.Setenv("LIBVIRT_URI", "test:///does-not-exist/devbox-audit")
	if _, err := ListExpectedVSockGuests(); err == nil {
		t.Fatal("failed hypervisor lookup reported empty healthy inventory")
	}
}

func newAuditInventoryConnection(t *testing.T) *libvirt.Connect {
	t.Helper()
	t.Setenv("LIBVIRT_URI", "test:///default")
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	return conn
}

func defineAuditInventoryVM(t *testing.T, conn *libvirt.Connect, name, owner string, cid uint32) *libvirt.Domain {
	t.Helper()
	devices := ""
	if cid != 0 {
		devices = fmt.Sprintf("<devices><vsock model='virtio'><cid auto='no' address='%d'/></vsock></devices>", cid)
	}
	dom, err := conn.DomainDefineXML("<domain type='test'><name>" + name + "</name><memory>1024</memory><vcpu>1</vcpu><os><type>hvm</type></os>" + devices + "</domain>")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dom.Destroy(); _ = dom.Undefine(); _ = dom.Free() })
	if owner != "" {
		if err := setDomainOwnerMetadata(dom, owner); err != nil {
			t.Fatal(err)
		}
	}
	if err := dom.Create(); err != nil {
		t.Fatal(err)
	}
	return dom
}
