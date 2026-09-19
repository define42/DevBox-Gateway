package virt

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/identity"
)

// requireVHostVSock skips a test that boots a domain with a vsock device on a
// host whose kernel offers no vhost-vsock backend for libvirt to open.
func requireVHostVSock(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/vhost-vsock"); err != nil {
		t.Skipf("no vhost-vsock device on this host: %v", err)
	}
}

// assertVSockGuest resolves the CID libvirt assigned to the running domain
// back to it, the way the SauronAgent collector does for each connection.
func assertVSockGuest(t *testing.T, name string, want VSockGuest) uint32 {
	t.Helper()
	conn := newTestLibvirtConn(t)
	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		t.Fatalf("lookup domain %s: %v", name, err)
	}
	defer func() { _ = dom.Free() }()
	desc, err := dom.GetXMLDesc(0)
	if err != nil {
		t.Fatalf("live xml: %v", err)
	}
	cid, ok := domainVSockCID(desc)
	if !ok {
		t.Fatalf("libvirt assigned no cid to the running domain:\n%s", desc)
	}
	if want.UUID == "" {
		if want.UUID, err = dom.GetUUIDString(); err != nil {
			t.Fatalf("domain uuid: %v", err)
		}
	}

	guest, found, err := LookupVSockGuest(cid)
	if err != nil || !found {
		t.Fatalf("LookupVSockGuest(%d) = %+v, %t, %v; want the running domain", cid, guest, found, err)
	}
	if guest != want {
		t.Fatalf("LookupVSockGuest(%d) = %+v, want %+v", cid, guest, want)
	}
	return cid
}

func TestDomainXMLVSockDevice(t *testing.T) {
	type vsockXML struct {
		Model string `xml:"model,attr"`
		CID   struct {
			Auto string `xml:"auto,attr"`
		} `xml:"cid"`
	}
	var parsed struct {
		Devices struct {
			VSock []vsockXML `xml:"vsock"`
		} `xml:"devices"`
	}

	with := DomainXML("alice-devbox", "alice-devbox_seed.iso", "desktop", 4, 4096, true)
	if err := xml.Unmarshal([]byte(with), &parsed); err != nil {
		t.Fatalf("domain xml with vsock must stay well-formed: %v\n%s", err, with)
	}
	if len(parsed.Devices.VSock) != 1 {
		t.Fatalf("got %d vsock devices, want 1:\n%s", len(parsed.Devices.VSock), with)
	}
	// libvirt must choose the CID: a fixed one could collide with another
	// running domain, and the collector trusts whatever CID libvirt assigned.
	if device := parsed.Devices.VSock[0]; device.Model != "virtio" || device.CID.Auto != "yes" {
		t.Fatalf("vsock device = %+v, want a virtio device with an auto-assigned cid", device)
	}

	without := DomainXML("alice-devbox", "alice-devbox_seed.iso", "desktop", 4, 4096, false)
	if strings.Contains(without, "<vsock") {
		t.Fatalf("domain xml without vsock must not add the device:\n%s", without)
	}
}

func TestDomainVSockCID(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		want    uint32
		wantHas bool
	}{
		{
			name:    "live xml carries the assigned cid",
			xml:     `<domain><devices><vsock model='virtio'><cid auto='yes' address='42'/></vsock></devices></domain>`,
			want:    42,
			wantHas: true,
		},
		{
			name: "inactive xml has no address yet",
			xml:  `<domain><devices><vsock model='virtio'><cid auto='yes'/></vsock></devices></domain>`,
		},
		{
			name: "reserved host cid is not a guest",
			xml:  `<domain><devices><vsock model='virtio'><cid auto='no' address='2'/></vsock></devices></domain>`,
		},
		{
			name: "no vsock device",
			xml:  `<domain><devices><serial type='pty'/></devices></domain>`,
		},
		{
			name: "non-numeric address",
			xml:  `<domain><devices><vsock model='virtio'><cid address='three'/></vsock></devices></domain>`,
		},
		{
			name: "malformed xml",
			xml:  `<domain`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, has := domainVSockCID(test.xml)
			if got != test.want || has != test.wantHas {
				t.Fatalf("domainVSockCID() = %d, %t, want %d, %t", got, has, test.want, test.wantHas)
			}
		})
	}
}

// TestPrepareVMCreationFollowsSauronEnable locks that new VDIs get the
// SauronAgent vsock device exactly when the collector is enabled.
func TestPrepareVMCreationFollowsSauronEnable(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		settings := newBootTestSettings(t)
		if err := settings.OverwriteForTestBool(config.SAURON_ENABLE, enabled); err != nil {
			t.Fatal(err)
		}
		owner, err := identity.New("vsocktest")
		if err != nil {
			t.Fatal(err)
		}
		spec, err := prepareVMCreation(VMCreateRequest{
			Name: "devbox", Owner: owner, GuestUsername: "guest",
			PasswordHash: testGuestPasswordHash, BaseImage: seedDummyBaseImage(t, settings),
		}, settings)
		if err != nil {
			t.Fatalf("prepareVMCreation: %v", err)
		}
		if got := spec.startConfig().VSock; got != enabled {
			t.Errorf("SAURON_ENABLE=%t: VMStartConfig.VSock = %t", enabled, got)
		}
	}
}

// TestLookupVSockGuestFindsTheRunningDomain boots a minimal domain with the
// vsock device the gateway gives every VDI and resolves its CID back to it.
func TestLookupVSockGuestFindsTheRunningDomain(t *testing.T) {
	requireVHostVSock(t)
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("vsock")
	dom := viocovDefineDomain(t, conn, name, vsockDeviceXML)
	if err := setDomainOwnerMetadata(dom, "alice"); err != nil {
		t.Fatalf("set owner metadata: %v", err)
	}
	if err := dom.Create(); err != nil {
		t.Fatalf("start domain %s with a vsock device: %v", name, err)
	}

	cid := assertVSockGuest(t, name, VSockGuest{Name: name, Owner: "alice"})
	if hinted, ok := vsockCIDHints.get(cid); !ok || hinted != name {
		t.Fatalf("scan recorded hint %q, %t for cid %d; want %q", hinted, ok, cid, name)
	}
	// A second lookup is answered from the confirmed hint.
	assertVSockGuest(t, name, VSockGuest{Name: name, Owner: "alice"})

	// Once the domain stops, its CID belongs to nobody.
	if err := dom.Destroy(); err != nil {
		t.Fatalf("stop domain: %v", err)
	}
	if guest, found, err := LookupVSockGuest(cid); err != nil || found {
		t.Fatalf("LookupVSockGuest(%d) after stop = %+v, %t, %v; want not found", cid, guest, found, err)
	}
}

// TestLookupVSockGuestIgnoresStaleHints proves a hint is only ever a shortcut:
// one naming a domain that no longer exists, or one that now holds a different
// CID, falls back to a scan and still finds the right domain.
func TestLookupVSockGuestIgnoresStaleHints(t *testing.T) {
	requireVHostVSock(t)
	conn := newTestLibvirtConn(t)
	name := viocovUniqueName("vsockhint")
	viocovStartDomain(t, conn, name, vsockDeviceXML)
	other := viocovUniqueName("vsockother")
	viocovStartDomain(t, conn, other, vsockDeviceXML)
	otherCID := assertVSockGuest(t, other, VSockGuest{Name: other})
	cid := assertVSockGuest(t, name, VSockGuest{Name: name})
	if cid == otherCID {
		t.Fatalf("two running domains share cid %d", cid)
	}

	for _, stale := range []string{"missing-" + name, other} {
		t.Run(stale, func(t *testing.T) {
			vsockCIDHints.replace(map[uint32]string{cid: stale})
			guest, found, err := LookupVSockGuest(cid)
			if err != nil || !found || guest.Name != name {
				t.Fatalf("LookupVSockGuest(%d) with stale hint %q = %+v, %t, %v; want %s", cid, stale, guest, found, err, name)
			}
			if hinted, _ := vsockCIDHints.get(cid); hinted != name {
				t.Errorf("hint after rescan = %q, want %q", hinted, name)
			}
		})
	}
}

// TestStartVMWithVSockIsAttributable boots a real VDI from the production
// domain XML with the SauronAgent vsock device, as SAURON_ENABLE does.
func TestStartVMWithVSockIsAttributable(t *testing.T) {
	requireVHostVSock(t)
	conn := newTestLibvirtConn(t)
	settings := newBootTestSettings(t)
	poolName := uniquePoolName("vsock-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })
	usePermissiveLibvirtVolumeMode(t)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, poolName); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	pool, err := ensureStoragePool(conn, poolName, config.VirtStoragePoolPath(settings))
	if err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}
	defer func() { _ = pool.Free() }()

	vmName := "startvm-vsock-" + time.Now().Format("150405")
	seedISO := vmName + "_seed.iso"
	if err := CopyAndResizeVolume(conn, poolName, vmName, existingBootBaseImagePath(t), 2*1024*1024); err != nil {
		t.Fatalf("CopyAndResizeVolume disk: %v", err)
	}
	if err := CreateSeedISOToPool(conn, poolName, seedISO, "bootuser", "$6$hash", vmName); err != nil {
		t.Fatalf("CreateSeedISOToPool: %v", err)
	}
	if err := StartVM(VMStartConfig{
		Name:            vmName,
		SeedISO:         seedISO,
		StoragePoolName: poolName,
		VCPU:            1,
		MemoryMiB:       1024,
		VSock:           true,
		Owner:           "alice",
	}); err != nil {
		t.Fatalf("StartVM with a vsock device: %v", err)
	}
	t.Cleanup(func() {
		if err := RemoveVM(vmName, settings); err != nil {
			t.Errorf("RemoveVM: %v", err)
		}
	})
	waitForDomainState(t, conn, vmName, true, bootLifecycleTimeout)

	assertVSockGuest(t, vmName, VSockGuest{Name: vmName, Owner: "alice"})
}
