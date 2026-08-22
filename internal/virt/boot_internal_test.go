package virt

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

func bootLimitSettings(t *testing.T, limit int) *config.Settings {
	t.Helper()
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestInt(config.MAX_VDI_PER_USER, limit); err != nil {
		t.Fatalf("overwrite MAX_VDI_PER_USER: %v", err)
	}
	return settings
}

// TestReserveUserVMSlotUsesCachedCount proves the quota check trusts an
// authoritative cached count and never falls back to live counting: the
// invalid zero-value connection would fail the fallback scan with a "count VMs
// owned by" error rather than the limit refusal asserted here.
func TestReserveUserVMSlotUsesCachedCount(t *testing.T) {
	settings := bootLimitSettings(t, 2)
	owner := "cached-count-user"
	cachedCount := func(string) (int, bool) { return 1, true }

	release, err := reserveUserVMSlotWithCounter(&libvirt.Connect{}, settings, owner, cachedCount)
	if err != nil {
		t.Fatalf("reserve below limit from cached count: %v", err)
	}

	// The cached count still reports 1, so only the in-flight reservation can
	// refuse the second create.
	if _, err := reserveUserVMSlotWithCounter(&libvirt.Connect{}, settings, owner, cachedCount); !errors.Is(err, ErrVMLimitReached) {
		t.Fatalf("reserve at limit = %v, want ErrVMLimitReached", err)
	}

	release()
	release, err = reserveUserVMSlotWithCounter(&libvirt.Connect{}, settings, owner, cachedCount)
	if err != nil {
		t.Fatalf("reserve after release: %v", err)
	}
	release()
}

func TestReserveUserVMSlotRefusesFromCachedCountAlone(t *testing.T) {
	settings := bootLimitSettings(t, 1)

	_, err := reserveUserVMSlotWithCounter(
		&libvirt.Connect{},
		settings,
		"cached-limit-user",
		func(string) (int, bool) { return 1, true },
	)
	if !errors.Is(err, ErrVMLimitReached) {
		t.Fatalf("reserve with cached count at limit = %v, want ErrVMLimitReached", err)
	}
}

func TestReserveUserVMSlotFallsBackToLiveCountWhenCacheUnavailable(t *testing.T) {
	settings := bootLimitSettings(t, 1)

	_, err := reserveUserVMSlotWithCounter(
		&libvirt.Connect{},
		settings,
		"fallback-count-user",
		func(string) (int, bool) { return 0, false },
	)
	if err == nil || !strings.Contains(err.Error(), "count VMs owned by") {
		t.Fatalf("reserve without cache on invalid connection = %v, want live-count error", err)
	}
}

func inflightReservationsForTest(owner string) int {
	vmCreationMu.Lock()
	defer vmCreationMu.Unlock()
	return inflightVMCreations[owner]
}

// TestReserveUserVMSlotDoesNotHoldMutexWhileCounting pins the property that
// vmCreationMu is released while the VM count runs: the live-count fallback
// can wedge in an uncancellable libvirt RPC exactly when libvirtd is
// unhealthy, and holding the process-wide mutex there would brick VM creation
// for every user until restart. The blocking counter stands in for that
// wedged RPC; a reservation for another owner must still complete.
func TestReserveUserVMSlotDoesNotHoldMutexWhileCounting(t *testing.T) {
	settings := bootLimitSettings(t, 1)

	counterEntered := make(chan struct{})
	unblockCounter := make(chan struct{})
	wedgedDone := make(chan error, 1)
	go func() {
		release, err := reserveUserVMSlotWithCounter(&libvirt.Connect{}, settings, "wedged-count-user", func(string) (int, bool) {
			close(counterEntered)
			<-unblockCounter
			return 0, true
		})
		if err == nil {
			release()
		}
		wedgedDone <- err
	}()
	<-counterEntered

	otherDone := make(chan error, 1)
	go func() {
		release, err := reserveUserVMSlotWithCounter(&libvirt.Connect{}, settings, "unblocked-user", func(string) (int, bool) { return 0, true })
		if err == nil {
			release()
		}
		otherDone <- err
	}()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Fatalf("reserve for other user while a count is wedged: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reservation for another user blocked behind a wedged count")
	}

	close(unblockCounter)
	if err := <-wedgedDone; err != nil {
		t.Fatalf("wedged reservation after unblocking: %v", err)
	}
}

// TestReserveUserVMSlotRefundsReservation proves the pre-count reservation is
// refunded when the check refuses or the count fails; a leaked reservation
// would consume the owner's quota forever.
func TestReserveUserVMSlotRefundsReservation(t *testing.T) {
	settings := bootLimitSettings(t, 1)

	owner := "refund-refused-user"
	if _, err := reserveUserVMSlotWithCounter(
		&libvirt.Connect{},
		settings,
		owner,
		func(string) (int, bool) { return 1, true },
	); !errors.Is(err, ErrVMLimitReached) {
		t.Fatalf("reserve at limit = %v, want ErrVMLimitReached", err)
	}
	if got := inflightReservationsForTest(owner); got != 0 {
		t.Fatalf("in-flight reservations after refusal = %d, want 0", got)
	}

	owner = "refund-error-user"
	if _, err := reserveUserVMSlotWithCounter(
		&libvirt.Connect{},
		settings,
		owner,
		func(string) (int, bool) { return 0, false },
	); err == nil {
		t.Fatal("reserve with failing live count should error")
	}
	if got := inflightReservationsForTest(owner); got != 0 {
		t.Fatalf("in-flight reservations after count error = %d, want 0", got)
	}
}

func TestDefaultNetworkXML(t *testing.T) {
	doc := defaultNetworkXML()

	// Must be well-formed XML so libvirt's NetworkDefineXML accepts it.
	var parsed struct {
		XMLName xml.Name `xml:"network"`
		Name    string   `xml:"name"`
		Forward struct {
			Mode string `xml:"mode,attr"`
		} `xml:"forward"`
		IP struct {
			DHCP struct {
				Range struct {
					Start string `xml:"start,attr"`
					End   string `xml:"end,attr"`
				} `xml:"range"`
			} `xml:"dhcp"`
		} `xml:"ip"`
	}
	if err := xml.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("defaultNetworkXML is not valid XML: %v", err)
	}

	if parsed.Name != defaultNetworkName {
		t.Fatalf("network name = %q, want %q", parsed.Name, defaultNetworkName)
	}
	if parsed.Forward.Mode != "nat" {
		t.Fatalf("forward mode = %q, want nat", parsed.Forward.Mode)
	}
	if parsed.IP.DHCP.Range.Start != "192.168.122.2" {
		t.Fatalf("DHCP range start = %q, want 192.168.122.2", parsed.IP.DHCP.Range.Start)
	}
	if parsed.IP.DHCP.Range.End != "192.168.122.253" {
		t.Fatalf("DHCP range end = %q, want 192.168.122.253", parsed.IP.DHCP.Range.End)
	}
	// The domain XML attaches VDIs to this exact network, so the name must match.
	if !strings.Contains(doc, "<name>"+defaultNetworkName+"</name>") {
		t.Fatalf("expected <name>%s</name> in network XML", defaultNetworkName)
	}
}
