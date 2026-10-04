package virt

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

func quotaLimitSettings(t *testing.T, limit int) *config.Settings {
	t.Helper()
	settings := config.NewSettings(false)
	if err := settings.OverwriteForTestInt(config.MAX_VDI_PER_USER, limit); err != nil {
		t.Fatalf("overwrite MAX_VDI_PER_USER: %v", err)
	}
	return settings
}

func TestReserveUserVMSlotCountsLiveDomainsAndReservations(t *testing.T) {
	settings := quotaLimitSettings(t, 2)
	owner := t.Name()
	count := func(string) (int, error) { return 1, nil }
	release, err := reserveUserVMSlotWithCounter(settings, owner, count)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	if _, err := reserveUserVMSlotWithCounter(settings, owner, count); !errors.Is(err, ErrVMLimitReached) {
		t.Fatalf("reserve at limit = %v, want ErrVMLimitReached", err)
	}

	// Failed provisioning releases its reservation, allowing a replacement.
	release()
	replacement, err := reserveUserVMSlotWithCounter(settings, owner, count)
	if err != nil {
		t.Fatalf("reserve after rollback: %v", err)
	}
	t.Cleanup(replacement)
	// Retrying a release must not steal a newer reservation.
	release()
	if _, err := reserveUserVMSlotWithCounter(settings, owner, count); !errors.Is(err, ErrVMLimitReached) {
		t.Fatalf("reserve after duplicate release = %v, want ErrVMLimitReached", err)
	}
}

func TestReserveUserVMSlotRejectsCompletedCreatesDespiteFreshEmptyInventory(t *testing.T) {
	conn := quotaTestConnection(t)
	settings := quotaLimitSettings(t, 1)
	owner := t.Name()
	worker := &Inventory{}
	worker.markVMSnapshotSwept()
	previous := inventoryInstance.Swap(worker)
	t.Cleanup(func() { inventoryInstance.Store(previous) })

	created := 0
	var dom *libvirt.Domain
	for attempt := range 5 {
		release, err := reserveUserVMSlot(conn, settings, owner)
		if errors.Is(err, ErrVMLimitReached) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
		dom = quotaDefineDomain(t, conn, fmt.Sprintf("quota-completed-%d", attempt), owner)
		created++
		release()
	}
	if created != 1 {
		t.Fatalf("created %d VMs against one unchanged empty snapshot; want 1", created)
	}
	if count, fresh := worker.CountVMsOwnedBy(owner); count != 0 || !fresh {
		t.Fatalf("inventory unexpectedly changed: (%d, %v)", count, fresh)
	}

	// Deletion frees the slot immediately, even if the dashboard still lists it.
	worker.setVMs([]VMInfo{{Name: "quota-completed-0", Owner: owner}})
	if err := dom.Undefine(); err != nil {
		t.Fatal(err)
	}
	release, err := reserveUserVMSlot(conn, settings, owner)
	if err != nil {
		t.Fatalf("reserve after deleting the completed VM: %v", err)
	}
	release()
}

func TestReserveUserVMSlotConcurrentAdmission(t *testing.T) {
	settings := quotaLimitSettings(t, 3)
	owner := t.Name()
	type result struct {
		release func()
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, 20)
	for range cap(results) {
		go func() {
			<-start
			release, err := reserveUserVMSlotWithCounter(settings, owner, func(string) (int, error) { return 0, nil })
			results <- result{release: release, err: err}
		}()
	}
	close(start)
	admitted := 0
	for range cap(results) {
		got := <-results
		if got.err == nil {
			admitted++
			t.Cleanup(got.release)
		} else if !errors.Is(got.err, ErrVMLimitReached) {
			t.Errorf("unexpected admission error: %v", got.err)
		}
	}
	if admitted != 3 {
		t.Fatalf("admitted %d concurrent creations, want 3", admitted)
	}
}

func TestReserveUserVMSlotReleaseWaitsForLiveScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		settings := quotaLimitSettings(t, 1)
		owner := t.Name()
		release, err := reserveUserVMSlotWithCounter(settings, owner, func(string) (int, error) { return 0, nil })
		if err != nil {
			t.Fatal(err)
		}
		counterEntered := make(chan struct{})
		finishCount := make(chan struct{})
		admitted := make(chan error, 1)
		go func() {
			nextRelease, err := reserveUserVMSlotWithCounter(settings, owner, func(string) (int, error) {
				close(counterEntered)
				<-finishCount
				return 0, nil
			})
			if err == nil {
				nextRelease()
			}
			admitted <- err
		}()
		<-counterEntered
		// The initial creation completes after the live scan enumerates domains.
		// Its reservation must survive until that scan's decision is finished.
		released := make(chan struct{})
		go func() { release(); close(released) }()
		synctest.Wait()
		select {
		case <-released:
			t.Error("completed creation released its slot during an older live scan")
		default:
		}
		close(finishCount)
		if err := <-admitted; !errors.Is(err, ErrVMLimitReached) {
			t.Errorf("admission during completion = %v, want ErrVMLimitReached", err)
		}
		<-released
	})
}

func TestReserveUserVMSlotDoesNotHoldGlobalMutexWhileCounting(t *testing.T) {
	settings := quotaLimitSettings(t, 1)
	counterEntered := make(chan struct{})
	unblockCounter := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(unblockCounter) })
	defer unblock()
	wedgedDone := make(chan error, 1)
	go func() {
		release, err := reserveUserVMSlotWithCounter(settings, "wedged-count-user", func(string) (int, error) {
			close(counterEntered)
			<-unblockCounter
			return 0, nil
		})
		if err == nil {
			release()
		}
		wedgedDone <- err
	}()
	<-counterEntered
	otherDone := make(chan error, 1)
	go func() {
		release, err := reserveUserVMSlotWithCounter(settings, "unblocked-user", func(string) (int, error) { return 0, nil })
		if err == nil {
			release()
		}
		otherDone <- err
	}()
	select {
	case err := <-otherDone:
		if err != nil {
			t.Errorf("reserve for another owner: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("reservation for another owner blocked behind a wedged count")
	}
	unblock()
	if err := <-wedgedDone; err != nil {
		t.Fatalf("wedged reservation after unblocking: %v", err)
	}
}

func TestReserveUserVMSlotCountFailureDoesNotConsumeSlot(t *testing.T) {
	settings := quotaLimitSettings(t, 1)
	owner := t.Name()
	countErr := errors.New("owner metadata unreadable")
	if _, err := reserveUserVMSlotWithCounter(settings, owner, func(string) (int, error) { return 0, countErr }); !errors.Is(err, countErr) {
		t.Fatalf("admission with incomplete count = %v, want %v", err, countErr)
	}
	release, err := reserveUserVMSlotWithCounter(settings, owner, func(string) (int, error) { return 0, nil })
	if err != nil {
		t.Fatalf("reserve after recovering live count: %v", err)
	}
	release()
}

func TestReserveUserVMSlotNormalizesOwner(t *testing.T) {
	settings := quotaLimitSettings(t, 1)
	owner := t.Name()
	count := func(got string) (int, error) {
		if got != owner {
			t.Errorf("count owner = %q, want %q", got, owner)
		}
		return 0, nil
	}
	release, err := reserveUserVMSlotWithCounter(settings, " "+owner+" ", count)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	if _, err := reserveUserVMSlotWithCounter(settings, owner, count); !errors.Is(err, ErrVMLimitReached) {
		t.Fatalf("equivalent owner bypassed quota: %v", err)
	}
	if _, err := reserveUserVMSlotWithCounter(settings, " ", count); err == nil {
		t.Fatal("empty owner admitted")
	}
}

func TestCountDomainsOwnedByFailsClosedOnUnreadableMetadata(t *testing.T) {
	conn := quotaTestConnection(t)
	dom := quotaDefineDomain(t, conn, "quota-bad-owner", "alice")
	// Valid XML with the wrong root element is unreadable as owner metadata.
	if err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, "<invalid>alice</invalid>", domainOwnerMetadataPrefix,
		domainOwnerMetadataNamespace, libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
		t.Fatal(err)
	}
	if _, err := countDomainsOwnedBy(conn, "alice"); err == nil || !strings.Contains(err.Error(), "read domain owner") {
		t.Fatalf("count with unreadable owner metadata = %v, want error", err)
	}
}

// The libvirt test driver is in-process and never accesses the host hypervisor.
func quotaTestConnection(t *testing.T) *libvirt.Connect {
	t.Helper()
	conn, err := libvirt.NewConnect("test:///default")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.Close() })
	return conn
}

func quotaDefineDomain(t *testing.T, conn *libvirt.Connect, name, owner string) *libvirt.Domain {
	t.Helper()
	dom, err := conn.DomainDefineXML("<domain type='test'><name>" + name +
		"</name><memory>1024</memory><vcpu>1</vcpu><os><type>hvm</type></os></domain>")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dom.Undefine(); _ = dom.Free() })
	if err := setDomainOwnerMetadata(dom, owner); err != nil {
		t.Fatal(err)
	}
	return dom
}
