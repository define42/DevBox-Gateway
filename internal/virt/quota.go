package virt

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

// ErrVMLimitReached indicates the requesting user already owns the maximum
// number of VDIs allowed by MAX_VDI_PER_USER, so creation is refused until the
// user deletes one.
var ErrVMLimitReached = errors.New("virt: vm limit reached")

// vmCreationMu guards inflightVMCreations, which tracks creations that have
// reserved a MAX_VDI_PER_USER slot but not yet persisted owner metadata (which
// only happens inside StartVM, late in BootNewVM). Counting existing
// domains alone would let two concurrent creates for the same user both pass
// the check before either domain exists; reserving a slot under the mutex and
// holding it until BootNewVM returns closes that race. The mutex is only ever
// held for map access — never across a libvirt call — so a wedged libvirtd
// cannot turn it into a gateway-wide creation stall (see reserveUserVMSlot).
var (
	vmCreationMu        sync.Mutex             //nolint:gochecknoglobals // process-wide reservation state for the per-user VM limit
	inflightVMCreations = make(map[string]int) //nolint:gochecknoglobals // process-wide reservation state for the per-user VM limit
)

// reserveUserVMSlot refuses creation when the owner already has as many VDIs as
// MAX_VDI_PER_USER allows, counting both existing domains and creations still
// in flight. The existing-domain count comes from the background worker's
// cached snapshot when that snapshot is fresh — the same owner-filtered view
// the dashboard shows, so the enforced count matches what the user sees without
// an O(domains) libvirt scan per create. When the worker is not running or its
// snapshot is stale, the count falls back to live libvirt state. On success it
// reserves a creation slot; the caller must invoke the returned release exactly
// once, after the domain (with its owner metadata) exists or the creation
// failed. A limit of 0 (configured <=0) disables the check and returns a no-op
// release.
//
// Using the cached snapshot makes the limit eventually consistent at its edges:
// a VM whose creation completed within the last sweep interval (~2s) is covered
// neither by the snapshot nor by the in-flight reservation (already released),
// so a create racing that window can overshoot the limit by one; conversely a
// VM deleted within the last sweep interval still counts, so a create can be
// transiently refused until the next sweep. Both windows are bounded by
// vmQuotaSnapshotMaxAge and self-heal; the in-flight reservations still make
// concurrent creates race-free.
//
// The reservation is taken BEFORE counting, and vmCreationMu is never held
// across the count: the live fallback issues libvirt RPCs, and it runs
// precisely when the worker snapshot is stale — that is, when libvirtd is
// already slow or wedged. Holding the process-wide mutex across one hung RPC
// there would stall VM creation for every user until restart; with the mutex
// released, a wedged fallback fails only its own request once keepalive kills
// the connection (see connectLibvirt).
func reserveUserVMSlot(conn *libvirt.Connect, settings *config.Settings, owner string) (release func(), err error) {
	return reserveUserVMSlotWithCounter(conn, settings, owner, cachedVMCountForQuota)
}

// cachedVMCountForQuota returns the worker's cached per-owner VM count. It
// deliberately peeks at the process-wide inventory instead of starting it:
// when the worker is not running (or its snapshot is stale) the second result
// is false and the quota check counts live libvirt state instead.
func cachedVMCountForQuota(owner string) (int, bool) {
	worker := peekInventory()
	if worker == nil {
		return 0, false
	}
	return worker.CountVMsOwnedBy(owner)
}

func reserveUserVMSlotWithCounter(
	conn *libvirt.Connect,
	settings *config.Settings,
	owner string,
	cachedCount func(string) (int, bool),
) (release func(), err error) {
	limit := config.MaxVDIPerUser(settings)
	if limit <= 0 {
		return func() {}, nil
	}

	// Reserve first, count after. The increment is atomic with reading the
	// in-flight total, but the mutex is released before counting so a hung
	// libvirt RPC in the live fallback can never block other users' creates
	// (see the reserveUserVMSlot doc). The reservation is refunded on refusal
	// or count failure.
	vmCreationMu.Lock()
	inflightVMCreations[owner]++
	inflightIncludingThis := inflightVMCreations[owner]
	vmCreationMu.Unlock()
	release = func() { releaseUserVMSlot(owner) }

	count, counted := cachedCount(owner)
	if !counted {
		count, err = countDomainsOwnedBy(conn, owner)
		if err != nil {
			release()
			return nil, fmt.Errorf("count vms owned by %s: %w", owner, err)
		}
	}
	// Reservations concurrently live for one owner observe strictly increasing
	// in-flight totals (each increment happens under vmCreationMu after the
	// earlier ones), so of k racing creates at most limit-count pass — the same
	// guarantee the fully locked check-and-reserve gave. A reservation released
	// after refusal or a failed create can transiently refuse a racing create
	// that would have fit; that is the same bounded, self-healing edge as the
	// snapshot staleness documented on reserveUserVMSlot.
	if have := count + inflightIncludingThis - 1; have >= limit {
		release()
		return nil, fmt.Errorf("%w: user %s already has %d of %d allowed vms (including creations in progress)", ErrVMLimitReached, owner, have, limit)
	}
	return release, nil
}

func releaseUserVMSlot(owner string) {
	vmCreationMu.Lock()
	defer vmCreationMu.Unlock()

	if inflightVMCreations[owner] <= 1 {
		delete(inflightVMCreations, owner)
		return
	}
	inflightVMCreations[owner]--
}

// countDomainsOwnedBy counts domains whose owner metadata matches username by
// scanning live libvirt state. It is the quota check's fallback for when the
// background worker's cached snapshot is unavailable or stale; the scan costs
// one metadata read per domain, so the cached count is preferred. A domain
// whose metadata cannot be read is logged and skipped, mirroring how the
// dashboard listing treats it (not attributed to any user).
func countDomainsOwnedBy(conn *libvirt.Connect, username string) (int, error) {
	doms, err := conn.ListAllDomains(0)
	if err != nil {
		return 0, fmt.Errorf("list domains: %w", err)
	}
	defer freeDomains(doms)

	count := 0
	for i := range doms {
		owner, hasOwner, err := domainOwner(&doms[i])
		if err != nil {
			log.Printf("domain owner while counting VMs: %v", err)
			continue
		}
		if ownedByUser(owner, hasOwner, username) {
			count++
		}
	}
	return count, nil
}
