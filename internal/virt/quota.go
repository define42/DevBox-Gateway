package virt

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

// ErrVMLimitReached indicates the requesting user already owns the maximum
// number of VDIs allowed by MAX_VDI_PER_USER, so creation is refused until the
// user deletes one.
var ErrVMLimitReached = errors.New("virt: vm limit reached")

// vmQuotaOwnerLocks serializes admission and reservation release for each owner.
// vmCreationMu protects only map access, so a slow libvirt count for one owner
// never holds a process-wide lock or stalls other owners' quota operations.
var (
	vmQuotaOwnerLocks   = newKeyedMutex()      //nolint:gochecknoglobals // process-wide per-owner quota admission serialization
	vmCreationMu        sync.Mutex             //nolint:gochecknoglobals // process-wide reservation state for the per-user VM limit
	inflightVMCreations = make(map[string]int) //nolint:gochecknoglobals // process-wide reservation state for the per-user VM limit
)

// reserveUserVMSlot refuses creation when the owner already has as many VDIs as
// MAX_VDI_PER_USER allows, counting both existing domains and creations still
// in flight. Admission always reads live libvirt ownership: the dashboard's
// inventory can omit a newly completed creation even while its snapshot is
// fresh. On success the caller must invoke release after the domain and its
// owner metadata exist, or after a failed creation has been rolled back. A
// limit of 0 (configured <=0) disables the check and returns a no-op release.
//
// The owner's lock covers both the scan and the reservation decision. Release
// takes the same lock, so a completed creation is either still reserved while
// the scan runs or visible to a scan that starts after release. An in-flight
// creation whose domain is already visible may temporarily count twice; this
// can conservatively refuse a request until that creation finishes.
//
// Callers holding a VM-name lock acquire this owner lock inside it. Quota
// operations never acquire VM-name locks, preserving the lifecycle lock order.
func reserveUserVMSlot(conn *libvirt.Connect, settings *config.Settings, owner string) (release func(), err error) {
	return reserveUserVMSlotWithCounter(settings, owner, func(owner string) (int, error) {
		return countDomainsOwnedBy(conn, owner)
	})
}

func reserveUserVMSlotWithCounter(
	settings *config.Settings,
	owner string,
	countOwned func(string) (int, error),
) (release func(), err error) {
	limit := config.MaxVDIPerUser(settings)
	if limit <= 0 {
		return func() {}, nil
	}

	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, errors.New("virt: VM quota requires a non-empty owner")
	}
	unlockOwner := vmQuotaOwnerLocks.Lock(owner)
	defer unlockOwner()

	count, err := countOwned(owner)
	if err != nil {
		return nil, fmt.Errorf("count vms owned by %s: %w", owner, err)
	}
	vmCreationMu.Lock()
	defer vmCreationMu.Unlock()
	if have := count + inflightVMCreations[owner]; have >= limit {
		return nil, fmt.Errorf("%w: user %s already has %d of %d allowed vms (including creations in progress)", ErrVMLimitReached, owner, have, limit)
	}
	inflightVMCreations[owner]++
	return sync.OnceFunc(func() { releaseUserVMSlot(owner) }), nil
}

func releaseUserVMSlot(owner string) {
	unlockOwner := vmQuotaOwnerLocks.Lock(owner)
	defer unlockOwner()

	vmCreationMu.Lock()
	defer vmCreationMu.Unlock()

	if inflightVMCreations[owner] <= 1 {
		delete(inflightVMCreations, owner)
		return
	}
	inflightVMCreations[owner]--
}

// countDomainsOwnedBy counts domains whose owner metadata matches username by
// scanning live libvirt state. Domains without owner metadata are unrelated to
// the quota. Other metadata errors fail admission closed because skipping an
// unreadable owner could undercount existing VMs.
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
			return 0, fmt.Errorf("read domain owner while counting VMs: %w", err)
		}
		if ownedByUser(owner, hasOwner, username) {
			count++
		}
	}
	return count, nil
}
