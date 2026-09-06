package virt

import (
	"context"
	"crypto/hmac"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/define42/devbox-gateway/internal/hash"

	"libvirt.org/go/libvirt"
)

// Inventory caches VM metadata in the background for fast read access.
type Inventory struct {
	ticker *time.Ticker
	ctx    context.Context
	cancel context.CancelFunc
	// outstandingSweeps counts sweep goroutines that are still running,
	// including abandoned ones blocked in uncancellable libvirt RPCs; it
	// bounds how many the worker may accumulate (maxOutstandingSweeps).
	outstandingSweeps atomic.Int32
	// spawnSweep overrides how startSweepIfDue launches a sweep goroutine;
	// nil means the inventory's sweep method. Tests inject a fake so tick
	// handling can be driven without a live libvirt connection.
	spawnSweep            func(chan<- sweepOutcome)
	inventoryCacheMu      sync.Mutex
	inventoryHostIdentity inventoryHostIdentity
	metadataByUUID        map[string]domainMetadataSnapshot
	diskByUUID            map[string]domainDiskSnapshot
	mu                    sync.RWMutex
	vms                   []VMInfo
	snapshotSweptAt       time.Time
	nextRDPGeneration     uint64
	nextRDPObservation    atomic.Uint64
	nextSubscriberID      uint64
	subscribers           map[uint64]chan struct{}
}

var (
	inventoryInstance atomic.Pointer[Inventory] //nolint:gochecknoglobals // package-level singleton needed for one-time registration
	inventoryOnce     sync.Once                 //nolint:gochecknoglobals // package-level singleton needed for one-time registration
)

// NewInventory returns the process-wide VM inventory.
func NewInventory() *Inventory {
	inventoryOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		inventory := &Inventory{
			ticker: time.NewTicker(2 * time.Second),
			ctx:    ctx,
			cancel: cancel,
		}
		inventoryInstance.Store(inventory)
		go inventory.run()
	})

	return inventoryInstance.Load()
}

// peekInventory returns the process-wide VM inventory only when NewInventory
// has already started it, and nil otherwise. Callers with a correct non-cache
// path (such as the VM creation quota check) use this so consulting the cache
// never starts the background worker as a side effect; in-package tests rely on
// the worker staying unstarted so their libvirt fixtures remain the only
// observer of domain state.
func peekInventory() *Inventory {
	return inventoryInstance.Load()
}

// Stop stops the background worker ticker and cancels its context.
func (s *Inventory) Stop() {
	s.cancel()
	s.ticker.Stop()
}

// vmQuotaSnapshotMaxAge bounds how old the worker's VM snapshot may be when it
// substitutes for a live per-owner domain count in the creation quota check.
// The worker sweeps every 2 seconds, so a healthy snapshot is well inside this
// bound; a sweep stalled longer than this (for example on a slow or
// unresponsive libvirtd) makes CountVMsOwnedBy report not-authoritative and
// the quota check falls back to counting live libvirt state.
const vmQuotaSnapshotMaxAge = 10 * time.Second

// CountVMsOwnedBy returns the number of cached VMs owned by user, and whether
// that count is authoritative enough for quota decisions: an inventory sweep
// must have completed recently (vmQuotaSnapshotMaxAge) and not been invalidated
// by a libvirt host change. Callers must treat a false result as "count
// unavailable", never as zero.
func (s *Inventory) CountVMsOwnedBy(user string) (int, bool) {
	if strings.TrimSpace(user) == "" {
		return 0, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.snapshotSweptAt.IsZero() || time.Since(s.snapshotSweptAt) > vmQuotaSnapshotMaxAge {
		return 0, false
	}

	count := 0
	for _, vm := range s.vms {
		if vm.Owner == user {
			count++
		}
	}
	return count, true
}

// markVMSnapshotSwept records that the visible VM snapshot was just produced by
// a completed inventory sweep, making it eligible for quota decisions.
func (s *Inventory) markVMSnapshotSwept() {
	s.mu.Lock()
	s.snapshotSweptAt = time.Now()
	s.mu.Unlock()
}

// invalidateVMSnapshot drops the visible VM snapshot and marks it unswept so
// quota decisions stop trusting it until a sweep against the (possibly new)
// libvirt host succeeds. The sweep timestamp is zeroed before the snapshot is
// cleared so a concurrent CountVMsOwnedBy can never judge soon-to-be-dropped
// data as fresh.
func (s *Inventory) invalidateVMSnapshot() {
	s.mu.Lock()
	s.snapshotSweptAt = time.Time{}
	s.mu.Unlock()
	s.setVMs(nil)
}

// VMs returns the cached VMs, optionally filtered by owner. Each returned
// entry's LastUsed is overlaid with the in-memory registry when it has a
// fresher value: the cached snapshot carries the persisted metadata as of the
// domain's first sweep, while the registry records every touch since. The
// overlay happens on the returned copies only — the internal snapshot keeps
// raw sweep data so its change detection is unaffected.
func (s *Inventory) VMs(user string) []VMInfo {
	snapshot := s.snapshotVMs()

	filteredVMs := make([]VMInfo, 0, len(snapshot))
	for _, vm := range snapshot {
		if user != "" && vm.Owner != user {
			continue
		}
		if lastUsed, ok := vmLastUsed.get(vm.Name); ok {
			vm.LastUsed = formatLastUsedTimestamp(lastUsed)
		}
		filteredVMs = append(filteredVMs, vm)
	}
	return filteredVMs
}

// NotifyVMDataChanged wakes the worker's subscribers so they take a fresh
// user-filtered dashboard snapshot. Callers use it for changes such as last-used
// timestamps and base-image availability that do not change the underlying
// sweep snapshot, so setVMs' own change detection would never fire for them.
func (s *Inventory) NotifyVMDataChanged() {
	s.mu.Lock()
	s.notifySubscribersLocked()
	s.mu.Unlock()
}

// VMNames returns the cached VM names.
func (s *Inventory) VMNames() []string {
	snapshot := s.snapshotVMs()

	names := make([]string, 0, len(snapshot))
	for _, vm := range snapshot {
		names = append(names, vm.Name)
	}
	return names
}

// VMIP returns the primary IP address cached for the named VM.
func (s *Inventory) VMIP(vmName string) (string, error) {
	for _, vm := range s.snapshotVMs() {
		if vm.Name == vmName {
			return vm.PrimaryIP, nil
		}
	}
	return "", fmt.Errorf("vm %s not found", vmName)
}

// ResolveVMNameByLabel returns the real VM name whose opaque SNI routing label
// (HMAC-SHA256 of the name, keyed by secret) matches label. Because the label
// is one-way, routing depends on the cached VM list being populated.
func (s *Inventory) ResolveVMNameByLabel(secret []byte, label string) (string, bool) {
	want := []byte(label)
	for _, vm := range s.snapshotVMs() {
		if hmac.Equal([]byte(hash.RoutingLabel(secret, vm.Name)), want) {
			return vm.Name, true
		}
	}
	return "", false
}

func (s *Inventory) snapshotVMs() []VMInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.vms) == 0 {
		return nil
	}

	snapshot := make([]VMInfo, len(s.vms))
	copy(snapshot, s.vms)
	return snapshot
}

// SubscribeVMChanges returns a coalescing notification channel for changes to
// the cached VM snapshot, including asynchronously refreshed RDP readiness. The
// caller must invoke unsubscribe when it no longer needs updates. Notifications
// carry no VM data: subscribers take a fresh, user-filtered snapshot after each
// signal, which prevents one user's VM metadata from being broadcast to another.
func (s *Inventory) SubscribeVMChanges() (<-chan struct{}, func()) {
	updates := make(chan struct{}, 1)

	s.mu.Lock()
	if s.subscribers == nil {
		s.subscribers = make(map[uint64]chan struct{})
	}
	s.nextSubscriberID++
	id := s.nextSubscriberID
	s.subscribers[id] = updates
	s.mu.Unlock()

	var unsubscribeOnce sync.Once
	return updates, func() {
		unsubscribeOnce.Do(func() {
			s.mu.Lock()
			delete(s.subscribers, id)
			close(updates)
			s.mu.Unlock()
		})
	}
}

func (s *Inventory) setVMs(vms []VMInfo) {
	s.mu.Lock()
	next := slices.Clone(vms)
	s.mergeRDPReadinessLocked(next)
	if slices.Equal(s.vms, next) {
		s.mu.Unlock()
		return
	}
	s.vms = next
	s.notifySubscribersLocked()
	s.mu.Unlock()
}

func (s *Inventory) notifySubscribersLocked() {
	for _, updates := range s.subscribers {
		select {
		case updates <- struct{}{}:
		default:
			// A pending notification already tells this subscriber to take the
			// latest snapshot, so intermediate refreshes can be coalesced.
		}
	}
}

// sweepTimeout bounds one inventory sweep. A healthy sweep finishes in well
// under one tick even with hundreds of domains; one that exceeds this bound is
// abandoned — an in-flight cgo RPC cannot be cancelled, so the worker walks
// away from the sweep goroutine and its connection and starts fresh — rather
// than blocking every future sweep behind it.
const sweepTimeout = 30 * time.Second

// maxOutstandingSweeps caps concurrently running sweep goroutines: the current
// one plus abandoned ones still blocked in libvirt. At the cap the worker
// stops starting sweeps instead of accumulating unbounded goroutines and
// connections against an unresponsive libvirtd; capacity frees as soon as any
// blocked sweep returns.
const maxOutstandingSweeps = 4

// sweepOutcome carries everything one inventory sweep produced. The sweep
// goroutine mutates no shared worker state itself; the worker loop applies an
// outcome only when the sweep that produced it has not been abandoned.
type sweepOutcome struct {
	identity inventoryHostIdentity
	vms      []VMInfo
	metadata map[string]domainMetadataSnapshot
	disks    map[string]domainDiskSnapshot
	err      error
}

// inflightSweep tracks the one sweep the worker loop currently waits on.
type inflightSweep struct {
	outcome chan sweepOutcome
	started time.Time
}

// done returns the channel delivering the in-flight sweep's outcome, or a nil
// channel — blocking forever in a select — when no sweep is in flight.
func (f *inflightSweep) done() <-chan sweepOutcome {
	if f == nil {
		return nil
	}
	return f.outcome
}

func (s *Inventory) run() {
	log.Println("vm inventory worker started")

	var inflight *inflightSweep
	for {
		select {
		case res := <-inflight.done():
			inflight = nil
			s.applySweep(res)
		case <-s.ticker.C:
			inflight = s.startSweepIfDue(inflight)
		case <-s.ctx.Done():
			// An in-flight sweep finishes on its own: its outcome channel is
			// buffered and it closes its own connection.
			log.Println("vm inventory worker stopped")
			return
		}
	}
}

// startSweepIfDue decides what one ticker tick does: keep waiting on a healthy
// in-flight sweep, abandon one that exceeded sweepTimeout, and start the next
// sweep unless too many earlier ones are still blocked in libvirt. Dropping an
// abandoned sweep's inflightSweep is what guarantees its stale outcome is
// never applied: the worker no longer holds the only reference to the channel
// it will report on.
func (s *Inventory) startSweepIfDue(current *inflightSweep) *inflightSweep {
	if current != nil {
		if time.Since(current.started) < sweepTimeout {
			return current
		}
		log.Printf("inventory sweep still running after %v; abandoning it and starting fresh", sweepTimeout)
	}

	if outstanding := s.outstandingSweeps.Load(); outstanding >= maxOutstandingSweeps {
		log.Printf("%d inventory sweeps still blocked in libvirt; not starting another", outstanding)
		return nil
	}

	next := &inflightSweep{outcome: make(chan sweepOutcome, 1), started: time.Now()}
	spawn := s.spawnSweep
	if spawn == nil {
		spawn = s.sweep
	}
	go spawn(next.outcome)
	return next
}

// sweep runs one full inventory collection against its own libvirt connection
// and reports the outcome without touching shared worker state. Owning the
// connection matters: when the worker abandons a sweep stuck in an
// uncancellable RPC, nothing else holds the same socket, so the next sweep
// starts on a fresh connection immediately while this goroutine keeps
// blocking until libvirt gives up.
func (s *Inventory) sweep(outcome chan<- sweepOutcome) {
	s.outstandingSweeps.Add(1)
	defer s.outstandingSweeps.Add(-1)

	conn, err := connectLibvirt()
	if err != nil {
		outcome <- sweepOutcome{err: fmt.Errorf("list vms connect: %w", err)}
		return
	}
	defer func() {
		_, _ = conn.Close()
	}()

	// Identify the host before trusting anything collected from it. On
	// failure, retain the existing snapshots and retry next tick so a
	// transient identity lookup cannot trigger a cold inventory read or mix
	// snapshots from different hosts.
	identity, err := loadInventoryHostIdentity(conn.GetURI, conn.GetCapabilities, conn.GetHostname)
	if err != nil {
		outcome <- sweepOutcome{err: fmt.Errorf("libvirt inventory host identity unavailable; retaining inventory caches and retrying: %w", err)}
		return
	}

	vms, metadata, disks, err := s.collectInventory(conn)
	if err != nil {
		outcome <- sweepOutcome{err: err}
		return
	}
	outcome <- sweepOutcome{identity: identity, vms: vms, metadata: metadata, disks: disks}
}

// applySweep publishes a completed sweep's results. Outcomes of abandoned
// sweeps never reach here — the worker dropped their channel — so data that
// is minutes stale, or was collected against a previous libvirt host, is
// discarded unread.
func (s *Inventory) applySweep(res sweepOutcome) {
	if res.err != nil {
		log.Printf("vm inventory list vms: %v", res.err)
		return
	}

	previous, invalidated := s.setInventoryHostIdentity(res.identity)
	if invalidated {
		// The sweep collected against cache state from the previous identity,
		// so its results cannot be attributed to the new host. The identity
		// change has already cleared the caches and the visible snapshot; the
		// next tick sweeps the new host from scratch.
		if previous == (inventoryHostIdentity{}) {
			log.Printf("libvirt inventory host identity established as %s; clearing unverified inventory caches and discarding the sweep collected before it", res.identity)
		} else {
			log.Printf("libvirt inventory host changed from %s to %s; clearing inventory caches and discarding the sweep collected across the change", previous, res.identity)
		}
		return
	}

	s.publishInventory(res.vms, res.metadata, res.disks)
}

// publishInventory installs a sweep's results: the UUID-keyed inventory
// caches, the visible VM snapshot, and the quota freshness stamp.
func (s *Inventory) publishInventory(
	vms []VMInfo,
	metadata map[string]domainMetadataSnapshot,
	disks map[string]domainDiskSnapshot,
) {
	s.inventoryCacheMu.Lock()
	s.metadataByUUID = metadata
	s.diskByUUID = disks
	s.inventoryCacheMu.Unlock()
	s.setVMs(vms)
	s.markVMSnapshotSwept()
}

// doWork runs one synchronous inventory sweep on conn and publishes the
// result unconditionally. The background worker goes through
// startSweepIfDue/sweep/applySweep instead so a stalled sweep can be
// abandoned; this synchronous form is the seam tests use to drive the worker
// against fixture connections.
func (s *Inventory) doWork(conn *libvirt.Connect) error {
	if conn == nil {
		return fmt.Errorf("libvirt connection is nil")
	}

	vms, metadata, disks, err := s.collectInventory(conn)
	if err != nil {
		return err
	}
	s.publishInventory(vms, metadata, disks)
	return nil
}

// collectInventory lists all domains on conn, reusing the UUID-keyed metadata
// and disk caches, and returns the fresh VM snapshot plus the cache entries to
// retain. It mutates no worker state: abandoned sweeps may still be running
// one of these concurrently with the current one, so installing the results
// is the caller's decision (applySweep for the worker, doWork for tests).
func (s *Inventory) collectInventory(conn *libvirt.Connect) (
	[]VMInfo,
	map[string]domainMetadataSnapshot,
	map[string]domainDiskSnapshot,
	error,
) {
	// Copy under the cache lock so libvirt calls never block unrelated cache
	// maintenance; the retained maps are installed only after a successful
	// full-domain listing, and only if the sweep is still current.
	s.inventoryCacheMu.Lock()
	previousMetadata := maps.Clone(s.metadataByUUID)
	previousDisks := maps.Clone(s.diskByUUID)
	s.inventoryCacheMu.Unlock()
	metadataSweep := newDomainMetadataCacheSweep(previousMetadata)
	diskSweep := newDomainDiskCacheSweep(previousDisks)
	vms, err := listVMsWithInventoryResolvers(
		"",
		conn,
		func(name string, d *libvirt.Domain) (domainMetadataSnapshot, string) {
			domainUUID := domainUUIDForInventoryCache(name, d)
			metadata, loadErr := metadataSweep.load(domainUUID, func() (domainMetadataSnapshot, error) {
				return loadDomainMetadataSnapshot(d.GetXMLDesc)
			})
			if loadErr != nil {
				log.Printf("domain metadata %s: %v", name, loadErr)
				return domainMetadataSnapshot{}, domainUUID
			}
			return metadata, domainUUID
		},
		func(domainUUID string, d *libvirt.Domain) domainDiskSnapshot {
			disk, loadErr := diskSweep.load(domainUUID, func() (domainDiskSnapshot, error) {
				return loadDomainDiskSnapshot(d.GetBlockInfo)
			})
			if loadErr != nil {
				return domainDiskSnapshot{}
			}
			return disk
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return vms, metadataSweep.retainedEntries(), diskSweep.retainedEntries(), nil
}
