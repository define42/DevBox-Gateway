package virt

import (
	"context"
	"crypto/hmac"
	"devboxgateway/internal/hash"
	"fmt"
	"log"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"libvirt.org/go/libvirt"
)

// defaultNetworkRoutingCIDR is the subnet of the libvirt 'default' NAT network
// the gateway defines in defaultNetworkXML (192.168.122.1/24). Backend RDP
// routing is constrained to this range as defense in depth: only an address the
// gateway's own DHCP server leased inside this subnet is trusted as a dial
// target. A guest cannot forge such a lease, so a rooted guest cannot steer the
// proxy at an off-network host (e.g. via a future qemu-guest-agent channel or ARP
// cache poisoning) and turn the gateway into an SSRF pivot. Keep this in sync
// with defaultNetworkXML.
const defaultNetworkRoutingCIDR = "192.168.122.0/24"

const (
	rdpPort                  = "3389"
	rdpReadinessProbeTimeout = 500 * time.Millisecond
)

// VMInfo describes a VM entry shown in the dashboard and worker cache.
type VMInfo struct {
	Name           string
	Owner          string
	GuestUser      string
	BaseImage      string
	CreatedAt      string
	State          string
	MemoryMiB      int
	VCPU           int
	VolumeGB       int
	VolumeUsedGB   int
	IP             string
	PrimaryIP      string
	RDPReady       bool
	rdpGeneration  uint64
	rdpObservation uint64
}

type (
	inventoryMetadataResolver func(string, *libvirt.Domain) (domainMetadataSnapshot, string)
	inventoryDiskResolver     func(string, *libvirt.Domain) domainDiskSnapshot
)

// ListVMs returns persistent VMs visible to the given user from the provided
// libvirt connection. Gateway-managed VDIs are persistent, and limiting the
// inventory here keeps its inactive-XML metadata semantics aligned with the
// config-only direct metadata helpers without an IsPersistent call per domain.
func ListVMs(user string, conn *libvirt.Connect) ([]VMInfo, error) {
	return listVMsWithInventoryResolvers(
		user,
		conn,
		func(name string, d *libvirt.Domain) (domainMetadataSnapshot, string) {
			return domainMetadataForVMInfo(name, d), ""
		},
		func(_ string, d *libvirt.Domain) domainDiskSnapshot {
			usedGB, totalGB := domainDiskGB(*d)
			return domainDiskSnapshot{UsedGB: usedGB, TotalGB: totalGB}
		},
	)
}

func listVMsWithInventoryResolvers(
	user string,
	conn *libvirt.Connect,
	resolveMetadata inventoryMetadataResolver,
	resolveDisk inventoryDiskResolver,
) ([]VMInfo, error) {
	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_PERSISTENT)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}
	defer freeDomains(doms)

	var result []VMInfo
	for _, d := range doms {
		info, ok := domainVMInfoWithInventoryResolvers(d, user, resolveMetadata, resolveDisk)
		if ok {
			result = append(result, info)
		}
	}
	return result, nil
}

func freeDomains(doms []libvirt.Domain) {
	for _, d := range doms {
		_ = d.Free()
	}
}

func domainVMInfo(d libvirt.Domain, user string) (VMInfo, bool) {
	return domainVMInfoWithInventoryResolvers(
		d,
		user,
		func(name string, d *libvirt.Domain) (domainMetadataSnapshot, string) {
			return domainMetadataForVMInfo(name, d), ""
		},
		func(_ string, d *libvirt.Domain) domainDiskSnapshot {
			usedGB, totalGB := domainDiskGB(*d)
			return domainDiskSnapshot{UsedGB: usedGB, TotalGB: totalGB}
		},
	)
}

func domainVMInfoWithInventoryResolvers(
	d libvirt.Domain,
	user string,
	resolveMetadata inventoryMetadataResolver,
	resolveDisk inventoryDiskResolver,
) (VMInfo, bool) {
	name, err := d.GetName()
	if err != nil {
		log.Printf("domain name: %v", err)
		return VMInfo{}, false
	}

	metadata, domainUUID := resolveMetadata(name, &d)
	if user != "" && metadata.Owner != user {
		return VMInfo{}, false
	}

	state, _, err := d.GetState()
	if err != nil {
		log.Printf("domain state %s: %v", name, err)
		return VMInfo{}, false
	}

	mem, vcpu := domainResources(d)
	ip, primaryIP := domainDisplayIPs(d, state)
	disk := resolveDisk(domainUUID, &d)
	return VMInfo{
		Name:         name,
		Owner:        metadata.Owner,
		GuestUser:    metadata.GuestUser,
		BaseImage:    metadata.BaseImage,
		CreatedAt:    metadata.CreatedAt,
		State:        formatState(state),
		MemoryMiB:    mem,
		VCPU:         vcpu,
		VolumeGB:     disk.TotalGB,
		VolumeUsedGB: disk.UsedGB,
		IP:           ip,
		PrimaryIP:    primaryIP,
	}, true
}

// domainUUIDForInventoryCache reads UUID state from the local libvirt domain
// handle; virDomainGetUUIDString does not add a daemon RPC to the inventory.
func domainUUIDForInventoryCache(name string, d *libvirt.Domain) string {
	domainUUID, err := d.GetUUIDString()
	if err != nil {
		log.Printf("domain UUID %s: %v", name, err)
		return ""
	}
	return strings.TrimSpace(domainUUID)
}

// domainDisplayIPs returns (display, routing). The display string aggregates
// the lease- and ARP-reported addresses for the dashboard, while the routing
// address — the one the RDP proxy actually dials — comes only from the
// authoritative DHCP lease: it reflects what the gateway's own dnsmasq
// assigned, which a guest cannot forge, and it must fall inside the default
// NAT subnet or routing fails closed (empty result) rather than dialing an
// off-network host. The qemu-guest-agent source is deliberately not queried:
// agent commands run with an unbounded response timeout by default, so a guest
// whose agent stops answering would wedge the inventory sweep that calls this
// for every running domain.
func domainDisplayIPs(d libvirt.Domain, state libvirt.DomainState) (string, string) {
	if !domainCanReportIPs(state) {
		return "", ""
	}

	seen := make(map[string]struct{})
	leaseIPs := appendDomainIPsFromSource(nil, seen, d, libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
	routingIP := firstRoutableVMIP(leaseIPs)
	ips := appendDomainIPsFromSource(leaseIPs, seen, d, libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_ARP)
	return strings.Join(ips, ", "), routingIP
}

// firstRoutableVMIP returns the first address in ips that is an IPv4 address
// inside the default NAT subnet, or "" when none qualifies.
func firstRoutableVMIP(ips []string) string {
	for _, ip := range ips {
		if ipInDefaultNetwork(ip) {
			return ip
		}
	}
	return ""
}

// ipInDefaultNetwork reports whether addr is an IPv4 address within the libvirt
// default NAT subnet (defaultNetworkRoutingCIDR).
func ipInDefaultNetwork(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil || ip.To4() == nil {
		return false
	}
	_, subnet, err := net.ParseCIDR(defaultNetworkRoutingCIDR)
	if err != nil {
		return false
	}
	return subnet.Contains(ip)
}

func domainCanReportIPs(state libvirt.DomainState) bool {
	switch state {
	case libvirt.DOMAIN_RUNNING, libvirt.DOMAIN_PAUSED, libvirt.DOMAIN_PMSUSPENDED:
		return true
	case libvirt.DOMAIN_NOSTATE, libvirt.DOMAIN_BLOCKED, libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_CRASHED, libvirt.DOMAIN_SHUTOFF:
		return false
	default:
		return false
	}
}

func tcpEndpointReady(address string, timeout time.Duration) bool {
	return tcpEndpointReadyContext(context.Background(), address, timeout)
}

func tcpEndpointReadyContext(ctx context.Context, address string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func domainResources(d libvirt.Domain) (int, int) {
	info, err := d.GetInfo()
	if err != nil {
		log.Printf("domain info: %v", err)
		return 0, 0
	}
	memMiB := int(info.Memory / 1024)
	return memMiB, int(info.NrVirtCpu)
}

// domainDiskGB returns the primary disk's used and total sizes in GiB. total is
// the virtual capacity the guest sees (the configured VM_DISK_SIZE_GB); used is
// the bytes the thin-provisioned qcow2 actually occupies on the host. Either is
// 0 when libvirt cannot report it.
func domainDiskGB(d libvirt.Domain) (used int, total int) {
	disk, err := loadDomainDiskSnapshot(d.GetBlockInfo)
	if err != nil {
		return 0, 0
	}
	return disk.UsedGB, disk.TotalGB
}

func bytesToGiBCeil(b uint64) int {
	if b == 0 {
		return 0
	}
	return int((b + (1 << 30) - 1) >> 30)
}

func appendDomainIPsFromSource(ips []string, seen map[string]struct{}, d libvirt.Domain, src libvirt.DomainInterfaceAddressesSource) []string {
	ifaces, err := d.ListAllInterfaceAddresses(src)
	if err != nil {
		return ips
	}

	for _, iface := range ifaces {
		ips = appendDomainInterfaceIPs(ips, seen, iface)
	}
	return ips
}

func appendDomainInterfaceIPs(ips []string, seen map[string]struct{}, iface libvirt.DomainInterface) []string {
	for _, addr := range iface.Addrs {
		ips = appendUniqueDomainIP(ips, seen, addr.Addr)
	}
	return ips
}

func appendUniqueDomainIP(ips []string, seen map[string]struct{}, addr string) []string {
	if addr == "" {
		return ips
	}
	if _, ok := seen[addr]; ok {
		return ips
	}
	seen[addr] = struct{}{}
	return append(ips, addr)
}

func formatState(state libvirt.DomainState) string {
	switch state {
	case libvirt.DOMAIN_NOSTATE:
		return "unknown"
	case libvirt.DOMAIN_BLOCKED:
		return "blocked"
	case libvirt.DOMAIN_RUNNING:
		return "running"
	case libvirt.DOMAIN_PAUSED:
		return "paused"
	case libvirt.DOMAIN_SHUTDOWN, libvirt.DOMAIN_SHUTOFF:
		return "shut off"
	case libvirt.DOMAIN_CRASHED:
		return "crashed"
	case libvirt.DOMAIN_PMSUSPENDED:
		return "suspended"
	default:
		return fmt.Sprintf("unknown (%d)", state)
	}
}

// SingletonWorker caches VM metadata in the background for fast read access.
type SingletonWorker struct {
	ticker *time.Ticker
	ctx    context.Context
	cancel context.CancelFunc
	// outstandingSweeps counts sweep goroutines that are still running,
	// including abandoned ones blocked in uncancellable libvirt RPCs; it
	// bounds how many the worker may accumulate (maxOutstandingSweeps).
	outstandingSweeps atomic.Int32
	// spawnSweep overrides how startSweepIfDue launches a sweep goroutine;
	// nil means s.sweep. Tests inject a fake so tick handling can be driven
	// without a live libvirt connection.
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
func (s *SingletonWorker) CountVMsOwnedBy(user string) (int, bool) {
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
func (s *SingletonWorker) markVMSnapshotSwept() {
	s.mu.Lock()
	s.snapshotSweptAt = time.Now()
	s.mu.Unlock()
}

// invalidateVMSnapshot drops the visible VM snapshot and marks it unswept so
// quota decisions stop trusting it until a sweep against the (possibly new)
// libvirt host succeeds. The sweep timestamp is zeroed before the snapshot is
// cleared so a concurrent CountVMsOwnedBy can never judge soon-to-be-dropped
// data as fresh.
func (s *SingletonWorker) invalidateVMSnapshot() {
	s.mu.Lock()
	s.snapshotSweptAt = time.Time{}
	s.mu.Unlock()
	s.setVMs(nil)
}

// GetVMs returns the cached VMs, optionally filtered by owner.
func (s *SingletonWorker) GetVMs(user string) []VMInfo {
	snapshot := s.snapshotVMs()

	var filteredVMs []VMInfo
	for _, vm := range snapshot {
		if user == "" || vm.Owner == user {
			filteredVMs = append(filteredVMs, vm)
		}
	}
	return filteredVMs
}

// GetVMnames returns the cached VM names.
func (s *SingletonWorker) GetVMnames() []string {
	snapshot := s.snapshotVMs()

	var names []string
	for _, vm := range snapshot {
		names = append(names, vm.Name)
	}
	return names
}

// GetIPOfVM returns the primary IP address cached for the named VM.
func (s *SingletonWorker) GetIPOfVM(vmName string) (string, error) {
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
func (s *SingletonWorker) ResolveVMNameByLabel(secret []byte, label string) (string, bool) {
	want := []byte(label)
	for _, vm := range s.snapshotVMs() {
		if hmac.Equal([]byte(hash.RoutingLabel(secret, vm.Name)), want) {
			return vm.Name, true
		}
	}
	return "", false
}

func (s *SingletonWorker) snapshotVMs() []VMInfo {
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
func (s *SingletonWorker) SubscribeVMChanges() (<-chan struct{}, func()) {
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

func (s *SingletonWorker) setVMs(vms []VMInfo) {
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

func (s *SingletonWorker) mergeRDPReadinessLocked(next []VMInfo) {
	previous := make(map[string]VMInfo, len(s.vms))
	for _, vm := range s.vms {
		previous[vm.Name] = vm
	}

	for i := range next {
		old, ok := previous[next[i].Name]
		if ok && sameRDPReadinessTarget(old, next[i]) {
			if next[i].State == "running" {
				next[i].RDPReady = old.RDPReady
			} else {
				next[i].RDPReady = false
			}
			next[i].rdpGeneration = old.rdpGeneration
			next[i].rdpObservation = old.rdpObservation
			continue
		}

		s.nextRDPGeneration++
		next[i].RDPReady = false
		next[i].rdpGeneration = s.nextRDPGeneration
		next[i].rdpObservation = 0
	}
}

func sameRDPReadinessTarget(old, next VMInfo) bool {
	return old.Name == next.Name &&
		old.Owner == next.Owner &&
		old.PrimaryIP == next.PrimaryIP &&
		old.CreatedAt == next.CreatedAt &&
		old.State == next.State
}

func (s *SingletonWorker) notifySubscribersLocked() {
	for _, updates := range s.subscribers {
		select {
		case updates <- struct{}{}:
		default:
			// A pending notification already tells this subscriber to take the
			// latest snapshot, so intermediate refreshes can be coalesced.
		}
	}
}

var (
	instance atomic.Pointer[SingletonWorker] //nolint:gochecknoglobals // package-level singleton needed for one-time registration
	once     sync.Once                       //nolint:gochecknoglobals // package-level singleton needed for one-time registration
)

// GetInstance returns the process-wide VM cache worker.
func GetInstance() *SingletonWorker {
	once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		worker := &SingletonWorker{
			ticker: time.NewTicker(2 * time.Second),
			ctx:    ctx,
			cancel: cancel,
		}
		instance.Store(worker)
		go worker.run()
	})

	return instance.Load()
}

// peekInstance returns the process-wide VM cache worker only when GetInstance
// has already started it, and nil otherwise. Callers with a correct non-cache
// path (such as the VM creation quota check) use this so consulting the cache
// never starts the background worker as a side effect; in-package tests rely on
// the worker staying unstarted so their libvirt fixtures remain the only
// observer of domain state.
func peekInstance() *SingletonWorker {
	return instance.Load()
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

func (s *SingletonWorker) run() {
	log.Println("singleton worker started")

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
			log.Println("singleton worker stopped")
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
func (s *SingletonWorker) startSweepIfDue(current *inflightSweep) *inflightSweep {
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
func (s *SingletonWorker) sweep(outcome chan<- sweepOutcome) {
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
func (s *SingletonWorker) applySweep(res sweepOutcome) {
	if res.err != nil {
		log.Printf("singleton worker list vms: %v", res.err)
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
func (s *SingletonWorker) publishInventory(
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
func (s *SingletonWorker) doWork(conn *libvirt.Connect) error {
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
func (s *SingletonWorker) collectInventory(conn *libvirt.Connect) (
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

// Stop stops the background worker ticker and cancels its context.
func (s *SingletonWorker) Stop() {
	s.cancel()
	s.ticker.Stop()
}
