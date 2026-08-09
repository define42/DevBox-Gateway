package virt

import (
	"context"
	"crypto/hmac"
	"devboxgateway/internal/hash"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"sync"
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
	Name         string
	Owner        string
	GuestUser    string
	BaseImage    string
	CreatedAt    string
	State        string
	MemoryMiB    int
	VCPU         int
	VolumeGB     int
	VolumeUsedGB int
	IP           string
	PrimaryIP    string
	RDPReady     bool
	TTYReady     bool
	VNCReady     bool
}

// ListVMs returns VMs visible to the given user from the provided libvirt connection.
func ListVMs(user string, conn *libvirt.Connect) ([]VMInfo, error) {
	doms, err := conn.ListAllDomains(0)
	if err != nil {
		log.Printf("list domains: %v", err)
		return nil, err
	}
	defer freeDomains(doms)

	var result []VMInfo
	for _, d := range doms {
		info, ok := domainVMInfo(d, user)
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
	name, err := d.GetName()
	if err != nil {
		log.Printf("domain name: %v", err)
		return VMInfo{}, false
	}

	owner := domainOwnerForVMInfo(name, &d)
	if user != "" && owner != user {
		return VMInfo{}, false
	}

	state, _, err := d.GetState()
	if err != nil {
		log.Printf("domain state %s: %v", name, err)
		return VMInfo{}, false
	}

	mem, vcpu := domainResources(d)
	ip, primaryIP := domainDisplayIPs(d, state)
	diskUsedGB, diskTotalGB := domainDiskGB(d)
	return VMInfo{
		Name:         name,
		Owner:        owner,
		GuestUser:    domainGuestUserForVMInfo(name, &d),
		BaseImage:    domainBaseImageForVMInfo(name, &d),
		CreatedAt:    domainCreatedAtForVMInfo(name, &d),
		State:        formatState(state),
		MemoryMiB:    mem,
		VCPU:         vcpu,
		VolumeGB:     diskTotalGB,
		VolumeUsedGB: diskUsedGB,
		IP:           ip,
		PrimaryIP:    primaryIP,
		RDPReady:     domainRDPReady(primaryIP),
		TTYReady:     domainTTYReady(&d),
		VNCReady:     domainVNCReady(&d),
	}, true
}

func domainOwnerForVMInfo(name string, d *libvirt.Domain) string {
	owner, hasOwner, err := domainOwner(d)
	if err != nil {
		log.Printf("domain owner %s: %v", name, err)
		return ""
	}
	if !hasOwner {
		return ""
	}
	return owner
}

func domainGuestUserForVMInfo(name string, d *libvirt.Domain) string {
	guestUser, hasGuestUser, err := domainGuestUser(d)
	if err != nil {
		log.Printf("domain guest user %s: %v", name, err)
		return ""
	}
	if !hasGuestUser {
		return ""
	}
	return guestUser
}

func domainBaseImageForVMInfo(name string, d *libvirt.Domain) string {
	baseImage, hasBaseImage, err := domainBaseImage(d)
	if err != nil {
		log.Printf("domain base image %s: %v", name, err)
		return ""
	}
	if !hasBaseImage {
		return ""
	}
	return baseImage
}

func domainCreatedAtForVMInfo(name string, d *libvirt.Domain) string {
	createdAt, hasCreatedAt, err := domainCreatedAt(d)
	if err != nil {
		log.Printf("domain created-at %s: %v", name, err)
		return ""
	}
	if !hasCreatedAt {
		return ""
	}
	return createdAt
}

// domainDisplayIPs returns (display, routing). The display string aggregates
// every address libvirt knows (agent/lease/ARP) for the dashboard, while the
// routing address — the one the RDP proxy actually dials — is restricted to the
// authoritative DHCP lease inside the default NAT subnet so untrusted
// guest-reported addresses can never become a dial target. See domainRoutingIP.
func domainDisplayIPs(d libvirt.Domain, state libvirt.DomainState) (string, string) {
	if !domainCanReportIPs(state) {
		return "", ""
	}

	return strings.Join(domainIPs(d), ", "), domainRoutingIP(d)
}

// domainRoutingIP returns the address the proxy may dial for the VM. Only the
// DHCP lease source is consulted: it reflects what the gateway's own dnsmasq
// actually assigned, which a guest cannot forge, unlike the agent- and
// ARP-reported addresses used for display. The lease must also fall inside the
// default NAT subnet; otherwise routing fails closed (empty result) rather than
// dialing an off-network host.
func domainRoutingIP(d libvirt.Domain) string {
	var ips []string
	seen := make(map[string]struct{})
	ips = appendDomainIPsFromSource(ips, seen, d, libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
	return firstRoutableVMIP(ips)
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

func domainTTYReady(d *libvirt.Domain) bool {
	_, ok, err := domainSerialSocketPath(d)
	if err != nil {
		log.Printf("domain tty readiness: %v", err)
		return false
	}
	return ok
}

func domainVNCReady(d *libvirt.Domain) bool {
	_, ok, err := domainVNCSocketPath(d)
	if err != nil {
		log.Printf("domain vnc readiness: %v", err)
		return false
	}
	return ok
}

// domainRDPReady reports whether the guest's RDP service is accepting TCP
// connections. primaryIP comes from the trusted DHCP lease constrained to the
// gateway's own VM subnet, so this probe cannot be redirected by guest-reported
// interface data. A short timeout keeps the background VM refresh responsive
// while a guest is still booting or its firewall is dropping connections.
func domainRDPReady(primaryIP string) bool {
	if primaryIP == "" {
		return false
	}
	return tcpEndpointReady(net.JoinHostPort(primaryIP, rdpPort), rdpReadinessProbeTimeout)
}

func tcpEndpointReady(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
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
	info, err := d.GetBlockInfo("vda", 0)
	if err != nil {
		return 0, 0
	}

	capacity := info.Capacity
	if capacity == 0 {
		capacity = info.Physical
	}
	if capacity == 0 {
		capacity = info.Allocation
	}

	allocation := info.Allocation
	if allocation == 0 {
		allocation = info.Physical
	}

	return bytesToGiBCeil(allocation), bytesToGiBCeil(capacity)
}

func bytesToGiBCeil(b uint64) int {
	if b == 0 {
		return 0
	}
	return int((b + (1 << 30) - 1) >> 30)
}

func domainIPs(d libvirt.Domain) []string {
	sources := []libvirt.DomainInterfaceAddressesSource{
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE,
		libvirt.DOMAIN_INTERFACE_ADDRESSES_SRC_ARP,
	}

	var ips []string
	seen := make(map[string]struct{})

	for _, src := range sources {
		ips = appendDomainIPsFromSource(ips, seen, d, src)
	}
	return ips
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
	ticker           *time.Ticker
	ctx              context.Context
	cancel           context.CancelFunc
	mu               sync.RWMutex
	vms              []VMInfo
	nextSubscriberID uint64
	subscribers      map[uint64]chan struct{}
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

// SubscribeVMChanges returns a coalescing notification channel for successful
// libvirt refreshes whose VM snapshot differs from the cached snapshot. The
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
	defer s.mu.Unlock()

	next := slices.Clone(vms)
	if slices.Equal(s.vms, next) {
		return
	}
	s.vms = next

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
	instance *SingletonWorker //nolint:gochecknoglobals // package-level singleton needed for one-time registration
	once     sync.Once        //nolint:gochecknoglobals // package-level singleton needed for one-time registration
)

// GetInstance returns the process-wide VM cache worker.
func GetInstance() *SingletonWorker {
	once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		instance = &SingletonWorker{
			ticker: time.NewTicker(2 * time.Second),
			ctx:    ctx,
			cancel: cancel,
		}

		go instance.run()
	})

	return instance
}

func (s *SingletonWorker) run() {
	log.Println("singleton worker started")

	var conn *libvirt.Connect
	defer func() {
		if conn != nil {
			_, _ = conn.Close()
		}
	}()

	for {
		select {
		case <-s.ticker.C:
			if conn == nil {
				var err error
				conn, err = libvirt.NewConnect(LibvirtURI())
				if err != nil {
					log.Printf("list vms connect: %v", err)
					continue
				}
			}

			if err := s.doWork(conn); err != nil {
				log.Printf("singleton worker list vms: %v", err)
				_, _ = conn.Close()
				conn = nil
			}
		case <-s.ctx.Done():
			log.Println("singleton worker stopped")
			return
		}
	}
}

func (s *SingletonWorker) doWork(conn *libvirt.Connect) error {
	if conn == nil {
		return fmt.Errorf("libvirt connection is nil")
	}

	vms, err := ListVMs("", conn)
	if err != nil {
		return err
	}
	s.setVMs(vms)
	return nil
}

// Stop stops the background worker ticker and cancels its context.
func (s *SingletonWorker) Stop() {
	s.cancel()
	s.ticker.Stop()
}
