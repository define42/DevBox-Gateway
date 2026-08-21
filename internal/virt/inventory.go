package virt

import (
	"fmt"
	"log"
	"math"
	"net"
	"strings"

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

// VMInfo describes a VM entry shown in the dashboard and worker cache.
type VMInfo struct {
	Name      string
	Owner     string
	GuestUser string
	BaseImage string
	CreatedAt string
	// LastUsed is the RFC3339 UTC timestamp of the VM's last recorded use. In
	// the worker cache it holds the persisted metadata value from the sweep;
	// VMs overlays the fresher in-memory registry before handing entries to
	// callers, so touches (RDP/serial/noVNC clicks, starts) show up without
	// waiting for a domain XML re-read.
	LastUsed       string
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
		LastUsed:     metadata.LastUsed,
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

func domainResources(d libvirt.Domain) (int, int) {
	info, err := d.GetInfo()
	if err != nil {
		log.Printf("domain info: %v", err)
		return 0, 0
	}
	memMiB := info.Memory / 1024
	if memMiB > math.MaxInt {
		memMiB = math.MaxInt
	}
	return int(memMiB), int(info.NrVirtCpu)
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
