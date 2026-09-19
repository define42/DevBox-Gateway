package virt

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"libvirt.org/go/libvirt"
)

// NetworkIdentity is the host-owned, persistent identity of one VM interface.
// It is enforced by the interface's network filter and DHCP reservation.
type NetworkIdentity struct {
	MAC string
	IP  string
}

func identityForAddress(lastOctet byte) NetworkIdentity {
	return NetworkIdentity{
		MAC: fmt.Sprintf("52:54:00:db:7b:%02x", lastOctet),
		IP:  netip.AddrFrom4([4]byte{192, 168, 123, lastOctet}).String(),
	}
}

func validateNetworkIdentity(identity NetworkIdentity) error {
	ip, err := netip.ParseAddr(identity.IP)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("network identity requires a reserved IPv4 address")
	}
	bytes := ip.As4()
	if bytes[0] != 192 || bytes[1] != 168 || bytes[2] != 123 || bytes[3] < 2 || bytes[3] > 253 {
		return fmt.Errorf("network identity address %s is outside the reservation pool", identity.IP)
	}
	if identity != identityForAddress(bytes[3]) {
		return fmt.Errorf("network identity MAC does not match its reserved IPv4 address")
	}
	return nil
}

// A DNS-safe digest also supports directory usernames containing '@' or '+'.
// Guest-supplied hostnames and DHCP client identifiers are never reservation keys.
func networkReservationName(vmName string) string {
	digest := sha256.Sum256([]byte(vmName))
	return "vm-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:]))
}

func validateNetworkReservations(hosts []networkDHCPHost) error {
	names := make(map[string]bool, len(hosts))
	addresses := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if err := validateNetworkIdentity(NetworkIdentity{MAC: host.MAC, IP: host.IP}); err != nil {
			return fmt.Errorf("invalid DHCP reservation %s: %w", host.Name, err)
		}
		if host.Name == "" || host.ID != "" || names[host.Name] || addresses[host.IP] {
			return fmt.Errorf("network has an ambiguous DHCP reservation for %s", host.Name)
		}
		names[host.Name], addresses[host.IP] = true, true
	}
	return nil
}

func chooseNetworkIdentity(hosts []networkDHCPHost, vmName string) (NetworkIdentity, bool, error) {
	if vmName == "" {
		return NetworkIdentity{}, false, fmt.Errorf("VM name is required for network reservation")
	}
	if err := validateNetworkReservations(hosts); err != nil {
		return NetworkIdentity{}, false, err
	}
	name := networkReservationName(vmName)
	used := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		if host.Name == name {
			return NetworkIdentity{MAC: host.MAC, IP: host.IP}, true, nil
		}
		used[host.IP] = true
	}
	for last := 2; last <= 253; last++ {
		identity := identityForAddress(byte(last))
		if !used[identity.IP] {
			return identity, false, nil
		}
	}
	return NetworkIdentity{}, false, fmt.Errorf("gateway network has no free VM addresses")
}

// reserveNetworkIdentity is serialized after the caller's VM-name lock. The
// persistent DHCP host is the allocation record, including while a VM is off.
func reserveNetworkIdentity(conn *libvirt.Connect, vmName string) (NetworkIdentity, error) {
	unlock := vmNameLocks.Lock(networkAllocationLock)
	defer unlock()
	network, err := prepareGatewayNetwork(conn)
	if err != nil {
		return NetworkIdentity{}, err
	}
	defer func() { _ = network.Free() }()
	return reserveAvailableNetworkIdentity(network, vmName)
}

// libvirt rejects duplicate DHCP addresses atomically. If another gateway
// process wins an allocation between our read and update, take a new snapshot
// and choose another address. Unrelated update failures are never ignored.
func reserveAvailableNetworkIdentity(network *libvirt.Network, vmName string) (NetworkIdentity, error) {
	for range 16 {
		hosts, err := readNetworkReservations(network)
		if err != nil {
			return NetworkIdentity{}, err
		}
		identity, exists, err := chooseNetworkIdentity(hosts, vmName)
		if err != nil || exists {
			return identity, err
		}
		host := networkDHCPHost{MAC: identity.MAC, IP: identity.IP, Name: networkReservationName(vmName)}
		if err := updateNetworkReservation(network, libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, host); err != nil {
			if !reservationWasTaken(network, host) {
				return NetworkIdentity{}, err
			}
			continue
		}
		return identity, nil
	}
	return NetworkIdentity{}, fmt.Errorf("network allocation changed too often; retry VM creation")
}

func reservationWasTaken(network *libvirt.Network, candidate networkDHCPHost) bool {
	hosts, err := readNetworkReservations(network)
	if err != nil {
		return false
	}
	for _, host := range hosts {
		if host.IP == candidate.IP || host.Name == candidate.Name {
			return true
		}
	}
	return false
}

func releaseNetworkIdentity(conn *libvirt.Connect, vmName string) error {
	unlock := vmNameLocks.Lock(networkAllocationLock)
	defer unlock()
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_NETWORK) {
			return nil
		}
		return fmt.Errorf("lookup reservation network: %w", err)
	}
	defer func() { _ = network.Free() }()
	hosts, err := readNetworkReservations(network)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if host.Name == networkReservationName(vmName) {
			return updateNetworkReservation(network, libvirt.NETWORK_UPDATE_COMMAND_DELETE, host)
		}
	}
	return nil
}

func updateNetworkReservation(network *libvirt.Network, command libvirt.NetworkUpdateCommand, host networkDHCPHost) error {
	doc, err := xml.Marshal(host)
	if err != nil {
		return fmt.Errorf("encode network reservation: %w", err)
	}
	active, err := network.IsActive()
	if err != nil {
		return fmt.Errorf("check reservation network: %w", err)
	}
	flags := libvirt.NETWORK_UPDATE_AFFECT_CONFIG
	if active {
		flags |= libvirt.NETWORK_UPDATE_AFFECT_LIVE
	}
	if err := network.Update(command, libvirt.NETWORK_SECTION_IP_DHCP_HOST, 0, string(doc), flags); err != nil {
		return fmt.Errorf("update DHCP reservation %s: %w", host.Name, err)
	}
	return nil
}

func readNetworkReservations(network *libvirt.Network) ([]networkDHCPHost, error) {
	var err error
	for range 8 {
		var hosts []networkDHCPHost
		hosts, err = readNetworkReservationSnapshot(network)
		var changed *networkReservationsChangedError
		if !errors.As(err, &changed) {
			return hosts, err
		}
	}
	return nil, err
}

func readNetworkReservationSnapshot(network *libvirt.Network) ([]networkDHCPHost, error) {
	persistent, err := readGatewayNetwork(network, libvirt.NETWORK_XML_INACTIVE)
	if err != nil {
		return nil, err
	}
	hosts := persistent.IPs[0].DHCP.Hosts
	if err := validateNetworkReservations(hosts); err != nil {
		return nil, err
	}
	active, err := network.IsActive()
	if err != nil {
		return nil, fmt.Errorf("check reservation network: %w", err)
	}
	if active {
		if err := validateLiveReservations(network, hosts); err != nil {
			return nil, err
		}
	}
	return hosts, nil
}

func validateLiveReservations(network *libvirt.Network, hosts []networkDHCPHost) error {
	live, err := readGatewayNetwork(network, 0)
	if err != nil {
		return err
	}
	liveHosts := live.IPs[0].DHCP.Hosts
	if len(liveHosts) != len(hosts) {
		return &networkReservationsChangedError{}
	}
	byName := make(map[string]networkDHCPHost, len(hosts))
	for _, host := range hosts {
		byName[host.Name] = host
	}
	for _, host := range liveHosts {
		if stored, ok := byName[host.Name]; !ok || stored != host {
			return &networkReservationsChangedError{}
		}
	}
	return validateNetworkReservations(liveHosts)
}

type networkReservationsChangedError struct{}

func (*networkReservationsChangedError) Error() string {
	return "live and persistent network reservations differ"
}
