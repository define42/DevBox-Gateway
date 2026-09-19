package virt

import (
	"encoding/xml"
	"fmt"

	"libvirt.org/go/libvirt"
)

type domainNetworkXML struct {
	Interfaces []struct {
		Type string `xml:"type,attr"`
		MAC  struct {
			Address string `xml:"address,attr"`
		} `xml:"mac"`
		Source struct {
			Network string `xml:"network,attr"`
			Bridge  string `xml:"bridge,attr"`
		} `xml:"source"`
		Port struct {
			Isolated string `xml:"isolated,attr"`
		} `xml:"port"`
		Filter struct {
			Name       string `xml:"filter,attr"`
			Parameters []struct {
				Name  string `xml:"name,attr"`
				Value string `xml:"value,attr"`
			} `xml:"parameter"`
		} `xml:"filterref"`
	} `xml:"devices>interface"`
}

func parseDomainNetworkIdentity(doc string) (NetworkIdentity, error) {
	var network domainNetworkXML
	if err := xml.Unmarshal([]byte(doc), &network); err != nil {
		return NetworkIdentity{}, fmt.Errorf("parse VM network identity: %w", err)
	}
	if len(network.Interfaces) != 1 {
		return NetworkIdentity{}, fmt.Errorf("VM must have exactly one protected network interface")
	}
	nic := network.Interfaces[0]
	if nic.Type != "network" || nic.Source.Network != defaultNetworkName || nic.Port.Isolated != "yes" ||
		nic.Filter.Name != networkFilterName || len(nic.Filter.Parameters) != 2 {
		return NetworkIdentity{}, fmt.Errorf("VM must use the isolated gateway network and mandatory filter")
	}
	identity := NetworkIdentity{MAC: nic.MAC.Address}
	learningDisabled := false
	for _, parameter := range nic.Filter.Parameters {
		switch parameter.Name {
		case "IP":
			identity.IP = parameter.Value
		case "CTRL_IP_LEARNING":
			learningDisabled = parameter.Value == "none"
		default:
			return NetworkIdentity{}, fmt.Errorf("VM has an unexpected network filter parameter")
		}
	}
	if !learningDisabled {
		return NetworkIdentity{}, fmt.Errorf("VM network identity must not be learned from guest traffic")
	}
	return identity, validateNetworkIdentity(identity)
}

// domainNetworkIdentity rejects missing protection and divergence between the
// configured NIC and the live one; neither DHCP leases nor guest agents define
// the address to which backend connections are sent.
func domainNetworkIdentity(dom *libvirt.Domain) (NetworkIdentity, error) {
	doc, err := dom.GetXMLDesc(libvirt.DOMAIN_XML_INACTIVE)
	if err != nil {
		return NetworkIdentity{}, fmt.Errorf("read persistent VM network identity: %w", err)
	}
	identity, err := parseDomainNetworkIdentity(doc)
	if err != nil {
		return NetworkIdentity{}, err
	}
	active, err := dom.IsActive()
	if err != nil {
		return NetworkIdentity{}, fmt.Errorf("check VM network state: %w", err)
	}
	if active {
		if err := validateLiveDomainIdentity(dom, identity); err != nil {
			return NetworkIdentity{}, err
		}
	}
	return identity, nil
}

func validateLiveDomainIdentity(dom *libvirt.Domain, identity NetworkIdentity) error {
	doc, err := dom.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("read active VM network identity: %w", err)
	}
	live, err := parseDomainNetworkIdentity(doc)
	if err != nil {
		return err
	}
	if live != identity {
		return fmt.Errorf("VM live and persistent network identities differ")
	}
	return nil
}

// validateDomainNetwork checks the allocation and reinstalls the gateway-owned
// filter before a VM starts. It does not inspect other in-progress creations.
func validateDomainNetwork(conn *libvirt.Connect, dom *libvirt.Domain) error {
	identity, err := domainNetworkIdentity(dom)
	if err != nil {
		return err
	}
	name, err := dom.GetName()
	if err != nil {
		return fmt.Errorf("read VM name for network reservation: %w", err)
	}
	unlock := vmNameLocks.Lock(networkAllocationLock)
	defer unlock()
	if err := ensureNetworkFilter(conn); err != nil {
		return err
	}
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if err != nil {
		return fmt.Errorf("lookup gateway network: %w", err)
	}
	defer func() { _ = network.Free() }()
	hosts, err := readNetworkReservations(network)
	if err != nil {
		return err
	}
	return validateIdentityReservation(hosts, name, identity)
}

func validateIdentityReservation(hosts []networkDHCPHost, name string, identity NetworkIdentity) error {
	for _, host := range hosts {
		if host.Name == networkReservationName(name) && host.MAC == identity.MAC && host.IP == identity.IP {
			return nil
		}
	}
	return fmt.Errorf("VM %s has no matching persistent network reservation", name)
}

func validateNetworkPorts(conn *libvirt.Connect, network *libvirt.Network) error {
	hosts, err := readNetworkReservations(network)
	if err != nil {
		return err
	}
	ports, err := network.ListAllPorts(0)
	if err != nil {
		return fmt.Errorf("inspect gateway network ports: %w", err)
	}
	defer func() {
		for i := range ports {
			_ = ports[i].Free()
		}
	}()
	for i := range ports {
		if err := validateNetworkPort(conn, &ports[i], hosts); err != nil {
			return err
		}
	}
	return rejectUnmanagedBridgeInterfaces(conn)
}

func validateNetworkPort(conn *libvirt.Connect, port *libvirt.NetworkPort, hosts []networkDHCPHost) error {
	doc, err := port.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("read gateway network port: %w", err)
	}
	var binding struct {
		Owner struct {
			UUID string `xml:"uuid"`
		} `xml:"owner"`
		MAC struct {
			Address string `xml:"address,attr"`
		} `xml:"mac"`
	}
	if err := xml.Unmarshal([]byte(doc), &binding); err != nil {
		return fmt.Errorf("parse gateway network port: %w", err)
	}
	dom, err := conn.LookupDomainByUUIDString(binding.Owner.UUID)
	if err != nil {
		return fmt.Errorf("gateway network contains an unmanaged port: %w", err)
	}
	defer func() { _ = dom.Free() }()
	identity, err := domainNetworkIdentity(dom)
	if err != nil {
		return fmt.Errorf("gateway network contains an unprotected VM: %w", err)
	}
	if binding.MAC.Address != identity.MAC {
		return fmt.Errorf("gateway network port does not match its VM identity")
	}
	name, err := dom.GetName()
	if err != nil {
		return fmt.Errorf("read gateway network port owner: %w", err)
	}
	return validateIdentityReservation(hosts, name, identity)
}

// Direct bridge attachments bypass libvirt network ports; reject those too.
func rejectUnmanagedBridgeInterfaces(conn *libvirt.Connect) error {
	domains, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return fmt.Errorf("inspect bridge domain interfaces: %w", err)
	}
	defer func() {
		for i := range domains {
			_ = domains[i].Free()
		}
	}()
	for i := range domains {
		if err := rejectUnmanagedDomainBridge(&domains[i]); err != nil {
			return err
		}
	}
	return nil
}

func rejectUnmanagedDomainBridge(dom *libvirt.Domain) error {
	doc, err := dom.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("inspect active domain bridge: %w", err)
	}
	var network domainNetworkXML
	if err := xml.Unmarshal([]byte(doc), &network); err != nil {
		return fmt.Errorf("parse active domain interfaces: %w", err)
	}
	for _, nic := range network.Interfaces {
		if nic.Source.Bridge == networkBridgeName && nic.Type != "network" {
			return fmt.Errorf("gateway bridge has an unmanaged domain interface")
		}
	}
	return nil
}
