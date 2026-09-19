package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"slices"

	"libvirt.org/go/libvirt"
)

// This network is owned exclusively by the gateway. Reusing libvirt's default
// bridge would let an unfiltered, independently managed guest spoof our VMs.
const (
	defaultNetworkName    = "devbox"
	networkBridgeName     = "virbr-devbox"
	networkAllocationLock = "\x00devbox-network-allocation"
)

type networkDHCPHost struct {
	XMLName xml.Name `xml:"host"`
	MAC     string   `xml:"mac,attr"`
	IP      string   `xml:"ip,attr"`
	Name    string   `xml:"name,attr"`
	ID      string   `xml:"id,attr,omitempty"`
}

type gatewayNetworkXML struct {
	XMLName  xml.Name `xml:"network"`
	Name     string   `xml:"name"`
	IPv6     string   `xml:"ipv6,attr"`
	Metadata struct {
		Owner struct {
			Version string `xml:"version,attr"`
		} `xml:"urn:devbox:network network"`
	} `xml:"metadata"`
	Forward struct {
		Mode string `xml:"mode,attr"`
	} `xml:"forward"`
	Bridge struct {
		Name string `xml:"name,attr"`
	} `xml:"bridge"`
	IPs []struct {
		Address string `xml:"address,attr"`
		Netmask string `xml:"netmask,attr"`
		DHCP    struct {
			Ranges []struct {
				Start string `xml:"start,attr"`
				End   string `xml:"end,attr"`
			} `xml:"range"`
			Hosts []networkDHCPHost `xml:"host"`
		} `xml:"dhcp"`
	} `xml:"ip"`
	Options struct {
		Items []struct {
			Value string `xml:"value,attr"`
		} `xml:"http://libvirt.org/schemas/network/dnsmasq/1.0 option"`
	} `xml:"http://libvirt.org/schemas/network/dnsmasq/1.0 options"`
}

// ensureDefaultNetwork installs the mandatory filter and prepares the dedicated
// network. A conflicting network definition is refused, never rewritten.
func ensureDefaultNetwork(conn *libvirt.Connect) error {
	unlock := vmNameLocks.Lock(networkAllocationLock)
	defer unlock()
	network, err := prepareGatewayNetwork(conn)
	if err != nil {
		return err
	}
	defer func() { _ = network.Free() }()
	return validateNetworkPorts(conn, network)
}

func prepareGatewayNetwork(conn *libvirt.Connect) (*libvirt.Network, error) {
	if err := ensureNetworkFilter(conn); err != nil {
		return nil, err
	}
	network, err := lookupOrDefineDefaultNetwork(conn)
	if err != nil {
		return nil, err
	}
	if err := prepareNetwork(network); err != nil {
		_ = network.Free()
		return nil, err
	}
	return network, nil
}

func prepareNetwork(network *libvirt.Network) error {
	if _, err := readGatewayNetwork(network, libvirt.NETWORK_XML_INACTIVE); err != nil {
		return err
	}
	if err := startNetworkIfNeeded(network); err != nil {
		return err
	}
	if _, err := readGatewayNetwork(network, 0); err != nil {
		return err
	}
	return configureNetworkAutostart(network)
}

func lookupOrDefineDefaultNetwork(conn *libvirt.Connect) (*libvirt.Network, error) {
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if err == nil {
		return network, nil
	}
	if !errors.Is(err, libvirt.ERR_NO_NETWORK) {
		return nil, fmt.Errorf("lookup network %s: %w", defaultNetworkName, err)
	}
	network, err = conn.NetworkDefineXML(defaultNetworkXML())
	if err != nil {
		// Another process may have defined it since our lookup. Preparation
		// validates ownership and every security-relevant setting before use.
		if existing, lookupErr := conn.LookupNetworkByName(defaultNetworkName); lookupErr == nil {
			return existing, nil
		}
		return nil, fmt.Errorf("define network %s: %w", defaultNetworkName, err)
	}
	log.Printf("Network %s defined", defaultNetworkName)
	return network, nil
}

func startNetworkIfNeeded(network *libvirt.Network) error {
	active, err := network.IsActive()
	if err != nil {
		return fmt.Errorf("check if network %s is active: %w", defaultNetworkName, err)
	}
	if active {
		return nil
	}
	if err := network.Create(); err != nil {
		return fmt.Errorf("start network %s: %w", defaultNetworkName, err)
	}
	return nil
}

func configureNetworkAutostart(network *libvirt.Network) error {
	if err := network.SetAutostart(true); err != nil {
		return fmt.Errorf("enable network %s autostart: %w", defaultNetworkName, err)
	}
	return nil
}

func readGatewayNetwork(network *libvirt.Network, flags libvirt.NetworkXMLFlags) (gatewayNetworkXML, error) {
	doc, err := network.GetXMLDesc(flags)
	if err != nil {
		return gatewayNetworkXML{}, fmt.Errorf("read network %s: %w", defaultNetworkName, err)
	}
	return parseGatewayNetwork(doc)
}

func parseGatewayNetwork(doc string) (gatewayNetworkXML, error) {
	var network gatewayNetworkXML
	if err := xml.Unmarshal([]byte(doc), &network); err != nil {
		return network, fmt.Errorf("parse gateway network: %w", err)
	}
	if network.Name != defaultNetworkName || network.Metadata.Owner.Version != "1" ||
		network.Forward.Mode != "nat" || network.Bridge.Name != networkBridgeName || network.IPv6 == "yes" {
		return network, fmt.Errorf("network %s is not the gateway-owned IPv4 NAT network", defaultNetworkName)
	}
	if len(network.IPs) != 1 || network.IPs[0].Address != "192.168.123.1" || network.IPs[0].Netmask != "255.255.255.0" {
		return network, fmt.Errorf("network %s has an unexpected subnet", defaultNetworkName)
	}
	ranges := network.IPs[0].DHCP.Ranges
	if len(ranges) != 1 || ranges[0].Start != "192.168.123.2" || ranges[0].End != "192.168.123.253" {
		return network, fmt.Errorf("network %s has an unexpected DHCP range", defaultNetworkName)
	}
	options := make([]string, 0, len(network.Options.Items))
	for _, option := range network.Options.Items {
		options = append(options, option.Value)
	}
	slices.Sort(options)
	if !slices.Equal(options, []string{"dhcp-ignore-clid", "dhcp-ignore=tag:!known"}) {
		return network, fmt.Errorf("network %s requires DHCP reservations and MAC-based identity", defaultNetworkName)
	}
	return network, nil
}

// A range keeps dnsmasq's DHCP service enabled before the first reservation is
// installed. dhcp-ignore excludes unknown clients, so leases are reservation-only.
func defaultNetworkXML() string {
	return fmt.Sprintf(`<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
  <name>%s</name>
  <metadata><devbox:network xmlns:devbox='urn:devbox:network' version='1'/></metadata>
  <forward mode='nat'/>
  <bridge name='%s' stp='on' delay='0'/>
  <ip address='192.168.123.1' netmask='255.255.255.0'>
    <dhcp><range start='192.168.123.2' end='192.168.123.253'/></dhcp>
  </ip>
  <dnsmasq:options>
    <dnsmasq:option value='dhcp-ignore-clid'/>
    <dnsmasq:option value='dhcp-ignore=tag:!known'/>
  </dnsmasq:options>
</network>`, defaultNetworkName, networkBridgeName)
}
