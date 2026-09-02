package virt

import (
	"errors"
	"fmt"
	"log"

	"libvirt.org/go/libvirt"
)

// defaultNetworkName is the libvirt NAT network every VDI attaches to (see the
// <source network='default'/> entry in the domain XML in domain.go).
const defaultNetworkName = "default"

// ensureDefaultNetwork makes sure the libvirt 'default' NAT network exists, is
// running, and is set to autostart, defining it from the standard libvirt
// template when absent. A fresh modular-libvirt host (e.g. Rocky/RHEL 9) ships
// without it, which otherwise fails VM boot with "Network not found".
func ensureDefaultNetwork(conn *libvirt.Connect) error {
	network, err := lookupOrDefineDefaultNetwork(conn)
	if err != nil {
		return err
	}
	defer func() { _ = network.Free() }()

	if err := startNetworkIfNeeded(network); err != nil {
		return err
	}
	configureNetworkAutostart(network)
	return nil
}

func lookupOrDefineDefaultNetwork(conn *libvirt.Connect) (*libvirt.Network, error) {
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if err == nil {
		return network, nil
	}

	var libErr libvirt.Error
	if !errors.As(err, &libErr) || libErr.Code != libvirt.ERR_NO_NETWORK {
		return nil, fmt.Errorf("lookup network %s: %w", defaultNetworkName, err)
	}

	network, err = conn.NetworkDefineXML(defaultNetworkXML())
	if err != nil {
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
	log.Printf("Network %s started", defaultNetworkName)
	return nil
}

func configureNetworkAutostart(network *libvirt.Network) {
	autostart, err := network.GetAutostart()
	if err != nil || autostart {
		return
	}
	if err := network.SetAutostart(true); err != nil {
		log.Printf("Failed to set autostart for network %s: %v", defaultNetworkName, err)
	}
}

// defaultNetworkXML is the standard libvirt default network: a NAT-forwarded
// virbr0 bridge serving DHCP on 192.168.122.0/24.
func defaultNetworkXML() string {
	return fmt.Sprintf(`
<network>
  <name>%s</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='on' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.253'/>
    </dhcp>
  </ip>
</network>`, defaultNetworkName)
}
