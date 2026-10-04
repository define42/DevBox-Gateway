package virt

import (
	"errors"
	"fmt"

	"libvirt.org/go/libvirt"
)

// ListExpectedVSockGuests returns running persistent VMs with gateway owner
// metadata. A failed or incomplete scan returns an error so audit monitoring
// cannot mistake an unavailable hypervisor for an empty inventory.
func ListExpectedVSockGuests() ([]VSockGuest, error) {
	conn, err := connectLibvirt()
	if err != nil {
		return nil, fmt.Errorf("connect libvirt for audit inventory: %w", err)
	}
	defer func() { _, _ = conn.Close() }()
	domains, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE | libvirt.CONNECT_LIST_DOMAINS_PERSISTENT)
	if err != nil {
		return nil, fmt.Errorf("list running audit guests: %w", err)
	}
	defer freeDomains(domains)
	guests := make([]VSockGuest, 0, len(domains))
	for i := range domains {
		guest, expected, err := expectedVSockGuest(&domains[i])
		if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
			continue // A concurrent removal is observed on the next scan.
		}
		if err != nil {
			return nil, err
		}
		if expected {
			guests = append(guests, guest)
		}
	}
	return guests, nil
}

func expectedVSockGuest(dom *libvirt.Domain) (VSockGuest, bool, error) {
	state, _, err := dom.GetState()
	if err != nil {
		return VSockGuest{}, false, fmt.Errorf("read audit guest state: %w", err)
	}
	if state != libvirt.DOMAIN_RUNNING && state != libvirt.DOMAIN_BLOCKED {
		return VSockGuest{}, false, nil
	}
	owner, hasOwner, err := domainOwner(dom)
	if err != nil || !hasOwner {
		return VSockGuest{}, false, err
	}
	name, err := dom.GetName()
	if err != nil {
		return VSockGuest{}, false, err
	}
	uuid, err := dom.GetUUIDString()
	if err != nil {
		return VSockGuest{}, false, fmt.Errorf("read audit guest UUID: %w", err)
	}
	desc, err := dom.GetXMLDesc(0)
	if err != nil {
		return VSockGuest{}, false, fmt.Errorf("read audit guest XML: %w", err)
	}
	cid, ok := domainVSockCID(desc)
	if !ok {
		return VSockGuest{}, false, fmt.Errorf("running managed VM %q has no assigned audit vsock CID", name)
	}
	return VSockGuest{CID: cid, Name: name, UUID: uuid, Owner: owner}, true, nil
}
