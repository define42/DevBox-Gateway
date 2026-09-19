package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"

	"libvirt.org/go/libvirt"
)

// VSockGuest identifies the running domain that holds a vsock CID.
type VSockGuest struct {
	Name  string
	UUID  string
	Owner string // gateway owner metadata; empty for domains the gateway did not create
}

// vsockCIDHints remembers which running domain held each CID at the last full
// scan (see LookupVSockGuest).
var vsockCIDHints = &vsockHintCache{} //nolint:gochecknoglobals // process-wide cache of the last running-domain scan, shared by every SauronAgent connection

// vsockHintCache maps CIDs to domain names as of the last scan.
type vsockHintCache struct {
	mu    sync.Mutex
	names map[uint32]string
}

func (c *vsockHintCache) get(cid uint32) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name, ok := c.names[cid]
	return name, ok
}

func (c *vsockHintCache) replace(names map[uint32]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names = names
}

// LookupVSockGuest returns the running domain libvirt assigned cid to. The
// SauronAgent collector calls it once per guest connection: the CID of a
// vsock connection is set by the hypervisor, so the domain found here -- not
// anything the guest reports -- is the authoritative source of its events.
//
// Only running domains are considered, because a CID is assigned at start
// and belongs to no domain once it stops; the live XML holds the assignment.
// ok is false when no running domain holds cid.
//
// Finding a CID takes a scan of every running domain's XML, and after a
// gateway restart every guest reconnects at once. So a scan records where
// every CID was, and a later lookup first confirms that hint against the one
// domain it names. CIDs are unique among running domains, so a hint that no
// longer holds costs a rescan, never a wrong attribution.
func LookupVSockGuest(cid uint32) (guest VSockGuest, ok bool, err error) {
	conn, err := connectLibvirt()
	if err != nil {
		return VSockGuest{}, false, fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	if name, hinted := vsockCIDHints.get(cid); hinted {
		if guest, confirmed := confirmVSockGuest(conn, name, cid); confirmed {
			return guest, true, nil
		}
	}
	return scanVSockGuests(conn, cid)
}

// confirmVSockGuest reports whether the named domain is running and holds cid.
func confirmVSockGuest(conn *libvirt.Connect, name string, cid uint32) (VSockGuest, bool) {
	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return VSockGuest{}, false
	}
	defer func() {
		_ = dom.Free()
	}()
	// A stopped domain's XML is its persistent definition, which can name a
	// fixed CID it does not hold right now.
	if active, err := dom.IsActive(); err != nil || !active {
		return VSockGuest{}, false
	}
	desc, err := dom.GetXMLDesc(0)
	if err != nil {
		return VSockGuest{}, false
	}
	if assigned, has := domainVSockCID(desc); !has || assigned != cid {
		return VSockGuest{}, false
	}
	guest, found, err := vsockGuest(dom)
	return guest, found && err == nil
}

// scanVSockGuests reads every running domain's CID, records them as hints,
// and returns the domain holding cid.
func scanVSockGuests(conn *libvirt.Connect, cid uint32) (VSockGuest, bool, error) {
	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)
	if err != nil {
		return VSockGuest{}, false, fmt.Errorf("list running domains: %w", err)
	}
	defer freeDomains(doms)

	names := make(map[uint32]string, len(doms))
	var match *libvirt.Domain
	// A domain whose XML cannot be read might be the one holding cid, so its
	// error is returned when no other domain matches.
	var readErrs []error
	for i := range doms {
		dom := &doms[i]
		desc, err := dom.GetXMLDesc(0)
		if err != nil {
			readErrs = append(readErrs, err)
			continue
		}
		assigned, has := domainVSockCID(desc)
		if !has {
			continue
		}
		name, err := dom.GetName()
		if err != nil {
			readErrs = append(readErrs, err)
			continue
		}
		names[assigned] = name
		if assigned == cid {
			match = dom
		}
	}
	vsockCIDHints.replace(names)

	if match != nil {
		return vsockGuest(match)
	}
	if len(readErrs) > 0 {
		return VSockGuest{}, false, fmt.Errorf("read running domain xml: %w", errors.Join(readErrs...))
	}
	return VSockGuest{}, false, nil
}

// vsockGuest describes the domain that holds a CID. The owner is best
// effort: the name alone already attributes the guest's events correctly.
func vsockGuest(dom *libvirt.Domain) (VSockGuest, bool, error) {
	name, err := dom.GetName()
	if err != nil {
		return VSockGuest{}, false, fmt.Errorf("domain name: %w", err)
	}
	guest := VSockGuest{Name: name}
	if guest.UUID, err = dom.GetUUIDString(); err != nil {
		log.Printf("sauron: uuid of domain %s: %v", name, err)
	}
	if owner, hasOwner, err := domainOwner(dom); err != nil {
		log.Printf("sauron: owner of domain %s: %v", name, err)
	} else if hasOwner {
		guest.Owner = owner
	}
	return guest, true, nil
}

// domainVSockCID extracts the guest CID of the domain's vsock device from its
// live XML, where libvirt records the address it assigned. Reserved CIDs
// (0-2) are never guest addresses and are ignored.
func domainVSockCID(domainXML string) (uint32, bool) {
	var parsed struct {
		Devices struct {
			VSock []struct {
				CID struct {
					Address string `xml:"address,attr"`
				} `xml:"cid"`
			} `xml:"vsock"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domainXML), &parsed); err != nil {
		return 0, false
	}
	for _, device := range parsed.Devices.VSock {
		cid, err := strconv.ParseUint(device.CID.Address, 10, 32)
		if err == nil && cid > 2 {
			return uint32(cid), true
		}
	}
	return 0, false
}
