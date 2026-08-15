package virt

import (
	"encoding/xml"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"libvirt.org/go/libvirt"
)

type inventoryHostIdentity struct {
	URI      string
	HostUUID string
	Hostname string
}

func (identity inventoryHostIdentity) String() string {
	host := identity.HostUUID
	if host == "" {
		host = identity.Hostname
	}
	return identity.URI + " (" + host + ")"
}

type (
	hostURIGetter          func() (string, error)
	hostCapabilitiesGetter func() (string, error)
	hostNameGetter         func() (string, error)
)

// loadInventoryHostIdentity combines libvirt's canonical connection URI with
// the stable host UUID advertised by capabilities XML. Some drivers (notably
// libvirt's test driver) omit that optional UUID, so hostname is the fallback.
func loadInventoryHostIdentity(
	getURI hostURIGetter,
	getCapabilities hostCapabilitiesGetter,
	getHostname hostNameGetter,
) (inventoryHostIdentity, error) {
	canonicalURI, err := getURI()
	if err != nil {
		return inventoryHostIdentity{}, fmt.Errorf("get canonical libvirt URI: %w", err)
	}
	canonicalURI = strings.TrimSpace(canonicalURI)
	if canonicalURI == "" {
		return inventoryHostIdentity{}, fmt.Errorf("get canonical libvirt URI: empty result")
	}

	capabilities, err := getCapabilities()
	if err != nil {
		return inventoryHostIdentity{}, fmt.Errorf("get libvirt capabilities: %w", err)
	}

	var document struct {
		XMLName xml.Name `xml:"capabilities"`
		Host    struct {
			UUID string `xml:"uuid"`
		} `xml:"host"`
	}
	if err := xml.Unmarshal([]byte(capabilities), &document); err != nil {
		return inventoryHostIdentity{}, fmt.Errorf("parse libvirt capabilities: %w", err)
	}

	rawHostUUID := strings.TrimSpace(document.Host.UUID)
	if rawHostUUID != "" {
		hostUUID, parseErr := uuid.Parse(rawHostUUID)
		if parseErr != nil {
			return inventoryHostIdentity{}, fmt.Errorf("parse libvirt host UUID: %w", parseErr)
		}
		if hostUUID != uuid.Nil {
			return inventoryHostIdentity{URI: canonicalURI, HostUUID: hostUUID.String()}, nil
		}
	}

	hostname, err := getHostname()
	if err != nil {
		return inventoryHostIdentity{}, fmt.Errorf("get libvirt hostname: %w", err)
	}
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" {
		return inventoryHostIdentity{}, fmt.Errorf("get libvirt hostname: empty result")
	}
	return inventoryHostIdentity{URI: canonicalURI, Hostname: hostname}, nil
}

func (s *SingletonWorker) observeInventoryHost(conn *libvirt.Connect) error {
	identity, err := loadInventoryHostIdentity(conn.GetURI, conn.GetCapabilities, conn.GetHostname)
	if err != nil {
		return err
	}

	previous, invalidated := s.setInventoryHostIdentity(identity)
	if invalidated && previous == (inventoryHostIdentity{}) {
		log.Printf("libvirt inventory host identity established as %s; clearing unverified inventory caches", identity)
	} else if invalidated {
		// UUID-keyed domain snapshots are valid only for the host from which they
		// were read. A positively identified host change is the one reconnect
		// boundary that invalidates both caches.
		log.Printf("libvirt inventory host changed from %s to %s; clearing inventory caches", previous, identity)
	}
	return nil
}

func (s *SingletonWorker) setInventoryHostIdentity(identity inventoryHostIdentity) (
	previous inventoryHostIdentity,
	invalidated bool,
) {
	if identity.URI == "" || (identity.HostUUID == "" && identity.Hostname == "") {
		return inventoryHostIdentity{}, false
	}

	s.inventoryCacheMu.Lock()
	previous = s.inventoryHostIdentity
	if previous == (inventoryHostIdentity{}) {
		hadUnverifiedCaches := len(s.metadataByUUID) != 0 || len(s.diskByUUID) != 0
		s.inventoryHostIdentity = identity
		s.metadataByUUID = nil
		s.diskByUUID = nil
		s.inventoryCacheMu.Unlock()
		if hadUnverifiedCaches {
			// Without a recorded source identity, cached UUIDs have unknown
			// provenance. Discard their associated visible snapshot as well.
			s.invalidateVMSnapshot()
		}
		return previous, hadUnverifiedCaches
	}
	if previous == identity {
		s.inventoryCacheMu.Unlock()
		return previous, false
	}

	s.inventoryHostIdentity = identity
	s.metadataByUUID = nil
	s.diskByUUID = nil
	s.inventoryCacheMu.Unlock()

	// Do not expose the previous host's VMs if the first inventory attempt on
	// the new host fails. This runs after releasing inventoryCacheMu so the VM
	// snapshot lock is never nested inside the inventory cache lock.
	s.invalidateVMSnapshot()
	return previous, true
}
