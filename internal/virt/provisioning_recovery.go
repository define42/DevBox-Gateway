package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/define42/devbox-gateway/internal/virt/internal/storage"
	"libvirt.org/go/libvirt"
)

// recoverPendingProvisioning runs before accepting requests. Only explicit,
// valid operation records are considered; legacy domains and nameless orphan
// files are never inferred to belong to the gateway. Failed cleanup leaves
// the persistent intent in place so the next start or same-name retry resumes.
func recoverPendingProvisioning(conn *libvirt.Connect) error {
	domains, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_PERSISTENT)
	if err != nil {
		return fmt.Errorf("list pending provisioning: %w", err)
	}
	defer freeDomains(domains)
	var failures []error
	for i := range domains {
		name, err := domains[i].GetName()
		if err == nil {
			err = recoverPendingProvisioningName(conn, name)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("recover provisioning %s: %w", name, err))
		}
	}
	return errors.Join(failures...)
}

func recoverPendingProvisioningName(conn *libvirt.Connect, name string) error {
	unlock := vmNameLocks.Lock(name)
	defer unlock()
	return recoverPendingProvisioningLocked(conn, name)
}

func recoverPendingProvisioningLocked(conn *libvirt.Connect, name string) error {
	dom, err := lookupRemovalDomain(conn, name)
	if err != nil || dom == nil {
		return err
	}
	defer func() { _ = dom.Free() }()
	intent, err := readProvisioningIntent(dom)
	if err != nil || intent == nil {
		return err
	}
	if intent.State == provisioningReady {
		// Completed VMs may subsequently be maintained by the operator. They
		// are not recovery candidates, so do not validate their current layout
		// against an old creation record or interfere with later owner changes.
		return nil
	}
	return recoverProvisioningDomain(conn, dom, *intent, false)
}

func rollbackProvisioningIntent(intent provisioningIntent) error {
	conn, err := connectLibvirt()
	if err != nil {
		return fmt.Errorf("connect to libvirt for rollback: %w", err)
	}
	defer func() { _, _ = conn.Close() }()
	dom, err := lookupRemovalDomain(conn, intent.Name)
	if err != nil || dom == nil {
		// A failed initial definition may have left nothing. Without the durable
		// domain identity there is no authority to delete same-named resources.
		return err
	}
	defer func() { _ = dom.Free() }()
	return recoverProvisioningDomain(conn, dom, intent, true)
}

type provisioningRecoveryActions struct {
	validateStorage func() error
	beginRollback   func() error
	stop            func() error
	removeVolumes   func() error
	releaseNetwork  func() error
	undefine        func() error
}

// A ready record is the durable commit point. It is written before the first
// start, so a crash after a successful Create (or a guest shutdown before
// recovery) can never be mistaken for an abandoned disk copy. An ordinary
// failed request may still explicitly roll back its own UUID-bound operation.
func runProvisioningRecovery(intent provisioningIntent, active, rollback bool, actions provisioningRecoveryActions) error {
	if intent.State == provisioningReady && !rollback {
		return nil
	}
	if active && !rollback && intent.State != provisioningRollback {
		return fmt.Errorf("pending VM is active; refusing automatic provisioning cleanup")
	}
	if err := actions.validateStorage(); err != nil {
		return err
	}
	// Reset the commit marker before destructive work. If rollback itself is
	// interrupted, startup must resume cleanup rather than preserve a ready
	// definition whose volumes have already been removed.
	if err := actions.beginRollback(); err != nil {
		return err
	}
	if active {
		if err := actions.stop(); err != nil {
			return fmt.Errorf("stop failed provisioning: %w", err)
		}
	}
	if err := actions.removeVolumes(); err != nil {
		return fmt.Errorf("remove provisioning volumes: %w", err)
	}
	if err := actions.releaseNetwork(); err != nil {
		return fmt.Errorf("release provisioning reservation: %w", err)
	}
	if err := actions.undefine(); err != nil {
		return fmt.Errorf("remove provisioning intent: %w", err)
	}
	return nil
}

func recoverProvisioningDomain(conn *libvirt.Connect, dom *libvirt.Domain, expected provisioningIntent, rollback bool) error {
	intent, err := verifyProvisioningDomain(dom, expected)
	if err != nil {
		return err
	}
	active, err := dom.IsActive()
	if err != nil {
		return fmt.Errorf("read pending VM state: %w", err)
	}
	return runProvisioningRecovery(intent, active, rollback, provisioningRecoveryActions{
		validateStorage: func() error { return validateProvisioningStorage(conn, intent) },
		beginRollback:   func() error { return setProvisioningState(dom, intent, provisioningRollback) },
		stop:            dom.Destroy,
		removeVolumes: func() error {
			return storage.RemoveVolumes(conn, intent.Pool, intent.Disk, intent.Seed)
		},
		releaseNetwork: func() error { return releaseNetworkIdentity(conn, intent.Name) },
		undefine:       dom.Undefine,
	})
}

func verifyProvisioningDomain(dom *libvirt.Domain, expected provisioningIntent) (provisioningIntent, error) {
	intent, err := readProvisioningIntent(dom)
	if err != nil {
		return provisioningIntent{}, err
	}
	if intent == nil || !sameProvisioningOperation(*intent, expected) {
		return provisioningIntent{}, fmt.Errorf("VM provisioning identity changed; refusing cleanup")
	}
	doc, err := dom.GetXMLDesc(libvirt.DOMAIN_XML_INACTIVE)
	if err != nil {
		return provisioningIntent{}, fmt.Errorf("read pending VM definition: %w", err)
	}
	if err := validateProvisioningDomainXML(doc, *intent); err != nil {
		return provisioningIntent{}, err
	}
	return *intent, nil
}

func sameProvisioningOperation(first, second provisioningIntent) bool {
	// State may advance to ready before an interrupted request rolls back.
	first.State, second.State = "", ""
	first.XMLName, second.XMLName = xml.Name{}, xml.Name{}
	return first == second
}

func validateProvisioningDomainXML(doc string, intent provisioningIntent) error {
	var domain struct {
		Name     string `xml:"name"`
		UUID     string `xml:"uuid"`
		Metadata struct {
			Owner string `xml:"urn:devboxgateway:domain:owner owner"`
		} `xml:"metadata"`
		Disks []struct {
			Source struct {
				Pool   string `xml:"pool,attr"`
				Volume string `xml:"volume,attr"`
			} `xml:"source"`
		} `xml:"devices>disk"`
	}
	if err := xml.Unmarshal([]byte(doc), &domain); err != nil {
		return fmt.Errorf("decode pending VM definition: %w", err)
	}
	if domain.Name != intent.Name || domain.UUID != intent.UUID || domain.Metadata.Owner != intent.Owner {
		return fmt.Errorf("pending VM UUID, name or owner changed; refusing cleanup")
	}
	for _, disk := range domain.Disks {
		if disk.Source.Pool != intent.Pool || (disk.Source.Volume != intent.Disk && disk.Source.Volume != intent.Seed) {
			return fmt.Errorf("pending VM references an unrelated disk; refusing cleanup")
		}
	}
	return nil
}

func validateProvisioningStorage(conn *libvirt.Connect, intent provisioningIntent) error {
	pool, err := conn.LookupStoragePoolByName(intent.Pool)
	if err != nil {
		return fmt.Errorf("lookup recovery pool: %w", err)
	}
	defer func() { _ = pool.Free() }()
	if err := verifyProvisioningPool(pool, intent); err != nil {
		return err
	}
	if err := verifyProvisioningVolumePaths(pool, intent); err != nil {
		return err
	}
	domains, err := conn.ListAllDomains(0)
	if err != nil {
		return fmt.Errorf("check provisioning disk users: %w", err)
	}
	defer freeDomains(domains)
	for i := range domains {
		if err := checkProvisioningDiskUser(&domains[i], intent); err != nil {
			return err
		}
	}
	return nil
}

func verifyProvisioningVolumePaths(pool *libvirt.StoragePool, intent provisioningIntent) error {
	for _, name := range []string{intent.Disk, intent.Seed} {
		volume, err := pool.LookupStorageVolByName(name)
		if errors.Is(err, libvirt.ERR_NO_STORAGE_VOL) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect recovery volume %s: %w", name, err)
		}
		path, pathErr := volume.GetPath()
		_ = volume.Free()
		if pathErr != nil {
			return fmt.Errorf("inspect recovery volume path: %w", pathErr)
		}
		if filepath.Clean(path) != filepath.Join(intent.PoolPath, name) {
			return fmt.Errorf("provisioning volume %s changed path; refusing cleanup", name)
		}
	}
	return nil
}

func checkProvisioningDiskUser(dom *libvirt.Domain, intent provisioningIntent) error {
	id, err := dom.GetUUIDString()
	if err != nil {
		return fmt.Errorf("identify provisioning disk user: %w", err)
	}
	if id == intent.UUID {
		return nil
	}
	flags := []libvirt.DomainXMLFlags{0}
	persistent, err := dom.IsPersistent()
	if err != nil {
		return fmt.Errorf("inspect provisioning disk user: %w", err)
	}
	if persistent {
		flags = append(flags, libvirt.DOMAIN_XML_INACTIVE)
	}
	for _, flag := range flags {
		doc, err := dom.GetXMLDesc(flag)
		if err != nil {
			return fmt.Errorf("read provisioning disk user: %w", err)
		}
		used, err := referencesProvisioningVolume(doc, intent)
		if err != nil {
			return err
		}
		if used {
			return fmt.Errorf("provisioning volume is referenced by domain %s; refusing cleanup", id)
		}
	}
	return nil
}

func referencesProvisioningVolume(doc string, intent provisioningIntent) (bool, error) {
	decoder := xml.NewDecoder(strings.NewReader(doc))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("decode provisioning disk references: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if ok && start.Name.Local == "source" && provisioningSourceMatches(start.Attr, intent) {
			return true, nil
		}
	}
}

func provisioningSourceMatches(attributes []xml.Attr, intent provisioningIntent) bool {
	for _, attribute := range attributes {
		switch attribute.Name.Local {
		case "volume":
			// A same-named volume in another pool may alias the same directory.
			// Refuse conservatively rather than assume independent storage.
			if attribute.Value == intent.Disk || attribute.Value == intent.Seed {
				return true
			}
		case "file", "dev":
			path := filepath.Clean(attribute.Value)
			if path == filepath.Join(intent.PoolPath, intent.Disk) || path == filepath.Join(intent.PoolPath, intent.Seed) {
				return true
			}
		}
	}
	return false
}
