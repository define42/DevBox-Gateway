package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/define42/devbox-gateway/internal/virt/internal/storage"
	"github.com/define42/devbox-gateway/internal/vmname"
	"github.com/google/uuid"
	"libvirt.org/go/libvirt"
)

const (
	provisioningNamespace = "urn:devboxgateway:domain:provisioning"
	provisioningPending   = "pending"
	provisioningReady     = "ready"
	provisioningRollback  = "rolling-back"
)

// provisioningIntent is a durable write-ahead record stored in the initial
// persistent domain definition, before its network reservation or disks exist.
// UUID and pool identity bind recovery to this exact operation. Name patterns
// alone never authorize recovery, and pre-existing volumes are never adopted.
type provisioningIntent struct {
	// GetMetadata selects the namespace but returns a payload without it.
	XMLName  xml.Name `xml:"provisioning"`
	Version  int      `xml:"version,attr"`
	State    string   `xml:"state,attr"`
	UUID     string   `xml:"uuid"`
	Name     string   `xml:"name"`
	Owner    string   `xml:"owner"`
	Pool     string   `xml:"pool"`
	PoolUUID string   `xml:"poolUUID"`
	PoolPath string   `xml:"poolPath"`
	Disk     string   `xml:"disk"`
	Seed     string   `xml:"seed"`
}

func (intent provisioningIntent) validate() error {
	if intent.Version != 1 || (intent.State != provisioningPending && intent.State != provisioningReady && intent.State != provisioningRollback) {
		return fmt.Errorf("unsupported provisioning intent version or state")
	}
	if err := validateProvisioningUUIDs(intent.UUID, intent.PoolUUID); err != nil {
		return err
	}
	name, err := vmname.Compose(intent.Owner, vmname.BareHostname(intent.Name, intent.Owner))
	if err != nil || name != intent.Name || intent.Disk != intent.Name || intent.Seed != intent.Name+"_seed.iso" {
		return fmt.Errorf("invalid provisioning owner or artifact names")
	}
	if strings.TrimSpace(intent.Pool) == "" || !filepath.IsAbs(intent.PoolPath) || filepath.Clean(intent.PoolPath) != intent.PoolPath {
		return fmt.Errorf("invalid provisioning storage identity")
	}
	return nil
}

func validateProvisioningUUIDs(values ...string) error {
	for _, value := range values {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return fmt.Errorf("invalid provisioning identity %q", value)
		}
	}
	return nil
}

func readProvisioningIntent(dom *libvirt.Domain) (*provisioningIntent, error) {
	payload, err := dom.GetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, provisioningNamespace, libvirt.DOMAIN_AFFECT_CONFIG)
	if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read provisioning intent: %w", err)
	}
	var intent provisioningIntent
	if err := xml.Unmarshal([]byte(payload), &intent); err != nil {
		return nil, fmt.Errorf("decode provisioning intent: %w", err)
	}
	if err := intent.validate(); err != nil {
		return nil, err
	}
	return &intent, nil
}

func planProvisioningIntent(conn *libvirt.Connect, spec vmProvisionSpec) (*provisioningIntent, error) {
	pool, err := conn.LookupStoragePoolByName(spec.poolName)
	if err != nil {
		return nil, fmt.Errorf("lookup provisioning pool: %w", err)
	}
	defer func() { _ = pool.Free() }()
	poolUUID, err := pool.GetUUIDString()
	if err != nil {
		return nil, fmt.Errorf("read provisioning pool identity: %w", err)
	}
	intent := &provisioningIntent{
		Version: 1, State: provisioningPending, UUID: uuid.NewString(),
		Name: spec.vmName, Owner: spec.owner, Pool: spec.poolName,
		PoolUUID: poolUUID, PoolPath: spec.poolPath, Disk: spec.vmName, Seed: spec.seedISO,
	}
	if err := intent.validate(); err != nil {
		return nil, err
	}
	if err := verifyProvisioningPool(pool, *intent); err != nil {
		return nil, err
	}
	if err := requireProvisioningVolumesAbsent(pool, *intent); err != nil {
		return nil, err
	}
	if err := requireProvisioningReservationAbsent(conn, spec.vmName); err != nil {
		return nil, err
	}
	return intent, nil
}

func requireProvisioningVolumesAbsent(pool *libvirt.StoragePool, intent provisioningIntent) error {
	for _, name := range []string{intent.Disk, intent.Seed} {
		volume, err := pool.LookupStorageVolByName(name)
		if errors.Is(err, libvirt.ERR_NO_STORAGE_VOL) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect provisioning volume %s: %w", name, err)
		}
		_ = volume.Free()
		return fmt.Errorf("provisioning volume %s already exists without an owned pending intent", name)
	}
	return nil
}

func requireProvisioningReservationAbsent(conn *libvirt.Connect, name string) error {
	network, err := conn.LookupNetworkByName(defaultNetworkName)
	if errors.Is(err, libvirt.ERR_NO_NETWORK) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect provisioning network: %w", err)
	}
	defer func() { _ = network.Free() }()
	hosts, err := readNetworkReservations(network)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if host.Name == networkReservationName(name) {
			return fmt.Errorf("VM %s already has a reservation without an owned pending intent", name)
		}
	}
	return nil
}

func provisioningMetadataXML(intent provisioningIntent) (string, error) {
	payload, err := xml.Marshal(intent)
	if err != nil {
		return "", fmt.Errorf("encode provisioning intent: %w", err)
	}
	namespaced := strings.Replace(string(payload), "<provisioning", "<provisioning xmlns='"+provisioningNamespace+"'", 1)
	return "<metadata><owner xmlns='" + domainOwnerMetadataNamespace + "'>" + xmlValue(intent.Owner) +
		"</owner>" + namespaced + "</metadata>", nil
}

func pendingProvisioningXML(intent provisioningIntent) (string, error) {
	metadata, err := provisioningMetadataXML(intent)
	if err != nil {
		return "", err
	}
	// This definition is deliberately unbootable: its sole purpose is a
	// persistent ownership record until the real disk and NIC are ready.
	return "<domain type='kvm'><name>" + xmlValue(intent.Name) + "</name><uuid>" + intent.UUID +
		"</uuid><memory unit='MiB'>128</memory><vcpu>1</vcpu><os><type arch='x86_64' machine='q35'>hvm</type></os>" +
		metadata + "</domain>", nil
}

func definePendingProvisioning(conn *libvirt.Connect, intent provisioningIntent) error {
	doc, err := pendingProvisioningXML(intent)
	if err != nil {
		return err
	}
	dom, err := conn.DomainDefineXML(doc)
	if err != nil {
		return fmt.Errorf("persist pending provisioning: %w", err)
	}
	defer func() { _ = dom.Free() }()
	return nil
}

func provisioningStartXML(cfg VMStartConfig) (string, error) {
	doc := DomainXML(cfg.Name, cfg.SeedISO, cfg.StoragePoolName, cfg.VCPU, cfg.MemoryMiB, cfg.VSock, cfg.Network)
	if cfg.provisioning == nil {
		return doc, nil
	}
	metadata, err := provisioningMetadataXML(*cfg.provisioning)
	if err != nil {
		return "", err
	}
	return strings.Replace(doc, "</name>", "</name><uuid>"+cfg.provisioning.UUID+"</uuid>"+metadata, 1), nil
}

func verifyProvisioningStart(conn *libvirt.Connect, cfg VMStartConfig) error {
	if cfg.provisioning == nil {
		return nil
	}
	dom, err := conn.LookupDomainByName(cfg.Name)
	if err != nil {
		return fmt.Errorf("lookup pending VM before start: %w", err)
	}
	defer func() { _ = dom.Free() }()
	_, err = verifyProvisioningDomain(dom, *cfg.provisioning)
	return err
}

func markProvisioningReady(dom *libvirt.Domain, intent *provisioningIntent) error {
	if intent == nil {
		return nil
	}
	return setProvisioningState(dom, *intent, provisioningReady)
}

func setProvisioningState(dom *libvirt.Domain, intent provisioningIntent, state string) error {
	intent.State = state
	payload, err := xml.Marshal(intent)
	if err != nil {
		return fmt.Errorf("encode provisioning state: %w", err)
	}
	if err := dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, string(payload), "devboxprovisioning", provisioningNamespace, libvirt.DOMAIN_AFFECT_CONFIG); err != nil {
		return fmt.Errorf("persist provisioning state: %w", err)
	}
	return nil
}

func ensureProvisioningComplete(dom *libvirt.Domain) error {
	intent, err := readProvisioningIntent(dom)
	if err != nil {
		return err
	}
	if intent != nil && intent.State != provisioningReady {
		return fmt.Errorf("VM provisioning is incomplete; retry creation or remove the VM")
	}
	return nil
}

func verifyProvisioningPool(pool *libvirt.StoragePool, intent provisioningIntent) error {
	id, err := pool.GetUUIDString()
	if err != nil {
		return fmt.Errorf("read recovery pool UUID: %w", err)
	}
	path, err := storage.PoolTargetPath(pool)
	if err != nil {
		return err
	}
	return verifyProvisioningPoolIdentity(id, path, intent)
}

func verifyProvisioningPoolIdentity(id, path string, intent provisioningIntent) error {
	if id != intent.PoolUUID || filepath.Clean(path) != intent.PoolPath {
		return fmt.Errorf("provisioning pool identity changed; refusing cleanup of %s", intent.Name)
	}
	return nil
}
