package virt

import (
	"encoding/xml"
	"fmt"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"libvirt.org/go/libvirt"
)

const domainBackendIdentityNamespace = "urn:devboxgateway:domain:backend"

// Only the public certificate is kept in libvirt metadata. The private key is
// delivered to this VM through its seed volume, never through the guest network.
type domainBackendMetadata struct {
	XMLName     xml.Name `xml:"backend"`
	UUID        string   `xml:"uuid,attr"`
	ServerName  string   `xml:"serverName"`
	Certificate string   `xml:"certificate"`
}

func setDomainBackendIdentity(dom *libvirt.Domain, certificate, serverName string) error {
	if _, err := backendidentity.TLSConfig(certificate, serverName); err != nil {
		return err
	}
	uuid, err := dom.GetUUIDString()
	if err != nil {
		return fmt.Errorf("read domain UUID: %w", err)
	}
	payload, err := xml.Marshal(domainBackendMetadata{
		UUID: uuid, ServerName: serverName, Certificate: certificate,
	})
	if err != nil {
		return fmt.Errorf("encode backend identity: %w", err)
	}
	return dom.SetMetadata(libvirt.DOMAIN_METADATA_ELEMENT, string(payload),
		"devboxgatewaybackend", domainBackendIdentityNamespace, libvirt.DOMAIN_AFFECT_CONFIG)
}

func domainBackendIdentity(dom *libvirt.Domain) (domainBackendMetadata, error) {
	payload, err := dom.GetMetadata(libvirt.DOMAIN_METADATA_ELEMENT,
		domainBackendIdentityNamespace, libvirt.DOMAIN_AFFECT_CONFIG)
	if err != nil {
		return domainBackendMetadata{}, fmt.Errorf("read provisioned backend identity (recreate VMs without one): %w", err)
	}
	uuid, err := dom.GetUUIDString()
	if err != nil {
		return domainBackendMetadata{}, fmt.Errorf("read domain UUID: %w", err)
	}
	return parseDomainBackendIdentity(payload, uuid)
}

func parseDomainBackendIdentity(payload, uuid string) (domainBackendMetadata, error) {
	var identity domainBackendMetadata
	if err := xml.Unmarshal([]byte(payload), &identity); err != nil {
		return identity, fmt.Errorf("parse backend identity: %w", err)
	}
	if uuid == "" || identity.UUID != uuid {
		return identity, fmt.Errorf("backend identity does not belong to this domain UUID")
	}
	if _, err := backendidentity.TLSConfig(identity.Certificate, identity.ServerName); err != nil {
		return identity, fmt.Errorf("invalid provisioned backend identity: %w", err)
	}
	return identity, nil
}

// VMBackendIdentity returns the trusted public identity provisioned into this
// exact domain. Old or modified domains with no enforced binding fail closed.
func VMBackendIdentity(name string) (certificatePEM, serverName string, err error) {
	conn, err := connectLibvirt()
	if err != nil {
		return "", "", fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() { _, _ = conn.Close() }()
	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return "", "", fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() { _ = dom.Free() }()
	if err := validateDomainNetwork(conn, dom); err != nil {
		return "", "", err
	}
	identity, err := domainBackendIdentity(dom)
	if err != nil {
		return "", "", err
	}
	return identity.Certificate, identity.ServerName, nil
}

func validateDomainSecurity(conn *libvirt.Connect, dom *libvirt.Domain) error {
	if err := validateDomainNetwork(conn, dom); err != nil {
		return fmt.Errorf("VM network protection unavailable (recreate VMs made before network isolation): %w", err)
	}
	if _, err := domainBackendIdentity(dom); err != nil {
		return err
	}
	return nil
}
