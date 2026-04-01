package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"libvirt.org/go/libvirt"
)

const (
	domainOwnerMetadataNamespace = "urn:rdptlsgateway:domain:owner"
	domainOwnerMetadataPrefix    = "rdptlsgateway"
)

type domainOwnerMetadata struct {
	XMLName xml.Name `xml:"owner"`
	Value   string   `xml:",chardata"`
}

func domainOwnerMetadataXML(owner string) (string, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", fmt.Errorf("domain owner metadata requires a non-empty owner")
	}

	payload, err := xml.Marshal(domainOwnerMetadata{Value: owner})
	if err != nil {
		return "", fmt.Errorf("marshal domain owner metadata: %w", err)
	}
	return string(payload), nil
}

func setDomainOwnerMetadata(dom *libvirt.Domain, owner string) error {
	payload, err := domainOwnerMetadataXML(owner)
	if err != nil {
		return err
	}

	return dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		domainOwnerMetadataPrefix,
		domainOwnerMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
}

func domainOwner(dom *libvirt.Domain) (string, bool, error) {
	payload, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainOwnerMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get domain owner metadata: %w", err)
	}

	var metadata domainOwnerMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain owner metadata: %w", err)
	}

	owner := strings.TrimSpace(metadata.Value)
	if owner == "" {
		return "", false, nil
	}
	return owner, true, nil
}

// UserOwnsVM reports whether the named VM is owned by the given user.
func UserOwnsVM(name, username string) (bool, error) {
	owner, hasOwner, err := VMOwner(name)
	if err != nil {
		return false, err
	}

	return ownedByUser(owner, hasOwner, username), nil
}

// VMOwner returns the owner metadata for the named VM when present.
func VMOwner(name string) (string, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false, nil
	}

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return "", false, fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	owner, hasOwner, err := domainOwner(dom)
	if err != nil {
		return "", false, fmt.Errorf("read domain owner for %s: %w", name, err)
	}
	if !hasOwner {
		return "", false, nil
	}

	return owner, true, nil
}

func ownedByUser(owner string, hasOwner bool, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" || !hasOwner {
		return false
	}

	return strings.TrimSpace(owner) == username
}
