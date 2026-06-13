package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	domainCreatedAtMetadataNamespace = "urn:rdptlsgateway:domain:createdat"
	domainCreatedAtMetadataPrefix    = "rdptlsgatewaycreatedat"
)

type domainCreatedAtMetadata struct {
	XMLName xml.Name `xml:"createdat"`
	Value   string   `xml:",chardata"`
}

func domainCreatedAtMetadataXML(createdAt string) (string, error) {
	createdAt = strings.TrimSpace(createdAt)
	if createdAt == "" {
		return "", fmt.Errorf("domain created-at metadata requires a non-empty timestamp")
	}

	payload, err := xml.Marshal(domainCreatedAtMetadata{Value: createdAt})
	if err != nil {
		return "", fmt.Errorf("marshal domain created-at metadata: %w", err)
	}
	return string(payload), nil
}

func setDomainCreatedAtMetadata(dom *libvirt.Domain, createdAt string) error {
	payload, err := domainCreatedAtMetadataXML(createdAt)
	if err != nil {
		return err
	}

	return dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		domainCreatedAtMetadataPrefix,
		domainCreatedAtMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
}

func domainCreatedAt(dom *libvirt.Domain) (string, bool, error) {
	payload, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainCreatedAtMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get domain created-at metadata: %w", err)
	}

	var metadata domainCreatedAtMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain created-at metadata: %w", err)
	}

	createdAt := strings.TrimSpace(metadata.Value)
	if createdAt == "" {
		return "", false, nil
	}
	return createdAt, true, nil
}

// nowCreatedAtTimestamp returns the current time formatted as the RFC3339 UTC
// string stored in domain created-at metadata.
func nowCreatedAtTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
