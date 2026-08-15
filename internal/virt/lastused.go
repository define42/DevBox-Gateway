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
	domainLastUsedMetadataNamespace = "urn:devboxgateway:domain:lastused"
	domainLastUsedMetadataPrefix    = "devboxgatewaylastused"
)

type domainLastUsedMetadata struct {
	XMLName xml.Name `xml:"lastused"`
	Value   string   `xml:",chardata"`
}

func domainLastUsedMetadataXML(lastUsed string) (string, error) {
	lastUsed = strings.TrimSpace(lastUsed)
	if lastUsed == "" {
		return "", fmt.Errorf("domain last-used metadata requires a non-empty timestamp")
	}

	payload, err := xml.Marshal(domainLastUsedMetadata{Value: lastUsed})
	if err != nil {
		return "", fmt.Errorf("marshal domain last-used metadata: %w", err)
	}
	return string(payload), nil
}

func setDomainLastUsedMetadata(dom *libvirt.Domain, lastUsed string) error {
	payload, err := domainLastUsedMetadataXML(lastUsed)
	if err != nil {
		return err
	}

	return dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		domainLastUsedMetadataPrefix,
		domainLastUsedMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
}

func domainLastUsed(dom *libvirt.Domain) (string, bool, error) {
	payload, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainLastUsedMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get domain last-used metadata: %w", err)
	}

	var metadata domainLastUsedMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain last-used metadata: %w", err)
	}

	lastUsed := strings.TrimSpace(metadata.Value)
	if lastUsed == "" {
		return "", false, nil
	}
	return lastUsed, true, nil
}

// MarkVMLastUsed records the current time in the named VM's persistent
// libvirt metadata.
func MarkVMLastUsed(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("virtual machine name is required")
	}
	unlockName := vmNameLocks.Lock(name)
	defer unlockName()

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("connect libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	if err := setDomainLastUsedMetadata(dom, nowLastUsedTimestamp()); err != nil {
		return fmt.Errorf("record last-used metadata for %s: %w", name, err)
	}
	return nil
}

func nowLastUsedTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
