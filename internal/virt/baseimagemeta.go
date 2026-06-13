package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"libvirt.org/go/libvirt"
)

const (
	domainBaseImageMetadataNamespace = "urn:rdptlsgateway:domain:baseimage"
	domainBaseImageMetadataPrefix    = "rdptlsgatewaybaseimage"
)

type domainBaseImageMetadata struct {
	XMLName xml.Name `xml:"baseimage"`
	Value   string   `xml:",chardata"`
}

func domainBaseImageMetadataXML(baseImage string) (string, error) {
	baseImage = strings.TrimSpace(baseImage)
	if baseImage == "" {
		return "", fmt.Errorf("domain base image metadata requires a non-empty image name")
	}

	payload, err := xml.Marshal(domainBaseImageMetadata{Value: baseImage})
	if err != nil {
		return "", fmt.Errorf("marshal domain base image metadata: %w", err)
	}
	return string(payload), nil
}

func setDomainBaseImageMetadata(dom *libvirt.Domain, baseImage string) error {
	payload, err := domainBaseImageMetadataXML(baseImage)
	if err != nil {
		return err
	}

	return dom.SetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		payload,
		domainBaseImageMetadataPrefix,
		domainBaseImageMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
}

func domainBaseImage(dom *libvirt.Domain) (string, bool, error) {
	payload, err := dom.GetMetadata(
		libvirt.DOMAIN_METADATA_ELEMENT,
		domainBaseImageMetadataNamespace,
		libvirt.DOMAIN_AFFECT_CONFIG,
	)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN_METADATA) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get domain base image metadata: %w", err)
	}

	var metadata domainBaseImageMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain base image metadata: %w", err)
	}

	baseImage := strings.TrimSpace(metadata.Value)
	if baseImage == "" {
		return "", false, nil
	}
	return baseImage, true, nil
}
