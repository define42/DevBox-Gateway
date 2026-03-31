package virt

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kdomanski/iso9660"
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

type domainDiskSourceXML struct {
	Pool   string `xml:"pool,attr"`
	Volume string `xml:"volume,attr"`
}

type domainDiskXML struct {
	Type   string              `xml:"type,attr"`
	Source domainDiskSourceXML `xml:"source"`
}

type domainDefinitionXML struct {
	Devices struct {
		Disks []domainDiskXML `xml:"disk"`
	} `xml:"devices"`
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
			return legacyDomainOwner(dom)
		}
		return "", false, fmt.Errorf("get domain owner metadata: %w", err)
	}

	var metadata domainOwnerMetadata
	if err := xml.Unmarshal([]byte(payload), &metadata); err != nil {
		return "", false, fmt.Errorf("parse domain owner metadata: %w", err)
	}

	owner := strings.TrimSpace(metadata.Value)
	if owner == "" {
		return legacyDomainOwner(dom)
	}
	return owner, true, nil
}

func legacyDomainOwner(dom *libvirt.Domain) (string, bool, error) {
	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return "", false, fmt.Errorf("get domain xml: %w", err)
	}

	poolName, volumeName, ok, err := seedISOVolumeFromDomainXML(xmlDesc)
	if err != nil || !ok {
		return "", false, err
	}

	conn, err := dom.DomainGetConnect()
	if err != nil {
		return "", false, fmt.Errorf("get domain connection: %w", err)
	}
	defer conn.Close()

	pool, err := conn.LookupStoragePoolByName(poolName)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_STORAGE_POOL) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("lookup storage pool %s: %w", poolName, err)
	}
	defer func() {
		_ = pool.Free()
	}()

	vol, err := pool.LookupStorageVolByName(volumeName)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_STORAGE_VOL) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("lookup seed ISO volume %s: %w", volumeName, err)
	}
	defer func() {
		_ = vol.Free()
	}()

	owner, ok, err := seedISOOwner(conn, vol)
	if err != nil || !ok {
		return "", false, err
	}

	// Best effort backfill so subsequent checks can read stable metadata directly.
	_ = setDomainOwnerMetadata(dom, owner)

	return owner, true, nil
}

func seedISOVolumeFromDomainXML(xmlDesc string) (string, string, bool, error) {
	var parsed domainDefinitionXML
	if err := xml.Unmarshal([]byte(xmlDesc), &parsed); err != nil {
		return "", "", false, fmt.Errorf("parse domain xml: %w", err)
	}

	for _, disk := range parsed.Devices.Disks {
		if strings.TrimSpace(disk.Type) != "volume" {
			continue
		}

		volumeName := strings.TrimSpace(disk.Source.Volume)
		if !strings.HasSuffix(volumeName, "_seed.iso") {
			continue
		}

		poolName := strings.TrimSpace(disk.Source.Pool)
		if poolName == "" {
			continue
		}

		return poolName, volumeName, true, nil
	}

	return "", "", false, nil
}

func seedISOOwner(conn *libvirt.Connect, vol *libvirt.StorageVol) (string, bool, error) {
	info, err := vol.GetInfo()
	if err != nil {
		return "", false, fmt.Errorf("get seed ISO info: %w", err)
	}

	stream, err := conn.NewStream(0)
	if err != nil {
		return "", false, fmt.Errorf("create seed ISO download stream: %w", err)
	}
	defer func() {
		_ = stream.Free()
	}()

	if err := vol.Download(stream, 0, info.Capacity, 0); err != nil {
		_ = stream.Abort()
		return "", false, fmt.Errorf("download seed ISO: %w", err)
	}

	var imageData bytes.Buffer
	if err := stream.RecvAll(func(_ *libvirt.Stream, data []byte) (int, error) {
		return imageData.Write(data)
	}); err != nil {
		_ = stream.Abort()
		return "", false, fmt.Errorf("receive seed ISO: %w", err)
	}

	if err := stream.Finish(); err != nil {
		return "", false, fmt.Errorf("finish seed ISO download: %w", err)
	}

	image, err := iso9660.OpenImage(bytes.NewReader(imageData.Bytes()))
	if err != nil {
		return "", false, fmt.Errorf("open seed ISO image: %w", err)
	}

	root, err := image.RootDir()
	if err != nil {
		return "", false, fmt.Errorf("read seed ISO root: %w", err)
	}

	children, err := root.GetChildren()
	if err != nil {
		return "", false, fmt.Errorf("read seed ISO entries: %w", err)
	}

	for _, child := range children {
		if child.IsDir() || !strings.EqualFold(child.Name(), "user-data") {
			continue
		}

		reader := child.Reader()
		if reader == nil {
			return "", false, nil
		}

		data, err := io.ReadAll(reader)
		if err != nil {
			return "", false, fmt.Errorf("read seed ISO user-data: %w", err)
		}

		return cloudInitUserName(data)
	}

	return "", false, nil
}

func cloudInitUserName(data []byte) (string, bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "- name:") {
			continue
		}

		username := strings.TrimSpace(strings.TrimPrefix(line, "- name:"))
		username = strings.Trim(username, `"'`)
		if username == "" {
			return "", false, nil
		}

		return username, true, nil
	}

	if err := scanner.Err(); err != nil {
		return "", false, fmt.Errorf("scan seed ISO user-data: %w", err)
	}

	return "", false, nil
}

func UserOwnsVM(name, username string) (bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return false, nil
	}

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return false, fmt.Errorf("connect libvirt: %w", err)
	}
	defer conn.Close()

	dom, err := conn.LookupDomainByName(name)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
			return false, nil
		}
		return false, fmt.Errorf("lookup domain %s: %w", name, err)
	}
	defer func() {
		_ = dom.Free()
	}()

	owner, hasOwner, err := domainOwner(dom)
	if err != nil {
		return false, fmt.Errorf("read domain owner for %s: %w", name, err)
	}
	if !hasOwner {
		return false, nil
	}

	return owner == username, nil
}
