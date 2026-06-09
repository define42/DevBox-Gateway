package virt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strings"
	"syscall"

	"libvirt.org/go/libvirt"
)

const (
	fixedLibvirtVolumeMode     = "0666"
	fixedLibvirtVolumeFileMode = 0o666
)

type storagePoolXML struct {
	Target struct {
		Path string `xml:"path"`
	} `xml:"target"`
}

type storageVolumeXML struct {
	XMLName  xml.Name               `xml:"volume"`
	Name     string                 `xml:"name"`
	Capacity storageVolumeCapacity  `xml:"capacity"`
	Target   storageVolumeTargetXML `xml:"target"`
}

type storageVolumeCapacity struct {
	Unit  string `xml:"unit,attr"`
	Value uint64 `xml:",chardata"`
}

type storageVolumeTargetXML struct {
	Format      storageVolumeFormatXML       `xml:"format"`
	Path        string                       `xml:"path,omitempty"`
	Permissions *storageVolumePermissionsXML `xml:"permissions,omitempty"`
}

type storageVolumeFormatXML struct {
	Type string `xml:"type,attr"`
}

type storageVolumePermissionsXML struct {
	Owner *uint64 `xml:"owner,omitempty"`
	Group *uint64 `xml:"group,omitempty"`
	Mode  *string `xml:"mode,omitempty"`
}

func storageVolCreateXML(pool *libvirt.StoragePool, volumeName string, capacityBytes uint64, formatType string) (string, error) {
	return storageVolCreateXMLWithSettings(nil, pool, volumeName, capacityBytes, formatType)
}

func storageVolCreateXMLWithSettings(_ *config.SettingsType, pool *libvirt.StoragePool, volumeName string, capacityBytes uint64, formatType string) (string, error) {
	poolPath, err := storagePoolTargetPath(pool)
	if err != nil {
		return "", err
	}

	permissions, err := storageVolPermissions()
	if err != nil {
		return "", err
	}

	volXML, err := xml.MarshalIndent(storageVolumeXML{
		Name: volumeName,
		Capacity: storageVolumeCapacity{
			Unit:  "bytes",
			Value: capacityBytes,
		},
		Target: storageVolumeTargetXML{
			Format:      storageVolumeFormatXML{Type: formatType},
			Path:        filepath.Join(poolPath, volumeName),
			Permissions: permissions,
		},
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal storage volume xml: %w", err)
	}

	return string(volXML), nil
}

func storageVolPermissions() (*storageVolumePermissionsXML, error) {
	mode := fixedLibvirtVolumeMode
	return &storageVolumePermissionsXML{Mode: &mode}, nil
}

func storageVolPermissionsXML() (string, error) {
	return fmt.Sprintf("\n    <permissions>\n      <mode>%s</mode>\n    </permissions>", fixedLibvirtVolumeMode), nil
}

func storageVolPathXML(pool *libvirt.StoragePool, volumeName string) (string, error) {
	poolPath, err := storagePoolTargetPath(pool)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("\n    <path>%s</path>", filepath.Join(poolPath, volumeName)), nil
}

func storagePoolTargetPath(pool *libvirt.StoragePool) (string, error) {
	xmlDesc, err := pool.GetXMLDesc(0)
	if err != nil {
		return "", fmt.Errorf("get storage pool xml: %w", err)
	}
	var parsed storagePoolXML
	if err := xml.Unmarshal([]byte(xmlDesc), &parsed); err != nil {
		return "", fmt.Errorf("parse storage pool xml: %w", err)
	}
	path := strings.TrimSpace(parsed.Target.Path)
	if path == "" {
		return "", fmt.Errorf("storage pool target path not found")
	}
	return path, nil
}

func applyStorageVolPermissions(_ *config.SettingsType, vol *libvirt.StorageVol) error {
	volPath, err := vol.GetPath()
	if err != nil {
		return fmt.Errorf("get volume path: %w", err)
	}
	if err := os.Chmod(volPath, fixedLibvirtVolumeFileMode); err != nil {
		if canIgnoreVolumeModeError(err) {
			log.Printf("Skipping chmod for volume %s: %v", volPath, err)
			return nil
		}
		return fmt.Errorf("chmod volume %s to %04o: %w", volPath, fixedLibvirtVolumeFileMode, err)
	}
	return nil
}

func canIgnoreVolumeModeError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
