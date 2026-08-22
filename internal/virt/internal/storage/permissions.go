package storage

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

const (
	// Keep VM disks and seed ISOs accessible to the owning/group libvirt stack
	// without exposing them to every local host user.
	fixedLibvirtVolumeMode     = "0660"
	fixedLibvirtVolumeFileMode = 0o660
)

type storagePoolXML struct {
	Target struct {
		Path string `xml:"path"`
	} `xml:"target"`
}

// VolumeXML describes a libvirt storage volume definition.
type VolumeXML struct {
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
	Format      storageVolumeFormatXML `xml:"format"`
	Path        string                 `xml:"path,omitempty"`
	Permissions *PermissionsXML        `xml:"permissions,omitempty"`
}

type storageVolumeFormatXML struct {
	Type string `xml:"type,attr"`
}

// PermissionsXML describes libvirt volume ownership and mode metadata.
type PermissionsXML struct {
	Owner *uint64 `xml:"owner,omitempty"`
	Group *uint64 `xml:"group,omitempty"`
	Mode  *string `xml:"mode,omitempty"`
}

// VolumeCreateXML returns a libvirt volume definition.
func VolumeCreateXML(pool *libvirt.StoragePool, volumeName string, capacityBytes uint64, formatType string) (string, error) {
	return VolumeCreateXMLWithSettings(nil, pool, volumeName, capacityBytes, formatType)
}

// VolumeCreateXMLWithSettings returns a libvirt volume definition using explicit settings.
func VolumeCreateXMLWithSettings(_ *config.SettingsType, pool *libvirt.StoragePool, volumeName string, capacityBytes uint64, formatType string) (string, error) {
	poolPath, err := PoolTargetPath(pool)
	if err != nil {
		return "", err
	}

	permissions, err := VolumePermissions()
	if err != nil {
		return "", err
	}

	volXML, err := xml.MarshalIndent(VolumeXML{
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

// VolumePermissions returns the fixed permissions applied to gateway volumes.
func VolumePermissions() (*PermissionsXML, error) {
	mode := fixedLibvirtVolumeMode
	return &PermissionsXML{Mode: &mode}, nil
}

// VolumePermissionsXML returns the fixed permissions as an XML fragment.
func VolumePermissionsXML() (string, error) {
	return fmt.Sprintf("\n    <permissions>\n      <mode>%s</mode>\n    </permissions>", fixedLibvirtVolumeMode), nil
}

// VolumePathXML returns the target-path XML fragment for a volume.
func VolumePathXML(pool *libvirt.StoragePool, volumeName string) (string, error) {
	poolPath, err := PoolTargetPath(pool)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("\n    <path>%s</path>", filepath.Join(poolPath, volumeName)), nil
}

// PoolTargetPath reads the configured target path from a libvirt pool.
func PoolTargetPath(pool *libvirt.StoragePool) (string, error) {
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

// ApplyVolumePermissions applies the gateway's fixed mode to a volume file.
func ApplyVolumePermissions(_ *config.SettingsType, vol *libvirt.StorageVol) error {
	volPath, err := vol.GetPath()
	if err != nil {
		return fmt.Errorf("get volume path: %w", err)
	}
	if err := os.Chmod(volPath, fixedLibvirtVolumeFileMode); err != nil {
		if CanIgnoreVolumeModeError(err) {
			log.Printf("Skipping chmod for volume %s: %v", volPath, err)
			return nil
		}
		return fmt.Errorf("chmod volume %s to %04o: %w", volPath, fixedLibvirtVolumeFileMode, err)
	}
	return nil
}

// CanIgnoreVolumeModeError reports whether a driver permission error is non-fatal.
func CanIgnoreVolumeModeError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
