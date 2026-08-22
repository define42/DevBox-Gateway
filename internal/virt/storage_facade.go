package virt

import (
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/virt/internal/storage"

	"libvirt.org/go/libvirt"
)

// DiskCopyProgressFunc receives synchronous observations of source-image bytes
// copied into a new VM's qcow2 volume.
type DiskCopyProgressFunc = storage.DiskCopyProgressFunc

// ListBaseImages returns the selectable images in the configured base-image directory.
func ListBaseImages(settings *config.Settings) ([]string, error) {
	return storage.ListBaseImages(settings)
}

// EnsureBaseImagesAvailable returns an error when no selectable base image exists.
func EnsureBaseImagesAvailable(settings *config.Settings) error {
	return storage.EnsureBaseImagesAvailable(settings)
}

// RemoveVolumes deletes the named volumes from the given storage pool.
func RemoveVolumes(conn *libvirt.Connect, storagePoolName string, volumeNames ...string) error {
	return storage.RemoveVolumes(conn, storagePoolName, volumeNames...)
}

// CopyAndResizeVolume creates a qcow2 volume from the source image and resizes it when needed.
func CopyAndResizeVolume(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {
	return storage.CopyAndResizeVolume(
		conn,
		storagePoolName,
		volumeName,
		sourceImagePath,
		capacityBytes,
	)
}

// CreateUbuntuSeedISOToPool builds a cloud-init seed ISO and uploads it to the storage pool.
func CreateUbuntuSeedISOToPool(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	username string,
	cloudInitPasswordHash string,
	hostname string,
) error {
	return storage.CreateUbuntuSeedISOToPool(
		conn,
		storagePoolName,
		volumeName,
		username,
		cloudInitPasswordHash,
		hostname,
	)
}
