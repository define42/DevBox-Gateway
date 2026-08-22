package virt

import (
	"io"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/virt/internal/storage"

	"libvirt.org/go/libvirt"
)

// DiskCopyProgressFunc receives synchronous observations of source-image bytes
// copied into a new VM's qcow2 volume.
type DiskCopyProgressFunc = storage.DiskCopyProgressFunc

var (
	// ErrInvalidBaseImageName means a managed image name is unsafe or unsupported.
	ErrInvalidBaseImageName = storage.ErrInvalidBaseImageName
	// ErrBaseImageExists means an upload would overwrite an existing entry.
	ErrBaseImageExists = storage.ErrBaseImageExists
	// ErrBaseImageNotFound means a managed regular image file does not exist.
	ErrBaseImageNotFound = storage.ErrBaseImageNotFound
	// ErrEmptyBaseImage means an uploaded image contains no data.
	ErrEmptyBaseImage = storage.ErrEmptyBaseImage
	// ErrInvalidBaseImageFormat means an image lacks the QCOW2 magic header.
	ErrInvalidBaseImageFormat = storage.ErrInvalidBaseImageFormat
	// ErrBaseImageTooLarge means an uploaded image exceeds its configured limit.
	ErrBaseImageTooLarge = storage.ErrBaseImageTooLarge
)

// ListBaseImages returns the selectable images in the configured base-image directory.
func ListBaseImages(settings *config.Settings) ([]string, error) {
	return storage.ListBaseImages(settings)
}

// BaseImageAvailableBytes returns available filesystem capacity for the base-image library.
func BaseImageAvailableBytes(settings *config.Settings) (uint64, error) {
	return storage.BaseImageAvailableBytes(settings)
}

// EnsureBaseImagesAvailable returns an error when no selectable base image exists.
func EnsureBaseImagesAvailable(settings *config.Settings) error {
	return storage.EnsureBaseImagesAvailable(settings)
}

// StoreBaseImage streams a base image into the configured library without overwriting.
func StoreBaseImage(settings *config.Settings, name string, src io.Reader, maxBytes int64) (int64, error) {
	return storage.StoreBaseImage(settings, name, src, maxBytes)
}

// DeleteBaseImage removes a regular file from the configured base-image library.
func DeleteBaseImage(settings *config.Settings, name string) error {
	return storage.DeleteBaseImage(settings, name)
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
