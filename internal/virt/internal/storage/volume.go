// Package storage manages libvirt storage pools, VM volumes, and selectable base images.
package storage

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

// DiskCopyProgressFunc receives synchronous observations of source-image bytes
// copied into a new VM's qcow2 volume. Callbacks should return promptly because
// they run from the libvirt upload stream's reader.
type DiskCopyProgressFunc func(copiedBytes, totalBytes int64)

// ReportProgress calls report when it is non-nil.
func ReportProgress(report DiskCopyProgressFunc, copiedBytes, totalBytes int64) {
	if report == nil {
		return
	}
	report(copiedBytes, totalBytes)
}

// RemoveVolumes deletes the named volumes from the given storage pool.
func RemoveVolumes(conn *libvirt.Connect, storagePoolName string, volumeNames ...string) error {
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return fmt.Errorf("lookup storage pool %s: %w", storagePoolName, err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			log.Printf("pool free error: %v", err)
		}
	}()

	for _, volumeName := range volumeNames {
		vol, err := pool.LookupStorageVolByName(volumeName)
		if err != nil {
			continue
		}
		deleteErr := vol.Delete(0)
		_ = vol.Free()
		if deleteErr != nil {
			return fmt.Errorf("delete volume %s: %w", volumeName, deleteErr)
		}
		log.Printf("Deleted volume %s", volumeName)
	}

	return nil
}

// CopyAndResizeVolume creates a qcow2 volume from the source image and resizes it when needed.
func CopyAndResizeVolume(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {
	return CopyAndResizeVolumeWithSettings(conn, nil, storagePoolName, volumeName, sourceImagePath, capacityBytes)
}

// CopyAndResizeVolumeWithSettings creates and resizes a volume using explicit settings.
func CopyAndResizeVolumeWithSettings(
	conn *libvirt.Connect,
	settings *config.Settings,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {
	return CopyAndResizeVolumeWithSettingsAndProgress(conn, settings, storagePoolName, volumeName, sourceImagePath, capacityBytes, nil)
}

// CopyAndResizeVolumeWithSettingsAndProgress creates and resizes a volume while reporting copy progress.
func CopyAndResizeVolumeWithSettingsAndProgress(
	conn *libvirt.Connect,
	settings *config.Settings,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
	report DiskCopyProgressFunc,
) error {
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return fmt.Errorf("lookup pool %s: %w", storagePoolName, err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			log.Printf("pool free error: %v", err)
		}
	}()

	vol, err := CreateQCOW2Volume(settings, pool, volumeName, capacityBytes)
	if err != nil {
		return err
	}
	defer func() {
		_ = vol.Free()
	}()

	if err := uploadFileToVolumeWithProgress(conn, vol, sourceImagePath, report); err != nil {
		return err
	}

	if err := ResizeVolumeIfNeeded(vol, capacityBytes); err != nil {
		return err
	}

	return ApplyVolumePermissions(settings, vol)
}

// CreateQCOW2Volume creates an empty qcow2 volume in pool.
func CreateQCOW2Volume(settings *config.Settings, pool *libvirt.StoragePool, volumeName string, capacityBytes uint64) (*libvirt.StorageVol, error) {
	volXML, err := VolumeCreateXMLWithSettings(settings, pool, volumeName, capacityBytes, "qcow2")
	if err != nil {
		return nil, err
	}

	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}
	return vol, nil
}

// UploadFileToVolume uploads a source image into a libvirt volume.
func UploadFileToVolume(conn *libvirt.Connect, vol *libvirt.StorageVol, sourceImagePath string) error {
	return uploadFileToVolumeWithProgress(conn, vol, sourceImagePath, nil)
}

func uploadFileToVolumeWithProgress(conn *libvirt.Connect, vol *libvirt.StorageVol, sourceImagePath string, report DiskCopyProgressFunc) error {
	src, srcSize, err := openSourceImage(sourceImagePath)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	stream, err := conn.NewStream(0)
	if err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	defer func() {
		_ = stream.Free()
	}()

	if srcSize < 0 {
		return fmt.Errorf("source image %s reports negative size %d", sourceImagePath, srcSize)
	}
	if err := vol.Upload(stream, 0, uint64(srcSize), 0); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}
	copiedBytes := int64(0)
	ReportProgress(report, copiedBytes, srcSize)
	chunks := StreamReaderChunksWithProgress(src, func(n int) {
		copiedBytes += int64(n)
		if copiedBytes < srcSize {
			ReportProgress(report, copiedBytes, srcSize)
		}
	})
	if err := stream.SendAll(chunks); err != nil {
		_ = stream.Abort()
		return fmt.Errorf("stream send: %w", err)
	}
	if err := stream.Finish(); err != nil {
		return fmt.Errorf("stream finish: %w", err)
	}
	ReportProgress(report, copiedBytes, srcSize)
	return nil
}

// StreamReaderChunks adapts an io.Reader to libvirt's stream callback shape.
func StreamReaderChunks(src io.Reader) func(*libvirt.Stream, int) ([]byte, error) {
	return StreamReaderChunksWithProgress(src, nil)
}

// StreamReaderChunksWithProgress adapts an io.Reader and reports each successful read.
func StreamReaderChunksWithProgress(src io.Reader, onRead func(int)) func(*libvirt.Stream, int) ([]byte, error) {
	return func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
		return readStreamChunk(src, nbytes, onRead)
	}
}

func readStreamChunk(src io.Reader, nbytes int, onRead func(int)) ([]byte, error) {
	if nbytes <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, nbytes)
	n, err := src.Read(buf)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return []byte{}, nil
	}
	if onRead != nil {
		onRead(n)
	}
	return buf[:n], nil
}

func openSourceImage(sourceImagePath string) (*os.File, int64, error) {
	src, err := os.Open(sourceImagePath) // #nosec G304 -- a gateway-resolved image below the operator-configured image/base-image directories, not a request-supplied path
	if err != nil {
		return nil, 0, fmt.Errorf("open source image: %w", err)
	}

	srcInfo, err := src.Stat()
	if err != nil {
		_ = src.Close()
		return nil, 0, fmt.Errorf("stat source image: %w", err)
	}

	return src, srcInfo.Size(), nil
}

// ResizeVolumeIfNeeded grows vol to capacityBytes when it is currently smaller.
func ResizeVolumeIfNeeded(vol *libvirt.StorageVol, capacityBytes uint64) error {
	if capacityBytes == 0 {
		return nil
	}

	volInfo, err := vol.GetInfo()
	if err != nil {
		return fmt.Errorf("get volume info: %w", err)
	}
	if volInfo.Capacity >= capacityBytes {
		return nil
	}
	if err := vol.Resize(capacityBytes, 0); err != nil {
		return fmt.Errorf("resize volume: %w", err)
	}
	return nil
}
