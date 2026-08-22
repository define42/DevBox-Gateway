package virt

import (
	"io"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/virt/internal/storage"

	"libvirt.org/go/libvirt"
)

// These aliases and delegates keep the existing virt white-box tests focused
// on behavior while the implementation lives behind the storage package
// boundary. They are compiled only for tests and do not widen virt's runtime
// API or reconnect production code to storage internals.
type (
	storageVolumeXML            = storage.VolumeXML
	storageVolumePermissionsXML = storage.PermissionsXML
)

func storagePoolConfig(settings *config.SettingsType) (string, string) {
	return storage.PoolConfig(settings)
}

func ensureStoragePool(
	conn *libvirt.Connect,
	poolName string,
	poolPath string,
) (*libvirt.StoragePool, error) {
	return storage.EnsurePool(conn, poolName, poolPath)
}

func ensureBootStoragePool(conn *libvirt.Connect, poolName, poolPath string) error {
	return storage.EnsureBootPool(conn, poolName, poolPath)
}

func lookupOrDefineStoragePool(
	conn *libvirt.Connect,
	poolName string,
	poolPath string,
) (*libvirt.StoragePool, error) {
	return storage.LookupOrDefinePool(conn, poolName, poolPath)
}

func reconcileStoragePoolTargetPath(
	conn *libvirt.Connect,
	pool *libvirt.StoragePool,
	poolName string,
	poolPath string,
) (*libvirt.StoragePool, error) {
	return storage.ReconcilePoolTargetPath(conn, pool, poolName, poolPath)
}

func storagePoolDefinitionXML(poolName, poolPath string) string {
	return storage.PoolDefinitionXML(poolName, poolPath)
}

func startStoragePoolIfNeeded(pool *libvirt.StoragePool, poolName string) error {
	return storage.StartPoolIfNeeded(pool, poolName)
}

func configureStoragePoolAutostart(pool *libvirt.StoragePool, poolName string) {
	storage.ConfigurePoolAutostart(pool, poolName)
}

func logStoragePoolTargetPath(pool *libvirt.StoragePool, poolName, poolPath string) {
	storage.LogPoolTargetPath(pool, poolName, poolPath)
}

func storageVolCreateXML(
	pool *libvirt.StoragePool,
	volumeName string,
	capacityBytes uint64,
	formatType string,
) (string, error) {
	return storage.VolumeCreateXML(pool, volumeName, capacityBytes, formatType)
}

func storageVolCreateXMLWithSettings(
	settings *config.SettingsType,
	pool *libvirt.StoragePool,
	volumeName string,
	capacityBytes uint64,
	formatType string,
) (string, error) {
	return storage.VolumeCreateXMLWithSettings(
		settings,
		pool,
		volumeName,
		capacityBytes,
		formatType,
	)
}

func storageVolPermissions() (*storageVolumePermissionsXML, error) {
	return storage.VolumePermissions()
}

func storageVolPermissionsXML() (string, error) {
	return storage.VolumePermissionsXML()
}

func storageVolPathXML(pool *libvirt.StoragePool, volumeName string) (string, error) {
	return storage.VolumePathXML(pool, volumeName)
}

func storagePoolTargetPath(pool *libvirt.StoragePool) (string, error) {
	return storage.PoolTargetPath(pool)
}

func applyStorageVolPermissions(settings *config.SettingsType, vol *libvirt.StorageVol) error {
	return storage.ApplyVolumePermissions(settings, vol)
}

func createQCOW2Volume(
	settings *config.SettingsType,
	pool *libvirt.StoragePool,
	volumeName string,
	capacityBytes uint64,
) (*libvirt.StorageVol, error) {
	return storage.CreateQCOW2Volume(settings, pool, volumeName, capacityBytes)
}

func uploadFileToVolume(
	conn *libvirt.Connect,
	vol *libvirt.StorageVol,
	sourceImagePath string,
) error {
	return storage.UploadFileToVolume(conn, vol, sourceImagePath)
}

func streamReaderChunks(src io.Reader) func(*libvirt.Stream, int) ([]byte, error) {
	return storage.StreamReaderChunks(src)
}

func resizeVolumeIfNeeded(vol *libvirt.StorageVol, capacityBytes uint64) error {
	return storage.ResizeVolumeIfNeeded(vol, capacityBytes)
}

func uploadSeedISO(conn *libvirt.Connect, vol *libvirt.StorageVol, data []byte) error {
	return storage.UploadSeedISO(conn, vol, data)
}
