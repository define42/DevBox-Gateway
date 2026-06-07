package virt

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/hash"
	"rdptlsgateway/internal/types"
	"rdptlsgateway/internal/vmname"
	"strings"

	"libvirt.org/go/libvirt"
)

// StartVM defines and starts a VM without attaching owner metadata.
func StartVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath string, vcpu int, memoryMiB int) error {
	return startVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, "", "", vcpu, memoryMiB)
}

// StartVMWithOwner defines and starts a VM while attaching owner and guest-user metadata.
func StartVMWithOwner(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, owner, guestUser string, vcpu int, memoryMiB int) error {
	return startVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, owner, guestUser, vcpu, memoryMiB)
}

func startVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, owner, guestUser string, vcpu int, memoryMiB int) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Close()
	}()

	if err := removeSocketPath(serialSocketPath, "serial"); err != nil {
		return err
	}
	if err := removeSocketPath(vncSocketPath, "vnc"); err != nil {
		return err
	}

	dom, err := conn.DomainDefineXML(UbuntuDomain(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, vcpu, memoryMiB))
	if err != nil {
		return err
	}
	defer func() {
		_ = dom.Free()
	}()

	if strings.TrimSpace(owner) != "" {
		if err := setDomainOwnerMetadata(dom, owner); err != nil {
			return fmt.Errorf("set owner metadata for %s: %w", name, err)
		}
	}

	if strings.TrimSpace(guestUser) != "" {
		if err := setDomainGuestUserMetadata(dom, guestUser); err != nil {
			return fmt.Errorf("set guest user metadata for %s: %w", name, err)
		}
	}

	if err := dom.Create(); err != nil {
		return err
	}

	return nil
}

// RemoveVolumes deletes the named volumes from the given storage pool.
func RemoveVolumes(conn *libvirt.Connect, storagePoolName string, volumeNames ...string) error {
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return fmt.Errorf("lookup storage pool %s: %w", storagePoolName, err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	for _, volumeName := range volumeNames {
		vol, err := pool.LookupStorageVolByName(volumeName)
		if err != nil {
			continue
		}
		defer func() {
			_ = vol.Free()
		}()

		if err := vol.Delete(0); err != nil {
			return fmt.Errorf("delete volume %s: %w", volumeName, err)
		}
		log.Printf("Deleted volume %s", volumeName)
	}

	return nil
}

func streamReaderChunks(src io.Reader) func(*libvirt.Stream, int) ([]byte, error) {
	return func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
		if nbytes <= 0 {
			return []byte{}, nil
		}
		buf := make([]byte, nbytes)
		n, err := src.Read(buf)
		if err != nil {
			if err == io.EOF {
				if n == 0 {
					return []byte{}, nil
				}
				return buf[:n], nil
			}
			return nil, err
		}
		if n == 0 {
			return []byte{}, nil
		}
		return buf[:n], nil
	}
}

// CopyAndResizeVolume creates a qcow2 volume from the source image and resizes it when needed.
func CopyAndResizeVolume(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {
	return copyAndResizeVolumeWithSettings(conn, nil, storagePoolName, volumeName, sourceImagePath, capacityBytes)
}

func copyAndResizeVolumeWithSettings(
	conn *libvirt.Connect,
	settings *config.SettingsType,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return fmt.Errorf("lookup pool %s: %w", storagePoolName, err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	vol, err := createQCOW2Volume(settings, pool, volumeName, capacityBytes)
	if err != nil {
		return err
	}
	defer func() {
		_ = vol.Free()
	}()

	if err := uploadFileToVolume(conn, vol, sourceImagePath); err != nil {
		return err
	}

	if err := resizeVolumeIfNeeded(vol, capacityBytes); err != nil {
		return err
	}

	return applyStorageVolPermissions(settings, vol)
}

// DestroyExistingDomain force-stops and undefines the named domain when it exists.
func DestroyExistingDomain(conn *libvirt.Connect, vmName string) error {
	existingDom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		return nil
	}
	defer func() {
		_ = existingDom.Free()
	}()

	active, err := existingDom.IsActive()
	if err != nil {
		return err
	}
	if active {
		if err := existingDom.Destroy(); err != nil {
			return err
		}
		log.Printf("Destroyed running domain %s", vmName)
	}

	if err := existingDom.Undefine(); err != nil {
		return err
	}
	log.Printf("Undefined domain %s", vmName)
	return nil
}

// ErrVMAlreadyExists indicates a domain with the requested name already exists.
// Creation never destroys an existing VM, so the user must delete it first.
var ErrVMAlreadyExists = errors.New("vm with this name already exists")

// ensureVMNameAvailable refuses creation when a domain with the same name already
// exists, so a boot can never destroy or overwrite an existing VM (the user must
// delete it first). A missing domain means the name is free to use.
func ensureVMNameAvailable(conn *libvirt.Connect, vmName string) error {
	dom, err := conn.LookupDomainByName(vmName)
	if err != nil {
		if errors.Is(err, libvirt.ERR_NO_DOMAIN) {
			return nil
		}
		return fmt.Errorf("lookup existing domain %s: %w", vmName, err)
	}
	_ = dom.Free()
	return fmt.Errorf("%w: %s", ErrVMAlreadyExists, vmName)
}

func storagePoolConfig(settings *config.SettingsType) (poolName string, poolPath string) {
	poolName = config.DefaultVirtStoragePoolName
	poolPath = config.VirtStoragePoolPath(nil)
	if settings == nil {
		return poolName, filepath.Clean(poolPath)
	}

	if configuredPoolName := strings.TrimSpace(settings.Get(config.VIRT_STORAGE_POOL_NAME)); configuredPoolName != "" {
		poolName = configuredPoolName
	}

	poolPath = config.VirtStoragePoolPath(settings)

	return poolName, filepath.Clean(poolPath)
}

func ensureStoragePool(conn *libvirt.Connect, storagePoolName, storagePoolPath string) (*libvirt.StoragePool, error) {
	storagePoolName, storagePoolPath, err := normalizeStoragePoolConfig(storagePoolName, storagePoolPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(storagePoolPath, 0o755); err != nil {
		return nil, fmt.Errorf("create storage pool path %s: %w", storagePoolPath, err)
	}

	pool, err := lookupOrDefineStoragePool(conn, storagePoolName, storagePoolPath)
	if err != nil {
		return nil, err
	}
	if err := startStoragePoolIfNeeded(pool, storagePoolName); err != nil {
		_ = pool.Free()
		return nil, err
	}

	configureStoragePoolAutostart(pool, storagePoolName)
	logStoragePoolTargetPath(pool, storagePoolName, storagePoolPath)
	return pool, nil
}

// InitVirt ensures the libvirt storage pool and base image are ready for VM operations.
func InitVirt(settings *config.SettingsType) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	if err := ensureLibvirtVersion(conn); err != nil {
		return err
	}

	poolName, poolPath := storagePoolConfig(settings)
	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		return fmt.Errorf("failed to ensure storage pool %s: %w", poolName, err)
	}
	defer func() {
		_ = pool.Free()
	}()

	if _, err := ensureBaseImage(settings); err != nil {
		return fmt.Errorf("failed to ensure base image: %w", err)
	}

	return nil
}

// BootNewVM creates or recreates a VM for the user and starts it with owner metadata.
// The resulting VM (VDI) name is always "<username>-<hostname>", enforced via
// vmname.Compose; an invalid owner or hostname is rejected before anything is created.
// guestUsername is the login account provisioned inside the guest (and used for RDP);
// it falls back to the owning user's name when empty. guestPassword is the password
// for that guest account; it falls back to the owner's gateway password when empty.
func BootNewVM(name string, user *types.User, guestUsername, guestPassword string, settings *config.SettingsType, vcpu int, memoryMiB int) (vmName string, err error) {
	if user == nil {
		return "", fmt.Errorf("vm owner is required")
	}
	name = strings.TrimSpace(name)
	// Enforce the VDI naming invariant ("<username>-<hostname>") at the single
	// construction point so no caller can bypass it.
	vmName, err = vmname.Compose(user.GetName(), name)
	if err != nil {
		return "", err
	}
	guestUsername = strings.TrimSpace(guestUsername)
	if guestUsername == "" {
		guestUsername = user.GetName()
	}

	// The guest account password defaults to the owner's gateway password
	// (preserving prior behavior) but can be overridden per VM at creation.
	cloudInitPasswordHash := user.GetCloudInitPasswordHash()
	if guestPassword != "" {
		cloudInitPasswordHash, err = hash.CloudInitPasswordHash(guestPassword)
		if err != nil {
			return vmName, fmt.Errorf("hash guest password: %w", err)
		}
	}

	if err := validateBootResources(vcpu, memoryMiB); err != nil {
		return vmName, err
	}

	seedIso := vmName + "_seed.iso"
	poolName, poolPath := storagePoolConfig(settings)
	vmSerialSocketPath, vmVNCSocketPath, err := prepareBootSocketPaths(settings, vmName)
	if err != nil {
		return vmName, err
	}

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return vmName, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	if err := ensureBootStoragePool(conn, poolName, poolPath); err != nil {
		return vmName, err
	}
	if err := ensureVMNameAvailable(conn, vmName); err != nil {
		return vmName, err
	}
	if err := resetExistingVMArtifacts(conn, settings, poolName, vmName, seedIso); err != nil {
		return vmName, err
	}
	if err := provisionBootVolumes(conn, settings, poolName, vmName, seedIso, name, guestUsername, cloudInitPasswordHash); err != nil {
		return vmName, err
	}
	if err := StartVMWithOwner(vmName, seedIso, poolName, vmSerialSocketPath, vmVNCSocketPath, user.GetName(), guestUsername, vcpu, memoryMiB); err != nil {
		return vmName, fmt.Errorf("failed to start VM: %w", err)
	}

	return vmName, nil
}

// RemoveVM deletes the named VM, its disks, and any leftover console sockets.
func RemoveVM(name string, settings *config.SettingsType) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return err
	}
	defer func() {
		_, _ = conn.Close()
	}()

	poolName, _ := storagePoolConfig(settings)

	if err := DestroyExistingDomain(conn, name); err != nil {
		return err
	}
	seedIso := name + "_seed.iso"
	if err := RemoveVolumes(conn, poolName, name, seedIso); err != nil {
		return err
	}
	if err := removeSerialSocket(settings, name); err != nil {
		return err
	}
	if err := removeVNCSocket(settings, name); err != nil {
		return err
	}
	return nil
}

func createQCOW2Volume(settings *config.SettingsType, pool *libvirt.StoragePool, volumeName string, capacityBytes uint64) (*libvirt.StorageVol, error) {
	volXML, err := storageVolCreateXMLWithSettings(settings, pool, volumeName, capacityBytes, "qcow2")
	if err != nil {
		return nil, err
	}

	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return nil, fmt.Errorf("create volume: %w", err)
	}
	return vol, nil
}

func uploadFileToVolume(conn *libvirt.Connect, vol *libvirt.StorageVol, sourceImagePath string) error {
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

	if err := vol.Upload(stream, 0, uint64(srcSize), 0); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}
	if err := stream.SendAll(streamReaderChunks(src)); err != nil {
		_ = stream.Abort()
		return fmt.Errorf("stream send: %w", err)
	}
	if err := stream.Finish(); err != nil {
		return fmt.Errorf("stream finish: %w", err)
	}
	return nil
}

func openSourceImage(sourceImagePath string) (*os.File, int64, error) {
	src, err := os.Open(sourceImagePath)
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

func resizeVolumeIfNeeded(vol *libvirt.StorageVol, capacityBytes uint64) error {
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

func normalizeStoragePoolConfig(storagePoolName, storagePoolPath string) (string, string, error) {
	storagePoolName = strings.TrimSpace(storagePoolName)
	if storagePoolName == "" {
		return "", "", fmt.Errorf("storage pool name cannot be empty")
	}

	storagePoolPath = filepath.Clean(strings.TrimSpace(storagePoolPath))
	if storagePoolPath == "." {
		return "", "", fmt.Errorf("storage pool path cannot be empty")
	}

	return storagePoolName, storagePoolPath, nil
}

func lookupOrDefineStoragePool(conn *libvirt.Connect, storagePoolName, storagePoolPath string) (*libvirt.StoragePool, error) {
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err == nil {
		return reconcileStoragePoolTargetPath(conn, pool, storagePoolName, storagePoolPath)
	}

	var libErr libvirt.Error
	if !errors.As(err, &libErr) || libErr.Code != libvirt.ERR_NO_STORAGE_POOL {
		return nil, fmt.Errorf("lookup storage pool %s: %w", storagePoolName, err)
	}

	pool, err = conn.StoragePoolDefineXML(storagePoolDefinitionXML(storagePoolName, storagePoolPath), 0)
	if err != nil {
		return nil, fmt.Errorf("define storage pool %s at %s: %w", storagePoolName, storagePoolPath, err)
	}
	log.Printf("Storage pool %s defined at %s", storagePoolName, storagePoolPath)
	return pool, nil
}

func reconcileStoragePoolTargetPath(conn *libvirt.Connect, pool *libvirt.StoragePool, storagePoolName, storagePoolPath string) (*libvirt.StoragePool, error) {
	targetPath, err := storagePoolTargetPath(pool)
	if err != nil {
		_ = pool.Free()
		return nil, fmt.Errorf("get storage pool %s target path: %w", storagePoolName, err)
	}

	targetPath = filepath.Clean(targetPath)
	if targetPath == storagePoolPath {
		return pool, nil
	}

	active, err := pool.IsActive()
	if err != nil {
		_ = pool.Free()
		return nil, fmt.Errorf("check if storage pool %s is active before reconciling target path: %w", storagePoolName, err)
	}
	if active {
		_ = pool.Free()
		return nil, fmt.Errorf("storage pool %s already exists at %s but configured path is %s", storagePoolName, targetPath, storagePoolPath)
	}

	if err := pool.Undefine(); err != nil {
		_ = pool.Free()
		return nil, fmt.Errorf("undefine storage pool %s at %s: %w", storagePoolName, targetPath, err)
	}
	if err := pool.Free(); err != nil {
		return nil, fmt.Errorf("free storage pool %s after undefine: %w", storagePoolName, err)
	}

	pool, err = conn.StoragePoolDefineXML(storagePoolDefinitionXML(storagePoolName, storagePoolPath), 0)
	if err != nil {
		return nil, fmt.Errorf("redefine storage pool %s from %s to %s: %w", storagePoolName, targetPath, storagePoolPath, err)
	}
	log.Printf("Storage pool %s redefined from %s to %s", storagePoolName, targetPath, storagePoolPath)
	return pool, nil
}

func storagePoolDefinitionXML(storagePoolName, storagePoolPath string) string {
	return fmt.Sprintf(`
<pool type='dir'>
  <name>%s</name>
  <target>
    <path>%s</path>
  </target>
</pool>`, storagePoolName, storagePoolPath)
}

func startStoragePoolIfNeeded(pool *libvirt.StoragePool, storagePoolName string) error {
	active, err := pool.IsActive()
	if err != nil {
		return fmt.Errorf("check if storage pool %s is active: %w", storagePoolName, err)
	}
	if active {
		return nil
	}
	if err := pool.Create(0); err != nil {
		return fmt.Errorf("start storage pool %s: %w", storagePoolName, err)
	}
	log.Printf("Storage pool %s started", storagePoolName)
	return nil
}

func configureStoragePoolAutostart(pool *libvirt.StoragePool, storagePoolName string) {
	autostart, err := pool.GetAutostart()
	if err != nil || autostart {
		return
	}
	if err := pool.SetAutostart(true); err != nil {
		log.Printf("Failed to set autostart for storage pool %s: %v", storagePoolName, err)
	}
}

func logStoragePoolTargetPath(pool *libvirt.StoragePool, storagePoolName, storagePoolPath string) {
	targetPath, err := storagePoolTargetPath(pool)
	if err != nil {
		return
	}
	if filepath.Clean(targetPath) != storagePoolPath {
		log.Printf("Storage pool %s target path is %s (configured %s)", storagePoolName, targetPath, storagePoolPath)
	}
}

func validateBootResources(vcpu int, memoryMiB int) error {
	if vcpu <= 0 || memoryMiB <= 0 {
		return fmt.Errorf("invalid resources (vcpu=%d memoryMiB=%d)", vcpu, memoryMiB)
	}
	return nil
}

func prepareBootSocketPaths(settings *config.SettingsType, vmName string) (string, string, error) {
	if _, err := ensureSerialSocketDir(settings); err != nil {
		return "", "", fmt.Errorf("failed to ensure serial socket directory: %w", err)
	}
	if _, err := ensureVNCSocketDir(settings); err != nil {
		return "", "", fmt.Errorf("failed to ensure VNC socket directory: %w", err)
	}
	return serialSocketPath(settings, vmName), vncSocketPath(settings, vmName), nil
}

func ensureBootStoragePool(conn *libvirt.Connect, poolName, poolPath string) error {
	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		return fmt.Errorf("failed to ensure storage pool %s: %w", poolName, err)
	}
	_ = pool.Free()
	return nil
}

func resetExistingVMArtifacts(conn *libvirt.Connect, settings *config.SettingsType, poolName, vmName, seedIso string) error {
	if err := DestroyExistingDomain(conn, vmName); err != nil {
		return fmt.Errorf("failed to destroy existing domain: %w", err)
	}
	if err := RemoveVolumes(conn, poolName, vmName, seedIso); err != nil {
		return fmt.Errorf("failed to remove existing volumes: %w", err)
	}
	if err := removeSerialSocket(settings, vmName); err != nil {
		return fmt.Errorf("failed to remove existing serial socket: %w", err)
	}
	if err := removeVNCSocket(settings, vmName); err != nil {
		return fmt.Errorf("failed to remove existing VNC socket: %w", err)
	}
	return nil
}

func provisionBootVolumes(conn *libvirt.Connect, settings *config.SettingsType, poolName, vmName, seedIso, hostname, guestUsername, cloudInitPasswordHash string) error {
	baseImage, err := ensureBaseImage(settings)
	if err != nil {
		return fmt.Errorf("failed to ensure base image: %w", err)
	}
	if err := copyAndResizeVolumeWithSettings(conn, settings, poolName, vmName, baseImage, 40*1024*1024*1024); err != nil {
		return fmt.Errorf("failed to copy and resize base image: %w", err)
	}
	if err := createUbuntuSeedISOToPoolWithSettings(settings, conn, poolName, seedIso, guestUsername, cloudInitPasswordHash, hostname); err != nil {
		return fmt.Errorf("failed to create seed ISO: %w", err)
	}
	return nil
}
