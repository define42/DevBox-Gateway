package virt

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/types"
	"strings"

	"libvirt.org/go/libvirt"
)

// startVM starts a libvirt VM by name if it is not already running

func StartVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath string, vcpu int, memoryMiB int) error {
	return startVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, "", vcpu, memoryMiB)
}

func StartVMWithOwner(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, owner string, vcpu int, memoryMiB int) error {
	return startVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, owner, vcpu, memoryMiB)
}

func startVM(name, seedIso, storagePoolName, serialSocketPath, vncSocketPath, owner string, vcpu int, memoryMiB int) error {
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
		fmt.Println("whaat", err)
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

	if err := dom.Create(); err != nil {
		return err
	}

	//fmt.Printf("VM %s started (ID %d)\n", name, dom.GetID())
	return nil
}

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

func CopyAndResizeVolume(
	conn *libvirt.Connect,
	storagePoolName string,
	volumeName string,
	sourceImagePath string,
	capacityBytes uint64,
) error {

	// Lookup storage pool
	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		return fmt.Errorf("lookup pool %s: %w", storagePoolName, err)
	}
	defer func() {
		if err := pool.Free(); err != nil {
			fmt.Println("pool free error:", err)
		}
	}()

	// Create volume XML
	volXML, err := storageVolCreateXML(pool, volumeName, capacityBytes, "qcow2")
	if err != nil {
		return err
	}

	// Create volume
	vol, err := pool.StorageVolCreateXML(volXML, 0)
	if err != nil {
		return fmt.Errorf("create volume: %w", err)
	}
	defer func() {
		_ = vol.Free()
	}()

	// Open source image
	src, err := os.Open(sourceImagePath)
	if err != nil {
		return fmt.Errorf("open source image: %w", err)
	}
	defer func() { _ = src.Close() }()

	srcInfo, err := src.Stat()
	if err != nil {
		return fmt.Errorf("stat source image: %w", err)
	}

	// Create libvirt stream
	stream, err := conn.NewStream(0)
	if err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	defer func() {
		_ = stream.Free()
	}()

	// Start upload
	if err := vol.Upload(stream, 0, uint64(srcInfo.Size()), 0); err != nil {
		return fmt.Errorf("start upload: %w", err)
	}

	if err := stream.SendAll(func(_ *libvirt.Stream, nbytes int) ([]byte, error) {
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
	}); err != nil {
		_ = stream.Abort()
		return fmt.Errorf("stream send: %w", err)
	}

	if err := stream.Finish(); err != nil {
		return fmt.Errorf("stream finish: %w", err)
	}

	if capacityBytes > 0 {
		volInfo, err := vol.GetInfo()
		if err != nil {
			return fmt.Errorf("get volume info: %w", err)
		}
		if volInfo.Capacity < capacityBytes {
			if err := vol.Resize(capacityBytes, 0); err != nil {
				return fmt.Errorf("resize volume: %w", err)
			}
		}
	}

	return nil
}

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

func storagePoolConfig(settings *config.SettingsType) (poolName string, poolPath string) {
	poolName = config.DefaultVirtStoragePoolName
	poolPath = config.DefaultVirtStoragePoolPath
	if settings == nil {
		return poolName, filepath.Clean(poolPath)
	}

	if configuredPoolName := strings.TrimSpace(settings.Get(config.VIRT_STORAGE_POOL_NAME)); configuredPoolName != "" {
		poolName = configuredPoolName
	}

	if configuredPoolPath := strings.TrimSpace(settings.Get(config.VIRT_STORAGE_POOL_PATH)); configuredPoolPath != "" {
		poolPath = configuredPoolPath
	} else if imageDir := strings.TrimSpace(settings.Get(config.VDI_IMAGE_DIR)); imageDir != "" {
		poolPath = imageDir
	}

	return poolName, filepath.Clean(poolPath)
}

func ensureStoragePool(conn *libvirt.Connect, storagePoolName, storagePoolPath string) (*libvirt.StoragePool, error) {
	storagePoolName = strings.TrimSpace(storagePoolName)
	if storagePoolName == "" {
		return nil, fmt.Errorf("storage pool name cannot be empty")
	}

	storagePoolPath = filepath.Clean(strings.TrimSpace(storagePoolPath))
	if storagePoolPath == "." {
		return nil, fmt.Errorf("storage pool path cannot be empty")
	}

	if err := os.MkdirAll(storagePoolPath, 0o755); err != nil {
		return nil, fmt.Errorf("create storage pool path %s: %w", storagePoolPath, err)
	}

	pool, err := conn.LookupStoragePoolByName(storagePoolName)
	if err != nil {
		var libErr libvirt.Error
		if !errors.As(err, &libErr) || libErr.Code != libvirt.ERR_NO_STORAGE_POOL {
			return nil, fmt.Errorf("lookup storage pool %s: %w", storagePoolName, err)
		}

		poolXML := fmt.Sprintf(`
<pool type='dir'>
  <name>%s</name>
  <target>
    <path>%s</path>
  </target>
</pool>`, storagePoolName, storagePoolPath)

		pool, err = conn.StoragePoolDefineXML(poolXML, 0)
		if err != nil {
			return nil, fmt.Errorf("define storage pool %s at %s: %w", storagePoolName, storagePoolPath, err)
		}
		log.Printf("Storage pool %s defined at %s", storagePoolName, storagePoolPath)
	}

	active, err := pool.IsActive()
	if err != nil {
		_ = pool.Free()
		return nil, fmt.Errorf("check if storage pool %s is active: %w", storagePoolName, err)
	}
	if !active {
		if err := pool.Create(0); err != nil {
			_ = pool.Free()
			return nil, fmt.Errorf("start storage pool %s: %w", storagePoolName, err)
		}
		log.Printf("Storage pool %s started", storagePoolName)
	}

	autostart, err := pool.GetAutostart()
	if err == nil && !autostart {
		if err := pool.SetAutostart(true); err != nil {
			log.Printf("Failed to set autostart for storage pool %s: %v", storagePoolName, err)
		}
	}

	if targetPath, err := storagePoolTargetPath(pool); err == nil {
		if filepath.Clean(targetPath) != storagePoolPath {
			log.Printf("Storage pool %s target path is %s (configured %s)", storagePoolName, targetPath, storagePoolPath)
		}
	}

	return pool, nil
}

func InitVirt(settings *config.SettingsType) error {
	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

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

func BootNewVM(name string, user *types.User, settings *config.SettingsType, vcpu int, memoryMiB int) (vmName string, err error) {

	vmName = user.GetName() + "-" + name
	if vcpu <= 0 || memoryMiB <= 0 {
		return vmName, fmt.Errorf("invalid resources (vcpu=%d memoryMiB=%d)", vcpu, memoryMiB)
	}

	seedIso := vmName + "_seed.iso"
	poolName, poolPath := storagePoolConfig(settings)
	if _, err := ensureSerialSocketDir(settings); err != nil {
		return vmName, fmt.Errorf("failed to ensure serial socket directory: %w", err)
	}
	if _, err := ensureVNCSocketDir(settings); err != nil {
		return vmName, fmt.Errorf("failed to ensure VNC socket directory: %w", err)
	}
	vmSerialSocketPath := serialSocketPath(settings, vmName)
	vmVNCSocketPath := vncSocketPath(settings, vmName)

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		return vmName, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		return vmName, fmt.Errorf("failed to ensure storage pool %s: %w", poolName, err)
	}
	_ = pool.Free()

	if err := DestroyExistingDomain(conn, vmName); err != nil {
		return vmName, fmt.Errorf("failed to destroy existing domain: %w", err)
	}
	if err := RemoveVolumes(conn, poolName, vmName, seedIso); err != nil {
		return vmName, fmt.Errorf("failed to remove existing volumes: %w", err)
	}
	if err := removeSerialSocket(settings, vmName); err != nil {
		return vmName, fmt.Errorf("failed to remove existing serial socket: %w", err)
	}
	if err := removeVNCSocket(settings, vmName); err != nil {
		return vmName, fmt.Errorf("failed to remove existing VNC socket: %w", err)
	}

	baseImage, err := ensureBaseImage(settings)
	if err != nil {
		return vmName, fmt.Errorf("failed to ensure base image: %w", err)
	}

	if err := CopyAndResizeVolume(conn, poolName, vmName, baseImage, 40*1024*1024*1024); err != nil {
		return vmName, fmt.Errorf("failed to copy and resize base image: %w", err)
	}

	if err := CreateUbuntuSeedISOToPool(conn, poolName, seedIso, user.GetName(), user.GetCloudInitPasswordHash(), vmName); err != nil {
		return vmName, fmt.Errorf("failed to create seed ISO: %w", err)
	}

	if err := StartVMWithOwner(vmName, seedIso, poolName, vmSerialSocketPath, vmVNCSocketPath, user.GetName(), vcpu, memoryMiB); err != nil {
		return vmName, fmt.Errorf("failed to start VM: %w", err)
	}

	return vmName, nil
}

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
