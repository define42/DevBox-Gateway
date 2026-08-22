package virt

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/define42/devbox-gateway/internal/config"

	"libvirt.org/go/libvirt"
)

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
	// #nosec G301 -- libvirt's qemu user must traverse the pool path to reach VM disks, so it cannot be group/other-restricted.
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

func ensureBootStoragePool(conn *libvirt.Connect, poolName, poolPath string) error {
	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		return fmt.Errorf("failed to ensure storage pool %s: %w", poolName, err)
	}
	_ = pool.Free()
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
