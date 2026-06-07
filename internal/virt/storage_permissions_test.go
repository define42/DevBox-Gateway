package virt

import (
	"context"
	"encoding/xml"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strings"
	"testing"
	"time"
)

func TestStoragePermissionHelpers(t *testing.T) {
	xml, err := storageVolPermissionsXML()
	if err != nil {
		t.Fatalf("storageVolPermissionsXML: %v", err)
	}
	if !strings.Contains(xml, "<mode>0666</mode>") {
		t.Fatalf("expected mode in permissions xml, got %q", xml)
	}
	if strings.Contains(xml, "<owner>") || strings.Contains(xml, "<group>") {
		t.Fatalf("did not expect owner/group in permissions xml, got %q", xml)
	}
}

func TestStorageVolPermissionsDefaultMode(t *testing.T) {
	perms, err := storageVolPermissions()
	if err != nil {
		t.Fatalf("storageVolPermissions default: %v", err)
	}
	if perms == nil {
		t.Fatal("expected default permissions to be present")
	}
	if perms.Owner != nil || perms.Group != nil {
		t.Fatalf("expected default owner/group to be unset, got %+v", perms)
	}
	if perms.Mode == nil || *perms.Mode != "0666" {
		t.Fatalf("expected default mode %q, got %+v", "0666", perms.Mode)
	}
}

func TestStoragePoolConfigAndPathHelpers(t *testing.T) {
	poolName, poolPath := storagePoolConfig(nil)
	if poolName != config.DefaultVirtStoragePoolName {
		t.Fatalf("expected default pool name %q, got %q", config.DefaultVirtStoragePoolName, poolName)
	}
	if poolPath != filepath.Clean(config.VirtStoragePoolPath(nil)) {
		t.Fatalf("expected default pool path %q, got %q", filepath.Clean(config.VirtStoragePoolPath(nil)), poolPath)
	}

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, "custom"); err != nil {
		t.Fatalf("overwrite pool name: %v", err)
	}
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, "/tmp/gateway-root"); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}

	poolName, poolPath = storagePoolConfig(settings)
	if poolName != "custom" {
		t.Fatalf("expected custom pool name, got %q", poolName)
	}
	if poolPath != filepath.Clean("/tmp/gateway-root/image") {
		t.Fatalf("expected derived image dir path, got %q", poolPath)
	}
}

func TestEnsureStoragePoolAndPathXML(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolPath := t.TempDir()
	poolName := uniquePoolName("permissions-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}
	defer func() {
		_ = pool.Free()
	}()

	targetPath, err := storagePoolTargetPath(pool)
	if err != nil {
		t.Fatalf("storagePoolTargetPath: %v", err)
	}
	if filepath.Clean(targetPath) != filepath.Clean(poolPath) {
		t.Fatalf("expected pool target path %q, got %q", filepath.Clean(poolPath), targetPath)
	}

	pathXML, err := storageVolPathXML(pool, "disk.qcow2")
	if err != nil {
		t.Fatalf("storageVolPathXML: %v", err)
	}
	if !strings.Contains(pathXML, filepath.Join(filepath.Clean(poolPath), "disk.qcow2")) {
		t.Fatalf("expected path xml to contain volume path, got %q", pathXML)
	}
}

func TestEnsureStoragePoolRedefinesInactivePoolWithStalePath(t *testing.T) {
	conn := newTestLibvirtConn(t)
	stalePoolPath := t.TempDir()
	poolPath := t.TempDir()
	poolName := uniquePoolName("stale-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := conn.StoragePoolDefineXML(storagePoolDefinitionXML(poolName, stalePoolPath), 0)
	if err != nil {
		t.Fatalf("define stale storage pool: %v", err)
	}
	if err := pool.Free(); err != nil {
		t.Fatalf("free stale storage pool: %v", err)
	}

	pool, err = ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool with stale path: %v", err)
	}
	defer func() {
		_ = pool.Free()
	}()

	targetPath, err := storagePoolTargetPath(pool)
	if err != nil {
		t.Fatalf("storagePoolTargetPath: %v", err)
	}
	if filepath.Clean(targetPath) != filepath.Clean(poolPath) {
		t.Fatalf("expected redefined pool target path %q, got %q", filepath.Clean(poolPath), targetPath)
	}

	active, err := pool.IsActive()
	if err != nil {
		t.Fatalf("check pool active: %v", err)
	}
	if !active {
		t.Fatal("expected redefined storage pool to be active")
	}
}

func TestEnsureStoragePoolRejectsActivePoolWithStalePath(t *testing.T) {
	conn := newTestLibvirtConn(t)
	stalePoolPath := t.TempDir()
	poolPath := t.TempDir()
	poolName := uniquePoolName("active-stale-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := conn.StoragePoolDefineXML(storagePoolDefinitionXML(poolName, stalePoolPath), 0)
	if err != nil {
		t.Fatalf("define stale storage pool: %v", err)
	}
	if err := pool.Create(0); err != nil {
		_ = pool.Free()
		t.Fatalf("start stale storage pool: %v", err)
	}
	if err := pool.Free(); err != nil {
		t.Fatalf("free stale storage pool: %v", err)
	}

	_, err = ensureStoragePool(conn, poolName, poolPath)
	if err == nil {
		t.Fatal("expected active stale storage pool to be rejected")
	}
	if !strings.Contains(err.Error(), "already exists at") {
		t.Fatalf("expected active stale path error, got %v", err)
	}
}

func TestStorageVolCreateXML(t *testing.T) {
	conn := newTestLibvirtConn(t)
	poolPath := t.TempDir()
	poolName := uniquePoolName("volume-xml-pool")
	t.Cleanup(func() { cleanupStoragePool(t, poolName) })

	pool, err := ensureStoragePool(conn, poolName, poolPath)
	if err != nil {
		t.Fatalf("ensureStoragePool: %v", err)
	}
	defer func() {
		_ = pool.Free()
	}()

	volXML, err := storageVolCreateXML(pool, "disk.qcow2", 12345, "qcow2")
	if err != nil {
		t.Fatalf("storageVolCreateXML: %v", err)
	}

	var parsed storageVolumeXML
	if err := xml.Unmarshal([]byte(volXML), &parsed); err != nil {
		t.Fatalf("unmarshal generated xml: %v", err)
	}

	assertStorageVolXMLCore(t, parsed, poolPath)
	assertStorageVolXMLPermissions(t, parsed.Target.Permissions)
}

func assertStorageVolXMLCore(t *testing.T, parsed storageVolumeXML, poolPath string) {
	t.Helper()

	if parsed.Name != "disk.qcow2" {
		t.Fatalf("expected volume name %q, got %q", "disk.qcow2", parsed.Name)
	}
	if parsed.Capacity.Unit != "bytes" || parsed.Capacity.Value != 12345 {
		t.Fatalf("unexpected capacity %+v", parsed.Capacity)
	}
	if parsed.Target.Format.Type != "qcow2" {
		t.Fatalf("expected format %q, got %q", "qcow2", parsed.Target.Format.Type)
	}

	wantPath := filepath.Join(filepath.Clean(poolPath), "disk.qcow2")
	if filepath.Clean(parsed.Target.Path) != wantPath {
		t.Fatalf("expected path %q, got %q", wantPath, parsed.Target.Path)
	}
}

func assertStorageVolXMLPermissions(t *testing.T, permissions *storageVolumePermissionsXML) {
	t.Helper()

	if permissions == nil {
		t.Fatal("expected permissions to be present")
	}
	if permissions.Owner != nil {
		t.Fatalf("expected owner to be unset, got %+v", permissions.Owner)
	}
	if permissions.Group != nil {
		t.Fatalf("expected group to be unset, got %+v", permissions.Group)
	}
	if permissions.Mode == nil || *permissions.Mode != "0666" {
		t.Fatalf("expected mode %q, got %+v", "0666", permissions.Mode)
	}
}

func TestInitVirtRequiresBaseImage(t *testing.T) {
	t.Run("with image", func(t *testing.T) {
		rootDir := t.TempDir()
		settings := newInitVirtSettings(t, rootDir)
		poolName := settings.Get(config.VIRT_STORAGE_POOL_NAME)
		t.Cleanup(func() { cleanupStoragePool(t, poolName) })

		if err := InitVirt(settings); err != nil {
			t.Fatalf("InitVirt with a populated image library: %v", err)
		}
	})

	t.Run("empty library", func(t *testing.T) {
		settings := config.NewSettingType(false)
		if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, t.TempDir()); err != nil {
			t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
		}
		if err := InitVirt(settings); err == nil {
			t.Fatal("expected InitVirt to fail with an empty base image library")
		}
	})
}

func TestSingletonWorkerStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	worker := &SingletonWorker{
		ticker: time.NewTicker(time.Hour),
		ctx:    ctx,
		cancel: cancel,
	}
	defer worker.ticker.Stop()

	done := make(chan struct{})
	go func() {
		worker.run()
		close(done)
	}()

	worker.Stop()
	waitForWorkerStop(t, done)
}
