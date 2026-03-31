package virt

import (
	"context"
	"encoding/xml"
	"net/http"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"strings"
	"testing"
	"time"
)

func TestStoragePermissionHelpers(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "1000")
	t.Setenv(volumeGroupEnv, "1001")
	t.Setenv(volumeModeEnv, "0666")

	xml, err := storageVolPermissionsXML()
	if err != nil {
		t.Fatalf("storageVolPermissionsXML: %v", err)
	}
	if !strings.Contains(xml, "<owner>1000</owner>") {
		t.Fatalf("expected owner in permissions xml, got %q", xml)
	}
	if !strings.Contains(xml, "<group>1001</group>") {
		t.Fatalf("expected group in permissions xml, got %q", xml)
	}
	if !strings.Contains(xml, "<mode>0666</mode>") {
		t.Fatalf("expected mode in permissions xml, got %q", xml)
	}
}

func TestEnvModeXMLAndEnvUintXMLErrors(t *testing.T) {
	t.Setenv(volumeModeEnv, "invalid")
	if _, err := envModeXML(); err == nil {
		t.Fatal("expected invalid mode error")
	}

	t.Setenv(volumeOwnerEnv, "invalid")
	if _, err := envUintXML(volumeOwnerEnv, "owner", 10); err == nil {
		t.Fatal("expected invalid owner error")
	}
}

func TestStoragePoolConfigAndPathHelpers(t *testing.T) {
	poolName, poolPath := storagePoolConfig(nil)
	if poolName != config.DefaultVirtStoragePoolName {
		t.Fatalf("expected default pool name %q, got %q", config.DefaultVirtStoragePoolName, poolName)
	}
	if poolPath != filepath.Clean(config.DefaultVirtStoragePoolPath) {
		t.Fatalf("expected default pool path %q, got %q", filepath.Clean(config.DefaultVirtStoragePoolPath), poolPath)
	}

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, "custom"); err != nil {
		t.Fatalf("overwrite pool name: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_PATH, ""); err != nil {
		t.Fatalf("overwrite pool path: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VDI_IMAGE_DIR, "/tmp/image-dir"); err != nil {
		t.Fatalf("overwrite image dir: %v", err)
	}

	poolName, poolPath = storagePoolConfig(settings)
	if poolName != "custom" {
		t.Fatalf("expected custom pool name, got %q", poolName)
	}
	if poolPath != filepath.Clean("/tmp/image-dir") {
		t.Fatalf("expected VDI image dir fallback, got %q", poolPath)
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

	t.Setenv(volumeOwnerEnv, "1000")
	t.Setenv(volumeGroupEnv, "1001")
	t.Setenv(volumeModeEnv, "0660")

	volXML, err := storageVolCreateXML(pool, "disk.qcow2", 12345, "qcow2")
	if err != nil {
		t.Fatalf("storageVolCreateXML: %v", err)
	}

	var parsed storageVolumeXML
	if err := xml.Unmarshal([]byte(volXML), &parsed); err != nil {
		t.Fatalf("unmarshal generated xml: %v", err)
	}

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
	if parsed.Target.Permissions == nil {
		t.Fatal("expected permissions to be present")
	}
	if parsed.Target.Permissions.Owner == nil || *parsed.Target.Permissions.Owner != 1000 {
		t.Fatalf("expected owner %d, got %+v", 1000, parsed.Target.Permissions.Owner)
	}
	if parsed.Target.Permissions.Group == nil || *parsed.Target.Permissions.Group != 1001 {
		t.Fatalf("expected group %d, got %+v", 1001, parsed.Target.Permissions.Group)
	}
	if parsed.Target.Permissions.Mode == nil || *parsed.Target.Permissions.Mode != "0660" {
		t.Fatalf("expected mode %q, got %+v", "0660", parsed.Target.Permissions.Mode)
	}
}

func TestInitVirtWithExistingAndDownloadedBaseImage(t *testing.T) {
	t.Run("existing image", func(t *testing.T) {
		poolPath := t.TempDir()
		settings := newInitVirtSettings(t, poolPath)
		poolName := settings.Get(config.VIRT_STORAGE_POOL_NAME)
		t.Cleanup(func() { cleanupStoragePool(t, poolName) })

		existingPath := filepath.Join(poolPath, "existing.img")
		if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "https://example.test/existing.img"); err != nil {
			t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
		}
		if err := os.WriteFile(existingPath, []byte("present"), 0o644); err != nil {
			t.Fatalf("write existing base image: %v", err)
		}

		if err := InitVirt(settings); err != nil {
			t.Fatalf("InitVirt with existing image: %v", err)
		}
	})

	t.Run("download image", func(t *testing.T) {
		poolPath := t.TempDir()
		settings := newInitVirtSettings(t, poolPath)
		poolName := settings.Get(config.VIRT_STORAGE_POOL_NAME)
		t.Cleanup(func() { cleanupStoragePool(t, poolName) })

		server := newImageServer(t, []byte("downloaded-image"), http.StatusOK)
		defer server.Close()
		if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, server.URL+"/download.img"); err != nil {
			t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
		}

		if err := InitVirt(settings); err != nil {
			t.Fatalf("InitVirt with download: %v", err)
		}
		if _, err := os.Stat(filepath.Join(poolPath, "download.img")); err != nil {
			t.Fatalf("expected downloaded base image to exist: %v", err)
		}
	})
}

func TestDownloadWithProgress(t *testing.T) {
	server := newImageServer(t, []byte("tiny-image"), http.StatusOK)
	defer server.Close()

	target := filepath.Join(t.TempDir(), "image.bin")
	if err := downloadWithProgress(server.URL+"/image.bin", target); err != nil {
		t.Fatalf("downloadWithProgress: %v", err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(data) != "tiny-image" {
		t.Fatalf("expected downloaded payload %q, got %q", "tiny-image", string(data))
	}
}

func TestDownloadWithProgressRejectsNonOKStatus(t *testing.T) {
	server := newImageServer(t, []byte("not-found"), http.StatusNotFound)
	defer server.Close()

	target := filepath.Join(t.TempDir(), "missing.bin")
	if err := downloadWithProgress(server.URL+"/missing.bin", target); err == nil {
		t.Fatal("expected non-OK download error")
	}
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
