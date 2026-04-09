package virt

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const legacyDefaultImageDir = "/data/desktop"

func newTestLibvirtConn(t *testing.T) *libvirt.Connect {
	t.Helper()

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Close()
	})
	return conn
}

func cleanupStoragePool(t *testing.T, name string) {
	t.Helper()

	conn, err := libvirt.NewConnect(LibvirtURI())
	if err != nil {
		t.Fatalf("connect libvirt for cleanup: %v", err)
	}
	defer func() {
		_, _ = conn.Close()
	}()

	pool, err := conn.LookupStoragePoolByName(name)
	if err != nil {
		return
	}
	defer func() {
		_ = pool.Free()
	}()

	active, err := pool.IsActive()
	if err == nil && active {
		_ = pool.Destroy()
	}
	_ = pool.Undefine()
}

func uniquePoolName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func newLibvirtAccessibleTempDir(t *testing.T, prefix string) string {
	t.Helper()

	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		t.Fatalf("mkdir temp dir %q: %v", prefix, err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func usePermissiveLibvirtVolumeMode(t *testing.T) {
	t.Helper()
	t.Setenv(volumeModeEnv, "0666")
}

func newInitVirtSettings(t *testing.T, rootDir string) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.VIRT_STORAGE_POOL_NAME, uniquePoolName("virt-test-pool")); err != nil {
		t.Fatalf("overwrite VIRT_STORAGE_POOL_NAME: %v", err)
	}
	stageExistingBaseImageFromDefaultRoot(t, settings)
	return settings
}

func stageExistingBaseImageFromDefaultRoot(t *testing.T, settings *config.SettingsType) {
	t.Helper()

	if settings == nil {
		return
	}
	parsedURL, err := url.Parse(settings.Get(config.BASE_IMAGE_URL))
	if err != nil {
		return
	}
	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return
	}

	sourcePath, ok := findExistingBaseImageSourcePath(imageName)
	if !ok {
		return
	}
	stageBootBaseImage(t, sourcePath, filepath.Join(config.ImageDir(settings), imageName))
}

func findExistingBaseImageSourcePath(imageName string) (string, bool) {
	candidates := []string{
		filepath.Join(config.ImageDir(nil), imageName),
		filepath.Join(legacyDefaultImageDir, imageName),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
	}
	return "", false
}

func newImageServer(t *testing.T, payload []byte, status int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		if _, err := w.Write(payload); err != nil {
			t.Errorf("write image payload: %v", err)
		}
	}))
}

func waitForWorkerStop(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop in time")
	}
}
