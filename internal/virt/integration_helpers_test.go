package virt

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"syscall"
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

const (
	legacyDefaultImageDir = "/data/desktop"

	// testBaseImageURL is the real, bootable image integration tests stage into
	// the base-image library. It is test-only and intentionally independent of
	// production configuration (BASE_IMAGE_DIR carries no URL).
	testBaseImageURL  = "https://github.com/define42/ubuntu-resolute-desktop-cloud-image/releases/download/v0.0.9/resolute-desktop-cloudimg-amd64-v0.0.9.img"
	testBaseImageName = "resolute-desktop-cloudimg-amd64-v0.0.9.img"
)

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
	// InitVirt only requires a non-empty image library (it does not clone), so a
	// tiny placeholder avoids a real multi-gigabyte download here.
	seedDummyBaseImage(t, settings)
	return settings
}

// seedDummyBaseImage writes a tiny placeholder image into the library so checks
// that only need a non-empty library (e.g. InitVirt) pass without downloading a
// real image. It returns the seeded file name.
func seedDummyBaseImage(t *testing.T, settings *config.SettingsType) string {
	t.Helper()

	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create base image dir %s: %v", dir, err)
	}
	const name = "test-base.img"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("seed dummy base image: %v", err)
	}
	return name
}

// stageExistingBaseImageFromDefaultRoot makes a real, bootable base image
// available in the settings' BaseImageDir and returns the staged file name to
// pass to BootNewVM. It is idempotent so callers can use it both to satisfy the
// boot-time library check and to learn the selectable image name.
func stageExistingBaseImageFromDefaultRoot(t *testing.T, settings *config.SettingsType) string {
	t.Helper()

	if settings == nil {
		return ""
	}
	sourcePath := ensureAccessibleBaseImageSourcePath(t, testBaseImageURL)
	if sourcePath == "" {
		return ""
	}
	stageBootBaseImage(t, sourcePath, filepath.Join(config.BaseImageDir(settings), testBaseImageName))
	return testBaseImageName
}

func ensureAccessibleBaseImageSourcePath(t *testing.T, baseImageURL string) string {
	t.Helper()

	parsedURL, err := url.Parse(baseImageURL)
	if err != nil {
		return ""
	}
	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return ""
	}

	sourcePath, ok := findExistingBaseImageSourcePath(imageName)
	if ok {
		return sourcePath
	}

	return ensureCachedBaseImageSourcePath(t, baseImageURL, imageName)
}

func ensureCachedBaseImageSourcePath(t *testing.T, baseImageURL, imageName string) string {
	t.Helper()

	cacheDir := filepath.Join(os.TempDir(), "rdptlsgateway-test-base-image-cache")
	cachedPath := filepath.Join(cacheDir, imageName)

	withTestBaseImageCacheLock(t, cacheDir, func() {
		ok, err := nonEmptyFileExists(cachedPath)
		if err != nil {
			t.Fatalf("stat cached base image %s: %v", cachedPath, err)
		}
		if ok {
			return
		}

		downloadCachedBaseImage(t, baseImageURL, cachedPath)
	})

	return cachedPath
}

func findExistingBaseImageSourcePath(imageName string) (string, bool) {
	candidates := []string{
		filepath.Join(config.ImageDir(nil), imageName),
		filepath.Join(legacyDefaultImageDir, imageName),
		filepath.Join(os.TempDir(), "rdptlsgateway-test-base-image-cache", imageName),
	}
	for _, candidate := range candidates {
		if canUseBaseImageSourcePath(candidate) {
			return candidate, true
		}
	}
	return "", false
}

func canUseBaseImageSourcePath(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func withTestBaseImageCacheLock(t *testing.T, cacheDir string, fn func()) {
	t.Helper()

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cached base image dir %s: %v", cacheDir, err)
	}

	lockPath := filepath.Join(cacheDir, ".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("open cached base image lock %s: %v", lockPath, err)
	}
	defer func() { _ = lockFile.Close() }()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("lock cached base image dir %s: %v", cacheDir, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	fn()
}

func downloadCachedBaseImage(t *testing.T, baseImageURL, cachedPath string) {
	t.Helper()

	resp, err := http.Get(baseImageURL)
	if err != nil {
		t.Fatalf("download cached base image %s: %v", baseImageURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("download cached base image %s: unexpected status %s", baseImageURL, resp.Status)
	}

	writeCachedBaseImage(t, cachedPath, resp.Body)
}

func writeCachedBaseImage(t *testing.T, cachedPath string, body io.Reader) {
	t.Helper()

	tmpPath := cachedPath + ".part"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("create cached base image %s: %v", tmpPath, err)
	}
	if _, err := io.Copy(out, body); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		t.Fatalf("copy cached base image %s: %v", tmpPath, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		t.Fatalf("close cached base image %s: %v", tmpPath, err)
	}
	if err := os.Rename(tmpPath, cachedPath); err != nil {
		_ = os.Remove(tmpPath)
		t.Fatalf("move cached base image into place %s: %v", cachedPath, err)
	}
}

// nonEmptyFileExists reports whether path is an existing, non-empty regular
// file. It is a test helper (the production downloader that once needed it was
// removed with the move to an operator-managed image library).
func nonEmptyFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		return info.Size() > 0, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func waitForWorkerStop(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop in time")
	}
}
