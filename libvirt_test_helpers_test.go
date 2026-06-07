package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"syscall"
	"testing"
)

const (
	legacyDefaultImageDir = "/data/desktop"

	// testBaseImageURL/testBaseImageName describe the real, bootable image
	// integration tests stage into the base-image library. They are test-only
	// (production no longer downloads images).
	testBaseImageURL  = "https://github.com/define42/ubuntu-resolute-desktop-cloud-image/releases/download/v0.0.9/resolute-desktop-cloudimg-amd64-v0.0.9.img"
	testBaseImageName = "resolute-desktop-cloudimg-amd64-v0.0.9.img"
)

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

// stageExistingBaseImageFromDefaultRoot makes a real, bootable base image
// available in the settings' BaseImageDir and returns the staged file name (for
// BootNewVM), downloading to a shared cache when not already present locally.
func stageExistingBaseImageFromDefaultRoot(t *testing.T, settings *config.SettingsType) string {
	t.Helper()

	if settings == nil {
		return ""
	}
	sourcePath, ok := findExistingBaseImageSourcePath(testBaseImageName)
	if !ok {
		sourcePath = ensureCachedBaseImageSourcePath(t, testBaseImageName)
	}
	targetPath := filepath.Join(config.BaseImageDir(settings), testBaseImageName)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("create image dir %s: %v", filepath.Dir(targetPath), err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		return testBaseImageName
	}
	if err := os.Link(sourcePath, targetPath); err == nil {
		return testBaseImageName
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open source base image %s: %v", sourcePath, err)
	}
	defer func() { _ = sourceFile.Close() }()

	targetFile, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("create staged base image %s: %v", targetPath, err)
	}
	defer func() { _ = targetFile.Close() }()

	if _, err := io.Copy(targetFile, sourceFile); err != nil {
		t.Fatalf("copy base image into test root: %v", err)
	}
	return testBaseImageName
}

func ensureCachedBaseImageSourcePath(t *testing.T, imageName string) string {
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

		downloadCachedBaseImage(t, testBaseImageURL, cachedPath)
	})

	return cachedPath
}

func findExistingBaseImageSourcePath(imageName string) (string, bool) {
	candidates := []string{
		filepath.Join(config.ImageDir(nil), imageName),
		filepath.Join(legacyDefaultImageDir, imageName),
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
