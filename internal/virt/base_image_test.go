package virt

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"sync/atomic"
	"testing"
)

func TestEnsureBaseImageDownloadsAndReusesExistingFile(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		_, _ = w.Write([]byte("fake-image-data"))
	}))
	defer server.Close()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, server.URL+"/resolute.qcow2"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}

	imagePath, err := ensureBaseImage(settings)
	if err != nil {
		t.Fatalf("ensure base image: %v", err)
	}

	data, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatalf("read base image: %v", err)
	}
	if got := string(data); got != "fake-image-data" {
		t.Fatalf("unexpected base image contents %q", got)
	}

	server.Close()

	reusedPath, err := ensureBaseImage(settings)
	if err != nil {
		t.Fatalf("ensure existing base image: %v", err)
	}
	if reusedPath != imagePath {
		t.Fatalf("expected reused path %q, got %q", imagePath, reusedPath)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected one download request, got %d", got)
	}
}

func TestBaseImageURLAndPathValidationInvalidURL(t *testing.T) {
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "://bad-url"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}
	if _, _, err := baseImageURLAndPath(settings); err == nil {
		t.Fatal("expected invalid base image URL error")
	}
}

func TestBaseImageURLAndPathValidationMissingImageName(t *testing.T) {
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "https://example.test/"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}
	if _, _, err := baseImageURLAndPath(settings); err == nil {
		t.Fatal("expected missing base image filename error")
	}
}

func TestBaseImageURLAndPathUsesDerivedImageDir(t *testing.T) {
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "https://example.test/base.qcow2"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, "/srv/vm-root"); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	_, imagePath, err := baseImageURLAndPath(settings)
	if err != nil {
		t.Fatalf("baseImageURLAndPath: %v", err)
	}
	if want := filepath.Join("/srv/vm-root", "image", "base.qcow2"); imagePath != want {
		t.Fatalf("expected image path %q, got %q", want, imagePath)
	}
}

func TestBaseImageURLAndPathValidationValidPath(t *testing.T) {
	settings := config.NewSettingType(false)
	rootDir := filepath.Join(t.TempDir(), "gateway-root")
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, rootDir); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_URL, "https://example.test/base.qcow2"); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_URL: %v", err)
	}
	_, imagePath, err := baseImageURLAndPath(settings)
	if err != nil {
		t.Fatalf("baseImageURLAndPath: %v", err)
	}
	if want := filepath.Join(rootDir, "image", "base.qcow2"); imagePath != want {
		t.Fatalf("expected image path %q, got %q", want, imagePath)
	}
}
