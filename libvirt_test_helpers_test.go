package main

import (
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"testing"
)

const legacyDefaultImageDir = "/data/desktop"

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
	targetPath := filepath.Join(config.ImageDir(settings), imageName)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("create image dir %s: %v", filepath.Dir(targetPath), err)
	}
	if _, err := os.Stat(targetPath); err == nil {
		return
	}
	if err := os.Link(sourcePath, targetPath); err == nil {
		return
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
