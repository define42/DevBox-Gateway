package virt

import (
	"devboxgateway/internal/config"
	"os"
	"path/filepath"
	"testing"
)

// viocovBrokenBaseImageSettings points BASE_IMAGE_DIR at a regular file so
// reading the "directory" fails with an error other than not-exist.
func viocovBrokenBaseImageSettings(t *testing.T) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write placeholder file: %v", err)
	}
	if err := settings.OverwriteForTestString(config.BASE_IMAGE_DIR, filePath); err != nil {
		t.Fatalf("overwrite BASE_IMAGE_DIR: %v", err)
	}
	return settings
}

func TestViocovBaseImageDirReadErrors(t *testing.T) {
	settings := viocovBrokenBaseImageSettings(t)

	if _, err := ListBaseImages(settings); err == nil {
		t.Fatal("expected ListBaseImages to surface the read error")
	}
	if _, err := resolveBaseImagePath(settings, "base.img"); err == nil {
		t.Fatal("expected resolveBaseImagePath to surface the read error")
	}
	if err := EnsureBaseImagesAvailable(settings); err == nil {
		t.Fatal("expected EnsureBaseImagesAvailable to surface the read error")
	}
}
