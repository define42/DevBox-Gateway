package virt

import (
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"testing"
)

// newBaseImageSettings returns settings whose BaseImageDir is seeded with the
// given files (name -> contents). A nil map leaves the directory absent.
func newBaseImageSettings(t *testing.T, files map[string][]byte) *config.SettingsType {
	t.Helper()

	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestString(config.DATA_ROOT_DIR, t.TempDir()); err != nil {
		t.Fatalf("overwrite DATA_ROOT_DIR: %v", err)
	}
	if len(files) == 0 {
		return settings
	}

	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create base image dir: %v", err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("write base image %s: %v", name, err)
		}
	}
	return settings
}

func TestListBaseImagesFiltersAndSorts(t *testing.T) {
	settings := newBaseImageSettings(t, map[string][]byte{
		"b.img":     []byte("x"),
		"a.qcow2":   []byte("x"),
		"c.RAW":     []byte("x"),
		"notes.txt": []byte("x"),
		"empty.img": {},
	})
	// A directory with a matching extension must be ignored.
	if err := os.MkdirAll(filepath.Join(config.BaseImageDir(settings), "sub.img"), 0o755); err != nil {
		t.Fatalf("create sub dir: %v", err)
	}

	got, err := ListBaseImages(settings)
	if err != nil {
		t.Fatalf("ListBaseImages: %v", err)
	}

	want := []string{"a.qcow2", "b.img", "c.RAW"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestListBaseImagesMissingDir(t *testing.T) {
	settings := newBaseImageSettings(t, nil)

	got, err := ListBaseImages(settings)
	if err != nil {
		t.Fatalf("ListBaseImages on missing dir: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no images, got %v", got)
	}
}

func TestEnsureBaseImagesAvailable(t *testing.T) {
	if err := EnsureBaseImagesAvailable(newBaseImageSettings(t, nil)); err == nil {
		t.Fatal("expected error when the base image library is empty")
	}

	populated := newBaseImageSettings(t, map[string][]byte{"base.img": []byte("data")})
	if err := EnsureBaseImagesAvailable(populated); err != nil {
		t.Fatalf("expected success with one image, got %v", err)
	}
}

func TestResolveBaseImagePath(t *testing.T) {
	settings := newBaseImageSettings(t, map[string][]byte{"base.img": []byte("data")})

	path, err := resolveBaseImagePath(settings, "base.img")
	if err != nil {
		t.Fatalf("resolveBaseImagePath: %v", err)
	}
	if want := filepath.Join(config.BaseImageDir(settings), "base.img"); path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}

	for _, bad := range []string{"", "   ", "missing.img", "../escape.img", "sub/base.img", `sub\base.img`, ".", ".."} {
		if _, err := resolveBaseImagePath(settings, bad); err == nil {
			t.Fatalf("expected error for selection %q", bad)
		}
	}
}
