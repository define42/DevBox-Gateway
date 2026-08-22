package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
)

// newBaseImageSettings returns settings whose BaseImageDir is seeded with the
// given files (name -> contents). A nil map leaves the directory absent.
func newBaseImageSettings(t *testing.T, files map[string][]byte) *config.Settings {
	t.Helper()

	settings := config.NewSettings(false)
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

func qcow2TestData(payload string) []byte {
	return append([]byte(qcow2Magic), []byte(payload)...)
}

func TestListBaseImagesFiltersAndSorts(t *testing.T) {
	settings := newBaseImageSettings(t, map[string][]byte{
		"b.img":       qcow2TestData("b"),
		"a.qcow2":     qcow2TestData("a"),
		"c.RAW":       qcow2TestData("c"),
		"notes.txt":   qcow2TestData("unsupported extension"),
		"invalid.img": []byte("not qcow2"),
		"short.raw":   []byte("QFI"),
		"empty.img":   {},
	})
	// A directory with a matching extension must be ignored.
	if err := os.MkdirAll(filepath.Join(config.BaseImageDir(settings), "sub.img"), 0o755); err != nil {
		t.Fatalf("create sub dir: %v", err)
	}
	if err := os.Symlink(filepath.Join(config.BaseImageDir(settings), "b.img"), filepath.Join(config.BaseImageDir(settings), "link.img")); err != nil {
		t.Fatalf("create symlink: %v", err)
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

func TestBaseImageAvailableBytes(t *testing.T) {
	settings := newBaseImageSettings(t, map[string][]byte{
		"base.img": qcow2TestData("data"),
	})

	available, err := BaseImageAvailableBytes(settings)
	if err != nil {
		t.Fatalf("BaseImageAvailableBytes: %v", err)
	}
	if available <= 0 {
		t.Fatalf("expected positive available storage, got %d", available)
	}

	missing := newBaseImageSettings(t, nil)
	if _, err := BaseImageAvailableBytes(missing); err == nil {
		t.Fatal("expected an error for a missing base-image directory")
	}
}

func TestStoreBaseImage(t *testing.T) {
	settings := newBaseImageSettings(t, nil)
	data := qcow2TestData("image data")

	written, err := StoreBaseImage(settings, "new.qcow2", bytes.NewReader(data), 64)
	if err != nil {
		t.Fatalf("StoreBaseImage: %v", err)
	}
	if written != int64(len(data)) {
		t.Fatalf("expected %d bytes, got %d", len(data), written)
	}
	got, err := os.ReadFile(filepath.Join(config.BaseImageDir(settings), "new.qcow2"))
	if err != nil {
		t.Fatalf("read stored image: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("unexpected stored data %q", got)
	}

	if _, err := StoreBaseImage(settings, "new.qcow2", bytes.NewReader(qcow2TestData("replacement")), 64); !errors.Is(err, ErrBaseImageExists) {
		t.Fatalf("expected ErrBaseImageExists, got %v", err)
	}
	got, err = os.ReadFile(filepath.Join(config.BaseImageDir(settings), "new.qcow2"))
	if err != nil {
		t.Fatalf("read original image: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("existing image was overwritten: %q", got)
	}
}

func TestStoreBaseImageConcurrentDuplicateHasOneCompleteWinner(t *testing.T) {
	settings := newBaseImageSettings(t, nil)
	contents := []string{
		string(qcow2TestData(strings.Repeat("a", 4096))),
		string(qcow2TestData(strings.Repeat("b", 4096))),
	}
	type result struct {
		data string
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, len(contents))
	for _, data := range contents {
		go func() {
			<-start
			_, err := StoreBaseImage(settings, "winner.img", strings.NewReader(data), 8192)
			results <- result{data: data, err: err}
		}()
	}
	close(start)

	successes := 0
	winner := ""
	for range contents {
		got := <-results
		if got.err == nil {
			successes++
			winner = got.data
			continue
		}
		if !errors.Is(got.err, ErrBaseImageExists) {
			t.Fatalf("expected duplicate conflict, got %v", got.err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected one successful upload, got %d", successes)
	}
	stored, err := os.ReadFile(filepath.Join(config.BaseImageDir(settings), "winner.img"))
	if err != nil {
		t.Fatalf("read winning image: %v", err)
	}
	if string(stored) != winner {
		t.Fatal("stored image was not the complete winning upload")
	}
}

func TestStoreBaseImageRejectsInvalidUploadsAndCleansUp(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		data    string
		limit   int64
		wantErr error
	}{
		{name: "missing name", file: "", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "path traversal", file: "../escape.img", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "unsupported extension", file: "image.iso", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "surrounding whitespace", file: " image.img", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "control character", file: "image\n.img", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "reserved prefix", file: ".base-image-upload-file.img", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "overlong", file: strings.Repeat("a", 252) + ".img", data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "invalid UTF-8", file: string([]byte{'x', 0xff, '.', 'i', 'm', 'g'}), data: "x", limit: 4, wantErr: ErrInvalidBaseImageName},
		{name: "empty", file: "empty.img", data: "", limit: 4, wantErr: ErrEmptyBaseImage},
		{name: "wrong magic", file: "invalid.img", data: "not qcow2", limit: 64, wantErr: ErrInvalidBaseImageFormat},
		{name: "short header", file: "short.raw", data: "QFI", limit: 64, wantErr: ErrInvalidBaseImageFormat},
		{name: "too large", file: "large.raw", data: qcow2Magic + "x", limit: 4, wantErr: ErrBaseImageTooLarge},
		{name: "limit below header", file: "small-limit.img", data: qcow2Magic, limit: 3, wantErr: ErrBaseImageTooLarge},
		{name: "invalid limit", file: "limit.img", data: qcow2Magic, limit: 0, wantErr: ErrBaseImageTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := newBaseImageSettings(t, nil)
			if _, err := StoreBaseImage(settings, tt.file, strings.NewReader(tt.data), tt.limit); !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}

			dir := config.BaseImageDir(settings)
			entries, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					return
				}
				t.Fatalf("read base image dir: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("expected upload cleanup, found %v", entries)
			}
		})
	}
}

func TestDeleteBaseImage(t *testing.T) {
	settings := newBaseImageSettings(t, map[string][]byte{"base.img": qcow2TestData("data")})
	if err := DeleteBaseImage(settings, "base.img"); err != nil {
		t.Fatalf("DeleteBaseImage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(config.BaseImageDir(settings), "base.img")); !os.IsNotExist(err) {
		t.Fatalf("expected image to be deleted, got %v", err)
	}
	if err := DeleteBaseImage(settings, "base.img"); !errors.Is(err, ErrBaseImageNotFound) {
		t.Fatalf("expected ErrBaseImageNotFound, got %v", err)
	}
	if err := DeleteBaseImage(settings, "../escape.img"); !errors.Is(err, ErrInvalidBaseImageName) {
		t.Fatalf("expected ErrInvalidBaseImageName, got %v", err)
	}
}

func TestDeleteBaseImageRejectsSymlinkWithoutDeletingTarget(t *testing.T) {
	settings := newBaseImageSettings(t, nil)
	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create base image dir: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target.img")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.img")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if err := DeleteBaseImage(settings, "link.img"); !errors.Is(err, ErrBaseImageNotFound) {
		t.Fatalf("expected ErrBaseImageNotFound, got %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "keep" {
		t.Fatalf("target was modified: %q", got)
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

	invalid := newBaseImageSettings(t, map[string][]byte{"base.img": []byte("not qcow2")})
	if err := EnsureBaseImagesAvailable(invalid); err == nil {
		t.Fatal("expected error when the library contains only an invalid image")
	}

	populated := newBaseImageSettings(t, map[string][]byte{"base.img": qcow2TestData("data")})
	if err := EnsureBaseImagesAvailable(populated); err != nil {
		t.Fatalf("expected success with one image, got %v", err)
	}
}

func TestResolveBaseImagePath(t *testing.T) {
	settings := newBaseImageSettings(t, map[string][]byte{
		"base.img":    qcow2TestData("data"),
		"invalid.raw": []byte("not qcow2"),
	})

	path, err := ResolveBaseImagePath(settings, "base.img")
	if err != nil {
		t.Fatalf("resolveBaseImagePath: %v", err)
	}
	if want := filepath.Join(config.BaseImageDir(settings), "base.img"); path != want {
		t.Fatalf("expected %q, got %q", want, path)
	}

	for _, bad := range []string{"", "   ", "missing.img", "invalid.raw", "../escape.img", "sub/base.img", `sub\base.img`, ".", ".."} {
		if _, err := ResolveBaseImagePath(settings, bad); err == nil {
			t.Fatalf("expected error for selection %q", bad)
		}
	}
}
