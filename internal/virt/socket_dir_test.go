package virt

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestEnsureSocketDirIgnoresPermissionDeniedChown(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "123")
	t.Setenv(volumeGroupEnv, "456")

	dir := filepath.Join(t.TempDir(), "serial")

	originalChown := socketDirChown
	t.Cleanup(func() {
		socketDirChown = originalChown
	})

	socketDirChown = func(path string, uid, gid int) error {
		if path != dir {
			t.Fatalf("expected chown path %q, got %q", dir, path)
		}
		if uid != 123 || gid != 456 {
			t.Fatalf("expected chown ownership 123:456, got %d:%d", uid, gid)
		}
		return &os.PathError{Op: "chown", Path: path, Err: syscall.EPERM}
	}

	got, err := ensureSocketDir(dir, "serial")
	if err != nil {
		t.Fatalf("expected permission-denied chown to be ignored, got %v", err)
	}
	if got != dir {
		t.Fatalf("expected ensured directory %q, got %q", dir, got)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat socket directory: %v", err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("expected socket directory permissions 0777, got %04o", info.Mode().Perm())
	}
}

func TestEnsureSocketDirReturnsUnexpectedChownError(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "123")

	dir := filepath.Join(t.TempDir(), "serial")
	expectedErr := errors.New("boom")

	originalChown := socketDirChown
	t.Cleanup(func() {
		socketDirChown = originalChown
	})

	socketDirChown = func(string, int, int) error {
		return expectedErr
	}

	_, err := ensureSocketDir(dir, "serial")
	if err == nil {
		t.Fatal("expected chown error")
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error to wrap %v, got %v", expectedErr, err)
	}
}
