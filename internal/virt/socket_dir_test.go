package virt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSocketDirCreatesDirectoryWithPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "serial")

	got, err := ensureSocketDir(dir, "serial")
	if err != nil {
		t.Fatalf("ensure socket directory: %v", err)
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

func TestEnsureSocketDirIgnoresPermissionDeniedChown(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "serial")

	const owner = 0
	const group = 0

	probeErr := os.Chown(dir, owner, group)
	if probeErr == nil {
		t.Skip("environment allows chown; cannot reproduce permission-denied path")
	}
	if !canIgnoreSocketDirChownError(probeErr) {
		t.Skipf("environment returned non-ignorable chown error: %v", probeErr)
	}

	t.Setenv(volumeOwnerEnv, "0")
	t.Setenv(volumeGroupEnv, "0")

	got, err := ensureSocketDir(dir, "serial")
	if err != nil {
		t.Fatalf("expected permission-denied chown to be ignored, got %v", err)
	}
	if got != dir {
		t.Fatalf("expected ensured directory %q, got %q", dir, got)
	}
}

func TestChownSocketDirReturnsUnexpectedChownError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")

	err := chownSocketDir(dir, "serial", 0, 0)
	if err == nil {
		t.Fatal("expected chown error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected error to wrap %v, got %v", os.ErrNotExist, err)
	}
}
