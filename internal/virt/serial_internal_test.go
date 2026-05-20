package virt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSocketOwnershipEnvEmpty(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "")
	value, has, err := parseSocketOwnershipEnv(volumeOwnerEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Fatal("expected has=false for empty value")
	}
	if value != 0 {
		t.Fatalf("expected value=0 for empty, got %d", value)
	}
}

func TestParseSocketOwnershipEnvValid(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "  42 ")
	value, has, err := parseSocketOwnershipEnv(volumeOwnerEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Fatal("expected has=true for valid value")
	}
	if value != 42 {
		t.Fatalf("expected value=42, got %d", value)
	}
}

func TestParseSocketOwnershipEnvInvalid(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "notanint")
	_, _, err := parseSocketOwnershipEnv(volumeOwnerEnv)
	if err == nil {
		t.Fatal("expected error for invalid integer value")
	}
}

func TestSocketOwnershipNoneConfigured(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "")
	t.Setenv(volumeGroupEnv, "")
	owner, group, has, err := socketOwnership()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if has {
		t.Fatal("expected has=false when neither env var is set")
	}
	if owner != 0 || group != 0 {
		t.Fatalf("expected zero owner/group, got %d/%d", owner, group)
	}
}

func TestSocketOwnershipOnlyOwner(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "100")
	t.Setenv(volumeGroupEnv, "")
	owner, group, has, err := socketOwnership()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Fatal("expected has=true when only owner is set")
	}
	if owner != 100 {
		t.Fatalf("expected owner=100, got %d", owner)
	}
	if group != -1 {
		t.Fatalf("expected group=-1 when unset, got %d", group)
	}
}

func TestSocketOwnershipOnlyGroup(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "")
	t.Setenv(volumeGroupEnv, "200")
	owner, group, has, err := socketOwnership()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Fatal("expected has=true when only group is set")
	}
	if owner != -1 {
		t.Fatalf("expected owner=-1 when unset, got %d", owner)
	}
	if group != 200 {
		t.Fatalf("expected group=200, got %d", group)
	}
}

func TestSocketOwnershipBoth(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "1")
	t.Setenv(volumeGroupEnv, "2")
	owner, group, has, err := socketOwnership()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has || owner != 1 || group != 2 {
		t.Fatalf("expected (1, 2, true), got (%d, %d, %v)", owner, group, has)
	}
}

func TestSocketOwnershipOwnerInvalid(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "not-a-number")
	t.Setenv(volumeGroupEnv, "")
	if _, _, _, err := socketOwnership(); err == nil {
		t.Fatal("expected error when owner env is invalid")
	}
}

func TestSocketOwnershipGroupInvalid(t *testing.T) {
	t.Setenv(volumeOwnerEnv, "")
	t.Setenv(volumeGroupEnv, "not-a-number")
	if _, _, _, err := socketOwnership(); err == nil {
		t.Fatal("expected error when group env is invalid")
	}
}

func TestRemoveSocketPathEmpty(t *testing.T) {
	if err := removeSocketPath("", "serial"); err != nil {
		t.Fatalf("expected nil error for empty path, got %v", err)
	}
	if err := removeSocketPath("   ", "serial"); err != nil {
		t.Fatalf("expected nil error for whitespace path, got %v", err)
	}
}

func TestRemoveSocketPathMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if err := removeSocketPath(missing, "serial"); err != nil {
		t.Fatalf("expected nil error for missing socket, got %v", err)
	}
}

func TestRemoveSocketPathRemovesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.sock")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("create test socket file: %v", err)
	}
	if err := removeSocketPath(path, "serial"); err != nil {
		t.Fatalf("remove socket: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected socket to be removed, stat err=%v", err)
	}
}
