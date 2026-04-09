package main

import (
	"os"
	"testing"
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
