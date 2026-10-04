package sauron

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

type spoolOpener func(string) (io.Closer, error)

func TestGuestAndDeliverySpoolsCannotShareDirectory(t *testing.T) {
	t.Parallel()
	openers := map[string]spoolOpener{
		"guest": func(dir string) (io.Closer, error) {
			return newHECForwarding(splunkhec.Config{Endpoint: "https://hec.example.test", Token: "test-token"}, dir, 1024)
		},
		"delivery": func(dir string) (io.Closer, error) {
			return OpenDeliverySpool(dir, 1024)
		},
	}
	for firstName, openFirst := range openers {
		for secondName, openSecond := range openers {
			t.Run(firstName+" then "+secondName, func(t *testing.T) {
				testSpoolExclusiveOwnership(t, openFirst, openSecond)
			})
		}
	}
}

func testSpoolExclusiveOwnership(t *testing.T, openFirst, openSecond spoolOpener) {
	t.Helper()
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	first, err := openFirst(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	for _, path := range []string{dir, alias} {
		if second, err := openSecond(path); err == nil {
			_ = second.Close()
			t.Fatal("another forwarder acquired the same spool directory")
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := openSecond(alias)
	if err != nil {
		t.Fatalf("reopening after Close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolFailedOpenReleasesDirectoryLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A directory with the first segment's name makes segment creation fail
	// after the lock was acquired.
	blocker := filepath.Join(dir, "00000000000000000001.jsonl")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	if s, err := openSpool(dir, 1024); err == nil {
		_ = s.Close()
		t.Fatal("opened spool with an obstructed segment file")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	openTestSpool(t, dir, 1024)
}
