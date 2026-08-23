package dashboard

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerDiskIODeviceForPath(t *testing.T) {
	t.Parallel()

	const storagePath = "/data/image"
	const wantLink = "/sys/dev/block/259:2"
	got, err := serverDiskIODeviceForPath(
		storagePath,
		func(path string, info *unix.Stat_t) error {
			if path != storagePath {
				t.Fatalf("stat path = %q, want %q", path, storagePath)
			}
			info.Dev = unix.Mkdev(259, 2)
			return nil
		},
		func(path string) (string, error) {
			if path != wantLink {
				t.Fatalf("readlink path = %q, want %q", path, wantLink)
			}
			return "../../devices/pci0000:00/nvme/nvme0/nvme0n1/nvme0n1p2", nil
		},
	)
	if err != nil {
		t.Fatalf("serverDiskIODeviceForPath() error = %v", err)
	}
	if got != "nvme0n1p2" {
		t.Fatalf("serverDiskIODeviceForPath() = %q, want %q", got, "nvme0n1p2")
	}
}

func TestServerDiskIODeviceForPathRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	statFailure := errors.New("stat failed")
	readlinkFailure := errors.New("readlink failed")
	validStat := func(_ string, info *unix.Stat_t) error {
		info.Dev = unix.Mkdev(8, 1)
		return nil
	}
	validReadlink := func(string) (string, error) {
		return "../../devices/block/sda/sda1", nil
	}
	tests := []struct {
		name     string
		path     string
		stat     func(string, *unix.Stat_t) error
		readlink func(string) (string, error)
	}{
		{name: "empty path", stat: validStat, readlink: validReadlink},
		{name: "nil stat", path: "/data/image", readlink: validReadlink},
		{name: "nil link reader", path: "/data/image", stat: validStat},
		{
			name:     "stat failure",
			path:     "/data/image",
			stat:     func(string, *unix.Stat_t) error { return statFailure },
			readlink: validReadlink,
		},
		{
			name:     "link failure",
			path:     "/data/image",
			stat:     validStat,
			readlink: func(string) (string, error) { return "", readlinkFailure },
		},
		{
			name:     "invalid link target",
			path:     "/data/image",
			stat:     validStat,
			readlink: func(string) (string, error) { return "", nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, err := serverDiskIODeviceForPath(tt.path, tt.stat, tt.readlink); err == nil {
				t.Fatalf("serverDiskIODeviceForPath() = %q, want error", got)
			}
		})
	}
}
