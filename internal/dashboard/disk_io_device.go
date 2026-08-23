package dashboard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const sysDevBlockPath = "/sys/dev/block"

// NewServerDiskIOSamplerForPath creates a sampler for the block device backing
// path. Resolving the filesystem's device keeps the I/O badge scoped to the VM
// storage filesystem instead of double-counting logical and physical devices.
func NewServerDiskIOSamplerForPath(path string) (*ServerDiskIOSampler, error) {
	device, err := serverDiskIODeviceForPath(path, unix.Stat, os.Readlink)
	if err != nil {
		return nil, fmt.Errorf("create server disk I/O sampler for %s: %w", path, err)
	}

	return NewServerDiskIOSampler(device)
}

func serverDiskIODeviceForPath(
	path string,
	stat func(string, *unix.Stat_t) error,
	readlink func(string) (string, error),
) (string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	if cleanPath == "." && strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("storage path is empty")
	}
	if stat == nil {
		return "", fmt.Errorf("filesystem stat function is nil")
	}
	if readlink == nil {
		return "", fmt.Errorf("device link reader is nil")
	}

	var info unix.Stat_t
	if err := stat(cleanPath, &info); err != nil {
		return "", fmt.Errorf("stat storage path %s: %w", cleanPath, err)
	}

	deviceLink := filepath.Join(
		sysDevBlockPath,
		fmt.Sprintf("%d:%d", unix.Major(info.Dev), unix.Minor(info.Dev)),
	)
	linkTarget, err := readlink(deviceLink)
	if err != nil {
		return "", fmt.Errorf("resolve block device %s: %w", deviceLink, err)
	}

	device, err := normalizeServerDiskIODevice(linkTarget)
	if err != nil {
		return "", fmt.Errorf("resolve block device %s: %w", deviceLink, err)
	}
	return device, nil
}
