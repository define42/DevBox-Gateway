// Package virt manages libvirt-backed virtual machine operations for the gateway.
package virt

import (
	"fmt"
	"os"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"sort"
	"strings"
)

// isBaseImageName reports whether name has a recognised base-image extension
// (.img, .qcow2, or .raw, case-insensitive).
func isBaseImageName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".img", ".qcow2", ".raw":
		return true
	default:
		return false
	}
}

// ListBaseImages returns the sorted file names of selectable base images found
// in the configured base-image directory. Only regular, non-empty files whose
// extension is one of .img/.qcow2/.raw are returned. A missing directory yields
// an empty list (not an error) so callers can treat "directory absent" the same
// as "no images yet".
func ListBaseImages(settings *config.SettingsType) ([]string, error) {
	dir := config.BaseImageDir(settings)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read base image directory %s: %w", dir, err)
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() || !isBaseImageName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// resolveBaseImagePath validates the user-selected base image name and returns
// its absolute path. The name must be a bare file name (no path separators or
// "."/"..") and must match one of the images currently in the base-image
// directory. This is the single guard against path traversal or selecting an
// arbitrary host file.
func resolveBaseImagePath(settings *config.SettingsType, selected string) (string, error) {
	selected = strings.TrimSpace(selected)
	if selected == "" {
		return "", fmt.Errorf("base image is required")
	}
	if selected != filepath.Base(selected) || selected == "." || selected == ".." || strings.ContainsAny(selected, `/\`) {
		return "", fmt.Errorf("invalid base image %q", selected)
	}

	available, err := ListBaseImages(settings)
	if err != nil {
		return "", err
	}
	for _, name := range available {
		if name == selected {
			return filepath.Join(config.BaseImageDir(settings), selected), nil
		}
	}
	return "", fmt.Errorf("base image %q is not available", selected)
}

// EnsureBaseImagesAvailable returns an error when no selectable base image
// exists, so the gateway refuses to boot with an empty image library instead of
// silently having nothing to clone VMs from.
func EnsureBaseImagesAvailable(settings *config.SettingsType) error {
	images, err := ListBaseImages(settings)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		return fmt.Errorf("no base images found in %s; place at least one .img/.qcow2/.raw file there", config.BaseImageDir(settings))
	}
	return nil
}
