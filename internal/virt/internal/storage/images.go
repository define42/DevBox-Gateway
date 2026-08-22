package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/define42/devbox-gateway/internal/config"
)

// IsBaseImageName reports whether name has a recognised base-image extension
// (.img, .qcow2, or .raw, case-insensitive).
func IsBaseImageName(name string) bool {
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
func ListBaseImages(settings *config.Settings) ([]string, error) {
	dir := config.BaseImageDir(settings)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("read base image directory %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !IsBaseImageName(entry.Name()) {
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

// IsBareFileName reports whether name is a plain file name that can only refer
// to an entry directly inside a directory: not "." or "..", no path separators,
// and identical to its own filepath.Base.
func IsBareFileName(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	return name == filepath.Base(name)
}

// ResolveBaseImagePath validates the user-selected base image name and returns
// its absolute path. The name must be a bare file name (no path separators or
// "."/"..") and must match one of the images currently in the base-image
// directory. This is the single guard against path traversal or selecting an
// arbitrary host file.
func ResolveBaseImagePath(settings *config.Settings, selected string) (string, error) {
	selected = strings.TrimSpace(selected)
	if selected == "" {
		return "", fmt.Errorf("base image is required")
	}
	if !IsBareFileName(selected) {
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
func EnsureBaseImagesAvailable(settings *config.Settings) error {
	images, err := ListBaseImages(settings)
	if err != nil {
		return err
	}
	if len(images) == 0 {
		return fmt.Errorf("no base images found in %s; place at least one .img/.qcow2/.raw file there", config.BaseImageDir(settings))
	}
	return nil
}
