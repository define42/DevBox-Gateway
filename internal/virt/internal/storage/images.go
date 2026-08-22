package storage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/define42/devbox-gateway/internal/config"
	"golang.org/x/sys/unix"
)

const (
	baseImageUploadPrefix = ".base-image-upload-"
	maxBaseImageNameBytes = 255
	qcow2Magic            = "QFI\xfb"
)

var (
	// ErrInvalidBaseImageName means the requested name is not a supported,
	// bare base-image file name.
	ErrInvalidBaseImageName = errors.New("invalid base image name")
	// ErrBaseImageExists means an upload would overwrite an existing entry.
	ErrBaseImageExists = errors.New("base image already exists")
	// ErrBaseImageNotFound means the requested regular file does not exist.
	ErrBaseImageNotFound = errors.New("base image not found")
	// ErrEmptyBaseImage means the uploaded file contained no data.
	ErrEmptyBaseImage = errors.New("base image is empty")
	// ErrInvalidBaseImageFormat means the file does not start with the QCOW2
	// magic header.
	ErrInvalidBaseImageFormat = errors.New("base image is not a QCOW2 image")
	// ErrBaseImageTooLarge means the upload exceeded the configured limit.
	ErrBaseImageTooLarge = errors.New("base image is too large")
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
// in the configured base-image directory. Only regular QCOW2 files whose
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open base image directory %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !IsBaseImageName(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			continue
		}
		image, err := root.Open(entry.Name())
		if err != nil {
			continue
		}
		valid := hasQCOW2Magic(image)
		_ = image.Close()
		if !valid {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// BaseImageAvailableBytes returns the filesystem space available to the
// gateway in the configured base-image directory.
func BaseImageAvailableBytes(settings *config.Settings) (uint64, error) {
	dir := config.BaseImageDir(settings)
	var stats unix.Statfs_t
	if err := unix.Statfs(dir, &stats); err != nil {
		return 0, fmt.Errorf("read available base image storage in %s: %w", dir, err)
	}
	if stats.Bsize <= 0 {
		return 0, fmt.Errorf("read available base image storage in %s: invalid block size %d", dir, stats.Bsize)
	}

	blockSize := uint64(stats.Bsize)
	if stats.Bavail > math.MaxUint64/blockSize {
		return math.MaxUint64, nil
	}
	return stats.Bavail * blockSize, nil
}

func validateManagedBaseImageName(name string) error {
	if name == "" || strings.TrimSpace(name) != name ||
		len(name) > maxBaseImageNameBytes || !utf8.ValidString(name) ||
		strings.HasPrefix(name, baseImageUploadPrefix) ||
		strings.ContainsFunc(name, unicode.IsControl) ||
		!IsBareFileName(name) || !IsBaseImageName(name) {
		return fmt.Errorf("%w: %q", ErrInvalidBaseImageName, name)
	}
	return nil
}

// StoreBaseImage streams a new base image into the configured directory. The
// file is written to a private same-directory temporary file, then published
// atomically without replacing an existing entry.
func StoreBaseImage(settings *config.Settings, name string, src io.Reader, maxBytes int64) (int64, error) {
	if err := validateManagedBaseImageName(name); err != nil {
		return 0, err
	}
	if src == nil {
		return 0, fmt.Errorf("base image reader is required")
	}
	if maxBytes <= 0 {
		return 0, ErrBaseImageTooLarge
	}

	root, err := openBaseImageUploadRoot(settings, name)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()

	temporaryName, written, err := writeTemporaryBaseImage(root, src, maxBytes)
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Remove(temporaryName) }()

	if err := root.Link(temporaryName, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return 0, fmt.Errorf("%w: %q", ErrBaseImageExists, name)
		}
		return 0, fmt.Errorf("publish base image %q: %w", name, err)
	}
	return written, nil
}

func openBaseImageUploadRoot(settings *config.Settings, name string) (*os.Root, error) {
	dir := config.BaseImageDir(settings)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create base image directory %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open base image directory %s: %w", dir, err)
	}
	if _, err := root.Lstat(name); err == nil {
		_ = root.Close()
		return nil, fmt.Errorf("%w: %q", ErrBaseImageExists, name)
	} else if !errors.Is(err, fs.ErrNotExist) {
		_ = root.Close()
		return nil, fmt.Errorf("inspect base image destination %q: %w", name, err)
	}
	return root, nil
}

func writeTemporaryBaseImage(root *os.Root, src io.Reader, maxBytes int64) (string, int64, error) {
	if maxBytes < int64(len(qcow2Magic)) {
		return "", 0, ErrBaseImageTooLarge
	}
	validatedSource, err := validateQCOW2Source(src)
	if err != nil {
		return "", 0, err
	}

	temporaryName := baseImageUploadPrefix + rand.Text()
	temporary, err := root.OpenFile(temporaryName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, fmt.Errorf("create base image upload file: %w", err)
	}
	temporaryOpen := true
	keepTemporary := false
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		if !keepTemporary {
			_ = root.Remove(temporaryName)
		}
	}()

	written, err := io.Copy(temporary, io.LimitReader(validatedSource, baseImageCopyLimit(maxBytes)))
	if err != nil {
		return "", 0, fmt.Errorf("write base image upload: %w", err)
	}
	if written == 0 {
		return "", 0, ErrEmptyBaseImage
	}
	if written > maxBytes {
		return "", 0, ErrBaseImageTooLarge
	}
	if err := temporary.Sync(); err != nil {
		return "", 0, fmt.Errorf("sync base image upload: %w", err)
	}
	if err := temporary.Close(); err != nil {
		temporaryOpen = false
		return "", 0, fmt.Errorf("close base image upload: %w", err)
	}
	temporaryOpen = false
	keepTemporary = true
	return temporaryName, written, nil
}

func validateQCOW2Source(src io.Reader) (io.Reader, error) {
	var header [len(qcow2Magic)]byte
	n, err := io.ReadFull(src, header[:])
	switch {
	case n == 0 && errors.Is(err, io.EOF):
		return nil, ErrEmptyBaseImage
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return nil, ErrInvalidBaseImageFormat
	case err != nil:
		return nil, fmt.Errorf("read base image header: %w", err)
	case string(header[:]) != qcow2Magic:
		return nil, ErrInvalidBaseImageFormat
	default:
		return io.MultiReader(bytes.NewReader(header[:]), src), nil
	}
}

func hasQCOW2Magic(src io.Reader) bool {
	var header [len(qcow2Magic)]byte
	_, err := io.ReadFull(src, header[:])
	return err == nil && string(header[:]) == qcow2Magic
}

func baseImageCopyLimit(maxBytes int64) int64 {
	if maxBytes == math.MaxInt64 {
		return math.MaxInt64
	}
	return maxBytes + 1
}

// DeleteBaseImage removes a managed regular base-image file. Symlinks and
// other special files are deliberately treated as unavailable.
func DeleteBaseImage(settings *config.Settings, name string) error {
	if err := validateManagedBaseImageName(name); err != nil {
		return err
	}

	root, err := os.OpenRoot(config.BaseImageDir(settings))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %q", ErrBaseImageNotFound, name)
		}
		return fmt.Errorf("open base image directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	info, err := root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %q", ErrBaseImageNotFound, name)
		}
		return fmt.Errorf("inspect base image %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %q", ErrBaseImageNotFound, name)
	}
	if err := root.Remove(name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: %q", ErrBaseImageNotFound, name)
		}
		return fmt.Errorf("delete base image %q: %w", name, err)
	}
	return nil
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
		return fmt.Errorf(
			"no QCOW2 base images found in %s; place at least one QCOW2 image named .img/.qcow2/.raw there",
			config.BaseImageDir(settings),
		)
	}
	return nil
}
