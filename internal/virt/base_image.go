// Package virt manages libvirt-backed virtual machine operations for the gateway.
package virt

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"rdptlsgateway/internal/config"
	"syscall"
)

func baseImageURLAndPath(settings *config.SettingsType) (string, string, error) {
	baseImageURL := settings.Get(config.BASE_IMAGE_URL)
	parsedURL, err := url.Parse(baseImageURL)
	if err != nil {
		return "", "", fmt.Errorf("parse base image URL %q: %w", baseImageURL, err)
	}

	imageName := path.Base(parsedURL.Path)
	if imageName == "." || imageName == "/" || imageName == "" {
		return "", "", fmt.Errorf("invalid base image URL %q", baseImageURL)
	}

	imageDir := config.ImageDir(settings)
	if imageDir == "." {
		return "", "", fmt.Errorf("invalid image directory derived from %q", settings.Get(config.DATA_ROOT_DIR))
	}

	return baseImageURL, filepath.Join(imageDir, imageName), nil
}

func ensureBaseImage(settings *config.SettingsType) (string, error) {
	baseImageURL, baseImagePath, err := baseImageURLAndPath(settings)
	if err != nil {
		return "", err
	}

	exists, err := nonEmptyFileExists(baseImagePath)
	if err != nil {
		return "", fmt.Errorf("stat base image %s: %w", baseImagePath, err)
	}
	if exists {
		return baseImagePath, nil
	}

	if err := ensureBaseImageDir(baseImagePath); err != nil {
		return "", err
	}

	return ensureLockedBaseImage(baseImageURL, baseImagePath)
}

func nonEmptyFileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		return info.Size() > 0, nil
	case os.IsNotExist(err):
		return false, nil
	default:
		return false, err
	}
}

func ensureBaseImageDir(baseImagePath string) error {
	imageDir := filepath.Dir(baseImagePath)
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return fmt.Errorf("create image directory %s: %w", imageDir, err)
	}
	return nil
}

func ensureLockedBaseImage(baseImageURL, baseImagePath string) (string, error) {
	lockFile, err := os.OpenFile(baseImagePath+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return "", fmt.Errorf("open base image lock: %w", err)
	}
	defer func() { _ = lockFile.Close() }()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return "", fmt.Errorf("lock base image %s: %w", baseImagePath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	exists, err := nonEmptyFileExists(baseImagePath)
	if err != nil {
		return "", fmt.Errorf("stat base image %s after lock: %w", baseImagePath, err)
	}
	if exists {
		return baseImagePath, nil
	}

	if err := downloadBaseImageToPath(baseImageURL, baseImagePath); err != nil {
		return "", err
	}

	return baseImagePath, nil
}

func downloadBaseImageToPath(baseImageURL, baseImagePath string) error {
	tmpPath, err := createTemporaryBaseImagePath(filepath.Dir(baseImagePath), filepath.Base(baseImagePath))
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()

	log.Printf("Base image %s not found, downloading...", baseImageURL)
	if err := downloadWithProgress(baseImageURL, tmpPath); err != nil {
		return fmt.Errorf("download base image: %w", err)
	}
	if err := os.Rename(tmpPath, baseImagePath); err != nil {
		return fmt.Errorf("move base image into place: %w", err)
	}
	return nil
}

func createTemporaryBaseImagePath(imageDir, imageName string) (string, error) {
	tmpFile, err := os.CreateTemp(imageDir, imageName+".*.part")
	if err != nil {
		return "", fmt.Errorf("create temporary base image file: %w", err)
	}

	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temporary base image file: %w", err)
	}

	return tmpPath, nil
}
