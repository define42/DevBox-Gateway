package virt

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var socketDirChown = os.Chown

func ensureSocketDir(dir, socketLabel string) (string, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "" || dir == "." {
		return "", fmt.Errorf("%s socket directory cannot be empty", socketLabel)
	}

	if err := os.MkdirAll(dir, 0o777); err != nil {
		return "", fmt.Errorf("create %s socket directory %s: %w", socketLabel, dir, err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		return "", fmt.Errorf("chmod %s socket directory %s: %w", socketLabel, dir, err)
	}

	owner, group, hasOwnership, err := socketOwnership()
	if err != nil {
		return "", err
	}
	if !hasOwnership {
		return dir, nil
	}

	if err := socketDirChown(dir, owner, group); err != nil {
		if canIgnoreSocketDirChownError(err) {
			log.Printf("Skipping chown for %s socket directory %s: %v", socketLabel, dir, err)
			return dir, nil
		}
		return "", fmt.Errorf("chown %s socket directory %s: %w", socketLabel, dir, err)
	}

	return dir, nil
}

func canIgnoreSocketDirChownError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}
