package audit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// auditFile serializes append/fsync and follows rename-and-create rotation.
// Retention is managed externally. Copytruncate is not supported because it
// can discard records concurrently with the writer.
type auditFile struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	info   os.FileInfo
	closed bool
}

// auditDirectoriesToSync records the directories that must be synced after
// opening the file: its immediate parent, followed by the parent of each
// directory that MkdirAll will create. Collect this before MkdirAll so new
// directory entries can be committed from the leaf up to an existing ancestor.
func auditDirectoriesToSync(directory string) ([]string, error) {
	directory = filepath.Clean(directory)
	directories := []string{directory}
	for {
		_, err := os.Stat(directory)
		if err == nil {
			return directories, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("stat audit log directory %q: %w", directory, err)
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil, fmt.Errorf("audit log directory has no existing ancestor: %q", directory)
		}
		directories = append(directories, parent)
		directory = parent
	}
}

func syncAuditDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- parent of the operator-configured audit path; no request data
	if err != nil {
		return fmt.Errorf("open audit log directory %q for sync: %w", path, err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("sync audit log directory %q: %w", path, err)
	}
	return nil
}

func newAuditFile(path string) (*auditFile, error) {
	file, err := openAuditFile(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &auditFile{path: path, file: file, info: info}, nil
}

func (f *auditFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	if err := f.reopenRotated(); err != nil {
		return 0, err
	}
	n, err := f.file.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, fmt.Errorf("append audit file: %w", err)
	}
	if err := f.file.Sync(); err != nil {
		return n, fmt.Errorf("sync audit file: %w", err)
	}
	return n, nil
}

// Called under mu. If rotation races this check, at most this append lands in
// the renamed file; the following append reopens the configured path.
func (f *auditFile) reopenRotated() error {
	info, err := os.Stat(f.path)
	if err == nil && os.SameFile(f.info, info) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat audit path: %w", err)
	}
	next, err := newAuditFile(f.path)
	if err != nil {
		return fmt.Errorf("reopen rotated audit file: %w", err)
	}
	previous := f.file
	f.file, f.info = next.file, next.info
	return previous.Close()
}

func (f *auditFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return f.file.Close()
}
