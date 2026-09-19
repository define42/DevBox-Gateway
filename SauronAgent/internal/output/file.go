package output

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/define42/SauronAgent/internal/config"
)

const (
	// fileMode keeps the evidence file readable by its owner and by a log
	// group only. Events carry command lines, file paths and usernames from
	// every monitored guest; a world-readable copy of that on the hypervisor
	// is an information leak in its own right.
	fileMode fs.FileMode = 0o640
	// dirMode matches fileMode: a traversable directory for the log group,
	// closed to everyone else.
	dirMode fs.FileMode = 0o750
)

// fileSink writes newline-delimited JSON to a file, rotating it by size.
type fileSink struct {
	// mu covers the file handle, the tracked size and rotation. Rotation
	// renames the file out from under concurrent writers, so it may only run
	// while no other write is in progress.
	mu sync.Mutex

	path        string
	maxSize     int64
	maxFiles    int
	syncOnWrite bool

	f      *os.File
	size   int64
	closed bool
}

// NewFile returns a sink writing newline-delimited JSON to cfg.Path.
//
// Parent directories are created as needed. A MaxSize of zero disables
// rotation so that an external logrotate can own the file instead.
func NewFile(cfg config.FileOutput) (Sink, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("output/file: path must be set")
	}
	maxFiles := cfg.MaxFiles
	if maxFiles < 1 {
		// Rotating with nothing kept would delete the only copy of the events
		// written since the last rotation. Keep one generation: an operator
		// who wants no history at all can disable the sink.
		maxFiles = 1
	}
	s := &fileSink{
		path:        cfg.Path,
		maxSize:     cfg.MaxSize.Bytes(),
		maxFiles:    maxFiles,
		syncOnWrite: cfg.SyncOnWrite,
	}
	if err := s.openLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// openLocked opens or creates the current file and records its size. The
// caller must hold mu, except in NewFile where the sink is not yet shared.
func (s *fileSink) openLocked() error {
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("output/file: creating %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return fmt.Errorf("output/file: opening %s: %w", s.path, err)
	}
	// The mode passed to O_CREATE is filtered through the process umask, and
	// an existing file keeps whatever mode it already had -- which may be the
	// 0644 some other tool created it with. Neither is a guarantee, so the
	// mode this file must have is set explicitly.
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("output/file: securing %s: %w", s.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("output/file: stat %s: %w", s.path, err)
	}
	s.f = f
	s.size = info.Size()
	return nil
}

// Write appends one envelope as a single JSON line.
//
// Returning nil means the bytes have reached the kernel, so they survive the
// collector crashing. They survive the machine losing power only after a
// Flush, or on every write when SyncOnWrite is set.
func (s *fileSink) Write(ctx context.Context, env *Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	line, err := marshalLine(env, false)
	if err != nil {
		return fmt.Errorf("output/file: encoding envelope: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	if s.f == nil {
		// A previous rotation failed part way through. Reopen rather than
		// refusing for ever: the events lost to that failure were already
		// reported as errors, and later events should still be collected.
		if err := s.openLocked(); err != nil {
			return err
		}
	}
	if err := s.rotateIfNeededLocked(int64(len(line))); err != nil {
		return err
	}

	n, err := s.f.Write(line)
	if err != nil {
		if n > 0 {
			// A short write leaves a truncated JSON object at the end of the
			// file, which breaks every consumer that reads it line by line.
			// Roll it back. The event is reported as not accepted, so it is
			// not acknowledged to the guest and will be delivered again.
			err = errors.Join(err, s.f.Truncate(s.size))
		}
		return fmt.Errorf("output/file: writing %s: %w", s.path, err)
	}
	s.size += int64(n)

	if s.syncOnWrite {
		if err := s.f.Sync(); err != nil {
			return fmt.Errorf("output/file: syncing %s: %w", s.path, err)
		}
	}
	return nil
}

// rotateIfNeededLocked rolls the file over when appending n bytes would take
// it past MaxSize. An event larger than MaxSize on its own is still written
// whole, to an empty file: dropping it would be exactly the silent loss this
// project exists to prevent.
func (s *fileSink) rotateIfNeededLocked(n int64) error {
	if s.maxSize <= 0 || s.size == 0 || s.size+n <= s.maxSize {
		return nil
	}
	return s.rotateLocked()
}

// rotateLocked shifts path.N-1 to path.N, moves the live file to path.1 and
// opens a fresh one. Everything past MaxFiles is discarded.
func (s *fileSink) rotateLocked() error {
	// Flush the outgoing generation before it is renamed: whatever is still
	// only in the kernel's page cache belongs with the events it was written
	// beside, not with the next file.
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("output/file: syncing %s before rotation: %w", s.path, err)
	}
	if err := s.f.Close(); err != nil {
		s.f = nil
		return fmt.Errorf("output/file: closing %s before rotation: %w", s.path, err)
	}
	s.f = nil

	if err := removeIfExists(rotatedName(s.path, s.maxFiles)); err != nil {
		return err
	}
	for i := s.maxFiles - 1; i >= 1; i-- {
		if err := renameIfExists(rotatedName(s.path, i), rotatedName(s.path, i+1)); err != nil {
			return err
		}
	}
	if err := renameIfExists(s.path, rotatedName(s.path, 1)); err != nil {
		return err
	}
	return s.openLocked()
}

func rotatedName(path string, n int) string { return fmt.Sprintf("%s.%d", path, n) }

// removeIfExists deletes path, treating an already absent file as success:
// fewer rotated generations than MaxFiles is the normal state early on.
func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("output/file: removing %s: %w", path, err)
	}
	return nil
}

func renameIfExists(from, to string) error {
	if err := os.Rename(from, to); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("output/file: rotating %s to %s: %w", from, to, err)
	}
	return nil
}

// Flush fsyncs the file, which is what makes everything written so far survive
// the machine losing power.
func (s *fileSink) Flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	if s.f == nil {
		return nil
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("output/file: syncing %s: %w", s.path, err)
	}
	return nil
}

// Close fsyncs and closes the file. It is safe to call more than once.
func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.f == nil {
		return nil
	}
	f := s.f
	s.f = nil
	var errs []error
	if err := f.Sync(); err != nil {
		errs = append(errs, fmt.Errorf("output/file: syncing %s: %w", s.path, err))
	}
	if err := f.Close(); err != nil {
		errs = append(errs, fmt.Errorf("output/file: closing %s: %w", s.path, err))
	}
	return errors.Join(errs...)
}

// Name identifies the sink in logs and metrics.
func (s *fileSink) Name() string { return "file" }
