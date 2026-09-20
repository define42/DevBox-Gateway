package sauron

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// DeliveryPosition identifies a record boundary in a delivery spool.
type DeliveryPosition = spoolPosition

// DeliveryRecord contains a complete record and the position following it.
type DeliveryRecord struct {
	Data []byte
	End  DeliveryPosition
}

// DeliverySpool retains records until a forwarder acknowledges them. Appends
// may run concurrently; one forwarder owns reading and acknowledgement.
// The directory lock is held until Close has finished all storage operations.
type DeliverySpool struct {
	store *spool
	lock  *os.File

	mu       sync.Mutex
	changed  chan struct{}
	closed   bool
	inFlight sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

// OpenDeliverySpool opens a bounded durable spool at an operator-configured
// directory. A separate advisory lock prevents concurrent forwarders from
// modifying its files; failing to acquire it leaves existing records untouched.
func OpenDeliverySpool(dir string, maxBytes int64) (*DeliverySpool, error) {
	if strings.TrimSpace(dir) == "" || maxBytes <= 0 {
		return nil, errors.New("delivery spool requires a directory and a positive size limit")
	}
	lock, err := lockDeliveryDirectory(dir)
	if err != nil {
		return nil, err
	}
	store, err := openSpool(dir, maxBytes)
	if err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	return &DeliverySpool{store: store, lock: lock, changed: make(chan struct{})}, nil
}

func lockDeliveryDirectory(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, spoolDirMode); err != nil {
		return nil, fmt.Errorf("create delivery spool directory: %w", err)
	}
	lockPath := filepath.Join(dir, ".lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600) // #nosec G304 -- fixed lock filename under the operator-configured spool directory
	if err != nil {
		return nil, fmt.Errorf("open delivery spool lock: %w", err)
	}
	info, err := lock.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("delivery spool lock must be a regular file")
	}
	if err == nil {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	}
	if err == nil {
		err = lock.Chmod(0o600)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("acquire delivery spool lock: %w", err), lock.Close())
	}
	return lock, nil
}

// Append returns after record is on stable storage. A full spool waits for
// acknowledgement without evicting pending records. Cancellation interrupts
// capacity waits, but cannot cancel a file write or fsync already in progress.
// Records must not contain newlines; their terminating newline counts toward
// the size limit, and a record that cannot fit by itself is rejected immediately.
func (s *DeliverySpool) Append(ctx context.Context, record []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(len(record)) >= s.store.maxBytes {
		return fmt.Errorf("delivery spool record exceeds the %d-byte limit including its newline", s.store.maxBytes)
	}
	if bytes.IndexByte(record, '\n') >= 0 {
		return errors.New("delivery spool record contains a newline")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Capture this generation before attempting the append: an ACK between
		// the capacity check and the select must still wake this writer.
		changed, err := s.begin()
		if err != nil {
			return err
		}
		err = s.store.Append(record)
		s.inFlight.Done()
		if !errors.Is(err, errSpoolFull) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (s *DeliverySpool) begin() (<-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	s.inFlight.Add(1)
	return s.changed, nil
}

// Checkpoint returns the last recorded delivery position, including after Close.
func (s *DeliverySpool) Checkpoint() DeliveryPosition {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	return s.store.checkpoint
}

// ReadBatch reads complete committed records after a position. maxBytes is a
// soft limit: the final whole record may take the batch past it.
func (s *DeliverySpool) ReadBatch(after DeliveryPosition, maxEvents, maxBytes int) ([]DeliveryRecord, error) {
	if _, err := s.begin(); err != nil {
		return nil, err
	}
	defer s.inFlight.Done()
	records, err := s.store.readBatch(after, maxEvents, maxBytes)
	out := make([]DeliveryRecord, len(records))
	for i, record := range records {
		out[i] = DeliveryRecord{Data: record.data, End: record.end}
	}
	return out, err
}

// Acknowledge advances the checkpoint and reclaims fully delivered segments.
// It wakes capacity waiters even when reclaiming the active segment must wait
// until the next append attempt.
func (s *DeliverySpool) Acknowledge(position DeliveryPosition) error {
	if _, err := s.begin(); err != nil {
		return err
	}
	defer s.inFlight.Done()
	err := s.store.acknowledge(position)
	s.mu.Lock()
	if !s.closed {
		close(s.changed)
		s.changed = make(chan struct{})
	}
	s.mu.Unlock()
	return err
}

// Ready is signalled when new records become durable. The forwarder must read
// from Checkpoint before waiting, and independently observe its shutdown signal.
func (s *DeliverySpool) Ready() <-chan struct{} { return s.store.ready }

// Usage returns the bytes occupied by retained segments, including newlines.
func (s *DeliverySpool) Usage() int64 { return s.store.usage() }

// Close wakes blocked appenders, waits for active storage operations and
// releases the directory lock. Concurrent and repeated calls are safe.
func (s *DeliverySpool) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.changed)
		s.mu.Unlock()
		s.inFlight.Wait()
		s.closeErr = errors.Join(s.store.Close(), s.lock.Close())
	})
	return s.closeErr
}
