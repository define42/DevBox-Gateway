package sauron

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
)

func openTestDeliverySpool(t *testing.T, dir string, maxBytes int64) *DeliverySpool {
	t.Helper()
	s, err := OpenDeliverySpool(dir, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func appendDelivery(t *testing.T, s *DeliverySpool, records ...string) {
	t.Helper()
	for _, record := range records {
		if err := s.Append(t.Context(), []byte(record)); err != nil {
			t.Fatal(err)
		}
	}
}

func readDelivery(t *testing.T, s *DeliverySpool) []DeliveryRecord {
	t.Helper()
	records, err := s.ReadBatch(s.Checkpoint(), 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

func startDeliveryWriters(
	ctx context.Context,
	s *DeliverySpool,
	count int,
	record func(int) []byte,
) <-chan error {
	done := make(chan error, count)
	for i := range count {
		payload := record(i)
		go func() { done <- s.Append(ctx, payload) }()
	}
	return done
}

func acknowledgeOneDelivery(
	t *testing.T,
	s *DeliverySpool,
	done <-chan error,
	seen map[string]bool,
) {
	t.Helper()
	records := readDelivery(t, s)
	if len(records) != 1 || seen[string(records[0].Data)] {
		t.Fatalf("unexpected pending records: %#v", records)
	}
	seen[string(records[0].Data)] = true
	if err := s.Acknowledge(records[0].End); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func closeDeliverySpoolConcurrently(t *testing.T, s *DeliverySpool, callers int) {
	t.Helper()
	var closing sync.WaitGroup
	for range callers {
		closing.Go(func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	closing.Wait()
}

func requireClosedDeliveryWriters(t *testing.T, done <-chan error, writers int) {
	t.Helper()
	for range writers {
		if err := <-done; !errors.Is(err, os.ErrClosed) {
			t.Errorf("closed append returned %v", err)
		}
	}
}

func TestDeliverySpoolRestartReplaysPendingRecords(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := openTestDeliverySpool(t, dir, 1<<20)
	appendDelivery(t, s, `{"n":1}`, `{"n":2}`, `{"n":3}`)
	records := readDelivery(t, s)
	if len(records) != 3 {
		t.Fatalf("read %d records, want 3", len(records))
	}
	checkpoint := records[0].End
	if err := s.Acknowledge(checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestDeliverySpool(t, dir, 1<<20)
	if got := reopened.Checkpoint(); got != checkpoint {
		t.Fatalf("checkpoint %v, want %v", got, checkpoint)
	}
	replayed := readDelivery(t, reopened)
	if !reflect.DeepEqual(replayed, records[1:]) {
		t.Fatalf("replayed %#v, want %#v", replayed, records[1:])
	}
}

func TestDeliverySpoolDirectoryLockPreservesExistingRecords(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := openTestDeliverySpool(t, dir, 1<<20)
	appendDelivery(t, s, `{"pending":true}`)
	want := readDelivery(t, s)
	second, err := OpenDeliverySpool(dir, 1<<20)
	if err == nil {
		_ = second.Close()
		t.Fatal("second opener acquired an already locked directory")
	}
	if got := readDelivery(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("failed lock changed records: %#v", got)
	}
	appendDelivery(t, s, `{"still_usable":true}`)
}

func TestDeliverySpoolRestrictsPermissions(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	s := openTestDeliverySpool(t, dir, 1<<20)
	appendDelivery(t, s, `{"n":1}`)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		allowed := os.FileMode(0o640)
		if entry.Name() == ".lock" {
			allowed = 0o600
		}
		if got := info.Mode().Perm(); got&^allowed != 0 {
			t.Errorf("%s permissions %o exceed %o", entry.Name(), got, allowed)
		}
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&^os.FileMode(0o750) != 0 {
		t.Fatalf("spool directory permissions: %v, %v", info, err)
	}
}

func TestDeliverySpoolRejectsLockSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".lock")); err != nil {
		t.Fatal(err)
	}
	if s, err := OpenDeliverySpool(dir, 1024); err == nil {
		_ = s.Close()
		t.Fatal("accepted symlink as spool lock")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("lock symlink target changed: %q, %v", data, err)
	}
}

func TestDeliverySpoolRejectsInvalidOptions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		dir  string
		max  int64
	}{
		{name: "empty directory", max: 1024},
		{name: "zero limit", dir: filepath.Join(t.TempDir(), "zero")},
		{name: "negative limit", dir: filepath.Join(t.TempDir(), "negative"), max: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if s, err := OpenDeliverySpool(tc.dir, tc.max); err == nil {
				_ = s.Close()
				t.Fatal("invalid options accepted")
			}
		})
	}
}

func TestDeliverySpoolFullWaitsWithoutEvictionAndResumesAfterAck(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := openTestDeliverySpool(t, t.TempDir(), 8)
		appendDelivery(t, s, `{"n":1}`)
		done := make(chan error, 1)
		go func() { done <- s.Append(t.Context(), []byte(`{"n":2}`)) }()
		synctest.Wait()
		select {
		case err := <-done:
			t.Fatalf("full append returned before acknowledgement: %v", err)
		default:
		}
		records := readDelivery(t, s)
		if len(records) != 1 || string(records[0].Data) != `{"n":1}` || s.Usage() != 8 {
			t.Fatalf("full spool lost pending records: %#v; usage %d", records, s.Usage())
		}
		if err := s.Acknowledge(records[0].End); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := readDelivery(t, s); len(got) != 1 || string(got[0].Data) != `{"n":2}` {
			t.Fatalf("pending records after acknowledgement: %#v", got)
		}
	})
}

func TestDeliverySpoolCancelledCapacityWait(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := openTestDeliverySpool(t, t.TempDir(), 8)
		appendDelivery(t, s, `{"n":1}`)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- s.Append(ctx, []byte(`{"n":2}`)) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled append returned %v", err)
		}
		if got := readDelivery(t, s); len(got) != 1 || string(got[0].Data) != `{"n":1}` {
			t.Fatalf("cancelled append changed pending records: %#v", got)
		}
	})
}

func TestDeliverySpoolAcknowledgementWakesConcurrentWriters(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		s := openTestDeliverySpool(t, t.TempDir(), 8)
		appendDelivery(t, s, `{"n":0}`)
		const writers = 5
		done := startDeliveryWriters(t.Context(), s, writers, func(i int) []byte {
			return fmt.Appendf(nil, `{"n":%d}`, i+1)
		})
		synctest.Wait()
		seen := make(map[string]bool)
		for range writers {
			acknowledgeOneDelivery(t, s, done, seen)
		}
		records := readDelivery(t, s)
		if len(records) != 1 || seen[string(records[0].Data)] {
			t.Fatalf("unexpected final pending records: %#v", records)
		}
	})
}

func TestDeliverySpoolRejectsOversizedAndMultilineRecords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		record string
	}{
		{name: "oversized including newline", record: strings.Repeat("x", 8)},
		{name: "multiple lines", record: "{}\n{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := openTestDeliverySpool(t, t.TempDir(), 8)
			if err := s.Append(t.Context(), []byte(tc.record)); err == nil {
				t.Fatalf("accepted invalid record %q", tc.record)
			}
			if s.Usage() != 0 {
				t.Fatalf("invalid record consumed %d bytes", s.Usage())
			}
		})
	}
}

func TestDeliverySpoolReadySignalsDurableRecords(t *testing.T) {
	t.Parallel()
	s := openTestDeliverySpool(t, t.TempDir(), 1<<20)
	appendDelivery(t, s, `{"n":1}`)
	select {
	case <-s.Ready():
	default:
		t.Fatal("durable append did not signal readiness")
	}
	if got := readDelivery(t, s); len(got) != 1 {
		t.Fatalf("read %d durable records, want 1", len(got))
	}
}

func TestDeliverySpoolCloseWakesAllWaitersAndReleasesLock(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		s := openTestDeliverySpool(t, dir, 8)
		appendDelivery(t, s, `{"n":1}`)
		const writers = 8
		done := startDeliveryWriters(t.Context(), s, writers, func(int) []byte {
			return []byte(`{"n":2}`)
		})
		synctest.Wait()
		closeDeliverySpoolConcurrently(t, s, 3)
		synctest.Wait()
		requireClosedDeliveryWriters(t, done, writers)
		reopened := openTestDeliverySpool(t, dir, 8)
		if got := readDelivery(t, reopened); len(got) != 1 || string(got[0].Data) != `{"n":1}` {
			t.Fatalf("close lost pending records: %#v", got)
		}
	})
}
