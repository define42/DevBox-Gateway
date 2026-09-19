package sauron

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestSpool(t *testing.T, dir string, maxBytes int64) *spool {
	t.Helper()
	s, err := openSpool(dir, maxBytes)
	if err != nil {
		t.Fatalf("openSpool() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func appendRecords(t *testing.T, s *spool, records ...string) {
	t.Helper()
	for _, record := range records {
		if err := s.Append([]byte(record)); err != nil {
			t.Fatalf("Append(%s) error = %v", record, err)
		}
	}
}

// readAll reads every committed record from position, in batches.
func readAll(t *testing.T, s *spool, from spoolPosition) ([]string, spoolPosition) {
	t.Helper()
	var got []string
	position := from
	for {
		records, err := s.readBatch(position, 3, 1<<20)
		if err != nil {
			t.Fatalf("readBatch() error = %v", err)
		}
		if len(records) == 0 {
			return got, position
		}
		for _, record := range records {
			got = append(got, string(record.data))
		}
		position = records[len(records)-1].end
	}
}

func numbered(prefix string, n int) []string {
	records := make([]string, n)
	for i := range records {
		records[i] = fmt.Sprintf(`{"%s":%d}`, prefix, i)
	}
	return records
}

func assertRecords(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d records %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("record %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestSpoolReturnsRecordsInOrder(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	want := numbered("r", 7)
	appendRecords(t, s, want...)

	got, _ := readAll(t, s, s.checkpoint)
	assertRecords(t, got, want)
}

func TestSpoolReadBatchRespectsItsLimits(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	appendRecords(t, s, numbered("r", 10)...)

	records, err := s.readBatch(s.checkpoint, 4, 1<<20)
	if err != nil || len(records) != 4 {
		t.Fatalf("readBatch(max 4 records) = %d records, %v", len(records), err)
	}
	// Each record is 8 bytes with its newline; the batch stops growing with
	// the record that reaches the byte limit.
	records, err = s.readBatch(s.checkpoint, 100, 20)
	if err != nil || len(records) != 3 {
		t.Fatalf("readBatch(max 20 bytes) = %d records, %v; want 3", len(records), err)
	}
}

func TestSpoolRotatesAndReclaimsDeliveredSegments(t *testing.T) {
	dir := t.TempDir()
	s := openTestSpool(t, dir, 1<<20)
	s.segmentSize = 64 // a few records per segment
	want := numbered("record", 20)
	appendRecords(t, s, want...)

	segments, err := listSpoolSegments(dir)
	if err != nil || len(segments) < 4 {
		t.Fatalf("spool holds %d segments (%v), want several", len(segments), err)
	}
	got, end := readAll(t, s, s.checkpoint)
	assertRecords(t, got, want)

	before := s.usage()
	if err := s.acknowledge(end); err != nil {
		t.Fatalf("acknowledge() error = %v", err)
	}
	remaining, err := listSpoolSegments(dir)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("after delivering everything the spool keeps %d segments (%v), want only the active one", len(remaining), err)
	}
	if s.usage() >= before {
		t.Fatalf("usage %d after delivery, want less than %d", s.usage(), before)
	}
}

func TestSpoolResumesFromItsCheckpointAfterReopen(t *testing.T) {
	dir := t.TempDir()
	first, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatalf("openSpool() error = %v", err)
	}
	appendRecords(t, first, `{"n":1}`, `{"n":2}`, `{"n":3}`)
	records, err := first.readBatch(first.checkpoint, 1, 1<<20)
	if err != nil || len(records) != 1 {
		t.Fatalf("readBatch() = %d records, %v", len(records), err)
	}
	if err := first.acknowledge(records[0].end); err != nil {
		t.Fatalf("acknowledge() error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened := openTestSpool(t, dir, 1<<20)
	got, _ := readAll(t, reopened, reopened.checkpoint)
	assertRecords(t, got, []string{`{"n":2}`, `{"n":3}`})

	appendRecords(t, reopened, `{"n":4}`)
	got, _ = readAll(t, reopened, reopened.checkpoint)
	assertRecords(t, got, []string{`{"n":2}`, `{"n":3}`, `{"n":4}`})
}

func TestSpoolDiscardsARecordTornByACrash(t *testing.T) {
	dir := t.TempDir()
	first, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatalf("openSpool() error = %v", err)
	}
	appendRecords(t, first, `{"n":1}`, `{"n":2}`)
	path := first.segmentPath(1)
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	// A crash in the middle of a write leaves half a record behind.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"n":3,"trunc`); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()

	reopened := openTestSpool(t, dir, 1<<20)
	appendRecords(t, reopened, `{"n":4}`)
	got, _ := readAll(t, reopened, reopened.checkpoint)
	assertRecords(t, got, []string{`{"n":1}`, `{"n":2}`, `{"n":4}`})
}

func TestSpoolRefusesRecordsOnceFull(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 400)
	record := `{"padding":"0123456789012345678901234567890123456789"}` // 55 bytes with its newline
	accepted := 0
	for {
		err := s.Append([]byte(record))
		if errors.Is(err, errSpoolFull) {
			break
		}
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
		accepted++
		if accepted > 100 {
			t.Fatal("the spool never reported itself full")
		}
	}
	if int64(accepted*(len(record)+1)) > 400 {
		t.Fatalf("accepted %d records, more than fit in 400 bytes", accepted)
	}

	// Delivering the backlog frees whole segments, and the spool accepts again.
	_, end := readAll(t, s, s.checkpoint)
	if err := s.acknowledge(end); err != nil {
		t.Fatalf("acknowledge() error = %v", err)
	}
	if err := s.Append([]byte(record)); err != nil {
		t.Fatalf("Append() after delivery error = %v", err)
	}
}

func TestSpoolReclaimsDeliveredActiveSegmentWhenFull(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		t.Run(fmt.Sprintf("reopen=%t", reopen), func(t *testing.T) {
			testSpoolReclaimsDeliveredActiveSegmentWhenFull(t, reopen)
		})
	}
}

func testSpoolReclaimsDeliveredActiveSegmentWhenFull(t *testing.T, reopen bool) {
	t.Helper()
	dir := t.TempDir()
	s := openTestSpool(t, dir, 1<<20)
	large := paddedSpoolRecord((1 << 20) - 100)
	next := paddedSpoolRecord(1024)
	appendRecords(t, s, large)
	if err := s.Append([]byte(next)); !errors.Is(err, errSpoolFull) {
		t.Fatalf("Append() before delivery = %v, want errSpoolFull", err)
	}
	_, delivered := readAll(t, s, s.checkpoint)
	if err := s.acknowledge(delivered); err != nil {
		t.Fatal(err)
	}
	if reopen {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s = openTestSpool(t, dir, 1<<20)
	}
	if err := s.Append([]byte(next)); err != nil {
		t.Fatalf("Append() after delivery = %v", err)
	}
	if got := s.usage(); got != int64(len(next)+1) {
		t.Fatalf("usage = %d, want only the pending record (%d)", got, len(next)+1)
	}
	segments, err := listSpoolSegments(dir)
	if err != nil || len(segments) != 1 || segments[0].id <= delivered.Segment {
		t.Fatalf("segments after reclamation = %v, %v; want a single successor", segments, err)
	}
	got, _ := readAll(t, s, delivered)
	assertRecords(t, got, []string{next})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestSpool(t, dir, 1<<20)
	got, _ = readAll(t, reopened, reopened.checkpoint)
	assertRecords(t, got, []string{next})
}

func paddedSpoolRecord(size int) string {
	const prefix, suffix = `{"data":"`, `"}`
	return prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
}

func TestSpoolKeepsUndeliveredActiveTailAfterCheckpoint(t *testing.T) {
	dir := t.TempDir()
	s := openTestSpool(t, dir, 1<<20)
	s.segmentSize = 1 << 20
	first := `{"n":1}`
	pending := paddedSpoolRecord((1 << 20) - len(first) - 2)
	appendRecords(t, s, first, pending)
	if err := s.acknowledge(spoolPosition{Segment: 1, Offset: int64(len(first) + 1)}); err != nil {
		t.Fatal(err)
	}
	assertFullSpoolRecord(t, s, pending)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openTestSpool(t, dir, 1<<20)
	assertFullSpoolRecord(t, reopened, pending)
	_, end := readAll(t, reopened, reopened.checkpoint)
	if err := reopened.acknowledge(end); err != nil {
		t.Fatal(err)
	}
	appendRecords(t, reopened, `{"n":3}`)
}

func assertFullSpoolRecord(t *testing.T, s *spool, pending string) {
	t.Helper()
	if err := s.Append([]byte(`{"n":3}`)); !errors.Is(err, errSpoolFull) {
		t.Fatalf("Append() with pending data = %v, want errSpoolFull", err)
	}
	if got := s.usage(); got != 1<<20 {
		t.Fatalf("full spool usage = %d, want %d", got, 1<<20)
	}
	got, _ := readAll(t, s, s.checkpoint)
	assertRecords(t, got, []string{pending})
}

func TestSpoolInvalidCheckpointsCannotReclaimPendingRecords(t *testing.T) {
	for _, test := range []struct {
		name     string
		position spoolPosition
	}{
		{name: "negative offset", position: spoolPosition{Segment: 2, Offset: -1}},
		{name: "inside a record", position: spoolPosition{Segment: 2, Offset: 1}},
		{name: "beyond segment", position: spoolPosition{Segment: 2, Offset: 301}},
		{name: "future segment", position: spoolPosition{Segment: 3}},
	} {
		t.Run(test.name, func(t *testing.T) {
			testSpoolInvalidCheckpointCannotReclaimPendingRecords(t, test.position)
		})
	}
}

func testSpoolInvalidCheckpointCannotReclaimPendingRecords(t *testing.T, position spoolPosition) {
	t.Helper()
	dir := t.TempDir()
	s := openTestSpool(t, dir, 400)
	want := []string{paddedSpoolRecord(99), paddedSpoolRecord(299)}
	appendRecords(t, s, want...)
	if err := s.acknowledge(position); err == nil {
		t.Fatal("acknowledge() accepted an invalid checkpoint")
	}
	if _, err := os.Stat(filepath.Join(dir, spoolCheckpointName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid checkpoint persisted: %v", err)
	}
	assertPendingSpoolIsFull(t, s, want)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A corrupt on-disk checkpoint must also retain all pending data.
	data, err := json.Marshal(position)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, spoolCheckpointName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := openTestSpool(t, dir, 400)
	assertPendingSpoolIsFull(t, reopened, want)
}

func assertPendingSpoolIsFull(t *testing.T, s *spool, want []string) {
	t.Helper()
	if err := s.Append([]byte(`{}`)); !errors.Is(err, errSpoolFull) {
		t.Fatalf("Append() with unconfirmed records = %v, want errSpoolFull", err)
	}
	got, _ := readAll(t, s, s.checkpoint)
	assertRecords(t, got, want)
	var size int64
	for _, record := range want {
		size += int64(len(record) + 1)
	}
	if got := s.usage(); got != size {
		t.Fatalf("usage = %d, want %d pending bytes", got, size)
	}
}

func TestSpoolCannotAcknowledgeUncommittedRecords(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 400)
	want := []string{paddedSpoolRecord(99), paddedSpoolRecord(299)}
	appendRecords(t, s, want[0])
	s.mu.Lock()
	generation, err := s.appendLocked(append([]byte(want[1]), '\n'))
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.acknowledge(spoolPosition{Segment: 2, Offset: 300}); err == nil {
		t.Fatal("acknowledge() accepted a record before its fsync completed")
	}
	if err := s.syncThrough(generation); err != nil {
		t.Fatal(err)
	}
	assertPendingSpoolIsFull(t, s, want)
}

func TestSpoolReclamationKeepsAnAppendWaitingForSync(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	large := paddedSpoolRecord((1 << 20) - 100)
	appendRecords(t, s, large)
	_, delivered := readAll(t, s, s.checkpoint)
	if err := s.acknowledge(delivered); err != nil {
		t.Fatal(err)
	}
	<-s.ready // Consume the initial append's commit notification.

	// Hold fsync back after the next append reclaims the delivered segment.
	// The rotation notification establishes when that append has run.
	s.syncMu.Lock()
	locked := true
	defer func() {
		if locked {
			s.syncMu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- s.Append([]byte(large)) }()
	select {
	case <-s.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("append did not rotate the delivered segment")
	}
	if err := s.Append([]byte(paddedSpoolRecord(1024))); !errors.Is(err, errSpoolFull) {
		t.Fatalf("Append() while another record waits for fsync = %v, want errSpoolFull", err)
	}
	s.syncMu.Unlock()
	locked = false
	if err := <-done; err != nil {
		t.Fatalf("Append() after reclamation and fsync = %v", err)
	}
	got, _ := readAll(t, s, delivered)
	assertRecords(t, got, []string{large})
}

func TestSpoolReclamationRequiresADurableSuccessor(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	large := paddedSpoolRecord((1 << 20) - 100)
	appendRecords(t, s, large)
	_, delivered := readAll(t, s, s.checkpoint)
	if err := s.acknowledge(delivered); err != nil {
		t.Fatal(err)
	}
	successor := s.segmentPath(delivered.Segment + 1)
	if err := os.Mkdir(successor, 0o700); err != nil {
		t.Fatal(err)
	}
	next := paddedSpoolRecord(1024)
	if err := s.Append([]byte(next)); err == nil {
		t.Fatal("Append() succeeded despite failing to create its successor segment")
	}
	info, err := os.Stat(s.segmentPath(delivered.Segment))
	if err != nil || info.Size() != int64(len(large)+1) || s.usage() != int64(len(large)+1) {
		t.Fatalf("failed rotation changed the delivered segment or its accounting: %v", err)
	}
	if err := os.Remove(successor); err != nil {
		t.Fatal(err)
	}
	appendRecords(t, s, next)
	got, _ := readAll(t, s, delivered)
	assertRecords(t, got, []string{next})
}

func TestSpoolDeliversEverythingAgainAfterABadCheckpoint(t *testing.T) {
	dir := t.TempDir()
	first, err := openSpool(dir, 1<<20)
	if err != nil {
		t.Fatalf("openSpool() error = %v", err)
	}
	appendRecords(t, first, `{"n":1}`, `{"n":2}`)
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	for name, checkpoint := range map[string]string{
		"garbage":           `not json`,
		"beyond the data":   `{"segment":1,"offset":999999}`,
		"a future segment":  `{"segment":42,"offset":0}`,
		"before the oldest": `{"segment":0,"offset":0}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, spoolCheckpointName), []byte(checkpoint), 0o600); err != nil {
				t.Fatal(err)
			}
			reopened := openTestSpool(t, dir, 1<<20)
			got, _ := readAll(t, reopened, reopened.checkpoint)
			assertRecords(t, got, []string{`{"n":1}`, `{"n":2}`})
			_ = reopened.Close()
		})
	}
}

func TestSpoolConcurrentAppendsAreAllKept(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 16<<20)
	s.segmentSize = 4 << 10 // rotate while writers race each other

	const writers, perWriter = 16, 50
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				if err := s.Append(fmt.Appendf(nil, `{"writer":%d,"n":%d}`, w, i)); err != nil {
					t.Errorf("Append() error = %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	got, _ := readAll(t, s, s.checkpoint)
	if len(got) != writers*perWriter {
		t.Fatalf("read back %d records, want %d", len(got), writers*perWriter)
	}
	next := make(map[int]int)
	for _, line := range got {
		var record struct{ Writer, N int }
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("record %q is not intact: %v", line, err)
		}
		if record.N != next[record.Writer] {
			t.Fatalf("writer %d: record %d read before %d", record.Writer, record.N, next[record.Writer])
		}
		next[record.Writer]++
	}
}

func TestSpoolAppendAfterCloseFails(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := s.Append([]byte(`{}`)); !errors.Is(err, errSpoolClosed) {
		t.Fatalf("Append() after Close = %v, want errSpoolClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestOpenSpoolRejectsUnusableSettings(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openSpool(filepath.Join(blocker, "spool"), 1<<20); err == nil {
		t.Error("openSpool() under a regular file succeeded, want an error")
	}
	if _, err := openSpool(t.TempDir(), 0); err == nil {
		t.Error("openSpool() with no size limit succeeded, want an error")
	}
}
