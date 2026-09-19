package spool

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/metrics"
)

// execEvent builds a normalized event of the shape the correlator produces for
// a sudo invocation, so the spool is exercised with records of a realistic
// size and structure rather than empty stubs.
//
// Every event with a single-digit sequence encodes to the same number of
// bytes, which is what lets the size-cap tests assert exact accounting.
func execEvent(seq uint64) *event.Event {
	return &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    seq,
		Timestamp:   time.Unix(1700000000+int64(seq), 123456789).UTC(),
		Type:        event.TypeUserCommand,
		Severity:    event.SeverityNotice,
		AuditID:     fmt.Sprintf("%d.123:%d", 1700000000+seq, seq),
		BootID:      "6f2a1f0c-0a1b-4c3d-9e8f-1a2b3c4d5e6f",
		PID:         event.Int(4242),
		PPID:        event.Int(1),
		UID:         event.Int(0),
		GID:         event.Int(0),
		AUID:        event.Int(1000),
		Executable:  "/usr/bin/sudo",
		Command:     "sudo -i",
		CWD:         "/home/analyst",
		Paths:       []string{"/usr/bin/sudo", "/etc/sudoers"},
		Result:      event.ResultSuccess,
		RecordTypes: []string{"SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"},
		Fields: map[string]any{
			"syscall": "execve",
			"arch":    "x86_64",
			"ses":     "3",
			"key":     "privileged",
			"subj":    "unconfined_u:unconfined_r:unconfined_t:s0",
		},
		Raw: []string{
			`type=SYSCALL msg=audit(1700000001.123:1): arch=c000003e syscall=59 success=yes exit=0 ` +
				`a0=5623f0a1b2c0 a1=5623f0a1b300 a2=5623f0a1b340 a3=8 items=2 ppid=1 pid=4242 ` +
				`auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 ` +
				`comm="sudo" exe="/usr/bin/sudo" key="privileged"`,
			`type=EXECVE msg=audit(1700000001.123:1): argc=2 a0="sudo" a1="-i"`,
			`type=CWD msg=audit(1700000001.123:1): cwd="/home/analyst"`,
		},
	}
}

func mustOpen(t *testing.T, opts Options) *Spool {
	t.Helper()
	sp, err := Open(opts)
	if err != nil {
		t.Fatalf("Open(%+v): %v", opts, err)
	}
	t.Cleanup(func() { sp.Close() })
	return sp
}

// appendRange appends events [from,to] and fails the test on any error.
func appendRange(t *testing.T, sp *Spool, from, to uint64) {
	t.Helper()
	for seq := from; seq <= to; seq++ {
		if err := sp.Append(execEvent(seq)); err != nil {
			t.Fatalf("Append(%d): %v", seq, err)
		}
	}
}

func nextSeqs(t *testing.T, sp *Spool, max int) []uint64 {
	t.Helper()
	evs, err := sp.Next(max)
	if err != nil {
		t.Fatalf("Next(%d): %v", max, err)
	}
	seqs := make([]uint64, len(evs))
	for i, e := range evs {
		if e == nil {
			t.Fatalf("Next returned a nil event at index %d", i)
		}
		seqs[i] = e.Sequence
	}
	return seqs
}

func wantSeqs(t *testing.T, got []uint64, want ...uint64) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sequences = %v, want %v", got, want)
	}
}

// recordBytes is the on-disk cost of one single-digit-sequence event,
// including its record header.
func recordBytes(t *testing.T) int64 {
	t.Helper()
	sp := mustOpen(t, Options{Dir: t.TempDir()})
	if err := sp.Append(execEvent(1)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	n := sp.Bytes()
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return n
}

func segmentFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), segmentSuffix) {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestAppendAndReadBackInOrder(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir, SyncOnWrite: true})

	want := make([]*event.Event, 0, 5)
	for seq := uint64(1); seq <= 5; seq++ {
		e := execEvent(seq)
		want = append(want, e)
		if err := sp.Append(e); err != nil {
			t.Fatalf("Append(%d): %v", seq, err)
		}
	}
	if got := sp.LastSequence(); got != 5 {
		t.Errorf("LastSequence = %d, want 5", got)
	}
	if got := sp.FirstUnacked(); got != 1 {
		t.Errorf("FirstUnacked = %d, want 1", got)
	}
	if got := sp.PendingCount(); got != 5 {
		t.Errorf("PendingCount = %d, want 5", got)
	}

	got, err := sp.Next(10)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Next returned %d events, want %d", len(got), len(want))
	}
	for i := range got {
		gotJSON, err := json.Marshal(got[i])
		if err != nil {
			t.Fatal(err)
		}
		wantJSON, err := json.Marshal(want[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("event %d round trip:\n got %s\nwant %s", i, gotJSON, wantJSON)
		}
	}
}

// Next is a read, not a consume: until an Ack arrives the same events must be
// available again, because nothing else can replay them after a failed send.
func TestNextIsIdempotent(t *testing.T) {
	sp := mustOpen(t, Options{Dir: t.TempDir()})
	appendRange(t, sp, 1, 4)

	first := nextSeqs(t, sp, 10)
	second := nextSeqs(t, sp, 10)
	wantSeqs(t, first, 1, 2, 3, 4)
	wantSeqs(t, second, 1, 2, 3, 4)

	wantSeqs(t, nextSeqs(t, sp, 2), 1, 2)
	if got := nextSeqs(t, sp, 0); len(got) != 0 {
		t.Errorf("Next(0) = %v, want nothing", got)
	}
	if got := nextSeqs(t, sp, -1); len(got) != 0 {
		t.Errorf("Next(-1) = %v, want nothing", got)
	}
}

func TestAckDiscardsPrefix(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir})
	appendRange(t, sp, 1, 6)

	if err := sp.Ack(3); err != nil {
		t.Fatalf("Ack(3): %v", err)
	}
	if got := sp.FirstUnacked(); got != 4 {
		t.Errorf("FirstUnacked = %d, want 4", got)
	}
	if got := sp.PendingCount(); got != 3 {
		t.Errorf("PendingCount = %d, want 3", got)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 4, 5, 6)

	// Acknowledging the rest empties the spool completely: the segment is the
	// unit of deletion, so the file goes away too.
	if err := sp.Ack(6); err != nil {
		t.Fatalf("Ack(6): %v", err)
	}
	if got := sp.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
	if got := sp.Bytes(); got != 0 {
		t.Errorf("Bytes = %d, want 0", got)
	}
	if got := sp.FirstUnacked(); got != 7 {
		t.Errorf("FirstUnacked = %d, want 7", got)
	}
	if got := sp.LastSequence(); got != 6 {
		t.Errorf("LastSequence = %d, want 6", got)
	}
	if names := segmentFiles(t, dir); len(names) != 0 {
		t.Errorf("segments left on disk: %v", names)
	}
	if got := nextSeqs(t, sp, 10); len(got) != 0 {
		t.Errorf("Next = %v, want nothing", got)
	}
	// Appending again after the spool drained must still move forwards.
	if err := sp.Append(execEvent(7)); err != nil {
		t.Fatalf("Append(7): %v", err)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 7)
}

func TestAckNoOps(t *testing.T) {
	tests := []struct {
		name             string
		ack              []uint64
		wantFirstUnacked uint64
		wantPending      int
	}{
		{name: "zero", ack: []uint64{0}, wantFirstUnacked: 1, wantPending: 5},
		{name: "older than the checkpoint", ack: []uint64{3, 2}, wantFirstUnacked: 4, wantPending: 2},
		{name: "repeated", ack: []uint64{3, 3, 3}, wantFirstUnacked: 4, wantPending: 2},
		{name: "unknown sequence inside a gap", ack: []uint64{4}, wantFirstUnacked: 5, wantPending: 1},
		{name: "beyond the last appended", ack: []uint64{99}, wantFirstUnacked: 6, wantPending: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp := mustOpen(t, Options{Dir: t.TempDir()})
			appendRange(t, sp, 1, 5)
			for _, seq := range tc.ack {
				if err := sp.Ack(seq); err != nil {
					t.Fatalf("Ack(%d): %v", seq, err)
				}
			}
			if got := sp.FirstUnacked(); got != tc.wantFirstUnacked {
				t.Errorf("FirstUnacked = %d, want %d", got, tc.wantFirstUnacked)
			}
			if got := sp.PendingCount(); got != tc.wantPending {
				t.Errorf("PendingCount = %d, want %d", got, tc.wantPending)
			}
			if got := sp.LastSequence(); got != 5 {
				t.Errorf("LastSequence = %d, want 5", got)
			}
			if dropped, _, _, ok := sp.DrainDropped(); ok {
				t.Errorf("DrainDropped reported %d events lost", dropped)
			}
		})
	}
}

func TestRestartPreservesSequencesAndPosition(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir, SyncOnWrite: true})
	appendRange(t, sp, 1, 6)
	if err := sp.Ack(2); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sp2 := mustOpen(t, Options{Dir: dir})
	if got := sp2.LastSequence(); got != 6 {
		t.Errorf("LastSequence after restart = %d, want 6", got)
	}
	if got := sp2.FirstUnacked(); got != 3 {
		t.Errorf("FirstUnacked after restart = %d, want 3", got)
	}
	if got := sp2.PendingCount(); got != 4 {
		t.Errorf("PendingCount after restart = %d, want 4", got)
	}
	wantSeqs(t, nextSeqs(t, sp2, 10), 3, 4, 5, 6)

	// The sequence must not go backwards across the restart.
	if err := sp2.Append(execEvent(6)); err == nil {
		t.Error("Append of an already used sequence was accepted")
	}
	if err := sp2.Append(execEvent(7)); err != nil {
		t.Fatalf("Append(7): %v", err)
	}
	if got := sp2.LastSequence(); got != 7 {
		t.Errorf("LastSequence = %d, want 7", got)
	}
}

// A spool that was drained by acknowledgements keeps no files at all, so the
// checkpoint is the only thing that can carry the sequence over a restart.
func TestRestartAfterFullAck(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir})
	appendRange(t, sp, 1, 3)
	if err := sp.Ack(3); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sp2 := mustOpen(t, Options{Dir: dir})
	if got := sp2.LastSequence(); got != 3 {
		t.Errorf("LastSequence = %d, want 3", got)
	}
	if got := sp2.FirstUnacked(); got != 4 {
		t.Errorf("FirstUnacked = %d, want 4", got)
	}
	if got := sp2.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
	if err := sp2.Append(execEvent(4)); err != nil {
		t.Fatalf("Append(4): %v", err)
	}
	wantSeqs(t, nextSeqs(t, sp2, 10), 4)
}

// Killing the agent without closing the spool is the normal case, not the
// exceptional one: the records are in the page cache and must come back.
func TestRecoverFromUncleanExit(t *testing.T) {
	dir := t.TempDir()
	sp, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	appendRange(t, sp, 1, 4)
	// No Close: the process is gone.

	sp2 := mustOpen(t, Options{Dir: dir})
	if got := sp2.LastSequence(); got != 4 {
		t.Errorf("LastSequence = %d, want 4", got)
	}
	wantSeqs(t, nextSeqs(t, sp2, 10), 1, 2, 3, 4)
}

func TestRecoverTruncatedFinalRecord(t *testing.T) {
	tests := []struct {
		name string
		// damage rewrites the segment file to simulate a crash mid-append.
		damage func(t *testing.T, path string, size int64)
	}{
		{
			name: "record cut in half",
			damage: func(t *testing.T, path string, size int64) {
				if err := os.Truncate(path, size-20); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "header only",
			damage: func(t *testing.T, path string, size int64) {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, fileMode)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.Write([]byte("SREC\x00\x00\x01\x00")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "tail of zeroes",
			damage: func(t *testing.T, path string, size int64) {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, fileMode)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if _, err := f.Write(make([]byte, 512)); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sp := mustOpen(t, Options{Dir: dir, SyncOnWrite: true})
			appendRange(t, sp, 1, 3)
			if err := sp.Close(); err != nil {
				t.Fatal(err)
			}

			names := segmentFiles(t, dir)
			if len(names) != 1 {
				t.Fatalf("segments = %v, want exactly one", names)
			}
			path := filepath.Join(dir, names[0])
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			whole := fi.Size()
			tc.damage(t, path, whole)

			sp2 := mustOpen(t, Options{Dir: dir})
			// The torn record is the one the crash interrupted; it was never
			// reported as durable, so it is not counted as a loss.
			if dropped, _, _, ok := sp2.DrainDropped(); ok {
				t.Errorf("DrainDropped reported %d events lost for a torn tail", dropped)
			}
			want := []uint64{1, 2, 3}
			if tc.name == "record cut in half" {
				want = []uint64{1, 2}
			}
			wantSeqs(t, nextSeqs(t, sp2, 10), want...)
			if got := sp2.LastSequence(); got != want[len(want)-1] {
				t.Errorf("LastSequence = %d, want %d", got, want[len(want)-1])
			}

			// The file must be clean enough to append to again.
			next := sp2.LastSequence() + 1
			if err := sp2.Append(execEvent(next)); err != nil {
				t.Fatalf("Append after recovery: %v", err)
			}
			if err := sp2.Close(); err != nil {
				t.Fatal(err)
			}
			sp3 := mustOpen(t, Options{Dir: dir})
			wantSeqs(t, nextSeqs(t, sp3, 10), append(want, next)...)
		})
	}
}

func TestRecoverCorruptRecordInTheMiddle(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir, SyncOnWrite: true})
	appendRange(t, sp, 1, 5)
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}

	names := segmentFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("segments = %v, want exactly one", names)
	}
	path := filepath.Join(dir, names[0])
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte inside the third record's payload, leaving its header and
	// therefore the framing of everything after it intact.
	rec := len(recordFor(t, 1))
	data[2*rec+recordHeaderSize+5] ^= 0xff
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatal(err)
	}

	m := &metrics.Agent{}
	sp2 := mustOpen(t, Options{Dir: dir, Metrics: m})
	dropped, first, last, ok := sp2.DrainDropped()
	if !ok {
		t.Fatal("DrainDropped reported nothing for a corrupt record")
	}
	if dropped != 1 || first != 3 || last != 3 {
		t.Errorf("DrainDropped = (%d, %d, %d), want (1, 3, 3)", dropped, first, last)
	}
	if got := m.EventsDropped.Load(); got != 1 {
		t.Errorf("EventsDropped = %d, want 1", got)
	}
	if _, _, _, ok := sp2.DrainDropped(); ok {
		t.Error("DrainDropped reported the same loss twice")
	}
	// The surviving records on both sides of the hole are still delivered.
	wantSeqs(t, nextSeqs(t, sp2, 10), 1, 2, 4, 5)
	if got := sp2.PendingCount(); got != 4 {
		t.Errorf("PendingCount = %d, want 4", got)
	}
	if got := sp2.LastSequence(); got != 5 {
		t.Errorf("LastSequence = %d, want 5", got)
	}
	// Reading again must not re-report a hole that is already accounted for.
	wantSeqs(t, nextSeqs(t, sp2, 10), 1, 2, 4, 5)
	if _, _, _, ok := sp2.DrainDropped(); ok {
		t.Error("a known hole was reported again by a second read")
	}
}

func TestSegmentRolling(t *testing.T) {
	dir := t.TempDir()
	rec := recordBytes(t)
	// Two records per segment.
	sp := mustOpen(t, Options{Dir: dir, SegmentSize: 2 * rec, MaxSize: 1 << 20})
	appendRange(t, sp, 1, 5)

	names := segmentFiles(t, dir)
	want := []string{segmentName(1), segmentName(3), segmentName(5)}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("segments = %v, want %v", names, want)
	}
	if got := sp.Bytes(); got != 5*rec {
		t.Errorf("Bytes = %d, want %d", got, 5*rec)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 1, 2, 3, 4, 5)

	// Reading across a segment boundary with a limit must not lose its place.
	wantSeqs(t, nextSeqs(t, sp, 3), 1, 2, 3)
	if err := sp.Ack(3); err != nil {
		t.Fatalf("Ack(3): %v", err)
	}
	if names := segmentFiles(t, dir); fmt.Sprint(names) != fmt.Sprint([]string{segmentName(3), segmentName(5)}) {
		t.Errorf("segments after Ack(3) = %v, want the first one deleted", names)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 4, 5)

	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	sp2 := mustOpen(t, Options{Dir: dir, SegmentSize: 2 * rec, MaxSize: 1 << 20})
	if got := sp2.FirstUnacked(); got != 4 {
		t.Errorf("FirstUnacked after restart = %d, want 4", got)
	}
	wantSeqs(t, nextSeqs(t, sp2, 10), 4, 5)
}

// An event larger than a whole segment still has to be stored: rolling first
// would otherwise loop forever or drop the event.
func TestOversizedEventGetsItsOwnSegment(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir, SegmentSize: 64, MaxSize: 1 << 20})
	appendRange(t, sp, 1, 3)
	if names := segmentFiles(t, dir); len(names) != 3 {
		t.Fatalf("segments = %v, want one per event", names)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 1, 2, 3)
}

func TestMaxSizeDropsOldest(t *testing.T) {
	dir := t.TempDir()
	rec := recordBytes(t)
	m := &metrics.Agent{}
	// One record per segment, room for three.
	sp := mustOpen(t, Options{Dir: dir, SegmentSize: rec, MaxSize: 3 * rec, Metrics: m})

	appendRange(t, sp, 1, 3)
	if _, _, _, ok := sp.DrainDropped(); ok {
		t.Fatal("DrainDropped reported a loss before the cap was exceeded")
	}
	if got := sp.Bytes(); got != 3*rec {
		t.Fatalf("Bytes = %d, want %d", got, 3*rec)
	}

	appendRange(t, sp, 4, 5)
	dropped, first, last, ok := sp.DrainDropped()
	if !ok {
		t.Fatal("DrainDropped reported nothing after the cap was exceeded")
	}
	if dropped != 2 || first != 1 || last != 2 {
		t.Errorf("DrainDropped = (%d, %d, %d), want (2, 1, 2)", dropped, first, last)
	}
	if got := m.EventsDropped.Load(); got != 2 {
		t.Errorf("EventsDropped = %d, want 2", got)
	}
	if got := sp.Bytes(); got > 3*rec {
		t.Errorf("Bytes = %d, want at most %d", got, 3*rec)
	}
	if got := sp.PendingCount(); got != 3 {
		t.Errorf("PendingCount = %d, want 3", got)
	}
	if got := sp.FirstUnacked(); got != 3 {
		t.Errorf("FirstUnacked = %d, want 3", got)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 3, 4, 5)
	if got := sp.LastSequence(); got != 5 {
		t.Errorf("LastSequence = %d, want 5", got)
	}
	if _, _, _, ok := sp.DrainDropped(); ok {
		t.Error("DrainDropped reported the same loss twice")
	}

	// The drop survives a restart as a gap, not as a hole in the counters.
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	sp2 := mustOpen(t, Options{Dir: dir, SegmentSize: rec, MaxSize: 3 * rec})
	if got := sp2.FirstUnacked(); got != 3 {
		t.Errorf("FirstUnacked after restart = %d, want 3", got)
	}
	wantSeqs(t, nextSeqs(t, sp2, 10), 3, 4, 5)
}

// Records the host has already acknowledged are not evidence loss when their
// segment is evicted, so the accounting has to exclude them.
func TestMaxSizeAccountingExcludesAckedRecords(t *testing.T) {
	dir := t.TempDir()
	rec := recordBytes(t)
	// Two records per segment, room for four.
	sp := mustOpen(t, Options{Dir: dir, SegmentSize: 2 * rec, MaxSize: 4 * rec})

	appendRange(t, sp, 1, 4)
	if err := sp.Ack(1); err != nil {
		t.Fatalf("Ack(1): %v", err)
	}
	if got := sp.PendingCount(); got != 3 {
		t.Fatalf("PendingCount = %d, want 3", got)
	}

	appendRange(t, sp, 5, 5)
	dropped, first, last, ok := sp.DrainDropped()
	if !ok {
		t.Fatal("DrainDropped reported nothing")
	}
	if dropped != 1 || first != 2 || last != 2 {
		t.Errorf("DrainDropped = (%d, %d, %d), want (1, 2, 2): sequence 1 was acknowledged",
			dropped, first, last)
	}
	if got := sp.PendingCount(); got != 3 {
		t.Errorf("PendingCount = %d, want 3", got)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 3, 4, 5)
}

func TestCorruptCheckpointFallsBackToOldestRecord(t *testing.T) {
	tests := []struct {
		name   string
		damage func(t *testing.T, path string)
	}{
		{
			name: "removed",
			damage: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncated",
			damage: func(t *testing.T, path string) {
				if err := os.Truncate(path, 8); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "sequence rewritten without fixing the checksum",
			damage: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				binary.BigEndian.PutUint64(data[4:12], 9999)
				if err := os.WriteFile(path, data, fileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "magic destroyed",
			damage: func(t *testing.T, path string) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				copy(data[0:4], []byte("....."))
				if err := os.WriteFile(path, data, fileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "empty",
			damage: func(t *testing.T, path string) {
				if err := os.WriteFile(path, nil, fileMode); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sp := mustOpen(t, Options{Dir: dir})
			appendRange(t, sp, 1, 5)
			if err := sp.Ack(3); err != nil {
				t.Fatalf("Ack(3): %v", err)
			}
			if err := sp.Close(); err != nil {
				t.Fatal(err)
			}
			tc.damage(t, filepath.Join(dir, checkpointName))

			sp2 := mustOpen(t, Options{Dir: dir})
			// Replaying delivered events is safe; skipping undelivered ones
			// is not, so the fallback is always backwards.
			if got := sp2.FirstUnacked(); got != 1 {
				t.Errorf("FirstUnacked = %d, want 1", got)
			}
			if got := sp2.PendingCount(); got != 5 {
				t.Errorf("PendingCount = %d, want 5", got)
			}
			if got := sp2.LastSequence(); got != 5 {
				t.Errorf("LastSequence = %d, want 5", got)
			}
			wantSeqs(t, nextSeqs(t, sp2, 10), 1, 2, 3, 4, 5)
			if _, _, _, ok := sp2.DrainDropped(); ok {
				t.Error("a lost checkpoint was reported as lost events")
			}
		})
	}
}

// A checkpoint that is intact but ahead of the data still has to be honoured
// for LastSequence, or a restart would reuse sequence numbers.
func TestCheckpointAheadOfRetainedData(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir})
	appendRange(t, sp, 1, 3)
	if err := sp.Ack(3); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	if names := segmentFiles(t, dir); len(names) != 0 {
		t.Fatalf("segments = %v, want none", names)
	}

	sp2 := mustOpen(t, Options{Dir: dir})
	if got := sp2.LastSequence(); got != 3 {
		t.Fatalf("LastSequence = %d, want 3", got)
	}
	if err := sp2.Append(execEvent(2)); err == nil {
		t.Error("a sequence below the checkpoint was accepted")
	}
}

func TestCheckpointIsWrittenAtomically(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir})
	appendRange(t, sp, 1, 2)
	if err := sp.Ack(1); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, checkpointName))
	if err != nil {
		t.Fatalf("reading checkpoint: %v", err)
	}
	if len(data) != checkpointSize {
		t.Fatalf("checkpoint is %d bytes, want %d", len(data), checkpointSize)
	}
	if string(data[0:4]) != string(checkpointMagic[:]) {
		t.Errorf("checkpoint magic = %q", data[0:4])
	}
	if got := binary.BigEndian.Uint64(data[4:12]); got != 1 {
		t.Errorf("checkpoint sequence = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint32(data[12:16]); got != crc32.Checksum(data[4:12], crcTable) {
		t.Error("checkpoint checksum does not cover the sequence")
	}
	if _, err := os.Stat(filepath.Join(dir, checkpointTemp)); !os.IsNotExist(err) {
		t.Error("the temporary checkpoint file was left behind")
	}
}

func TestAppendRejectsNonMonotonicSequence(t *testing.T) {
	sp := mustOpen(t, Options{Dir: t.TempDir()})
	appendRange(t, sp, 1, 3)

	for _, seq := range []uint64{0, 1, 3} {
		if err := sp.Append(execEvent(seq)); err == nil {
			t.Errorf("Append(%d) after sequence 3 was accepted", seq)
		}
	}
	if got := sp.PendingCount(); got != 3 {
		t.Errorf("PendingCount = %d, want 3: a rejected append must not store anything", got)
	}
	if got := sp.LastSequence(); got != 3 {
		t.Errorf("LastSequence = %d, want 3", got)
	}
	// A gap in the sequence is legitimate: the queue may have dropped events.
	if err := sp.Append(execEvent(99)); err != nil {
		t.Fatalf("Append(99): %v", err)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 1, 2, 3, 99)
}

func TestAppendRejectsNilAndOversizedEvents(t *testing.T) {
	dir := t.TempDir()
	sp := mustOpen(t, Options{Dir: dir})

	if err := sp.Append(nil); err == nil {
		t.Error("Append(nil) was accepted")
	}
	big := execEvent(1)
	big.Raw = []string{strings.Repeat("a", maxRecordSize+1)}
	err := sp.Append(big)
	if err == nil {
		t.Fatal("an event larger than the record ceiling was accepted")
	}
	if !strings.Contains(err.Error(), "record limit") {
		t.Errorf("error = %v, want it to name the record limit", err)
	}
	if got := sp.Bytes(); got != 0 {
		t.Errorf("Bytes = %d, want 0: the rejected event must not be stored", got)
	}
	if got := sp.LastSequence(); got != 0 {
		t.Errorf("LastSequence = %d, want 0", got)
	}
	// The spool is still usable afterwards.
	if err := sp.Append(execEvent(1)); err != nil {
		t.Fatalf("Append after a rejected event: %v", err)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 1)
}

func TestClosedSpoolRefusesWork(t *testing.T) {
	sp := mustOpen(t, Options{Dir: t.TempDir()})
	appendRange(t, sp, 1, 2)
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sp.Close(); err != nil {
		t.Errorf("second Close: %v, want nil", err)
	}
	if err := sp.Append(execEvent(3)); err == nil {
		t.Error("Append on a closed spool was accepted")
	}
	if _, err := sp.Next(1); err == nil {
		t.Error("Next on a closed spool was accepted")
	}
	if err := sp.Ack(1); err == nil {
		t.Error("Ack on a closed spool was accepted")
	}
	if err := sp.Sync(); err == nil {
		t.Error("Sync on a closed spool was accepted")
	}
	// Reading state is still safe, so a shutdown path can report it.
	if got := sp.LastSequence(); got != 2 {
		t.Errorf("LastSequence = %d, want 2", got)
	}
}

func TestOpenValidatesOptions(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Error("Open without a directory was accepted")
	}

	dir := filepath.Join(t.TempDir(), "nested", "spool")
	sp := mustOpen(t, Options{Dir: dir})
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("spool directory was not created: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != dirMode {
		t.Errorf("spool directory mode = %o, want %o", perm, dirMode)
	}
	if err := sp.Append(execEvent(1)); err != nil {
		t.Fatal(err)
	}
	names := segmentFiles(t, dir)
	if len(names) != 1 {
		t.Fatalf("segments = %v", names)
	}
	sfi, err := os.Stat(filepath.Join(dir, names[0]))
	if err != nil {
		t.Fatal(err)
	}
	if perm := sfi.Mode().Perm(); perm != fileMode {
		t.Errorf("segment mode = %o, want %o", perm, fileMode)
	}
}

// Files that are not segments must be left alone: the spool directory is not
// exclusively ours, and guessing at a name would be a way to smuggle records
// into the stream.
func TestForeignFilesAreIgnored(t *testing.T) {
	dir := t.TempDir()
	stray := filepath.Join(dir, "README")
	if err := os.WriteFile(stray, []byte("not a segment\n"), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "1.seg"), recordFor(t, 1), fileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "00000000000000000009.seg"), dirMode); err != nil {
		t.Fatal(err)
	}

	sp := mustOpen(t, Options{Dir: dir})
	if got := sp.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
	if got := sp.LastSequence(); got != 0 {
		t.Errorf("LastSequence = %d, want 0", got)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("a foreign file was removed: %v", err)
	}
}

// An empty segment is what a crash between creating a file and writing the
// first record leaves behind; it must not block the next append.
func TestEmptySegmentIsRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segmentName(1))
	if err := os.WriteFile(path, []byte("SREC"), fileMode); err != nil {
		t.Fatal(err)
	}
	sp := mustOpen(t, Options{Dir: dir})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("empty segment still present: %v", err)
	}
	if err := sp.Append(execEvent(1)); err != nil {
		t.Fatalf("Append: %v", err)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 1)
}

func TestSyncAndMetrics(t *testing.T) {
	dir := t.TempDir()
	m := &metrics.Agent{}
	sp := mustOpen(t, Options{Dir: dir, Metrics: m, SyncInterval: time.Hour})
	if err := sp.Sync(); err != nil {
		t.Fatalf("Sync on an empty spool: %v", err)
	}
	appendRange(t, sp, 1, 4)
	if err := sp.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := sp.Sync(); err != nil {
		t.Fatalf("repeated Sync: %v", err)
	}
	if got := m.SpoolEvents.Load(); got != 4 {
		t.Errorf("SpoolEvents = %d, want 4", got)
	}
	if got, want := m.SpoolBytes.Load(), sp.Bytes(); got != want {
		t.Errorf("SpoolBytes = %d, want %d", got, want)
	}
	if err := sp.Ack(4); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got := m.SpoolEvents.Load(); got != 0 {
		t.Errorf("SpoolEvents after Ack = %d, want 0", got)
	}
	if got := m.SpoolBytes.Load(); got != 0 {
		t.Errorf("SpoolBytes after Ack = %d, want 0", got)
	}
}

// The sender, the acknowledgement handler and the writer are separate
// goroutines in the agent, so the spool has to hold under all three at once.
// The invariant that matters is the one the audit trail depends on: every
// sequence that was appended is either acknowledged or still readable.
func TestConcurrentAppendNextAck(t *testing.T) {
	dir := t.TempDir()
	rec := recordBytes(t)
	sp := mustOpen(t, Options{
		Dir:          dir,
		SegmentSize:  8 * rec,
		MaxSize:      1 << 20,
		SyncInterval: 10 * time.Millisecond,
	})

	const total = 300
	var (
		assign   sync.Mutex
		nextSeq  uint64
		appended = make(chan struct{})
		wg       sync.WaitGroup
	)

	// Two writers, sharing the sequence assignment the way the sender does.
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				assign.Lock()
				if nextSeq >= total {
					assign.Unlock()
					return
				}
				nextSeq++
				seq := nextSeq
				err := sp.Append(execEvent(seq))
				assign.Unlock()
				if err != nil {
					t.Errorf("Append(%d): %v", seq, err)
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(appended)
	}()

	// One consumer: read, "send", acknowledge.
	var maxAcked uint64
	consumer := make(chan struct{})
	go func() {
		defer close(consumer)
		for {
			evs, err := sp.Next(16)
			if err != nil {
				t.Errorf("Next: %v", err)
				return
			}
			if len(evs) > 0 {
				prev := uint64(0)
				for _, e := range evs {
					if prev != 0 && e.Sequence <= prev {
						t.Errorf("Next returned %d after %d", e.Sequence, prev)
					}
					prev = e.Sequence
				}
				if evs[0].Sequence <= maxAcked {
					t.Errorf("Next returned acknowledged sequence %d (acked through %d)",
						evs[0].Sequence, maxAcked)
				}
				last := evs[len(evs)-1].Sequence
				if err := sp.Ack(last); err != nil {
					t.Errorf("Ack(%d): %v", last, err)
					return
				}
				maxAcked = last
			}
			select {
			case <-appended:
				if len(evs) == 0 {
					return
				}
			default:
			}
		}
	}()

	// Observers, to catch races on the accounting.
	var obs sync.WaitGroup
	stop := make(chan struct{})
	for range 3 {
		obs.Add(1)
		go func() {
			defer obs.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = sp.Bytes()
				_ = sp.PendingCount()
				_ = sp.LastSequence()
				_ = sp.FirstUnacked()
				if dropped, _, _, ok := sp.DrainDropped(); ok {
					t.Errorf("DrainDropped reported %d events lost", dropped)
				}
				if err := sp.Sync(); err != nil {
					t.Errorf("Sync: %v", err)
					return
				}
			}
		}()
	}

	<-consumer
	close(stop)
	obs.Wait()

	if got := sp.LastSequence(); got != total {
		t.Fatalf("LastSequence = %d, want %d", got, total)
	}
	// Whatever was not acknowledged must still be there, in order and with no
	// gaps between the acknowledgement point and the last append.
	remaining := nextSeqs(t, sp, total)
	want := make([]uint64, 0, total)
	for seq := maxAcked + 1; seq <= total; seq++ {
		want = append(want, seq)
	}
	wantSeqs(t, remaining, want...)
	if got := sp.PendingCount(); got != len(want) {
		t.Errorf("PendingCount = %d, want %d", got, len(want))
	}
}

// A record whose checksum is intact but whose payload is not an event can only
// come from someone editing the spool. It must not be able to wedge delivery
// of everything behind it, so it is skipped, counted and reported.
func TestUndecodableRecordIsSkippedAndReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segmentName(1))

	var data []byte
	data = append(data, recordFor(t, 1)...)
	data = append(data, recordFor(t, 2)...)
	data = append(data, rawRecord([]byte(`{"sequence":3,"timestamp":"the day before yesterday"}`))...)
	data = append(data, recordFor(t, 4)...)
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatal(err)
	}

	m := &metrics.Agent{}
	sp := mustOpen(t, Options{Dir: dir, Metrics: m})
	// Recovery accepts the record: its framing and checksum are valid.
	if got := sp.PendingCount(); got != 4 {
		t.Errorf("PendingCount = %d, want 4", got)
	}
	if _, _, _, ok := sp.DrainDropped(); ok {
		t.Error("recovery reported a loss for a well-framed record")
	}

	wantSeqs(t, nextSeqs(t, sp, 10), 1, 2, 4)
	dropped, first, last, ok := sp.DrainDropped()
	if !ok {
		t.Fatal("DrainDropped reported nothing for an undecodable record")
	}
	if dropped != 1 || first != 3 || last != 3 {
		t.Errorf("DrainDropped = (%d, %d, %d), want (1, 3, 3)", dropped, first, last)
	}
	if got := m.EventsDropped.Load(); got != 1 {
		t.Errorf("EventsDropped = %d, want 1", got)
	}
	// Reading again delivers the same events and reports nothing new.
	wantSeqs(t, nextSeqs(t, sp, 10), 1, 2, 4)
	if _, _, _, ok := sp.DrainDropped(); ok {
		t.Error("the same undecodable record was reported twice")
	}
	// Acknowledging past it still works.
	if err := sp.Ack(4); err != nil {
		t.Fatalf("Ack(4): %v", err)
	}
	if got := sp.PendingCount(); got != 0 {
		t.Errorf("PendingCount = %d, want 0", got)
	}
}
