package agent

import (
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/spool"
)

func numbered(seq uint64, bootID string) *event.Event {
	return &event.Event{
		Version:   event.SchemaVersion,
		Sequence:  seq,
		BootID:    bootID,
		Timestamp: time.Unix(1700000000+int64(seq), 0).UTC(),
		Type:      event.TypeProcessExec,
		Severity:  event.SeverityInfo,
	}
}

func TestSequencerIssuesIncreasingNumbers(t *testing.T) {
	s := newSequencer(1, "boot-a")
	for want := uint64(1); want <= 5; want++ {
		e := &event.Event{Type: event.TypeProcessExec}
		if got := s.assign(e); got != want {
			t.Fatalf("assign #%d returned %d, want %d", want, got, want)
		}
		if e.Sequence != want {
			t.Errorf("event sequence = %d, want %d", e.Sequence, want)
		}
		if e.BootID != "boot-a" {
			t.Errorf("event boot_id = %q, want boot-a", e.BootID)
		}
	}
	if got := s.peek(); got != 6 {
		t.Errorf("peek = %d, want 6", got)
	}
}

// Sequence 0 means "no sequence" on the wire and must never be issued, however
// the sequencer was started.
func TestSequencerNeverIssuesZero(t *testing.T) {
	s := newSequencer(0, "boot-a")
	e := &event.Event{Type: event.TypeSystemSecurity}
	if got := s.assign(e); got != 1 {
		t.Errorf("assign on a zero-started sequencer returned %d, want 1", got)
	}
}

// An event that already carries a sequence has been numbered once. Renumbering
// it would break the (boot id, sequence) identity the host deduplicates on.
func TestSequencerLeavesNumberedEventsAlone(t *testing.T) {
	s := newSequencer(10, "boot-new")

	replayed := numbered(4, "boot-old")
	if got := s.assign(replayed); got != 4 {
		t.Errorf("assign renumbered a replayed event to %d, want 4", got)
	}
	if replayed.BootID != "boot-old" {
		t.Errorf("assign rewrote the boot id to %q; a replayed event belongs to the boot it was created in",
			replayed.BootID)
	}
	if got := s.peek(); got != 10 {
		t.Errorf("peek = %d: a pre-numbered event must not consume a sequence", got)
	}

	// An event of this boot that arrives without a boot id gets this one.
	fresh := &event.Event{Type: event.TypeProcessExec}
	if got := s.assign(fresh); got != 10 {
		t.Errorf("assign = %d, want 10", got)
	}
	if fresh.BootID != "boot-new" {
		t.Errorf("boot_id = %q, want boot-new", fresh.BootID)
	}
}

// After a restart within one boot the numbering continues above whatever the
// spool still holds. Reissuing a number the host has already seen used for a
// different event would make its deduplication discard real evidence.
func TestSequencerResumesAboveSpool(t *testing.T) {
	dir := t.TempDir()
	opts := spool.Options{Dir: dir, MaxSize: 1 << 20, SegmentSize: 64 << 10, SyncOnWrite: true}

	sp, err := spool.Open(opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s := newSequencer(sp.LastSequence()+1, "boot-a")
	for i := 0; i < 7; i++ {
		e := &event.Event{Type: event.TypeProcessExec}
		s.assign(e)
		if err := sp.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	// Acknowledging everything empties the spool; LastSequence survives it,
	// which is the case a naive "highest event on disk" would get wrong.
	if err := sp.Ack(7); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := sp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := spool.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if got := reopened.LastSequence(); got != 7 {
		t.Fatalf("LastSequence after reopen = %d, want 7", got)
	}

	resumed := newSequencer(reopened.LastSequence()+1, "boot-a")
	e := &event.Event{Type: event.TypeProcessExec}
	if got := resumed.assign(e); got != 8 {
		t.Errorf("first sequence after restart = %d, want 8", got)
	}
	// The spool accepts it, which it would not if numbering had gone
	// backwards.
	if err := reopened.Append(e); err != nil {
		t.Errorf("Append after restart: %v", err)
	}
}

func TestSequencerIsConcurrencySafe(t *testing.T) {
	const (
		writers = 8
		each    = 250
	)
	s := newSequencer(1, "boot-a")

	var (
		mu   sync.Mutex
		seen = make(map[uint64]bool, writers*each)
		wg   sync.WaitGroup
	)
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			local := make([]uint64, 0, each)
			for range each {
				local = append(local, s.assign(&event.Event{Type: event.TypeProcessExec}))
			}
			mu.Lock()
			defer mu.Unlock()
			for _, seq := range local {
				if seen[seq] {
					t.Errorf("sequence %d was issued twice", seq)
				}
				seen[seq] = true
			}
		}()
	}
	wg.Wait()

	if len(seen) != writers*each {
		t.Fatalf("got %d distinct sequences, want %d", len(seen), writers*each)
	}
	for seq := uint64(1); seq <= writers*each; seq++ {
		if !seen[seq] {
			t.Fatalf("sequence %d was never issued: the numbering has a hole", seq)
		}
	}
	if got := s.peek(); got != writers*each+1 {
		t.Errorf("peek = %d, want %d", got, writers*each+1)
	}
}

// advanceTo is how the agent answers a host that turns out to be ahead of it
// for this boot id: the numbering continues from the host's position instead
// of colliding with numbers it already holds. It must never move backwards,
// because the spool refuses a sequence that is not greater than the last one
// it stored and because a cumulative ACK over reused numbers would cover two
// different events at once.
func TestSequencerAdvanceTo(t *testing.T) {
	s := newSequencer(1, "boot-a")

	first := &event.Event{Type: event.TypeProcessExec}
	if got := s.assign(first); got != 1 {
		t.Fatalf("first assign = %d, want 1", got)
	}

	if got := s.advanceTo(1001); got != 1001 {
		t.Errorf("advanceTo(1001) = %d, want 1001", got)
	}
	next := &event.Event{Type: event.TypeProcessExec}
	if got := s.assign(next); got != 1001 {
		t.Errorf("assign after the lift = %d, want 1001", got)
	}

	// A position at or below where numbering already is changes nothing: a
	// second READY carrying the same resume_from, or a late ACK, must not
	// reissue numbers that are already in use.
	if got := s.advanceTo(500); got != 1002 {
		t.Errorf("advanceTo(500) = %d, want the counter left at 1002", got)
	}
	if got := s.peek(); got != 1002 {
		t.Errorf("peek = %d, want 1002", got)
	}

	// Zero is never issued, whatever it is asked for.
	empty := newSequencer(1, "boot-a")
	if got := empty.advanceTo(0); got != 1 {
		t.Errorf("advanceTo(0) = %d, want 1", got)
	}
}
