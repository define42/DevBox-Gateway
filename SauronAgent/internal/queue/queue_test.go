package queue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/metrics"
)

const testBootID = "6f2b4a1c-9d3e-4c7a-8b15-2f0d9a7c4e11"

// Realistic normalized events, of the shapes the correlator and normalizer
// actually produce, so that the tests exercise the sequence accounting against
// data with the same identity fields the agent ships.
func execEvent(seq uint64) *event.Event {
	return &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    seq,
		Timestamp:   time.Unix(1716203045, 123000000).UTC(),
		Type:        event.TypeProcessExec,
		Severity:    event.SeverityNotice,
		AuditID:     fmt.Sprintf("1716203045.123:%d", 4000+seq),
		BootID:      testBootID,
		PID:         event.Int(2941),
		PPID:        event.Int(2870),
		UID:         event.Int(0),
		GID:         event.Int(0),
		AUID:        event.Int(1000),
		Executable:  "/usr/bin/sudo",
		Command:     "sudo cat /etc/shadow",
		CWD:         "/home/alice",
		Paths:       []string{"/usr/bin/sudo", "/etc/shadow"},
		Result:      event.ResultSuccess,
		RecordTypes: []string{"SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"},
	}
}

func fileEvent(seq uint64) *event.Event {
	return &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    seq,
		Timestamp:   time.Unix(1716203046, 887000000).UTC(),
		Type:        event.TypeFileModify,
		Severity:    event.SeverityWarning,
		AuditID:     fmt.Sprintf("1716203046.887:%d", 4000+seq),
		BootID:      testBootID,
		PID:         event.Int(2955),
		UID:         event.Int(1000),
		GID:         event.Int(1000),
		AUID:        event.Int(1000),
		Executable:  "/usr/bin/vim",
		Command:     "vim /etc/ssh/sshd_config",
		CWD:         "/etc/ssh",
		Paths:       []string{"/etc/ssh/sshd_config"},
		Result:      event.ResultSuccess,
		RecordTypes: []string{"SYSCALL", "CWD", "PATH"},
	}
}

func auditConfigEvent(seq uint64) *event.Event {
	// A CONFIG_CHANGE from auditctl: no login uid, hence no AUID, which is
	// exactly how the normalizer renders AUIDUnset.
	e := &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    seq,
		Timestamp:   time.Unix(1716203050, 4000000).UTC(),
		Type:        event.TypeAuditConfiguration,
		Severity:    event.SeverityCritical,
		AuditID:     fmt.Sprintf("1716203050.004:%d", 4000+seq),
		BootID:      testBootID,
		PID:         event.Int(1),
		UID:         event.Int(0),
		Executable:  "/usr/sbin/auditctl",
		Result:      event.ResultSuccess,
		RecordTypes: []string{"CONFIG_CHANGE"},
	}
	e.SetField("op", "set")
	e.SetField("audit_enabled", 0)
	return e
}

// sampleEvent cycles through the shapes so a batch is not uniform.
func sampleEvent(seq uint64) *event.Event {
	switch seq % 3 {
	case 0:
		return auditConfigEvent(seq)
	case 1:
		return execEvent(seq)
	default:
		return fileEvent(seq)
	}
}

func drainSequences(t *testing.T, q *Queue) []uint64 {
	t.Helper()
	var got []uint64
	for {
		e, ok := q.TryGet()
		if !ok {
			return got
		}
		if e == nil {
			t.Fatal("TryGet reported an event but returned nil")
		}
		got = append(got, e.Sequence)
	}
}

func TestNewCapacity(t *testing.T) {
	tests := []struct {
		name     string
		capacity int
		want     int
	}{
		{name: "explicit", capacity: 7, want: 7},
		{name: "one", capacity: 1, want: 1},
		{name: "zero falls back", capacity: 0, want: defaultCapacity},
		{name: "negative falls back", capacity: -5, want: defaultCapacity},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := New(Options{Capacity: tc.capacity})
			if got := q.Cap(); got != tc.want {
				t.Fatalf("Cap() = %d, want %d", got, tc.want)
			}
			if got := q.Len(); got != 0 {
				t.Fatalf("Len() on a fresh queue = %d, want 0", got)
			}
		})
	}
}

func TestPutGetFIFO(t *testing.T) {
	q := New(Options{Capacity: 8})

	for seq := uint64(1); seq <= 5; seq++ {
		if dropped := q.Put(sampleEvent(seq)); dropped != 0 {
			t.Fatalf("Put(seq=%d) dropped %d events with room to spare", seq, dropped)
		}
	}
	if got := q.Len(); got != 5 {
		t.Fatalf("Len() = %d, want 5", got)
	}

	got := drainSequences(t, q)
	want := []uint64{1, 2, 3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("drained %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("drained %v, want %v (FIFO order)", got, want)
		}
	}
	if _, _, _, ok := q.DrainOverflow(); ok {
		t.Fatal("DrainOverflow reported a loss on a queue that never overflowed")
	}
	if got := q.Len(); got != 0 {
		t.Fatalf("Len() after drain = %d, want 0", got)
	}
}

func TestPutNilIgnored(t *testing.T) {
	q := New(Options{Capacity: 4})
	if dropped := q.Put(nil); dropped != 0 {
		t.Fatalf("Put(nil) = %d, want 0", dropped)
	}
	if got := q.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0 after Put(nil)", got)
	}
	if _, ok := q.TryGet(); ok {
		t.Fatal("TryGet returned an event after Put(nil)")
	}
}

func TestOverflowDropsOldestWithAccounting(t *testing.T) {
	tests := []struct {
		name         string
		capacity     int
		produce      uint64 // sequences 1..produce
		wantDropped  uint64
		wantFirst    uint64
		wantLast     uint64
		wantOverflow bool
		wantRetained []uint64
	}{
		{
			name:         "exactly full never drops",
			capacity:     4,
			produce:      4,
			wantRetained: []uint64{1, 2, 3, 4},
		},
		{
			name:         "one over",
			capacity:     4,
			produce:      5,
			wantDropped:  1,
			wantFirst:    1,
			wantLast:     1,
			wantOverflow: true,
			wantRetained: []uint64{2, 3, 4, 5},
		},
		{
			name:         "many over",
			capacity:     4,
			produce:      10,
			wantDropped:  6,
			wantFirst:    1,
			wantLast:     6,
			wantOverflow: true,
			wantRetained: []uint64{7, 8, 9, 10},
		},
		{
			name:         "capacity one keeps only the newest",
			capacity:     1,
			produce:      6,
			wantDropped:  5,
			wantFirst:    1,
			wantLast:     5,
			wantOverflow: true,
			wantRetained: []uint64{6},
		},
		{
			name:         "wraps the ring several times",
			capacity:     3,
			produce:      31,
			wantDropped:  28,
			wantFirst:    1,
			wantLast:     28,
			wantOverflow: true,
			wantRetained: []uint64{29, 30, 31},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &metrics.Agent{}
			q := New(Options{Capacity: tc.capacity, Metrics: m})

			var totalDropped int
			for seq := uint64(1); seq <= tc.produce; seq++ {
				dropped := q.Put(sampleEvent(seq))
				if seq <= uint64(tc.capacity) && dropped != 0 {
					t.Fatalf("Put(seq=%d) dropped %d before the queue was full", seq, dropped)
				}
				if seq > uint64(tc.capacity) && dropped != 1 {
					t.Fatalf("Put(seq=%d) = %d, want exactly 1 drop on a full queue", seq, dropped)
				}
				totalDropped += dropped
			}

			if got, want := uint64(totalDropped), tc.wantDropped; got != want {
				t.Fatalf("Put reported %d drops in total, want %d", got, want)
			}
			if got := q.Len(); got != len(tc.wantRetained) {
				t.Fatalf("Len() = %d, want %d", got, len(tc.wantRetained))
			}

			dropped, first, last, ok := q.DrainOverflow()
			if ok != tc.wantOverflow {
				t.Fatalf("DrainOverflow ok = %v, want %v", ok, tc.wantOverflow)
			}
			if dropped != tc.wantDropped || first != tc.wantFirst || last != tc.wantLast {
				t.Fatalf("DrainOverflow = (%d, %d, %d), want (%d, %d, %d)",
					dropped, first, last, tc.wantDropped, tc.wantFirst, tc.wantLast)
			}

			got := drainSequences(t, q)
			if len(got) != len(tc.wantRetained) {
				t.Fatalf("retained %v, want %v", got, tc.wantRetained)
			}
			for i := range tc.wantRetained {
				if got[i] != tc.wantRetained[i] {
					t.Fatalf("retained %v, want %v (oldest dropped first, FIFO out)", got, tc.wantRetained)
				}
			}

			if got := m.EventsDropped.Load(); got != tc.wantDropped {
				t.Fatalf("metrics.EventsDropped = %d, want %d", got, tc.wantDropped)
			}
			if got := m.QueueDepth.Load(); got != 0 {
				t.Fatalf("metrics.QueueDepth after drain = %d, want 0", got)
			}
		})
	}
}

func TestDrainOverflowClearsAndAccumulates(t *testing.T) {
	q := New(Options{Capacity: 2})

	for seq := uint64(1); seq <= 5; seq++ {
		q.Put(execEvent(seq))
	}
	dropped, first, last, ok := q.DrainOverflow()
	if !ok || dropped != 3 || first != 1 || last != 3 {
		t.Fatalf("first DrainOverflow = (%d, %d, %d, %v), want (3, 1, 3, true)", dropped, first, last, ok)
	}

	// Cleared: a second call must not repeat a loss the caller already
	// reported, or the host would see phantom overflow events.
	if dropped, first, last, ok := q.DrainOverflow(); ok || dropped != 0 || first != 0 || last != 0 {
		t.Fatalf("second DrainOverflow = (%d, %d, %d, %v), want (0, 0, 0, false)", dropped, first, last, ok)
	}

	// A fresh overflow starts a new range rather than extending the old one.
	for seq := uint64(6); seq <= 9; seq++ {
		q.Put(execEvent(seq))
	}
	dropped, first, last, ok = q.DrainOverflow()
	if !ok || dropped != 4 || first != 4 || last != 7 {
		t.Fatalf("third DrainOverflow = (%d, %d, %d, %v), want (4, 4, 7, true)", dropped, first, last, ok)
	}
}

func TestDrainOverflowExcludesUnsequencedEvents(t *testing.T) {
	// Sequences are assigned before the queue (DESIGN.md section 20), so a
	// zero here is a bug upstream; it must still be counted, but must not pull
	// firstMissing down to 0 and tell the host the whole stream is missing.
	q := New(Options{Capacity: 1})
	q.Put(execEvent(0))
	q.Put(execEvent(41))
	q.Put(execEvent(42))

	dropped, first, last, ok := q.DrainOverflow()
	if !ok || dropped != 2 {
		t.Fatalf("DrainOverflow = (%d, _, _, %v), want (2, true)", dropped, ok)
	}
	if first != 41 || last != 41 {
		t.Fatalf("DrainOverflow range = (%d, %d), want (41, 41)", first, last)
	}
}

func TestGetBlocksUntilPut(t *testing.T) {
	q := New(Options{Capacity: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		e   *event.Event
		err error
	}
	done := make(chan result, 1)
	go func() {
		e, err := q.Get(ctx)
		done <- result{e, err}
	}()

	select {
	case r := <-done:
		t.Fatalf("Get returned (%v, %v) on an empty queue instead of blocking", r.e, r.err)
	case <-time.After(50 * time.Millisecond):
	}

	q.Put(execEvent(77))

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Get after Put returned error %v", r.err)
		}
		if r.e == nil || r.e.Sequence != 77 {
			t.Fatalf("Get returned %+v, want the event with sequence 77", r.e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Get did not wake up after Put")
	}
}

func TestGetHonoursContext(t *testing.T) {
	t.Run("cancelled while waiting", func(t *testing.T) {
		q := New(Options{Capacity: 4})
		ctx, cancel := context.WithCancel(context.Background())

		errCh := make(chan error, 1)
		go func() {
			_, err := q.Get(ctx)
			errCh <- err
		}()

		select {
		case err := <-errCh:
			t.Fatalf("Get returned %v before cancellation", err)
		case <-time.After(50 * time.Millisecond):
		}

		cancel()
		select {
		case err := <-errCh:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Get returned %v, want context.Canceled", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Get did not return after the context was cancelled")
		}
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		q := New(Options{Capacity: 4})
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		start := time.Now()
		if _, err := q.Get(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Get returned %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
			t.Fatalf("Get returned after %v, well before the deadline", elapsed)
		}
	})

	t.Run("already cancelled beats a queued event", func(t *testing.T) {
		q := New(Options{Capacity: 4})
		q.Put(execEvent(9))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := q.Get(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Get returned %v, want context.Canceled", err)
		}
		// The event is not consumed by the failed Get: it is still drainable.
		if e, ok := q.TryGet(); !ok || e.Sequence != 9 {
			t.Fatalf("TryGet = (%v, %v), want the event with sequence 9", e, ok)
		}
	})
}

func TestCloseDrainsThenReportsErrClosed(t *testing.T) {
	q := New(Options{Capacity: 8})
	for seq := uint64(1); seq <= 3; seq++ {
		q.Put(sampleEvent(seq))
	}
	q.Close()
	q.Close() // idempotent

	ctx := context.Background()
	for seq := uint64(1); seq <= 3; seq++ {
		e, err := q.Get(ctx)
		if err != nil {
			t.Fatalf("Get after Close returned %v, want the queued event %d", err, seq)
		}
		if e.Sequence != seq {
			t.Fatalf("Get returned sequence %d, want %d", e.Sequence, seq)
		}
	}

	if _, err := q.Get(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("Get on a drained closed queue returned %v, want ErrClosed", err)
	}
	if _, ok := q.TryGet(); ok {
		t.Fatal("TryGet returned an event from a drained closed queue")
	}
}

func TestCloseWakesParkedConsumer(t *testing.T) {
	q := New(Options{Capacity: 4})
	errCh := make(chan error, 1)
	go func() {
		_, err := q.Get(context.Background())
		errCh <- err
	}()

	select {
	case err := <-errCh:
		t.Fatalf("Get returned %v before Close", err)
	case <-time.After(50 * time.Millisecond):
	}

	q.Close()
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Get returned %v after Close, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wake the parked consumer")
	}
}

func TestPutAfterCloseIsAccountedNotSilent(t *testing.T) {
	m := &metrics.Agent{}
	q := New(Options{Capacity: 4, Metrics: m})
	q.Put(execEvent(1))
	q.Close()

	if dropped := q.Put(execEvent(2)); dropped != 1 {
		t.Fatalf("Put after Close = %d, want 1 (the event is lost and must be counted)", dropped)
	}
	if dropped := q.Put(execEvent(5)); dropped != 1 {
		t.Fatalf("second Put after Close = %d, want 1", dropped)
	}
	if got := q.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1: Close must not discard the backlog nor accept new events", got)
	}

	dropped, first, last, ok := q.DrainOverflow()
	if !ok || dropped != 2 || first != 2 || last != 5 {
		t.Fatalf("DrainOverflow = (%d, %d, %d, %v), want (2, 2, 5, true)", dropped, first, last, ok)
	}
	if got := m.EventsDropped.Load(); got != 2 {
		t.Fatalf("metrics.EventsDropped = %d, want 2", got)
	}

	e, err := q.Get(context.Background())
	if err != nil || e.Sequence != 1 {
		t.Fatalf("Get = (%v, %v), want the event queued before Close", e, err)
	}
}

func TestMetricsTrackDepth(t *testing.T) {
	m := &metrics.Agent{}
	q := New(Options{Capacity: 3, Metrics: m})

	for seq := uint64(1); seq <= 3; seq++ {
		q.Put(sampleEvent(seq))
		if got, want := m.QueueDepth.Load(), int64(seq); got != want {
			t.Fatalf("QueueDepth after %d puts = %d, want %d", seq, got, want)
		}
	}

	// Overflow keeps the queue full and only moves the drop counter.
	q.Put(sampleEvent(4))
	if got := m.QueueDepth.Load(); got != 3 {
		t.Fatalf("QueueDepth after overflow = %d, want 3", got)
	}
	if got := m.EventsDropped.Load(); got != 1 {
		t.Fatalf("EventsDropped = %d, want 1", got)
	}

	if _, ok := q.TryGet(); !ok {
		t.Fatal("TryGet found nothing on a full queue")
	}
	if got := m.QueueDepth.Load(); got != 2 {
		t.Fatalf("QueueDepth after TryGet = %d, want 2", got)
	}
	if _, err := q.Get(context.Background()); err != nil {
		t.Fatalf("Get returned %v", err)
	}
	if got := m.QueueDepth.Load(); got != 1 {
		t.Fatalf("QueueDepth after Get = %d, want 1", got)
	}
}

func TestNilMetricsIsUsable(t *testing.T) {
	q := New(Options{Capacity: 1})
	q.Put(execEvent(1))
	if dropped := q.Put(execEvent(2)); dropped != 1 {
		t.Fatalf("Put = %d, want 1", dropped)
	}
	if _, ok := q.TryGet(); !ok {
		t.Fatal("TryGet found nothing")
	}
}

// TestConcurrentProducersConsumers checks the invariant that matters
// operationally: every event a producer handed over was either delivered
// exactly once or counted as dropped. Nothing may vanish unaccounted for.
func TestConcurrentProducersConsumers(t *testing.T) {
	const (
		producers     = 8
		perProducer   = 2000
		consumers     = 4
		capacity      = 64
		totalProduced = producers * perProducer
	)

	m := &metrics.Agent{}
	q := New(Options{Capacity: capacity, Metrics: m})

	var putMu sync.Mutex
	var putDropped uint64

	var prodWG sync.WaitGroup
	for p := 0; p < producers; p++ {
		prodWG.Add(1)
		go func(p int) {
			defer prodWG.Done()
			local := 0
			for i := 0; i < perProducer; i++ {
				// Globally unique sequences, as the sequencer guarantees.
				seq := uint64(p*perProducer+i) + 1
				local += q.Put(sampleEvent(seq))
			}
			putMu.Lock()
			putDropped += uint64(local)
			putMu.Unlock()
		}(p)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	received := make([][]uint64, consumers)
	var consWG sync.WaitGroup
	for c := 0; c < consumers; c++ {
		consWG.Add(1)
		go func(c int) {
			defer consWG.Done()
			for {
				e, err := q.Get(ctx)
				if err != nil {
					if !errors.Is(err, ErrClosed) {
						t.Errorf("consumer %d: Get returned %v, want ErrClosed", c, err)
					}
					return
				}
				received[c] = append(received[c], e.Sequence)
			}
		}(c)
	}

	// Drain the overflow accounting while the load runs, the way the agent
	// does when it turns losses into sauron.queue.overflow events.
	var accountedDropped uint64
	stopAccounting := make(chan struct{})
	accountingDone := make(chan struct{})
	go func() {
		defer close(accountingDone)
		for {
			dropped, first, last, ok := q.DrainOverflow()
			if ok {
				if dropped == 0 || first == 0 || last == 0 || first > last {
					t.Errorf("DrainOverflow = (%d, %d, %d): incoherent loss range", dropped, first, last)
				}
				accountedDropped += dropped
			}
			select {
			case <-stopAccounting:
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()

	prodWG.Wait()
	q.Close()
	consWG.Wait()
	close(stopAccounting)
	<-accountingDone

	// Whatever the periodic drain missed on its last pass.
	if dropped, _, _, ok := q.DrainOverflow(); ok {
		accountedDropped += dropped
	}

	seen := make(map[uint64]bool, totalProduced)
	totalReceived := 0
	for _, seqs := range received {
		for _, s := range seqs {
			if seen[s] {
				t.Fatalf("sequence %d was delivered twice", s)
			}
			seen[s] = true
			totalReceived++
		}
	}

	if putDropped != accountedDropped {
		t.Fatalf("Put reported %d drops, DrainOverflow accounted for %d", putDropped, accountedDropped)
	}
	if got := uint64(totalReceived) + accountedDropped; got != totalProduced {
		t.Fatalf("received %d + dropped %d = %d, want %d produced",
			totalReceived, accountedDropped, got, totalProduced)
	}
	if got := m.EventsDropped.Load(); got != accountedDropped {
		t.Fatalf("metrics.EventsDropped = %d, want %d", got, accountedDropped)
	}
	if got := m.QueueDepth.Load(); got != 0 {
		t.Fatalf("metrics.QueueDepth = %d, want 0 after everything drained", got)
	}
	if got := q.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0 after everything drained", got)
	}
}
