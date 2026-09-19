// Package queue is the bounded hand-off between event collection and
// delivery.
//
// The netlink reader must never be made to wait on the host: a stalled or
// disconnected collector would otherwise back-pressure all the way into the
// kernel's audit backlog, where the loss is invisible to SauronAgent and, on a
// system with audit failure mode 2, can take the guest down with it. So the
// queue is fixed-capacity and Put never blocks. Under sustained overload
// events are lost here on purpose -- but never quietly: every loss is counted
// and its sequence range retained so the caller can emit
// sauron.queue.overflow (DESIGN.md sections 18-22 and 40).
package queue

import (
	"context"
	"errors"
	"sync"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/metrics"
)

// ErrClosed is returned by Get once the queue has been closed and every event
// it still held has been handed out. It is the consumer's end-of-stream
// signal, and is distinct from a context error so that a shutdown can be told
// apart from a cancelled wait.
var ErrClosed = errors.New("queue: closed")

// defaultCapacity is used when Options.Capacity is not positive. A queue with
// no room would drop every event it is given, which is exactly the silent
// failure this package exists to prevent, so a misconfigured capacity falls
// back to the documented default instead (config.QueueSection defaults to the
// same value).
const defaultCapacity = 10000

// Options configures a Queue.
type Options struct {
	// Capacity is the maximum number of events held in memory. Values that
	// are not positive select the default.
	Capacity int

	// Metrics, when non-nil, receives queue depth and drop counts.
	Metrics *metrics.Agent
}

// Queue is a fixed-capacity FIFO ring of events, safe for any number of
// concurrent producers and consumers.
//
// Events reach the queue after normalization and sequence assignment
// (DESIGN.md section 20), so every event in it carries a non-zero
// Event.Sequence and a drop can be reported as a precise range of missing
// sequence numbers.
type Queue struct {
	mu   sync.Mutex
	buf  []*event.Event
	head int // index of the oldest event
	n    int // events currently held

	closed bool

	// notify is closed to wake parked consumers and then replaced. Waking is
	// a broadcast rather than a hand-off because the queue state itself is the
	// condition: a woken consumer re-checks it under the lock. A buffered
	// "signal" channel would lose wakeups when several consumers park and
	// several producers fire between two wakeups.
	notify chan struct{}
	// waiters counts parked consumers so that the common case -- Put on the
	// netlink hot path with no consumer parked -- costs no channel allocation.
	waiters int

	// Overflow accounting since the last DrainOverflow. Losing events under
	// extreme load is acceptable; losing them without being able to say which
	// ones is not, and this is the whole mechanism that prevents it.
	dropped      uint64
	firstMissing uint64
	lastMissing  uint64

	metrics *metrics.Agent
}

// New returns an empty queue.
func New(opts Options) *Queue {
	capacity := opts.Capacity
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &Queue{
		buf:     make([]*event.Event, capacity),
		notify:  make(chan struct{}),
		metrics: opts.Metrics,
	}
}

// Put appends e and returns how many events this call dropped to make room.
// It never blocks.
//
// When the queue is full the OLDEST event is dropped. Dropping the newest
// instead would be wrong twice over. First, an agent that stops reporting
// current activity while holding stale history is useless for detection
// precisely when it matters -- the events arriving during an overload are the
// ones describing what is happening now. Second, dropping from the head keeps
// the retained events a contiguous suffix of the sequence space, so the loss
// is exactly describable as "everything from firstMissing to lastMissing";
// dropping newest would scatter the gaps and make that range a lie.
//
// The queue takes ownership of e: a producer must not mutate an event after
// handing it over. A nil event is ignored and reported as no drop, since there
// is no telemetry to lose and a nil in the ring would break Get's contract.
//
// After Close, Put stores nothing but still counts the event as dropped, so
// that events produced during a racing shutdown appear in the overflow
// accounting rather than vanishing.
func (q *Queue) Put(e *event.Event) (dropped int) {
	if e == nil {
		return 0
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		q.recordDropLocked(e)
		return 1
	}

	if q.n == len(q.buf) {
		oldest := q.buf[q.head]
		q.buf[q.head] = nil
		q.head = (q.head + 1) % len(q.buf)
		q.n--
		q.recordDropLocked(oldest)
		dropped = 1
	}

	q.buf[(q.head+q.n)%len(q.buf)] = e
	q.n++
	q.wakeLocked()
	q.updateDepthLocked()
	return dropped
}

// Get returns the oldest event, blocking until one is available, the queue is
// closed and drained, or ctx is done.
//
// It returns ErrClosed once a closed queue is empty, and ctx.Err() if ctx ends
// first. A context that is already done wins over an available event: a
// consumer loop driven by a cancelled context must terminate, and a caller
// that wants to empty a cancelled queue uses TryGet.
func (q *Queue) Get(ctx context.Context) (*event.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for {
		q.mu.Lock()
		if e, ok := q.popLocked(); ok {
			q.mu.Unlock()
			return e, nil
		}
		if q.closed {
			q.mu.Unlock()
			return nil, ErrClosed
		}
		wait := q.notify
		q.waiters++
		q.mu.Unlock()

		select {
		case <-wait:
			q.mu.Lock()
			q.waiters--
			q.mu.Unlock()
		case <-ctx.Done():
			q.mu.Lock()
			q.waiters--
			q.mu.Unlock()
			return nil, ctx.Err()
		}
	}
}

// TryGet returns the oldest event without blocking, reporting whether one was
// available. It keeps working on a closed queue until the backlog is drained.
func (q *Queue) TryGet() (*event.Event, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.popLocked()
}

// Len returns the number of events currently held.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// Cap returns the maximum number of events the queue can hold.
func (q *Queue) Cap() int {
	// The ring is allocated once in New and never resized, so this needs no
	// lock and stays callable from a metrics path that must not contend with
	// the producer.
	return len(q.buf)
}

// DrainOverflow returns and clears the accumulated overflow accounting:
// how many events were dropped since the last call, and the lowest and
// highest sequence numbers among them. ok is false when nothing was dropped,
// which is the caller's signal that no sauron.queue.overflow event is due.
//
// A dropped event that somehow carried no sequence number is still counted but
// left out of the range, because folding a zero into it would tell the host
// that sequences from 0 onwards are missing.
func (q *Queue) DrainOverflow() (dropped uint64, firstMissing, lastMissing uint64, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.dropped == 0 {
		return 0, 0, 0, false
	}
	dropped, firstMissing, lastMissing = q.dropped, q.firstMissing, q.lastMissing
	q.dropped, q.firstMissing, q.lastMissing = 0, 0, 0
	return dropped, firstMissing, lastMissing, true
}

// Close stops further Puts from being stored and wakes every parked consumer.
//
// Events already queued stay drainable: Close means "no more producers", not
// "discard the backlog", so a shutdown can still flush what was collected into
// the spool. Get reports ErrClosed only once the backlog is gone. Close is
// idempotent.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	// Wake unconditionally: a consumer parked before Close must learn about it
	// even though no event was added.
	close(q.notify)
	q.notify = make(chan struct{})
}

// popLocked removes and returns the oldest event. q.mu must be held.
func (q *Queue) popLocked() (*event.Event, bool) {
	if q.n == 0 {
		return nil, false
	}
	e := q.buf[q.head]
	q.buf[q.head] = nil // release the reference so the event can be collected
	q.head = (q.head + 1) % len(q.buf)
	q.n--
	q.updateDepthLocked()
	return e, true
}

// recordDropLocked accounts for one lost event. q.mu must be held.
func (q *Queue) recordDropLocked(e *event.Event) {
	q.dropped++
	if q.metrics != nil {
		q.metrics.EventsDropped.Add(1)
	}
	if e == nil || e.Sequence == 0 {
		return
	}
	if q.firstMissing == 0 || e.Sequence < q.firstMissing {
		q.firstMissing = e.Sequence
	}
	if e.Sequence > q.lastMissing {
		q.lastMissing = e.Sequence
	}
}

// wakeLocked releases parked consumers. q.mu must be held.
func (q *Queue) wakeLocked() {
	if q.waiters == 0 {
		return
	}
	close(q.notify)
	q.notify = make(chan struct{})
}

// updateDepthLocked publishes the depth gauge. Holding the lock across the
// atomic store is what keeps the published depth consistent with the ring.
func (q *Queue) updateDepthLocked() {
	if q.metrics != nil {
		q.metrics.QueueDepth.Store(int64(q.n))
	}
}
