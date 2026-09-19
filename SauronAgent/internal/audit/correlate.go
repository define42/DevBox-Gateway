package audit

import (
	"container/list"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/define42/SauronAgent/internal/metrics"
)

const (
	// defaultCorrelationTimeout matches config.DefaultAgent. A group that the
	// kernel never closes with an EOE record must still be emitted, or one
	// missing marker would hold an event forever.
	defaultCorrelationTimeout = 2 * time.Second

	// defaultMaxPendingEvents matches config.DefaultAgent.
	defaultMaxPendingEvents = 4096

	// minTickInterval and maxTickInterval bound how often Run expires groups.
	// The tick decides the worst-case extra latency an event picks up on top
	// of the correlation timeout.
	minTickInterval = 10 * time.Millisecond
	maxTickInterval = time.Second

	// shutdownGrace bounds how long Run keeps trying to hand its remaining
	// groups downstream after its context is cancelled. Without a bound a
	// consumer that stopped reading would wedge shutdown; with one, the
	// events that could not be delivered are at least reported.
	shutdownGrace = 2 * time.Second
)

// Correlator assembles the records the kernel emits for one logical operation
// into a single Group.
//
// A group is closed when its AUDIT_EOE marker arrives, and otherwise when the
// correlation timeout expires. Nothing is ever dropped: an event that has to
// be forced out early is emitted with Complete false so that the difference is
// visible downstream instead of being silently lost.
type Correlator struct {
	timeout    time.Duration
	maxPending int
	metrics    *metrics.Agent
	log        *slog.Logger
	now        func() time.Time

	mu sync.Mutex
	// pending indexes order by audit id; order keeps groups oldest-first so
	// that the group to force out under pressure is always the front one.
	pending map[string]*list.Element
	order   *list.List
}

// pendingGroup is a group still waiting for more records.
type pendingGroup struct {
	group *Group
	// first is when the group's first record arrived, which is what the
	// correlation timeout is measured from. Using the first record rather than
	// the most recent one bounds total latency: a steady trickle of records
	// sharing one audit id cannot postpone delivery indefinitely.
	first time.Time
}

// NewCorrelator returns a Correlator. Zero-valued options take the same
// defaults as the shipped agent configuration.
func NewCorrelator(opts CorrelatorOptions) *Correlator {
	c := &Correlator{
		timeout:    opts.Timeout,
		maxPending: opts.MaxPendingEvents,
		metrics:    opts.Metrics,
		log:        opts.Logger,
		now:        opts.Now,
		pending:    make(map[string]*list.Element),
		order:      list.New(),
	}
	if c.timeout <= 0 {
		c.timeout = defaultCorrelationTimeout
	}
	if c.maxPending <= 0 {
		c.maxPending = defaultMaxPendingEvents
	}
	if c.metrics == nil {
		c.metrics = &metrics.Agent{}
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// CorrelatorOptions configures a Correlator.
type CorrelatorOptions struct {
	// Timeout is how long a group waits for more records after its first one.
	Timeout time.Duration

	// MaxPendingEvents bounds how many groups may be open at once. Reaching it
	// forces the oldest group out early rather than letting a flood of
	// never-closed events exhaust memory.
	MaxPendingEvents int

	// Metrics is optional.
	Metrics *metrics.Agent

	// Logger is optional; nil discards.
	Logger *slog.Logger

	// Now overrides the clock, so correlation timing can be tested without
	// sleeping. nil means time.Now.
	Now func() time.Time
}

// Add files a record and returns any groups that closed as a result.
//
// A record with no audit event id -- some control-range messages carry none --
// cannot be correlated with anything, so it is returned immediately as a group
// of its own rather than being held for a timeout that would never help.
func (c *Correlator) Add(r *Record) []*Group {
	if r == nil {
		return nil
	}
	if r.AuditID == "" {
		// Complete stays false: it means "closed by an explicit end-of-event
		// marker", and this group never saw one. Downstream must not read it
		// as "records are missing".
		return []*Group{{
			Serial:    r.Serial,
			Timestamp: r.Timestamp,
			Records:   []*Record{r},
		}}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.pending[r.AuditID]
	if !ok {
		pg := &pendingGroup{
			group: &Group{AuditID: r.AuditID, Serial: r.Serial, Timestamp: r.Timestamp},
			first: c.now(),
		}
		el = c.order.PushBack(pg)
		c.pending[r.AuditID] = el
	}
	pg := el.Value.(*pendingGroup)
	pg.group.Records = append(pg.group.Records, r)

	var closed []*Group
	if r.Type == TypeEoe {
		// The EOE record is kept in Records. It carries no fields worth
		// normalizing, but dropping it would mean the preserved raw evidence
		// no longer matches what the kernel actually emitted.
		pg.group.Complete = true
		c.remove(el)
		closed = append(closed, pg.group)
	}

	for len(c.pending) > c.maxPending {
		front := c.order.Front()
		if front == nil {
			break
		}
		oldest := front.Value.(*pendingGroup)
		c.remove(front)
		c.log.Warn("audit correlator at capacity, emitting oldest event early",
			"audit_id", oldest.group.AuditID,
			"records", len(oldest.group.Records),
			"max_pending_events", c.maxPending)
		closed = append(closed, oldest.group)
	}
	return closed
}

// Expire returns every group whose correlation timeout has elapsed at now,
// oldest first. The groups are marked incomplete, because only an EOE record
// proves that no further records are coming.
func (c *Correlator) Expire(now time.Time) []*Group {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expired []*Group
	// The whole list is scanned rather than stopping at the first unexpired
	// group: with an injected clock the insertion order is not guaranteed to
	// be the expiry order, and the list is bounded by MaxPendingEvents.
	for el := c.order.Front(); el != nil; {
		next := el.Next()
		pg := el.Value.(*pendingGroup)
		if now.Sub(pg.first) >= c.timeout {
			c.remove(el)
			expired = append(expired, pg.group)
		}
		el = next
	}
	return expired
}

// Flush returns every group still open, oldest first, and empties the
// correlator. It is what shutdown uses so that partially assembled events are
// reported rather than discarded with the process.
func (c *Correlator) Flush() []*Group {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]*Group, 0, len(c.pending))
	for el := c.order.Front(); el != nil; {
		next := el.Next()
		out = append(out, el.Value.(*pendingGroup).group)
		c.remove(el)
		el = next
	}
	return out
}

// Pending reports how many groups are currently open.
func (c *Correlator) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// remove unlinks a pending group. The caller must hold c.mu.
func (c *Correlator) remove(el *list.Element) {
	pg := el.Value.(*pendingGroup)
	delete(c.pending, pg.group.AuditID)
	c.order.Remove(el)
}

// Run correlates records from in onto out until ctx is cancelled or in is
// closed, flushing whatever is still open before it returns.
//
// Cancellation is an orderly shutdown, so Run returns nil for it rather than
// an error; the wiring that owns the pipeline should not have to special-case
// context.Canceled to tell a clean stop from a failure.
func (c *Correlator) Run(ctx context.Context, in <-chan *Record, out chan<- *Group) error {
	interval := c.timeout / 4
	if interval < minTickInterval {
		interval = minTickInterval
	}
	if interval > maxTickInterval {
		interval = maxTickInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.drain(c.Flush(), out)
			return nil

		case r, ok := <-in:
			if !ok {
				// The producer is finished, so nothing more can arrive for any
				// open group and holding them for their timeouts is pointless.
				undelivered := c.send(ctx, c.Flush(), out)
				c.drain(undelivered, out)
				return nil
			}
			if undelivered := c.send(ctx, c.Add(r), out); len(undelivered) > 0 {
				c.drain(append(undelivered, c.Flush()...), out)
				return nil
			}

		case <-ticker.C:
			if undelivered := c.send(ctx, c.Expire(c.now()), out); len(undelivered) > 0 {
				c.drain(append(undelivered, c.Flush()...), out)
				return nil
			}
		}
	}
}

// send delivers groups downstream. Blocking here is ordinary backpressure and
// is allowed while ctx is live; it returns the groups it could not deliver
// because ctx was cancelled mid-flight, so the caller can account for them.
func (c *Correlator) send(ctx context.Context, groups []*Group, out chan<- *Group) []*Group {
	for i, g := range groups {
		select {
		case out <- g:
		case <-ctx.Done():
			return groups[i:]
		}
	}
	return nil
}

// drain makes a last, time-bounded attempt to deliver groups after the context
// is already cancelled. Anything that still cannot be delivered is logged with
// a count: a lost event is bad, a lost event nobody knows about is worse.
func (c *Correlator) drain(groups []*Group, out chan<- *Group) {
	if len(groups) == 0 {
		return
	}
	timer := time.NewTimer(shutdownGrace)
	defer timer.Stop()

	for i, g := range groups {
		select {
		case out <- g:
		case <-timer.C:
			c.metrics.EventsDropped.Add(uint64(len(groups) - i))
			c.log.Error("audit correlator shut down with undelivered events",
				"undelivered", len(groups)-i,
				"grace", shutdownGrace)
			return
		}
	}
}
