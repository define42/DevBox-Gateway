package host

import (
	"cmp"
	"slices"
	"sync"

	"github.com/define42/SauronAgent/internal/output"
)

// minDedupWindow is the floor applied to limits.dedup_window.
//
// The window bounds the out-of-order set below, and a window of zero would not
// mean "no deduplication" but "an unbounded set": entries are only released when
// the contiguous watermark catches up with them, and behind a permanent hole it
// never does. Deduplication therefore cannot be switched off by configuration,
// only made smaller.
const minDedupWindow = 64

// maxMissingRanges bounds each stream's pending and reported missing ranges.
// Pending overflow refuses the new arrival while retrying existing evidence;
// reported overflow leaves the acknowledgement parked below the unretained hole.
// Both fail closed instead of acknowledging something the host cannot account for.
const maxMissingRanges = 64

// streamKey identifies one guest event stream.
//
// It is the deduplication key from protocol.md section 6 minus the sequence:
// the peer bucket (the hypervisor-assigned CID for a VSOCK guest) and the boot
// id the guest reported. The boot id is untrusted, but a guest that lies about
// it only damages the continuity of its own stream: it cannot reach another
// CID's state, because the CID half of the key is not something it can choose.
type streamKey struct {
	peer string
	boot string
}

// seqRange is an inclusive range of sequence numbers.
type seqRange struct{ first, last uint64 }

// dedupResult is what the collector learns from the arrival of one sequence.
type dedupResult struct {
	// Duplicate means this sequence has already been durably written and must
	// not be written again. It is still acknowledgeable: the host holds it.
	Duplicate bool

	// Gap identifies missing sequence evidence still awaiting sink acceptance.
	// HELLO may establish that a previously received but unwritten event is now
	// unreplayable too. Detection by itself never makes a range acknowledgeable.
	Gap      bool
	GapFirst uint64
	GapLast  uint64

	// Blocked means remembering this arrival would discard unresolved gap
	// evidence. The caller must leave the event with the guest for retry.
	Blocked bool
}

// dedup suppresses duplicate events and detects gaps, per DESIGN section 21.
//
// Delivery is at-least-once: after a reconnect the agent re-sends everything its
// spool still holds, so duplicates are normal and expected. Each stream is
// tracked as a highest-contiguous-accounted watermark plus a bounded set of
// out-of-order sequences above it, which costs one integer in the normal case
// (sequences arrive in order) and degrades safely when they do not.
//
// FAILURE MODE, deliberately chosen: the out-of-order set holds at most
// limits.dedup_window entries per stream, and the table holds a bounded number
// of streams. Once a sequence falls out of the window -- or its whole stream is
// evicted -- a re-delivery of it is no longer detectable and the event will be
// written twice. That is the safe direction: at-least-once delivery makes a
// duplicate an expected nuisance, while a suppressed original is evidence
// destroyed. Keep limits.dedup_window well above the agent's
// transport.max_unacked, or a replay after a long outage will be written twice.
type dedup struct {
	mu         sync.Mutex
	window     int
	maxStreams int
	clock      uint64 // monotonic counter used to evict the least recently used stream
	streams    map[streamKey]*dedupStream
}

// dedupStream is the per-stream state.
type dedupStream struct {
	// written is the watermark: every sequence up to and including it is
	// accounted for, meaning it was durably written or it was reported missing.
	// A new stream starts immediately before its first received sequence:
	// earlier events may predate the collector, but this first event must be
	// committed before the watermark can advance past it.
	// It is what the host acknowledges and what it offers as ResumeFrom.
	written uint64

	// ahead holds sequences durably written out of order, above written. They
	// are absorbed into the watermark as soon as the hole below them is closed.
	ahead map[uint64]struct{}

	// missing holds ranges reported as lost, which the watermark may also
	// advance over. Without this a permanent hole -- the agent dropped events
	// and said so -- would stall the acknowledgement forever and the guest's
	// spool would fill up behind it, turning one recorded loss into a second,
	// unrecorded one. Advancing is only safe because the loss was reported as
	// an event first: the evidence of the hole outlives the hole.
	missing []seqRange

	// pending holds detected gaps whose reports have not reached the sink.
	// They never advance written and remain retryable after reconnects. Such
	// streams cannot be evicted until their loss evidence is accepted.
	pending []seqRange

	// gapSource preserves the first gap's attribution across CID reuse and
	// guest reboots. retrying pins a bounded snapshot while sink I/O runs.
	gapSource *output.Source
	retrying  bool

	// highest is the highest sequence ever received on this stream, written or
	// not. Gap detection uses it rather than the watermark so that an event
	// whose output failed is not reported as missing: the guest still holds it
	// and will send it again.
	highest uint64

	// forgotten counts sequences evicted from ahead, whose re-delivery can no
	// longer be suppressed.
	forgotten uint64

	used uint64 // clock value at last use, for eviction
}

// newDedup builds the deduplication table. window is limits.dedup_window and
// maxStreams bounds how many (peer, boot id) streams are remembered.
func newDedup(window, maxStreams int) *dedup {
	if window < minDedupWindow {
		window = minDedupWindow
	}
	if maxStreams < 1 {
		maxStreams = 1
	}
	return &dedup{
		window:     window,
		maxStreams: maxStreams,
		streams:    make(map[streamKey]*dedupStream),
	}
}

// Check reports what the arrival of seq on stream k means, without recording it
// as held.
//
// Recording is deliberately separate: an event is only marked as held once a
// sink has accepted it (see Commit). Marking it on arrival would mean that an
// event whose output failed is suppressed when the guest re-sends it -- the
// collector would answer a retry with silence, and the event would be lost for
// good.
func (d *dedup) Check(k streamKey, seq uint64) dedupResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	s := d.stream(k)
	if s == nil {
		return dedupResult{Blocked: true}
	}
	var r dedupResult

	// Anchor the stream on arrival, not on its first successful sink write.
	// Otherwise a later successful write could acknowledge a failed first one.
	if s.highest == 0 && seq > 0 {
		s.written = seq - 1
	}

	// A sequence more than one above the highest ever received means events are
	// missing. The first sequence on a brand-new stream is not a gap: the
	// collector simply started after the guest did.
	if s.highest != 0 && seq > s.highest && seq-s.highest > 1 {
		if !s.queueMissing(s.highest+1, seq-1) {
			r = s.pendingGap()
			r.Blocked = true
			return r
		}
	}
	if seq > s.highest {
		s.highest = seq
	}
	r = s.pendingGap()

	if seq <= s.written {
		r.Duplicate = true
		return r
	}
	_, r.Duplicate = s.ahead[seq]
	return r
}

// Commit records that seq has been durably written for stream k and returns the
// new acknowledgement point: the highest sequence such that everything up to it
// is accounted for. forgotten counts sequences this call pushed out of the
// window.
//
// Acknowledging the returned value is safe by construction. The watermark only
// advances over sequences whose sink write returned nil and over ranges that
// were explicitly reported missing, so an ACK never silently tells a guest to
// delete an event the collector neither holds nor reported losing.
func (d *dedup) Commit(k streamKey, seq uint64) (ack uint64, forgotten uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	s := d.stream(k)
	if s == nil {
		return 0, 0
	}
	if seq <= s.written {
		return s.written, 0
	}
	s.ahead[seq] = struct{}{}
	s.absorb()
	s.prunePending()
	return s.written, s.trim(d.window)
}

// CheckReplay detects loss established by HELLO's first_sequence without
// acknowledging it. Unknown streams have no established history to lose. A
// known stream may still have written == 0 after its first output failed.
func (d *dedup) CheckReplay(k streamKey, firstSequence uint64) dedupResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.streams[k]
	if !ok {
		return dedupResult{}
	}
	d.clock++
	s.used = d.clock
	if firstSequence > s.written && firstSequence-s.written > 1 {
		if !s.queueReplayMissing(firstSequence - 1) {
			r := s.pendingGap()
			r.Blocked = true
			return r
		}
	}
	return s.pendingGap()
}

// NoteMissing commits a range only after its loss report was accepted by the
// sink. Detection alone must never let the watermark advance over a hole.
//
// Both arrival gaps and HELLO's first_sequence feed this commit point. Recording
// the accepted report also keeps the hole from being reported a second time.
func (d *dedup) NoteMissing(k streamKey, first, last uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// A concurrent successful report may already have released this stream's
	// pin and allowed eviction. A late completion must not recreate it.
	s := d.streams[k]
	if s == nil {
		return
	}
	d.clock++
	s.used = d.clock
	s.noteMissing(first, last)
	s.pending = slices.DeleteFunc(s.pending, func(r seqRange) bool {
		return r.first >= first && r.last <= last
	})
	s.prunePending()
	if last > s.highest {
		s.highest = last
	}
}

// ResumeFrom is the highest sequence the collector has accounted for on a
// stream. It is what READY offers the agent so it can skip re-sending data the
// host already has -- an optimisation only, since deduplication covers the rest.
//
// An unknown stream reports 0, meaning "the host holds nothing, send
// everything", and is not created here: a lookup must not be able to evict a
// live stream's history.
func (d *dedup) ResumeFrom(k streamKey) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.streams[k]
	if !ok {
		return 0
	}
	d.clock++
	s.used = d.clock
	return s.written
}

// stream returns the state for k, creating it and evicting the least recently
// used stream if the table is full. Callers hold d.mu.
func (d *dedup) stream(k streamKey) *dedupStream {
	d.clock++
	if s, ok := d.streams[k]; ok {
		s.used = d.clock
		return s
	}
	if len(d.streams) >= d.maxStreams && !d.evictOldest() {
		return nil
	}
	s := &dedupStream{ahead: make(map[uint64]struct{}), used: d.clock}
	d.streams[k] = s
	return s
}

// evictOldest drops the least recently used stream. Callers hold d.mu.
//
// Unresolved loss evidence pins its stream: forgetting it would let a reconnect
// anchor beyond a hole that was never reported. If every stream is pinned, new
// arrivals are refused until output recovers and the pending reports succeed.
// Other evicted history may be replayed twice, the same safe trade as the window.
func (d *dedup) evictOldest() bool {
	var (
		victim streamKey
		oldest uint64
		found  bool
	)
	for k, s := range d.streams {
		if len(s.pending) != 0 || s.retrying {
			continue
		}
		if !found || s.used < oldest {
			victim, oldest, found = k, s.used, true
		}
	}
	if found {
		delete(d.streams, victim)
	}
	return found
}

// queueMissing retains a detected gap until its report is accepted. Overlapping
// or adjacent ranges are coalesced to keep repeated HELLOs and retries bounded.
// At capacity, rejection preserves every existing range and the caller leaves
// this arrival unobserved so the guest can retry it later.
func (s *dedupStream) queueMissing(first, last uint64) bool {
	if last < first || last <= s.written {
		return true
	}
	if first <= s.written {
		first = s.written + 1
	}
	ranges := make([]seqRange, 0, len(s.pending)+1)
	for _, r := range s.pending {
		before := first > r.last && first-r.last > 1
		after := r.first > last && r.first-last > 1
		if before || after {
			ranges = append(ranges, r)
			continue
		}
		first = min(first, r.first)
		last = max(last, r.last)
	}
	if len(ranges) >= maxMissingRanges {
		return false
	}
	ranges = append(ranges, seqRange{first: first, last: last})
	slices.SortFunc(ranges, func(a, b seqRange) int { return cmp.Compare(a.first, b.first) })
	s.pending = ranges
	return true
}

func (s *dedupStream) pendingGap() dedupResult {
	if len(s.pending) == 0 {
		return dedupResult{}
	}
	gap := s.pending[0]
	return dedupResult{Gap: true, GapFirst: gap.first, GapLast: gap.last}
}

// queueReplayMissing excludes events already held out of order and losses
// already reported. HELLO only establishes loss for sequences neither end has.
func (s *dedupStream) queueReplayMissing(last uint64) bool {
	accounted := make([]seqRange, 0, len(s.ahead)+len(s.missing))
	accounted = append(accounted, s.missing...)
	for seq := range s.ahead {
		accounted = append(accounted, seqRange{first: seq, last: seq})
	}
	slices.SortFunc(accounted, func(a, b seqRange) int { return cmp.Compare(a.first, b.first) })
	next := s.written + 1
	for _, r := range accounted {
		if r.last < next {
			continue
		}
		if r.first > last {
			break
		}
		if r.first > next && !s.queueMissing(next, r.first-1) {
			return false
		}
		if r.last >= last {
			return true
		}
		next = r.last + 1
	}
	return s.queueMissing(next, last)
}

func (s *dedupStream) prunePending() {
	s.pending = slices.DeleteFunc(s.pending, func(r seqRange) bool { return r.last <= s.written })
	for i := range s.pending {
		if s.pending[i].first <= s.written {
			s.pending[i].first = s.written + 1
		}
	}
}

// noteMissing records a reported-lost range and lets the watermark catch up.
func (s *dedupStream) noteMissing(first, last uint64) {
	if last < first || last <= s.written {
		return
	}
	if first <= s.written {
		first = s.written + 1
	}
	if len(s.missing) >= maxMissingRanges {
		return
	}
	s.missing = append(s.missing, seqRange{first: first, last: last})
	s.absorb()
}

// absorb advances the watermark over everything immediately above it that is
// accounted for: written out of order, or reported missing.
func (s *dedupStream) absorb() {
	for {
		next := s.written + 1
		if _, ok := s.ahead[next]; ok {
			delete(s.ahead, next)
			s.written = next
			continue
		}
		if last, ok := s.takeMissing(next); ok {
			s.written = last
			continue
		}
		return
	}
}

// takeMissing consumes the reported-missing range containing seq and returns its
// upper bound. A whole range is consumed at once so that a hole of a million
// sequences costs one step rather than a million.
func (s *dedupStream) takeMissing(seq uint64) (uint64, bool) {
	for i, r := range s.missing {
		if seq < r.first || seq > r.last {
			continue
		}
		s.missing = slices.Delete(s.missing, i, i+1)
		return r.last, true
	}
	return 0, false
}

// trim bounds the out-of-order set to the configured window.
//
// The lowest sequences are dropped first: they are the oldest, and behind a hole
// that will never be filled they are the ones that will never be absorbed. A
// batch is dropped rather than a single entry so that a stream parked behind a
// hole pays for the scan once every quarter window instead of on every event,
// which is what stops a guest from turning the eviction path into a denial of
// service.
func (s *dedupStream) trim(window int) uint64 {
	if len(s.ahead) <= window {
		return 0
	}
	keys := make([]uint64, 0, len(s.ahead))
	for k := range s.ahead {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	drop := len(keys) - window + window/4
	if drop > len(keys) {
		drop = len(keys)
	}
	for _, k := range keys[:drop] {
		delete(s.ahead, k)
	}
	s.forgotten += uint64(drop)
	return uint64(drop)
}
