package host

import (
	"context"
	"fmt"
	"maps"

	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

// gapPublication is an exclusive claim on one retained range. The stream and
// generation identities make completion safe after sink I/O, when concurrent
// delivery may have recovered the range or replaced it with newer evidence.
type gapPublication struct {
	key        streamKey
	stream     *dedupStream
	generation uint64
	claim      uint64
	source     output.Source
	gap        seqRange
}

// readiness includes ranges whose output write is in flight. Claims prevent
// duplicate publication but do not prove that the evidence has been accepted.
func (d *dedup) readiness() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	pending := 0
	for _, stream := range d.streams {
		if stream.arrivalOverflow {
			return fmt.Errorf("arrival tracking overflowed; operator recovery required")
		}
		pending += len(stream.pending)
	}
	if pending != 0 {
		return fmt.Errorf("%d audit gap reports await output acceptance", pending)
	}
	return nil
}

func cloneGapSource(source output.Source) output.Source {
	source.Labels = maps.Clone(source.Labels)
	if source.Reported != nil {
		reported := *source.Reported
		source.Reported = &reported
	}
	return source
}

// claimGap remembers the first source for the current evidence generation and
// exclusively claims the requested range. A busy claim still remembers a new
// generation's source so recovery can retry it after the old I/O completes.
func (d *dedup) claimGap(
	key streamKey, source output.Source, first, last uint64, version gapVersion,
) (gapPublication, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	stream := d.streams[key]
	if stream == nil || len(stream.pending) == 0 || stream.identity != version.stream ||
		stream.gapGeneration != version.generation ||
		!stream.pendingContains(first, last) {
		return gapPublication{}, false
	}
	if stream.gapSource == nil {
		copy := cloneGapSource(source)
		stream.gapSource = &copy
	}
	if stream.activeGapClaim != 0 || !stream.canPublishGap(first, last) {
		return gapPublication{}, false
	}
	d.clock++
	stream.used = d.clock
	return claimGapLocked(key, stream, first, last), true
}

// takePendingGap claims the oldest retryable stream. Rotating its used clock
// prevents one persistently failing sink write from starving other streams.
func (d *dedup) takePendingGap() (gapPublication, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var key streamKey
	var oldest *dedupStream
	var gap seqRange
	for candidate, stream := range d.streams {
		if len(stream.pending) == 0 || stream.gapSource == nil || stream.activeGapClaim != 0 {
			continue
		}
		next, ok := stream.nextPublishableGap()
		if !ok {
			continue
		}
		if oldest == nil || stream.used < oldest.used {
			key, oldest, gap = candidate, stream, next
		}
	}
	if oldest == nil {
		return gapPublication{}, false
	}
	d.clock++
	oldest.used = d.clock
	return claimGapLocked(key, oldest, gap.first, gap.last), true
}

// takeNextPendingGap keeps a successful recovery pass on the same stream while
// still claiming only one range at a time.
func (d *dedup) takeNextPendingGap(key streamKey) (gapPublication, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	stream := d.streams[key]
	if stream == nil || len(stream.pending) == 0 || stream.gapSource == nil || stream.activeGapClaim != 0 {
		return gapPublication{}, false
	}
	gap, ok := stream.nextPublishableGap()
	if !ok {
		return gapPublication{}, false
	}
	d.clock++
	stream.used = d.clock
	return claimGapLocked(key, stream, gap.first, gap.last), true
}

// nextPublishableGap skips evidence that cannot yet fit the accepted-loss
// ledger. Another range may merge with existing losses or close the early hole
// keeping the ledger full. No sink write is attempted until its result can be
// retained, so healthy output cannot be flooded with an unrecordable report.
func (s *dedupStream) nextPublishableGap() (seqRange, bool) {
	s.excludeArrivals()
	for _, pending := range s.pending {
		if gap, ok := s.safeGapPart(pending, 0); ok && s.canPublishGap(gap.first, gap.last) {
			return gap, true
		}
	}
	return seqRange{}, false
}

// canPublishGap reserves room in both ledgers before an exclusive claim starts
// output I/O. While that claim is active, other publication completions cannot
// grow missing; event commits can only consume its ranges. Pending evidence may
// change, which finishGap still checks separately before accounting for a write.
func (s *dedupStream) canPublishGap(first, last uint64) bool {
	if s.coversArrival(first, last) {
		return false
	}
	if _, ok := subtractRange(s.pending, first, last); !ok {
		return false
	}
	if last < first || last <= s.written || first <= s.written+1 {
		return true
	}
	ranges := 0
	for _, gap := range s.missing {
		if gap.last <= s.written {
			continue
		}
		before := first > gap.last && first-gap.last > 1
		after := gap.first > last && gap.first-last > 1
		if before || after {
			ranges++
			continue
		}
		first = min(first, gap.first)
		last = max(last, gap.last)
	}
	return ranges < maxMissingRanges
}

// claimGapLocked records only in-memory ownership; callers release the mutex
// before publishing to the sink.
func claimGapLocked(key streamKey, stream *dedupStream, first, last uint64) gapPublication {
	stream.nextGapClaim++
	if stream.nextGapClaim == 0 {
		stream.nextGapClaim++
	}
	stream.activeGapClaim = stream.nextGapClaim
	return gapPublication{
		key:        key,
		stream:     stream,
		generation: stream.gapGeneration,
		claim:      stream.activeGapClaim,
		source:     cloneGapSource(*stream.gapSource),
		gap:        seqRange{first: first, last: last},
	}
}

// finishGap releases a publication claim and, after an accepted sink write,
// accounts for it only if the same generation still contains the full range.
// A recovered event or a drain-and-refill makes the completion stale.
func (d *dedup) finishGap(publication gapPublication, accepted bool) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	stream := d.streams[publication.key]
	if stream == nil || stream != publication.stream || stream.activeGapClaim != publication.claim {
		return false
	}
	stream.activeGapClaim = 0
	if !accepted || stream.coversArrival(publication.gap.first, publication.gap.last) ||
		stream.gapGeneration != publication.generation ||
		!stream.pendingContains(publication.gap.first, publication.gap.last) {
		return false
	}
	remaining, ok := subtractRange(stream.pending, publication.gap.first, publication.gap.last)
	if !ok || !stream.noteMissing(publication.gap.first, publication.gap.last) {
		return false
	}
	stream.pending = remaining
	stream.prunePending()
	if publication.gap.last > stream.highest {
		stream.highest = publication.gap.last
	}
	d.clock++
	stream.used = d.clock
	return true
}

// retryPendingGaps attempts at most maxMissingRanges reports from one retained
// stream. The background worker and blocked new streams can drive recovery
// even when the originating boot never reconnects. Sink I/O runs outside the
// dedup lock and stops at the first error.
func (s *Server) retryPendingGaps(ctx context.Context) {
	publication, ok := s.dedup.takePendingGap()
	if !ok {
		return
	}
	key := publication.key
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout())
	defer cancel()
	for attempts := 0; attempts < maxMissingRanges; attempts++ {
		if ctx.Err() != nil {
			s.dedup.finishGap(publication, false)
			return
		}
		if !s.publishGap(ctx, publication, "retrying retained gap evidence") {
			return
		}
		publication, ok = s.dedup.takeNextPendingGap(key)
		if !ok {
			return
		}
	}
	// The bound normally drains every retained range. Release a claim acquired
	// for a concurrently split remainder rather than leaving the stream pinned.
	s.dedup.finishGap(publication, false)
}
