package host

import (
	"fmt"

	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

type arrivalReservation struct {
	d      *dedup
	stream *dedupStream
	seq    uint64
}

// reserveArrival records receipt before any blocking work. A queued original
// must invalidate an in-flight loss claim even though output is still pending.
// Check runs again under the output gate to observe other copies' commits.
func (d *dedup) reserveArrival(key streamKey, seq uint64, source output.Source) (*arrivalReservation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.stream(key)
	if s == nil {
		return nil, fmt.Errorf("pending gap evidence limit reached for stream %q", key.boot)
	}
	if _, exists := s.arrivals[seq]; !exists && len(s.arrivals) >= d.window {
		// Do not let a capacity failure turn a received event into acknowledgeable
		// loss. This exceptional state stops gap accounting until operator recovery.
		s.arrivalOverflow = true
		return nil, fmt.Errorf("arrival tracking limit reached for stream %q", key.boot)
	}
	if s.arrivals == nil {
		s.arrivals = make(map[uint64]int)
	}
	s.arrivals[seq]++
	s.check(seq)
	if len(s.pending) != 0 && s.gapSource == nil {
		copy := cloneGapSource(source)
		s.gapSource = &copy
	}
	return &arrivalReservation{d: d, stream: s, seq: seq}, nil
}

func (r *arrivalReservation) release() {
	r.d.mu.Lock()
	defer r.d.mu.Unlock()
	r.stream.arrivals[r.seq]--
	r.stream.excludeArrivals()
}

// excludeArrivals makes exclusions permanent when space permits. A zero-ref
// entry is retained only if splitting the pending range would exceed its bound.
// Publishing a safe prefix then leaves the received sequence at a range edge,
// where exclusion needs no extra slot. This also protects failed output writes.
func (s *dedupStream) excludeArrivals() {
	for seq, refs := range s.arrivals {
		if s.excludePending(seq) && refs == 0 {
			delete(s.arrivals, seq)
		}
	}
}

func (s *dedupStream) coversArrival(first, last uint64) bool {
	if s.arrivalOverflow {
		return true
	}
	for seq := range s.arrivals {
		if first <= seq && seq <= last {
			return true
		}
	}
	return false
}

// safeGapPart returns the first contiguous part that contains no received
// events. exclude is an additional unreserved arrival used by Check callers.
func (s *dedupStream) safeGapPart(gap seqRange, exclude uint64) (seqRange, bool) {
	if s.arrivalOverflow {
		return seqRange{}, false
	}
	for {
		firstProtected, found := exclude, exclude >= gap.first && exclude <= gap.last
		for seq := range s.arrivals {
			if seq >= gap.first && seq <= gap.last && (!found || seq < firstProtected) {
				firstProtected, found = seq, true
			}
		}
		if !found {
			return gap, true
		}
		if firstProtected > gap.first {
			return seqRange{first: gap.first, last: firstProtected - 1}, true
		}
		if firstProtected == gap.last {
			return seqRange{}, false
		}
		gap.first++
	}
}

func (s *dedupStream) safePendingGap(exclude uint64) dedupResult {
	for _, pending := range s.pending {
		if gap, ok := s.safeGapPart(pending, exclude); ok {
			return dedupResult{
				Gap: true, GapFirst: gap.first, GapLast: gap.last,
				GapVersion: gapVersion{stream: s.identity, generation: s.gapGeneration},
			}
		}
	}
	return dedupResult{}
}
