package host

import (
	"context"
	"maps"
	"slices"

	"github.com/define42/SauronAgent/internal/output"
)

// pendingGapReports is one stream's bounded snapshot of unresolved evidence.
// The stream stays pinned until this snapshot's writes finish, even if another
// session accounts for its remaining gaps in the meantime.
type pendingGapReports struct {
	key    streamKey
	source output.Source
	ranges []seqRange
}

func (d *dedup) rememberGapSource(key streamKey, source output.Source) output.Source {
	d.mu.Lock()
	defer d.mu.Unlock()
	stream := d.streams[key]
	if stream == nil || len(stream.pending) == 0 {
		return source
	}
	if stream.gapSource == nil {
		copy := cloneGapSource(source)
		stream.gapSource = &copy
	}
	return cloneGapSource(*stream.gapSource)
}

func cloneGapSource(source output.Source) output.Source {
	source.Labels = maps.Clone(source.Labels)
	if source.Reported != nil {
		reported := *source.Reported
		source.Reported = &reported
	}
	return source
}

func (d *dedup) takePendingGaps() (pendingGapReports, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var key streamKey
	var oldest *dedupStream
	for candidate, stream := range d.streams {
		if len(stream.pending) == 0 || stream.gapSource == nil || stream.retrying {
			continue
		}
		if oldest == nil || stream.used < oldest.used {
			key, oldest = candidate, stream
		}
	}
	if oldest == nil {
		return pendingGapReports{}, false
	}
	// Rotate failed attempts too, so one persistently failing report does not
	// prevent other streams' evidence from being retried on later admissions.
	d.clock++
	oldest.used = d.clock
	oldest.retrying = true
	return pendingGapReports{
		key:    key,
		source: cloneGapSource(*oldest.gapSource),
		ranges: slices.Clone(oldest.pending),
	}, true
}

func (d *dedup) finishPendingGaps(key streamKey) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if stream := d.streams[key]; stream != nil {
		stream.retrying = false
	}
}

// retryPendingGaps attempts at most maxMissingRanges reports from one retained
// stream. New guests drive recovery even when the originating boot never
// reconnects. Sink I/O runs outside the dedup lock and stops at the first error.
func (s *Server) retryPendingGaps(ctx context.Context) {
	reports, ok := s.dedup.takePendingGaps()
	if !ok {
		return
	}
	defer s.dedup.finishPendingGaps(reports.key)
	ctx, cancel := context.WithTimeout(ctx, s.writeTimeout())
	defer cancel()
	for _, gap := range reports.ranges {
		if ctx.Err() != nil {
			return
		}
		if !s.publishGap(ctx, reports.key, reports.source, gap.first, gap.last, "retrying retained gap evidence") {
			return
		}
	}
}
