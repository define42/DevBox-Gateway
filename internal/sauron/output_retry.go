package sauron

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

const (
	maxRejectedGuestBytes = 64 << 20
	outputRetryInterval   = time.Second
	outputRetryTimeout    = 5 * time.Second
	outputRetryBatch      = 64
)

// rejectedRecord owns an immutable encoded copy. A guest may already have
// deleted an accepted copy before another session's duplicate fails; recovery
// must therefore remain possible without asking that guest to replay it.
type rejectedRecord struct {
	key      rejectedEventKey
	version  uint64
	encoded  []byte
	inflight bool
}

// retryCandidate does not hold the encoded body. A live session may release or
// replace queued records while the worker is processing an earlier candidate.
type retryCandidate struct {
	key     rejectedEventKey
	version uint64
}

// canRetain avoids cloning more guest data once the bounded store is full.
// rejectLocked repeats the capacity check after encoding because live sessions
// can fill the remaining space concurrently.
func (s *observedSink) canRetain(key rejectedEventKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.rejected[key]; old != nil {
		retained := s.rejectedBytes
		if !old.inflight {
			retained -= len(old.encoded)
		}
		return retained < maxRejectedGuestBytes
	}
	return len(s.rejected) < maxRejectedGuestEvents && s.rejectedBytes < maxRejectedGuestBytes
}

func (s *observedSink) startRetries(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retryDone != nil {
		return
	}
	ctx, s.retryCancel = context.WithCancel(ctx)
	s.retryDone = make(chan struct{})
	go func() {
		defer close(s.retryDone)
		ticker := time.NewTicker(outputRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.retryRejected(ctx)
			}
		}
	}()
}

// retryRejected makes one bounded pass. Failed records move to the back of the
// version order, so a persistent large-record failure cannot starve others.
func (s *observedSink) retryRejected(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, outputRetryTimeout)
	defer cancel()
	for _, rejected := range s.retryBatch() {
		if ctx.Err() != nil {
			return
		}
		s.retryRecord(ctx, rejected)
	}
}

func (s *observedSink) retryBatch() []retryCandidate {
	s.mu.Lock()
	defer s.mu.Unlock()
	batch := make([]retryCandidate, 0, len(s.rejected))
	for _, rejected := range s.rejected {
		if len(rejected.encoded) != 0 {
			batch = append(batch, retryCandidate{key: rejected.key, version: rejected.version})
		}
	}
	slices.SortFunc(batch, func(a, b retryCandidate) int { return cmp.Compare(a.version, b.version) })
	return batch[:min(len(batch), outputRetryBatch)]
}

func (s *observedSink) retryRecord(ctx context.Context, candidate retryCandidate) {
	s.mu.Lock()
	rejected := s.rejected[candidate.key]
	if rejected == nil || rejected.version != candidate.version || rejected.inflight {
		s.mu.Unlock()
		return
	}
	rejected.inflight = true
	before := s.failures
	s.mu.Unlock()

	var env collector.Envelope
	decoder := json.NewDecoder(bytes.NewReader(rejected.encoded))
	// Preserve integers in generic event fields without a float64 round trip.
	decoder.UseNumber()
	err := decoder.Decode(&env)
	if err == nil {
		err = s.Sink.Write(ctx, &env)
	}
	s.mu.Lock()
	rejected.inflight = false
	if s.rejected[rejected.key] != rejected {
		// A live matching success or a newer rejection superseded this attempt.
		// An old completion cannot erase newer evidence or resurrect a failure
		// for a copy that the live session has since delivered successfully.
		s.rejectedBytes -= len(rejected.encoded)
		s.mu.Unlock()
		return
	}
	change := s.recordLocked(err, true, before, rejected.key, true, rejected.encoded)
	s.mu.Unlock()
	change.log()
}

// Close stops the retry worker before releasing the outputs it uses. The
// collector calls it only after its guest sessions have finished writing.
func (s *observedSink) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		cancel, done := s.retryCancel, s.retryDone
		s.mu.Unlock()
		if cancel != nil {
			cancel()
			<-done
		}
		s.closeErr = s.Sink.Close()
	})
	return s.closeErr
}
