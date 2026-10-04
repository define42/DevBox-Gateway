package sauron

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

type duplicateGateSink struct {
	healthTestSink

	failFirst bool
	calls     atomic.Uint32
	entered   chan uint32
	first     chan struct{}
	second    chan struct{}
}

func (s *duplicateGateSink) Write(ctx context.Context, env *collector.Envelope) error {
	if env.Event == nil || env.Event.Sequence != 1 {
		return nil
	}
	call := s.calls.Add(1)
	s.entered <- call
	release := s.first
	if call != 1 {
		release = s.second
	}
	select {
	case <-release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if call == 1 && s.failFirst {
		return errors.New("temporary first-copy output failure")
	}
	if call != 1 && !s.failFirst {
		return errors.New("already accepted duplicate must not reach output")
	}
	return nil
}

func TestCollectorConcurrentDuplicatesRecoverReadiness(t *testing.T) {
	for _, tt := range []struct {
		name      string
		failFirst bool
	}{
		{name: "accepted first copy suppresses queued duplicate"},
		{name: "rejected first copy is recovered by queued duplicate", failFirst: true},
	} {
		t.Run(tt.name, func(t *testing.T) { testConcurrentDuplicateHealth(t, tt.failFirst) })
	}
}

func testConcurrentDuplicateHealth(t *testing.T, failFirst bool) {
	t.Helper()
	sink := &duplicateGateSink{
		failFirst: failFirst, entered: make(chan uint32, 4),
		first: make(chan struct{}), second: make(chan struct{}),
	}
	c, listener := startHealthCollector(t, sink)
	releaseFirst := sync.OnceFunc(func() { close(sink.first) })
	releaseSecond := sync.OnceFunc(func() { close(sink.second) })
	t.Cleanup(func() { releaseFirst(); releaseSecond() })
	first := connectHealthAgent(t, listener, "duplicate-boot")
	second := connectHealthAgent(t, listener, "duplicate-boot")
	first.sendEvent(1, "duplicate-boot")
	waitDuplicateWrite(t, sink, 1)
	second.sendEvent(1, "duplicate-boot")
	assertDuplicateWriteBlocked(t, sink)
	releaseFirst()
	wantCalls := uint32(1)
	if failFirst {
		wantCalls = 2
		waitDuplicateWrite(t, sink, 2)
		if c.Readiness() == nil {
			t.Fatal("first rejection remained healthy while replay output was pending")
		}
		releaseSecond()
	} else {
		receiveHealthACK(t, first, 1)
		// A late failure from a second copy used to poison readiness after this
		// ACK. Releasing the fixture lets that erroneous path finish, if present.
		releaseSecond()
	}
	receiveHealthACK(t, second, 1)
	second.sendEvent(2, "duplicate-boot")
	receiveHealthACK(t, second, 2)
	if got := sink.calls.Load(); got != wantCalls {
		t.Fatalf("sequence-one output writes = %d, want %d", got, wantCalls)
	}
	if err := c.Readiness(); err != nil {
		t.Fatalf("accepted stream remains unhealthy: %v", err)
	}
}

func waitDuplicateWrite(t *testing.T, sink *duplicateGateSink, want uint32) {
	t.Helper()
	select {
	case got := <-sink.entered:
		if got != want {
			t.Fatalf("output write order = %d, want %d", got, want)
		}
	case <-time.After(testTimeout):
		t.Fatal("output write did not begin")
	}
}

func assertDuplicateWriteBlocked(t *testing.T, sink *duplicateGateSink) {
	t.Helper()
	select {
	case call := <-sink.entered:
		t.Fatalf("output write %d bypassed the pending first copy", call)
	case <-time.After(100 * time.Millisecond):
		// The first writer owns acceptance until its result is committed. This
		// is a bounded negative assertion, not a wait for the second sink write.
	}
}

type crossBootRetrySink struct {
	healthTestSink

	first, second chan struct{}
	entered       chan uint32
	calls         atomic.Uint32
	retrySource   atomic.Pointer[collector.Source]
}

func (s *crossBootRetrySink) Write(ctx context.Context, env *collector.Envelope) error {
	if env.Event == nil || env.Event.Sequence != 1 {
		return nil
	}
	call := s.calls.Add(1)
	s.entered <- call
	if call > 2 {
		source := env.Source
		s.retrySource.Store(&source)
		return nil
	}
	release := s.first
	if call == 2 {
		release = s.second
	}
	select {
	case <-release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if call == 2 {
		return errors.New("retired connection duplicate rejected after current acceptance")
	}
	return nil
}

func TestCollectorRetainedCrossBootDuplicateRecoversWithoutGuestReplay(t *testing.T) {
	sink := &crossBootRetrySink{
		first: make(chan struct{}), second: make(chan struct{}), entered: make(chan uint32, 4),
	}
	c, listener := startHealthCollector(t, sink)
	releaseFirst := sync.OnceFunc(func() { close(sink.first) })
	releaseSecond := sync.OnceFunc(func() { close(sink.second) })
	t.Cleanup(func() { releaseFirst(); releaseSecond() })
	current := connectHealthAgent(t, listener, "current-boot")
	retired := connectHealthAgent(t, listener, "retired-boot")
	current.sendEvent(1, "retired-boot")
	if call := <-sink.entered; call != 1 {
		t.Fatalf("first output call = %d", call)
	}
	retired.sendEvent(1, "retired-boot")
	releaseFirst()
	receiveHealthACK(t, current, 1)
	select {
	case call := <-sink.entered:
		if call != 2 {
			t.Fatalf("retired output call = %d", call)
		}
	case <-time.After(testTimeout):
		t.Fatal("retired copy did not reach output")
	}
	releaseSecond()
	receiveHealthPONG(t, retired)
	if err := retired.conn.Close(); err != nil {
		t.Fatal(err)
	}
	// The current sender has already received ACK1 and deleted that record.
	// Later accepted traffic cannot clear the retired copy's failure, and no
	// guest sends sequence one again. Only the retained original can recover.
	current.sendEvent(2, "current-boot")
	receiveHealthACK(t, current, 2)
	waitForCollectorReadiness(t, c)
	if sink.calls.Load() != 3 {
		t.Fatalf("sequence-one writes = %d, want two live attempts and one retained retry", sink.calls.Load())
	}
	if source := sink.retrySource.Load(); source == nil || source.Reported == nil ||
		source.Reported.BootID != "retired-boot" {
		t.Fatalf("retained retry changed the original connection attribution: %+v", source)
	}
}
