package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
	"github.com/define42/devbox-gateway/SauronAgent/internal/logging"
	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

func claimTestGap(t *testing.T, d *dedup) gapPublication {
	t.Helper()
	accept(t, d, testStream, 1)
	gap := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	publication, ok := d.claimGap(testStream, output.Source{VM: "original-vm"}, 2, 2, gap.GapVersion)
	if !ok {
		t.Fatal("pending gap was not claimable")
	}
	return publication
}

func TestPendingGapReadinessIncludesInflightPublication(t *testing.T) {
	h := newHarness(t, nil)
	publication := claimTestGap(t, h.srv.dedup)
	if err := h.srv.Readiness(); err == nil || !strings.Contains(err.Error(), "audit gap") {
		t.Fatalf("in-flight gap evidence did not affect readiness: %v", err)
	}
	if !h.srv.dedup.finishGap(publication, true) {
		t.Fatal("gap evidence was not accepted")
	}
	if err := h.srv.Readiness(); err != nil {
		t.Fatalf("accepted evidence did not restore readiness: %v", err)
	}
}

func TestGapRetryContinuesWhileInventoryIsBlocked(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := newHarnessWithOptions(t, func(cfg *config.Host) {
		cfg.Monitor.Enabled = true
	}, func(opts *Options) {
		opts.ExpectedVMs = func() ([]config.VMMapping, error) {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release
			return nil, nil
		}
	})
	defer close(release)
	select {
	case <-entered:
	case <-time.After(testTimeout):
		t.Fatal("inventory callback did not start")
	}
	publication := claimTestGap(t, h.srv.dedup)
	h.srv.dedup.finishGap(publication, false)
	h.waitInternal(typeStreamGap)
	waitForPendingGapsToDrain(t, h.srv.dedup)
	if len(h.sink.internals()) != 1 {
		t.Fatal("background retry did not publish retained gap evidence")
	}
	if err := h.srv.Readiness(); err == nil || !strings.Contains(err.Error(), "inventory") {
		t.Fatalf("blocked inventory should remain independently unhealthy: %v", err)
	}
}

type cancelGapSink struct {
	*fakeSink

	entered chan struct{}
}

func (s *cancelGapSink) Write(ctx context.Context, env *output.Envelope) error {
	if env.Event == nil || env.Event.Type != typeStreamGap {
		return s.fakeSink.Write(ctx, env)
	}
	close(s.entered)
	<-ctx.Done()
	return ctx.Err()
}

func TestGapRetryCancellationReleasesClaimBeforeClosingSink(t *testing.T) {
	sink := &cancelGapSink{fakeSink: newFakeSink(), entered: make(chan struct{})}
	h := newHarnessWithOptions(t, nil, func(opts *Options) { opts.Sink = sink })
	publication := claimTestGap(t, h.srv.dedup)
	h.srv.dedup.finishGap(publication, false)
	select {
	case <-sink.entered:
	case <-time.After(testTimeout):
		t.Fatal("background gap write did not start")
	}
	health := make(chan error, 1)
	go func() { health <- h.srv.Readiness() }()
	select {
	case err := <-health:
		if err == nil {
			t.Fatal("blocked gap write remained healthy")
		}
	case <-time.After(testTimeout):
		t.Fatal("gap output I/O held the readiness lock")
	}
	h.stop()
	if sink.closed() != 1 {
		t.Fatal("collector did not close sink after cancelling retry")
	}
	if h.srv.dedup.readiness() == nil {
		t.Fatal("cancellation discarded unpublished gap evidence")
	}
	claim, ok := h.srv.dedup.takePendingGap()
	if !ok {
		t.Fatal("cancelled worker leaked its publication claim")
	}
	h.srv.dedup.finishGap(claim, false)
}

func waitForPendingGapsToDrain(t *testing.T, d *dedup) {
	t.Helper()
	deadline := time.NewTimer(testTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if d.readiness() == nil {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("gap evidence was not accepted: %v", d.readiness())
		}
	}
}

func TestGapRetryWaitsForAccountingCapacityWithoutRepeatingReports(t *testing.T) {
	srv, sink := newGapCapacityServer(t)
	fillAcceptedGapCapacity(t, srv, 1)
	d := srv.dedup
	last := uint64(2*maxMissingRanges + 3)
	gap := d.Check(testStream, last)
	if !gap.Gap || gap.Blocked {
		t.Fatalf("overflow gap = %+v", gap)
	}
	if _, ok := d.claimGap(testStream, output.Source{VM: "original-vm"},
		gap.GapFirst, gap.GapLast, gap.GapVersion); ok {
		t.Fatal("report was claimable without room to account for its acceptance")
	}
	d.Commit(testStream, last)
	for range 3 {
		srv.retryPendingGaps(t.Context())
	}
	if got := len(sink.internals()); got != maxMissingRanges {
		t.Fatalf("accepted gap reports = %d, want %d without retry duplicates", got, maxMissingRanges)
	}
	if d.readiness() == nil || d.ResumeFrom(testStream) != 0 {
		t.Fatal("unreported gap or unwritten first event was treated as accepted")
	}

	// The accepted out-of-order events and reported gaps can now drain. The
	// independent retry publishes the remaining report exactly once.
	d.Check(testStream, 1)
	d.Commit(testStream, 1)
	srv.retryPendingGaps(t.Context())
	srv.retryPendingGaps(t.Context())
	if got := len(sink.internals()); got != maxMissingRanges+1 {
		t.Fatalf("reports after recovery = %d, want %d", got, maxMissingRanges+1)
	}
	if err := d.readiness(); err != nil {
		t.Fatalf("recovered accounting capacity did not drain pending evidence: %v", err)
	}
	if got := d.ResumeFrom(testStream); got != last {
		t.Fatalf("ACK after recovery = %d, want %d", got, last)
	}
}

func TestGapRetryAtCapacityStillPublishesOtherStreams(t *testing.T) {
	srv, sink := newGapCapacityServer(t)
	fillAcceptedGapCapacity(t, srv, 1)
	d := srv.dedup
	gap := d.Check(testStream, 2*maxMissingRanges+3)
	d.claimGap(testStream, output.Source{VM: "full-vm"}, gap.GapFirst, gap.GapLast, gap.GapVersion)

	other := streamKey{peer: "cid:103", boot: "other"}
	accept(t, d, other, 1)
	gap = d.Check(other, 3)
	claim, ok := d.claimGap(other, output.Source{VM: "other-vm"}, 2, 2, gap.GapVersion)
	if !ok {
		t.Fatal("other stream gap was not claimable")
	}
	d.finishGap(claim, false)
	d.Commit(other, 3)
	srv.retryPendingGaps(t.Context())
	if got := len(sink.internals()); got != maxMissingRanges+1 {
		t.Fatalf("gap reports = %d, want one additional report from the other stream", got)
	}
	if got := d.ResumeFrom(other); got != 3 {
		t.Fatalf("other stream remained blocked at %d", got)
	}
	if d.readiness() == nil {
		t.Fatal("other stream success hid the gap still waiting for accounting capacity")
	}
}

func TestGapRetryAtCapacityCanAccountForLostFirstEvent(t *testing.T) {
	srv, sink := newGapCapacityServer(t)
	// Retain 64 disjoint losses at 3, 5, ... with sequence 2 durably held.
	// A report for the lost sequence 1 cannot merge directly with those ranges,
	// but it can immediately advance the watermark and consume them all.
	fillAcceptedGapCapacity(t, srv, 2)
	d := srv.dedup
	gap := d.CheckReplay(testStream, 2)
	if !gap.Gap || gap.GapFirst != 1 || gap.GapLast != 1 {
		t.Fatalf("first-event loss = %+v", gap)
	}
	claim, ok := d.claimGap(testStream, output.Source{VM: "original-vm"}, 1, 1, gap.GapVersion)
	if !ok {
		t.Fatal("full accounting ledger blocked the report that would drain it")
	}
	if got := d.ResumeFrom(testStream); got != 0 {
		t.Fatalf("claim advanced ACK to %d before output acceptance", got)
	}
	if !srv.publishGap(t.Context(), claim, "first event no longer replayable") {
		t.Fatal("first-event report was rejected")
	}
	srv.retryPendingGaps(t.Context())
	if got := len(sink.internals()); got != maxMissingRanges+1 {
		t.Fatalf("gap reports after HELLO recovery = %d", got)
	}
	if got := d.ResumeFrom(testStream); got != 2*maxMissingRanges+2 {
		t.Fatalf("HELLO recovery ACK = %d, want %d", got, 2*maxMissingRanges+2)
	}
	if err := d.readiness(); err != nil {
		t.Fatalf("accepted first-event loss did not restore readiness: %v", err)
	}
}

func newGapCapacityServer(t *testing.T) (*Server, *fakeSink) {
	t.Helper()
	sink := newFakeSink()
	srv, err := New(Options{
		Config: config.DefaultHost(), Sink: sink,
		Listener: newPipeListener(), Logger: logging.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, sink
}

func fillAcceptedGapCapacity(t *testing.T, srv *Server, start uint64) {
	t.Helper()
	d := srv.dedup
	d.Check(testStream, 1) // Retain an early uncommitted event below every loss.
	if start > 1 {
		d.Check(testStream, start)
		d.Commit(testStream, start)
	}
	for i := uint64(1); i <= maxMissingRanges; i++ {
		seq := start + i*2
		gap := d.Check(testStream, seq)
		claim, ok := d.claimGap(testStream, output.Source{VM: "original-vm"},
			gap.GapFirst, gap.GapLast, gap.GapVersion)
		if !ok || !srv.publishGap(t.Context(), claim, "seeding accepted gap evidence") {
			t.Fatalf("gap %d could not be published", i)
		}
		d.Commit(testStream, seq)
	}
	if got := d.ResumeFrom(testStream); got != 0 {
		t.Fatalf("accepted gaps crossed uncommitted sequence 1: ACK=%d", got)
	}
}
