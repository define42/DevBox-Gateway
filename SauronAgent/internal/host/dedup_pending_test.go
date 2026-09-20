package host

import (
	"sync"
	"testing"
)

func TestDedupGapRequiresAcceptedReportBeforeAcknowledgement(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	gap := d.Check(testStream, 3)
	assertDedupPendingGap(t, gap, 2, 2)
	if ack, _ := d.Commit(testStream, 3); ack != 1 {
		t.Fatalf("ACK = %d before loss report was accepted, want 1", ack)
	}
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("ResumeFrom = %d before loss report was accepted, want 1", resume)
	}

	retry := d.Check(testStream, 3)
	assertDedupPendingGap(t, retry, 2, 2)
	if !retry.Duplicate {
		t.Fatal("durable event should be suppressed while its gap report is retried")
	}
	d.NoteMissing(testStream, retry.GapFirst, retry.GapLast)
	if resume := d.ResumeFrom(testStream); resume != 3 {
		t.Fatalf("ResumeFrom = %d after accepted report, want 3", resume)
	}
	if retry := d.Check(testStream, 3); retry.Gap || !retry.Duplicate {
		t.Fatalf("retry after accepted report = %+v", retry)
	}
}

func TestDedupGapRetryDoesNotCoverEarlierFailedEvent(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	d.Check(testStream, 2) // Ordinary event output failed; the guest still holds it.
	assertDedupPendingGap(t, d.Check(testStream, 4), 3, 3)
	d.Commit(testStream, 4)
	assertDedupPendingGap(t, d.Check(testStream, 4), 3, 3)
	d.NoteMissing(testStream, 3, 3)
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("accepted gap report acknowledged failed event 2: ResumeFrom=%d", resume)
	}
	if result, ack := accept(t, d, testStream, 2); result.Gap || result.Duplicate || ack != 4 {
		t.Fatalf("retrying failed event = %+v, ACK=%d, want accepted through 4", result, ack)
	}
}

func TestDedupRecoveredArrivalIsExcludedFromPendingGap(t *testing.T) {
	tests := []struct {
		name         string
		high         uint64
		arrival      uint64
		wantGap      bool
		wantGapFirst uint64
		wantGapLast  uint64
	}{
		{name: "only missing sequence", high: 3, arrival: 2},
		{name: "first in range", high: 5, arrival: 2, wantGap: true, wantGapFirst: 3, wantGapLast: 4},
		{name: "middle of range", high: 5, arrival: 3, wantGap: true, wantGapFirst: 2, wantGapLast: 2},
		{name: "last in range", high: 5, arrival: 4, wantGap: true, wantGapFirst: 2, wantGapLast: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDedup(1024, 16)
			accept(t, d, testStream, 1)
			d.Check(testStream, tt.high)
			d.Commit(testStream, tt.high)

			result := d.Check(testStream, tt.arrival)
			if result.Gap != tt.wantGap || result.GapFirst != tt.wantGapFirst || result.GapLast != tt.wantGapLast {
				t.Fatalf("recovered arrival = %+v, want gap=%t %d..%d",
					result, tt.wantGap, tt.wantGapFirst, tt.wantGapLast)
			}
			if result.Gap {
				d.NoteMissing(testStream, result.GapFirst, result.GapLast)
			}
			if resume := d.ResumeFrom(testStream); resume >= tt.arrival {
				t.Fatalf("ResumeFrom = %d, must remain below unwritten arrival %d", resume, tt.arrival)
			}
		})
	}
}

func TestDedupRecoveredArrivalFailsClosedAtPendingRangeLimit(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	d.Check(testStream, 5) // The first pending range is 2..4.
	d.Commit(testStream, 5)
	for sequence := uint64(7); sequence < 7+2*(maxMissingRanges-1); sequence += 2 {
		result := d.Check(testStream, sequence)
		if result.Blocked {
			t.Fatalf("building pending range before the limit at sequence %d: %+v", sequence, result)
		}
		d.Commit(testStream, sequence)
	}

	// Splitting 2..4 around the recovered sequence 3 would create a 65th
	// range. Refuse the arrival and report different evidence instead of either
	// exceeding the bound or calling sequence 3 missing.
	blocked := d.Check(testStream, 3)
	if !blocked.Blocked || !blocked.Gap {
		t.Fatalf("arrival at pending range limit = %+v, want a blocked safe gap", blocked)
	}
	if blocked.GapFirst <= 3 && 3 <= blocked.GapLast {
		t.Fatalf("blocked gap %d..%d covers arriving sequence 3", blocked.GapFirst, blocked.GapLast)
	}
	d.NoteMissing(testStream, blocked.GapFirst, blocked.GapLast)

	retry := d.Check(testStream, 3)
	if retry.Blocked {
		t.Fatalf("accepted gap evidence did not make room for retry: %+v", retry)
	}
	if retry.Gap && retry.GapFirst <= 3 && 3 <= retry.GapLast {
		t.Fatalf("retry gap %d..%d covers arriving sequence 3", retry.GapFirst, retry.GapLast)
	}
}

func TestDedupHelloGapAfterFirstWriteFailure(t *testing.T) {
	d := newDedup(1024, 16)
	d.Check(testStream, 1) // No successful write, so ResumeFrom is still zero.
	assertDedupPendingGap(t, d.CheckReplay(testStream, 3), 1, 2)
	if resume := d.ResumeFrom(testStream); resume != 0 {
		t.Fatalf("unwritten HELLO loss report moved ResumeFrom to %d", resume)
	}
	// A later HELLO that omits first_sequence must still retry the evidence.
	assertDedupPendingGap(t, d.CheckReplay(testStream, 0), 1, 2)
	d.NoteMissing(testStream, 1, 2)
	if result, ack := accept(t, d, testStream, 3); result.Gap || ack != 3 {
		t.Fatalf("after accepted HELLO report = %+v, ACK=%d", result, ack)
	}
	unknown := streamKey{peer: "cid:103", boot: "unknown"}
	if result := d.CheckReplay(unknown, 200); result.Gap || result.Blocked {
		t.Fatalf("a previously unknown stream reported prehistory as lost: %+v", result)
	}
}

func TestDedupPendingEvidenceIsBoundedWithoutForgetting(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	for i := uint64(1); i <= maxMissingRanges; i++ {
		if result := d.Check(testStream, 2*i+1); result.Blocked {
			t.Fatalf("pending range %d unexpectedly rejected", i)
		}
	}
	next := uint64(2*maxMissingRanges + 3)
	if result := d.Check(testStream, next); !result.Blocked || !result.Gap || result.GapFirst != 2 {
		t.Fatalf("overflow must refuse the arrival and offer existing evidence for retry: %+v", result)
	}
	d.mu.Lock()
	count := len(d.streams[testStream].pending)
	highest := d.streams[testStream].highest
	d.mu.Unlock()
	if count != maxMissingRanges || highest != next-2 {
		t.Fatalf("overflow changed retained evidence: ranges=%d highest=%d", count, highest)
	}
	d.NoteMissing(testStream, 2, 2)
	if result := d.Check(testStream, next); result.Blocked {
		t.Fatal("accepting one pending report did not restore capacity")
	}
	assertDedupPendingGap(t, d.CheckReplay(testStream, 0), 4, 4)
}

func TestDedupCannotEvictUnreportedGapEvidence(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	d.Check(testStream, 3)
	d.Commit(testStream, 3)
	other := streamKey{peer: "cid:103", boot: "other"}
	if result := d.Check(other, 1); !result.Blocked {
		t.Fatal("new stream displaced an unresolved loss report")
	}
	assertDedupPendingGap(t, d.CheckReplay(testStream, 0), 2, 2)
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("pinned stream's ResumeFrom = %d, want 1", resume)
	}
	d.NoteMissing(testStream, 2, 2)
	if result := d.Check(other, 1); result.Blocked {
		t.Fatal("persisted loss report did not release the stream's eviction pin")
	}
}

func TestDedupMergedGapSurvivesPartialReportCompletion(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	d.Check(testStream, 3) // A report for 2 is in flight.
	assertDedupPendingGap(t, d.CheckReplay(testStream, 5), 2, 4)
	d.NoteMissing(testStream, 2, 2) // The earlier, smaller report completes.
	assertDedupPendingGap(t, d.CheckReplay(testStream, 0), 3, 4)
	if resume := d.ResumeFrom(testStream); resume != 2 {
		t.Fatalf("partial report acknowledged unreported loss: ResumeFrom=%d", resume)
	}
	d.NoteMissing(testStream, 3, 4)
	if result, ack := accept(t, d, testStream, 5); result.Gap || ack != 5 {
		t.Fatalf("after complete report = %+v, ACK=%d", result, ack)
	}
}

func TestDedupConcurrentArrivalsDoNotAcknowledgePendingLoss(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	var group sync.WaitGroup
	for i := uint64(1); i <= 16; i++ {
		group.Go(func() {
			d.Check(testStream, 2*i+1)
			d.Commit(testStream, 2*i+1)
		})
	}
	group.Wait()
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("concurrent writes crossed unresolved gap: ResumeFrom=%d", resume)
	}
	for result := d.CheckReplay(testStream, 0); result.Gap; result = d.CheckReplay(testStream, 0) {
		d.NoteMissing(testStream, result.GapFirst, result.GapLast)
	}
	if resume := d.ResumeFrom(testStream); resume != 33 {
		t.Fatalf("accepted reports did not release durable events: ResumeFrom=%d", resume)
	}
}

func TestDedupHelloDoesNotReportDurableOutOfOrderEventsMissing(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	d.Check(testStream, 2) // Failed output, later discarded by the guest.
	accept(t, d, testStream, 3)
	d.Check(testStream, 4)
	accept(t, d, testStream, 5)
	assertDedupPendingGap(t, d.CheckReplay(testStream, 6), 2, 2)
	d.NoteMissing(testStream, 2, 2)
	assertDedupPendingGap(t, d.CheckReplay(testStream, 0), 4, 4)
	d.NoteMissing(testStream, 4, 4)
	if resume := d.ResumeFrom(testStream); resume != 5 {
		t.Fatalf("accepted reports did not account for intervening held events: ResumeFrom=%d", resume)
	}
}

func TestDedupReceivingMissingEventReleasesPendingEvidence(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	d.Check(testStream, 3)
	d.Commit(testStream, 3)
	d.Check(testStream, 2)
	if ack, _ := d.Commit(testStream, 2); ack != 3 {
		t.Fatalf("recovered missing event did not close the hole: ACK=%d", ack)
	}
	if result := d.CheckReplay(testStream, 0); result.Gap {
		t.Fatalf("a fully recovered gap still requires loss evidence: %+v", result)
	}
	other := streamKey{peer: "cid:103", boot: "other"}
	if result := d.Check(other, 1); result.Blocked {
		t.Fatal("recovered stream remained pinned against eviction")
	}
}

func assertDedupPendingGap(t *testing.T, result dedupResult, first, last uint64) {
	t.Helper()
	if result.Blocked || !result.Gap || result.GapFirst != first || result.GapLast != last {
		t.Fatalf("gap = %+v, want pending %d..%d", result, first, last)
	}
}
