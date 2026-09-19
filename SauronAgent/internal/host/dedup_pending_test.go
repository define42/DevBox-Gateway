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
