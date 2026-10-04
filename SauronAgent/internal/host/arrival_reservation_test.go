package host

import (
	"testing"

	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
)

func TestArrivalReservationKeepsDuplicateReferencesProtected(t *testing.T) {
	d := newDedup(64, 1)
	accept(t, d, testStream, 1)
	first := reserveTestArrival(t, d, 2)
	second := reserveTestArrival(t, d, 2)
	first.release()
	if refs := second.stream.arrivals[2]; refs != 1 {
		t.Fatalf("remaining original references = %d, want 1", refs)
	}
	gap := d.CheckReplay(testStream, 4)
	assertDedupPendingGap(t, gap, 3, 3)
	publication, ok := d.claimGap(testStream, output.Source{}, gap.GapFirst, gap.GapLast, gap.GapVersion)
	if !ok || !d.finishGap(publication, true) {
		t.Fatal("loss beyond the received original was not publishable")
	}
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("loss report acknowledged the remaining original: %d", resume)
	}
	if gap := d.CheckReplay(testStream, 4); gap.Gap {
		t.Fatalf("HELLO classified the remaining original as missing: %+v", gap)
	}
	second.release()
	if len(second.stream.arrivals) != 0 {
		t.Fatal("finished originals retained their reservations")
	}
	if result := d.Check(testStream, 2); result.Duplicate {
		t.Fatal("releasing the last reservation marked an unwritten original accepted")
	}
	if ack, _ := d.Commit(testStream, 2); ack != 3 {
		t.Fatalf("accepted original did not close the reported hole: ACK %d, want 3", ack)
	}
}

func TestReleasedArrivalInvalidatesInflightGapClaim(t *testing.T) {
	d := newDedup(64, 1)
	accept(t, d, testStream, 1)
	gap := d.Check(testStream, 5)
	d.Commit(testStream, 5)
	publication, ok := d.claimGap(testStream, output.Source{}, gap.GapFirst, gap.GapLast, gap.GapVersion)
	if !ok {
		t.Fatal("initial gap was not claimable")
	}
	reservation := reserveTestArrival(t, d, 3)
	// Releasing without Commit models a gate timeout or rejected sink write.
	reservation.release()
	if d.finishGap(publication, true) {
		t.Fatal("released arrival reactivated its stale covering gap claim")
	}
	for {
		publication, ok := d.takePendingGap()
		if !ok {
			break
		}
		if publication.gap.first <= 3 && publication.gap.last >= 3 {
			t.Fatalf("background retry includes received original: %+v", publication.gap)
		}
		if !d.finishGap(publication, true) {
			t.Fatal("safe remainder was not accepted")
		}
	}
	if resume := d.ResumeFrom(testStream); resume != 2 {
		t.Fatalf("gap completion crossed rejected original: %d, want 2", resume)
	}
	if result := d.Check(testStream, 3); result.Duplicate {
		t.Fatal("rejected original cannot be replayed")
	}
	if ack, _ := d.Commit(testStream, 3); ack != 5 {
		t.Fatalf("replayed original ACK = %d, want 5", ack)
	}
}

func TestArrivalAtPendingRangeLimitSurvivesReleaseAndHello(t *testing.T) {
	d := newDedup(64, 1)
	accept(t, d, testStream, 1)
	for i := range maxMissingRanges {
		seq := uint64(5 + 2*i)
		if result := d.Check(testStream, seq); result.Blocked {
			t.Fatalf("fixture exceeded pending range capacity at sequence %d", seq)
		}
		d.Commit(testStream, seq)
	}
	gap := d.CheckReplay(testStream, 0)
	assertDedupPendingGap(t, gap, 2, 4)
	stale, ok := d.claimGap(testStream, output.Source{}, gap.GapFirst, gap.GapLast, gap.GapVersion)
	if !ok {
		t.Fatal("full-range fixture did not permit its original claim")
	}
	reservation := reserveTestArrival(t, d, 3)
	reservation.release()
	refs, protected := reservation.stream.arrivals[3]
	if !protected || refs != 0 {
		t.Fatal("range capacity discarded protection for a received, unaccepted original")
	}
	// The existing covering range cannot be split yet. A concurrent HELLO
	// must not restore that range's eligibility to account for sequence 3.
	gap = d.CheckReplay(testStream, uint64(6+2*(maxMissingRanges-1)))
	if !gap.Gap || gap.GapFirst <= 3 && gap.GapLast >= 3 {
		t.Fatalf("HELLO selected evidence covering the received original: %+v", gap)
	}
	if d.finishGap(stale, true) {
		t.Fatal("covering claim acknowledged a released but protected original")
	}
	prefix, ok := d.takePendingGap()
	if !ok || prefix.gap != (seqRange{first: 2, last: 2}) {
		t.Fatalf("safe prefix = %+v, available = %t", prefix.gap, ok)
	}
	if !d.finishGap(prefix, true) {
		t.Fatal("safe prefix did not create space for permanent exclusion")
	}
	if _, protected := reservation.stream.arrivals[3]; protected {
		t.Fatal("safe partial publication retained unnecessary arrival protection")
	}
	if resume := d.ResumeFrom(testStream); resume != 2 {
		t.Fatalf("partial publication crossed the received original: %d, want 2", resume)
	}
	if reservation.stream.pendingContains(3, 3) {
		t.Fatal("partial publication failed to remove the received original permanently")
	}
	if result := d.Check(testStream, 3); result.Duplicate || result.Blocked {
		t.Fatalf("original remained unreplayable after capacity recovery: %+v", result)
	}
	d.Commit(testStream, 3)
	for range maxMissingRanges {
		publication, ok := d.takePendingGap()
		if !ok {
			break
		}
		if !d.finishGap(publication, true) {
			t.Fatal("remaining gap failed after capacity recovery")
		}
	}
	if err := d.readiness(); err != nil {
		t.Fatalf("capacity did not recover after original acceptance and safe gaps: %v", err)
	}
	if resume := d.ResumeFrom(testStream); resume != uint64(5+2*(maxMissingRanges-1)) {
		t.Fatalf("recovered stream watermark = %d", resume)
	}
}

func TestArrivalReservationOverflowStopsLossAccounting(t *testing.T) {
	d := newDedup(64, 1)
	accept(t, d, testStream, 1)
	reservations := make([]*arrivalReservation, 0, 64)
	for seq := uint64(2); seq <= 65; seq++ {
		reservations = append(reservations, reserveTestArrival(t, d, seq))
	}
	gap := d.CheckReplay(testStream, 68)
	assertDedupPendingGap(t, gap, 66, 67)
	publication, ok := d.claimGap(testStream, output.Source{}, gap.GapFirst, gap.GapLast, gap.GapVersion)
	if !ok {
		t.Fatal("gap claim did not start before arrival capacity was exceeded")
	}
	if reservation, err := d.reserveArrival(testStream, 66, output.Source{}); err == nil {
		reservation.release()
		t.Fatal("arrival beyond the 64-record protection bound was accepted")
	}
	if d.finishGap(publication, true) {
		t.Fatal("overflow allowed an existing loss claim to acknowledge the refused original")
	}
	for _, reservation := range reservations {
		reservation.release()
	}
	if len(reservations[0].stream.arrivals) != 0 {
		t.Fatal("completed reservations retained their references after overflow")
	}
	if err := d.readiness(); err == nil {
		t.Fatal("releasing reservations cleared an untracked-original failure")
	}
	if _, ok := d.takePendingGap(); ok {
		t.Fatal("overflow permitted new loss accounting")
	}
	if result := d.Check(testStream, 66); !result.Blocked {
		t.Fatal("overflow allowed the untracked original to advance processing")
	}
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("overflow advanced acknowledgement to %d, want 1", resume)
	}
}

func reserveTestArrival(t *testing.T, d *dedup, seq uint64) *arrivalReservation {
	t.Helper()
	reservation, err := d.reserveArrival(testStream, seq, output.Source{VM: "original-vm"})
	if err != nil {
		t.Fatalf("reserve original sequence %d: %v", seq, err)
	}
	return reservation
}
