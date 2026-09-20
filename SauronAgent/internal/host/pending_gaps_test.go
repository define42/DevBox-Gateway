package host

import (
	"sync"
	"testing"

	"github.com/define42/SauronAgent/internal/output"
)

func TestGapPublicationPinsStreamAndRejectsRecoveredRange(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	gap := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	source := output.Source{
		CID: 102, VM: "original-vm", Labels: map[string]string{"owner": "original-owner"},
		Reported: &output.Reported{BootID: "boot-a"},
	}
	publication, ok := d.claimGap(testStream, source, 2, 2, gap.GapVersion)
	if !ok {
		t.Fatal("pending gap was not claimable")
	}
	source.Labels["owner"] = "replacement-owner"
	source.Reported.BootID = "boot-b"
	if publication.source.Labels["owner"] != "original-owner" || publication.source.Reported.BootID != "boot-a" {
		t.Fatalf("publication did not preserve original attribution: %+v", publication.source)
	}
	if _, ok := d.claimGap(testStream, source, 2, 2, gap.GapVersion); ok {
		t.Fatal("same gap was claimed by concurrent publishers")
	}

	// The delayed event wins over an in-flight loss report. Its arrival removes
	// the evidence, but the claim still pins the stream until sink I/O finishes.
	if result := d.Check(testStream, 2); result.Gap || result.Blocked {
		t.Fatalf("recovered event = %+v, want an accepted original", result)
	}
	other := streamKey{peer: "cid:102", boot: "boot-b"}
	if result := d.Check(other, 1); !result.Blocked {
		t.Fatal("stream was evicted while its stale publication was in flight")
	}
	if d.finishGap(publication, true) {
		t.Fatal("accepted sink write accounted for evidence invalidated by recovery")
	}
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("stale publication advanced ResumeFrom to %d, want 1", resume)
	}
	if result := d.Check(other, 1); result.Blocked {
		t.Fatal("completed stale publication still pins the stream")
	}
}

func TestGapSourceResetsAfterPendingGenerationDrains(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	firstGap := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	firstSource := output.Source{
		VM: "original-vm", Labels: map[string]string{"owner": "original-owner"},
		Reported: &output.Reported{BootID: "boot-a"},
	}
	first, ok := d.claimGap(
		testStream, firstSource, firstGap.GapFirst, firstGap.GapLast, firstGap.GapVersion,
	)
	if !ok || !d.finishGap(first, true) {
		t.Fatal("first gap publication was not accepted")
	}

	secondGap := d.Check(testStream, 5)
	d.Commit(testStream, 5)
	secondSource := output.Source{
		VM: "replacement-vm", Labels: map[string]string{"owner": "replacement-owner"},
		Reported: &output.Reported{BootID: "boot-a", Hostname: "replacement-guest"},
	}
	second, ok := d.claimGap(
		testStream, secondSource, secondGap.GapFirst, secondGap.GapLast, secondGap.GapVersion,
	)
	if !ok {
		t.Fatal("second gap publication was not claimable")
	}
	if second.source.VM != "replacement-vm" || second.source.Labels["owner"] != "replacement-owner" ||
		second.source.Reported == nil || second.source.Reported.Hostname != "replacement-guest" {
		t.Fatalf("new gap generation retained stale attribution: %+v", second.source)
	}
	d.finishGap(second, false)
}

func TestStaleCheckCannotClaimOrAttributeRecreatedStream(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	stale := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	if result := d.Check(testStream, 2); result.Gap || result.Blocked {
		t.Fatalf("recovering old range = %+v", result)
	}
	d.Commit(testStream, 2)

	// Evict and recreate the same key, then form the same numeric gap in its
	// first generation. The stream identity must distinguish the two results.
	other := streamKey{peer: "cid:103", boot: "other"}
	accept(t, d, other, 1)
	accept(t, d, testStream, 1)
	current := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	if _, ok := d.claimGap(testStream, output.Source{VM: "stale-vm"}, 2, 2, stale.GapVersion); ok {
		t.Fatal("stale Check result claimed a recreated stream")
	}
	publication, ok := d.claimGap(
		testStream, output.Source{VM: "current-vm"}, 2, 2, current.GapVersion,
	)
	if !ok || publication.source.VM != "current-vm" {
		t.Fatalf("current publication = %+v, %t; stale source poisoned attribution", publication, ok)
	}
	d.finishGap(publication, false)
}

func TestStalePublicationCannotCompleteRecreatedRange(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	oldGap := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	old, ok := d.claimGap(testStream, output.Source{VM: "old-vm"}, 2, 2, oldGap.GapVersion)
	if !ok {
		t.Fatal("old generation was not claimable")
	}

	// Recovery drains generation one. A reconnect can then establish the same
	// numeric range as genuinely unreplayable generation-two evidence.
	d.Check(testStream, 2)
	newGap := d.CheckReplay(testStream, 3)
	assertDedupPendingGap(t, newGap, 2, 2)
	newSource := output.Source{VM: "new-vm"}
	if _, ok := d.claimGap(testStream, newSource, 2, 2, newGap.GapVersion); ok {
		t.Fatal("new generation bypassed the old publication claim")
	}
	if d.finishGap(old, true) {
		t.Fatal("old publication completed a recreated range")
	}
	if resume := d.ResumeFrom(testStream); resume != 1 {
		t.Fatalf("old publication advanced recreated range to %d, want 1", resume)
	}
	current, ok := d.takeNextPendingGap(testStream)
	if !ok || current.source.VM != "new-vm" {
		t.Fatalf("recreated range claim = %+v, %t; want new source", current, ok)
	}
	d.finishGap(current, false)
}

func TestConcurrentGapClaimsPublishOnceAndMissingIsIdempotent(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	d.Check(testStream, 2) // Failed output keeps the watermark below the gap.
	gap := d.Check(testStream, 4)
	d.Commit(testStream, 4)

	const publishers = 32
	claims := make(chan gapPublication, publishers)
	var group sync.WaitGroup
	for range publishers {
		group.Go(func() {
			if publication, ok := d.claimGap(
				testStream, output.Source{VM: "vm"}, 3, 3, gap.GapVersion,
			); ok {
				claims <- publication
			}
		})
	}
	group.Wait()
	close(claims)
	var publications []gapPublication
	for publication := range claims {
		publications = append(publications, publication)
	}
	if len(publications) != 1 {
		t.Fatalf("concurrent claims = %d, want exactly one", len(publications))
	}
	if !d.finishGap(publications[0], true) {
		t.Fatal("winning publication was not accounted")
	}

	// Defensive idempotence keeps even accidental late completions from using
	// one bounded missing slot each while an earlier failed event blocks absorb.
	for range maxMissingRanges * 2 {
		d.NoteMissing(testStream, 3, 3)
	}
	d.mu.Lock()
	missing := append([]seqRange(nil), d.streams[testStream].missing...)
	d.mu.Unlock()
	if len(missing) != 1 || missing[0] != (seqRange{first: 3, last: 3}) {
		t.Fatalf("idempotent missing ledger = %+v, want one 3..3 range", missing)
	}
}

func TestPendingGapRetryFailurePreservesEvidenceAndRotatesStreams(t *testing.T) {
	d := newDedup(1024, 2)
	other := streamKey{peer: "cid:103", boot: "other"}
	for _, key := range []streamKey{testStream, other} {
		accept(t, d, key, 1)
		gap := d.Check(key, 3)
		d.Commit(key, 3)
		publication, ok := d.claimGap(key, output.Source{VM: key.peer}, 2, 2, gap.GapVersion)
		if !ok {
			t.Fatalf("seeding source for %v", key)
		}
		d.finishGap(publication, false)
	}
	first, ok := d.takePendingGap()
	if !ok || first.key != testStream {
		t.Fatalf("first retry = %+v, %t; want oldest stream", first, ok)
	}
	// A failed write releases only its claim, never its evidence, and rotating
	// the use clock lets the other stream run on the next recovery admission.
	d.finishGap(first, false)
	second, ok := d.takePendingGap()
	if !ok || second.key != other {
		t.Fatalf("failed report starved another stream: %+v, %t", second, ok)
	}
	d.finishGap(second, false)
	for _, key := range []streamKey{testStream, other} {
		assertDedupPendingGap(t, d.CheckReplay(key, 0), 2, 2)
		if resume := d.ResumeFrom(key); resume != 1 {
			t.Fatalf("failed retry changed %v acknowledgement to %d", key, resume)
		}
	}
}

func TestLateGapCompletionDoesNotAffectEvictedStream(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	gap := d.Check(testStream, 3)
	d.Commit(testStream, 3)
	publication, ok := d.claimGap(testStream, output.Source{VM: "old-vm"}, 2, 2, gap.GapVersion)
	if !ok || !d.finishGap(publication, true) {
		t.Fatal("old stream gap was not accepted")
	}
	other := streamKey{peer: "cid:102", boot: "boot-b"}
	accept(t, d, other, 1)

	if d.finishGap(publication, true) {
		t.Fatal("duplicate late completion was accepted")
	}
	if resume := d.ResumeFrom(other); resume != 1 {
		t.Fatalf("late report changed new stream ResumeFrom to %d, want 1", resume)
	}
	if result := d.Check(other, 1); !result.Duplicate {
		t.Fatal("late report discarded the new stream's delivery history")
	}
}
