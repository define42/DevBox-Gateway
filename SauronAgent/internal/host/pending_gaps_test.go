package host

import (
	"testing"

	"github.com/define42/SauronAgent/internal/output"
)

func TestPendingGapSnapshotPinsStreamAndPreservesSource(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	for i := uint64(1); i <= maxMissingRanges; i++ {
		d.Check(testStream, 2*i+1)
		d.Commit(testStream, 2*i+1)
	}
	source := output.Source{
		CID: 102, VM: "original-vm", Labels: map[string]string{"owner": "original-owner"},
		Reported: &output.Reported{BootID: "boot-a"},
	}
	d.rememberGapSource(testStream, source)
	source.Labels["owner"] = "replacement-owner"
	source.Reported.BootID = "boot-b"
	reports, ok := d.takePendingGaps()
	if !ok || len(reports.ranges) != maxMissingRanges {
		t.Fatalf("retained snapshot = %d ranges, %t; want %d ranges", len(reports.ranges), ok, maxMissingRanges)
	}
	if reports.source.Labels["owner"] != "original-owner" || reports.source.Reported.BootID != "boot-a" {
		t.Fatalf("snapshot did not preserve original attribution: %+v", reports.source)
	}
	if _, ok := d.takePendingGaps(); ok {
		t.Fatal("same stream was claimed by concurrent recovery attempts")
	}
	// Concurrent ordinary delivery may resolve all gaps while the snapshot's
	// sink write is in progress. Keep its stream alive until that write ends.
	for _, gap := range reports.ranges {
		d.NoteMissing(reports.key, gap.first, gap.last)
	}
	other := streamKey{peer: "cid:102", boot: "boot-b"}
	if result := d.Check(other, 1); !result.Blocked {
		t.Fatal("stream was evicted while its retained reports were being written")
	}
	d.finishPendingGaps(reports.key)
	if result := d.Check(other, 1); result.Blocked {
		t.Fatal("completed snapshot still blocks admission")
	}
}

func TestPendingGapRetryFailurePreservesEvidenceAndRotatesStreams(t *testing.T) {
	d := newDedup(1024, 2)
	other := streamKey{peer: "cid:103", boot: "other"}
	for _, key := range []streamKey{testStream, other} {
		accept(t, d, key, 1)
		d.Check(key, 3)
		d.Commit(key, 3)
		d.rememberGapSource(key, output.Source{VM: key.peer})
	}
	first, ok := d.takePendingGaps()
	if !ok || first.key != testStream {
		t.Fatalf("first retry = %+v, %t; want oldest stream", first, ok)
	}
	// A failed write releases only the in-flight claim, never its evidence.
	d.finishPendingGaps(first.key)
	second, ok := d.takePendingGaps()
	if !ok || second.key != other {
		t.Fatalf("failed report starved another stream: %+v, %t", second, ok)
	}
	d.finishPendingGaps(second.key)
	for _, key := range []streamKey{testStream, other} {
		assertDedupPendingGap(t, d.CheckReplay(key, 0), 2, 2)
		if resume := d.ResumeFrom(key); resume != 1 {
			t.Fatalf("failed retry changed %v acknowledgement to %d", key, resume)
		}
	}
}

func TestLateGapCompletionDoesNotRecreateEvictedStream(t *testing.T) {
	d := newDedup(1024, 1)
	accept(t, d, testStream, 1)
	d.Check(testStream, 3)
	d.Commit(testStream, 3)
	d.NoteMissing(testStream, 2, 2)
	other := streamKey{peer: "cid:102", boot: "boot-b"}
	accept(t, d, other, 1)

	// Another writer was already publishing the same old gap when recovery
	// succeeded. Completing that duplicate must leave the new stream intact.
	d.NoteMissing(testStream, 2, 2)
	if resume := d.ResumeFrom(other); resume != 1 {
		t.Fatalf("late report evicted new stream: ResumeFrom=%d, want 1", resume)
	}
	if result := d.Check(other, 1); !result.Duplicate {
		t.Fatal("late report discarded the new stream's delivery history")
	}
}
