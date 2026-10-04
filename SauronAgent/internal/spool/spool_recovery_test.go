package spool

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAckCheckpointFailureRetainsRecordsAndRetries(t *testing.T) {
	for _, failure := range []string{"create", "write", "rename"} {
		for _, ack := range []uint64{3, 4} {
			t.Run(failure+"/"+segmentName(ack), func(t *testing.T) {
				dir := t.TempDir()
				opts := Options{Dir: dir, SegmentSize: 2 * recordBytes(t), SyncOnWrite: true}
				sp := mustOpen(t, opts)
				appendRange(t, sp, 1, 4)
				beforeBytes := sp.Bytes()
				blocker := filepath.Join(dir, checkpointTemp)
				switch failure {
				case "write":
					if _, err := os.Stat("/dev/full"); err != nil {
						t.Skip("/dev/full is unavailable")
					}
					if err := os.Symlink("/dev/full", blocker); err != nil {
						t.Fatal(err)
					}
				case "rename":
					blocker = filepath.Join(dir, checkpointName)
					fallthrough
				default:
					if err := os.Mkdir(blocker, dirMode); err != nil {
						t.Fatal(err)
					}
				}

				if err := sp.Ack(ack); err == nil {
					t.Fatal("Ack succeeded while checkpoint persistence was blocked")
				}
				if sp.PendingCount() != 4 || sp.FirstUnacked() != 1 || sp.LastSequence() != 4 || sp.Bytes() != beforeBytes {
					t.Fatalf("failed ACK changed backlog: pending=%d first=%d last=%d bytes=%d",
						sp.PendingCount(), sp.FirstUnacked(), sp.LastSequence(), sp.Bytes())
				}
				wantSeqs(t, nextSeqs(t, sp, 10), 1, 2, 3, 4)
				// Failed writes remove the temporary file; recreate the fault
				// to show an identical ACK still attempts persistence.
				if failure == "write" {
					if err := os.Symlink("/dev/full", blocker); err != nil {
						t.Fatal(err)
					}
				}
				if err := sp.Ack(ack); err == nil {
					t.Fatal("repeated ACK forgot the failed checkpoint")
				}
				if err := os.Remove(blocker); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := sp.Ack(ack); err != nil {
					t.Fatalf("retry after storage recovery: %v", err)
				}
				if got := sp.PendingCount(); got != 4-int(ack) {
					t.Fatalf("pending after retry = %d, want %d", got, 4-int(ack))
				}
				if err := sp.Close(); err != nil {
					t.Fatal(err)
				}

				recovered := mustOpen(t, opts)
				if got := recovered.LastSequence(); got != 4 {
					t.Fatalf("last sequence after reopening = %d, want 4", got)
				}
				if got := recovered.PendingCount(); got != 4-int(ack) {
					t.Fatalf("pending after reopening = %d, want %d", got, 4-int(ack))
				}
				appendRange(t, recovered, 5, 5)
				if ack == 3 {
					wantSeqs(t, nextSeqs(t, recovered, 10), 4, 5)
				} else {
					wantSeqs(t, nextSeqs(t, recovered, 10), 5)
				}
			})
		}
	}
}

func TestCheckpointFailureRecoveryPreservesSequenceWithTornTail(t *testing.T) {
	for _, tail := range []string{"same segment", "empty rollover", "torn rollover"} {
		t.Run(tail, func(t *testing.T) {
			dir := t.TempDir()
			opts := Options{Dir: dir, SyncOnWrite: true}
			sp := mustOpen(t, opts)
			appendRange(t, sp, 1, 3)
			if err := sp.Ack(1); err != nil {
				t.Fatal(err)
			}
			blocker := filepath.Join(dir, checkpointTemp)
			if err := os.Mkdir(blocker, dirMode); err != nil {
				t.Fatal(err)
			}
			if err := sp.Ack(3); err == nil {
				t.Fatal("expected checkpoint failure")
			}
			path := filepath.Join(dir, segmentName(1))
			if tail != "same segment" {
				path = filepath.Join(dir, segmentName(4))
			}
			if err := sp.Close(); err != nil {
				t.Fatal(err)
			}
			// Model a crash after creating the next segment or halfway through
			// its first record. Recovery must keep the preceding high-water mark.
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
			if err != nil {
				t.Fatal(err)
			}
			if tail != "empty rollover" {
				if _, err := f.Write([]byte("SREC\x00")); err != nil {
					f.Close()
					t.Fatal(err)
				}
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			// Leave the checkpoint fault in place across the restart.
			recovered := mustOpen(t, opts)
			if got := recovered.LastSequence(); got != 3 {
				t.Fatalf("last sequence after recovery = %d, want 3", got)
			}
			wantSeqs(t, nextSeqs(t, recovered, 10), 2, 3)
			appendRange(t, recovered, 4, 4)
			if err := os.Remove(blocker); err != nil {
				t.Fatal(err)
			}
			if err := recovered.Ack(3); err != nil {
				t.Fatal(err)
			}
			wantSeqs(t, nextSeqs(t, recovered, 10), 4)
		})
	}
}

func TestAckRetriesPartlyCompletedSegmentCleanup(t *testing.T) {
	dir := t.TempDir()
	opts := Options{Dir: dir, SegmentSize: recordBytes(t), SyncOnWrite: true}
	sp := mustOpen(t, opts)
	appendRange(t, sp, 1, 3)
	blockedPath := filepath.Join(dir, segmentName(2))
	backupPath := blockedPath + ".saved"
	if err := os.Rename(blockedPath, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blockedPath, dirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedPath, "block"), nil, fileMode); err != nil {
		t.Fatal(err)
	}
	if err := sp.Ack(3); err == nil {
		t.Fatal("expected segment cleanup failure")
	}
	if got := sp.PendingCount(); got != 2 {
		t.Fatalf("pending after partial cleanup = %d, want 2", got)
	}
	if got := sp.FirstUnacked(); got != 2 {
		t.Fatalf("retry cursor after partial cleanup = %d, want 2", got)
	}
	if err := os.RemoveAll(blockedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backupPath, blockedPath); err != nil {
		t.Fatal(err)
	}
	if err := sp.Ack(3); err != nil {
		t.Fatalf("retry the same ACK: %v", err)
	}
	if sp.PendingCount() != 0 || sp.Bytes() != 0 {
		t.Fatalf("cleanup did not finish: pending=%d bytes=%d", sp.PendingCount(), sp.Bytes())
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	recovered := mustOpen(t, opts)
	if got := recovered.LastSequence(); got != 3 {
		t.Fatalf("empty spool last sequence = %d, want 3", got)
	}
}

func TestEvictionRequiresDurableNewestSegment(t *testing.T) {
	dir := t.TempDir()
	size := recordBytes(t)
	sp := mustOpen(t, Options{Dir: dir, SegmentSize: size, MaxSize: 3 * size})
	appendRange(t, sp, 1, 2)
	// A closed descriptor makes the pending fsync fail, as a storage failure
	// would. Shrink the cap to request eviction without performing another write.
	if err := sp.w.Close(); err != nil {
		t.Fatal(err)
	}
	sp.opts.MaxSize = size
	if err := sp.enforceMaxSize(); err == nil {
		t.Fatal("eviction succeeded without syncing the newest segment")
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 1, 2)
	f, err := os.OpenFile(sp.active().path, os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		t.Fatal(err)
	}
	sp.w = f
	if err := sp.enforceMaxSize(); err != nil {
		t.Fatal(err)
	}
	wantSeqs(t, nextSeqs(t, sp, 10), 2)
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	recovered := mustOpen(t, Options{Dir: dir, SegmentSize: size, MaxSize: size})
	if got := recovered.LastSequence(); got != 2 {
		t.Fatalf("last sequence after eviction and restart = %d, want 2", got)
	}
}
