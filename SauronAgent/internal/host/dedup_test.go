package host

import "testing"

var testStream = streamKey{peer: "cid:102", boot: "boot-a"}

// accept is the ordinary path for an event the sinks took: check it, then
// record it.
func accept(t *testing.T, d *dedup, k streamKey, seq uint64) (dedupResult, uint64) {
	t.Helper()
	res := d.Check(k, seq)
	if res.Blocked {
		t.Fatal("accept: unresolved gap evidence exceeded the configured bounds")
	}
	if res.Gap {
		d.NoteMissing(k, res.GapFirst, res.GapLast)
	}
	if res.Duplicate {
		return res, d.ResumeFrom(k)
	}
	ack, _ := d.Commit(k, seq)
	return res, ack
}

func TestDedupInOrderStream(t *testing.T) {
	d := newDedup(1024, 16)

	// An agent that has been running for a week starts high. Nothing below the
	// first sequence was ever promised to anyone, so the watermark starts there.
	res, ack := accept(t, d, testStream, 184213)
	if res.Duplicate || res.Gap {
		t.Fatalf("first event on a new stream = %+v, want neither duplicate nor gap", res)
	}
	if ack != 184213 {
		t.Fatalf("ack = %d, want 184213", ack)
	}

	for seq := uint64(184214); seq <= 184220; seq++ {
		res, ack = accept(t, d, testStream, seq)
		if res.Duplicate || res.Gap {
			t.Fatalf("sequence %d = %+v", seq, res)
		}
		if ack != seq {
			t.Fatalf("ack after %d = %d", seq, ack)
		}
	}
	if got := d.ResumeFrom(testStream); got != 184220 {
		t.Fatalf("ResumeFrom = %d, want 184220", got)
	}
}

func TestDedupSuppressesReplay(t *testing.T) {
	d := newDedup(1024, 16)
	for seq := uint64(1); seq <= 5; seq++ {
		accept(t, d, testStream, seq)
	}

	for seq := uint64(1); seq <= 5; seq++ {
		if res := d.Check(testStream, seq); !res.Duplicate {
			t.Errorf("replayed sequence %d was not recognised as a duplicate", seq)
		}
	}
	// A duplicate does not move the acknowledgement point backwards.
	if got := d.ResumeFrom(testStream); got != 5 {
		t.Fatalf("ResumeFrom = %d, want 5", got)
	}
	// And the first genuinely new sequence after a replay is not a duplicate.
	if res := d.Check(testStream, 6); res.Duplicate || res.Gap {
		t.Fatalf("sequence 6 = %+v", res)
	}
}

func TestDedupBootIDAndPeerScopeTheStream(t *testing.T) {
	d := newDedup(1024, 16)
	for seq := uint64(1); seq <= 3; seq++ {
		accept(t, d, testStream, seq)
	}

	// A reboot restarts the sequence: same guest, different stream.
	rebooted := streamKey{peer: "cid:102", boot: "boot-b"}
	if res := d.Check(rebooted, 1); res.Duplicate {
		t.Error("sequence 1 after a reboot was suppressed as a duplicate")
	}
	// Another VM's numbering is its own. The CID half of the key is the half the
	// guest cannot choose, which is what keeps one guest out of another's state.
	other := streamKey{peer: "cid:103", boot: "boot-a"}
	if res := d.Check(other, 1); res.Duplicate {
		t.Error("sequence 1 from another CID was suppressed as a duplicate")
	}
	if got := d.ResumeFrom(rebooted); got != 0 {
		t.Errorf("ResumeFrom for a new boot id = %d, want 0", got)
	}
}

func TestDedupHoldsAcknowledgementBehindAnUncommittedSequence(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)

	// Sequence 2 was checked but never committed: its sink write failed. It is
	// not a gap -- the guest sent it and still holds it -- so the watermark must
	// simply wait.
	if res := d.Check(testStream, 2); res.Gap {
		t.Fatal("a sequence that arrived was reported as missing")
	}
	res := d.Check(testStream, 3)
	if res.Gap {
		t.Fatalf("sequence 3 reported a gap: %+v", res)
	}
	ack, _ := d.Commit(testStream, 3)
	if ack != 1 {
		t.Fatalf("ack = %d, want 1: sequence 2 was never written", ack)
	}

	// The retry closes the hole and the watermark jumps over both.
	if res := d.Check(testStream, 2); res.Duplicate {
		t.Fatal("a retry of an unwritten sequence was suppressed")
	}
	ack, _ = d.Commit(testStream, 2)
	if ack != 3 {
		t.Fatalf("ack = %d, want 3", ack)
	}
}

func TestDedupFirstWriteFailureBlocksAcknowledgement(t *testing.T) {
	cases := []struct {
		name  string
		first uint64
		step  uint64
	}{
		{name: "sequence one", first: 1, step: 1},
		{name: "late stream", first: 184213, step: 1},
		{name: "sequence one with gap", first: 1, step: 3},
		{name: "late stream with gap", first: 184213, step: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDedup(1024, 16)
			// The first event arrived, but its sink write failed.
			if res := d.Check(testStream, tc.first); res.Duplicate || res.Gap {
				t.Fatalf("first event = %+v, want neither duplicate nor gap", res)
			}

			later := tc.first + tc.step
			res, ack := accept(t, d, testStream, later)
			if res.Gap != (tc.step > 1) {
				t.Fatalf("later event = %+v, want gap=%t", res, tc.step > 1)
			}
			if res.Gap && (res.GapFirst != tc.first+1 || res.GapLast != later-1) {
				t.Fatalf("gap = %+v, must exclude the failed first event", res)
			}
			if ack >= tc.first {
				t.Fatalf("ack = %d, must stay below unwritten sequence %d", ack, tc.first)
			}
			if got := d.ResumeFrom(testStream); got >= tc.first {
				t.Fatalf("ResumeFrom = %d, must stay below unwritten sequence %d", got, tc.first)
			}
			if res, ack := accept(t, d, testStream, later); !res.Duplicate || ack >= tc.first {
				t.Fatalf("replay = %+v, ack = %d, want duplicate without advancing past the failure", res, ack)
			}

			// Retrying the failed first write closes the barrier, including any
			// later successful write and explicitly detected gap.
			res, ack = accept(t, d, testStream, tc.first)
			if res.Duplicate || res.Gap || ack != later {
				t.Fatalf("retry = %+v, ack = %d, want accepted with ack %d", res, ack, later)
			}
			if res := d.Check(testStream, tc.first); !res.Duplicate {
				t.Fatal("successfully retried event was not remembered")
			}
		})
	}
}

func TestDedupDetectsGapOnceAndMovesPastIt(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)
	accept(t, d, testStream, 2)

	res, ack := accept(t, d, testStream, 5)
	if !res.Gap || res.GapFirst != 3 || res.GapLast != 4 {
		t.Fatalf("gap = %+v, want 3..4", res)
	}
	if ack != 5 {
		t.Fatalf("ack = %d, want 5: the hole was reported, so it must not stall the stream", ack)
	}

	// The same hole is not reported again by the next event.
	res, ack = accept(t, d, testStream, 6)
	if res.Gap {
		t.Fatalf("the gap was reported twice: %+v", res)
	}
	if ack != 6 {
		t.Fatalf("ack = %d, want 6", ack)
	}
}

func TestDedupNoteMissingClearsAHoleTheAgentCannotReplay(t *testing.T) {
	d := newDedup(1024, 16)
	accept(t, d, testStream, 1)

	// HELLO said first_sequence=10: 2..9 are gone from the agent too.
	d.NoteMissing(testStream, 2, 9)
	if got := d.ResumeFrom(testStream); got != 9 {
		t.Fatalf("ResumeFrom = %d, want 9", got)
	}
	res, ack := accept(t, d, testStream, 10)
	if res.Gap {
		t.Fatalf("the hole was reported a second time: %+v", res)
	}
	if ack != 10 {
		t.Fatalf("ack = %d, want 10", ack)
	}
}

func TestDedupNoteMissingClearsFirstWriteFailure(t *testing.T) {
	cases := []struct {
		name  string
		first uint64
	}{
		{name: "sequence one", first: 1},
		{name: "late stream", first: 184213},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDedup(1024, 16)
			d.Check(testStream, tc.first) // sink write failed
			if _, ack := accept(t, d, testStream, tc.first+1); ack >= tc.first {
				t.Fatalf("ack = %d, must stay below unwritten sequence %d", ack, tc.first)
			}

			// An explicit loss report accounts for an event the guest can no
			// longer replay, so the saved event after it can now be acknowledged.
			d.NoteMissing(testStream, tc.first, tc.first)
			if got := d.ResumeFrom(testStream); got != tc.first+1 {
				t.Fatalf("ResumeFrom = %d, want %d after reported loss", got, tc.first+1)
			}
			if res, ack := accept(t, d, testStream, tc.first+2); res.Gap || res.Duplicate || ack != tc.first+2 {
				t.Fatalf("next event = %+v, ack = %d, want accepted with ack %d", res, ack, tc.first+2)
			}
		})
	}
}

func TestDedupWindowForgetsOldestOutOfOrderSequences(t *testing.T) {
	const window = minDedupWindow
	d := newDedup(window, 16)

	// Sequence 1 is written, 2 never arrives, and then a long run arrives above
	// the hole. The watermark cannot advance, so the out-of-order set is what
	// has to be bounded.
	accept(t, d, testStream, 1)
	d.Check(testStream, 2) // arrived, never committed

	var forgotten uint64
	for seq := uint64(3); seq <= 3+window*2; seq++ {
		d.Check(testStream, seq)
		_, f := d.Commit(testStream, seq)
		forgotten += f
	}
	if forgotten == 0 {
		t.Fatal("the out-of-order set grew past the window without forgetting anything")
	}

	d.mu.Lock()
	held := len(d.streams[testStream].ahead)
	d.mu.Unlock()
	if held > window {
		t.Fatalf("out-of-order set holds %d entries, want at most the window %d", held, window)
	}

	// A sequence that fell out of the window is no longer recognised: it will be
	// written twice. That is the documented trade -- a duplicate is recoverable,
	// a suppressed original is not.
	if res := d.Check(testStream, 3); res.Duplicate {
		t.Error("the oldest out-of-order sequence was still remembered; the window did not bound anything")
	}
}

func TestDedupEvictsLeastRecentlyUsedStream(t *testing.T) {
	d := newDedup(1024, 2)

	a := streamKey{peer: "cid:1", boot: "b"}
	b := streamKey{peer: "cid:2", boot: "b"}
	c := streamKey{peer: "cid:3", boot: "b"}
	accept(t, d, a, 1)
	accept(t, d, b, 1)
	// Touch b so that a is the least recently used.
	d.ResumeFrom(b)
	accept(t, d, c, 1)

	if got := d.ResumeFrom(a); got != 0 {
		t.Errorf("stream a survived eviction with ResumeFrom %d", got)
	}
	if got := d.ResumeFrom(b); got != 1 {
		t.Errorf("stream b was evicted instead of the least recently used one (ResumeFrom %d)", got)
	}
}

func TestDedupWindowHasAFloor(t *testing.T) {
	// Zero would not mean "no deduplication" but "an unbounded out-of-order
	// set", so the window cannot be switched off by configuration.
	if got := newDedup(0, 16).window; got != minDedupWindow {
		t.Fatalf("window = %d, want the floor %d", got, minDedupWindow)
	}
}
