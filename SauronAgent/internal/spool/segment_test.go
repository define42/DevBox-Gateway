package spool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// recordFor builds an on-disk record for a realistic event.
func recordFor(t testing.TB, seq uint64) []byte {
	t.Helper()
	payload, err := json.Marshal(execEvent(seq))
	if err != nil {
		t.Fatalf("marshalling event %d: %v", seq, err)
	}
	return encodeRecord(nil, payload)
}

// rawRecord builds a record around an arbitrary payload, for corruption cases
// that have to bypass the event encoder.
func rawRecord(payload []byte) []byte {
	return encodeRecord(nil, payload)
}

func TestSegmentName(t *testing.T) {
	tests := []struct {
		seq  uint64
		name string
	}{
		{1, "00000000000000000001.seg"},
		{0, "00000000000000000000.seg"},
		{9999, "00000000000000009999.seg"},
		{1 << 40, "00000001099511627776.seg"},
	}
	for _, tc := range tests {
		if got := segmentName(tc.seq); got != tc.name {
			t.Errorf("segmentName(%d) = %q, want %q", tc.seq, got, tc.name)
		}
		got, err := parseSegmentName(tc.name)
		if err != nil {
			t.Errorf("parseSegmentName(%q): %v", tc.name, err)
			continue
		}
		if got != tc.seq {
			t.Errorf("parseSegmentName(%q) = %d, want %d", tc.name, got, tc.seq)
		}
	}
}

// Lexical order of the names must equal sequence order, because recovery
// relies on the directory listing to order the segments.
func TestSegmentNamesSortBySequence(t *testing.T) {
	prev := segmentName(0)
	for _, seq := range []uint64{1, 2, 10, 99, 100, 1 << 20, 1 << 62} {
		name := segmentName(seq)
		if !(prev < name) {
			t.Fatalf("segment name %q does not sort after %q", name, prev)
		}
		prev = name
	}
}

func TestParseSegmentNameRejects(t *testing.T) {
	bad := []string{
		"",
		"checkpoint",
		"checkpoint.tmp",
		"1.seg",                        // not zero padded
		"00000000000000000001.seg.tmp", // extra suffix
		"0000000000000000000a.seg",     // not a number
		"000000000000000000001.seg",    // too long
		"-0000000000000000001.seg",     // signed
		"00000000000000000001",         // no suffix
		"+0000000000000000001.seg",
	}
	for _, name := range bad {
		if seq, err := parseSegmentName(name); err == nil {
			t.Errorf("parseSegmentName(%q) = %d, want an error", name, seq)
		}
	}
}

func TestEncodeRecordRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte(`{"sequence":1}`),
		[]byte(`{"sequence":2,"type":"process.exec","raw":["` + string(bytes.Repeat([]byte("x"), 64<<10)) + `"]}`),
		[]byte(`{"sequence":18446744073709551615}`),
	}
	var file []byte
	for _, p := range payloads {
		file = append(file, rawRecord(p)...)
	}

	var got [][]byte
	st, err := walkRecords(bytes.NewReader(file), 0, int64(len(file)),
		func(_ uint64, payload []byte, _ int64) bool {
			got = append(got, append([]byte(nil), payload...))
			return true
		})
	if err != nil {
		t.Fatalf("walkRecords: %v", err)
	}
	if st.count != len(payloads) {
		t.Fatalf("count = %d, want %d", st.count, len(payloads))
	}
	for i := range got {
		if !bytes.Equal(got[i], payloads[i]) {
			t.Errorf("payload %d = %.40q..., want %.40q...", i, got[i], payloads[i])
		}
	}
}

// A record whose payload carries no sequence number cannot be placed in the
// log, so it is damage rather than data.
func TestWalkRecordsRejectsSequencelessPayload(t *testing.T) {
	data := rawRecord([]byte(`{"version":1,"type":"process.exec"}`))
	st, err := walkRecords(bytes.NewReader(data), 0, int64(len(data)),
		func(seq uint64, _ []byte, _ int64) bool {
			t.Errorf("record with sequence %d was accepted", seq)
			return true
		})
	if err != nil {
		t.Fatalf("walkRecords: %v", err)
	}
	if st.count != 0 || st.validEnd != 0 {
		t.Fatalf("count = %d validEnd = %d, want 0 and 0", st.count, st.validEnd)
	}
}

func TestWalkRecords(t *testing.T) {
	valid := func(seqs ...uint64) []byte {
		var b []byte
		for _, s := range seqs {
			b = append(b, recordFor(t, s)...)
		}
		return b
	}

	tests := []struct {
		name string
		// build returns the file bytes and the expected offset of the end of
		// the last valid record.
		build       func(t *testing.T) (data []byte, validEnd int64)
		wantCount   int
		wantSkipped int
		wantGapLow  uint64
		wantGapHigh uint64
		wantSeqs    []uint64
	}{
		{
			name:      "empty file",
			build:     func(*testing.T) ([]byte, int64) { return nil, 0 },
			wantCount: 0,
		},
		{
			name: "three records",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2, 3)
				return d, int64(len(d))
			},
			wantCount: 3,
			wantSeqs:  []uint64{1, 2, 3},
		},
		{
			name: "sparse sequences are fine",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(7, 19, 4096)
				return d, int64(len(d))
			},
			wantCount: 3,
			wantSeqs:  []uint64{7, 19, 4096},
		},
		{
			name: "torn tail: header only",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2)
				end := int64(len(d))
				d = append(d, recordFor(t, 3)[:recordHeaderSize]...)
				return d, end
			},
			wantCount: 2,
			wantSeqs:  []uint64{1, 2},
		},
		{
			name: "torn tail: half a payload",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2)
				end := int64(len(d))
				r := recordFor(t, 3)
				d = append(d, r[:len(r)/2]...)
				return d, end
			},
			wantCount: 2,
			wantSeqs:  []uint64{1, 2},
		},
		{
			name: "torn tail: trailing zeroes",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2)
				end := int64(len(d))
				d = append(d, make([]byte, 4096)...)
				return d, end
			},
			wantCount: 2,
			wantSeqs:  []uint64{1, 2},
		},
		{
			name: "corrupt payload in the middle",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2, 3)
				// Flip a byte inside the second record's payload.
				off := len(recordFor(t, 1)) + recordHeaderSize + 4
				d[off] ^= 0xff
				return d, int64(len(d))
			},
			wantCount:   2,
			wantSkipped: 1,
			wantGapLow:  2,
			wantGapHigh: 2,
			wantSeqs:    []uint64{1, 3},
		},
		{
			name: "destroyed magic in the middle",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(10, 20, 30)
				off := len(recordFor(t, 10))
				copy(d[off:off+4], []byte("XXXX"))
				return d, int64(len(d))
			},
			wantCount:   2,
			wantSkipped: 1,
			wantGapLow:  11,
			wantGapHigh: 29,
			wantSeqs:    []uint64{10, 30},
		},
		{
			name: "garbage before the first record",
			build: func(t *testing.T) ([]byte, int64) {
				d := append([]byte("this is not a spool segment\x00\x00"), valid(5, 6)...)
				return d, int64(len(d))
			},
			wantCount:   2,
			wantSkipped: 1,
			wantGapLow:  1,
			wantGapHigh: 4,
			wantSeqs:    []uint64{5, 6},
		},
		{
			name: "length beyond the end of the file",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2)
				end := int64(len(d))
				r := recordFor(t, 3)
				binary.BigEndian.PutUint32(r[4:8], 1<<20)
				return append(d, r...), end
			},
			wantCount: 2,
			wantSeqs:  []uint64{1, 2},
		},
		{
			name: "length above the record ceiling",
			build: func(t *testing.T) ([]byte, int64) {
				r := recordFor(t, 1)
				binary.BigEndian.PutUint32(r[4:8], 0xffffffff)
				d := append(r, valid(2)...)
				return d, int64(len(d))
			},
			wantCount:   1,
			wantSkipped: 1,
			wantGapLow:  1,
			wantGapHigh: 1,
			wantSeqs:    []uint64{2},
		},
		{
			name: "zero length record",
			build: func(t *testing.T) ([]byte, int64) {
				r := rawRecord(nil)
				d := append(r, valid(9)...)
				return d, int64(len(d))
			},
			wantCount:   1,
			wantSkipped: 1,
			wantGapLow:  1,
			wantGapHigh: 8,
			wantSeqs:    []uint64{9},
		},
		{
			name: "payload is not an event",
			build: func(t *testing.T) ([]byte, int64) {
				d := rawRecord([]byte("not json at all"))
				d = append(d, valid(3)...)
				return d, int64(len(d))
			},
			wantCount:   1,
			wantSkipped: 1,
			wantGapLow:  1,
			wantGapHigh: 2,
			wantSeqs:    []uint64{3},
		},
		{
			name: "sequence out of order is treated as damage",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 5)
				d = append(d, recordFor(t, 3)...)
				d = append(d, recordFor(t, 7)...)
				return d, int64(len(d))
			},
			wantCount:   3,
			wantSkipped: 1,
			wantGapLow:  6,
			wantGapHigh: 6,
			wantSeqs:    []uint64{1, 5, 7},
		},
		{
			name: "two separate holes",
			build: func(t *testing.T) ([]byte, int64) {
				d := valid(1, 2, 3, 4, 5)
				r := len(recordFor(t, 1))
				d[r+recordHeaderSize+2] ^= 0xff   // record 2
				d[3*r+recordHeaderSize+2] ^= 0xff // record 4
				return d, int64(len(d))
			},
			wantCount:   3,
			wantSkipped: 2,
			wantGapLow:  2,
			wantGapHigh: 4,
			wantSeqs:    []uint64{1, 3, 5},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, wantEnd := tc.build(t)
			var seqs []uint64
			st, err := walkRecords(bytes.NewReader(data), 0, int64(len(data)),
				func(seq uint64, payload []byte, end int64) bool {
					if len(payload) == 0 {
						t.Errorf("record %d has an empty payload", seq)
					}
					seqs = append(seqs, seq)
					return true
				})
			if err != nil {
				t.Fatalf("walkRecords: %v", err)
			}
			if st.count != tc.wantCount {
				t.Errorf("count = %d, want %d", st.count, tc.wantCount)
			}
			if st.validEnd != wantEnd {
				t.Errorf("validEnd = %d, want %d", st.validEnd, wantEnd)
			}
			if st.skipped != tc.wantSkipped {
				t.Errorf("skipped = %d, want %d", st.skipped, tc.wantSkipped)
			}
			if tc.wantSkipped > 0 {
				if st.gapLow != tc.wantGapLow || st.gapHigh != tc.wantGapHigh {
					t.Errorf("gap = [%d,%d], want [%d,%d]",
						st.gapLow, st.gapHigh, tc.wantGapLow, tc.wantGapHigh)
				}
			}
			if len(tc.wantSeqs) > 0 && fmt.Sprint(seqs) != fmt.Sprint(tc.wantSeqs) {
				t.Errorf("sequences = %v, want %v", seqs, tc.wantSeqs)
			}
		})
	}
}

func TestWalkRecordsStopsEarly(t *testing.T) {
	var data []byte
	for seq := uint64(1); seq <= 5; seq++ {
		data = append(data, recordFor(t, seq)...)
	}
	var seen []uint64
	st, err := walkRecords(bytes.NewReader(data), 0, int64(len(data)),
		func(seq uint64, _ []byte, _ int64) bool {
			seen = append(seen, seq)
			return seq < 2
		})
	if err != nil {
		t.Fatalf("walkRecords: %v", err)
	}
	if !st.stopped {
		t.Error("stopped = false, want true")
	}
	if len(seen) != 2 || seen[1] != 2 {
		t.Fatalf("seen = %v, want [1 2]", seen)
	}
	if want := int64(len(recordFor(t, 1)) + len(recordFor(t, 2))); st.validEnd != want {
		t.Errorf("validEnd = %d, want %d", st.validEnd, want)
	}
}

// Starting a walk part way into a file is how Ack avoids re-reading records it
// has already accounted for.
func TestWalkRecordsFromOffset(t *testing.T) {
	var data []byte
	var offsets []int64
	for seq := uint64(1); seq <= 4; seq++ {
		data = append(data, recordFor(t, seq)...)
		offsets = append(offsets, int64(len(data)))
	}
	start := offsets[1]
	var seen []uint64
	st, err := walkRecords(bytes.NewReader(data[start:]), start, int64(len(data)),
		func(seq uint64, _ []byte, _ int64) bool {
			seen = append(seen, seq)
			return true
		})
	if err != nil {
		t.Fatalf("walkRecords: %v", err)
	}
	if st.count != 2 || len(seen) != 2 || seen[0] != 3 || seen[1] != 4 {
		t.Fatalf("seen = %v (count %d), want [3 4]", seen, st.count)
	}
	if st.validEnd != int64(len(data)) {
		t.Errorf("validEnd = %d, want %d", st.validEnd, len(data))
	}
}

func TestScanSegmentTruncatesTornTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segmentName(1))

	var data []byte
	for seq := uint64(1); seq <= 3; seq++ {
		data = append(data, recordFor(t, seq)...)
	}
	good := int64(len(data))
	data = append(data, recordFor(t, 4)[:9]...) // a header cut in half
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatal(err)
	}

	sg, st, err := scanSegment(path, 1)
	if err != nil {
		t.Fatalf("scanSegment: %v", err)
	}
	if sg.count != 3 || sg.base != 1 || sg.last != 3 {
		t.Errorf("segment = %+v, want count 3 base 1 last 3", sg)
	}
	if st.skipped != 0 {
		t.Errorf("skipped = %d, want 0: a torn tail is not a gap", st.skipped)
	}
	if st.torn != 9 {
		t.Errorf("torn = %d, want 9", st.torn)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != good {
		t.Errorf("file size after repair = %d, want %d", fi.Size(), good)
	}
	if sg.size != good {
		t.Errorf("segment size = %d, want %d", sg.size, good)
	}
}

func TestScanSegmentReportsHole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segmentName(100))

	var data []byte
	for seq := uint64(100); seq <= 103; seq++ {
		data = append(data, recordFor(t, seq)...)
	}
	rec := len(recordFor(t, 100))
	data[rec+recordHeaderSize+1] ^= 0xff // corrupt record 101
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatal(err)
	}

	sg, st, err := scanSegment(path, 100)
	if err != nil {
		t.Fatalf("scanSegment: %v", err)
	}
	if st.skipped != 1 {
		t.Fatalf("skipped = %d, want 1", st.skipped)
	}
	if st.gapLow != 101 || st.gapHigh != 101 {
		t.Errorf("gap = [%d,%d], want [101,101]", st.gapLow, st.gapHigh)
	}
	if sg.count != 3 || sg.base != 100 || sg.last != 103 {
		t.Errorf("segment = %+v, want count 3 base 100 last 103", sg)
	}
	if st.torn != 0 {
		t.Errorf("torn = %d, want 0: the hole is in the middle", st.torn)
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != int64(len(data)) {
		t.Errorf("file was truncated although the damage is in the middle")
	}
}

// A gap that swallows the start of a segment cannot be bounded by a surviving
// record, so the file name is used as the lower bound instead.
func TestScanSegmentGapAtStartUsesNameBase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segmentName(500))

	data := append(bytes.Repeat([]byte{0x11}, 64), recordFor(t, 505)...)
	if err := os.WriteFile(path, data, fileMode); err != nil {
		t.Fatal(err)
	}
	_, st, err := scanSegment(path, 500)
	if err != nil {
		t.Fatalf("scanSegment: %v", err)
	}
	if st.skipped != 1 || st.gapLow != 500 || st.gapHigh != 504 {
		t.Fatalf("skipped = %d gap = [%d,%d], want 1 [500,504]", st.skipped, st.gapLow, st.gapHigh)
	}
}

func TestSequenceOf(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    uint64
		wantErr bool
	}{
		{name: "event", payload: `{"version":1,"sequence":42,"type":"process.exec"}`, want: 42},
		{name: "missing", payload: `{"version":1}`, want: 0},
		{name: "max", payload: `{"sequence":18446744073709551615}`, want: 1<<64 - 1},
		{name: "not json", payload: `sequence=42`, wantErr: true},
		{name: "truncated", payload: `{"sequence":4`, wantErr: true},
		{name: "wrong type", payload: `{"sequence":"42"}`, wantErr: true},
		{name: "negative", payload: `{"sequence":-1}`, wantErr: true},
		{name: "deeply nested", payload: `{"sequence":1,"fields":` + deepJSON(20000) + `}`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sequenceOf([]byte(tc.payload))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("sequenceOf(%q) = %d, want an error", tc.payload, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("sequenceOf(%q): %v", tc.payload, err)
			}
			if got != tc.want {
				t.Errorf("sequenceOf(%q) = %d, want %d", tc.payload, got, tc.want)
			}
		})
	}
}

// deepJSON builds a nested array, used to check that a hostile payload cannot
// drive the decoder into unbounded recursion.
func deepJSON(depth int) string {
	return string(bytes.Repeat([]byte("["), depth)) + string(bytes.Repeat([]byte("]"), depth))
}

// FuzzWalkRecords drives the record parser with arbitrary bytes: a spool file
// is the one input the agent parses that an intruder with disk access can
// shape, so the walk must always terminate, never allocate beyond the file and
// never return a record it has not verified.
func FuzzWalkRecords(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte("SREC"))
	f.Add(append([]byte("SREC"), 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0))
	f.Add(recordFor(f, 1))
	f.Add(append(recordFor(f, 1), recordFor(f, 2)...))
	f.Add(append(recordFor(f, 9), recordFor(f, 2)...))
	f.Add(bytes.Repeat([]byte("SREC\x00\x00\x00\x01\x00\x00\x00\x01"), 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		size := int64(len(data))
		var prev uint64
		var records int
		st, err := walkRecords(bytes.NewReader(data), 0, size,
			func(seq uint64, payload []byte, end int64) bool {
				records++
				if seq == 0 {
					t.Fatalf("record with sequence 0 accepted")
				}
				if prev != 0 && seq <= prev {
					t.Fatalf("sequence %d does not follow %d", seq, prev)
				}
				prev = seq
				if end > size || end < int64(len(payload)) {
					t.Fatalf("record ends at %d, outside a %d byte file", end, size)
				}
				if int64(len(payload)) > maxRecordSize {
					t.Fatalf("payload of %d bytes exceeds the ceiling", len(payload))
				}
				return true
			})
		if err != nil {
			t.Fatalf("walkRecords on %d bytes: %v", size, err)
		}
		if st.count != records {
			t.Fatalf("count = %d but %d records were delivered", st.count, records)
		}
		if st.validEnd < 0 || st.validEnd > size {
			t.Fatalf("validEnd = %d, outside a %d byte file", st.validEnd, size)
		}
		if st.skipped < 0 {
			t.Fatalf("skipped = %d", st.skipped)
		}
	})
}

// FuzzScanSegment covers the recovery path as a whole, including the in-place
// truncation, so that no arbitrary file can make Open fail or lose a record it
// has already accepted.
func FuzzScanSegment(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(rawRecord([]byte(`{"sequence":1}`)))
	f.Add(append(rawRecord([]byte(`{"sequence":1}`)), []byte("SREC\x00\x00")...))
	f.Add(append([]byte("junk"), rawRecord([]byte(`{"sequence":4}`))...))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, segmentName(1))
		if err := os.WriteFile(path, data, fileMode); err != nil {
			t.Fatal(err)
		}
		sg, st, err := scanSegment(path, 1)
		if err != nil {
			t.Fatalf("scanSegment on %d bytes: %v", len(data), err)
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Size() != sg.size {
			t.Fatalf("file is %d bytes after repair but the segment says %d", fi.Size(), sg.size)
		}
		if sg.size > int64(len(data)) {
			t.Fatalf("repair grew the file from %d to %d bytes", len(data), sg.size)
		}
		if sg.count > 0 && sg.last < sg.base {
			t.Fatalf("segment holds %d..%d", sg.base, sg.last)
		}
		if st.torn != int64(len(data))-sg.size {
			t.Fatalf("torn = %d, but %d bytes were removed", st.torn, int64(len(data))-sg.size)
		}
		// A second pass over a repaired file must find the same records and
		// nothing further to repair.
		sg2, st2, err := scanSegment(path, 1)
		if err != nil {
			t.Fatalf("rescan: %v", err)
		}
		if sg2.count != sg.count || sg2.size != sg.size || st2.torn != 0 {
			t.Fatalf("rescan changed the segment: %+v %+v", sg2, st2)
		}
	})
}
