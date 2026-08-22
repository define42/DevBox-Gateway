package storage

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestStreamReaderChunksWithProgressReportsBytesRead(t *testing.T) {
	var reads []int
	nextChunk := StreamReaderChunksWithProgress(strings.NewReader("abcdef"), func(n int) {
		reads = append(reads, n)
	})

	requests := []int{2, 3, 8, 8}
	wantChunks := []string{"ab", "cde", "f", ""}
	for i, requested := range requests {
		chunk, err := nextChunk(nil, requested)
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", i, err)
		}
		if got := string(chunk); got != wantChunks[i] {
			t.Fatalf("chunk %d = %q, want %q", i, got, wantChunks[i])
		}
	}

	if want := []int{2, 3, 1}; !reflect.DeepEqual(reads, want) {
		t.Fatalf("reported reads = %v, want %v", reads, want)
	}
}

type readThenError struct {
	data []byte
	err  error
}

func (r *readThenError) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = nil
	return n, r.err
}

func TestStreamReaderChunksWithProgressDoesNotReportDiscardedPartialRead(t *testing.T) {
	readErr := errors.New("source read failed")
	src := &readThenError{data: []byte("xy"), err: readErr}
	var reported int
	nextChunk := StreamReaderChunksWithProgress(src, func(n int) {
		reported += n
	})

	chunk, err := nextChunk(nil, 8)
	if !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want %v", err, readErr)
	}
	if chunk != nil {
		t.Fatalf("chunk = %q, want nil on read error", chunk)
	}
	if reported != 0 {
		t.Fatalf("reported bytes = %d, want 0 because the errored chunk was not returned", reported)
	}
}

func TestStreamReaderChunksWithProgressReportsPartialEOFChunk(t *testing.T) {
	src := &readThenError{data: []byte("xy"), err: io.EOF}
	var reported int
	nextChunk := StreamReaderChunksWithProgress(src, func(n int) {
		reported += n
	})

	chunk, err := nextChunk(nil, 8)
	if err != nil {
		t.Fatalf("partial EOF read returned error: %v", err)
	}
	if got := string(chunk); got != "xy" {
		t.Fatalf("chunk = %q, want %q", got, "xy")
	}
	if reported != 2 {
		t.Fatalf("reported bytes = %d, want 2 returned bytes", reported)
	}
}

func TestReportDiskCopyProgress(t *testing.T) {
	type observation struct {
		copied int64
		total  int64
	}
	var got []observation
	report := func(copiedBytes, totalBytes int64) {
		got = append(got, observation{copied: copiedBytes, total: totalBytes})
	}

	ReportProgress(report, 0, 11)
	ReportProgress(report, 7, 11)
	ReportProgress(report, 11, 11)
	// BootNewVM uses this nil-callback path to preserve its existing API.
	ReportProgress(nil, 11, 11)

	want := []observation{
		{copied: 0, total: 11},
		{copied: 7, total: 11},
		{copied: 11, total: 11},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disk-copy observations = %#v, want %#v", got, want)
	}
}
