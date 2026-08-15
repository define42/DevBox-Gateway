package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestCreationCopyPercent(t *testing.T) {
	tests := []struct {
		name   string
		copied int64
		total  int64
		want   int
	}{
		{name: "not started", copied: 0, total: 100, want: 0},
		{name: "unknown total", copied: 10, total: 0, want: 0},
		{name: "partial", copied: 25, total: 100, want: 25},
		{name: "fraction truncates", copied: 2, total: 3, want: 66},
		{name: "complete", copied: 100, total: 100, want: 100},
		{name: "clamps growth", copied: 120, total: 100, want: 100},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := creationCopyPercent(test.copied, test.total); got != test.want {
				t.Fatalf("creationCopyPercent(%d, %d) = %d, want %d", test.copied, test.total, got, test.want)
			}
		})
	}
}

func TestAcceptsCreationStream(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{name: "explicit stream", headers: []string{"application/x-ndjson"}, want: true},
		{name: "case insensitive", headers: []string{"Application/X-NDJSON"}, want: true},
		{name: "media type parameter", headers: []string{"application/x-ndjson; charset=utf-8"}, want: true},
		{name: "positive quality", headers: []string{"application/x-ndjson; q=0.5"}, want: true},
		{name: "comma separated", headers: []string{"application/json, application/x-ndjson"}, want: true},
		{name: "multiple header lines", headers: []string{"application/json", "application/x-ndjson"}, want: true},
		{name: "zero quality declines stream", headers: []string{"application/x-ndjson; q=0"}, want: false},
		{name: "invalid quality declines stream", headers: []string{"application/x-ndjson; q=invalid"}, want: false},
		{name: "NaN quality declines stream", headers: []string{"application/x-ndjson; q=NaN"}, want: false},
		{name: "legacy json", headers: []string{"application/json"}, want: false},
		{name: "wildcard does not opt in", headers: []string{"*/*"}, want: false},
		{name: "missing accept", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/dashboard", nil)
			for _, header := range test.headers {
				req.Header.Add("Accept", header)
			}
			if got := AcceptsCreationStream(req); got != test.want {
				t.Fatalf("AcceptsCreationStream() = %t, want %t for Accept %q", got, test.want, test.headers)
			}
		})
	}
}

func TestCreationStreamStartsLazily(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := NewCreationStream(recorder)

	if stream.Started() {
		t.Fatal("new creation stream must not be started")
	}
	if recorder.Body.Len() != 0 || recorder.Header().Get("Content-Type") != "" || recorder.Flushed {
		t.Fatal("constructing a creation stream must not commit the HTTP response")
	}

	stream.ReportDiskCopy(0, 100)
	if !stream.Started() {
		t.Fatal("first progress event must start the creation stream")
	}
}

func TestCreationStreamThrottlesProgressAndEndsWithResult(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := NewCreationStream(recorder)

	// Multiple byte observations within the same displayed percentage should
	// produce only one line, while crossing the next percentage should publish.
	stream.ReportDiskCopy(0, 1000)
	stream.ReportDiskCopy(1, 1000)
	stream.ReportDiskCopy(9, 1000)
	stream.ReportDiskCopy(10, 1000)
	stream.ReportDiskCopy(19, 1000)
	stream.ReportDiskCopy(20, 1000)
	stream.WriteResult(ActionResponse{OK: true, Message: "VM created."})

	response := recorder.Result()
	defer func() { _ = response.Body.Close() }()

	if got := response.Header.Get("Content-Type"); got != creationStreamMediaType+"; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want NDJSON", got)
	}
	if got := response.Header.Get("Cache-Control"); got != cacheControlValue {
		t.Fatalf("Cache-Control = %q, want %q", got, cacheControlValue)
	}
	if !recorder.Flushed {
		t.Fatal("expected creation stream events to be flushed")
	}

	type creationEvent struct {
		Type        string `json:"type"`
		CopiedBytes int64  `json:"copiedBytes"`
		TotalBytes  int64  `json:"totalBytes"`
		OK          bool   `json:"ok"`
		Message     string `json:"message"`
		Error       string `json:"error"`
	}

	decoder := json.NewDecoder(response.Body)
	var got []creationEvent
	for {
		var event creationEvent
		err := decoder.Decode(&event)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode creation event: %v", err)
		}
		got = append(got, event)
	}

	want := []creationEvent{
		{Type: "progress", CopiedBytes: 0, TotalBytes: 1000},
		{Type: "progress", CopiedBytes: 10, TotalBytes: 1000},
		{Type: "progress", CopiedBytes: 20, TotalBytes: 1000},
		{Type: "result", OK: true, Message: "VM created."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("creation events = %#v, want %#v", got, want)
	}
}
