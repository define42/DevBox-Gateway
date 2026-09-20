package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

// hecRequest is one request received by a fake collector.
type hecRequest struct {
	path          string
	authorization string
	contentType   string
	events        []map[string]any
}

// fakeCollector is an HEC stand-in that answers each request with the next
// scripted status, then 200 once the script is exhausted.
type fakeCollector struct {
	t        *testing.T
	mu       sync.Mutex
	statuses []int
	requests []hecRequest
	server   *httptest.Server
}

func newFakeCollector(t *testing.T, statuses ...int) *fakeCollector {
	t.Helper()
	collector := &fakeCollector{t: t, statuses: statuses}
	collector.server = httptest.NewTLSServer(http.HandlerFunc(collector.handle))
	t.Cleanup(collector.server.Close)
	return collector
}

func (c *fakeCollector) handle(w http.ResponseWriter, r *http.Request) {
	events := decodeEnvelopes(c.t, r.Body)

	c.mu.Lock()
	c.requests = append(c.requests, hecRequest{
		path:          r.URL.Path,
		authorization: r.Header.Get("Authorization"),
		contentType:   r.Header.Get("Content-Type"),
		events:        events,
	})
	status := http.StatusOK
	if len(c.statuses) > 0 {
		status, c.statuses = c.statuses[0], c.statuses[1:]
	}
	c.mu.Unlock()

	w.WriteHeader(status)
	if status == http.StatusOK {
		_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
		return
	}
	_, _ = io.WriteString(w, `{"text":"scripted failure","code":8}`)
}

func (c *fakeCollector) received() []hecRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]hecRequest(nil), c.requests...)
}

// decodeEnvelopes splits a batch body into its concatenated HEC envelopes.
func decodeEnvelopes(t *testing.T, body io.Reader) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(body)
	decoder.UseNumber()
	var events []map[string]any
	for {
		var envelope map[string]any
		err := decoder.Decode(&envelope)
		if errors.Is(err, io.EOF) {
			return events
		}
		if err != nil {
			t.Errorf("decode hec envelope: %v", err)
			return events
		}
		events = append(events, envelope)
	}
}

// newTestForwarder builds a forwarder for collector with fast retries.
func newTestForwarder(t *testing.T, config HECConfig) *hecForwarder {
	t.Helper()
	forwarder, err := newHECForwarder(config)
	if err != nil {
		t.Fatalf("newHECForwarder() error = %v", err)
	}
	forwarder.retryInitial = time.Millisecond
	forwarder.retryLimit = 5 * time.Millisecond
	return forwarder
}

func writeRecord(t *testing.T, forwarder *hecForwarder, record string) {
	t.Helper()
	if n, err := forwarder.Write([]byte(record + "\n")); err != nil || n != len(record)+1 {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(record)+1)
	}
}

func eventUsers(requests []hecRequest) []string {
	var users []string
	for _, request := range requests {
		for _, envelope := range request.events {
			event, _ := envelope["event"].(map[string]any)
			user, _ := event["user"].(string)
			users = append(users, user)
		}
	}
	return users
}

func assertHECRequestHeaders(t *testing.T, request hecRequest, token string) {
	t.Helper()
	if request.path != splunkhec.EventPath {
		t.Errorf("request path = %q, want %q", request.path, splunkhec.EventPath)
	}
	if want := "Splunk " + token; request.authorization != want {
		t.Errorf("Authorization = %q, want %q", request.authorization, want)
	}
	if request.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", request.contentType)
	}
}

func assertFields(t *testing.T, label string, got, want map[string]any) {
	t.Helper()
	for key, wantValue := range want {
		if gotValue := got[key]; gotValue != wantValue {
			t.Errorf("%s %q = %#v, want %#v", label, key, gotValue, wantValue)
		}
	}
}

func TestNewHECForwarderRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config HECConfig
	}{
		{name: "empty token", config: HECConfig{Endpoint: "https://splunk.example.test", Token: " "}},
		{name: "bad endpoint", config: HECConfig{Endpoint: "splunk.example.test", Token: "token"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newHECForwarder(test.config); err == nil {
				t.Fatal("newHECForwarder() error = nil, want non-nil")
			}
		})
	}
}

func TestConfigureForwardsAuditRecordsToHEC(t *testing.T) {
	collector := newFakeCollector(t)
	path := filepath.Join(t.TempDir(), "unused", "audit.jsonl")

	closer, err := Configure(Options{
		FilePath: path,
		HEC: HECConfig{
			Endpoint:           collector.server.URL,
			Token:              "hec-token",
			Index:              "devbox_audit",
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })

	Log(context.Background(), Event{Action: ActionUserLogin, User: "alice", SourceIP: "192.0.2.10"})
	Log(context.Background(), Event{Action: ActionVMStart, User: "alice", VM: "alice.desktop"})
	// Close flushes the queue, so every record has reached the collector after it.
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := collector.received()
	if got := eventUsers(requests); len(got) != 2 {
		t.Fatalf("collector received %d events, want 2: %#v", len(got), requests)
	}
	for _, request := range requests {
		assertHECRequestHeaders(t, request, "hec-token")
	}

	hostname, _ := os.Hostname()
	envelope := requests[0].events[0]
	assertFields(t, "envelope", envelope, map[string]any{
		"index":      "devbox_audit",
		"source":     hecSource,
		"sourcetype": hecSourcetype,
		"host":       hostname,
	})
	if timestamp, _ := envelope["time"].(json.Number); !regexp.MustCompile(`^\d{10}\.\d{3}$`).MatchString(string(timestamp)) {
		t.Errorf("envelope time = %#v, want epoch seconds with milliseconds", envelope["time"])
	}
	event, _ := envelope["event"].(map[string]any)
	assertFields(t, "event", event, map[string]any{
		"msg":       "audit",
		"action":    ActionUserLogin,
		"user":      "alice",
		"source_ip": "192.0.2.10",
	})

	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("HEC-only logging created the local audit directory: %v", err)
	}
}

func TestConfigureHECRejectionDoesNotCreateLocalFile(t *testing.T) {
	collector := newFakeCollector(t, http.StatusBadRequest)
	path := filepath.Join(t.TempDir(), "unused", "audit.jsonl")
	closer, err := Configure(Options{
		FilePath: path,
		HEC:      HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })

	Log(context.Background(), Event{Action: ActionUserLogin, User: "rejected"})
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	requests := collector.received()
	if len(requests) != 1 || strings.Join(eventUsers(requests), ",") != "rejected" {
		t.Fatalf("collector requests = %#v, want one rejected event without a retry", requests)
	}
	collector.mu.Lock()
	remainingStatuses := len(collector.statuses)
	collector.mu.Unlock()
	if remainingStatuses != 0 {
		t.Fatal("collector did not return the scripted HTTP 400 rejection")
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("HEC rejection created a local audit directory: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("HEC rejection created a local audit file: %v", err)
	}
}

func TestConfigureHECLeavesExistingFileUntouched(t *testing.T) {
	collector := newFakeCollector(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	const existing = "{\"existing\":true}\n"
	if err := os.WriteFile(path, []byte(existing), 0o640); err != nil {
		t.Fatal(err)
	}

	closer, err := Configure(Options{
		FilePath: path,
		HEC:      HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	Log(context.Background(), Event{Action: ActionUserLogin, User: "alice"})
	if err := closer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := strings.Join(eventUsers(collector.received()), ","); got != "alice" {
		t.Errorf("collector users = %q, want alice", got)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != existing {
		t.Errorf("HEC-only logging changed existing audit file: %q", raw)
	}
	assertPathMode(t, path, 0o640)
}

func TestConfigureHECIgnoresUnusableFilePaths(t *testing.T) {
	directory := t.TempDir()
	parentFile := filepath.Join(directory, "regular-file")
	if err := os.WriteFile(parentFile, []byte("existing"), 0o640); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
	}{
		{name: "empty", path: ""},
		{name: "whitespace", path: " \t "},
		{name: "directory", path: directory},
		{name: "parent is a file", path: filepath.Join(parentFile, "audit.jsonl")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := newFakeCollector(t)
			closer, err := Configure(Options{
				FilePath: test.path,
				HEC:      HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
			})
			if err != nil {
				t.Fatalf("Configure() with ignored file path %q: %v", test.path, err)
			}
			t.Cleanup(func() { _ = closer.Close() })
			Log(context.Background(), Event{Action: ActionUserLogin, User: "alice"})
			if err := closer.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got := strings.Join(eventUsers(collector.received()), ","); got != "alice" {
				t.Errorf("collector users = %q, want alice", got)
			}
		})
	}
}

func TestConfigureHECPreservesOperationalLogAndRestoresLogging(t *testing.T) {
	collector := newFakeCollector(t)
	previousLogger := slog.Default()
	previousLogWriter := log.Writer()
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
		log.SetOutput(previousLogWriter)
	})
	var restoredSlog, operationalLog bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&restoredSlog, nil))
	slog.SetDefault(logger)
	log.SetOutput(&operationalLog)

	closer, err := Configure(Options{
		HEC: HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	log.Print("ordinary service event")
	Log(context.Background(), Event{Action: ActionUserLogout, User: "alice"})
	for range 2 {
		if err := closer.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	Log(context.Background(), Event{Action: ActionUserLogout, User: "after-close"})
	log.Print("ordinary event after close")

	if slog.Default() != logger || log.Writer() != &operationalLog {
		t.Error("Close() did not restore the previous logging destinations")
	}
	if got := strings.Join(eventUsers(collector.received()), ","); got != "alice" {
		t.Errorf("collector users = %q, want only alice", got)
	}
	if !strings.Contains(restoredSlog.String(), `"user":"after-close"`) {
		t.Errorf("previous slog logger did not receive the post-close event: %q", restoredSlog.String())
	}
	if !strings.Contains(operationalLog.String(), "ordinary service event") ||
		!strings.Contains(operationalLog.String(), "ordinary event after close") {
		t.Errorf("standard log destination was not preserved and restored: %q", operationalLog.String())
	}
}

func TestConfigureRejectsInvalidHECWithoutTouchingLogging(t *testing.T) {
	tests := []struct {
		name   string
		config HECConfig
	}{
		{name: "missing token", config: HECConfig{Endpoint: "https://splunk.example.test"}},
		{name: "whitespace token", config: HECConfig{Endpoint: "https://splunk.example.test", Token: " \t "}},
		{name: "invalid endpoint", config: HECConfig{Endpoint: "splunk.example.test", Token: "token"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			previousLogger := slog.Default()
			previousLogWriter := log.Writer()
			path := filepath.Join(t.TempDir(), "unused", "audit.jsonl")
			closer, err := Configure(Options{FilePath: path, HEC: test.config})
			if err == nil {
				_ = closer.Close()
				t.Fatal("Configure() error = nil, want HEC configuration error")
			}
			if !strings.Contains(err.Error(), "hec") {
				t.Errorf("Configure() error = %v, want HEC configuration error", err)
			}
			if slog.Default() != previousLogger || log.Writer() != previousLogWriter {
				t.Error("failed Configure replaced a logging destination")
			}
			if _, statErr := os.Stat(filepath.Dir(path)); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("failed Configure created the audit directory: %v", statErr)
			}
		})
	}
}

func TestHECForwarderOmitsEmptyIndex(t *testing.T) {
	collector := newFakeCollector(t)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := collector.received()
	if len(requests) != 1 || len(requests[0].events) != 1 {
		t.Fatalf("collector received %#v, want one event", requests)
	}
	if _, ok := requests[0].events[0]["index"]; ok {
		t.Errorf("envelope has an index field without SPLUNK_HEC_INDEX: %#v", requests[0].events[0])
	}
}

func TestHECForwarderBatchesQueuedRecords(t *testing.T) {
	collector := newFakeCollector(t)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})

	// Queue the records before the sender runs so they are sent as one batch.
	for _, user := range []string{"alice", "bob", "carol"} {
		writeRecord(t, forwarder, `{"user":"`+user+`"}`)
	}
	forwarder.start()
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := collector.received()
	if len(requests) != 1 {
		t.Fatalf("collector received %d requests, want 1 batch", len(requests))
	}
	if got, want := strings.Join(eventUsers(requests), ","), "alice,bob,carol"; got != want {
		t.Fatalf("batched users = %q, want %q", got, want)
	}
}

func TestHECForwarderRetriesTransientFailures(t *testing.T) {
	collector := newFakeCollector(t, http.StatusServiceUnavailable, http.StatusForbidden, http.StatusTooManyRequests)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := collector.received()
	if len(requests) != 4 {
		t.Fatalf("collector received %d requests, want 3 failures and 1 success", len(requests))
	}
	if got := forwarder.dropped.Load(); got != 0 {
		t.Errorf("dropped = %d, want 0", got)
	}
}

func TestHECForwarderRetriesUnconfirmedResponses(t *testing.T) {
	var attempts atomic.Int64
	requests := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			t.Error("followed a redirect away from the configured collector")
			_, _ = io.WriteString(w, `{"code":0}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		select {
		case requests <- string(body):
		default:
			t.Error("received more delivery attempts than expected")
		}
		switch attempts.Add(1) {
		case 1:
			http.Redirect(w, r, "/login", http.StatusFound)
		case 2:
			_, _ = io.WriteString(w, `<html>Please sign in</html>`)
		case 3:
			_, _ = io.WriteString(w, `{"code":6}`)
		default:
			_, _ = io.WriteString(w, `{"text":"Success","code":0}`)
		}
	}))
	t.Cleanup(server.Close)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: server.URL, Token: "token"})
	writeRecord(t, forwarder, `{"user":"alice"}`)
	forwarder.start()
	t.Cleanup(func() { _ = forwarder.Close() })
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	if got := attempts.Load(); got != 4 {
		t.Fatalf("delivery attempts = %d, want three retries and a confirmed success", got)
	}
	first := <-requests
	for range 3 {
		if got := <-requests; got != first {
			t.Fatalf("retried a different batch: %q, want %q", got, first)
		}
	}
}

func TestHECForwarderDropsRejectedBatchAndContinues(t *testing.T) {
	collector := newFakeCollector(t, http.StatusBadRequest)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"rejected"}`)
	waitForRequests(t, collector, 1)
	writeRecord(t, forwarder, `{"user":"accepted"}`)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got, want := strings.Join(eventUsers(collector.received()), ","), "rejected,accepted"; got != want {
		t.Fatalf("received users = %q, want %q (a rejected batch is not retried)", got, want)
	}
}

func TestHECForwarderVerifiesTLSByDefault(t *testing.T) {
	collector := newFakeCollector(t)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token"})
	forwarder.shutdownTimeout = 100 * time.Millisecond
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	if err := forwarder.Close(); err == nil {
		t.Fatal("Close() error = nil, want undelivered-events error")
	}
	if got := len(collector.received()); got != 0 {
		t.Fatalf("collector with an untrusted certificate received %d requests, want 0", got)
	}
}

func TestHECForwarderCloseAbandonsQueueAfterDeadline(t *testing.T) {
	collector := newFakeCollector(t, http.StatusServiceUnavailable)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})
	forwarder.retryInitial = time.Hour
	forwarder.retryLimit = time.Hour
	forwarder.shutdownTimeout = 50 * time.Millisecond
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	waitForRequests(t, collector, 1)

	started := time.Now()
	if err := forwarder.Close(); err == nil {
		t.Fatal("Close() error = nil, want undelivered-events error")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("Close() took %s despite a %s shutdown deadline", elapsed, forwarder.shutdownTimeout)
	}
}

func TestHECForwarderWriteNeverBlocksWhenQueueIsFull(t *testing.T) {
	forwarder := newTestForwarder(t, HECConfig{Endpoint: "https://splunk.example.test", Token: "token"})
	forwarder.queue = make(chan []byte, 2)

	var output strings.Builder
	previousLogWriter := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })

	// The sender is not running, so nothing drains the queue.
	for range 5 {
		writeRecord(t, forwarder, `{"user":"alice"}`)
	}
	if got := forwarder.dropped.Load(); got != 3 {
		t.Fatalf("dropped = %d, want 3", got)
	}

	forwarder.reportDropped()
	if !strings.Contains(output.String(), "3 audit event(s) could not be forwarded") {
		t.Errorf("drop report = %q, want the dropped count", output.String())
	}
	if got := forwarder.dropped.Load(); got != 0 {
		t.Errorf("dropped after report = %d, want 0", got)
	}
}

func TestHECForwarderDropsInvalidRecord(t *testing.T) {
	forwarder := newTestForwarder(t, HECConfig{Endpoint: "https://splunk.example.test", Token: "token"})

	writeRecord(t, forwarder, `{"user":`)
	if got := forwarder.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if got := len(forwarder.queue); got != 0 {
		t.Fatalf("queue length = %d, want 0", got)
	}
}

func waitForRequests(t *testing.T, collector *fakeCollector, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(collector.received()) < count {
		if time.Now().After(deadline) {
			t.Fatalf("collector received %d requests, want at least %d", len(collector.received()), count)
		}
		time.Sleep(time.Millisecond)
	}
}
