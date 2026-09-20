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

// replayCollector records exact request bodies so restart tests can prove that
// persisted HEC routing metadata is replayed byte-for-byte.
type replayCollector struct {
	mu       sync.Mutex
	requests []string
	reject   atomic.Bool
	server   *httptest.Server
}

func newReplayCollector(t *testing.T) *replayCollector {
	t.Helper()
	collector := &replayCollector{}
	collector.reject.Store(true)
	collector.server = httptest.NewServer(http.HandlerFunc(collector.handle))
	t.Cleanup(collector.server.Close)
	return collector
}

func (c *replayCollector) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.mu.Lock()
	c.requests = append(c.requests, string(body))
	c.mu.Unlock()
	if c.reject.Load() {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"code":4}`)
		return
	}
	_, _ = io.WriteString(w, `{"code":0}`)
}

func (c *replayCollector) snapshotFrom(start int) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requests[start:]...)
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
	return newTestForwarderWithSpool(t, config, t.TempDir(), 1<<20)
}

func newTestForwarderWithSpool(t *testing.T, config HECConfig, dir string, capacity int64) *hecForwarder {
	t.Helper()
	forwarder, err := newHECForwarder(config, dir, capacity)
	if err != nil {
		t.Fatalf("newHECForwarder() error = %v", err)
	}
	forwarder.retryInitial = time.Millisecond
	forwarder.retryLimit = 5 * time.Millisecond
	t.Cleanup(func() { _ = forwarder.Close() })
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
			if forwarder, err := newHECForwarder(test.config, t.TempDir(), 1<<20); err == nil {
				_ = forwarder.Close()
				t.Fatal("newHECForwarder() error = nil, want non-nil")
			}
		})
	}
}

func TestNewHECForwarderRequiresUsableSpool(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		dir      string
		capacity int64
	}{
		{name: "empty directory", capacity: 1 << 20},
		{name: "blank directory", dir: " \t ", capacity: 1 << 20},
		{name: "zero capacity", dir: t.TempDir()},
		{name: "negative capacity", dir: t.TempDir(), capacity: -1},
		{name: "directory is a file", dir: blocker, capacity: 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := HECConfig{Endpoint: "https://splunk.example.test", Token: "token"}
			forwarder, err := newHECForwarder(cfg, tc.dir, tc.capacity)
			if err == nil {
				_ = forwarder.Close()
				t.Fatal("invalid persistent spool configuration accepted")
			}
		})
	}
}

func TestConfigureForwardsAuditRecordsToHEC(t *testing.T) {
	collector := newFakeCollector(t)
	path := filepath.Join(t.TempDir(), "unused", "audit.jsonl")

	closer, err := Configure(Options{
		FilePath:      path,
		SpoolDir:      t.TempDir(),
		SpoolMaxBytes: 1 << 20,
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
	// The healthy collector receives the pending spool records during Close.
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
		FilePath:      path,
		SpoolDir:      t.TempDir(),
		SpoolMaxBytes: 1 << 20,
		HEC:           HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
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
	if len(requests) != 2 || strings.Join(eventUsers(requests), ",") != "rejected,rejected" {
		t.Fatalf("collector requests = %#v, want rejected event retried until accepted", requests)
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
		FilePath:      path,
		SpoolDir:      t.TempDir(),
		SpoolMaxBytes: 1 << 20,
		HEC:           HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
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
				FilePath:      test.path,
				SpoolDir:      t.TempDir(),
				SpoolMaxBytes: 1 << 20,
				HEC:           HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
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
		SpoolDir:      t.TempDir(),
		SpoolMaxBytes: 1 << 20,
		HEC:           HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true},
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
			closer, err := Configure(Options{FilePath: path, SpoolDir: t.TempDir(), SpoolMaxBytes: 1 << 20, HEC: test.config})
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

func TestHECForwarderDeliversSpooledRecordsInOrder(t *testing.T) {
	collector := newFakeCollector(t)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})

	// Records written before startup must be delivered in their original order.
	for _, user := range []string{"alice", "bob", "carol"} {
		writeRecord(t, forwarder, `{"user":"`+user+`"}`)
	}
	forwarder.start()
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := collector.received()
	if got, want := strings.Join(eventUsers(requests), ","), "alice,bob,carol"; got != want {
		t.Fatalf("batched users = %q, want %q", got, want)
	}
}

func TestHECForwarderRetriesAllHTTPFailures(t *testing.T) {
	collector := newFakeCollector(t, http.StatusServiceUnavailable, http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	requests := collector.received()
	if len(requests) != 5 {
		t.Fatalf("collector received %d requests, want 4 failures and 1 success", len(requests))
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

func TestHECForwarderRetainsRejectedBatchAndContinuesAfterAcceptance(t *testing.T) {
	collector := newFakeCollector(t, http.StatusBadRequest)
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true})
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"rejected"}`)
	waitForRequests(t, collector, 1)
	writeRecord(t, forwarder, `{"user":"accepted"}`)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got, want := strings.Join(eventUsers(collector.received()), ","), "rejected,rejected,accepted"; got != want {
		t.Fatalf("received users = %q, want %q (rejected events must be retried)", got, want)
	}
}

func TestHECForwarderVerifiesTLSByDefault(t *testing.T) {
	collector := newFakeCollector(t)
	dir := t.TempDir()
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
	forwarder.shutdownTimeout = 100 * time.Millisecond
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() must retain undelivered events without treating an outage as a close failure: %v", err)
	}
	if got := len(collector.received()); got != 0 {
		t.Fatalf("collector with an untrusted certificate received %d requests, want 0", got)
	}

	recovered := newTestForwarderWithSpool(t, HECConfig{
		Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true,
	}, dir, 1<<20)
	recovered.start()
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(eventUsers(collector.received()), ","); got != "alice" {
		t.Fatalf("recovered users = %q, want the event retained through TLS failure", got)
	}
}

func TestHECForwarderCloseRetainsSpoolAfterDeadline(t *testing.T) {
	collector := newFakeCollector(t, http.StatusServiceUnavailable)
	dir := t.TempDir()
	cfg := HECConfig{Endpoint: collector.server.URL, Token: "token", InsecureSkipVerify: true}
	forwarder := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	forwarder.retryInitial = time.Hour
	forwarder.retryLimit = time.Hour
	forwarder.shutdownTimeout = 50 * time.Millisecond
	forwarder.start()

	writeRecord(t, forwarder, `{"user":"alice"}`)
	waitForRequests(t, collector, 1)

	started := time.Now()
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v, want pending records retained without error", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("Close() took %s despite a %s shutdown deadline", elapsed, forwarder.shutdownTimeout)
	}
	recovered := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	recovered.start()
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(eventUsers(collector.received()), ","); got != "alice,alice" {
		t.Fatalf("delivery attempts = %q, want failed event replayed after restart", got)
	}
}

func TestHECForwarderRejectsInvalidRecord(t *testing.T) {
	forwarder := newTestForwarder(t, HECConfig{Endpoint: "https://splunk.example.test", Token: "token"})
	if n, err := forwarder.Write([]byte(`{"user":`)); err == nil || n != 0 {
		t.Fatalf("Write(invalid JSON) = %d, %v; want 0 and an error", n, err)
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHECForwarderReplayPreservesOriginalEnvelope(t *testing.T) {
	collector := newReplayCollector(t)
	dir := t.TempDir()
	cfg := HECConfig{Endpoint: collector.server.URL, Token: "token", Index: "original-index"}
	first := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	first.host = "original-host"
	first.shutdownTimeout = 30 * time.Millisecond
	const originalEvent = `{"time":"2001-02-03T04:05:06Z","user":"alice","source_ip":"192.0.2.42"}`
	writeRecord(t, first, originalEvent)
	first.start()
	if err := first.Close(); err != nil {
		t.Fatalf("close while HEC rejects: %v", err)
	}
	failedAttempts := collector.snapshotFrom(0)
	if len(failedAttempts) == 0 {
		t.Fatal("no initial delivery attempted")
	}

	// A new process may have a different hostname/index configuration. Records
	// already accepted into the spool must keep their original complete envelope.
	collector.reject.Store(false)
	cfg.Index = "new-index"
	recovered := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	recovered.host = "new-host"
	recovered.start()
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	replayed := collector.snapshotFrom(len(failedAttempts))
	if len(replayed) != 1 || replayed[0] != failedAttempts[0] {
		t.Fatalf("replay changed or lost the original envelope: replay=%q, original=%q", replayed, failedAttempts[0])
	}
	envelopes := decodeEnvelopes(t, strings.NewReader(replayed[0]))
	if len(envelopes) != 1 {
		t.Fatalf("replayed envelopes=%d, want 1", len(envelopes))
	}
	assertFields(t, "replayed envelope", envelopes[0], map[string]any{"host": "original-host", "index": "original-index"})
	event, _ := envelopes[0]["event"].(map[string]any)
	assertFields(t, "replayed event", event, map[string]any{"time": "2001-02-03T04:05:06Z", "user": "alice", "source_ip": "192.0.2.42"})

	// A persisted success checkpoint prevents already delivered records from
	// being sent again on the following restart.
	third := newTestForwarderWithSpool(t, cfg, dir, 1<<20)
	writeRecord(t, third, `{"user":"bob"}`)
	third.start()
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
	finalRequests := collector.snapshotFrom(len(failedAttempts) + 1)
	if len(finalRequests) != 1 || strings.Contains(finalRequests[0], "alice") || !strings.Contains(finalRequests[0], "bob") {
		t.Fatalf("acknowledged event was replayed: %q", finalRequests)
	}
}

func TestHECForwarderFullSpoolBlocksUntilClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":9}`)
	}))
	t.Cleanup(server.Close)
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: server.URL, Token: "token"}, t.TempDir(), 512)
	forwarder.host = "test-host"
	forwarder.shutdownTimeout = 30 * time.Millisecond
	record := `{"user":"` + strings.Repeat("a", 200) + `"}`
	writeRecord(t, forwarder, record)
	forwarder.start()

	written := make(chan error, 1)
	go func() {
		_, err := forwarder.Write([]byte(record))
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("full-spool Write returned before space became available or shutdown: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("blocked writer reported success without persisting its record")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the full-spool writer")
	}
	if n, err := forwarder.Write([]byte(`{"user":"after-close"}`)); n != 0 || err == nil {
		t.Fatalf("Write after Close = %d, %v; want 0 and an error", n, err)
	}
}

func TestHECForwarderFullSpoolResumesAfterDelivery(t *testing.T) {
	var reject atomic.Bool
	reject.Store(true)
	var acceptedMu sync.Mutex
	var accepted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		events := decodeEnvelopes(t, r.Body)
		if reject.Load() {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"code":4}`)
			return
		}
		acceptedMu.Lock()
		accepted = append(accepted, eventUsers([]hecRequest{{events: events}})...)
		acceptedMu.Unlock()
		_, _ = io.WriteString(w, `{"code":0}`)
	}))
	t.Cleanup(server.Close)
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: server.URL, Token: "token"}, t.TempDir(), 512)
	forwarder.host = "test-host"
	firstUser, secondUser := strings.Repeat("a", 200), strings.Repeat("b", 200)
	writeRecord(t, forwarder, `{"user":"`+firstUser+`"}`)
	forwarder.start()

	record := []byte(`{"user":"` + secondUser + `"}`)
	written := make(chan error, 1)
	go func() {
		n, err := forwarder.Write(record)
		if err == nil && n != len(record) {
			t.Errorf("resumed Write persisted %d bytes, want %d", n, len(record))
		}
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("full-spool Write returned while HEC was still rejecting: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	reject.Store(false)
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("writer failed after confirmed delivery released capacity: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirmed HEC delivery did not release the blocked writer")
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
	acceptedMu.Lock()
	defer acceptedMu.Unlock()
	if len(accepted) != 2 || accepted[0] != firstUser || accepted[1] != secondUser {
		t.Fatalf("accepted events=%q, want both persisted records in order", accepted)
	}
}

func TestConfigureBeginShutdownUnblocksFullSpoolWriter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	closer, err := Configure(Options{
		SpoolDir:      t.TempDir(),
		SpoolMaxBytes: 512,
		HEC:           HECConfig{Endpoint: server.URL, Token: "token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closer.Close() })
	sink := closer.(*configuredSink)
	sink.forwarder.host = "test-host"
	sink.forwarder.shutdownTimeout = 30 * time.Millisecond
	record := `{"user":"` + strings.Repeat("a", 200) + `"}`
	writeRecord(t, sink.forwarder, record)
	written := make(chan error, 1)
	go func() {
		_, err := sink.forwarder.Write([]byte(record))
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("full-spool writer returned before shutdown: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	sink.BeginShutdown()
	select {
	case err := <-written:
		if err == nil {
			t.Fatal("unpersisted writer returned success during shutdown")
		}
	case <-time.After(time.Second):
		t.Fatal("BeginShutdown did not release the writer before Close")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHECForwarderRejectsRecordLargerThanCapacity(t *testing.T) {
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: "https://splunk.example.test", Token: "token"}, t.TempDir(), 512)
	result := make(chan error, 1)
	go func() {
		_, err := forwarder.Write([]byte(`{"user":"` + strings.Repeat("a", 1024) + `"}`))
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("oversized record accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("oversized record blocked even though it can never fit")
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
