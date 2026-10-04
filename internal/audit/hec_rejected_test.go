package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// verdictCollector answers each request with the reply chosen by verdict for
// its decoded event users, and records the users of every accepted request.
type verdictCollector struct {
	mu       sync.Mutex
	verdict  func(users []string) (int, string)
	requests [][]string
	accepted []string
	server   *httptest.Server
}

func newVerdictCollector(t *testing.T, verdict func(users []string) (int, string)) *verdictCollector {
	t.Helper()
	collector := &verdictCollector{verdict: verdict}
	collector.server = httptest.NewServer(http.HandlerFunc(collector.handle))
	t.Cleanup(collector.server.Close)
	return collector
}

func (c *verdictCollector) handle(w http.ResponseWriter, r *http.Request) {
	var users []string
	decoder := json.NewDecoder(r.Body)
	for {
		var envelope struct {
			Event struct {
				User string `json:"user"`
			} `json:"event"`
		}
		if err := decoder.Decode(&envelope); err != nil {
			break
		}
		users = append(users, envelope.Event.User)
	}
	c.mu.Lock()
	verdict := c.verdict
	c.requests = append(c.requests, users)
	status, body := verdict(users)
	if status == http.StatusOK && body == hecSuccessReply {
		c.accepted = append(c.accepted, users...)
	}
	c.mu.Unlock()
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (c *verdictCollector) setVerdict(verdict func(users []string) (int, string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verdict = verdict
}

func (c *verdictCollector) acceptedUsers() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.accepted, ",")
}

func (c *verdictCollector) requestCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *verdictCollector) waitForRequests(t *testing.T, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.requestCount() < count {
		if time.Now().After(deadline) {
			t.Fatalf("collector received %d requests, want at least %d", c.requestCount(), count)
		}
		time.Sleep(time.Millisecond)
	}
}

const (
	hecSuccessReply       = `{"text":"Success","code":0}`
	hecInvalidFormatReply = `{"text":"Invalid data format","code":6}`
)

// rejectPoison refuses any request containing the "poison" user as invalid.
func rejectPoison(users []string) (int, string) {
	for _, user := range users {
		if user == "poison" {
			return http.StatusBadRequest, hecInvalidFormatReply
		}
	}
	return http.StatusOK, hecSuccessReply
}

func rejectedUsers(t *testing.T, dir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, hecRejectedFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read rejected records: %v", err)
	}
	var users []string
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		var envelope struct {
			Sourcetype string `json:"sourcetype"`
			Event      struct {
				User string `json:"user"`
			} `json:"event"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("rejected record %q is not a complete HEC envelope: %v", line, err)
		}
		if envelope.Sourcetype != hecSourcetype {
			t.Errorf("rejected envelope sourcetype = %q, want %q", envelope.Sourcetype, hecSourcetype)
		}
		users = append(users, envelope.Event.User)
	}
	return users
}

func TestHECForwarderSetsAsideInvalidEventAndDeliversTheRest(t *testing.T) {
	collector := newVerdictCollector(t, rejectPoison)
	dir := t.TempDir()
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
	for _, user := range []string{"alice", "poison", "bob"} {
		writeRecord(t, forwarder, `{"user":"`+user+`"}`)
	}
	forwarder.start()
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got, want := collector.acceptedUsers(), "alice,bob"; got != want {
		t.Fatalf("accepted users = %q, want %q", got, want)
	}
	if got, want := strings.Join(rejectedUsers(t, dir), ","), "poison"; got != want {
		t.Fatalf("rejected users = %q, want %q", got, want)
	}

	// The checkpoint moved past every record: a restart resends nothing.
	before := collector.requestCount()
	restarted := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
	restarted.start()
	if err := restarted.Close(); err != nil {
		t.Fatalf("restarted Close() error = %v", err)
	}
	if got := collector.requestCount(); got != before {
		t.Fatalf("restart sent %d more requests, want none", got-before)
	}
}

func TestHECForwarderSplitsBatchRejectedAsTooLarge(t *testing.T) {
	collector := newVerdictCollector(t, func(users []string) (int, string) {
		if len(users) > 1 {
			return http.StatusRequestEntityTooLarge, `{"text":"Content too large"}`
		}
		return http.StatusOK, hecSuccessReply
	})
	dir := t.TempDir()
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
	for _, user := range []string{"alice", "bob", "carol"} {
		writeRecord(t, forwarder, `{"user":"`+user+`"}`)
	}
	forwarder.start()
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got, want := collector.acceptedUsers(), "alice,bob,carol"; got != want {
		t.Fatalf("accepted users = %q, want %q", got, want)
	}
	if got := rejectedUsers(t, dir); got != nil {
		t.Fatalf("set aside %q although each event was accepted on its own", got)
	}
}

func TestHECForwarderNeverSetsAsideOnConfigurationRejections(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reply  string
	}{
		{name: "invalid token", status: http.StatusForbidden, reply: `{"text":"Invalid token","code":4}`},
		{name: "incorrect index", status: http.StatusBadRequest, reply: `{"text":"Incorrect index","code":7}`},
		{name: "invalid data format on success status", status: http.StatusOK, reply: hecInvalidFormatReply},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var failures atomic.Int64
			collector := newVerdictCollector(t, func([]string) (int, string) {
				if failures.Add(1) <= 3 {
					return test.status, test.reply
				}
				return http.StatusOK, hecSuccessReply
			})
			dir := t.TempDir()
			forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
			writeRecord(t, forwarder, `{"user":"alice"}`)
			writeRecord(t, forwarder, `{"user":"bob"}`)
			forwarder.start()
			if err := forwarder.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got, want := collector.acceptedUsers(), "alice,bob"; got != want {
				t.Fatalf("accepted users = %q, want %q after retries", got, want)
			}
			if got := rejectedUsers(t, dir); got != nil {
				t.Fatalf("set aside %q on a configuration rejection", got)
			}
		})
	}
}

func TestHECForwarderPausesWhenRejectedEventCannotBePreserved(t *testing.T) {
	collector := newVerdictCollector(t, rejectPoison)
	dir := t.TempDir()
	// A directory in place of the rejected-records file makes preservation fail.
	if err := os.Mkdir(filepath.Join(dir, hecRejectedFile), 0o750); err != nil {
		t.Fatal(err)
	}
	forwarder := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
	for _, user := range []string{"alice", "poison", "bob"} {
		writeRecord(t, forwarder, `{"user":"`+user+`"}`)
	}
	forwarder.start()
	// The rejected batch, then alice and poison on their own.
	collector.waitForRequests(t, 3)
	time.Sleep(20 * time.Millisecond)
	if err := forwarder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := collector.acceptedUsers(); strings.Contains(got, "bob") {
		t.Fatalf("delivery moved past an event it could not preserve: accepted %q", got)
	}

	if err := os.Remove(filepath.Join(dir, hecRejectedFile)); err != nil {
		t.Fatal(err)
	}
	restarted := newTestForwarderWithSpool(t, HECConfig{Endpoint: collector.server.URL, Token: "token"}, dir, 1<<20)
	restarted.start()
	if err := restarted.Close(); err != nil {
		t.Fatalf("restarted Close() error = %v", err)
	}
	if got := collector.acceptedUsers(); !strings.HasSuffix(got, "bob") {
		t.Fatalf("accepted users = %q, want bob delivered after the restart", got)
	}
	if got, want := strings.Join(rejectedUsers(t, dir), ","), "poison"; got != want {
		t.Fatalf("rejected users = %q, want %q", got, want)
	}
}

func TestHECForwarderReadinessReportsStalledDelivery(t *testing.T) {
	collector := newVerdictCollector(t, func([]string) (int, string) {
		return http.StatusServiceUnavailable, `{"text":"Server is busy","code":9}`
	})
	forwarder := newTestForwarder(t, HECConfig{Endpoint: collector.server.URL, Token: "token"})
	var clockMu sync.Mutex
	clock := time.Unix(1_700_000_000, 0)
	forwarder.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(d)
	}
	forwarder.stallTimeout = time.Minute

	if err := forwarder.readiness(); err != nil {
		t.Fatalf("readiness() before any delivery = %v, want nil", err)
	}
	writeRecord(t, forwarder, `{"user":"alice"}`)
	forwarder.start()
	// The second request proves the first failure was recorded.
	collector.waitForRequests(t, 2)
	if err := forwarder.readiness(); err != nil {
		t.Fatalf("readiness() within the stall timeout = %v, want nil", err)
	}
	advance(time.Minute)
	if err := forwarder.readiness(); err == nil {
		t.Fatal("readiness() after the stall timeout = nil, want an error")
	}

	forwarder.stallTimeout = 0
	if err := forwarder.readiness(); err != nil {
		t.Fatalf("readiness() with the check disabled = %v, want nil", err)
	}
	forwarder.stallTimeout = time.Minute

	collector.setVerdict(func([]string) (int, string) { return http.StatusOK, hecSuccessReply })
	deadline := time.Now().Add(5 * time.Second)
	for forwarder.readiness() != nil {
		if time.Now().After(deadline) {
			t.Fatal("readiness() did not recover after delivery resumed")
		}
		time.Sleep(time.Millisecond)
	}
}
