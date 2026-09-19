package sauron

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/collector"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

const testTimeout = 5 * time.Second

// hecReply is how the fake collector answers a request.
type hecReply int

const (
	hecOK hecReply = iota
	hecBusy
	hecBadIndex      // HEC code 7: a configuration problem
	hecInvalidFormat // HEC code 6: the event itself is invalid
	hecTooLarge      // HTTP 413: the event itself is too large
)

// write sends the reply the way Splunk HEC does.
func (r hecReply) write(w http.ResponseWriter) {
	status, code := http.StatusOK, 0
	switch r {
	case hecOK:
	case hecBusy:
		status, code = http.StatusServiceUnavailable, 9
	case hecBadIndex:
		status, code = http.StatusBadRequest, 7
	case hecInvalidFormat:
		status, code = http.StatusBadRequest, 6
	case hecTooLarge:
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = io.WriteString(w, "Content-Length of 9999999 too large (maximum is 1000000)")
		return
	}
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"text":"scripted","code":%d}`, code)
}

// fakeHEC is a Splunk HEC stand-in. Each request is answered by respond,
// which defaults to hecOK; events it accepted are recorded.
type fakeHEC struct {
	t       *testing.T
	server  *httptest.Server
	mu      sync.Mutex
	respond func(events []map[string]any) hecReply
	// hold, while set, parks every request until it is closed.
	hold     chan struct{}
	requests int
	accepted []map[string]any
	arrived  chan struct{}
}

func newFakeHEC(t *testing.T) *fakeHEC {
	t.Helper()
	hec := &fakeHEC{t: t, arrived: make(chan struct{}, 4096)}
	hec.server = httptest.NewServer(http.HandlerFunc(hec.handle))
	t.Cleanup(hec.server.Close)
	return hec
}

func (h *fakeHEC) handle(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
		h.t.Errorf("Authorization = %q, want the configured token", got)
	}
	var events []map[string]any
	decoder := json.NewDecoder(r.Body)
	for {
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			if !errors.Is(err, io.EOF) {
				h.t.Errorf("request body is not concatenated JSON events: %v", err)
			}
			break
		}
		events = append(events, event)
	}

	h.mu.Lock()
	h.requests++
	respond, hold := h.respond, h.hold
	h.mu.Unlock()
	select {
	case h.arrived <- struct{}{}:
	default:
	}
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return
		}
	}

	reply := hecOK
	if respond != nil {
		reply = respond(events)
	}
	if reply == hecOK {
		h.mu.Lock()
		h.accepted = append(h.accepted, events...)
		h.mu.Unlock()
	}
	reply.write(w)
}

// always answers every request the same way.
func always(reply hecReply) func([]map[string]any) hecReply {
	return func([]map[string]any) hecReply { return reply }
}

func (h *fakeHEC) set(respond func(events []map[string]any) hecReply) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.respond = respond
}

func (h *fakeHEC) holdRequests() (release func()) {
	hold := make(chan struct{})
	h.mu.Lock()
	h.hold = hold
	h.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			h.hold = nil
			h.mu.Unlock()
			close(hold)
		})
	}
}

func (h *fakeHEC) waitForRequest(t *testing.T) {
	t.Helper()
	select {
	case <-h.arrived:
	case <-time.After(testTimeout):
		t.Fatal("no request reached the collector")
	}
}

func (h *fakeHEC) snapshot() (requests int, accepted []map[string]any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests, append([]map[string]any(nil), h.accepted...)
}

// waitAccepted waits until the collector has accepted n events and returns them.
func (h *fakeHEC) waitAccepted(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(testTimeout)
	for {
		_, accepted := h.snapshot()
		if len(accepted) >= n {
			return accepted
		}
		if time.Now().After(deadline) {
			t.Fatalf("collector accepted %d events, want %d", len(accepted), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *fakeHEC) config(index string) splunkhec.Config {
	return splunkhec.Config{Endpoint: h.server.URL, Token: "test-token", Index: index}
}

// newTestForwarding opens a forwarding sink on dir with fast retries.
func newTestForwarding(t *testing.T, hec *fakeHEC, dir string, maxBytes int64) *hecForwarding {
	t.Helper()
	forwarding, err := newHECForwarding(hec.config("sauron"), dir, maxBytes)
	if err != nil {
		t.Fatalf("newHECForwarding() error = %v", err)
	}
	forwarding.retryInitial = time.Millisecond
	forwarding.retryLimit = 5 * time.Millisecond
	forwarding.start()
	t.Cleanup(func() { _ = forwarding.Close() })
	return forwarding
}

func testEnvelope(vm string, seq uint64) *collector.Envelope {
	return &collector.Envelope{
		ReceivedAt: time.Unix(1789752345, 318_000_000).UTC(),
		Source:     collector.Source{CID: 7, VM: vm, Host: "hypervisor-01", Known: true, Labels: map[string]string{"owner": "alice"}},
		Event: &collector.Event{
			Version:   1,
			Sequence:  seq,
			Timestamp: time.Unix(946684800, 0).UTC(), // a guest clock far in the past
			Type:      "process.exec",
			BootID:    "boot-1",
			Command:   "cat /etc/shadow > /tmp/x && true",
		},
	}
}

func write(t *testing.T, sink collector.Sink, vm string, seqs ...uint64) {
	t.Helper()
	for _, seq := range seqs {
		if err := sink.Write(context.Background(), testEnvelope(vm, seq)); err != nil {
			t.Fatalf("Write(%s %d) error = %v", vm, seq, err)
		}
	}
}

func eventOf(hecEvent map[string]any) map[string]any {
	envelope, _ := hecEvent["event"].(map[string]any)
	return envelope
}

func sequenceOf(hecEvent map[string]any) float64 {
	event, _ := eventOf(hecEvent)["event"].(map[string]any)
	sequence, _ := event["sequence"].(float64)
	return sequence
}

func assertSequences(t *testing.T, accepted []map[string]any, want ...float64) {
	t.Helper()
	if len(accepted) != len(want) {
		t.Fatalf("collector accepted %d events, want %d", len(accepted), len(want))
	}
	for i, event := range accepted {
		if got := sequenceOf(event); got != want[i] {
			t.Fatalf("event %d has sequence %v, want %v (delivery out of order or duplicated)", i, got, want[i])
		}
	}
}

func TestForwardingDeliversSpooledEventsToHEC(t *testing.T) {
	hec := newFakeHEC(t)
	forwarding := newTestForwarding(t, hec, t.TempDir(), 1<<20)

	write(t, forwarding, "alice-dev", 1)

	got := hec.waitAccepted(t, 1)[0]
	for key, want := range map[string]any{
		"host":       "alice-dev",
		"source":     hecSource,
		"sourcetype": hecSourcetype,
		"index":      "sauron",
		// The gateway's receive time, not the guest's clock.
		"time": 1789752345.318,
	} {
		if got[key] != want {
			t.Errorf("HEC %s = %v, want %v", key, got[key], want)
		}
	}
	envelope := eventOf(got)
	source, _ := envelope["source"].(map[string]any)
	labels, _ := source["labels"].(map[string]any)
	event, _ := envelope["event"].(map[string]any)
	if source["vm"] != "alice-dev" || labels["owner"] != "alice" || event["command"] != "cat /etc/shadow > /tmp/x && true" {
		t.Errorf("HEC event does not carry the collector envelope: %v", envelope)
	}
	if event["timestamp"] != "2000-01-01T00:00:00Z" {
		t.Errorf("guest timestamp = %v, want it kept in the envelope", event["timestamp"])
	}
}

func TestForwardingAcceptsEventsWhileSplunkIsDown(t *testing.T) {
	hec := newFakeHEC(t)
	hec.set(always(hecBusy))
	forwarding := newTestForwarding(t, hec, t.TempDir(), 1<<20)

	// Writes succeed -- the guest is released -- although Splunk refuses.
	write(t, forwarding, "alice-dev", 1, 2, 3)
	hec.waitForRequest(t)
	hec.waitForRequest(t)

	hec.set(nil)
	assertSequences(t, hec.waitAccepted(t, 3), 1, 2, 3)
}

func TestForwardingSurvivesAGatewayRestart(t *testing.T) {
	hec := newFakeHEC(t)
	dir := t.TempDir()

	first, err := newHECForwarding(hec.config("sauron"), dir, 1<<20)
	if err != nil {
		t.Fatalf("newHECForwarding() error = %v", err)
	}
	first.start()
	write(t, first, "alice-dev", 1)
	hec.waitAccepted(t, 1)

	hec.set(always(hecBusy))
	write(t, first, "alice-dev", 2, 3)
	hec.waitForRequest(t)
	if err := first.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Splunk comes back only after the gateway restarted: the spooled events
	// are delivered, and the one delivered before the restart is not resent.
	hec.set(nil)
	newTestForwarding(t, hec, dir, 1<<20)
	assertSequences(t, hec.waitAccepted(t, 3), 1, 2, 3)
	time.Sleep(50 * time.Millisecond)
	_, accepted := hec.snapshot()
	assertSequences(t, accepted, 1, 2, 3)
}

func TestForwardingDropsAnEventSplunkWillNeverTake(t *testing.T) {
	for name, verdict := range map[string]hecReply{"too large": hecTooLarge, "invalid data format": hecInvalidFormat} {
		t.Run(name, func(t *testing.T) { testForwardingDropsPoison(t, verdict) })
	}
}

func testForwardingDropsPoison(t *testing.T, verdict hecReply) {
	hec := newFakeHEC(t)
	// The collector rejects any request that contains the poison event.
	hec.set(func(events []map[string]any) hecReply {
		for _, event := range events {
			if event["host"] == "poison" {
				return verdict
			}
		}
		return hecOK
	})
	release := hec.holdRequests()
	defer release()
	forwarding := newTestForwarding(t, hec, t.TempDir(), 1<<20)

	// Park the first request so the next events share a batch.
	write(t, forwarding, "vm-a", 1)
	hec.waitForRequest(t)
	write(t, forwarding, "poison", 2)
	write(t, forwarding, "vm-b", 3)
	release()

	accepted := hec.waitAccepted(t, 2)
	assertSequences(t, accepted, 1, 3)

	// The backlog behind it keeps flowing.
	write(t, forwarding, "vm-c", 4)
	assertSequences(t, hec.waitAccepted(t, 3), 1, 3, 4)
}

func TestForwardingKeepsEventsSplunkRejectsAltogether(t *testing.T) {
	hec := newFakeHEC(t)
	// A misconfigured index rejects every request outright.
	hec.set(always(hecBadIndex))
	forwarding := newTestForwarding(t, hec, t.TempDir(), 1<<20)

	write(t, forwarding, "alice-dev", 1, 2, 3)
	for range 4 {
		hec.waitForRequest(t)
	}

	// Once the configuration is fixed, nothing was lost.
	hec.set(nil)
	assertSequences(t, hec.waitAccepted(t, 3), 1, 2, 3)
}

func TestForwardingCloseAbortsARequestInFlight(t *testing.T) {
	hec := newFakeHEC(t)
	release := hec.holdRequests()
	defer release()
	dir := t.TempDir()
	forwarding, err := newHECForwarding(hec.config("sauron"), dir, 1<<20)
	if err != nil {
		t.Fatalf("newHECForwarding() error = %v", err)
	}
	forwarding.start()
	write(t, forwarding, "alice-dev", 1)
	hec.waitForRequest(t)

	start := time.Now()
	if err := forwarding.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > testTimeout/2 {
		t.Fatalf("Close() took %s with a request in flight, want it aborted", elapsed)
	}
	if err := forwarding.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if err := forwarding.Write(context.Background(), testEnvelope("alice-dev", 2)); !errors.Is(err, errSpoolClosed) {
		t.Fatalf("Write() after Close = %v, want errSpoolClosed", err)
	}

	// The undelivered event is still spooled for the next start.
	release()
	newTestForwarding(t, hec, dir, 1<<20)
	assertSequences(t, hec.waitAccepted(t, 1), 1)
}

func TestForwardingWriteFailsWhenTheSpoolIsFull(t *testing.T) {
	hec := newFakeHEC(t)
	hec.set(always(hecBusy))
	forwarding := newTestForwarding(t, hec, t.TempDir(), 2048)

	var err error
	for seq := uint64(1); seq < 100 && err == nil; seq++ {
		err = forwarding.Write(context.Background(), testEnvelope("alice-dev", seq))
	}
	// Not accepted, so the collector does not acknowledge it and the guest
	// keeps the event.
	if !errors.Is(err, errSpoolFull) {
		t.Fatalf("Write() into a full spool = %v, want errSpoolFull", err)
	}
}

func TestForwardingWriteHonorsContext(t *testing.T) {
	forwarding := newTestForwarding(t, newFakeHEC(t), t.TempDir(), 1<<20)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := forwarding.Write(ctx, testEnvelope("alice-dev", 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Write() with a canceled context = %v, want context.Canceled", err)
	}
}

func TestNewHECForwardingRejectsInvalidConfig(t *testing.T) {
	if _, err := newHECForwarding(splunkhec.Config{Endpoint: "https://splunk.example.test"}, t.TempDir(), 1<<20); err == nil {
		t.Error("newHECForwarding() without a token succeeded, want an error")
	}
	if _, err := newHECForwarding(splunkhec.Config{Endpoint: "https://splunk.example.test", Token: "t"}, t.TempDir(), 0); err == nil {
		t.Error("newHECForwarding() without a spool size succeeded, want an error")
	}
}

func TestHECForwardingFlushAndName(t *testing.T) {
	forwarding := newTestForwarding(t, newFakeHEC(t), t.TempDir(), 1<<20)
	if err := forwarding.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if forwarding.Name() == "" {
		t.Fatal("Name() is empty")
	}
}

// TestForwardingNeverDropsForAConfigurationRejection covers the collector's
// configuration breaking while a batch is being isolated: an event the
// collector refuses for a configuration reason is kept, and only the event it
// calls invalid itself is dropped.
func TestForwardingNeverDropsForAConfigurationRejection(t *testing.T) {
	hec := newFakeHEC(t)
	var mu sync.Mutex
	requests := 0
	hec.set(func(events []map[string]any) hecReply {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if requests == 2 {
			// The first event sent on its own meets a broken index.
			return hecBadIndex
		}
		for _, event := range events {
			if event["host"] == "poison" {
				return hecInvalidFormat
			}
		}
		return hecOK
	})

	// Spool all three before delivery starts, so they share the first batch.
	forwarding, err := newHECForwarding(hec.config("sauron"), t.TempDir(), 1<<20)
	if err != nil {
		t.Fatalf("newHECForwarding() error = %v", err)
	}
	forwarding.retryInitial, forwarding.retryLimit = time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { _ = forwarding.Close() })
	write(t, forwarding, "vm-a", 1)
	write(t, forwarding, "poison", 2)
	write(t, forwarding, "vm-b", 3)
	forwarding.start()

	assertSequences(t, hec.waitAccepted(t, 2), 1, 3)
}

// readJSONLines decodes every line of a JSON Lines stream.
func readJSONLines(t *testing.T, r io.Reader) []map[string]any {
	t.Helper()
	var lines []map[string]any
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var line map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("line %q is not JSON: %v", scanner.Text(), err)
		}
		lines = append(lines, line)
	}
	return lines
}
