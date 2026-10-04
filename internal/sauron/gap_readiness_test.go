package sauron

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

func startHealthCollector(t *testing.T, sink collector.Sink) (*Collector, net.Listener) {
	t.Helper()
	listener := tcpListener(t)
	observed := &observedSink{Sink: sink}
	cfg := collector.DefaultConfig()
	cfg.Limits.AckInterval = 1
	server, err := collector.New(collector.Options{Config: cfg, Sink: observed, Listener: listener})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	observed.startRetries(ctx)
	c := &Collector{server: server, output: observed, cancel: cancel, done: make(chan struct{})}
	go func() { c.runErr = server.Run(ctx); close(c.done) }()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, listener
}

func connectHealthAgent(t *testing.T, listener net.Listener, boot string) *fakeAgent {
	t.Helper()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	agent := newFakeAgent(t, conn)
	agent.handshake(boot)
	return agent
}

func receiveHealthFrame(t *testing.T, agent *fakeAgent, want byte) []byte {
	t.Helper()
	for {
		typ, body, err := agent.receive()
		if err != nil {
			t.Fatal(err)
		}
		if typ == want {
			return body
		}
	}
}

func receiveHealthACK(t *testing.T, agent *fakeAgent, want uint64) {
	t.Helper()
	var ack struct {
		Sequence uint64 `json:"sequence"`
	}
	for ack.Sequence < want {
		if err := json.Unmarshal(receiveHealthFrame(t, agent, msgAck), &ack); err != nil {
			t.Fatal(err)
		}
	}
	if ack.Sequence != want {
		t.Fatalf("ACK = %d, want %d", ack.Sequence, want)
	}
}

func receiveHealthPONG(t *testing.T, agent *fakeAgent) {
	t.Helper()
	agent.send(5, 0, map[string]any{"audit_enabled": true})
	receiveHealthFrame(t, agent, 6)
}

type gapCapacitySink struct {
	healthTestSink

	store       *spool
	gapAttempts atomic.Uint32
	accepted    atomic.Uint32
}

func (s *gapCapacitySink) Write(ctx context.Context, env *collector.Envelope) error {
	if env.Event != nil && env.Event.Type == "sauron.stream.gap" && s.gapAttempts.Add(1) == 1 {
		if err := s.fillBeforeGap(env); err != nil {
			return err
		}
	}
	err := (&hecForwarding{spool: s.store}).Write(ctx, env)
	if err == nil && env.Event != nil && env.Event.Sequence > 0 {
		s.accepted.Add(1)
	}
	return err
}

func (s *gapCapacitySink) fillBeforeGap(env *collector.Envelope) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(env); err != nil {
		return err
	}
	s.store.mu.Lock()
	fillerSize := s.store.maxBytes - s.store.total - int64(encoded.Len()-1)
	s.store.mu.Unlock()
	const overhead = len(`{"padding":""}`) + 1
	if fillerSize < int64(overhead) {
		return fmt.Errorf("insufficient fixture capacity: %d", fillerSize)
	}
	filler := []byte(`{"padding":"` + strings.Repeat("x", int(fillerSize)-overhead) + `"}`)
	return s.store.Append(filler)
}

func TestCollectorRetainsGapReadinessAndRetriesAfterGuestDisconnects(t *testing.T) {
	sink := &gapCapacitySink{store: openTestSpool(t, t.TempDir(), 1<<20)}
	c, listener := startHealthCollector(t, sink)
	agent := connectHealthAgent(t, listener, "gap-boot")
	agent.sendEvent(1, "gap-boot")
	receiveHealthACK(t, agent, 1)
	agent.sendEvent(3, "gap-boot")
	receiveHealthPONG(t, agent)
	if sink.gapAttempts.Load() < 1 || sink.accepted.Load() != 2 {
		t.Fatalf("gap attempts = %d, accepted guest events = %d", sink.gapAttempts.Load(), sink.accepted.Load())
	}
	if err := c.Readiness(); err == nil || !strings.Contains(err.Error(), "audit gap") {
		t.Fatalf("unpublished gap was masked by smaller accepted guest event: %v", err)
	}
	records, delivered := readAll(t, sink.store, spoolPosition{})
	assertGapRecordCount(t, records, 0)
	if err := agent.conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.store.acknowledge(delivered); err != nil {
		t.Fatal(err)
	}
	waitForCollectorReadiness(t, c)
	records, _ = readAll(t, sink.store, delivered)
	assertGapRecordCount(t, records, 1)
}

func assertGapRecordCount(t *testing.T, records []string, want int) {
	t.Helper()
	count := 0
	for _, record := range records {
		if strings.Contains(record, `"type":"sauron.stream.gap"`) {
			count++
		}
	}
	if count != want {
		t.Fatalf("persisted gap reports = %d, want %d", count, want)
	}
}

func waitForCollectorReadiness(t *testing.T, c *Collector) {
	t.Helper()
	deadline := time.NewTimer(testTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := c.Readiness(); err == nil {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal(errors.Join(errors.New("collector did not recover readiness"), c.Readiness()))
		}
	}
}
