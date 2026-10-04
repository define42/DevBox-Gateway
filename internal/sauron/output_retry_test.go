package sauron

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

type retryCaptureSink struct {
	healthTestSink

	mu       sync.Mutex
	rejected map[uint64]bool
	attempts map[uint64]int
	accepted [][]byte
}

func newRetryCaptureSink() *retryCaptureSink {
	return &retryCaptureSink{rejected: make(map[uint64]bool), attempts: make(map[uint64]int)}
}

func (s *retryCaptureSink) Write(_ context.Context, env *collector.Envelope) error {
	encoded, err := json.Marshal(env)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[env.Event.Sequence]++
	if s.rejected[env.Event.Sequence] {
		return errors.New("temporary output rejection")
	}
	s.accepted = append(s.accepted, encoded)
	return nil
}

func TestOutputRetryPreservesOriginalRecordAndRequiresAllOutputs(t *testing.T) {
	first, second := newRetryCaptureSink(), newRetryCaptureSink()
	second.rejected[1] = true
	observed := &observedSink{Sink: collector.NewMultiSink(first, second)}
	original := healthGuestEnvelope("vm-a", 1)
	original.Source.Known = false
	original.Source.Labels = map[string]string{"owner": "original-owner"}
	original.Source.Reported = &collector.Reported{BootID: "original-connection", Hostname: "original-host"}
	original.Event.Fields = map[string]any{"nested": map[string]any{"count": uint64(9007199254740993)}}
	original.Event.Raw = []string{"original audit record"}
	want, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := observed.Write(t.Context(), original); err == nil {
		t.Fatal("expected second output rejection")
	}
	original.Source.Labels["owner"] = "changed-owner"
	original.Source.Reported.Hostname = "changed-host"
	original.Event.Fields["nested"].(map[string]any)["count"] = 0
	original.Event.Raw[0] = "changed record"
	if err := observed.Write(t.Context(), healthGuestEnvelope("other-vm", 2)); err != nil {
		t.Fatal(err)
	}
	observed.retryRejected(t.Context())
	if observed.readiness() == nil || len(observed.rejected) != 1 {
		t.Fatal("another record or a partial retry cleared the original rejection")
	}
	second.rejected[1] = false
	observed.retryRejected(t.Context())
	if err := observed.readiness(); err != nil {
		t.Fatalf("retained original did not recover readiness: %v", err)
	}
	for _, sink := range []*retryCaptureSink{first, second} {
		if got := sink.accepted[len(sink.accepted)-1]; !bytes.Equal(got, want) {
			t.Fatalf("retry changed pinned attribution or event fields:\n got %s\nwant %s", got, want)
		}
	}
	if observed.rejectedBytes != 0 || len(observed.rejected) != 0 {
		t.Fatal("successful retry retained its record")
	}
}

func TestOutputRetryPassIsBoundedAndRotatesFailedRecords(t *testing.T) {
	sink := newRetryCaptureSink()
	observed := &observedSink{Sink: sink}
	for seq := uint64(1); seq <= outputRetryBatch+1; seq++ {
		sink.rejected[seq] = true
		if err := observed.Write(t.Context(), healthGuestEnvelope("vm-a", seq)); err == nil {
			t.Fatal("expected output rejection")
		}
	}
	observed.retryRejected(t.Context())
	if sink.attempts[outputRetryBatch] != 2 || sink.attempts[outputRetryBatch+1] != 1 {
		t.Fatalf("retry pass exceeded its bound: %v", sink.attempts)
	}
	sink.rejected[outputRetryBatch+1] = false
	observed.retryRejected(t.Context())
	if sink.attempts[outputRetryBatch+1] != 2 || len(observed.rejected) != outputRetryBatch {
		t.Fatal("persistent earlier failures starved the next record")
	}
	if observed.readiness() == nil {
		t.Fatal("one successful retry hid other rejected records")
	}
}

func TestOutputRetryEncodedBytesAreBoundedAndOverflowStaysUnhealthy(t *testing.T) {
	sink := &healthTestSink{writeErr: errors.New("output unavailable")}
	observed := &observedSink{Sink: sink}
	env := healthGuestEnvelope("vm-a", 1)
	// Each event fits the collector's one-MiB wire payload limit.
	env.Event.Command = strings.Repeat("x", (1<<20)-4096)
	var last uint64
	for seq := uint64(1); seq <= 70; seq++ {
		env.Event.Sequence = seq
		if err := observed.Write(t.Context(), env); err == nil {
			t.Fatal("expected output rejection")
		}
		last = seq
		if observed.overflow {
			break
		}
	}
	if !observed.overflow || observed.rejectedBytes > maxRejectedGuestBytes {
		t.Fatalf("retry memory bound: bytes=%d overflow=%t", observed.rejectedBytes, observed.overflow)
	}
	sink.writeErr = nil
	for seq := uint64(1); seq <= last; seq++ {
		env.Event.Sequence = seq
		if err := observed.Write(t.Context(), env); err != nil {
			t.Fatal(err)
		}
	}
	if observed.rejectedBytes != 0 || len(observed.rejected) != 0 || observed.readiness() == nil {
		t.Fatal("overflow must remain visible after all retained records recover")
	}
}

type callbackRetrySink struct {
	healthTestSink

	write func(context.Context, *collector.Envelope) error
	close func() error
}

func (s *callbackRetrySink) Write(ctx context.Context, env *collector.Envelope) error {
	return s.write(ctx, env)
}

func (s *callbackRetrySink) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}

func TestOutputRetryCompletionCannotOverrideNewerLiveResult(t *testing.T) {
	for _, liveFails := range []bool{true, false} {
		t.Run(map[bool]string{true: "newer failure", false: "newer acceptance"}[liveFails], func(t *testing.T) {
			testOutputRetryCompletion(t, liveFails)
		})
	}
}

func testOutputRetryCompletion(t *testing.T, liveFails bool) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	sink := newLiveResultRetrySink(liveFails, entered, release)
	observed := &observedSink{Sink: sink}
	env := healthGuestEnvelope("vm-a", 1)
	if err := observed.Write(t.Context(), env); err == nil {
		t.Fatal("expected original rejection")
	}
	done := make(chan struct{})
	go func() { observed.retryRejected(t.Context()); close(done) }()
	<-entered
	err := observed.Write(t.Context(), env)
	observed.mu.Lock()
	retainedWhileWriting := observed.rejectedBytes
	observed.mu.Unlock()
	close(release)
	<-done
	if retainedWhileWriting == 0 {
		t.Fatal("in-flight original stopped counting against the byte budget")
	}
	if (err != nil) != liveFails || (observed.readiness() != nil) != liveFails {
		t.Fatalf("old retry changed newer live result: write=%v readiness=%v", err, observed.readiness())
	}
	observed.retryRejected(t.Context())
	if err := observed.readiness(); err != nil {
		t.Fatalf("latest retained rejection did not recover: %v", err)
	}
	if observed.rejectedBytes != 0 {
		t.Fatalf("completed retries retained %d encoded bytes", observed.rejectedBytes)
	}
}

func newLiveResultRetrySink(liveFails bool, entered, release chan struct{}) *callbackRetrySink {
	var calls atomic.Int32
	return &callbackRetrySink{write: func(context.Context, *collector.Envelope) error {
		switch calls.Add(1) {
		case 1:
			return errors.New("original rejection")
		case 2:
			close(entered)
			<-release
			if !liveFails {
				return errors.New("old retry failed after live success")
			}
		case 3:
			if liveFails {
				return errors.New("newer live rejection")
			}
		}
		return nil
	}}
}

func TestOutputRetryCloseCancelsWorkerBeforeClosingOutput(t *testing.T) {
	entered, finished := make(chan struct{}), make(chan struct{})
	var calls, closes atomic.Int32
	sink := &callbackRetrySink{
		write: func(ctx context.Context, _ *collector.Envelope) error {
			if calls.Add(1) == 1 {
				return errors.New("original rejection")
			}
			close(entered)
			<-ctx.Done()
			close(finished)
			return ctx.Err()
		},
		close: func() error {
			select {
			case <-finished:
			default:
				t.Error("output closed before retry stopped")
			}
			closes.Add(1)
			return nil
		},
	}
	observed := &observedSink{Sink: sink}
	if err := observed.Write(t.Context(), healthGuestEnvelope("vm-a", 1)); err == nil {
		t.Fatal("expected original rejection")
	}
	observed.startRetries(t.Context())
	observed.startRetries(t.Context())
	t.Cleanup(func() { _ = observed.Close() })
	select {
	case <-entered:
	case <-time.After(testTimeout):
		t.Fatal("retry worker did not start")
	}
	if err := observed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := observed.Close(); err != nil || closes.Load() != 1 {
		t.Fatalf("close is not idempotent: closes=%d err=%v", closes.Load(), err)
	}
	if observed.readiness() == nil || len(observed.rejected) != 1 {
		t.Fatal("shutdown discarded an unaccepted retained record")
	}
}
