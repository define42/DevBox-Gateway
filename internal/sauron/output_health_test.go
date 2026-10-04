package sauron

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

func TestCollectorReadinessTracksOutputFailureAndRecovery(t *testing.T) {
	failure := errors.New("temporary output failure")
	first, second := &healthTestSink{}, &healthTestSink{writeErr: failure}
	observed := &observedSink{Sink: collector.NewMultiSink(first, second)}
	server, err := collector.New(collector.Options{
		Config: collector.DefaultConfig(), Sink: observed, Listener: tcpListener(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	c := &Collector{server: server, output: observed, done: make(chan struct{})}
	if err := observed.Write(t.Context(), &collector.Envelope{}); !errors.Is(err, failure) {
		t.Fatalf("output error = %v, want failure", err)
	}
	if err := c.Readiness(); !errors.Is(err, failure) {
		t.Fatalf("healthy first output masked failed second output: %v", err)
	}
	if err := observed.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c.Readiness() == nil {
		t.Fatal("successful flush masked rejected event")
	}
	second.writeErr = nil
	if err := observed.Write(t.Context(), &collector.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Readiness(); err != nil {
		t.Fatalf("successful all-output write did not restore readiness: %v", err)
	}
	second.flushErr = failure
	if err := observed.Flush(t.Context()); !errors.Is(err, failure) || c.Readiness() == nil {
		t.Fatalf("flush failure not reflected in readiness: %v", err)
	}
}

func TestOutputHealthInflightSuccessCannotMaskNewerFailure(t *testing.T) {
	for _, guest := range []bool{false, true} {
		env := &collector.Envelope{}
		if guest {
			env = healthGuestEnvelope("vm-a", 1)
		}
		sink := &concurrentHealthTestSink{entered: make(chan struct{}), release: make(chan struct{})}
		observed := &observedSink{Sink: sink}
		finished := make(chan error, 1)
		go func() { finished <- observed.Write(t.Context(), env) }()
		<-sink.entered
		err := observed.Write(t.Context(), env)
		close(sink.release)
		if err == nil {
			t.Fatal("second write should fail")
		}
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
		if observed.readiness() == nil {
			t.Fatalf("in-flight success cleared a more recent output failure (guest=%v)", guest)
		}
		if err := observed.Write(t.Context(), env); err != nil || observed.readiness() != nil {
			t.Fatalf("subsequent matching write did not restore readiness: %v", err)
		}
	}
}

type concurrentHealthTestSink struct {
	healthTestSink

	calls   atomic.Uint32
	entered chan struct{}
	release chan struct{}
}

func (s *concurrentHealthTestSink) Write(context.Context, *collector.Envelope) error {
	switch s.calls.Add(1) {
	case 1:
		close(s.entered)
		<-s.release
	case 2:
		return errors.New("output failed while first write was in flight")
	}
	return nil
}

type healthTestSink struct {
	writeErr error
	flushErr error
}

func (s *healthTestSink) Write(context.Context, *collector.Envelope) error { return s.writeErr }
func (s *healthTestSink) Flush(context.Context) error                      { return s.flushErr }
func (*healthTestSink) Close() error                                       { return nil }
func (*healthTestSink) Name() string                                       { return "health-test" }
