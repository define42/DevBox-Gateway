package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/protocol"
	"github.com/define42/SauronAgent/internal/transport"
)

const testTimeout = 5 * time.Second

// recordingSink keeps every envelope it is given.
type recordingSink struct {
	mu     sync.Mutex
	envs   []*Envelope
	closed bool
}

func newRecordingSink() *recordingSink {
	return &recordingSink{}
}

func (s *recordingSink) Write(_ context.Context, env *Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.envs = append(s.envs, env)
	return nil
}

func (s *recordingSink) Flush(context.Context) error { return nil }

func (s *recordingSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *recordingSink) Name() string { return "recording" }

func (s *recordingSink) guestEvents() []*Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Envelope
	for _, env := range s.envs {
		if env.Event != nil && !event.IsInternal(env.Event.Type) {
			out = append(out, env)
		}
	}
	return out
}

// runServer starts srv and stops it when the test ends, failing the test if an
// orderly shutdown is reported as an error.
func runServer(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run() = %v, want nil after an orderly shutdown", err)
			}
		case <-time.After(testTimeout):
			t.Error("Run did not return after the context was cancelled")
		}
	})
}

// deliver plays a guest: HELLO, one EVENT, and waits for its ACK.
func deliver(t *testing.T, conn net.Conn) {
	t.Helper()
	agent := protocol.NewConn(conn, protocol.DefaultMaxPayloadSize)
	defer func() { _ = agent.Close() }()

	hello := &protocol.Hello{ProtocolVersion: protocol.Version, AgentVersion: "test", Hostname: "guest-claim", BootID: "boot-1"}
	if err := agent.Send(protocol.MsgHello, 0, hello, testTimeout); err != nil {
		t.Fatalf("send HELLO: %v", err)
	}
	if f, err := agent.Receive(testTimeout); err != nil || f.Type != protocol.MsgReady {
		t.Fatalf("after HELLO got %v, %v; want READY", f, err)
	}

	ev := &event.Event{Version: event.SchemaVersion, Sequence: 1, Timestamp: time.Now().UTC(), Type: event.TypeProcessExec, BootID: "boot-1"}
	if err := agent.Send(protocol.MsgEvent, ev.Sequence, &protocol.EventMessage{Event: ev}, testTimeout); err != nil {
		t.Fatalf("send EVENT: %v", err)
	}
	for {
		f, err := agent.Receive(testTimeout)
		if err != nil {
			t.Fatalf("waiting for ACK: %v", err)
		}
		if f.Type != protocol.MsgAck {
			continue
		}
		var ack protocol.Ack
		if err := protocol.DecodePayload(f, &ack); err != nil {
			t.Fatalf("decode ACK: %v", err)
		}
		if ack.Sequence == 1 {
			return
		}
	}
}

func TestNewServesAGuestThroughTheGivenListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Host.Name = "hypervisor-test"
	// Listen must still validate; the Listener option replaces the socket it
	// describes.
	cfg.Listen.Kind = TransportTCP
	cfg.Listen.TCPAddress = "127.0.0.1:1"
	cfg.Limits.AckInterval = 1

	resolveCalls := 0
	sink := newRecordingSink()
	srv, err := New(Options{
		Config:   cfg,
		Sink:     sink,
		Logger:   logging.Discard(),
		Listener: listener,
		Resolve: func(uint32) (VM, bool) {
			resolveCalls++
			return VM{}, false
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	runServer(t, srv)

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), testTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	deliver(t, conn)

	envs := sink.guestEvents()
	if len(envs) != 1 {
		t.Fatalf("got %d guest events, want 1", len(envs))
	}
	src := envs[0].Source
	if src.Known || src.Host != "hypervisor-test" {
		t.Errorf("Source = %+v, want an unknown TCP peer on hypervisor-test", src)
	}
	if src.Reported == nil || src.Reported.Hostname != "guest-claim" {
		t.Errorf("Reported = %+v, want the guest's claim", src.Reported)
	}
	if resolveCalls != 0 {
		t.Errorf("Resolve called %d times for a TCP peer, want 0: it has no CID", resolveCalls)
	}
}

func TestNewRejectsAMissingSink(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	if _, err := New(Options{Config: DefaultConfig(), Listener: listener}); err == nil {
		t.Fatal("New() without a sink succeeded, want an error")
	}
}

func TestResolveNamesAVSOCKGuest(t *testing.T) {
	// Needs an AF_VSOCK transport that can reach itself, such as the
	// vsock_loopback module; a loopback peer's CID is 1 (VMADDR_CID_LOCAL).
	listener, err := transport.ListenVSOCK(0, 0)
	if err != nil {
		t.Skipf("no AF_VSOCK listener on this host: %v", err)
	}
	addr, ok := listener.Addr().(*vsock.Addr)
	if !ok {
		_ = listener.Close()
		t.Fatalf("listener address %T is not a vsock address", listener.Addr())
	}
	conn, err := transport.NewVSOCKDialer(1, addr.Port).Dial(context.Background())
	if err != nil {
		_ = listener.Close()
		t.Skipf("no AF_VSOCK loopback transport on this host: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Limits.AckInterval = 1
	sink := newRecordingSink()
	srv, err := New(Options{
		Config:   cfg,
		Sink:     sink,
		Logger:   logging.Discard(),
		Listener: listener,
		Resolve: func(cid uint32) (VM, bool) {
			if cid != 1 {
				return VM{}, false
			}
			return VM{CID: cid, Name: "alice-dev", Labels: map[string]string{"owner": "alice"}}, true
		},
	})
	if err != nil {
		_ = conn.Close()
		_ = listener.Close()
		t.Fatalf("New() error = %v", err)
	}
	runServer(t, srv)
	deliver(t, conn)

	envs := sink.guestEvents()
	if len(envs) != 1 {
		t.Fatalf("got %d guest events, want 1", len(envs))
	}
	if src := envs[0].Source; !src.Known || src.CID != 1 || src.VM != "alice-dev" || src.Labels["owner"] != "alice" {
		t.Errorf("Source = %+v, want the resolved alice-dev on CID 1", src)
	}
}

func TestNewFileSinkWritesJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "sauron.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink() error = %v", err)
	}
	other := newRecordingSink()
	multi := NewMultiSink(sink, other)

	env := &Envelope{
		ReceivedAt: time.Now().UTC(),
		Source:     Source{CID: 7, VM: "alice-dev", Known: true},
		Event:      &Event{Version: event.SchemaVersion, Sequence: 1, Type: event.TypeProcessExec},
	}
	if err := multi.Write(context.Background(), env); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := multi.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	var lines []map[string]any
	for scanner.Scan() {
		var line map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatalf("line %q is not JSON: %v", scanner.Text(), err)
		}
		lines = append(lines, line)
	}
	if len(lines) != 1 {
		t.Fatalf("file holds %d lines, want 1", len(lines))
	}
	if source, _ := lines[0]["source"].(map[string]any); source["vm"] != "alice-dev" {
		t.Errorf("line source = %v, want vm alice-dev", lines[0]["source"])
	}
	if len(other.envs) != 1 || !other.closed {
		t.Errorf("the second sink got %d envelopes (closed=%t), want 1 and closed", len(other.envs), other.closed)
	}
}
