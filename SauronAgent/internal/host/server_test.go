package host

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/protocol"
)

// testTimeout bounds every blocking operation in these tests, so that a
// regression shows up as a failure rather than as a hung test binary. Nothing
// here sleeps to synchronise: the tests wait on frames, on channels or on an
// injected clock.
const testTimeout = 5 * time.Second

// fakeSink records envelopes and can be made to reject chosen sequences, which
// is how the "never acknowledge what the outputs refused" rule is tested.
type fakeSink struct {
	mu      sync.Mutex
	envs    []*output.Envelope
	failSeq map[uint64]bool
	closes  int
	flushes int
}

func newFakeSink() *fakeSink {
	return &fakeSink{failSeq: make(map[uint64]bool)}
}

func (f *fakeSink) Write(_ context.Context, env *output.Envelope) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if env.Event != nil && !event.IsInternal(env.Event.Type) && f.failSeq[env.Event.Sequence] {
		return errors.New("fake sink: disk is on fire")
	}
	f.envs = append(f.envs, env)
	return nil
}

func (f *fakeSink) Flush(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	return nil
}

func (f *fakeSink) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

func (f *fakeSink) Name() string { return "fake" }

// fail makes the sink reject the write of one event sequence.
func (f *fakeSink) fail(seq uint64, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failSeq[seq] = on
}

// events returns the guest events written, in order, excluding the collector's
// own internal events.
func (f *fakeSink) events() []*output.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*output.Envelope
	for _, e := range f.envs {
		if e.Event != nil && !event.IsInternal(e.Event.Type) {
			out = append(out, e)
		}
	}
	return out
}

// internals returns the internal events written to the sink.
func (f *fakeSink) internals() []*output.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*output.Envelope
	for _, e := range f.envs {
		if e.Event != nil && event.IsInternal(e.Event.Type) {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeSink) closed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closes
}

// pipeListener hands net.Pipe connections to the accept loop, so a session runs
// against a real protocol.Conn without a socket.
type pipeListener struct {
	conns     chan net.Conn
	closeOnce sync.Once
	done      chan struct{}
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 16), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// harness runs a collector over net.Pipe with a controllable clock and a
// controllable peer identity, because net.Pipe carries no CID of its own.
type harness struct {
	t        *testing.T
	srv      *Server
	sink     *fakeSink
	lis      *pipeListener
	counters *metrics.Host
	internal chan *output.Envelope

	cancel   context.CancelFunc
	runErr   chan error
	stopOnce sync.Once

	mu    sync.Mutex
	cids  map[net.Conn]uint32
	clock time.Time
}

func newHarness(t *testing.T, tweak func(*config.Host)) *harness {
	t.Helper()
	return newHarnessWithOptions(t, tweak, nil)
}

// newHarnessWithOptions is newHarness with a hook to adjust the server Options,
// for the settings the configuration file cannot express, such as Resolve.
func newHarnessWithOptions(t *testing.T, tweak func(*config.Host), tweakOptions func(*Options)) *harness {
	t.Helper()

	cfg := config.DefaultHost()
	cfg.Host.Name = "hypervisor-test"
	// Listen is never used: the harness supplies its own listener. It still has
	// to be valid, because New validates the whole configuration.
	cfg.Listen = config.ListenSection{Kind: config.TransportTCP, TCPAddress: "127.0.0.1:0"}
	cfg.VMs = []config.VMMapping{{
		CID:            102,
		Name:           "transfer-vm-03",
		UUID:           "b1c4e0d2-55a7-42c9-8f31-9d0e4c6a7b18",
		Environment:    "production",
		SecurityDomain: "restricted",
		VLAN:           "310",
		Labels:         map[string]string{"owner": "data-team"},
		Expected:       true,
	}}
	cfg.Monitor.Enabled = false // exercised directly in monitor_test.go
	cfg.Limits.AckInterval = 1
	cfg.Limits.AckMaxDelay = config.Duration(time.Hour)
	cfg.Limits.HandshakeTimeout = config.Duration(testTimeout)
	cfg.Limits.IdleTimeout = config.Duration(testTimeout)
	if tweak != nil {
		tweak(&cfg)
	}

	h := &harness{
		t:        t,
		sink:     newFakeSink(),
		lis:      newPipeListener(),
		counters: &metrics.Host{},
		internal: make(chan *output.Envelope, 64),
		runErr:   make(chan error, 1),
		cids:     make(map[net.Conn]uint32),
	}

	opts := Options{
		Config:   cfg,
		Sink:     h.sink,
		Metrics:  h.counters,
		Logger:   logging.Discard(),
		Listener: h.lis,
		OnInternalEvent: func(env *output.Envelope) {
			select {
			case h.internal <- env:
			default:
			}
		},
	}
	if tweakOptions != nil {
		tweakOptions(&opts)
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.srv = srv
	srv.now = h.now
	srv.peerCID = h.peerCID

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.runErr <- srv.Run(ctx) }()
	t.Cleanup(h.stop)
	return h
}

// now is the collector's clock. It is the wall clock until a test pins it.
func (h *harness) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clock.IsZero() {
		return time.Now()
	}
	return h.clock
}

func (h *harness) setNow(t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clock = t
}

// peerCID stands in for transport.PeerCID: the harness registers the CID the
// hypervisor would have assigned to each connection it hands to the listener.
func (h *harness) peerCID(c net.Conn) (uint32, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cid, ok := h.cids[c]
	return cid, ok
}

// stop shuts the collector down and asserts that an orderly shutdown is not
// reported as a failure.
func (h *harness) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case err := <-h.runErr:
			if err != nil {
				h.t.Errorf("Run returned %v, want nil after an orderly shutdown", err)
			}
		case <-time.After(testTimeout):
			h.t.Fatal("Run did not return after the context was cancelled")
		}
	})
}

// dial opens a guest connection. vsock selects whether the peer has a
// hypervisor-assigned CID; false is the TCP development case, where it does not.
func (h *harness) dial(cid uint32, vsock bool) *guest {
	h.t.Helper()
	client, server := net.Pipe()
	if vsock {
		h.mu.Lock()
		h.cids[server] = cid
		h.mu.Unlock()
	}
	h.lis.conns <- server
	return newGuest(h.t, client)
}

// waitInternal waits for a host-generated internal event of the given type.
func (h *harness) waitInternal(typ string) *output.Envelope {
	h.t.Helper()
	deadline := time.After(testTimeout)
	for {
		select {
		case env := <-h.internal:
			if env.Event != nil && env.Event.Type == typ {
				return env
			}
		case <-deadline:
			h.t.Fatalf("no %s event was reported", typ)
			return nil
		}
	}
}

// guest is the agent side of a session under test.
//
// It reads continuously in the background. net.Pipe is unbuffered, so a guest
// that only read when it expected something would deadlock the collector's
// writer against its own -- and a real agent reads continuously too.
type guest struct {
	t      *testing.T
	conn   *protocol.Conn
	raw    net.Conn
	frames chan *protocol.Frame
	done   chan struct{}
	err    error
}

func newGuest(t *testing.T, c net.Conn) *guest {
	g := &guest{
		t:      t,
		conn:   protocol.NewConn(c, protocol.DefaultMaxPayloadSize),
		raw:    c,
		frames: make(chan *protocol.Frame, 64),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(g.done)
		for {
			f, err := g.conn.Receive(0)
			if err != nil {
				g.err = err
				return
			}
			// The payload aliases the decoder's buffer; copy before queueing.
			cp := &protocol.Frame{Header: f.Header, Payload: append([]byte(nil), f.Payload...)}
			g.frames <- cp
		}
	}()
	t.Cleanup(func() { _ = g.conn.Close() })
	return g
}

func (g *guest) send(t protocol.MessageType, seq uint64, v any) {
	g.t.Helper()
	if err := g.conn.Send(t, seq, v, testTimeout); err != nil {
		g.t.Fatalf("sending %s: %v", t, err)
	}
}

// next returns the next frame the collector sent.
func (g *guest) next() *protocol.Frame {
	g.t.Helper()
	// Frames already read win over a closed connection: the collector routinely
	// sends a fatal ERROR and closes immediately, and a plain select over both
	// would report the close half the time.
	select {
	case f := <-g.frames:
		return f
	default:
	}
	select {
	case f := <-g.frames:
		return f
	case <-g.done:
		g.t.Fatalf("connection closed while waiting for a frame: %v", g.err)
	case <-time.After(testTimeout):
		g.t.Fatal("timed out waiting for a frame")
	}
	return nil
}

func (g *guest) expect(want protocol.MessageType) *protocol.Frame {
	g.t.Helper()
	f := g.next()
	if f.Type != want {
		g.t.Fatalf("got %s, want %s", f.Type, want)
	}
	return f
}

// handshake performs HELLO/READY and returns the collector's answer.
func (g *guest) handshake(hello *protocol.Hello) protocol.Ready {
	g.t.Helper()
	if hello.ProtocolVersion == 0 {
		hello.ProtocolVersion = protocol.Version
	}
	g.send(protocol.MsgHello, 0, hello)
	f := g.expect(protocol.MsgReady)
	var ready protocol.Ready
	if err := protocol.DecodePayload(f, &ready); err != nil {
		g.t.Fatalf("decoding READY: %v", err)
	}
	return ready
}

// sendEvent sends one EVENT frame with the header and payload sequences agreeing.
func (g *guest) sendEvent(seq uint64, boot string) {
	g.t.Helper()
	g.send(protocol.MsgEvent, seq, &protocol.EventMessage{Event: testEvent(seq, boot)})
}

func (g *guest) expectAck() uint64 {
	g.t.Helper()
	f := g.expect(protocol.MsgAck)
	var ack protocol.Ack
	if err := protocol.DecodePayload(f, &ack); err != nil {
		g.t.Fatalf("decoding ACK: %v", err)
	}
	if f.Sequence != 0 {
		g.t.Errorf("ACK header sequence = %d, want 0: the sequence belongs in the payload", f.Sequence)
	}
	return ack.Sequence
}

func (g *guest) expectError() protocol.ErrorMessage {
	g.t.Helper()
	f := g.expect(protocol.MsgError)
	var em protocol.ErrorMessage
	if err := protocol.DecodePayload(f, &em); err != nil {
		g.t.Fatalf("decoding ERROR: %v", err)
	}
	return em
}

// ping exchanges a heartbeat. It doubles as a barrier: the collector reads one
// frame at a time, so a PONG proves every earlier frame has been processed.
func (g *guest) ping() protocol.Pong {
	g.t.Helper()
	g.send(protocol.MsgPing, 0, &protocol.Ping{UptimeSeconds: 42, AuditEnabled: true})
	f := g.expect(protocol.MsgPong)
	var pong protocol.Pong
	if err := protocol.DecodePayload(f, &pong); err != nil {
		g.t.Fatalf("decoding PONG: %v", err)
	}
	return pong
}

// wantClosed asserts that the collector closed the connection.
func (g *guest) wantClosed() {
	g.t.Helper()
	select {
	case <-g.done:
	case <-time.After(testTimeout):
		g.t.Fatal("the collector did not close the connection")
	}
}

func (g *guest) close() { _ = g.conn.Close() }

// testEvent builds a normalized event the way the agent would.
func testEvent(seq uint64, boot string) *event.Event {
	return &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    seq,
		Timestamp:   time.Date(2026, 9, 18, 17, 25, 45, 312000000, time.UTC),
		Type:        event.TypeProcessExec,
		Severity:    event.SeverityNotice,
		AuditID:     "1789752345.312:8421",
		BootID:      boot,
		PID:         event.Int(4821),
		UID:         event.Int(0),
		Executable:  "/usr/bin/cat",
		Command:     "cat /etc/shadow",
		RecordTypes: []string{"SYSCALL", "EXECVE"},
	}
}

func TestNewRejectsMissingSink(t *testing.T) {
	cfg := config.DefaultHost()
	cfg.Listen = config.ListenSection{Kind: config.TransportTCP, TCPAddress: "127.0.0.1:0"}
	if _, err := New(Options{Config: cfg, Listener: newPipeListener()}); err == nil {
		t.Fatal("New accepted a collector with no sink; it would acknowledge and discard every event")
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	cfg := config.DefaultHost()
	cfg.VMs = []config.VMMapping{{CID: 7, Name: "a"}, {CID: 7, Name: "b"}}
	_, err := New(Options{Config: cfg, Sink: newFakeSink(), Listener: newPipeListener()})
	if err == nil {
		t.Fatal("New accepted two VMs sharing one CID")
	}
}

func TestCloseWithoutRunReleasesResources(t *testing.T) {
	sink := newFakeSink()
	lis := newPipeListener()
	cfg := config.DefaultHost()
	cfg.Listen = config.ListenSection{Kind: config.TransportTCP, TCPAddress: "127.0.0.1:0"}
	srv, err := New(Options{Config: cfg, Sink: sink, Listener: lis, Logger: logging.Discard()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := sink.closed(); got != 1 {
		t.Fatalf("sink closed %d times, want exactly 1", got)
	}
	if _, err := lis.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener still accepting after Close: %v", err)
	}
}

func TestRunDrainsSessionsAndClosesSink(t *testing.T) {
	h := newHarness(t, nil)
	g := h.dial(102, true)
	g.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})
	g.sendEvent(1, "boot-a")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}

	h.stop()

	// The collector announces the planned stop rather than dropping the
	// connection, so the guest can tell maintenance from a crash.
	g.wantClosed()
	sawShutdown := false
	for drained := false; !drained; {
		select {
		case f := <-g.frames:
			if f.Type == protocol.MsgShutdown {
				sawShutdown = true
			}
		default:
			drained = true
		}
	}
	if !sawShutdown {
		t.Error("no SHUTDOWN was sent to the guest on an orderly collector stop")
	}
	if got := h.sink.closed(); got != 1 {
		t.Fatalf("sink closed %d times, want exactly 1 and only after the sessions drained", got)
	}
}

func TestMaxConnectionsRejectsAndReports(t *testing.T) {
	h := newHarness(t, func(c *config.Host) {
		c.Limits.MaxConnections = 1
		c.Limits.MaxConnectionsPerCID = 4
	})

	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	second := h.dial(102, true)
	em := second.expectError()
	if em.Code != protocol.ErrCodeOverloaded || !em.Fatal {
		t.Fatalf("ERROR = %+v, want a fatal %s", em, protocol.ErrCodeOverloaded)
	}
	if !strings.Contains(em.Message, reasonMaxConns) {
		t.Errorf("ERROR message %q does not name the limit that was hit", em.Message)
	}
	second.wantClosed()

	env := h.waitInternal(typeConnectionRejected)
	if got := env.Event.Fields["reason"]; got != reasonMaxConns {
		t.Errorf("rejection reason = %v, want %q", got, reasonMaxConns)
	}
	if got := h.counters.ConnectionsRejected.Load(); got != 1 {
		t.Errorf("ConnectionsRejected = %d, want 1", got)
	}
	if got := h.counters.ConnectionsAccepted.Load(); got != 1 {
		t.Errorf("ConnectionsAccepted = %d, want 1", got)
	}
}

func TestMaxConnectionsPerCIDRejects(t *testing.T) {
	h := newHarness(t, func(c *config.Host) {
		c.Limits.MaxConnections = 16
		c.Limits.MaxConnectionsPerCID = 1
	})

	first := h.dial(102, true)
	first.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-a"})

	second := h.dial(102, true)
	em := second.expectError()
	if !strings.Contains(em.Message, reasonMaxConnsCID) {
		t.Fatalf("ERROR message %q does not name the per-CID limit", em.Message)
	}
	second.wantClosed()

	// A different VM is unaffected: the limit is per CID so that one guest
	// cannot lock the others out by reconnecting in a loop.
	other := h.dial(103, true)
	ready := other.handshake(&protocol.Hello{AgentVersion: "test", BootID: "boot-c"})
	if ready.ProtocolVersion != protocol.Version {
		t.Fatalf("READY = %+v", ready)
	}
}

func TestUnmappedCIDRefusedWhenNotAllowed(t *testing.T) {
	h := newHarness(t, func(c *config.Host) { c.Limits.AllowUnknownCIDs = false })

	g := h.dial(999, true)
	em := g.expectError()
	if em.Code != protocol.ErrCodeUnauthorized || !em.Fatal {
		t.Fatalf("ERROR = %+v, want a fatal %s", em, protocol.ErrCodeUnauthorized)
	}
	g.wantClosed()

	env := h.waitInternal(typeConnectionRejected)
	if got := env.Event.Fields["reason"]; got != reasonUnauthorized {
		t.Errorf("rejection reason = %v, want %q", got, reasonUnauthorized)
	}
	if got := env.Event.Fields["cid"]; got != uint32(999) {
		t.Errorf("rejection cid = %v, want 999", got)
	}
	if got := h.counters.ConnectionsRejected.Load(); got != 1 {
		t.Errorf("ConnectionsRejected = %d, want 1", got)
	}
	if len(h.sink.events()) != 0 {
		t.Errorf("a refused guest still produced events: %d", len(h.sink.events()))
	}
}

func TestUnidentifiedPeerIsNotGivenACID(t *testing.T) {
	h := newHarness(t, func(c *config.Host) { c.Limits.AllowUnknownCIDs = true })

	// vsock=false: the TCP development case, where the hypervisor vouches for
	// nothing.
	g := h.dial(0, false)
	g.handshake(&protocol.Hello{AgentVersion: "test", Hostname: "claims-to-be-web01", BootID: "boot-x"})
	g.sendEvent(1, "boot-x")
	if ack := g.expectAck(); ack != 1 {
		t.Fatalf("ACK = %d, want 1", ack)
	}

	envs := h.sink.events()
	if len(envs) != 1 {
		t.Fatalf("got %d events, want 1", len(envs))
	}
	src := envs[0].Source
	if src.Known {
		t.Error("a peer with no hypervisor-backed identity was recorded as known")
	}
	if src.CID != cidUnidentified {
		t.Errorf("Source.CID = %d, want the synthetic %d; 0 is a real CID and must not be implied",
			src.CID, cidUnidentified)
	}
	if !strings.HasPrefix(src.VM, "unidentified-peer-") {
		t.Errorf("Source.VM = %q, want a clearly synthetic name", src.VM)
	}
	if src.Reported == nil || src.Reported.Hostname != "claims-to-be-web01" {
		t.Errorf("the guest's claim was not recorded under Reported: %+v", src.Reported)
	}
}
