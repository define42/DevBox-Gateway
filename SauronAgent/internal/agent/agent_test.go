package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/audit"
	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/protocol"
	"github.com/define42/SauronAgent/internal/transport"
)

// The tests drive a real agent against an in-process collector over the TCP
// transport: no netlink socket, no VSOCK, no kernel. Audit records are injected
// through Options.Source, which is the same channel the netlink listener writes
// to, so everything from correlation onwards is the production code path.
//
// Nothing here sleeps to synchronise. Where a test has to wait for the
// pipeline to reach a state it polls for that state with a deadline; where it
// has to wait for a timeout to fire (the acknowledgement timeout, the
// heartbeat) the timeout itself is configured down to milliseconds.

const (
	// waitTimeout is generous: it only bounds a test that is already failing.
	waitTimeout  = 20 * time.Second
	pollInterval = 2 * time.Millisecond
)

func TestMain(m *testing.M) {
	// The loss poller drives every internal loss event. Shortening it once,
	// before any agent exists, keeps the tests fast without making the
	// production default a test-shaped number.
	lossPollInterval = 20 * time.Millisecond
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// fake host collector
// ---------------------------------------------------------------------------

// recvEvent is one EVENT frame as the collector saw it.
type recvEvent struct {
	ev        *event.Event
	headerSeq uint64
	conn      int
	// acksBefore is how many ACKs the collector had sent when this event
	// arrived. It is what makes "the agent waited for an acknowledgement"
	// checkable without timing.
	acksBefore int
}

// collectorOptions configures the fake collector's behaviour.
type collectorOptions struct {
	// autoAck acknowledges every event as it arrives.
	autoAck bool
	// dropAfter closes the connection once this many events have arrived on
	// it, without acknowledging them. It fires once.
	dropAfter int
	// resumeFromHighest answers READY with the highest sequence received so
	// far, which is how a host tells the agent not to replay.
	resumeFromHighest bool
	// resumeFrom answers READY with this position whatever the collector has
	// actually received. It is how a host that kept its deduplication
	// watermark for a boot id looks to an agent whose own record of that boot
	// -- its spool -- was reset, rotated away or never enabled.
	resumeFrom uint64
	// ackAhead acknowledges this sequence once, when the first event of a
	// session arrives, whatever the agent has actually sent.
	ackAhead uint64
	// badHandshake answers the first HELLO with something that is not READY.
	badHandshake bool
	// maxPayload is announced in READY when non-zero.
	maxPayload uint32
}

// collector is an in-process SauronHost: it speaks the protocol, records what
// arrives and misbehaves on demand.
type collector struct {
	t    *testing.T
	opts collectorOptions
	addr string

	mu        sync.Mutex
	ln        transport.Listener
	live      []net.Conn
	cur       *protocol.Conn
	conns     int
	received  []recvEvent
	hellos    []protocol.Hello
	pings     []protocol.Ping
	pingAt    []time.Time
	shutdowns []protocol.Shutdown
	acksSent  int
	autoAck   bool
	dropAfter int
	ackAhead  uint64
	// holds is the cumulative position the collector claims, from resumeFrom
	// or from ackAhead. A real host does not acknowledge an event at or below
	// its position again: it suppresses the event as a duplicate and its
	// acknowledgement point does not move, so no new ACK goes out. The fake
	// does the same, because an agent that only stops re-sending once the host
	// acknowledges it again would look correct here and spin against the real
	// collector.
	holds    uint64
	stopped  bool
	failures []string
	// frames counts every frame of every type the collector has read. An
	// agent that re-sends in a loop shows up here before it shows up anywhere
	// else, which is what makes "the sender is not spinning" an assertion
	// rather than an observation about CPU time.
	frames int
}

func newCollector(t *testing.T, opts collectorOptions) *collector {
	t.Helper()
	c := &collector{t: t, opts: opts, autoAck: opts.autoAck, dropAfter: opts.dropAfter, ackAhead: opts.ackAhead}
	ln, err := transport.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	c.ln = ln
	c.addr = ln.Addr().String()
	go c.serve(ln)
	t.Cleanup(c.kill)
	return c
}

// serve accepts connections until the listener is closed.
func (c *collector) serve(ln transport.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.conns++
		id := c.conns
		c.live = append(c.live, nc)
		c.mu.Unlock()
		go c.handle(id, nc)
	}
}

// handle speaks the protocol on one connection.
func (c *collector) handle(id int, nc net.Conn) {
	maxPayload := c.opts.maxPayload
	if maxPayload == 0 {
		maxPayload = protocol.DefaultMaxPayloadSize
	}
	conn := protocol.NewConn(nc, maxPayload)
	defer conn.Close()

	f, err := conn.Receive(waitTimeout)
	if err != nil {
		return
	}
	if f.Type != protocol.MsgHello {
		c.fail(fmt.Sprintf("first frame was %s, want HELLO", f.Type))
		return
	}
	var hello protocol.Hello
	if err := protocol.DecodePayload(f, &hello); err != nil {
		c.fail(fmt.Sprintf("decoding HELLO: %v", err))
		return
	}
	c.mu.Lock()
	c.frames++
	c.hellos = append(c.hellos, hello)
	bad := c.opts.badHandshake && id == 1
	resume := c.opts.resumeFrom
	if c.opts.resumeFromHighest {
		resume = c.highestLocked()
	}
	if resume > c.holds {
		c.holds = resume
	}
	c.cur = conn
	c.mu.Unlock()

	if bad {
		// A PONG in place of READY: a legal frame in an illegal place, which
		// is what a malformed peer looks like from the agent's side.
		_ = conn.Send(protocol.MsgPong, 0, protocol.Pong{UnixNano: time.Now().UnixNano()}, time.Second)
		return
	}
	ready := protocol.Ready{
		ProtocolVersion: protocol.Version,
		HostVersion:     "fake",
		SessionID:       fmt.Sprintf("session-%d", id),
		ResumeFrom:      resume,
		MaxPayloadSize:  c.opts.maxPayload,
	}
	if err := conn.Send(protocol.MsgReady, 0, ready, time.Second); err != nil {
		return
	}

	onThisConn := 0
	for {
		f, err := conn.Receive(0)
		if err != nil {
			return
		}
		c.mu.Lock()
		c.frames++
		c.mu.Unlock()
		switch f.Type {
		case protocol.MsgEvent:
			var em protocol.EventMessage
			if err := protocol.DecodePayload(f, &em); err != nil {
				c.fail(fmt.Sprintf("decoding EVENT: %v", err))
				return
			}
			if em.Event == nil {
				c.fail("EVENT frame carried no event")
				return
			}
			if f.Sequence != em.Event.Sequence {
				c.fail(fmt.Sprintf("frame sequence %d does not match event sequence %d",
					f.Sequence, em.Event.Sequence))
			}
			onThisConn++

			c.mu.Lock()
			c.received = append(c.received, recvEvent{
				ev:         em.Event,
				headerSeq:  f.Sequence,
				conn:       id,
				acksBefore: c.acksSent,
			})
			// An event at or below the position the collector already claims
			// is a duplicate: it is suppressed and the acknowledgement point
			// stays where it was, so nothing is sent back for it.
			auto := c.autoAck && f.Sequence > c.holds
			drop := c.dropAfter > 0 && onThisConn >= c.dropAfter
			if drop {
				c.dropAfter = 0
			}
			ahead := c.ackAhead
			if ahead > 0 {
				c.ackAhead = 0
			}
			c.mu.Unlock()

			if drop {
				// Killed after the event was sent and before it was
				// acknowledged: the agent must send it again.
				nc.Close()
				return
			}
			switch {
			case ahead > 0:
				// A cumulative acknowledgement for a sequence the agent has
				// not reached. A real host does this when it still holds a
				// watermark for this boot id that the agent's own numbering
				// has fallen behind.
				c.sendAck(conn, ahead)
			case auto:
				c.sendAck(conn, f.Sequence)
			}

		case protocol.MsgPing:
			var p protocol.Ping
			if err := protocol.DecodePayload(f, &p); err != nil {
				c.fail(fmt.Sprintf("decoding PING: %v", err))
				return
			}
			c.mu.Lock()
			c.pings = append(c.pings, p)
			c.pingAt = append(c.pingAt, time.Now())
			c.mu.Unlock()
			_ = conn.Send(protocol.MsgPong, 0, protocol.Pong{
				EchoUptime: p.UptimeSeconds,
				UnixNano:   time.Now().UnixNano(),
			}, time.Second)

		case protocol.MsgShutdown:
			var sd protocol.Shutdown
			if err := protocol.DecodePayload(f, &sd); err != nil {
				c.fail(fmt.Sprintf("decoding SHUTDOWN: %v", err))
				return
			}
			c.mu.Lock()
			c.shutdowns = append(c.shutdowns, sd)
			c.mu.Unlock()

		case protocol.MsgError:
			var em protocol.ErrorMessage
			_ = protocol.DecodePayload(f, &em)
			c.fail(fmt.Sprintf("agent reported an error: %s: %s", em.Code, em.Message))

		default:
			c.fail(fmt.Sprintf("agent sent %s, which it may not", f.Type))
			return
		}
	}
}

// sendAck acknowledges cumulatively through seq. The collector's position
// moves with it: that position is what it deduplicates against and what it
// offers as resume_from, exactly as the real collector's watermark does.
func (c *collector) sendAck(conn *protocol.Conn, seq uint64) {
	c.mu.Lock()
	c.acksSent++
	if seq > c.holds {
		c.holds = seq
	}
	c.mu.Unlock()
	_ = conn.Send(protocol.MsgAck, 0, protocol.Ack{Sequence: seq}, time.Second)
}

// ack acknowledges through seq on the current connection, for tests that hold
// acknowledgement back on purpose.
func (c *collector) ack(seq uint64) {
	c.mu.Lock()
	conn := c.cur
	c.mu.Unlock()
	if conn == nil {
		c.t.Fatalf("ack(%d): no live connection", seq)
	}
	c.sendAck(conn, seq)
}

func (c *collector) setAutoAck(v bool) {
	c.mu.Lock()
	c.autoAck = v
	c.mu.Unlock()
}

// fail records a protocol violation by the agent. It does not call t.Errorf
// directly because the collector outlives some of the tests' assertions; the
// failures are reported from the test goroutine by checkClean.
func (c *collector) fail(msg string) {
	c.mu.Lock()
	c.failures = append(c.failures, msg)
	c.mu.Unlock()
}

// checkClean fails the test if the agent ever broke the protocol.
func (c *collector) checkClean(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.failures {
		t.Errorf("collector: %s", f)
	}
}

// kill closes the listener and every live connection, as an abruptly stopped
// collector would.
func (c *collector) kill() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	ln := c.ln
	live := c.live
	c.live = nil
	c.cur = nil
	c.mu.Unlock()

	if ln != nil {
		ln.Close()
	}
	for _, nc := range live {
		nc.Close()
	}
}

// restart listens again on the same address, as a collector that was
// restarted would.
func (c *collector) restart() {
	c.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		ln, err := transport.ListenTCP(c.addr)
		if err == nil {
			c.mu.Lock()
			c.ln = ln
			c.stopped = false
			c.mu.Unlock()
			go c.serve(ln)
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("restarting the collector on %s: %v", c.addr, err)
		}
		time.Sleep(pollInterval)
	}
}

// ---- collector accessors, all safe to call from the test goroutine ----

func (c *collector) connCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conns
}

func (c *collector) events() []recvEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]recvEvent(nil), c.received...)
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.received)
}

// framesSeen is every frame the agent has sent, of every type.
func (c *collector) framesSeen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frames
}

func (c *collector) highestLocked() uint64 {
	var high uint64
	for _, r := range c.received {
		if r.headerSeq > high {
			high = r.headerSeq
		}
	}
	return high
}

// delivered returns the set of sequence numbers the collector has seen.
func (c *collector) delivered() map[uint64]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[uint64]int, len(c.received))
	for _, r := range c.received {
		out[r.headerSeq]++
	}
	return out
}

// eventsOfType returns every delivered event of the given normalized type.
func (c *collector) eventsOfType(typ string) []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*event.Event
	for _, r := range c.received {
		if r.ev.Type == typ {
			out = append(out, r.ev)
		}
	}
	return out
}

func (c *collector) pingsSeen() ([]protocol.Ping, []time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]protocol.Ping(nil), c.pings...), append([]time.Time(nil), c.pingAt...)
}

func (c *collector) shutdownsSeen() []protocol.Shutdown {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]protocol.Shutdown(nil), c.shutdowns...)
}

func (c *collector) hellosSeen() []protocol.Hello {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]protocol.Hello(nil), c.hellos...)
}

// ---------------------------------------------------------------------------
// record injection
// ---------------------------------------------------------------------------

// recordSource is the injected replacement for the netlink listener. It stays
// alive until the agent's context ends, so a test can feed records at any
// point in the run.
type recordSource struct {
	ch chan *audit.Record
}

func newRecordSource() *recordSource {
	return &recordSource{ch: make(chan *audit.Record, 4096)}
}

func (s *recordSource) run(ctx context.Context, out chan<- *audit.Record) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-s.ch:
			select {
			case out <- r:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// exec feeds the records the kernel emits for one execve, closed by an EOE
// marker so that correlation completes without waiting for its timeout.
func (s *recordSource) exec(t *testing.T, serial uint64, exe, arg string) {
	t.Helper()
	stamp := fmt.Sprintf("1700000%03d.123:%d", serial, serial)
	lines := []string{
		fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=59 success=yes exit=0 `+
			`a0=7ffd0 a1=7ffd1 a2=7ffd2 a3=8 items=1 ppid=1 pid=%d auid=1000 uid=0 gid=0 `+
			`euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="%s" exe="%s" key="exec"`,
			stamp, 4000+serial, "prog", exe),
		fmt.Sprintf(`type=EXECVE msg=audit(%s): argc=2 a0="%s" a1="%s"`, stamp, exe, arg),
		fmt.Sprintf(`type=CWD msg=audit(%s): cwd="/home/analyst"`, stamp),
		fmt.Sprintf(`type=PATH msg=audit(%s): item=0 name="%s" inode=1 dev=fd:00 mode=0100755 `+
			`ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`, stamp, exe),
		fmt.Sprintf(`type=PROCTITLE msg=audit(%s): proctitle="%s"`, stamp, exe),
		fmt.Sprintf(`type=EOE msg=audit(%s):`, stamp),
	}
	for _, line := range lines {
		r, err := audit.ParseLine(line)
		if err != nil {
			t.Fatalf("ParseLine(%q): %v", line, err)
		}
		s.ch <- r
	}
}

// ---------------------------------------------------------------------------
// agent harness
// ---------------------------------------------------------------------------

func testIdentity() identity.Identity {
	return identity.Identity{
		Hostname:  "transfer-vm-03",
		MachineID: "9d1f0a6c4f2b41d8a0b7c3e5d6f78901",
		BootID:    "5f1c7d2a-1f7e-4f41-9c33-2a5bd2c0b0e7",
		Kernel:    "6.8.0-45-generic",
		Version:   "test",
	}
}

// testConfig is a stock agent pointed at addr, with every timer short enough
// that a test does not wait on production defaults.
func testConfig(addr string) config.Agent {
	cfg := config.DefaultAgent()
	cfg.Transport.Kind = config.TransportTCP
	cfg.Transport.TCPAddress = addr
	cfg.Transport.MaxUnacked = 64
	cfg.Transport.WriteTimeout = config.Duration(5 * time.Second)
	cfg.Transport.AckTimeout = config.Duration(10 * time.Second)
	cfg.Audit.Enabled = true
	cfg.Audit.CorrelationTimeout = config.Duration(50 * time.Millisecond)
	cfg.Queue.Capacity = 512
	cfg.Spool.Enabled = false
	// One hour: the tests that exercise heartbeats set their own interval, and
	// the rest must not have PING frames arriving in the middle of them.
	cfg.Heartbeat.Interval = config.Duration(time.Hour)
	cfg.Heartbeat.Timeout = 0
	cfg.Reconnect.InitialDelay = config.Duration(5 * time.Millisecond)
	cfg.Reconnect.MaxDelay = config.Duration(50 * time.Millisecond)
	cfg.Reconnect.Jitter = 0
	return cfg
}

// withSpool enables the disk spool in a temporary directory.
func withSpool(t *testing.T, cfg config.Agent, dir string) config.Agent {
	t.Helper()
	cfg.Spool.Enabled = true
	cfg.Spool.Path = dir
	cfg.Spool.MaxSize = config.Size(8 << 20)
	cfg.Spool.SegmentSize = config.Size(256 << 10)
	cfg.Spool.SyncOnWrite = false
	cfg.Spool.SyncInterval = config.Duration(10 * time.Millisecond)
	return cfg
}

// harness is a running agent plus the handles a test needs to drive it.
type harness struct {
	t       *testing.T
	agent   *Agent
	src     *recordSource
	metrics *metrics.Agent
	cancel  context.CancelFunc
	done    chan error

	stopOnce sync.Once
	runErr   error
}

func startAgent(t *testing.T, cfg config.Agent) *harness {
	t.Helper()
	src := newRecordSource()
	m := &metrics.Agent{}
	a, err := New(Options{
		Config:   cfg,
		Identity: testIdentity(),
		Metrics:  m,
		Logger:   logging.Discard(),
		Source:   src.run,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, agent: a, src: src, metrics: m, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- a.Run(ctx) }()
	t.Cleanup(func() { h.stop() })
	return h
}

// stop cancels the run, waits for it and closes the agent. It is idempotent,
// so an explicit stop in a test and the cleanup do not collide.
func (h *harness) stop() error {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case err := <-h.done:
			h.runErr = err
		case <-time.After(waitTimeout):
			h.t.Error("Run did not return after the context was cancelled")
		}
		if err := h.agent.Close(); err != nil {
			h.t.Errorf("Close: %v", err)
		}
		// Close is documented as idempotent, and a test that never noticed
		// would be a test that is not checking it.
		if err := h.agent.Close(); err != nil {
			h.t.Errorf("second Close: %v", err)
		}
	})
	return h.runErr
}

// ---------------------------------------------------------------------------
// assertions and waiting
// ---------------------------------------------------------------------------

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(pollInterval)
	}
}

// waitEvents waits until at least n events have been delivered.
func waitEvents(t *testing.T, c *collector, n int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d events at the collector (have %d)", n, c.count()), func() bool {
		return c.count() >= n
	})
}

// waitType waits for an event of the given type and returns the first one.
func waitType(t *testing.T, c *collector, typ string) *event.Event {
	t.Helper()
	var found *event.Event
	waitFor(t, "an event of type "+typ, func() bool {
		evs := c.eventsOfType(typ)
		if len(evs) == 0 {
			return false
		}
		found = evs[0]
		return true
	})
	return found
}

// assertNoGaps checks that the delivered sequences are exactly 1..max with
// nothing missing. A gap that no loss event explains is the one outcome the
// whole design exists to prevent.
func assertNoGaps(t *testing.T, c *collector) uint64 {
	t.Helper()
	got := c.delivered()
	if len(got) == 0 {
		t.Fatal("no events were delivered")
	}
	var max uint64
	for seq := range got {
		if seq > max {
			max = seq
		}
	}
	var missing []uint64
	for seq := uint64(1); seq <= max; seq++ {
		if got[seq] == 0 {
			missing = append(missing, seq)
		}
	}
	if len(missing) > 0 {
		t.Errorf("sequences missing from the delivered stream: %v (highest delivered %d)", missing, max)
	}
	return max
}

// numberField reads a numeric field off a decoded event. Payload numbers
// arrive as json.Number because the decoder uses UseNumber, so a float
// assertion would be a bug waiting for a value above 2^53.
func numberField(t *testing.T, e *event.Event, key string) uint64 {
	t.Helper()
	v, ok := e.Fields[key]
	if !ok {
		t.Fatalf("event %s has no field %q (fields: %v)", e.Type, key, e.Fields)
	}
	n, ok := v.(json.Number)
	if !ok {
		t.Fatalf("event %s field %q is %T, want json.Number", e.Type, key, v)
	}
	u, err := n.Int64()
	if err != nil {
		t.Fatalf("event %s field %q = %q: %v", e.Type, key, n.String(), err)
	}
	if u < 0 {
		t.Fatalf("event %s field %q = %d, want a count", e.Type, key, u)
	}
	return uint64(u)
}

func stringField(t *testing.T, e *event.Event, key string) string {
	t.Helper()
	v, ok := e.Fields[key]
	if !ok {
		t.Fatalf("event %s has no field %q (fields: %v)", e.Type, key, e.Fields)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("event %s field %q is %T, want string", e.Type, key, v)
	}
	return s
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestAgentEndToEnd drives records through every stage and checks what comes
// out of the far end: correlated, normalized, numbered and in order.
func TestAgentEndToEnd(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	h := startAgent(t, testConfig(c.addr))

	for i := uint64(1); i <= 3; i++ {
		h.src.exec(t, i, fmt.Sprintf("/usr/bin/prog%d", i), "-x")
	}

	waitFor(t, "three process.exec events", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 3
	})

	execs := c.eventsOfType(event.TypeProcessExec)
	for i, e := range execs[:3] {
		want := fmt.Sprintf("/usr/bin/prog%d", i+1)
		if e.Executable != want {
			t.Errorf("event %d: exe = %q, want %q", i, e.Executable, want)
		}
		if e.Command != want+" -x" {
			t.Errorf("event %d: command = %q, want %q", i, e.Command, want+" -x")
		}
		if e.CWD != "/home/analyst" {
			t.Errorf("event %d: cwd = %q, want /home/analyst", i, e.CWD)
		}
		if e.BootID != testIdentity().BootID {
			t.Errorf("event %d: boot_id = %q, want %q", i, e.BootID, testIdentity().BootID)
		}
		if e.Sequence == 0 {
			t.Errorf("event %d was delivered without a sequence number", i)
		}
		if e.UID == nil || *e.UID != 0 {
			t.Errorf("event %d: uid = %v, want 0", i, e.UID)
		}
		if len(e.Raw) == 0 {
			t.Errorf("event %d: raw records were not preserved", i)
		}
	}

	// The stream is delivered in sequence order within a session, and the
	// agent announces itself before anything it collects.
	var last uint64
	for _, r := range c.events() {
		if r.headerSeq <= last {
			t.Fatalf("events arrived out of order: %d after %d", r.headerSeq, last)
		}
		last = r.headerSeq
	}
	if started := c.eventsOfType(event.TypeAgentStarted); len(started) != 1 {
		t.Errorf("got %d sauron.agent.started events, want 1", len(started))
	} else if started[0].Sequence != 1 {
		t.Errorf("sauron.agent.started has sequence %d, want 1", started[0].Sequence)
	}
	// The connected event is produced when the handshake completes, which can
	// be after the first records were normalized, so its sequence is not
	// fixed; what matters is that it arrives.
	waitType(t, c, event.TypeTransportConnected)

	hellos := c.hellosSeen()
	if len(hellos) != 1 {
		t.Fatalf("got %d HELLO frames, want 1", len(hellos))
	}
	if hellos[0].BootID != testIdentity().BootID || hellos[0].Hostname != testIdentity().Hostname {
		t.Errorf("HELLO = %+v, want the guest's identity", hellos[0])
	}
	if hellos[0].ProtocolVersion != protocol.Version {
		t.Errorf("HELLO protocol_version = %d, want %d", hellos[0].ProtocolVersion, protocol.Version)
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	assertNoGaps(t, c)
	c.checkClean(t)
}

// TestTransportOnlyWithoutAudit checks that the delivery path runs with audit
// collection switched off, which is what audit.enabled: false is for.
func TestTransportOnlyWithoutAudit(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	cfg := testConfig(c.addr)
	cfg.Audit.Enabled = false
	h := startAgent(t, cfg)

	// The agent still reports on itself, and that is the only traffic there
	// should be.
	waitType(t, c, event.TypeAgentStarted)
	waitType(t, c, event.TypeTransportConnected)
	for _, r := range c.events() {
		if !event.IsInternal(r.ev.Type) {
			t.Errorf("audit event %q was delivered although collection is disabled", r.ev.Type)
		}
	}
	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestHostOutage kills the collector mid-stream. Collection must continue, the
// events must be spooled, and everything must arrive once the host is back --
// with no gap in the sequence numbers.
func TestHostOutage(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	for i := uint64(1); i <= 3; i++ {
		h.src.exec(t, i, "/usr/bin/before", "-a")
	}
	waitFor(t, "the first events to be delivered", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 3
	})

	c.kill()

	// Collection carries on through the outage: these events have nowhere to
	// go but the spool.
	for i := uint64(10); i <= 15; i++ {
		h.src.exec(t, i, "/usr/bin/during", "-b")
	}
	waitFor(t, "the events collected during the outage to reach the spool", func() bool {
		return h.agent.spool.PendingCount() >= 6
	})
	// They are held, not delivered: nothing collected during the outage can
	// have reached a collector that was not running.
	for _, r := range c.events() {
		if r.ev.Executable == "/usr/bin/during" {
			t.Fatalf("sequence %d was delivered while the host was down", r.headerSeq)
		}
	}

	c.restart()

	waitFor(t, "every event to be delivered after the reconnect", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 9
	})
	waitFor(t, "a second connection", func() bool { return c.connCount() >= 2 })

	// The outage itself is reported into the stream: the event is produced
	// while the host is unreachable, spooled with everything else, and
	// delivered after the reconnect.
	dis := waitType(t, c, event.TypeTransportDisconnect)
	if got := stringField(t, dis, "reason"); got == "" {
		t.Error("sauron.transport.disconnected carries no reason")
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	assertNoGaps(t, c)
	c.checkClean(t)
}

// TestAtLeastOnceResend drops a connection after events were sent and before
// they were acknowledged. Every one of them must be sent again.
func TestAtLeastOnceResend(t *testing.T) {
	c := newCollector(t, collectorOptions{dropAfter: 3})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	for i := uint64(1); i <= 3; i++ {
		h.src.exec(t, i, "/usr/bin/resend", "-r")
	}

	waitFor(t, "the connection to be dropped and remade", func() bool { return c.connCount() >= 2 })
	c.setAutoAck(true)
	// Nudge the sender: the events it had in flight are re-sent on the new
	// connection without any prompting, but the collector only acknowledges
	// from now on.
	waitFor(t, "every event to be delivered after the reconnect", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 3
	})

	delivered := c.delivered()
	resent := 0
	for _, n := range delivered {
		if n > 1 {
			resent++
		}
	}
	if resent == 0 {
		t.Error("nothing was re-sent after the connection was dropped before the ACK")
	}
	if h.metrics.EventsResent.Load() == 0 {
		t.Error("events_resent_total was not incremented by the replay")
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	assertNoGaps(t, c)
	c.checkClean(t)
}

// TestAckTruncatesSpool checks the acknowledgement contract: after ACK N the
// spool holds nothing at or below N.
func TestAckTruncatesSpool(t *testing.T) {
	c := newCollector(t, collectorOptions{})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	for i := uint64(1); i <= 3; i++ {
		h.src.exec(t, i, "/usr/bin/ack", "-k")
	}
	waitEvents(t, c, 5)

	evs := c.events()
	ackTo := evs[2].headerSeq
	if got := h.agent.spool.FirstUnacked(); got != 1 {
		t.Errorf("FirstUnacked before any ACK = %d, want 1", got)
	}
	c.ack(ackTo)

	waitFor(t, fmt.Sprintf("the spool to release everything through %d", ackTo), func() bool {
		return h.agent.spool.FirstUnacked() == ackTo+1
	})
	if got := h.agent.spool.FirstUnacked(); got != ackTo+1 {
		t.Errorf("FirstUnacked after ACK %d = %d, want %d", ackTo, got, ackTo+1)
	}

	c.setAutoAck(true)
	c.ack(assertHighest(t, c))
	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// assertHighest returns the highest sequence the collector has seen.
func assertHighest(t *testing.T, c *collector) uint64 {
	t.Helper()
	var high uint64
	for seq := range c.delivered() {
		if seq > high {
			high = seq
		}
	}
	return high
}

// TestQueueOverflowIsReported fills the bounded queue with the transport
// stalled, then lets it drain. The loss must arrive at the collector as a
// sauron.queue.overflow naming the exact range that went missing.
func TestQueueOverflowIsReported(t *testing.T) {
	c := newCollector(t, collectorOptions{})
	cfg := testConfig(c.addr)
	cfg.Queue.Capacity = 8
	// One event in flight at a time and no acknowledgements: with no spool the
	// queue is the only buffer, so it fills and starts dropping.
	cfg.Transport.MaxUnacked = 1
	cfg.Transport.AckTimeout = config.Duration(time.Minute)
	h := startAgent(t, cfg)

	const produced = 60
	for i := uint64(1); i <= produced; i++ {
		h.src.exec(t, i, "/usr/bin/flood", "-f")
	}
	waitFor(t, "every record to be normalized", func() bool {
		return h.metrics.EventsCreated.Load() >= produced
	})
	waitFor(t, "the queue to start dropping", func() bool {
		return h.metrics.EventsDropped.Load() > 0
	})

	// Let the transport move again so the overflow report can be delivered.
	c.setAutoAck(true)
	c.ack(assertHighest(t, c))

	overflow := waitType(t, c, event.TypeQueueOverflow)
	dropped := numberField(t, overflow, "events_dropped")
	first := numberField(t, overflow, "first_missing_sequence")
	last := numberField(t, overflow, "last_missing_sequence")
	if dropped == 0 {
		t.Error("sauron.queue.overflow reported no dropped events")
	}
	if first == 0 || last < first {
		t.Errorf("sauron.queue.overflow range is [%d,%d], want a non-empty range above 0", first, last)
	}
	if overflow.Severity != event.SeverityCritical {
		t.Errorf("sauron.queue.overflow severity = %q, want %q", overflow.Severity, event.SeverityCritical)
	}

	// The range it names must be exactly what is missing: an event inside the
	// reported gap would make the report a lie.
	for seq, n := range c.delivered() {
		if seq >= first && seq <= last && n > 0 {
			t.Errorf("sequence %d was delivered although the overflow report says %d..%d is missing",
				seq, first, last)
		}
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestCollectionFailuresBecomeEvents checks the two listener callbacks. They
// are the only way a parse failure or a kernel overrun becomes visible to the
// host, and they are wired without a netlink socket so that the wiring itself
// is what gets tested.
func TestCollectionFailuresBecomeEvents(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	h := startAgent(t, testConfig(c.addr))

	opts := h.agent.listenerOptions()
	if opts.OnParseError == nil || opts.OnKernelLoss == nil {
		t.Fatal("the listener is built without the loss callbacks")
	}
	raw := audit.RawMessage{
		Type: audit.TypeSyscall,
		Data: []byte("audit(1700000001.123:9): this is not a record the parser knows"),
	}
	opts.OnParseError(raw, errors.New("no key=value pairs"))
	opts.OnKernelLoss(4)

	failure := waitType(t, c, event.TypeParseFailure)
	if got := stringField(t, failure, "raw"); got != string(raw.Data) {
		t.Errorf("sauron.parse.failure raw = %q, want the original record text", got)
	}
	if got := stringField(t, failure, "reason"); got != "no key=value pairs" {
		t.Errorf("sauron.parse.failure reason = %q", got)
	}
	if failure.Sequence == 0 {
		t.Error("sauron.parse.failure was delivered without a sequence number")
	}

	lost := waitType(t, c, event.TypeAuditKernelLost)
	if got := numberField(t, lost, "records_lost"); got != 4 {
		t.Errorf("sauron.audit.lost records_lost = %d, want 4", got)
	}
	if lost.Severity != event.SeverityCritical {
		t.Errorf("sauron.audit.lost severity = %q, want %q", lost.Severity, event.SeverityCritical)
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestHeartbeats checks that PING arrives on schedule with counters that
// describe the guest. A missing heartbeat is itself a security signal, so the
// counters have to be real rather than zero.
func TestHeartbeats(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	cfg := testConfig(c.addr)
	const interval = 40 * time.Millisecond
	cfg.Heartbeat.Interval = config.Duration(interval)
	cfg.Heartbeat.Timeout = config.Duration(5 * time.Second)
	h := startAgent(t, cfg)

	h.src.exec(t, 1, "/usr/bin/beat", "-b")
	waitFor(t, "three heartbeats", func() bool {
		pings, _ := c.pingsSeen()
		return len(pings) >= 3
	})

	pings, at := c.pingsSeen()
	for i := 1; i < 3; i++ {
		if gap := at[i].Sub(at[i-1]); gap < interval/2 {
			t.Errorf("heartbeat %d arrived %s after the previous one, want about %s", i, gap, interval)
		}
	}
	last := pings[len(pings)-1]
	if !last.AuditEnabled {
		t.Error("PING reports audit_enabled false although collection is on")
	}
	if last.EventsReceived == 0 {
		t.Error("PING reports events_received 0 although events were collected")
	}
	if last.EventsSent == 0 {
		t.Error("PING reports events_sent 0 although events were delivered")
	}
	if last.QueueDepth > uint64(cfg.Queue.Capacity) {
		t.Errorf("PING reports queue_depth %d, above the capacity %d", last.QueueDepth, cfg.Queue.Capacity)
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestOrderlyShutdown checks that a cancelled run flushes what it collected
// and ends the session with SHUTDOWN, which is how the collector tells
// maintenance from a crash.
func TestOrderlyShutdown(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	h := startAgent(t, cfg)

	// The session has to be established before the shutdown starts, otherwise
	// the test would be racing the handshake rather than the flush.
	h.src.exec(t, 1, "/usr/bin/hello", "-h")
	waitFor(t, "the session to be established", func() bool {
		return len(c.eventsOfType(event.TypeTransportConnected)) > 0
	})

	// Deliberately not waiting for delivery this time: these events are still
	// in flight through the pipeline when the shutdown starts.
	for i := uint64(2); i <= 6; i++ {
		h.src.exec(t, i, "/usr/bin/bye", "-q")
	}
	waitFor(t, "the pipeline to have events in it", func() bool {
		return h.metrics.EventsCreated.Load() >= 7
	})

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}

	waitFor(t, "the SHUTDOWN frame", func() bool { return len(c.shutdownsSeen()) > 0 })
	sd := c.shutdownsSeen()[0]

	created := h.metrics.EventsCreated.Load()
	max := assertNoGaps(t, c)
	if max != created {
		t.Errorf("highest delivered sequence %d, but %d events were created: the flush lost events",
			max, created)
	}
	if sd.LastSequence != max {
		t.Errorf("SHUTDOWN last_sequence = %d, want %d", sd.LastSequence, max)
	}
	if stopping := c.eventsOfType(event.TypeAgentStopping); len(stopping) != 1 {
		t.Errorf("got %d sauron.agent.stopping events, want 1", len(stopping))
	}
	c.checkClean(t)
}

// TestSequenceResumesAfterRestart restarts an agent against the same spool.
// Numbering must continue where the previous run left off: a repeated sequence
// within one boot would make the host's deduplication discard a real event.
func TestSequenceResumesAfterRestart(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	dir := t.TempDir()
	cfg := withSpool(t, testConfig(c.addr), dir)

	first := startAgent(t, cfg)
	for i := uint64(1); i <= 2; i++ {
		first.src.exec(t, i, "/usr/bin/first", "-1")
	}
	waitFor(t, "the first run's events", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 2
	})
	if err := first.stop(); err != nil {
		t.Errorf("first Run: %v", err)
	}
	highestFirstRun := assertNoGaps(t, c)

	second := startAgent(t, cfg)
	for i := uint64(10); i <= 11; i++ {
		second.src.exec(t, i, "/usr/bin/second", "-2")
	}
	waitFor(t, "the second run's events", func() bool {
		return len(c.eventsOfType(event.TypeProcessExec)) >= 4
	})

	var newSeqs []uint64
	for _, r := range c.events() {
		if r.headerSeq > highestFirstRun {
			newSeqs = append(newSeqs, r.headerSeq)
		}
	}
	sort.Slice(newSeqs, func(i, j int) bool { return newSeqs[i] < newSeqs[j] })
	if len(newSeqs) == 0 {
		t.Fatal("the restarted agent delivered no new events")
	}
	if newSeqs[0] != highestFirstRun+1 {
		t.Errorf("the restarted agent started at sequence %d, want %d",
			newSeqs[0], highestFirstRun+1)
	}

	// Sequence numbers are never reused, so nothing above the first run's
	// highest may appear twice.
	seen := map[uint64]bool{}
	for _, seq := range newSeqs {
		if seen[seq] {
			t.Errorf("sequence %d was issued twice across the restart", seq)
		}
		seen[seq] = true
	}

	if err := second.stop(); err != nil {
		t.Errorf("second Run: %v", err)
	}
	assertNoGaps(t, c)
	c.checkClean(t)
}

// TestSpoolFullIsReported drives the spool into its size cap with the host
// refusing to acknowledge anything. Evidence is lost at that point -- that is
// what the cap is for, the alternative being a full disk -- and the loss has to
// arrive at the collector naming the sequences that will never come.
func TestSpoolFullIsReported(t *testing.T) {
	c := newCollector(t, collectorOptions{})
	cfg := withSpool(t, testConfig(c.addr), t.TempDir())
	// Small enough that a hundred events do not fit, and segment-sized so that
	// eviction has something to evict.
	cfg.Spool.MaxSize = config.Size(64 << 10)
	cfg.Spool.SegmentSize = config.Size(16 << 10)
	cfg.Transport.MaxUnacked = 2
	cfg.Transport.AckTimeout = config.Duration(time.Minute)
	h := startAgent(t, cfg)

	for i := uint64(1); i <= 120; i++ {
		h.src.exec(t, i, "/usr/bin/fullspool", "-f")
	}
	waitFor(t, "the spool to reach its size cap", func() bool {
		return h.metrics.EventsDropped.Load() > 0
	})

	// Let the stream move again so the report can be delivered.
	c.setAutoAck(true)
	c.ack(assertHighest(t, c))

	full := waitType(t, c, event.TypeSpoolFull)
	dropped := numberField(t, full, "events_dropped")
	first := numberField(t, full, "first_missing_sequence")
	last := numberField(t, full, "last_missing_sequence")
	if dropped == 0 {
		t.Error("sauron.spool.full reported no dropped events")
	}
	if first == 0 || last < first {
		t.Errorf("sauron.spool.full range is [%d,%d], want a non-empty range above 0", first, last)
	}
	if full.Severity != event.SeverityCritical {
		t.Errorf("sauron.spool.full severity = %q, want %q", full.Severity, event.SeverityCritical)
	}

	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
	c.checkClean(t)
}

// TestNewRejectsUnusableConfiguration checks that a configuration that cannot
// work is refused at startup rather than becoming an agent that never delivers.
func TestNewRejectsUnusableConfiguration(t *testing.T) {
	cfg := testConfig("127.0.0.1:1")
	cfg.Transport.TCPAddress = ""
	if _, err := New(Options{Config: cfg, Logger: logging.Discard()}); err == nil {
		t.Error("New accepted a TCP transport with no address")
	}

	cfg = testConfig("127.0.0.1:1")
	cfg.Spool.Enabled = true
	cfg.Spool.Path = "relative/path"
	if _, err := New(Options{Config: cfg, Logger: logging.Discard()}); err == nil {
		t.Error("New accepted a relative spool path")
	}
}

// TestRunIsSingleUse: an agent that had been run twice would hand out the same
// sequence numbers from two pipelines at once.
func TestRunIsSingleUse(t *testing.T) {
	c := newCollector(t, collectorOptions{autoAck: true})
	h := startAgent(t, testConfig(c.addr))
	waitType(t, c, event.TypeAgentStarted)

	if err := h.agent.Run(context.Background()); err == nil {
		t.Error("Run succeeded a second time")
	}
	if err := h.stop(); err != nil {
		t.Errorf("Run: %v", err)
	}
}

// TestCloseAfterFailedRunIsSafe: Close has to work on an agent whose Run never
// got anywhere, because that is exactly when a caller reaches for it.
func TestCloseAfterFailedRunIsSafe(t *testing.T) {
	cfg := withSpool(t, testConfig("127.0.0.1:1"), t.TempDir())
	a, err := New(Options{
		Config:   cfg,
		Identity: testIdentity(),
		Logger:   logging.Discard(),
		Source:   newRecordSource().run,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Nothing was ever run: no stage started, no connection was made.
	if err := a.Close(); err != nil {
		t.Errorf("Close after a run that never happened: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
