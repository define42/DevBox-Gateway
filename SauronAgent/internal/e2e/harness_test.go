package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/agent"
	"github.com/define42/SauronAgent/internal/audit"
	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/host"
	"github.com/define42/SauronAgent/internal/identity"
	"github.com/define42/SauronAgent/internal/logging"
	"github.com/define42/SauronAgent/internal/metrics"
	"github.com/define42/SauronAgent/internal/output"
	"github.com/define42/SauronAgent/internal/protocol"
	"github.com/define42/SauronAgent/internal/transport"
	"github.com/mdlayher/vsock"
)

// Timing. Nothing in this package sleeps in order to synchronise: a test that
// has to wait for the system to reach a state polls for that state with a
// deadline, and a test that has to wait for a timer configures the timer down
// to milliseconds first.
const (
	// waitTimeout is generous on purpose. It only bounds a test that is
	// already failing, so making it tight would buy nothing but flakiness on a
	// loaded machine.
	waitTimeout = 30 * time.Second

	// pollInterval is how often a wait re-checks its condition.
	pollInterval = 2 * time.Millisecond
)

// The fleet the harness pretends to run. The CIDs and names are the ones in
// examples/sauronhost.yaml, so a test failure reads like the shipped
// configuration rather than like a fixture.
const (
	// guestCID is the VM under test and guestVM is the name the collector's
	// configuration gives it. Every assertion about trusted enrichment is an
	// assertion that the collector reported guestVM and not what the guest
	// said about itself.
	guestCID uint32 = 102
	guestVM         = "transfer-vm-03"

	// otherCID is a second VM, used for the connections that are meant to
	// misbehave. It exists so that a hostile guest cannot be confused with the
	// well-behaved one: they arrive on different CIDs, which is the one
	// identity claim in the system a guest cannot forge.
	otherCID uint32 = 200
	otherVM         = "build-runner-07"

	// claimedCID and claimedVM are a third VM that the guest in
	// TestIdentityCannotBeForged claims to be. It is deliberately a real entry
	// in the collector's map: the point is that a truthful-looking name still
	// does not decide identity.
	claimedCID uint32 = 103
	claimedVM         = "db-primary-01"

	// hypervisorName is trusted metadata: it is configured on the host and no
	// guest can influence it.
	hypervisorName = "hypervisor-test-01"
)

// TestMain runs the tests and then checks that nothing was left running.
//
// These tests start agents, collectors, listeners, sessions and hand-written
// clients. One that forgot to stop something would still pass and leave the
// leak for whatever ran next, so the count is checked once at the end:
// every listener, session and pipeline stage in this system owns a goroutine,
// which makes the goroutine count the cheapest honest proxy for "it all shut
// down".
func TestMain(m *testing.M) {
	before := runtime.NumGoroutine()
	code := m.Run()
	if code == 0 {
		if leaked, stacks := leakedGoroutines(before); leaked > 0 {
			fmt.Fprintf(os.Stderr, "%d goroutines outlived the tests:\n%s\n", leaked, stacks)
			code = 1
		}
	}
	os.Exit(code)
}

// leakedGoroutines waits for the goroutine count to fall back to want, which
// takes a scheduling quantum or two after the last Close, and reports what is
// still running if it never does.
func leakedGoroutines(want int) (int, string) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= want {
			return 0, ""
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			return n - want, string(buf[:runtime.Stack(buf, true)])
		}
		time.Sleep(pollInterval)
	}
}

// ---------------------------------------------------------------------------
// the audit session
// ---------------------------------------------------------------------------

// block is one logical audit event: every record the kernel emitted under one
// audit(<secs>.<msecs>:<serial>) event id, in the order it emitted them.
type block struct {
	auditID string
	lines   []string
}

// sessionPath is the raw record text the tests replay.
const sessionPath = "testdata/audit_session.txt"

// loadSession reads the recorded audit session.
//
// The file is auditd's on-disk record text. Blocks are separated by blank
// lines and '#' starts a comment; everything else is handed to audit.ParseLine
// exactly as it appears, so the tests exercise the real parser on real record
// syntax rather than on structures built in Go.
func loadSession(t *testing.T) []block {
	t.Helper()

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		t.Fatalf("reading %s: %v", sessionPath, err)
	}

	var (
		blocks  []block
		current block
	)
	flush := func() {
		if len(current.lines) > 0 {
			blocks = append(blocks, current)
		}
		current = block{}
	}
	for n, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			continue
		case trimmed == "":
			flush()
			continue
		}
		r, err := audit.ParseLine(line)
		if err != nil {
			t.Fatalf("%s:%d: ParseLine(%q): %v", sessionPath, n+1, line, err)
		}
		if r.AuditID == "" {
			t.Fatalf("%s:%d: record has no audit event id: %q", sessionPath, n+1, line)
		}
		if current.auditID == "" {
			current.auditID = r.AuditID
		}
		if r.AuditID != current.auditID {
			// A block whose records do not share an event id would be
			// correlated into two events and every ordering assertion built on
			// it would be wrong.
			t.Fatalf("%s:%d: audit id %s does not match %s, the first of its block",
				sessionPath, n+1, r.AuditID, current.auditID)
		}
		current.lines = append(current.lines, line)
	}
	flush()

	if len(blocks) == 0 {
		t.Fatalf("%s contains no audit records", sessionPath)
	}
	return blocks
}

// ---------------------------------------------------------------------------
// the collector's output
// ---------------------------------------------------------------------------

// delivered is one envelope as a sink received it, with the JSON document a
// real sink would have written for it.
//
// The JSON is kept because some of what these tests check is only visible in
// the encoding: "uid":0 has to survive as a field, and an absent identity has
// to stay absent rather than be rendered as 0.
type delivered struct {
	env  *output.Envelope
	line []byte
}

// recorder is the collector's sink and the tests' view of what the whole
// system delivered.
//
// It can be told to refuse every write, which is how backpressure is
// exercised: an event a sink refuses must not be acknowledged to the guest,
// and the guest must keep it and send it again.
//
// Close does not stop it recording. A collector owns its sink and closes it on
// shutdown, but the tests that stop and restart the collector want one
// continuous record of everything the system delivered across both
// generations, so closing is counted rather than enforced.
type recorder struct {
	mu       sync.Mutex
	got      []delivered
	refused  map[string]int
	failing  bool
	failures int
	closes   int
}

func newRecorder() *recorder { return &recorder{refused: make(map[string]int)} }

// Write records one envelope, or refuses it while the recorder is failing.
func (r *recorder) Write(ctx context.Context, env *output.Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if env == nil || env.Event == nil {
		return errors.New("recorder: envelope carried no event")
	}
	line, err := marshalEnvelope(env)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failing {
		// The refusal is remembered by kernel event id, so a test can wait for
		// the collector to have tried a particular event rather than for a
		// count that its own internal events could reach on their own.
		r.failures++
		r.refused[env.Event.AuditID]++
		return errors.New("recorder: the output is refusing writes")
	}
	r.got = append(r.got, delivered{env: env, line: line})
	return nil
}

// Flush has nothing to make durable: everything the recorder holds is in
// memory and is read from there.
func (r *recorder) Flush(ctx context.Context) error { return ctx.Err() }

func (r *recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closes++
	return nil
}

func (r *recorder) Name() string { return "recorder" }

// setFailing turns the sink's refusal on or off.
func (r *recorder) setFailing(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failing = v
}

// refusedAuditIDs reports how often each kernel event id was offered to the
// sink and refused.
func (r *recorder) refusedAuditIDs() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.refused))
	for id, n := range r.refused {
		out[id] = n
	}
	return out
}

// closed is how many times a collector closed the sink.
func (r *recorder) closed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closes
}

// audited returns the guest's audit events, in the order the collector wrote
// them, without the sauron.* events the agent and the collector report about
// themselves.
func (r *recorder) audited() []delivered {
	return r.filter(func(e *event.Event) bool { return !event.IsInternal(e.Type) })
}

// internalOfType returns the internal events of one type.
func (r *recorder) internalOfType(typ string) []delivered {
	return r.filter(func(e *event.Event) bool { return e.Type == typ })
}

func (r *recorder) filter(keep func(*event.Event) bool) []delivered {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []delivered
	for _, d := range r.got {
		if d.env.Event != nil && keep(d.env.Event) {
			out = append(out, d)
		}
	}
	return out
}

// auditedCount is the number of audit events delivered so far.
func (r *recorder) auditedCount() int { return len(r.audited()) }

// auditIDs is the set of kernel event ids delivered, with how many times each
// one arrived. Delivery is at-least-once, so a count above one is legal.
func (r *recorder) auditIDs() map[string]int {
	out := make(map[string]int)
	for _, d := range r.audited() {
		out[d.env.Event.AuditID]++
	}
	return out
}

// sequences maps every delivered sequence number to the events that arrived
// under it. More than one entry is a duplicate delivery, which is expected;
// two *different* events under one sequence would mean the stream had been
// renumbered, which is not.
func (r *recorder) sequences() map[uint64][]*event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[uint64][]*event.Event, len(r.got))
	for _, d := range r.got {
		e := d.env.Event
		out[e.Sequence] = append(out[e.Sequence], e)
	}
	return out
}

// marshalEnvelope renders an envelope exactly as the shipped sinks do, so that
// what a test inspects is what an installation's log would contain.
func marshalEnvelope(env *output.Envelope) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// the listener, and the identity the hypervisor would have supplied
// ---------------------------------------------------------------------------

// cidConn is an accepted TCP connection wearing the VSOCK address the
// hypervisor would have given it.
//
// The collector identifies a guest with transport.PeerCID, which reads the
// connection's remote address and accepts it only when it is a *vsock.Addr.
// There is no VSOCK device in a test, so the harness supplies the address the
// kernel would have written. That is the one piece of the production path
// these tests fake, and it is faked here rather than by reaching into the
// collector, so everything downstream -- authorisation, the CID-to-VM map,
// the per-CID connection limits and the deduplication key -- is the real code
// running on a real CID.
type cidConn struct {
	net.Conn
	remote *vsock.Addr
}

// RemoteAddr reports the guest's context ID, as the hypervisor would.
func (c *cidConn) RemoteAddr() net.Addr { return c.remote }

// endpoint is one TCP listening address plus the CID the harness attributes to
// every connection that arrives on it. One address per CID is what lets
// several guests exist at once without the harness having to guess which
// connection belongs to which of them.
type endpoint struct {
	cid  uint32
	addr string
}

// fanIn presents the per-CID listeners to the collector as the single
// transport.Listener it expects.
type fanIn struct {
	conns chan net.Conn
	subs  []transport.Listener
	addr  net.Addr

	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}

	// live is every connection handed to this collector generation, kept only
	// so that a test can cut them all at once. Entries are not removed when a
	// connection ends: closing a closed connection is harmless, and a
	// generation lasts one test.
	mu   sync.Mutex
	live []net.Conn
}

// listenAll binds one TCP listener per endpoint and fans them into one
// Listener. An endpoint with no address yet is bound on an ephemeral port and
// its address recorded, so that a collector restarted later can bind the same
// one and the guest's dialler does not have to know it moved.
func listenAll(t *testing.T, eps []endpoint) *fanIn {
	t.Helper()

	f := &fanIn{conns: make(chan net.Conn, 16), done: make(chan struct{})}
	for i := range eps {
		addr := eps[i].addr
		if addr == "" {
			addr = "127.0.0.1:0"
		}
		ln := listenRetry(t, addr)
		eps[i].addr = ln.Addr().String()
		f.subs = append(f.subs, ln)
		if f.addr == nil {
			f.addr = ln.Addr()
		}

		cid := eps[i].cid
		f.wg.Add(1)
		go f.accept(ln, cid)
	}
	return f
}

// listenRetry binds addr, retrying while the address is still held by the
// listener a previous collector generation closed a moment ago.
func listenRetry(t *testing.T, addr string) transport.Listener {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		ln, err := transport.ListenTCP(addr)
		if err == nil {
			return ln
		}
		if time.Now().After(deadline) {
			t.Fatalf("listening on %s: %v", addr, err)
		}
		time.Sleep(pollInterval)
	}
}

// accept feeds one sub-listener's connections into the fan-in, stamped with
// its CID.
func (f *fanIn) accept(ln transport.Listener, cid uint32) {
	defer f.wg.Done()
	for {
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		conn := &cidConn{Conn: nc, remote: &vsock.Addr{ContextID: cid, Port: 9000}}
		f.mu.Lock()
		f.live = append(f.live, conn)
		f.mu.Unlock()

		select {
		case f.conns <- conn:
		case <-f.done:
			_ = conn.Close()
			return
		}
	}
}

// killConns cuts every live guest connection, which is what a collector that
// died looks like from the guest: no SHUTDOWN, no last acknowledgement, and
// whatever was in flight still owed.
func (f *fanIn) killConns() {
	f.mu.Lock()
	live := f.live
	f.live = nil
	f.mu.Unlock()
	for _, c := range live {
		_ = c.Close()
	}
}

// Accept hands the collector the next guest connection.
func (f *fanIn) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

// Close stops every sub-listener and releases the addresses, so that the next
// collector generation can bind them again.
func (f *fanIn) Close() error {
	f.once.Do(func() {
		close(f.done)
		for _, ln := range f.subs {
			_ = ln.Close()
		}
		f.wg.Wait()
		// A connection accepted but never handed over would leave a guest
		// waiting for a handshake that is not coming, and leak the socket.
		for {
			select {
			case c := <-f.conns:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

// Addr reports the first endpoint's address; it is only used in log lines.
func (f *fanIn) Addr() net.Addr { return f.addr }

// ---------------------------------------------------------------------------
// the collector
// ---------------------------------------------------------------------------

// harness is a running SauronHost collector plus the handles a test needs to
// drive it: the output it wrote, its counters, the addresses its guests dial
// and the ability to stop and restart it on those same addresses.
type harness struct {
	t        *testing.T
	cfg      config.Host
	rec      *recorder
	counters *metrics.Host
	eps      []endpoint

	mu       sync.Mutex
	notified []*output.Envelope

	srv     *host.Server
	fan     *fanIn
	cancel  context.CancelFunc
	runErr  chan error
	running bool
}

// newHarness starts a collector with the fleet configured and the timers
// turned down. tweak, when set, gets the last word over the configuration.
func newHarness(t *testing.T, tweak func(*config.Host)) *harness {
	t.Helper()

	cfg := config.DefaultHost()
	cfg.Host.Name = hypervisorName
	// The harness supplies its own listener, but Listen still has to be a
	// configuration the collector would accept: New validates all of it.
	cfg.Listen = config.ListenSection{Kind: config.TransportTCP, TCPAddress: "127.0.0.1:0"}
	cfg.VMs = []config.VMMapping{
		{
			CID:            guestCID,
			Name:           guestVM,
			UUID:           "b1c4e0d2-55a7-42c9-8f31-9d0e4c6a7b18",
			Environment:    "production",
			SecurityDomain: "restricted",
			VLAN:           "310",
			Labels:         map[string]string{"owner": "data-team", "compliance": "pci"},
			Expected:       true,
		},
		{CID: claimedCID, Name: claimedVM, Environment: "production", SecurityDomain: "internal"},
		{CID: otherCID, Name: otherVM, Environment: "staging"},
	}
	// Stream health is covered by the host package's own tests and would
	// otherwise report a VM as lost while a test is deliberately holding one
	// silent.
	cfg.Monitor.Enabled = false
	cfg.Limits.AckInterval = 1
	cfg.Limits.AckMaxDelay = config.Duration(100 * time.Millisecond)
	cfg.Limits.HandshakeTimeout = config.Duration(2 * time.Second)
	cfg.Limits.IdleTimeout = config.Duration(waitTimeout)
	// A guest that reconnects on a short acknowledgement timeout can have more
	// than one session in flight for a moment; the limit is not what these
	// tests are about.
	cfg.Limits.MaxConnectionsPerCID = 16
	if tweak != nil {
		tweak(&cfg)
	}

	h := &harness{
		t:        t,
		cfg:      cfg,
		rec:      newRecorder(),
		counters: &metrics.Host{},
		eps:      []endpoint{{cid: guestCID}, {cid: otherCID}},
	}
	h.startCollector()
	t.Cleanup(h.stopCollector)
	return h
}

// startCollector binds the endpoints and runs a collector on them. It is used
// both for the initial start and for a restart after an outage, which is why
// the addresses are remembered in h.eps.
func (h *harness) startCollector() {
	h.t.Helper()
	if h.running {
		h.t.Fatal("the collector is already running")
	}

	fan := listenAll(h.t, h.eps)
	srv, err := host.New(host.Options{
		Config:   h.cfg,
		Sink:     h.rec,
		Metrics:  h.counters,
		Logger:   logging.Discard(),
		Listener: fan,
		OnInternalEvent: func(env *output.Envelope) {
			h.mu.Lock()
			h.notified = append(h.notified, env)
			h.mu.Unlock()
		},
	})
	if err != nil {
		_ = fan.Close()
		h.t.Fatalf("host.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.srv, h.fan, h.cancel = srv, fan, cancel
	h.runErr = make(chan error, 1)
	h.running = true
	go func() { h.runErr <- srv.Run(ctx) }()
}

// crashCollector stops the collector the way a crash would. The live guest
// connections are cut first, so nothing is acknowledged on the way out and the
// guest is left holding events it has already sent -- which is what makes the
// recovery a real at-least-once replay rather than a tidy resumption.
func (h *harness) crashCollector() {
	h.t.Helper()
	if !h.running {
		return
	}
	h.fan.killConns()
	h.stopCollector()
}

// stopCollector stops the collector as a service manager would, and waits for
// it: an orderly stop drains the live sessions and closes the sink, and a test
// that raced ahead of that would be asserting on a half-written output.
func (h *harness) stopCollector() {
	h.t.Helper()
	if !h.running {
		return
	}
	h.running = false

	h.cancel()
	select {
	case err := <-h.runErr:
		if err != nil {
			h.t.Errorf("collector Run returned %v, want nil for an orderly stop", err)
		}
	case <-time.After(waitTimeout):
		h.t.Fatal("the collector did not stop")
	}
	if err := h.srv.Close(); err != nil {
		h.t.Errorf("collector Close: %v", err)
	}
	// The listener is closed by Run's teardown; closing it again is how the
	// harness makes sure the addresses are free before they are bound again.
	_ = h.fan.Close()
}

// addr is the address a guest on cid dials.
func (h *harness) addr(cid uint32) string {
	h.t.Helper()
	for _, e := range h.eps {
		if e.cid == cid {
			return e.addr
		}
	}
	h.t.Fatalf("no endpoint for CID %d", cid)
	return ""
}

// reported returns the internal events the collector handed to
// Options.OnInternalEvent, which is how a supervising process sees them
// without parsing the collector's own output.
func (h *harness) reported() []*output.Envelope {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*output.Envelope(nil), h.notified...)
}

// ---------------------------------------------------------------------------
// the guest
// ---------------------------------------------------------------------------

// guestIdentity is what the agent says about itself. Every field of it is a
// claim: the collector records them under source.reported and identifies the
// VM by the CID its connection arrived on.
func guestIdentity() identity.Identity {
	return identity.Identity{
		Hostname:  guestVM,
		MachineID: "9d1f0a6c4f2b41d8a0b7c3e5d6f78901",
		BootID:    "5f1c7d2a-1f7e-4f41-9c33-2a5bd2c0b0e7",
		Kernel:    "6.8.0-45-generic",
		Version:   "e2e",
	}
}

// agentConfig is a production agent configuration pointed at addr, with a
// spool in dir and every timer short enough that a test waits on the system
// rather than on a default measured in seconds.
func agentConfig(addr, dir string) config.Agent {
	cfg := config.DefaultAgent()
	cfg.Transport.Kind = config.TransportTCP
	cfg.Transport.TCPAddress = addr
	cfg.Transport.MaxUnacked = 64
	cfg.Transport.WriteTimeout = config.Duration(5 * time.Second)
	cfg.Transport.AckTimeout = config.Duration(10 * time.Second)

	cfg.Audit.Enabled = true
	cfg.Audit.PreserveRaw = true
	// Long enough that the records of one event are never split, short enough
	// that a user-space record with no EOE marker does not hold a test up.
	cfg.Audit.CorrelationTimeout = config.Duration(30 * time.Millisecond)

	cfg.Queue.Capacity = 1024
	cfg.Spool.Enabled = true
	cfg.Spool.Path = dir
	cfg.Spool.MaxSize = config.Size(8 << 20)
	cfg.Spool.SegmentSize = config.Size(256 << 10)
	cfg.Spool.SyncOnWrite = false
	cfg.Spool.SyncInterval = config.Duration(10 * time.Millisecond)

	// Heartbeats are off by default here: a PING in the middle of a test that
	// is counting frames proves nothing. The happy-path test turns them on.
	cfg.Heartbeat.Interval = config.Duration(time.Hour)
	cfg.Heartbeat.Timeout = 0

	cfg.Reconnect.InitialDelay = config.Duration(5 * time.Millisecond)
	cfg.Reconnect.MaxDelay = config.Duration(50 * time.Millisecond)
	cfg.Reconnect.Jitter = 0
	return cfg
}

// recordSource is the injected replacement for the netlink listener. It is the
// same channel the real listener writes to, so everything from correlation
// onwards is the production path.
type recordSource struct {
	ch chan *audit.Record
}

func newRecordSource() *recordSource {
	return &recordSource{ch: make(chan *audit.Record, 4096)}
}

// run forwards injected records until the agent's context ends.
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

// guest is a running SauronAgent with the records it is fed.
type guest struct {
	t       *testing.T
	agent   *agent.Agent
	src     *recordSource
	metrics *metrics.Agent

	cancel context.CancelFunc
	done   chan error

	stopOnce sync.Once
}

// startGuest builds and runs an agent. Its records are injected rather than
// read from a netlink socket; everything else -- correlation, normalization,
// sequence assignment, the queue, the spool, the codec and the transport -- is
// the shipped code.
func (h *harness) startGuest(cfg config.Agent, id identity.Identity) *guest {
	h.t.Helper()

	src := newRecordSource()
	m := &metrics.Agent{}
	a, err := agent.New(agent.Options{
		Config:   cfg,
		Identity: id,
		Metrics:  m,
		Logger:   logging.Discard(),
		Source:   src.run,
	})
	if err != nil {
		h.t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	g := &guest{t: h.t, agent: a, src: src, metrics: m, cancel: cancel, done: make(chan error, 1)}
	go func() { g.done <- a.Run(ctx) }()
	h.t.Cleanup(g.stop)
	return g
}

// feed injects one block of audit records, as the kernel would deliver them.
func (g *guest) feed(b block) {
	g.t.Helper()
	for _, line := range b.lines {
		r, err := audit.ParseLine(line)
		if err != nil {
			g.t.Fatalf("ParseLine(%q): %v", line, err)
		}
		select {
		case g.src.ch <- r:
		case <-time.After(waitTimeout):
			g.t.Fatalf("the agent is not consuming records: %q", line)
		}
	}
}

// feedAll injects several blocks without waiting for any of them.
func (g *guest) feedAll(blocks []block) {
	g.t.Helper()
	for _, b := range blocks {
		g.feed(b)
	}
}

// created is how many events the agent has numbered, which is also the highest
// sequence it has assigned: numbering starts at 1 and every event takes the
// next one.
func (g *guest) created() uint64 { return g.metrics.EventsCreated.Load() }

// acknowledged is how many delivered events the host has acknowledged.
func (g *guest) acknowledged() uint64 { return g.metrics.EventsAcknowledged.Load() }

// stop ends the run the way a service manager would and waits for the agent to
// flush what it has. It is idempotent, so an explicit stop in a test and the
// cleanup do not collide.
func (g *guest) stop() {
	g.stopOnce.Do(func() {
		g.cancel()
		select {
		case err := <-g.done:
			if err != nil {
				g.t.Errorf("agent Run returned %v, want nil for an orderly stop", err)
			}
		case <-time.After(waitTimeout):
			g.t.Error("the agent did not stop")
		}
		if err := g.agent.Close(); err != nil {
			g.t.Errorf("agent Close: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// a guest that speaks the protocol by hand
// ---------------------------------------------------------------------------

// frameEcho is one frame the collector sent, decoded.
type frameEcho struct {
	typ       protocol.MessageType
	ready     protocol.Ready
	ack       protocol.Ack
	fail      protocol.ErrorMessage
	decodeErr error
}

// rawClient is a guest written by hand: it speaks the wire protocol directly,
// which is the only way to send a collector the things a correct agent never
// would.
type rawClient struct {
	t    *testing.T
	nc   net.Conn
	conn *protocol.Conn

	frames chan frameEcho
	closed chan struct{}
	stop   chan struct{}

	mu      sync.Mutex
	readErr error
}

// dialRaw connects to the endpoint for cid and starts reading whatever the
// collector says back.
func (h *harness) dialRaw(cid uint32) *rawClient {
	h.t.Helper()

	nc, err := net.DialTimeout("tcp", h.addr(cid), waitTimeout)
	if err != nil {
		h.t.Fatalf("dialling the collector on CID %d: %v", cid, err)
	}
	c := &rawClient{
		t:      h.t,
		nc:     nc,
		conn:   protocol.NewConn(nc, protocol.DefaultMaxPayloadSize),
		frames: make(chan frameEcho, 256),
		closed: make(chan struct{}),
		stop:   make(chan struct{}),
	}
	go c.read()
	h.t.Cleanup(c.close)
	return c
}

// read decodes frames until the connection ends.
func (c *rawClient) read() {
	defer close(c.closed)
	for {
		f, err := c.conn.Receive(0)
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			c.mu.Unlock()
			return
		}
		// The header sequence is deliberately not kept: it is meaningless on
		// every message the collector sends, and an ACK carries its sequence
		// in the payload.
		e := frameEcho{typ: f.Type}
		switch f.Type {
		case protocol.MsgReady:
			e.decodeErr = protocol.DecodePayload(f, &e.ready)
		case protocol.MsgAck:
			e.decodeErr = protocol.DecodePayload(f, &e.ack)
		case protocol.MsgError:
			e.decodeErr = protocol.DecodePayload(f, &e.fail)
		}
		select {
		case c.frames <- e:
		case <-c.stop:
			return
		}
	}
}

// hello completes the handshake and returns the collector's READY.
func (c *rawClient) hello(bootID string, firstSeq uint64) protocol.Ready {
	c.t.Helper()
	c.send(protocol.MsgHello, 0, protocol.Hello{
		ProtocolVersion: protocol.Version,
		AgentVersion:    "raw-client",
		Hostname:        "raw-client",
		BootID:          bootID,
		FirstSequence:   firstSeq,
	})
	return c.waitFrame(protocol.MsgReady).ready
}

// send writes one well-formed frame.
func (c *rawClient) send(typ protocol.MessageType, seq uint64, v any) {
	c.t.Helper()
	if err := c.conn.Send(typ, seq, v, waitTimeout); err != nil {
		c.t.Fatalf("sending %s: %v", typ, err)
	}
}

// sendEvent delivers one event with the given header sequence. headerSeq and
// the event's own sequence are separate arguments on purpose: a guest that
// disagrees with itself is one of the things the collector has to refuse.
func (c *rawClient) sendEvent(headerSeq uint64, ev *event.Event) {
	c.t.Helper()
	c.send(protocol.MsgEvent, headerSeq, protocol.EventMessage{Event: ev})
}

// sendRaw writes bytes straight to the socket, past the encoder.
func (c *rawClient) sendRaw(b []byte) {
	c.t.Helper()
	if err := c.nc.SetWriteDeadline(time.Now().Add(waitTimeout)); err != nil {
		c.t.Fatalf("setting a write deadline: %v", err)
	}
	if _, err := c.nc.Write(b); err != nil {
		c.t.Fatalf("writing %d raw bytes: %v", len(b), err)
	}
}

// closeWrite half-closes the connection, which is how a truncated frame is
// presented to the collector as a stream that stopped rather than as a peer
// that is still typing.
func (c *rawClient) closeWrite() {
	c.t.Helper()
	tc, ok := c.nc.(*net.TCPConn)
	if !ok {
		c.t.Fatalf("connection is %T, not a TCP connection", c.nc)
	}
	if err := tc.CloseWrite(); err != nil {
		c.t.Fatalf("half-closing: %v", err)
	}
}

// waitFrame waits for the next frame of the given type, ignoring the others.
func (c *rawClient) waitFrame(typ protocol.MessageType) frameEcho {
	c.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		select {
		case e := <-c.frames:
			if e.decodeErr != nil {
				c.t.Fatalf("decoding a %s frame: %v", e.typ, e.decodeErr)
			}
			if e.typ == typ {
				return e
			}
			continue
		default:
		}
		if c.isClosed() && len(c.frames) == 0 {
			c.t.Fatalf("the collector closed the connection before sending %s: %v", typ, c.err())
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("timed out waiting for a %s frame", typ)
		}
		time.Sleep(pollInterval)
	}
}

// waitAck waits for a cumulative acknowledgement through at least seq and
// returns the highest one seen.
//
// It waits for a value rather than for the next ACK frame: acknowledgement is
// cumulative and batched, so which frame carries a given sequence is the
// collector's business and not something a test may depend on.
func (c *rawClient) waitAck(seq uint64) uint64 {
	c.t.Helper()
	var highest uint64
	deadline := time.Now().Add(waitTimeout)
	for {
		select {
		case e := <-c.frames:
			if e.decodeErr != nil {
				c.t.Fatalf("decoding a %s frame: %v", e.typ, e.decodeErr)
			}
			if e.typ == protocol.MsgAck && e.ack.Sequence > highest {
				highest = e.ack.Sequence
			}
			continue
		default:
		}
		if highest >= seq {
			return highest
		}
		if c.isClosed() && len(c.frames) == 0 {
			c.t.Fatalf("the collector closed the connection having acknowledged only %d of %d: %v",
				highest, seq, c.err())
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("timed out waiting for an acknowledgement through %d, highest was %d", seq, highest)
		}
		time.Sleep(pollInterval)
	}
}

// waitClosed waits for the collector to close the connection.
func (c *rawClient) waitClosed() {
	c.t.Helper()
	select {
	case <-c.closed:
	case <-time.After(waitTimeout):
		c.t.Fatal("the collector kept the connection open")
	}
}

// drain returns every frame received so far. It is called after waitClosed,
// where the reader has already finished and nothing more can arrive.
func (c *rawClient) drain() []frameEcho {
	var out []frameEcho
	for {
		select {
		case e := <-c.frames:
			out = append(out, e)
		default:
			return out
		}
	}
}

func (c *rawClient) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *rawClient) err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readErr
}

// close ends the connection and the reader.
func (c *rawClient) close() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	_ = c.nc.Close()
}

// ---------------------------------------------------------------------------
// waiting
// ---------------------------------------------------------------------------

// waitFor polls cond until it holds or the deadline passes. Every wait in this
// package goes through it: a test that slept for a fixed time would pass on a
// fast machine and fail on a loaded one, and prove nothing on either.
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

// waitAudited waits until at least n audit events have reached the sink.
func (h *harness) waitAudited(n int) {
	h.t.Helper()
	waitFor(h.t, fmt.Sprintf("%d audit events at the collector", n), func() bool {
		return h.rec.auditedCount() >= n
	})
}

// waitAuditIDs waits until every one of the given kernel event ids has been
// delivered at least once.
func (h *harness) waitAuditIDs(want []string) {
	h.t.Helper()
	waitFor(h.t, fmt.Sprintf("%d distinct audit events at the collector", len(want)), func() bool {
		got := h.rec.auditIDs()
		for _, id := range want {
			if got[id] == 0 {
				return false
			}
		}
		return true
	})
}

// assertNoGaps checks that every sequence from 1 to the highest delivered was
// delivered, and that no two different events ever arrived under one sequence.
//
// A duplicate is expected: delivery is at-least-once and a reconnect replays.
// A hole is not, and a hole nobody reports is exactly the failure the whole
// design exists to prevent.
func assertNoGaps(t *testing.T, r *recorder) uint64 {
	t.Helper()

	seqs := r.sequences()
	if len(seqs) == 0 {
		t.Fatal("nothing was delivered")
	}
	var highest uint64
	for seq := range seqs {
		if seq > highest {
			highest = seq
		}
	}

	var missing []uint64
	for seq := uint64(1); seq <= highest; seq++ {
		evs := seqs[seq]
		if len(evs) == 0 {
			missing = append(missing, seq)
			continue
		}
		for _, e := range evs[1:] {
			if e.Type != evs[0].Type || e.AuditID != evs[0].AuditID {
				t.Errorf("sequence %d carried two different events: %s/%s and %s/%s",
					seq, evs[0].Type, evs[0].AuditID, e.Type, e.AuditID)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("sequences never delivered: %v (highest delivered %d)", missing, highest)
	}
	return highest
}

// eventJSON decodes the JSON a sink would have written, so that a test can ask
// what is in the document rather than what is in the Go value. The two differ
// in exactly the place that matters: an identity field that is nil disappears,
// and one that is zero must not.
func eventJSON(t *testing.T, d delivered) map[string]any {
	t.Helper()
	var doc struct {
		Event map[string]any `json:"event"`
	}
	dec := json.NewDecoder(bytes.NewReader(d.line))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decoding the written envelope: %v\n%s", err, d.line)
	}
	if doc.Event == nil {
		t.Fatalf("the written envelope has no event object:\n%s", d.line)
	}
	return doc.Event
}
