package sauron

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/define42/devbox-gateway/internal/splunkhec"
)

// SAUR message types (SauronAgent docs/protocol.md section 3).
const (
	msgHello    = 1
	msgReady    = 2
	msgEvent    = 3
	msgAck      = 4
	msgShutdown = 8
)

// fakeAgent speaks the guest side of the SAUR wire protocol, written out by
// hand from protocol.md so the gateway's collector is exercised exactly as a
// real SauronAgent would drive it.
type fakeAgent struct {
	t    *testing.T
	conn net.Conn
}

func newFakeAgent(t *testing.T, conn net.Conn) *fakeAgent {
	t.Helper()
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeAgent{t: t, conn: conn}
}

func (a *fakeAgent) send(messageType byte, sequence uint64, payload any) {
	a.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		a.t.Fatalf("encode payload: %v", err)
	}
	frame := make([]byte, 20, 20+len(body))
	copy(frame, "SAUR")
	frame[4] = 1 // protocol version
	frame[5] = messageType
	binary.BigEndian.PutUint64(frame[8:16], sequence)
	binary.BigEndian.PutUint32(frame[16:20], uint32(len(body)))
	frame = append(frame, body...)
	_ = a.conn.SetWriteDeadline(time.Now().Add(testTimeout))
	if _, err := a.conn.Write(frame); err != nil {
		a.t.Fatalf("send frame type %d: %v", messageType, err)
	}
}

// receive returns the next frame's type and payload.
func (a *fakeAgent) receive() (byte, []byte, error) {
	_ = a.conn.SetReadDeadline(time.Now().Add(testTimeout))
	header := make([]byte, 20)
	if _, err := io.ReadFull(a.conn, header); err != nil {
		return 0, nil, err
	}
	if !bytes.Equal(header[:4], []byte("SAUR")) || header[4] != 1 {
		a.t.Fatalf("collector sent a malformed header %x", header)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[16:20]))
	if _, err := io.ReadFull(a.conn, payload); err != nil {
		return 0, nil, err
	}
	return header[5], payload, nil
}

func (a *fakeAgent) handshake(bootID string) {
	a.t.Helper()
	a.send(msgHello, 0, map[string]any{"protocol_version": 1, "agent_version": "test", "hostname": "guest-claim", "boot_id": bootID})
	messageType, payload, err := a.receive()
	if err != nil || messageType != msgReady {
		a.t.Fatalf("after HELLO got type %d %s, %v; want READY", messageType, payload, err)
	}
}

func (a *fakeAgent) sendEvent(sequence uint64, bootID string) {
	a.t.Helper()
	a.send(msgEvent, sequence, map[string]any{"event": map[string]any{
		"version":   1,
		"sequence":  sequence,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"type":      "process.exec",
		"boot_id":   bootID,
		"command":   "cat /etc/shadow",
	}})
}

// acknowledged sends SHUTDOWN, which makes the collector send its final
// cumulative ACK, and returns the highest sequence acknowledged before the
// connection closed.
func (a *fakeAgent) acknowledged() uint64 {
	a.t.Helper()
	a.send(msgShutdown, 0, map[string]any{"reason": "test"})
	var acked uint64
	for {
		messageType, payload, err := a.receive()
		if err != nil {
			return acked
		}
		if messageType != msgAck {
			continue
		}
		var ack struct {
			Sequence uint64 `json:"sequence"`
		}
		if err := json.Unmarshal(payload, &ack); err != nil {
			a.t.Fatalf("decode ACK %s: %v", payload, err)
		}
		acked = max(acked, ack.Sequence)
	}
}

func startTestCollector(t *testing.T, options Options) *Collector {
	t.Helper()
	collector, err := Start(options)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { _ = collector.Close() })
	return collector
}

func tcpListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

// hecOptions configures the collector to forward to hec through a spool in dir.
func hecOptions(hec *fakeHEC, dir string, listener net.Listener) Options {
	return Options{
		Port:          9000,
		HEC:           hec.config("sauron"),
		SpoolDir:      dir,
		SpoolMaxBytes: 1 << 20,
		listener:      listener,
	}
}

func readEventLog(t *testing.T, path string) []map[string]any {
	t.Helper()
	file, err := os.Open(path) // #nosec G304 -- test-owned temporary path
	if err != nil {
		t.Fatalf("open event log: %v", err)
	}
	defer func() { _ = file.Close() }()
	return readJSONLines(t, file)
}

func eventSource(event map[string]any) map[string]any {
	source, _ := event["source"].(map[string]any)
	return source
}

// TestCollectorAttributesVSockGuestsByCID drives the production path: an
// AF_VSOCK connection whose CID the gateway resolves to a VM. It needs a vsock
// transport that can reach itself (vsock_loopback), where the peer CID is 1.
func TestCollectorAttributesVSockGuestsByCID(t *testing.T) {
	listener, err := vsock.ListenContextID(0xFFFFFFFF, 0, nil)
	if err != nil {
		t.Skipf("no AF_VSOCK listener on this host: %v", err)
	}
	conn, err := vsock.Dial(1, listener.Addr().(*vsock.Addr).Port, nil)
	if err != nil {
		_ = listener.Close()
		t.Skipf("no AF_VSOCK loopback transport on this host: %v", err)
	}

	var resolved []uint32
	hec := newFakeHEC(t)
	logFile := filepath.Join(t.TempDir(), "logs", "sauron.jsonl")
	options := hecOptions(hec, t.TempDir(), listener)
	options.EventLogFile = logFile
	options.Resolve = func(cid uint32) (VM, bool, error) {
		resolved = append(resolved, cid)
		return VM{Name: "alice-dev", UUID: "4f7c1b9e-0d52-4c55-9b8a-3e1f2a6d7c80", Owner: "alice"}, true, nil
	}
	collector := startTestCollector(t, options)

	agent := newFakeAgent(t, conn)
	agent.handshake("boot-1")
	agent.sendEvent(1, "boot-1")
	if acked := agent.acknowledged(); acked != 1 {
		t.Fatalf("collector acknowledged through %d, want 1", acked)
	}
	accepted := hec.waitAccepted(t, 1)
	if err := collector.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if len(resolved) != 1 || resolved[0] != 1 {
		t.Fatalf("Resolve calls = %v, want one for the loopback CID 1", resolved)
	}
	if len(accepted) != 1 || accepted[0]["host"] != "alice-dev" {
		t.Fatalf("HEC events = %v, want one with host alice-dev", accepted)
	}
	envelope, _ := accepted[0]["event"].(map[string]any)
	source := eventSource(envelope)
	labels, _ := source["labels"].(map[string]any)
	if source["vm"] != "alice-dev" || source["known"] != true || source["cid"] != float64(1) || labels["owner"] != "alice" {
		t.Errorf("HEC event source = %v, want the resolved VM on CID 1 owned by alice", source)
	}
	if lines := readEventLog(t, logFile); len(lines) != 1 || eventSource(lines[0])["vm"] != "alice-dev" {
		t.Errorf("event log = %v, want the same event", lines)
	}
}

func TestCollectorWritesEventsToTheEventLogAndHEC(t *testing.T) {
	hec := newFakeHEC(t)
	logFile := filepath.Join(t.TempDir(), "sauron.jsonl")
	resolveCalls := 0
	listener := tcpListener(t)
	options := hecOptions(hec, t.TempDir(), listener)
	options.EventLogFile = logFile
	options.Resolve = func(uint32) (VM, bool, error) {
		resolveCalls++
		return VM{}, false, nil
	}
	collector := startTestCollector(t, options)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	agent := newFakeAgent(t, conn)
	agent.handshake("boot-1")
	agent.sendEvent(1, "boot-1")
	agent.sendEvent(2, "boot-1")
	if acked := agent.acknowledged(); acked != 2 {
		t.Fatalf("collector acknowledged through %d, want 2", acked)
	}
	accepted := hec.waitAccepted(t, 2)
	if err := collector.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if len(accepted) != 2 {
		t.Fatalf("HEC accepted %d events, want 2", len(accepted))
	}
	for _, event := range accepted {
		if event["index"] != "sauron" || event["sourcetype"] != hecSourcetype {
			t.Errorf("HEC event metadata = %v, want index sauron and sourcetype %s", event, hecSourcetype)
		}
	}
	lines := readEventLog(t, logFile)
	if len(lines) != 2 {
		t.Fatalf("event log holds %d lines, want 2", len(lines))
	}
	// A TCP peer carries no hypervisor identity, so it is never resolved.
	if source := eventSource(lines[0]); source["known"] != false || !strings.HasPrefix(source["vm"].(string), "unidentified-peer-") {
		t.Errorf("TCP peer source = %v, want an unidentified peer", source)
	}
	if resolveCalls != 0 {
		t.Errorf("Resolve called %d times for a TCP peer, want 0", resolveCalls)
	}
}

// TestCollectorOutlivesASplunkOutageTheVMDoesNot is the scenario the spool
// exists for: Splunk is down, the guest's events are acknowledged anyway --
// its own copy is gone -- the VM disappears, the gateway restarts, and only
// then does Splunk come back. Every event still arrives.
func TestCollectorOutlivesASplunkOutageTheVMDoesNot(t *testing.T) {
	hec := newFakeHEC(t)
	hec.set(always(hecBusy))
	spoolDir := t.TempDir()
	listener := tcpListener(t)
	collector := startTestCollector(t, hecOptions(hec, spoolDir, listener))

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	agent := newFakeAgent(t, conn)
	agent.handshake("boot-1")
	agent.sendEvent(1, "boot-1")
	agent.sendEvent(2, "boot-1")
	// The guest does not wait for Splunk.
	if acked := agent.acknowledged(); acked != 2 {
		t.Fatalf("collector acknowledged through %d while Splunk was down, want 2", acked)
	}
	_ = conn.Close() // the VM is deleted
	hec.waitForRequest(t)
	if err := collector.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	hec.set(nil)
	startTestCollector(t, hecOptions(hec, spoolDir, tcpListener(t)))
	accepted := hec.waitAccepted(t, 2)
	for i, event := range accepted {
		if got := sequenceOf(event); got != float64(i+1) {
			t.Fatalf("event %d has sequence %v, want %d", i, got, i+1)
		}
	}
}

func TestCollectorCloseDoesNotWaitForAnUnresponsiveSplunk(t *testing.T) {
	hec := newFakeHEC(t)
	release := hec.holdRequests()
	defer release()
	listener := tcpListener(t)
	collector := startTestCollector(t, hecOptions(hec, t.TempDir(), listener))

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	agent := newFakeAgent(t, conn)
	agent.handshake("boot-1")
	agent.sendEvent(1, "boot-1")
	if acked := agent.acknowledged(); acked != 1 {
		t.Fatalf("collector acknowledged through %d, want 1: the event is spooled", acked)
	}
	hec.waitForRequest(t)

	start := time.Now()
	if err := collector.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close() took %s with Splunk unresponsive, want it prompt", elapsed)
	}
}

func TestStartRejectsAnUnusableSpool(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	listener := tcpListener(t)
	defer func() { _ = listener.Close() }()
	if _, err := Start(hecOptions(newFakeHEC(t), filepath.Join(blocker, "spool"), listener)); err == nil {
		t.Fatal("Start() with a spool under a regular file succeeded, want an error")
	}
}

func TestStartRejectsMissingOutputs(t *testing.T) {
	listener := tcpListener(t)
	defer func() { _ = listener.Close() }()
	if _, err := Start(Options{Port: 9000, listener: listener}); err == nil {
		t.Fatal("Start() with no event output succeeded, want an error")
	}
}

func TestStartRejectsInvalidHECConfig(t *testing.T) {
	listener := tcpListener(t)
	defer func() { _ = listener.Close() }()
	logFile := filepath.Join(t.TempDir(), "sauron.jsonl")
	_, err := Start(Options{Port: 9000, EventLogFile: logFile, HEC: splunkhec.Config{Endpoint: "splunk.example.test"}, SpoolDir: t.TempDir(), SpoolMaxBytes: 1 << 20, listener: listener})
	if err == nil {
		t.Fatal("Start() with an invalid HEC endpoint succeeded, want an error")
	}
}

func TestStartRejectsAnUnwritableEventLog(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	listener := tcpListener(t)
	defer func() { _ = listener.Close() }()
	if _, err := Start(Options{Port: 9000, EventLogFile: filepath.Join(blocker, "sauron.jsonl"), listener: listener}); err == nil {
		t.Fatal("Start() with an event log under a regular file succeeded, want an error")
	}
}

func TestResolverAdaptsTheGatewayLookup(t *testing.T) {
	if resolver(nil) != nil {
		t.Fatal("resolver(nil) must stay nil so the collector falls back to its own mapping")
	}

	resolve := resolver(func(cid uint32) (VM, bool, error) {
		switch cid {
		case 3:
			return VM{Name: "alice-dev", UUID: "uuid-3", Owner: "alice"}, true, nil
		case 4:
			return VM{Name: "unowned"}, true, nil
		case 5:
			return VM{}, false, errors.New("libvirt is down")
		default:
			return VM{}, false, nil
		}
	})

	if vm, ok := resolve(3); !ok || vm.CID != 3 || vm.Name != "alice-dev" || vm.UUID != "uuid-3" || vm.Labels["owner"] != "alice" {
		t.Errorf("resolve(3) = %+v, %t; want alice-dev owned by alice", vm, ok)
	}
	if vm, ok := resolve(4); !ok || vm.Labels != nil {
		t.Errorf("resolve(4) = %+v, %t; want no labels for a VM without an owner", vm, ok)
	}
	if _, ok := resolve(5); ok {
		t.Error("resolve(5) succeeded although the lookup failed")
	}
	if _, ok := resolve(6); ok {
		t.Error("resolve(6) succeeded for a CID no VM holds")
	}
}

func TestNewLoggerWritesThroughTheLogPackage(t *testing.T) {
	var buffer bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previous)
		log.SetFlags(flags)
	})

	newLogger().Info("guest connected", "cid", 7)

	got := buffer.String()
	if !strings.Contains(got, `msg="guest connected"`) || !strings.Contains(got, "component=sauron") || !strings.Contains(got, "cid=7") {
		t.Fatalf("log output = %q, want the record with its attributes", got)
	}
	if strings.Contains(got, "time=") {
		t.Fatalf("log output = %q, want the log package's timestamp only", got)
	}
}
