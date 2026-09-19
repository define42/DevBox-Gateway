package protocol

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// testTimeout bounds every blocking operation in these tests so that a
// regression shows up as a failure rather than as a hung test binary.
const testTimeout = 5 * time.Second

func TestConnFullExchange(t *testing.T) {
	agentSide, hostSide := net.Pipe()
	agent := NewConn(agentSide, DefaultMaxPayloadSize)
	host := NewConn(hostSide, DefaultMaxPayloadSize)
	defer agent.Close()
	defer host.Close()

	hostErr := make(chan error, 1)
	go func() { hostErr <- runCollector(host) }()

	// HELLO -> READY. The agent introduces itself; everything it says about
	// itself is informational, which is why the host answers with its own view
	// of the stream position.
	hello := &Hello{
		ProtocolVersion: Version,
		AgentVersion:    "sauronagent/1.0.0",
		Hostname:        "transfer-vm-03",
		BootID:          "2f1c9a7e-3b5d-4a1e-9c6f-8d2b0e4a7c31",
		MachineID:       "9d4a1f0c8b7e4d2a91f3c6b5a8e07d14",
		Kernel:          "6.12.9-200.fc41.x86_64",
		FirstSequence:   8400,
	}
	if err := agent.Send(MsgHello, 0, hello, testTimeout); err != nil {
		t.Fatalf("send HELLO: %v", err)
	}

	f, err := agent.Receive(testTimeout)
	if err != nil {
		t.Fatalf("receive READY: %v", err)
	}
	if f.Type != MsgReady {
		t.Fatalf("got %s, want READY", f.Type)
	}
	var ready Ready
	if err := DecodePayload(f, &ready); err != nil {
		t.Fatalf("decode READY: %v", err)
	}
	if ready.ProtocolVersion != Version || ready.ResumeFrom != 8420 {
		t.Fatalf("READY = %+v", ready)
	}

	// EVENT -> ACK.
	ev := sampleEvent()
	if err := agent.Send(MsgEvent, ev.Sequence, &EventMessage{Event: ev}, testTimeout); err != nil {
		t.Fatalf("send EVENT: %v", err)
	}
	f, err = agent.Receive(testTimeout)
	if err != nil {
		t.Fatalf("receive ACK: %v", err)
	}
	if f.Type != MsgAck {
		t.Fatalf("got %s, want ACK", f.Type)
	}
	var ack Ack
	if err := DecodePayload(f, &ack); err != nil {
		t.Fatalf("decode ACK: %v", err)
	}
	if ack.Sequence != ev.Sequence {
		t.Fatalf("ACK sequence = %d, want %d", ack.Sequence, ev.Sequence)
	}
	if f.Sequence != ev.Sequence {
		t.Fatalf("ACK frame sequence = %d, want %d", f.Sequence, ev.Sequence)
	}

	// PING -> PONG.
	ping := &Ping{UptimeSeconds: 86_400, EventsReceived: 1_204_331, EventsSent: 1_204_200, AuditEnabled: true, QueueDepth: 17}
	if err := agent.Send(MsgPing, 1, ping, testTimeout); err != nil {
		t.Fatalf("send PING: %v", err)
	}
	f, err = agent.Receive(testTimeout)
	if err != nil {
		t.Fatalf("receive PONG: %v", err)
	}
	if f.Type != MsgPong {
		t.Fatalf("got %s, want PONG", f.Type)
	}
	var pong Pong
	if err := DecodePayload(f, &pong); err != nil {
		t.Fatalf("decode PONG: %v", err)
	}
	if pong.EchoUptime != ping.UptimeSeconds {
		t.Fatalf("PONG echo = %d, want %d", pong.EchoUptime, ping.UptimeSeconds)
	}

	// SHUTDOWN ends the session in the orderly way, so the collector can tell
	// a planned stop from a guest that was silenced.
	if err := agent.Send(MsgShutdown, 2, &Shutdown{Reason: "systemd stop", LastSequence: ev.Sequence}, testTimeout); err != nil {
		t.Fatalf("send SHUTDOWN: %v", err)
	}

	select {
	case err := <-hostErr:
		if err != nil {
			t.Fatalf("collector: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("collector did not finish")
	}
}

// runCollector plays the host side of one session: negotiate, acknowledge
// events, answer heartbeats, stop on SHUTDOWN or EOF.
func runCollector(c *Conn) error {
	var lastEvent uint64
	for {
		f, err := c.Receive(testTimeout)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch f.Type {
		case MsgHello:
			var hello Hello
			if err := DecodePayload(f, &hello); err != nil {
				return err
			}
			if hello.Hostname != "transfer-vm-03" {
				return errors.New("unexpected hostname")
			}
			ready := &Ready{
				ProtocolVersion: Version,
				HostVersion:     "sauronhost/1.0.0",
				SessionID:       "hypervisor-01/cid-102",
				ResumeFrom:      8420,
				MaxPayloadSize:  DefaultMaxPayloadSize,
			}
			if err := c.Send(MsgReady, 0, ready, testTimeout); err != nil {
				return err
			}
		case MsgEvent:
			var msg EventMessage
			if err := DecodePayload(f, &msg); err != nil {
				return err
			}
			if msg.Event == nil || msg.Event.Sequence != f.Sequence {
				return errors.New("event sequence disagrees with the frame header")
			}
			lastEvent = f.Sequence
			if err := c.Send(MsgAck, lastEvent, &Ack{Sequence: lastEvent}, testTimeout); err != nil {
				return err
			}
		case MsgPing:
			var ping Ping
			if err := DecodePayload(f, &ping); err != nil {
				return err
			}
			pong := &Pong{EchoUptime: ping.UptimeSeconds, UnixNano: time.Now().UnixNano()}
			if err := c.Send(MsgPong, f.Sequence, pong, testTimeout); err != nil {
				return err
			}
		case MsgShutdown:
			var sd Shutdown
			if err := DecodePayload(f, &sd); err != nil {
				return err
			}
			if sd.LastSequence != lastEvent {
				return errors.New("shutdown reports a sequence the host never saw")
			}
			// An announced stop ends the session; the collector does not wait
			// for the close that follows it.
			return nil
		default:
			return errors.New("unexpected message type " + f.Type.String())
		}
	}
}

// readSignalConn reports when a read has started, so a test can close the peer
// at a point where the outcome is not a race.
type readSignalConn struct {
	net.Conn
	once    sync.Once
	reading chan struct{}
}

func (c *readSignalConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}

func TestConnReceiveEOFOnPeerClose(t *testing.T) {
	// A guest that disconnects between frames must surface as io.EOF and not
	// as a protocol violation: the collector reconnects rather than reporting
	// the guest for misbehaving.
	local, remote := net.Pipe()
	signal := &readSignalConn{Conn: local, reading: make(chan struct{})}
	c := NewConn(signal, DefaultMaxPayloadSize)
	defer c.Close()

	result := make(chan error, 1)
	go func() {
		_, err := c.Receive(testTimeout)
		result <- err
	}()

	<-signal.reading
	remote.Close()

	select {
	case err := <-result:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want io.EOF", err)
		}
		if IsProtocolError(err) {
			t.Errorf("IsProtocolError(%v) = true; a disconnect is not a violation", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Receive did not notice the peer closing")
	}
}

func TestConnReceiveDeadline(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := NewConn(local, DefaultMaxPayloadSize)
	defer c.Close()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := c.Receive(50 * time.Millisecond)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("err = %v, want a net.Error reporting a timeout", err)
		}
		if IsProtocolError(err) {
			t.Errorf("IsProtocolError(%v) = true; a quiet peer is not a malformed one", err)
		}
		if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
			t.Errorf("Receive returned after %v, before its deadline", elapsed)
		}
	case <-time.After(testTimeout):
		t.Fatal("Receive hung instead of honouring its deadline")
	}
}

func TestConnZeroTimeoutClearsPreviousDeadline(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := NewConn(local, DefaultMaxPayloadSize)
	defer c.Close()

	// A deadline left over from an earlier operation would make this
	// "wait indefinitely" receive fail immediately.
	if _, err := c.Receive(20 * time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("first receive err = %v, want os.ErrDeadlineExceeded", err)
	}

	go func() {
		time.Sleep(60 * time.Millisecond)
		enc := NewEncoder(remote, DefaultMaxPayloadSize)
		_ = enc.WriteMessage(MsgAck, 8421, &Ack{Sequence: 8421})
	}()

	f, err := c.Receive(0)
	if err != nil {
		t.Fatalf("receive with no deadline: %v", err)
	}
	if f.Type != MsgAck {
		t.Fatalf("got %s, want ACK", f.Type)
	}
}

func TestConnSendDeadlineAbandonsTornStream(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := NewConn(local, DefaultMaxPayloadSize)
	defer c.Close()

	// Nobody is reading the pipe, so the write deadline fires mid-frame.
	err := c.Send(MsgEvent, 1, &EventMessage{Event: sampleEvent()}, 50*time.Millisecond)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}

	// Sending again would append a frame to a half-written one, which the peer
	// would read as payload. The connection must be abandoned instead.
	again := c.Send(MsgPing, 2, &Ping{}, testTimeout)
	if !errors.Is(again, os.ErrDeadlineExceeded) {
		t.Fatalf("second send err = %v, want it to still report the failed write", again)
	}
}

func TestConnSendIsSerialized(t *testing.T) {
	// The agent's heartbeat goroutine and its event sender share one
	// connection. Two frames interleaved on the wire would desynchronize the
	// host's parser permanently, so Send holds a lock for the whole frame.
	agentSide, hostSide := net.Pipe()
	agent := NewConn(agentSide, DefaultMaxPayloadSize)
	defer agent.Close()
	defer hostSide.Close()

	const perGoroutine = 50

	type received struct {
		typ MessageType
		seq uint64
	}
	got := make(chan received, 2*perGoroutine)
	readErr := make(chan error, 1)
	go func() {
		dec := NewDecoder(hostSide, DefaultMaxPayloadSize)
		for i := 0; i < 2*perGoroutine; i++ {
			f, err := dec.ReadFrame()
			if err != nil {
				readErr <- err
				return
			}
			switch f.Type {
			case MsgEvent:
				var msg EventMessage
				if err := DecodePayload(f, &msg); err != nil {
					readErr <- err
					return
				}
				if msg.Event == nil || msg.Event.Sequence != f.Sequence {
					readErr <- errors.New("interleaved frame: event payload does not match its header")
					return
				}
			case MsgPing:
				var ping Ping
				if err := DecodePayload(f, &ping); err != nil {
					readErr <- err
					return
				}
				if ping.UptimeSeconds != f.Sequence {
					readErr <- errors.New("interleaved frame: ping payload does not match its header")
					return
				}
			default:
				readErr <- errors.New("unexpected type " + f.Type.String())
				return
			}
			got <- received{typ: f.Type, seq: f.Sequence}
		}
		readErr <- nil
	}()

	var wg sync.WaitGroup
	sendErr := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 1; i <= perGoroutine; i++ {
			ev := sampleEvent()
			ev.Sequence = uint64(i)
			if err := agent.Send(MsgEvent, ev.Sequence, &EventMessage{Event: ev}, testTimeout); err != nil {
				sendErr <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 1; i <= perGoroutine; i++ {
			if err := agent.Send(MsgPing, uint64(i), &Ping{UptimeSeconds: uint64(i), AuditEnabled: true}, testTimeout); err != nil {
				sendErr <- err
				return
			}
		}
	}()
	wg.Wait()
	close(sendErr)
	for err := range sendErr {
		t.Fatalf("send: %v", err)
	}

	select {
	case err := <-readErr:
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("reader did not finish")
	}

	close(got)
	counts := map[MessageType]int{}
	for r := range got {
		counts[r.typ]++
	}
	if counts[MsgEvent] != perGoroutine || counts[MsgPing] != perGoroutine {
		t.Fatalf("received %d events and %d pings, want %d of each", counts[MsgEvent], counts[MsgPing], perGoroutine)
	}
}

func TestConnCloseIsIdempotent(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := NewConn(local, DefaultMaxPayloadSize)

	first := c.Close()
	if first != nil {
		t.Fatalf("first Close: %v", first)
	}
	for i := 0; i < 3; i++ {
		if err := c.Close(); err != first {
			t.Fatalf("Close %d returned %v, want %v", i+2, err, first)
		}
	}
	if _, err := c.Receive(testTimeout); err == nil {
		t.Fatal("Receive on a closed connection succeeded")
	}
}

func TestConnRejectsMalformedPeer(t *testing.T) {
	// What the host sees from a compromised guest that stops speaking the
	// protocol: the error must classify as a violation so the collector closes
	// the connection and reports sauron.protocol.violation.
	local, remote := net.Pipe()
	c := NewConn(local, DefaultMaxPayloadSize)
	defer c.Close()

	go func() {
		defer remote.Close()
		_, _ = remote.Write([]byte("SAUR\x02\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02{}"))
	}()

	_, err := c.Receive(testTimeout)
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("err = %v, want ErrBadVersion", err)
	}
	if !IsProtocolError(err) {
		t.Errorf("IsProtocolError(%v) = false, want true", err)
	}
}

func TestConnNetConn(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := NewConn(local, DefaultMaxPayloadSize)
	defer c.Close()

	// The host identifies a guest from the connection itself, never from what
	// the guest says, so the underlying conn must remain reachable.
	if c.NetConn() != local {
		t.Fatal("NetConn did not return the wrapped connection")
	}
}
