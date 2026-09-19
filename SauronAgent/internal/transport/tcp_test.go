package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// helloFrame is a realistic first thing the agent writes: the SAUR magic, a
// version byte and a HELLO type byte. The transport must move bytes exactly,
// including zero bytes, since the framing layer depends on it.
var helloFrame = []byte{'S', 'A', 'U', 'R', 0x01, 0x01, 0x00, 0x00}

func TestTCPRoundTrip(t *testing.T) {
	l, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer l.Close()

	if got := l.Addr().Network(); got != "tcp" {
		t.Errorf("Addr().Network() = %q, want %q", got, "tcp")
	}

	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		accepts <- accepted{conn: c, err: err}
	}()

	d := NewTCPDialer(l.Addr().String())
	if got := d.String(); !strings.HasPrefix(got, "tcp:") || !strings.Contains(got, l.Addr().String()) {
		t.Errorf("String() = %q, want tcp: prefix and the address", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	a := <-accepts
	if a.err != nil {
		t.Fatalf("Accept: %v", a.err)
	}
	defer a.conn.Close()

	// TCP carries no hypervisor-assigned identity, so neither end may be
	// mistaken for an identified VM.
	if cid, ok := PeerCID(client); ok {
		t.Errorf("PeerCID(client) = (%d, true), want ok=false for a TCP conn", cid)
	}
	if cid, ok := PeerCID(a.conn); ok {
		t.Errorf("PeerCID(server) = (%d, true), want ok=false for a TCP conn", cid)
	}

	if _, err := client.Write(helloFrame); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(helloFrame))
	if err := a.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(a.conn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != string(helloFrame) {
		t.Errorf("server read %v, want %v", got, helloFrame)
	}

	// And back, because ACKs travel the other way.
	ack := []byte{'S', 'A', 'U', 'R', 0x01, 0x04, 0x00, 0x00}
	if _, err := a.conn.Write(ack); err != nil {
		t.Fatalf("server write: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got = got[:len(ack)]
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(got) != string(ack) {
		t.Errorf("client read %v, want %v", got, ack)
	}
}

func TestTCPDialContextCanceled(t *testing.T) {
	l, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	conn, err := NewTCPDialer(l.Addr().String()).Dial(ctx)
	if err == nil {
		conn.Close()
		t.Fatal("Dial with a cancelled context returned a connection, want error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Dial error = %v, want it to wrap context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Dial took %v with an already-cancelled context, want an immediate return", elapsed)
	}
}

func TestTCPDialNoListener(t *testing.T) {
	// Bind and immediately release a port, so nothing is listening on an
	// address that is certainly local and reachable.
	l, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := NewTCPDialer(addr).Dial(ctx)
	if err == nil {
		conn.Close()
		t.Fatal("Dial to a closed port succeeded, want error")
	}
	if !strings.Contains(err.Error(), addr) {
		t.Errorf("Dial error = %v, want it to name the destination %s", err, addr)
	}
}

func TestListenTCPErrors(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "not a port", address: "127.0.0.1:not-a-port"},
		{name: "port out of range", address: "127.0.0.1:99999"},
		{name: "unassignable address", address: "192.0.2.1:9000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := ListenTCP(tt.address)
			if err == nil {
				l.Close()
				t.Fatalf("ListenTCP(%q) succeeded, want error", tt.address)
			}
			if l != nil {
				t.Errorf("ListenTCP(%q) returned a non-nil Listener with an error", tt.address)
			}
			if !strings.Contains(err.Error(), tt.address) {
				t.Errorf("error = %v, want it to name the address %q", err, tt.address)
			}
		})
	}
}

func TestTCPAcceptAfterClose(t *testing.T) {
	l, err := ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	conn, err := l.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("Accept on a closed listener succeeded, want error")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("Accept error = %v, want net.ErrClosed", err)
	}
}
