package main

import (
	"devboxgateway/internal/config"
	"net"
	"os"
	"testing"
	"time"
)

// newLimitTestSettings builds settings with MAX_CONCURRENT_CONNECTIONS set to
// max so the limiter helper can be exercised in isolation.
func newLimitTestSettings(t *testing.T, maxConns int) *config.SettingsType {
	t.Helper()
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestInt(config.MAX_CONCURRENT_CONNECTIONS, maxConns); err != nil {
		t.Fatalf("set max concurrent connections: %v", err)
	}
	return settings
}

// TestLimitListenerConnectionsDisabled verifies that a non-positive cap leaves
// the listener untouched (unbounded behavior preserved).
func TestLimitListenerConnectionsDisabled(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	if got := limitListenerConnections(base, newLimitTestSettings(t, 0)); got != base {
		t.Fatalf("expected unwrapped listener when cap <= 0, got %T", got)
	}
	if got := limitListenerConnections(base, newLimitTestSettings(t, -1)); got != base {
		t.Fatalf("expected unwrapped listener for negative cap, got %T", got)
	}
}

// dialLimitTestConn dials the limited listener under test and registers
// cleanup for the client side of the connection.
func dialLimitTestConn(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestLimitListenerConnectionsFailFastAtCap verifies that connections over the
// cap are accepted and immediately closed — clients fail fast instead of
// hanging unserved in the accept backlog — and that closing an accepted
// connection frees its slot for the next client.
func TestLimitListenerConnectionsFailFastAtCap(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	limited := limitListenerConnections(base, newLimitTestSettings(t, 1))
	defer func() { _ = limited.Close() }()

	addr := base.Addr().String()

	// Accept runs in the background for the whole test, as in serveListener.
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, acceptErr := limited.Accept()
			if acceptErr != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()

	// First connection takes the only slot.
	dialLimitTestConn(t, addr)
	var first net.Conn
	select {
	case first = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("first connection was not accepted")
	}

	// Over the cap: the listener closes the connection instead of delivering
	// it to Accept, so the client's read fails fast rather than timing out.
	dial2 := dialLimitTestConn(t, addr)
	if err := dial2.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := dial2.Read(buf); err == nil || os.IsTimeout(err) {
		t.Fatalf("expected the over-cap connection to be closed promptly, got %v", err)
	}
	select {
	case c := <-accepted:
		t.Fatalf("over-cap connection was delivered to Accept: %v", c.RemoteAddr())
	default:
	}

	// Closing the accepted connection frees the slot for the next client.
	_ = first.Close()
	dialLimitTestConn(t, addr)
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not accepted after the slot was freed")
	}
}
