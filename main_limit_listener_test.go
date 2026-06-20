package main

import (
	"devboxgateway/internal/config"
	"net"
	"testing"
	"time"
)

// newLimitTestSettings builds settings with MAX_CONCURRENT_CONNECTIONS set to
// max so the limiter helper can be exercised in isolation.
func newLimitTestSettings(t *testing.T, max int) *config.SettingsType {
	t.Helper()
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestInt(config.MAX_CONCURRENT_CONNECTIONS, max); err != nil {
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

// TestLimitListenerConnectionsCapsConcurrency verifies that Accept blocks once
// the cap is reached and resumes once an accepted connection is closed.
func TestLimitListenerConnectionsCapsConcurrency(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	limited := limitListenerConnections(base, newLimitTestSettings(t, 1))
	defer func() { _ = limited.Close() }()

	addr := base.Addr().String()

	// First connection takes the only slot.
	dial1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer func() { _ = dial1.Close() }()
	accepted1, err := limited.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}

	// Second connection cannot be accepted until the first is closed.
	dial2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer func() { _ = dial2.Close() }()

	accept2 := make(chan net.Conn, 1)
	go func() {
		c, acceptErr := limited.Accept()
		if acceptErr != nil {
			accept2 <- nil
			return
		}
		accept2 <- c
	}()

	select {
	case <-accept2:
		t.Fatal("second Accept returned while the connection cap was reached")
	case <-time.After(200 * time.Millisecond):
	}

	// Releasing the slot lets the blocked Accept proceed.
	_ = accepted1.Close()

	select {
	case c := <-accept2:
		if c == nil {
			t.Fatal("second Accept failed after slot freed")
		}
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("second Accept did not return after the slot was freed")
	}
}
