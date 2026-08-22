package gateway

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
)

// newLimitTestSettings builds settings with the global and per-source
// connection caps set explicitly so each limiter can be exercised in
// isolation.
func newLimitTestSettings(t *testing.T, maxConns, perSource int) *config.SettingsType {
	t.Helper()
	settings := config.NewSettingType(false)
	if err := settings.OverwriteForTestInt(config.MAX_CONCURRENT_CONNECTIONS, maxConns); err != nil {
		t.Fatalf("set max concurrent connections: %v", err)
	}
	if err := settings.OverwriteForTestInt(config.MAX_CONNECTIONS_PER_SOURCE, perSource); err != nil {
		t.Fatalf("set max connections per source: %v", err)
	}
	return settings
}

// TestLimitListenerConnectionsDisabled verifies that non-positive caps leave
// the listener untouched (unbounded behavior preserved).
func TestLimitListenerConnectionsDisabled(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	if got := limitListenerConnections(base, newLimitTestSettings(t, 0, 0)); got != base {
		t.Fatalf("expected unwrapped listener when caps <= 0, got %T", got)
	}
	if got := limitListenerConnections(base, newLimitTestSettings(t, -1, -1)); got != base {
		t.Fatalf("expected unwrapped listener for negative caps, got %T", got)
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

// startLimitTestAccepts runs Accept in the background for the whole test, as
// in serveListener, delivering accepted connections on the returned channel.
func startLimitTestAccepts(limited net.Listener) <-chan net.Conn {
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := limited.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	return accepted
}

// waitLimitTestAccept waits for the next accepted connection, failing the test
// with msg if none arrives in time.
func waitLimitTestAccept(t *testing.T, accepted <-chan net.Conn, msg string) net.Conn {
	t.Helper()
	select {
	case c := <-accepted:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal(msg)
		return nil
	}
}

// expectLimitTestRejected asserts that the listener closed conn instead of
// delivering it to Accept, so the client's read fails fast rather than timing
// out.
func expectLimitTestRejected(t *testing.T, conn net.Conn, accepted <-chan net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil || os.IsTimeout(err) {
		t.Fatalf("expected the over-cap connection to be closed promptly, got %v", err)
	}
	select {
	case c := <-accepted:
		t.Fatalf("over-cap connection was delivered to Accept: %v", c.RemoteAddr())
	default:
	}
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

	limited := limitListenerConnections(base, newLimitTestSettings(t, 1, 0))
	defer func() { _ = limited.Close() }()

	addr := base.Addr().String()
	accepted := startLimitTestAccepts(limited)

	// First connection takes the only slot.
	dialLimitTestConn(t, addr)
	first := waitLimitTestAccept(t, accepted, "first connection was not accepted")

	// Over the cap: the connection is closed instead of accepted.
	expectLimitTestRejected(t, dialLimitTestConn(t, addr), accepted)

	// Closing the accepted connection frees the slot for the next client.
	_ = first.Close()
	dialLimitTestConn(t, addr)
	_ = waitLimitTestAccept(t, accepted, "connection was not accepted after the slot was freed")
}

// stringAddr is a net.Addr whose String() is not host:port, to exercise the
// perSourceLimitKey fallback for unparseable addresses.
type stringAddr string

func (a stringAddr) Network() string { return "test" }
func (a stringAddr) String() string  { return string(a) }

// TestPerSourceLimitKey verifies the bucketing of remote addresses: per IPv4
// address, per /64 for IPv6, raw-string fallback for anything unparseable.
func TestPerSourceLimitKey(t *testing.T) {
	cases := []struct {
		name   string
		remote net.Addr
		want   string
	}{
		{"nil", nil, "unknown"},
		{"ipv4", &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}, "192.0.2.10"},
		{"ipv4 mapped", &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.10"), Port: 80}, "192.0.2.10"},
		{"ipv6", &net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:3:4:5:6"), Port: 443}, "2001:db8:1:2::/64"},
		{"unparseable", stringAddr("not-an-address"), "not-an-address"},
	}
	for _, tc := range cases {
		if got := perSourceLimitKey(tc.remote); got != tc.want {
			t.Errorf("%s: perSourceLimitKey(%v) = %q, want %q", tc.name, tc.remote, got, tc.want)
		}
	}

	// Two addresses inside the same /64 share a bucket, so rotating through a
	// delegated IPv6 prefix does not evade the cap.
	a := perSourceLimitKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2::1"), Port: 1})
	b := perSourceLimitKey(&net.TCPAddr{IP: net.ParseIP("2001:db8:1:2:ffff::1"), Port: 2})
	if a != b {
		t.Errorf("addresses in the same /64 got different buckets: %q vs %q", a, b)
	}
}

// dialLimitTestConnFrom dials addr with an explicit local source IP so tests
// can present distinct sources to the per-source limiter.
func dialLimitTestConnFrom(t *testing.T, localIP, addr string) net.Conn {
	t.Helper()
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s from %s: %v", addr, localIP, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestPerSourceLimitListenerFailFast verifies that one source is capped
// independently of others: over-cap connections from a saturated source are
// closed immediately, a different source still gets through, and closing a
// connection frees its source's slot.
func TestPerSourceLimitListenerFailFast(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = base.Close() }()

	// Global cap disabled: only the per-source cap (1) is under test.
	limited := limitListenerConnections(base, newLimitTestSettings(t, 0, 1))
	defer func() { _ = limited.Close() }()

	addr := base.Addr().String()
	accepted := startLimitTestAccepts(limited)

	// First connection takes 127.0.0.1's only slot.
	dialLimitTestConnFrom(t, "127.0.0.1", addr)
	first := waitLimitTestAccept(t, accepted, "first connection was not accepted")

	// Second connection from the same source is closed instead of accepted.
	expectLimitTestRejected(t, dialLimitTestConnFrom(t, "127.0.0.1", addr), accepted)

	// A different source address is unaffected by 127.0.0.1's saturation.
	dialLimitTestConnFrom(t, "127.0.0.2", addr)
	_ = waitLimitTestAccept(t, accepted, "connection from a second source was not accepted")

	// Closing the first connection frees 127.0.0.1's slot.
	_ = first.Close()
	dialLimitTestConnFrom(t, "127.0.0.1", addr)
	_ = waitLimitTestAccept(t, accepted, "connection was not accepted after the source's slot was freed")
}
