package sshtunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// noDeadlineConn embeds a net.Conn but makes its deadline methods no-ops, so it
// reproduces the SSH forwarded channel's behavior (deadlines unsupported) on top
// of an ordinary pipe for testing.
type noDeadlineConn struct {
	net.Conn
}

func (noDeadlineConn) SetDeadline(time.Time) error      { return nil }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return nil }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

func newTestDeadlineConn(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	dc := NewReadDeadlineConn(noDeadlineConn{Conn: s})
	t.Cleanup(func() {
		_ = dc.Close()
		_ = c.Close()
	})
	return c, dc
}

func TestDeadlineConnReadsData(t *testing.T) {
	client, server := newTestDeadlineConn(t)

	go func() { _, _ = client.Write([]byte("hello world")) }()

	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if got := string(buf[:n]); got != "hello world" {
		t.Fatalf("expected %q, got %q", "hello world", got)
	}
}

func TestDeadlineConnReadTimesOut(t *testing.T) {
	_, server := newTestDeadlineConn(t)

	if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf := make([]byte, 64)
	_, err := server.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

// TestDeadlineConnAbortsBlockedRead reproduces what net/http's Hijack does: a
// Read is blocked with no data available, and another goroutine sets a past read
// deadline to abort it. Without working deadlines this is the hang that wedged
// the WebSocket upgrade over the tunnel.
func TestDeadlineConnAbortsBlockedRead(t *testing.T) {
	_, server := newTestDeadlineConn(t)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := server.Read(buf)
		errCh <- err
	}()

	// Let the Read block, then abort it the way abortPendingRead does.
	time.Sleep(20 * time.Millisecond)
	if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline exceeded, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Read was not aborted by setting a past deadline")
	}
}

// TestDeadlineConnReadsAfterClearedDeadline verifies a connection is reusable
// after the abort: the deadline is reset to zero and reads work again, mirroring
// how Hijack proceeds once the background read has been aborted.
func TestDeadlineConnReadsAfterClearedDeadline(t *testing.T) {
	client, server := newTestDeadlineConn(t)

	if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := server.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}

	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline: %v", err)
	}
	go func() { _, _ = client.Write([]byte("after-clear")) }()

	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read after clearing deadline: %v", err)
	}
	if got := string(buf[:n]); got != "after-clear" {
		t.Fatalf("expected %q, got %q", "after-clear", got)
	}
}

func TestDeadlineConnCloseUnblocksRead(t *testing.T) {
	_, server := newTestDeadlineConn(t)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, err := server.Read(buf)
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	_ = server.Close()

	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected a close/EOF error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return after Close")
	}
}

// chunkedLargeWrite ensures a chunk larger than the caller's buffer is delivered
// across multiple Reads without loss (the leftover path).
func TestDeadlineConnLeftover(t *testing.T) {
	client, server := newTestDeadlineConn(t)

	payload := "abcdefghij"
	go func() { _, _ = client.Write([]byte(payload)) }()

	var got []byte
	buf := make([]byte, 4)
	for len(got) < len(payload) {
		n, err := server.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("Read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != payload {
		t.Fatalf("expected %q, got %q", payload, string(got))
	}
}
