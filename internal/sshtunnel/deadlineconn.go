package sshtunnel

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// NewReadDeadlineConn wraps a connection whose own deadline methods do not work
// — the SSH forwarded channel returns "deadline not supported", which is why the
// tunnel listener hands back connections with no-op deadlines — and provides
// working read deadlines on top of it.
//
// This is required by the dashboard's WebSocket consoles (serial and noVNC).
// net/http's connection Hijack, used by the WebSocket upgrade, aborts its
// pending background read by setting a read deadline in the past and waiting for
// the read to return; if SetReadDeadline is a no-op the background read never
// unblocks and Hijack blocks forever, so the upgrade never completes over the
// tunnel.
//
// A reader goroutine pumps the underlying connection so Read can both honor a
// deadline and, crucially, wake up when the deadline is changed from another
// goroutine (which is exactly what Hijack does). Write deadlines are not needed
// and remain no-ops; a dead tunnel is detected by the SSH keepalive.
func NewReadDeadlineConn(c net.Conn) net.Conn {
	dc := &deadlineConn{
		Conn:    c,
		data:    make(chan []byte),
		done:    make(chan struct{}),
		closed:  make(chan struct{}),
		dlReset: make(chan struct{}),
	}
	go dc.pump()
	return dc
}

type deadlineConn struct {
	net.Conn

	data      chan []byte   // chunks delivered by the pump goroutine
	done      chan struct{} // closed when the pump has exited; pumpErr is then set
	closed    chan struct{} // closed by Close to stop the pump
	closeOnce sync.Once
	pumpErr   error // written before done is closed; read only after done observed

	leftover []byte // bytes from a chunk that did not fit the caller's buffer; Read-only

	dlMu    sync.Mutex
	dl      time.Time
	dlReset chan struct{} // closed and replaced whenever the read deadline changes
}

func (c *deadlineConn) pump() {
	defer close(c.done)
	for {
		buf := make([]byte, 32*1024)
		n, err := c.Conn.Read(buf)
		if n > 0 {
			select {
			case c.data <- buf[:n]:
			case <-c.closed:
				return
			}
		}
		if err != nil {
			c.pumpErr = err
			return
		}
	}
}

func (c *deadlineConn) Read(p []byte) (int, error) {
	if n, ok := c.readLeftover(p); ok {
		return n, nil
	}
	for {
		n, retry, err := c.readOnce(p)
		if !retry {
			return n, err
		}
	}
}

// readLeftover serves bytes stashed from a previous chunk that did not fit the
// caller's buffer. It is only touched by Read, which is single-reader.
func (c *deadlineConn) readLeftover(p []byte) (int, bool) {
	if len(c.leftover) == 0 {
		return 0, false
	}
	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	if len(c.leftover) == 0 {
		c.leftover = nil
	}
	return n, true
}

// readOnce waits for one chunk, the current read deadline, or the connection
// ending. retry is true when the deadline changed mid-wait and the caller should
// re-evaluate against the new deadline.
func (c *deadlineConn) readOnce(p []byte) (n int, retry bool, err error) {
	c.dlMu.Lock()
	dl := c.dl
	reset := c.dlReset
	c.dlMu.Unlock()

	var timerCh <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, false, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		timerCh = timer.C
	}

	select {
	case b := <-c.data:
		n = copy(p, b)
		if n < len(b) {
			c.leftover = append([]byte(nil), b[n:]...)
		}
		return n, false, nil
	case <-c.closed:
		return 0, false, net.ErrClosed
	case <-c.done:
		if c.pumpErr != nil {
			return 0, false, c.pumpErr
		}
		return 0, false, io.EOF
	case <-timerCh:
		return 0, false, os.ErrDeadlineExceeded
	case <-reset:
		// The read deadline changed under us; re-evaluate against the new one.
		return 0, true, nil
	}
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.dlMu.Lock()
	c.dl = t
	close(c.dlReset)
	c.dlReset = make(chan struct{})
	c.dlMu.Unlock()
	return nil
}

// SetWriteDeadline is a no-op: writes go straight to the SSH channel and a stuck
// tunnel is caught by the keepalive, matching the behavior of the unwrapped
// channel connection.
func (c *deadlineConn) SetWriteDeadline(time.Time) error { return nil }

// SetDeadline applies the read deadline; the write side stays unbounded as in
// SetWriteDeadline.
func (c *deadlineConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *deadlineConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
