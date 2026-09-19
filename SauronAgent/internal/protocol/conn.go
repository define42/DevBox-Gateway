package protocol

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Conn couples an Encoder and a Decoder to one net.Conn and applies a deadline
// to each operation.
//
// Send is safe for use from several goroutines -- the agent's heartbeat runs
// independently of its event sender, and two frames interleaved on the wire
// would desynchronize the peer's parser for good. Receive is not: it returns a
// payload aliasing the Decoder's buffer, so a second concurrent reader would
// both race on that buffer and hand the first reader's payload away. One
// receive loop per connection.
type Conn struct {
	c   net.Conn
	dec *Decoder

	mu  sync.Mutex // guards enc, torn and the write deadline
	enc *Encoder
	// torn records the first write failure. A failed write may have left part
	// of a frame on the wire, after which every later frame would be read by
	// the peer as the continuation of that payload, so the connection is
	// refused rather than quietly corrupting the stream.
	torn error

	closeOnce sync.Once
	closeErr  error
}

// NewConn wraps c. maxPayload bounds both directions; 0 selects
// DefaultMaxPayloadSize and values above MaxPayloadCeiling are clamped.
func NewConn(c net.Conn, maxPayload uint32) *Conn {
	return &Conn{
		c:   c,
		enc: NewEncoder(c, maxPayload),
		dec: NewDecoder(c, maxPayload),
	}
}

// Send encodes v as the payload of one frame and writes it.
//
// timeout bounds the write; 0 means no deadline. Once a write has failed the
// connection is considered torn and every later Send fails with that original
// error, because a partially written frame cannot be recovered from by
// retrying -- the caller must close and reconnect.
func (c *Conn) Send(t MessageType, seq uint64, v any, timeout time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.torn != nil {
		return fmt.Errorf("protocol: connection abandoned after a failed write: %w", c.torn)
	}
	if err := c.c.SetWriteDeadline(deadline(timeout)); err != nil {
		// An unenforceable deadline would make a stalled peer look like a
		// healthy one, so it is reported rather than ignored.
		return fmt.Errorf("protocol: set write deadline: %w", err)
	}

	if err := c.enc.WriteMessage(t, seq, v); err != nil {
		// Only a failure of the underlying writer can have torn a frame; an
		// oversized or unencodable payload is caught before any byte moves.
		var we *writeError
		if errors.As(err, &we) {
			c.torn = err
		}
		return err
	}
	return nil
}

// Receive reads the next frame.
//
// timeout bounds the read; 0 means no deadline, which is what a host collector
// wants while it waits for a quiet guest's next heartbeat.
//
// THE RETURNED FRAME'S PAYLOAD ALIASES THE INTERNAL DECODER BUFFER AND IS ONLY
// VALID UNTIL THE NEXT CALL TO Receive. Decode it, or copy it, before reading
// again. A clean close returns io.EOF unwrapped; use IsProtocolError to tell a
// malformed peer from a broken connection.
func (c *Conn) Receive(timeout time.Duration) (*Frame, error) {
	if err := c.c.SetReadDeadline(deadline(timeout)); err != nil {
		return nil, fmt.Errorf("protocol: set read deadline: %w", err)
	}
	return c.dec.ReadFrame()
}

// NetConn returns the underlying connection, for peer identification --
// transport.PeerCID is the only authoritative identity in the system -- and
// for address strings in logs. Reading or writing it directly corrupts the
// framing.
func (c *Conn) NetConn() net.Conn { return c.c }

// Close closes the underlying connection. It is idempotent: repeated calls
// return the result of the first, so a deferred Close and an explicit one on
// an error path do not race or report a spurious "use of closed connection".
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.c.Close()
	})
	return c.closeErr
}

// deadline converts a per-operation timeout into an absolute deadline. The
// zero time clears any deadline left by a previous operation, so a timeout of
// 0 really means "no deadline" and not "whatever the last call set".
func deadline(timeout time.Duration) time.Time {
	if timeout <= 0 {
		return time.Time{}
	}
	return time.Now().Add(timeout)
}
