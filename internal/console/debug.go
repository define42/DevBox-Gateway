package console

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
)

// debugLogging gates verbose per-connection serial/VNC console diagnostics. It is
// enabled from main when DEBUG_CONNECTIONS is set so the noisy step-by-step and
// byte-count logging stays off in normal operation.
var debugLogging atomic.Bool //nolint:gochecknoglobals // package-level debug toggle set once at startup

// SetDebugLogging toggles verbose serial/VNC console debug logging.
func SetDebugLogging(enabled bool) {
	debugLogging.Store(enabled)
}

func debugf(format string, args ...any) {
	if debugLogging.Load() {
		log.Printf("console-debug: "+format, args...) // #nosec G706 -- DEBUG_CONNECTIONS-only diagnostics; call sites %q-escape request-derived values
	}
}

// previewBytes returns a short, printable preview of a stream's first bytes for
// debug logging (e.g. the "RFB 003.008" VNC greeting), capped so the log stays
// readable and with non-printable bytes shown as '.'.
func previewBytes(b []byte) string {
	const maxPreview = 32
	if len(b) > maxPreview {
		b = b[:maxPreview]
	}
	out := make([]byte, len(b))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			out[i] = '.'
			continue
		}
		out[i] = c
	}
	return string(out)
}

// debugUpgradeWriter logs around Hijack and wraps the hijacked conn so the first
// post-upgrade write (the 101 response) is traced start-to-finish.
type debugUpgradeWriter struct {
	http.ResponseWriter

	channel string
	name    string
}

func (w *debugUpgradeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *debugUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("debugUpgradeWriter: underlying response writer is not an http.Hijacker")
	}
	debugf("%s: hijacking connection for vm %q", w.channel, w.name)
	conn, brw, err := hj.Hijack()
	debugf("%s: hijack returned for vm %q (err=%v)", w.channel, w.name, err)
	if err != nil {
		return conn, brw, err
	}
	return &debugConn{Conn: conn, channel: w.channel, name: w.name}, brw, nil
}

// debugConn logs the start and completion of the first write on a hijacked
// connection. If the "starting" line appears without the "returned" line, the
// write to the SSH-channel-backed conn is blocking.
type debugConn struct {
	net.Conn

	channel string
	name    string
	logged  atomic.Bool
}

func (c *debugConn) Write(p []byte) (int, error) {
	first := c.logged.CompareAndSwap(false, true)
	if first {
		debugf("%s: first post-upgrade write of %d bytes for vm %q starting (101 handshake)", c.channel, len(p), c.name)
	}
	n, err := c.Conn.Write(p)
	if first {
		debugf("%s: first post-upgrade write returned for vm %q (n=%d err=%v)", c.channel, c.name, n, err)
	}
	return n, err
}
