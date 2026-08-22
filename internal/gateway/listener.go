package gateway

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/define42/devbox-gateway/internal/cert"
	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/rdp"
	"github.com/define42/devbox-gateway/internal/session"
)

// rejectionLogInterval throttles connection-cap logging so a flood at the cap
// reports a periodic count instead of one line per rejected connection.
const rejectionLogInterval = 30 * time.Second

// rejectionThrottle counts rejected connections and admits at most one log
// line per rejectionLogInterval, so saturation is visible without flooding
// the log.
type rejectionThrottle struct {
	rejectedSinceLog atomic.Uint64
	lastRejectionLog atomic.Int64 // unix nanoseconds of the last saturation log
}

// note counts one rejection. When it returns true the caller should log,
// reporting the returned number of rejections since the previous log line.
func (t *rejectionThrottle) note() (uint64, bool) {
	count := t.rejectedSinceLog.Add(1)
	now := time.Now().UnixNano()
	last := t.lastRejectionLog.Load()
	if now-last < int64(rejectionLogInterval) || !t.lastRejectionLog.CompareAndSwap(last, now) {
		return 0, false
	}
	t.rejectedSinceLog.Store(0)
	return count, true
}

// failFastLimitListener caps the number of simultaneously open accepted
// connections. Unlike netutil.LimitListener, which blocks Accept at the cap —
// leaving new clients hanging in the kernel accept backlog with no trace in
// the logs — this listener keeps accepting and immediately closes connections
// over the cap: clients fail fast and retry, and every saturation episode is
// visible in the logs.
type failFastLimitListener struct {
	net.Listener

	// slots holds one token per open accepted connection; capacity is the cap.
	slots chan struct{}

	rejections rejectionThrottle
}

func newFailFastLimitListener(ln net.Listener, maxConns int) *failFastLimitListener {
	return &failFastLimitListener{
		Listener: ln,
		slots:    make(chan struct{}, maxConns),
	}
}

func (l *failFastLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &slotTrackedConn{Conn: conn, release: l.releaseSlot}, nil
		default:
			_ = conn.Close()
			if count, ok := l.rejections.note(); ok {
				log.Printf("front connection cap (%d) reached: %d connections rejected since last report (latest from %s); consider raising MAX_CONCURRENT_CONNECTIONS", cap(l.slots), count, conn.RemoteAddr())
			}
		}
	}
}

func (l *failFastLimitListener) releaseSlot() {
	<-l.slots
}

// perSourceLimitListener caps the number of simultaneously open accepted
// connections per source address, so one unauthenticated source cannot occupy
// the whole shared connection budget enforced by failFastLimitListener (e.g.
// by parking idle keep-alive connections on the unauthenticated health
// endpoint). Like failFastLimitListener it fails fast: connections over a
// source's cap are accepted and immediately closed, and saturation is logged.
type perSourceLimitListener struct {
	net.Listener

	maxPerSource int

	mu     sync.Mutex
	counts map[string]int // open connections per perSourceLimitKey bucket

	rejections rejectionThrottle
}

func newPerSourceLimitListener(ln net.Listener, maxPerSource int) *perSourceLimitListener {
	return &perSourceLimitListener{
		Listener:     ln,
		maxPerSource: maxPerSource,
		counts:       make(map[string]int),
	}
}

func (l *perSourceLimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := perSourceLimitKey(conn.RemoteAddr())
		if l.acquire(key) {
			return &slotTrackedConn{Conn: conn, release: func() { l.release(key) }}, nil
		}
		_ = conn.Close()
		if count, ok := l.rejections.note(); ok {
			log.Printf("per-source connection cap (%d) reached: %d connections rejected since last report (latest from %s); consider raising MAX_CONNECTIONS_PER_SOURCE if this source is a shared NAT or proxy", l.maxPerSource, count, conn.RemoteAddr())
		}
	}
}

func (l *perSourceLimitListener) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] >= l.maxPerSource {
		return false
	}
	l.counts[key]++
	return true
}

// release returns one slot for key, dropping the map entry at zero so the
// table stays bounded by open connections rather than by distinct sources seen.
func (l *perSourceLimitListener) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[key] <= 1 {
		delete(l.counts, key)
		return
	}
	l.counts[key]--
}

// perSourceLimitKey buckets a remote address for the per-source cap: one
// bucket per IPv4 address, one per /64 prefix for IPv6 — a single IPv6 host
// commonly controls an entire /64, so per-address buckets would be trivial to
// rotate through. Unparseable addresses fall back to the raw string so they
// are still limited rather than exempt.
func perSourceLimitKey(remote net.Addr) string {
	if remote == nil {
		return "unknown"
	}
	raw := remote.String()
	addrPort, err := netip.ParseAddrPort(raw)
	if err != nil {
		return raw
	}
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

// slotTrackedConn returns its listener slot exactly once when closed, however
// many times Close is called on it along the connection's teardown paths.
type slotTrackedConn struct {
	net.Conn

	releaseOnce sync.Once
	release     func()
}

func (c *slotTrackedConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

// openFrontListener binds LISTEN_ADDR and returns the listener that feeds the
// gateway accept loop.
func openFrontListener(settings *config.Settings) (net.Listener, error) {
	listen := settings.Get(config.LISTEN_ADDR)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listen, err)
	}
	log.Printf("listening on %s", listen)
	return limitListenerConnections(ln, settings), nil
}

// limitListenerConnections caps the number of simultaneously open front
// connections so a flood of connections — or slow clients that stall before the
// TLS handshake — cannot spawn an unbounded number of per-connection goroutines
// and exhaust the gateway's memory and file descriptors. Two caps compose: a
// per-source cap (per IPv4 address / per IPv6 /64, see perSourceLimitListener)
// keeps any single unauthenticated source from occupying the budget, and a
// global cap bounds the total. Connections over either cap are accepted and
// immediately closed (see failFastLimitListener) so clients fail fast instead
// of hanging unserved in the accept backlog, and saturation shows up in the
// logs. A value <=0 disables that cap; both <=0 restores the previous
// unbounded behavior.
func limitListenerConnections(ln net.Listener, settings *config.Settings) net.Listener {
	// The per-source cap wraps the raw listener, inside the global cap, so a
	// connection rejected for one greedy source never consumes a global slot.
	if perSource := settings.Int(config.MAX_CONNECTIONS_PER_SOURCE); perSource > 0 {
		log.Printf("limiting to %d concurrent front connections per source address", perSource)
		ln = newPerSourceLimitListener(ln, perSource)
	}
	maxConns := settings.Int(config.MAX_CONCURRENT_CONNECTIONS)
	if maxConns <= 0 {
		return ln
	}
	log.Printf("limiting to %d concurrent front connections", maxConns)
	return newFailFastLimitListener(ln, maxConns)
}

// acceptRetryDelayMax caps the exponential backoff between retries of
// transient Accept errors.
const acceptRetryDelayMax = 1 * time.Second

// nextAcceptRetryDelay classifies an Accept error: for transient failures —
// fd exhaustion (EMFILE/ENFILE) and deadline timeouts — it returns the next
// backoff delay (5ms doubling up to acceptRetryDelayMax) and true; for
// permanent failures it returns false. net.Error.Temporary is deprecated but
// is exactly how the net package reports EMFILE/ENFILE from accept;
// net/http.Server.Serve relies on the same signal for its retry loop.
func nextAcceptRetryDelay(err error, current time.Duration) (time.Duration, bool) {
	var ne net.Error
	if !errors.As(err, &ne) || (!ne.Timeout() && !ne.Temporary()) {
		return 0, false
	}
	if current == 0 {
		return 5 * time.Millisecond, true
	}
	current *= 2
	if current > acceptRetryDelayMax {
		current = acceptRetryDelayMax
	}
	return current, true
}

// serveListener runs the front accept loop until the listener is closed.
// Transient Accept errors are retried with exponential backoff, mirroring
// net/http.Server.Serve, so a temporary resource squeeze cannot silently kill
// the loop while the process lives on looking healthy. It returns nil once
// the listener is closed (normal shutdown) and the error on any other
// permanent Accept failure, so the caller can take the process down and let
// systemd restart it instead of leaving a zombie holding a dead listener.
func serveListener(ln net.Listener, mux http.Handler, frontTLS *cert.TLSManager, sessionManager *session.Manager, settings *config.Settings) error {
	var retryDelay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Printf("listener stopped: %v", err)
				return nil
			}
			next, transient := nextAcceptRetryDelay(err, retryDelay)
			if !transient {
				log.Printf("accept failed permanently: %v", err)
				return err
			}
			retryDelay = next
			log.Printf("accept: %v; retrying in %v", err, retryDelay)
			time.Sleep(retryDelay)
			continue
		}
		retryDelay = 0
		go handleSharedConn(c, frontTLS, mux, sessionManager, settings)
	}
}

func handleSharedConn(raw net.Conn, frontTLS *cert.TLSManager, mux http.Handler, sessionManager *session.Manager, settings *config.Settings) {
	defer func() { _ = raw.Close() }()

	// Defense in depth: this goroutine parses attacker-controlled bytes (the RDP
	// X.224/TPKT negotiation, the channel filter, and the TLS handshake) before
	// any net/http handler — which has its own per-request recover — takes over.
	// An unanticipated panic here would otherwise crash the whole gateway, so
	// contain it to this single connection. Registered after the Close defer so
	// it runs first on unwind and the socket is still closed afterward.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered from panic handling connection from %s: %v\n%s", raw.RemoteAddr(), r, debug.Stack())
		}
	}()

	if !setSetupDeadline(raw, settings) {
		return
	}

	br := bufio.NewReader(raw)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("peek protocol byte: %v", err)
		return
	}
	conn := &bufferedConn{Conn: raw, r: br}

	if first[0] == tlsHandshakeRecordType {
		if settings.Bool(config.DEBUG_CONNECTIONS) {
			log.Printf("debug-conn: accepted TLS/HTTPS connection from %s", raw.RemoteAddr())
		}
		handleHTTPS(conn, frontTLS, mux, settings)
		return
	}
	if settings.Bool(config.DEBUG_CONNECTIONS) {
		log.Printf("debug-conn: accepted RDP connection from %s", raw.RemoteAddr())
	}
	rdp.HandleRDP(conn, frontTLS, sessionManager, settings)
}

const tlsHandshakeRecordType = 0x16

// httpIdleTimeout bounds how long an otherwise-idle keep-alive HTTPS connection
// is held open between dashboard requests before the server closes it, so idle
// browsers do not pin front-connection slots (which are capped by
// MAX_CONCURRENT_CONNECTIONS). It does not apply to the WebSocket consoles: once
// upgraded they hijack the connection and manage their own deadlines.
const httpIdleTimeout = 120 * time.Second

func setSetupDeadline(conn net.Conn, settings *config.Settings) bool {
	if conn == nil || settings == nil {
		return true
	}
	timeout := settings.Duration(config.TIMEOUT)
	if timeout <= 0 {
		return true
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		log.Printf("set setup deadline: %v", err)
		return false
	}
	return true
}

type bufferedConn struct {
	net.Conn

	r *bufio.Reader
}

// Read drains the bufio.Reader used for the one-byte protocol sniff, then reads
// straight from the underlying conn. Keeping bufio in the path for the whole
// session would copy every RDP byte through its 4 KiB buffer; once the buffered
// sniff bytes are gone there is nothing left to drain, so we bypass it and let
// the TLS layer read record-aligned chunks directly off the socket.
func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.r != nil {
		if n := c.r.Buffered(); n > 0 {
			if len(p) > n {
				p = p[:n]
			}
			return c.r.Read(p)
		}
		c.r = nil
	}
	return c.Conn.Read(p)
}

func handleHTTPS(raw net.Conn, frontTLS *cert.TLSManager, mux http.Handler, settings *config.Settings) {
	// TLS handshake with client; get SNI
	clientTLS := tls.Server(raw, frontTLS.TLSConfig())
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client tls handshake: %v", err)
		return
	}

	state := clientTLS.ConnectionState()
	if cert.IsACMETLSALPN(state.NegotiatedProtocol) {
		_ = clientTLS.Close()
		return
	}

	sni := strings.ToLower(strings.TrimSpace(state.ServerName))
	log.Printf("https client %s SNI=%q -> https page", raw.RemoteAddr(), sni)

	_ = clientTLS.SetDeadline(time.Time{})

	srv := &http.Server{
		Handler:           withRequestScheme(mux, "https"),
		ReadTimeout:       settings.Duration(config.TIMEOUT),
		ReadHeaderTimeout: settings.Duration(config.TIMEOUT),
		IdleTimeout:       httpIdleTimeout,
		// WriteTimeout is deliberately unset. This server multiplexes the
		// dashboard's long-lived WebSocket consoles (serial/VNC/ping), which hijack
		// the connection and enforce their own write deadlines (see the console
		// package). A blanket WriteTimeout would risk cutting a streaming console
		// mid-write while adding negligible protection for the small HTTP responses
		// the dashboard otherwise returns; slow-header attacks are bounded by
		// ReadHeaderTimeout and the pre-TLS setup deadline instead.
	}
	ln := newSingleConnListener(clientTLS)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("https serve: %v", err)
	}
}

func withRequestScheme(next http.Handler, scheme string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r.Clone(r.Context())
		req.URL.Scheme = scheme
		next.ServeHTTP(w, req)
	})
}

type singleConnListener struct {
	conn net.Conn
	addr net.Addr
	done chan struct{}
	once sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	l := &singleConnListener{
		addr: conn.LocalAddr(),
		done: make(chan struct{}),
	}
	l.conn = &closeNotifyConn{Conn: conn, done: l.done, once: &l.once}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.addr
}

type closeNotifyConn struct {
	net.Conn

	done chan struct{}
	once *sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
