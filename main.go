// main.go
//
// RDP TLS SNI gateway (TLS terminate on the front, TLS initiate to backend).
// Routing is based on the client's TLS SNI.
// Backend TLS certificates are NOT validated (InsecureSkipVerify=true).
//
// Flow (front side):
//   1) Read client's X.224 Connection Request (TPKT)
//   2) Reply with X.224 Connection Confirm selecting TLS (PROTOCOL_SSL)
//   3) Do TLS handshake with client, read SNI
//
// Flow (backend side):
//   4) TCP connect to chosen backend
//   5) Send a new Connection Request to backend that only requests TLS (RDP_NEG_REQ)
//   6) Read backend Connection Confirm, require it selects TLS (PROTOCOL_SSL)
//   7) Do TLS handshake to backend (skip cert verification)
//   8) Proxy bytes both ways: clientTLS <-> backendTLS
//
// Note: This is NOT Microsoft RD Gateway (no HTTP/UDP transports). It’s a TLS-to-TLS RDP proxy.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	consolepkg "rdptlsgateway/internal/console"
	"rdptlsgateway/internal/rdp"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/sshtunnel"
	"rdptlsgateway/internal/virt"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gateway, err := bootGateway()
	if err != nil {
		// If booting the gateway fails, we can't do much about it, so log and exit.
		log.Printf("Failed to boot gateway: %v", err)
		return 1
	}
	defer func() {
		if err := gateway.Close(); err != nil {
			log.Printf("gateway shutdown: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		return 0
	case err := <-gateway.Fatal():
		// The front SSH tunnel dropped. Exit non-zero so the process supervisor
		// (systemd Restart=on-failure) re-establishes it.
		log.Printf("front listener failed: %v", err)
		return 1
	}
}

type gatewayRuntime struct {
	listener net.Listener
	frontTLS *cert.TLSManager
	tunnel   *sshtunnel.Tunnel // nil when listening locally
	done     <-chan struct{}
}

// Fatal reports a front SSH tunnel failure so run can exit and let a supervisor
// reconnect. It returns a nil channel when listening locally, which blocks
// forever in a select and therefore never fires.
func (g *gatewayRuntime) Fatal() <-chan error {
	if g.tunnel == nil {
		return nil
	}
	return g.tunnel.Fatal()
}

func (g *gatewayRuntime) Close() error {
	var errs []error

	// In tunnel mode the listener is owned by the tunnel, so closing the tunnel
	// also closes the listener; avoid closing it twice.
	switch {
	case g.tunnel != nil:
		if err := g.tunnel.Close(); err != nil {
			errs = append(errs, err)
		}
	case g.listener != nil:
		if err := g.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	if g.done != nil {
		select {
		case <-g.done:
		case <-time.After(5 * time.Second):
			errs = append(errs, fmt.Errorf("gateway listener did not stop in time"))
		}
	}

	if g.frontTLS != nil {
		if err := g.frontTLS.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func bootGateway() (*gatewayRuntime, error) {
	virt.GetInstance()

	rdp.InitLogging()

	// Configuration lives in a KEY=VALUE config file (default
	// /etc/rdp-tls-gateway/rdp-tls-gateway.conf, overridable via CONFIG_FILE).
	// Explicit environment variables still take precedence, so containers and
	// development setups can override individual values.
	if err := config.LoadConfigFile(config.FilePath()); err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}
	settings := config.NewSettingType(true)
	sessionManager := session.NewManager()

	// Verbose per-connection console diagnostics, off unless DEBUG_CONNECTIONS.
	debugConns := settings.GetBool(config.DEBUG_CONNECTIONS)
	consolepkg.SetDebugLogging(debugConns)
	virt.SetVNCDebugLogging(debugConns)

	if err := virt.InitVirt(settings); err != nil {
		return nil, fmt.Errorf("failed to initialize virtualization: %w", err)
	}

	if err := config.EnsureSNIHashSecret(settings); err != nil {
		return nil, fmt.Errorf("failed to resolve SNI hash secret: %w", err)
	}

	mux := getRemoteGatewayRotuer(sessionManager, settings)

	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		return nil, fmt.Errorf("tls setup: %w", err)
	}

	ln, tunnel, err := openFrontListener(settings)
	if err != nil {
		_ = frontTLS.Close()
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		serveListener(ln, mux, frontTLS, sessionManager, settings)
		close(done)
	}()

	// Start ACME only once the front listener is accepting connections: ACME
	// TLS-ALPN-01 validation is answered through that listener (bound locally or
	// published via the SSH reverse tunnel). This is non-fatal — the gateway
	// serves the self-signed fallback while certmagic keeps retrying issuance in
	// the background, so a slow relay or DNS does not prevent boot.
	if err := frontTLS.StartManaging(); err != nil {
		log.Printf("%v; continuing with the fallback certificate", err)
	}

	return &gatewayRuntime{
		listener: ln,
		frontTLS: frontTLS,
		tunnel:   tunnel,
		done:     done,
	}, nil
}

// openFrontListener returns the listener that feeds the gateway accept loop.
// With SSH_TUNNEL_ENABLE it dials a public relay over SSH and serves the
// relay's remote listener (so the gateway can run behind NAT); otherwise it
// binds LISTEN_ADDR locally. The returned tunnel is non-nil only in tunnel mode.
func openFrontListener(settings *config.SettingsType) (net.Listener, *sshtunnel.Tunnel, error) {
	if settings.GetBool(config.SSH_TUNNEL_ENABLE) {
		tunnel, err := sshtunnel.Open(sshTunnelConfig(settings))
		if err != nil {
			return nil, nil, fmt.Errorf("open SSH tunnel: %w", err)
		}
		log.Printf("listening via SSH reverse tunnel: relay %s forwards %s",
			settings.Get(config.SSH_TUNNEL_SERVER), settings.Get(config.SSH_TUNNEL_REMOTE_ADDR))
		return tunnel.Listener(), tunnel, nil
	}

	listen := settings.Get(config.LISTEN_ADDR)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s: %w", listen, err)
	}
	log.Printf("listening on %s", listen)
	return ln, nil, nil
}

func sshTunnelConfig(settings *config.SettingsType) sshtunnel.Config {
	return sshtunnel.Config{
		User:              settings.Get(config.SSH_TUNNEL_USER),
		Server:            settings.Get(config.SSH_TUNNEL_SERVER),
		PrivateKeyPath:    settings.Get(config.SSH_TUNNEL_PRIVATE_KEY),
		Passphrase:        []byte(settings.Get(config.SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE)),
		KnownHostsPath:    settings.Get(config.SSH_TUNNEL_KNOWN_HOSTS),
		RemoteListenAddr:  settings.Get(config.SSH_TUNNEL_REMOTE_ADDR),
		DialTimeout:       settings.GetDuration(config.TIMEOUT),
		KeepAliveInterval: settings.GetDuration(config.SSH_TUNNEL_KEEPALIVE_INTERVAL),
		KeepAliveTimeout:  settings.GetDuration(config.SSH_TUNNEL_KEEPALIVE_TIMEOUT),
	}
}

func serveListener(ln net.Listener, mux http.Handler, frontTLS *cert.TLSManager, sessionManager *session.Manager, settings *config.SettingsType) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Printf("listener stopped: %v", err)
				return
			}
			if os.IsTimeout(err) {
				log.Printf("accept: %v", err)
				continue
			}
			log.Printf("listener stopped: %v", err)
			return
		}
		go handleSharedConn(c, frontTLS, mux, sessionManager, settings)
	}
}

func handleSharedConn(raw net.Conn, frontTLS *cert.TLSManager, mux http.Handler, sessionManager *session.Manager, settings *config.SettingsType) {
	defer func() { _ = raw.Close() }()

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
		if settings.GetBool(config.DEBUG_CONNECTIONS) {
			log.Printf("debug-conn: accepted TLS/HTTPS connection from %s", raw.RemoteAddr())
		}
		handleHTTPS(conn, frontTLS, mux, settings)
		return
	}
	if settings.GetBool(config.DEBUG_CONNECTIONS) {
		log.Printf("debug-conn: accepted RDP connection from %s", raw.RemoteAddr())
	}
	rdp.HandleRDP(conn, frontTLS, sessionManager, settings)
}

const tlsHandshakeRecordType = 0x16

func setSetupDeadline(conn net.Conn, settings *config.SettingsType) bool {
	if conn == nil || settings == nil {
		return true
	}
	timeout := settings.GetDuration(config.TIMEOUT)
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

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func handleHTTPS(raw net.Conn, frontTLS *cert.TLSManager, mux http.Handler, settings *config.SettingsType) {
	// Over the SSH reverse tunnel the connection is an SSH channel whose deadline
	// methods are no-ops. net/http's Hijack (used by the dashboard's WebSocket
	// consoles) aborts a pending background read by setting a past read deadline
	// and waiting for it; with no-op deadlines that wait never returns and the
	// upgrade hangs. Give the HTTPS path a connection with working read deadlines.
	// RDP keeps the raw channel, so its proxy path is unaffected.
	if settings.GetBool(config.SSH_TUNNEL_ENABLE) {
		raw = sshtunnel.NewReadDeadlineConn(raw)
	}

	// TLS handshake with client; get SNI
	clientTLS := tls.Server(raw, frontTLS.GetTLSConfig())
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
		Handler:     withRequestScheme(mux, "https"),
		ReadTimeout: settings.GetDuration(config.TIMEOUT),
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
