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
	"rdptlsgateway/internal/ldap"
	"rdptlsgateway/internal/localauth"
	"rdptlsgateway/internal/rdp"
	"rdptlsgateway/internal/session"
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

	<-ctx.Done()

	return 0
}

type gatewayRuntime struct {
	listener net.Listener
	frontTLS *cert.TLSManager
	done     <-chan struct{}
}

func (g *gatewayRuntime) Close() error {
	var errs []error

	if g.listener != nil {
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
	configureSessionManager(sessionManager, settings)

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

	listen := settings.Get(config.LISTEN_ADDR)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		_ = frontTLS.Close()
		return nil, fmt.Errorf("listen on %s: %w", listen, err)
	}
	log.Printf("listening on %s", listen)

	done := make(chan struct{})
	go func() {
		serveListener(ln, mux, frontTLS, sessionManager, settings)
		close(done)
	}()
	return &gatewayRuntime{
		listener: ln,
		frontTLS: frontTLS,
		done:     done,
	}, nil
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

	br := bufio.NewReader(raw)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("peek protocol byte: %v", err)
		return
	}
	conn := &bufferedConn{Conn: raw, r: br}

	if first[0] == tlsHandshakeRecordType {
		handleHTTPS(conn, frontTLS, mux, settings)
		return
	}
	rdp.HandleRDP(conn, frontTLS, sessionManager, settings)
}

const tlsHandshakeRecordType = 0x16

type bufferedConn struct {
	net.Conn

	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func handleHTTPS(raw net.Conn, frontTLS *cert.TLSManager, mux http.Handler, settings *config.SettingsType) {
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
		Handler:     mux,
		ReadTimeout: settings.GetDuration(config.TIMEOUT),
	}
	ln := newSingleConnListener(clientTLS)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("https serve: %v", err)
	}
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

func configureSessionManager(sessionManager *session.Manager, settings *config.SettingsType) {
	sessionManager.SetSessionValidator(func(username, password string) (bool, error) {
		if localauth.Validate(username, password, settings) {
			return true, nil
		}
		return ldap.ValidateSessionAccess(username, password, settings)
	})
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
