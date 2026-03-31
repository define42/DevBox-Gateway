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
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/rdp"
	"rdptlsgateway/internal/session"
	"rdptlsgateway/internal/virt"
)

func main() {
	if err := bootGateway(); err != nil {
		log.Fatalf("Failed to boot gateway: %v", err)
	}

	// run forever
	select {}
}

func bootGateway() error {
	virt.GetInstance()

	rdp.InitLogging()
	sessionManager := session.NewManager()
	settings := config.NewSettingType(true)

	if err := virt.InitVirt(settings); err != nil {
		return fmt.Errorf("failed to initialize virtualization: %v", err)
	}

	mux := getRemoteGatewayRotuer(sessionManager, settings)

	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		return fmt.Errorf("tls setup: %v", err)
	}
	//go listenServer(routes, mux, frontTLS, settings, ":3389")
	go listenServer(mux, frontTLS, settings)
	return nil
}

func listenServer(mux http.Handler, frontTLS *cert.TLSManager, settings *config.SettingsType) {
	listen := settings.Get(config.LISTEN_ADDR)
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on %s", listen)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSharedConn(c, frontTLS, mux, settings)
	}
}

func handleSharedConn(raw net.Conn, frontTLS *cert.TLSManager, mux http.Handler, settings *config.SettingsType) {
	defer raw.Close()

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
	rdp.HandleRDP(conn, frontTLS, settings)
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
