package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/session"
	"testing"
	"time"
)

func TestSingleConnListenerLifecycle(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	listener := newSingleConnListener(server)
	if listener.Addr() == nil {
		t.Fatal("expected listener address")
	}

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept first conn: %v", err)
	}

	want := []byte("hello")
	go func() {
		_, _ = client.Write(want)
		_ = client.Close()
	}()

	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read accepted conn: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("expected %q, got %q", string(want), string(got))
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close conn: %v", err)
	}

	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected second accept to return net.ErrClosed, got %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
}

func TestSingleConnListenerCloseBeforeAccept(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	listener := newSingleConnListener(server)
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener before accept: %v", err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected accept after close to return net.ErrClosed, got %v", err)
	}
}

func TestSingleConnListenerCloseTwice(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	listener := newSingleConnListener(server)
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener first time: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener second time: %v", err)
	}
}

func TestBufferedConnRead(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	reader := bufio.NewReader(server)
	conn := &bufferedConn{Conn: server, r: reader}

	go func() {
		_, _ = client.Write([]byte("peeked"))
	}()

	buf := make([]byte, len("peeked"))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("bufferedConn.Read: %v", err)
	}
	if string(buf) != "peeked" {
		t.Fatalf("expected %q, got %q", "peeked", string(buf))
	}
}

func TestServeListenerReturnsWhenClosed(t *testing.T) {
	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}
	t.Cleanup(func() {
		if err := frontTLS.Close(); err != nil {
			t.Fatalf("close TLS manager: %v", err)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	sessionManager := session.NewManager()
	go func() {
		serveListener(ln, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), frontTLS, sessionManager, settings)
		close(done)
	}()

	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveListener did not return after listener close")
	}
}

func TestServeListenerRetriesTimeoutAccept(t *testing.T) {
	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}
	t.Cleanup(func() {
		if err := frontTLS.Close(); err != nil {
			t.Fatalf("close TLS manager: %v", err)
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tcpLn, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatalf("expected TCP listener, got %T", ln)
	}

	if err := tcpLn.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set listener deadline: %v", err)
	}

	done := make(chan struct{})
	sessionManager := session.NewManager()
	go func() {
		serveListener(tcpLn, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), frontTLS, sessionManager, settings)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	if err := tcpLn.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveListener did not return after timeout and close")
	}
}

func TestHandleSharedConnRoutesNonTLS(t *testing.T) {
	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}
	t.Cleanup(func() {
		if err := frontTLS.Close(); err != nil {
			t.Fatalf("close TLS manager: %v", err)
		}
	})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	done := make(chan struct{})
	sessionManager := session.NewManager()
	go func() {
		handleSharedConn(server, frontTLS, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("HTTPS handler should not be called for non-TLS payload")
		}), sessionManager, settings)
		close(done)
	}()

	if _, err := client.Write([]byte{0x03, 0x00, 0x00, 0x02}); err != nil {
		t.Fatalf("write non-TLS payload: %v", err)
	}
	_ = client.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleSharedConn did not return for non-TLS payload")
	}
}

func TestHandleSharedConnPeekFailure(t *testing.T) {
	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}
	t.Cleanup(func() {
		if err := frontTLS.Close(); err != nil {
			t.Fatalf("close TLS manager: %v", err)
		}
	})

	client, server := net.Pipe()

	done := make(chan struct{})
	sessionManager := session.NewManager()
	go func() {
		handleSharedConn(server, frontTLS, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("HTTPS handler should not be called when no bytes are available")
		}), sessionManager, settings)
		close(done)
	}()

	_ = client.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleSharedConn did not return after peek failure")
	}
}

func TestBootGatewayErrors(t *testing.T) {
	t.Run("invalid listen address", func(t *testing.T) {
		t.Setenv(config.LISTEN_ADDR, "bad::addr")
		t.Setenv(config.CERT_FILE, "")
		t.Setenv(config.KEY_FILE, "")
		if _, err := bootGateway(); err == nil {
			t.Fatal("expected bootGateway to fail for invalid listen address")
		}
	})

	t.Run("invalid base image url", func(t *testing.T) {
		t.Setenv(config.LISTEN_ADDR, "127.0.0.1:0")
		t.Setenv(config.CERT_FILE, "")
		t.Setenv(config.KEY_FILE, "")
		t.Setenv(config.BASE_IMAGE_URL, "://bad-url")
		if _, err := bootGateway(); err == nil {
			t.Fatal("expected bootGateway to fail for invalid base image url")
		}
	})
}

func TestHandleSharedConnRoutesTLS(t *testing.T) {
	frontTLS, settings := newTestTLSManager(t)

	reqCh := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reqCh <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan struct{})
	sessionManager := session.NewManager()
	go func() {
		handleSharedConn(server, frontTLS, handler, sessionManager, settings)
		close(done)
	}()

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if _, err := tlsClient.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write https request: %v", err)
	}
	_ = tlsClient.Close()

	select {
	case <-reqCh:
	case <-time.After(5 * time.Second):
		t.Fatal("expected HTTPS handler to be called")
	}

	waitHandleHTTPSDone(t, done)
}
