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
	"testing"
	"time"

	"github.com/mholt/acmez"
)

type handleHTTPSRequestInfo struct {
	host string
	path string
}

func waitHandleHTTPSDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		return
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTPS did not return in time")
	}
}

func newTestTLSManager(t *testing.T) (*cert.TLSManager, *config.SettingsType) {
	t.Helper()
	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
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
	return frontTLS, settings
}

func assertHandleHTTPSResponse(t *testing.T, tlsClient *tls.Conn) {
	t.Helper()

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %v", resp.Status)
	}
	if got := string(body); got != "hello" {
		t.Fatalf("unexpected body: %q", got)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("unexpected header X-Test: %q", got)
	}
}

func assertObservedHTTPRequest(t *testing.T, reqCh <-chan handleHTTPSRequestInfo) {
	t.Helper()

	select {
	case req := <-reqCh:
		if req.host != "example.com" {
			t.Fatalf("unexpected host: %q", req.host)
		}
		if req.path != "/" {
			t.Fatalf("unexpected path: %q", req.path)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("handler was not called")
	}
}

func TestHandleHTTPS_ServesRequest(t *testing.T) {
	frontTLS, settings := newTestTLSManager(t)

	reqCh := make(chan handleHTTPSRequestInfo, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCh <- handleHTTPSRequestInfo{host: r.Host, path: r.URL.Path}
		w.Header().Set("X-Test", "ok")
		_, _ = w.Write([]byte("hello"))
	})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		handleHTTPS(server, frontTLS, handler, settings)
		close(done)
	}()

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	defer func() { _ = tlsClient.Close() }()

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client tls handshake: %v", err)
	}

	if _, err := io.WriteString(tlsClient, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}

	assertHandleHTTPSResponse(t, tlsClient)
	assertObservedHTTPRequest(t, reqCh)
	_ = tlsClient.Close()
	_ = client.Close()
	waitHandleHTTPSDone(t, done)
}

func TestHandleHTTPS_ACMETLSALPNClosesConn(t *testing.T) {
	frontTLS, settings := newTestTLSManager(t)

	frontTLS.GetTLSConfig().NextProtos = []string{acmez.ACMETLS1Protocol}

	handlerCalled := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		handlerCalled <- struct{}{}
	})

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	done := make(chan struct{})
	go func() {
		handleHTTPS(server, frontTLS, handler, settings)
		close(done)
	}()

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{acmez.ACMETLS1Protocol},
	})
	defer func() { _ = tlsClient.Close() }()

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client tls handshake: %v", err)
	}

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	buf := make([]byte, 1)
	if _, err := tlsClient.Read(buf); err == nil {
		t.Fatal("expected connection close after ACME TLS-ALPN handshake")
	} else {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("expected connection close, got timeout: %v", err)
		}
	}

	select {
	case <-handlerCalled:
		t.Fatal("handler should not be called for ACME TLS-ALPN")
	default:
	}

	waitHandleHTTPSDone(t, done)
}

func TestHandleHTTPSHandshakeFailure(t *testing.T) {
	frontTLS, settings := newTestTLSManager(t)

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	done := make(chan struct{})
	go func() {
		handleHTTPS(server, frontTLS, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler should not be called when TLS handshake fails")
		}), settings)
		close(done)
	}()

	_ = client.Close()
	waitHandleHTTPSDone(t, done)
}
