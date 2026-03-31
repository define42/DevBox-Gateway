package rdp

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"rdptlsgateway/internal/virt"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/tomatome/grdp/protocol/x224"
)

func setVMInventoryForTest(t *testing.T, entries map[string]string) {
	t.Helper()

	instance := virt.GetInstance()
	rv := reflect.ValueOf(instance).Elem()

	muField := rv.FieldByName("mu")
	mu := reflect.NewAt(muField.Type(), unsafe.Pointer(muField.UnsafeAddr())).Elem().Addr().Interface().(*sync.RWMutex)

	vmsField := rv.FieldByName("vms")
	settableVMs := reflect.NewAt(vmsField.Type(), unsafe.Pointer(vmsField.UnsafeAddr())).Elem()

	mu.Lock()
	old := reflect.MakeSlice(settableVMs.Type(), settableVMs.Len(), settableVMs.Len())
	reflect.Copy(old, settableVMs)

	next := reflect.MakeSlice(settableVMs.Type(), 0, len(entries))
	for name, ip := range entries {
		elem := reflect.New(settableVMs.Type().Elem()).Elem()
		elem.FieldByName("Name").SetString(name)
		elem.FieldByName("PrimaryIP").SetString(ip)
		elem.FieldByName("IP").SetString(ip)
		elem.FieldByName("State").SetString("running")
		next = reflect.Append(next, elem)
	}
	settableVMs.Set(next)
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		settableVMs.Set(old)
		mu.Unlock()
	})
}

func buildServerCCFForProtocol(protocol uint32) []byte {
	neg := x224.Negotiation{
		Type:   x224.TYPE_RDP_NEG_RSP,
		Flag:   0,
		Length: 8,
		Result: protocol,
	}

	li := uint8(6 + neg.Length)
	payload := make([]byte, 0, int(li)+1)
	payload = append(payload,
		li,
		byte(x224.TPDU_CONNECTION_CONFIRM),
		0x00, 0x00,
		0x12, 0x34,
		0x00,
		byte(neg.Type),
		neg.Flag,
	)

	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, neg.Length)
	payload = append(payload, lengthBytes...)

	resultBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(resultBytes, neg.Result)
	payload = append(payload, resultBytes...)

	return payload
}

func startBackendServer(t *testing.T, host string, handler func(net.Conn)) func() {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort(host, "3389"))
	if err != nil {
		t.Fatalf("listen backend server: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		handler(conn)
	}()

	return func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("backend server did not stop in time")
		}
	}
}

func newFrontTLSManager(t *testing.T, frontDomain string) (*cert.TLSManager, *config.SettingsType) {
	t.Helper()

	t.Setenv(config.ACME_ENABLE, "false")
	t.Setenv(config.CERT_FILE, "")
	t.Setenv(config.KEY_FILE, "")
	t.Setenv(config.FRONT_DOMAIN, frontDomain)

	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}
	return frontTLS, settings
}

func backendTLSCert(t *testing.T) tls.Certificate {
	t.Helper()

	settings := config.NewSettingType(false)
	certificate, err := cert.LoadOrGenerateCert(settings)
	if err != nil {
		t.Fatalf("load backend certificate: %v", err)
	}
	return certificate
}

func performFrontHandshake(t *testing.T, client net.Conn, serverName string) *tls.Conn {
	t.Helper()

	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	if err := writeTPKT(client, buildClientCRQ(x224.PROTOCOL_SSL)); err != nil {
		t.Fatalf("write client CRQ: %v", err)
	}
	if _, err := readTPKT(client); err != nil {
		t.Fatalf("read front CCF: %v", err)
	}

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("front TLS handshake: %v", err)
	}
	return tlsClient
}

func TestHandleRDPSuccessfulProxy(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.42"
	setVMInventoryForTest(t, map[string]string{"vm1": backendHost})

	stopBackend := startBackendServer(t, backendHost, func(raw net.Conn) {
		req, err := readTPKT(raw)
		if err != nil {
			t.Errorf("backend read CRQ: %v", err)
			return
		}
		if proto, ok := findClientRequestedProtocols(req); !ok || proto != x224.PROTOCOL_SSL {
			t.Errorf("backend expected TLS-only CRQ, got ok=%v proto=0x%08x", ok, proto)
			return
		}
		if err := writeTPKT(raw, buildServerCCFForProtocol(x224.PROTOCOL_SSL)); err != nil {
			t.Errorf("backend write CCF: %v", err)
			return
		}

		tlsConn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{backendTLSCert(t)},
			MinVersion:   tls.VersionTLS10,
		})
		if err := tlsConn.Handshake(); err != nil {
			t.Errorf("backend TLS handshake: %v", err)
			return
		}
		defer tlsConn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(tlsConn, buf); err != nil {
			t.Errorf("backend read proxied bytes: %v", err)
			return
		}
		if string(buf) != "ping" {
			t.Errorf("expected proxied payload %q, got %q", "ping", string(buf))
			return
		}
		if _, err := tlsConn.Write([]byte("pong")); err != nil {
			t.Errorf("backend write proxied bytes: %v", err)
		}
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vm1.example.test")
	defer tlsClient.Close()

	if _, err := tlsClient.Write([]byte("ping")); err != nil {
		t.Fatalf("write proxied client bytes: %v", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(tlsClient, reply); err != nil {
		t.Fatalf("read proxied backend bytes: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("expected backend reply %q, got %q", "pong", string(reply))
	}

	_ = tlsClient.Close()
	waitDone(t, done)
}

func TestHandleRDPRejectsMissingSubdomain(t *testing.T) {
	InitLogging()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "example.test")
	defer tlsClient.Close()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPRejectsMissingRoute(t *testing.T) {
	InitLogging()

	setVMInventoryForTest(t, map[string]string{})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "missing.example.test")
	defer tlsClient.Close()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPBackendDialFailure(t *testing.T) {
	InitLogging()

	setVMInventoryForTest(t, map[string]string{"vmdial": "127.0.0.43"})
	frontTLS, settings := newFrontTLSManager(t, "example.test")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmdial.example.test")
	defer tlsClient.Close()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}

func TestHandleRDPRejectsBackendWithoutTLS(t *testing.T) {
	InitLogging()

	backendHost := "127.0.0.44"
	setVMInventoryForTest(t, map[string]string{"vmbad": backendHost})

	stopBackend := startBackendServer(t, backendHost, func(raw net.Conn) {
		if _, err := readTPKT(raw); err != nil {
			t.Errorf("backend read CRQ: %v", err)
			return
		}
		if err := writeTPKT(raw, buildServerCCFForProtocol(x224.PROTOCOL_RDP)); err != nil {
			t.Errorf("backend write non-TLS CCF: %v", err)
		}
	})
	defer stopBackend()

	frontTLS, settings := newFrontTLSManager(t, "example.test")
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, settings)
		close(done)
	}()

	tlsClient := performFrontHandshake(t, client, "vmbad.example.test")
	defer tlsClient.Close()
	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}
