package rdp

import (
	"crypto/tls"
	"io"
	"net"
	"rdptlsgateway/internal/cert"
	"rdptlsgateway/internal/config"
	"testing"
	"time"

	"github.com/tomatome/grdp/protocol/x224"
)

func buildClientCRQ(protocol uint32) []byte {
	pdu := x224.NewClientConnectionRequestPDU(nil)
	pdu.ProtocolNeg.Type = x224.TYPE_RDP_NEG_REQ
	pdu.ProtocolNeg.Flag = 0
	pdu.ProtocolNeg.Length = 8
	pdu.ProtocolNeg.Result = protocol
	pdu.Len = uint8(len(pdu.Serialize()) - 1)
	return pdu.Serialize()
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		return
	case <-time.After(2 * time.Second):
		t.Fatal("HandleRDP did not return in time")
	}
}

func TestHandleRDPRejectsClientWithoutTLS(t *testing.T) {
	InitLogging()
	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
	}()
	defer func() {
		_ = server.Close()
	}()

	done := make(chan struct{})
	settings := config.NewSettingType(false)
	go func() {
		HandleRDP(server, nil, nil, settings)
		close(done)
	}()

	if err := writeTPKT(client, buildClientCRQ(x224.PROTOCOL_RDP)); err != nil {
		t.Fatalf("write CRQ: %v", err)
	}

	waitDone(t, done)
}

func TestHandleRDPRejectsSNIMismatch(t *testing.T) {
	InitLogging()
	t.Setenv(config.FRONT_DOMAIN, "example.test")
	settings := config.NewSettingType(false)
	frontTLS, err := cert.NewTLSManager(settings)
	if err != nil {
		t.Fatalf("new TLS manager: %v", err)
	}

	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
	}()
	defer func() {
		_ = server.Close()
	}()

	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	done := make(chan struct{})
	go func() {
		HandleRDP(server, frontTLS, nil, settings)
		close(done)
	}()

	if err := writeTPKT(client, buildClientCRQ(x224.PROTOCOL_SSL)); err != nil {
		t.Fatalf("write CRQ: %v", err)
	}

	if _, err := readTPKT(client); err != nil {
		t.Fatalf("read CCF: %v", err)
	}

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "bad.example.com",
	})
	defer func() {
		_ = tlsClient.Close()
	}()

	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client tls handshake: %v", err)
	}

	go func() {
		_, _ = io.Copy(io.Discard, tlsClient)
	}()

	waitDone(t, done)
}
