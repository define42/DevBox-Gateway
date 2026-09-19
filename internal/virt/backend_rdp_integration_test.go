package virt_test

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/define42/devbox-gateway/internal/backendidentity"
	"github.com/define42/devbox-gateway/internal/virt"
	"libvirt.org/go/libvirt"
)

// This uses the actual cloud-init seed and xrdp server from the booted image,
// so a certificate path, file permission, or service configuration regression
// cannot pass solely because the Go TLS client accepts a synthetic server.
func waitForProvisionedRDPCertificate(t *testing.T, conn *libvirt.Connect, name string) {
	t.Helper()
	certificate, serverName, err := virt.VMBackendIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := backendidentity.TLSConfig(certificate, serverName)
	if err != nil {
		t.Fatal(err)
	}
	vms, err := virt.ListVMs("", conn)
	if err != nil {
		t.Fatal(err)
	}
	var address string
	for _, vm := range vms {
		if vm.Name == name && vm.PrimaryIP != "" {
			address = net.JoinHostPort(vm.PrimaryIP, "3389")
		}
	}
	if address == "" {
		t.Fatal("new VM has no protected backend address")
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		if err = verifyProvisionedRDP(address, tlsConfig); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("cloud-init did not provision the expected xrdp certificate: %v", err)
}

func verifyProvisionedRDP(address string, config *tls.Config) error {
	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Close() }()
	if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	// TPKT + X.224 Connection Request selecting PROTOCOL_SSL.
	request := []byte{3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0, 1, 0, 0, 0}
	if _, err := raw.Write(request); err != nil {
		return err
	}
	if err := readRDPServerTLSSelection(raw); err != nil {
		return err
	}
	client := tls.Client(raw, config.Clone())
	return client.Handshake()
}

func readRDPServerTLSSelection(reader io.Reader) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(header[2:]))
	if header[0] != 3 || length < 19 || length > 4096 {
		return fmt.Errorf("invalid RDP negotiation response")
	}
	response := make([]byte, length-4)
	if _, err := io.ReadFull(reader, response); err != nil {
		return err
	}
	negotiation := response[len(response)-8:]
	if negotiation[0] != 2 || binary.LittleEndian.Uint32(negotiation[4:]) != 1 {
		return fmt.Errorf("xrdp did not select TLS")
	}
	return nil
}
