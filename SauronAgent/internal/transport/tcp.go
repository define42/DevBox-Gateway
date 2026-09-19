package transport

// TCP is a development and integration-testing transport only, and must not be
// used in a deployment.
//
// It reintroduces exactly the dependency the design exists to remove: a route
// from the guest to the host, an address the guest can reach, a listening TCP
// port on the collector, and a path that the guest's own firewall, routing
// table and network namespaces can break or redirect. Worse, it hands the
// authoritative identity back to the guest: TCP carries no CID, so PeerCID
// returns ok=false for these connections and the collector has nothing but the
// guest's own claims to identify it by. Anything an attacker inside a VM can
// reconfigure is not a security telemetry channel.

import (
	"context"
	"fmt"
	"net"
)

// tcpDialer dials the collector over TCP. Development use only.
type tcpDialer struct {
	address string
	dialer  net.Dialer
}

// NewTCPDialer returns a Dialer that connects to address over TCP.
//
// For development and integration tests only: TCP reintroduces exactly the
// dependency on guest networking that VSOCK exists to remove, and gives the
// collector no unforgeable peer identity. Do not use it in a deployment; use
// NewVSOCKDialer.
func NewTCPDialer(address string) Dialer {
	return &tcpDialer{address: address}
}

// Dial connects to the collector, giving up as soon as ctx is done.
func (d *tcpDialer) Dial(ctx context.Context) (net.Conn, error) {
	c, err := d.dialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", d.address, err)
	}
	return c, nil
}

// String describes the destination, for logs.
func (d *tcpDialer) String() string { return "tcp:" + d.address }

// ListenTCP listens for guest connections on address, e.g. "127.0.0.1:9000".
//
// For development and integration tests only: TCP reintroduces exactly the
// dependency on guest networking that VSOCK exists to remove, and a connection
// accepted here has no hypervisor-assigned CID, so the collector cannot
// establish which VM it is talking to. Do not use it in a deployment; use
// ListenVSOCK.
func ListenTCP(address string) (Listener, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", address, err)
	}
	// net.Listener already provides Accept, Close and Addr.
	return l, nil
}
