// Package transport provides the guest-to-host byte stream.
//
// In production that is AF_VSOCK, which reaches the hypervisor without any of
// the guest's IP configuration: no host address, no route, no gateway, no DNS
// and no listening socket on the VM's own network. A TCP implementation exists
// for development and integration testing only.
package transport

import (
	"context"
	"net"
)

// Dialer opens a connection to the host collector.
type Dialer interface {
	// Dial connects to the collector. The returned connection is a plain
	// ordered, reliable byte stream; framing is the protocol package's job.
	Dial(ctx context.Context) (net.Conn, error)

	// String describes the destination, for logs.
	String() string
}

// Listener accepts guest connections on the host.
type Listener interface {
	// Accept returns the next guest connection.
	Accept() (net.Conn, error)

	// Close stops the listener.
	Close() error

	// Addr describes the listening address.
	Addr() net.Addr
}

// PeerCID is implemented in vsock.go. It returns the VSOCK context ID of the
// connection's remote end.
//
// This is the load-bearing security property of the whole design: the CID is
// assigned by the hypervisor and cannot be chosen by the guest, so it is the
// only identity claim in the system that a compromised guest cannot forge.
// Everything a guest says about itself is treated as informational.
