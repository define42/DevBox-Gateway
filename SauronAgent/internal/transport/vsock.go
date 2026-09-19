package transport

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// Context IDs Linux reserves, repeated here so the transport does not depend
// on the configuration package.
const (
	// cidHost is VMADDR_CID_HOST: the hypervisor-side host, and the only
	// destination a guest agent ever dials.
	cidHost uint32 = 2
	// cidAny is VMADDR_CID_ANY, the wildcard a collector binds so that every
	// guest can reach it regardless of the CID the hypervisor handed out.
	cidAny uint32 = 0xFFFFFFFF
	// defaultVSOCKPort is the collector port from DESIGN section 11.
	defaultVSOCKPort uint32 = 9000
)

// vsockDialer dials the host collector over AF_VSOCK.
type vsockDialer struct {
	cid  uint32
	port uint32
}

// NewVSOCKDialer returns a Dialer that reaches the host collector over
// AF_VSOCK, which needs no address, route, gateway or DNS inside the guest and
// leaves no listening socket on the VM's network.
//
// A zero cid means VMADDR_CID_HOST (2) and a zero port means 9000. CID 0 is
// VMADDR_CID_HYPERVISOR and port 0 is not a connectable destination, so
// neither is a value this agent could have meant; treating them as "unset"
// turns a half-configured agent into a working one instead of a confusing
// connect failure.
func NewVSOCKDialer(cid, port uint32) Dialer {
	if cid == 0 {
		cid = cidHost
	}
	if port == 0 {
		port = defaultVSOCKPort
	}
	return &vsockDialer{cid: cid, port: port}
}

// Dial connects to the collector, giving up as soon as ctx is done.
func (d *vsockDialer) Dial(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type dialResult struct {
		conn *vsock.Conn
		err  error
	}
	// Buffered: the dial goroutine must always be able to hand off its result
	// and exit, even once nobody is waiting for it any more.
	done := make(chan dialResult, 1)
	go func() {
		c, err := vsock.Dial(d.cid, d.port, nil)
		done <- dialResult{conn: c, err: err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, vsockError("dial", d.cid, d.port, r.err)
		}
		return r.conn, nil
	case <-ctx.Done():
		// vsock.Dial takes no context and the connect(2) underneath it cannot
		// be cancelled, so the only thing left is to adopt whatever it
		// produces. Without this an established connection would survive with
		// no owner: a socket the agent can neither read nor close, and a
		// connection the collector would count as a live guest.
		go func() {
			if r := <-done; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// String describes the destination, for logs.
func (d *vsockDialer) String() string {
	return "vsock:" + (&vsock.Addr{ContextID: d.cid, Port: d.port}).String()
}

// ListenVSOCK listens for guest connections on the host.
//
// A zero cid means VMADDR_CID_ANY, because binding the collector to CID 0
// (VMADDR_CID_HYPERVISOR) would accept nothing from the VMs it is meant to
// audit, and a silently deaf collector is the worst failure this program has.
// A zero port is passed through, which asks the kernel to assign one; that is
// only useful in tests, since guests dial a fixed port.
func ListenVSOCK(cid, port uint32) (Listener, error) {
	if cid == 0 {
		cid = cidAny
	}
	l, err := vsock.ListenContextID(cid, port, nil)
	if err != nil {
		return nil, vsockError("listen", cid, port, err)
	}
	// *vsock.Listener already provides Accept, Close and Addr.
	return l, nil
}

// PeerCID returns the VSOCK context ID of the connection's remote end, and
// whether conn is a VSOCK connection at all.
//
// This is the authoritative VM identity in the whole system. The CID is
// assigned by the hypervisor and written into the address by the kernel, so a
// compromised guest can lie about its hostname, machine-id, boot-id and
// anything else it puts in HELLO, but it cannot dial from a CID that is not
// its own. Callers must therefore key their CID-to-VM mapping and their
// deduplication on this value and never on what the guest claims.
//
// A connection that is not VSOCK -- a TCP development connection, or a nil
// conn -- returns ok=false, so a caller cannot accidentally treat an
// unauthenticated peer as an identified VM.
func PeerCID(conn net.Conn) (uint32, bool) {
	if conn == nil {
		return 0, false
	}
	addr, ok := conn.RemoteAddr().(*vsock.Addr)
	if !ok || addr == nil {
		return 0, false
	}
	return addr.ContextID, true
}

// vsockError annotates a VSOCK failure, and turns the errnos a missing
// virtio-vsock device produces into something an operator can act on.
//
// This matters because the raw failure is misleading: "address family not
// supported by protocol" or "no such device" from a connect to CID 2 reads
// like an agent bug, when what is actually wrong is the VM's hardware or the
// host's kernel modules.
func vsockError(op string, cid, port uint32, err error) error {
	addr := &vsock.Addr{ContextID: cid, Port: port}
	if vsockUnavailable(err) {
		return fmt.Errorf("vsock %s %s: no AF_VSOCK transport on this system: "+
			"load the vsock kernel modules (guest: vmw_vsock_virtio_transport, host: vhost_vsock) "+
			"and give the VM a virtio-vsock device (qemu: -device vhost-vsock-pci,guest-cid=N): %w",
			op, addr, err)
	}
	return fmt.Errorf("vsock %s %s: %w", op, addr, err)
}

// vsockUnavailable reports whether err means this system has no working
// AF_VSOCK transport, as opposed to a collector that is merely down.
func vsockUnavailable(err error) bool {
	switch {
	case errors.Is(err, unix.EAFNOSUPPORT),
		// socket(AF_VSOCK) with the vsock module not loaded at all.
		errors.Is(err, unix.EPROTONOSUPPORT),
		// vsock core is loaded but no transport is bound to it, i.e. the VM
		// has no vhost-vsock-pci device.
		errors.Is(err, unix.ENODEV),
		// /dev/vsock is absent, which is how ContextID reports the same thing.
		errors.Is(err, fs.ErrNotExist):
		return true
	}
	return false
}
