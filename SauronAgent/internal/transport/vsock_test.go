package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/sys/unix"
)

// stubConn reports whatever remote address a test wants, so PeerCID can be
// exercised without a live VSOCK connection.
type stubConn struct {
	net.Conn // nil: only RemoteAddr is called
	remote   net.Addr
}

func (c stubConn) RemoteAddr() net.Addr { return c.remote }

func TestPeerCID(t *testing.T) {
	var nilVSOCKAddr *vsock.Addr

	tests := []struct {
		name    string
		conn    net.Conn
		wantCID uint32
		wantOK  bool
	}{
		{
			name:    "guest vsock connection",
			conn:    stubConn{remote: &vsock.Addr{ContextID: 102, Port: 51234}},
			wantCID: 102,
			wantOK:  true,
		},
		{
			name:    "host dialled from the hypervisor",
			conn:    stubConn{remote: &vsock.Addr{ContextID: cidHost, Port: defaultVSOCKPort}},
			wantCID: 2,
			wantOK:  true,
		},
		{
			name: "loopback cid is still a cid",
			conn: stubConn{remote: &vsock.Addr{ContextID: vsock.Local, Port: 9000}},
			// Whether CID 1 may deliver events is the collector's policy;
			// PeerCID only reports what the kernel recorded.
			wantCID: 1,
			wantOK:  true,
		},
		{
			name:   "tcp connection is not identified",
			conn:   stubConn{remote: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 9000}},
			wantOK: false,
		},
		{
			name:   "unix connection is not identified",
			conn:   stubConn{remote: &net.UnixAddr{Name: "/run/sauron.sock", Net: "unix"}},
			wantOK: false,
		},
		{
			name:   "nil conn",
			conn:   nil,
			wantOK: false,
		},
		{
			name:   "conn without a remote address",
			conn:   stubConn{remote: nil},
			wantOK: false,
		},
		{
			name:   "typed nil vsock address",
			conn:   stubConn{remote: nilVSOCKAddr},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cid, ok := PeerCID(tt.conn)
			if ok != tt.wantOK {
				t.Fatalf("PeerCID ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if cid != 0 {
					t.Errorf("PeerCID cid = %d with ok=false, want 0", cid)
				}
				return
			}
			if cid != tt.wantCID {
				t.Errorf("PeerCID cid = %d, want %d", cid, tt.wantCID)
			}
		})
	}
}

func TestVSOCKDialerString(t *testing.T) {
	tests := []struct {
		name      string
		cid, port uint32
		want      string
	}{
		{name: "host collector", cid: cidHost, port: defaultVSOCKPort, want: "vsock:host(2):9000"},
		{name: "zero means the documented defaults", cid: 0, port: 0, want: "vsock:host(2):9000"},
		{name: "explicit vm cid", cid: 102, port: 9100, want: "vsock:vm(102):9100"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewVSOCKDialer(tt.cid, tt.port).String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestVSOCKDialContextCanceled runs everywhere: the context is checked before
// any socket is created, so a machine with no VSOCK support still sees the
// cancellation rather than a device error.
func TestVSOCKDialContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	conn, err := NewVSOCKDialer(cidHost, defaultVSOCKPort).Dial(ctx)
	if err == nil {
		conn.Close()
		t.Fatal("Dial with a cancelled context returned a connection, want error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Dial error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Dial took %v with an already-cancelled context, want an immediate return", elapsed)
	}
}

func TestVSOCKErrorMapping(t *testing.T) {
	const (
		wantModules = "virtio-vsock"
		wantGuest   = "guest-cid"
	)

	tests := []struct {
		name     string
		err      error
		wantHint bool
	}{
		{
			// socket(AF_VSOCK, ...) on a kernel with no vsock module.
			name:     "address family not supported",
			err:      &net.OpError{Op: "dial", Net: "vsock", Err: unix.EAFNOSUPPORT},
			wantHint: true,
		},
		{
			// vsock core loaded, but the VM has no vhost-vsock-pci device, so
			// no transport is bound and connect fails with ENODEV.
			name:     "no transport bound",
			err:      &net.OpError{Op: "dial", Net: "vsock", Err: unix.ENODEV},
			wantHint: true,
		},
		{
			name:     "protocol not supported",
			err:      unix.EPROTONOSUPPORT,
			wantHint: true,
		},
		{
			// vsock.ContextID opens /dev/vsock, which is absent for the same
			// underlying reason.
			name:     "dev vsock missing",
			err:      &os.PathError{Op: "open", Path: "/dev/vsock", Err: unix.ENOENT},
			wantHint: true,
		},
		{
			// The collector is simply down. This must NOT be reported as a
			// missing device, or an operator will go and rebuild the VM.
			name:     "collector not listening",
			err:      &net.OpError{Op: "dial", Net: "vsock", Err: unix.ECONNRESET},
			wantHint: false,
		},
		{
			name:     "permission denied",
			err:      &os.PathError{Op: "open", Path: "/dev/vsock", Err: unix.EACCES},
			wantHint: false,
		},
		{
			name:     "unrecognised failure",
			err:      errors.New("something else entirely"),
			wantHint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vsockError("dial", cidHost, defaultVSOCKPort, tt.err)
			msg := got.Error()

			if !errors.Is(got, tt.err) {
				t.Errorf("error %q no longer wraps the original %v", msg, tt.err)
			}
			if !strings.Contains(msg, "host(2):9000") {
				t.Errorf("error = %q, want it to name the destination", msg)
			}
			hasHint := strings.Contains(msg, wantModules) && strings.Contains(msg, wantGuest)
			if hasHint != tt.wantHint {
				t.Errorf("error = %q, device hint present = %v, want %v", msg, hasHint, tt.wantHint)
			}
		})
	}
}

func TestVSOCKUnavailableDoesNotSwallowNil(t *testing.T) {
	if vsockUnavailable(nil) {
		t.Error("vsockUnavailable(nil) = true, want false")
	}
}

// requireVSOCKLoopback skips when this machine cannot talk AF_VSOCK to itself,
// which is the normal state of a CI container: the vsock_loopback module is
// not loaded and there is no virtio-vsock device.
func requireVSOCKLoopback(t *testing.T) {
	t.Helper()
	l, err := vsock.ListenContextID(vsock.Local, 0, nil)
	if err != nil {
		t.Skipf("AF_VSOCK loopback unavailable (%v); run 'modprobe vsock_loopback' or use a VM with a virtio-vsock device to exercise this test", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("closing probe listener: %v", err)
	}
}

func TestVSOCKLoopbackRoundTrip(t *testing.T) {
	requireVSOCKLoopback(t)

	l, err := ListenVSOCK(vsock.Local, 0)
	if err != nil {
		t.Fatalf("ListenVSOCK: %v", err)
	}
	defer l.Close()

	addr, ok := l.Addr().(*vsock.Addr)
	if !ok {
		t.Fatalf("Addr() = %T, want *vsock.Addr", l.Addr())
	}

	type accepted struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		accepts <- accepted{conn: c, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := NewVSOCKDialer(vsock.Local, addr.Port).Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	a := <-accepts
	if a.err != nil {
		t.Fatalf("Accept: %v", a.err)
	}
	defer a.conn.Close()

	cid, ok := PeerCID(a.conn)
	if !ok {
		t.Fatalf("PeerCID(accepted) ok = false, want true for a VSOCK connection")
	}
	if cid != vsock.Local {
		t.Errorf("PeerCID = %d, want %d for a loopback connection", cid, vsock.Local)
	}

	if _, err := client.Write(helloFrame); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, len(helloFrame))
	if err := a.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(a.conn, got); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(got) != string(helloFrame) {
		t.Errorf("server read %v, want %v", got, helloFrame)
	}
}
