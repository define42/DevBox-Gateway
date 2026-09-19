package audit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// nlMsg builds one netlink message, padded to the netlink alignment exactly as
// the kernel lays several messages out in a single datagram.
func nlMsg(typ uint16, payload []byte) []byte {
	length := unix.NLMSG_HDRLEN + len(payload)
	b := make([]byte, nlmsgAlign(length))
	binary.NativeEndian.PutUint32(b[0:4], uint32(length))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	copy(b[unix.NLMSG_HDRLEN:], payload)
	return b
}

func nlErrorMsg(errno int32) []byte {
	payload := make([]byte, 4+unix.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(payload[0:4], uint32(errno))
	return nlMsg(unix.NLMSG_ERROR, payload)
}

const syscallBody = `audit(1699887654.123:8421): arch=c000003e syscall=59 success=yes exit=0 pid=4821 comm="cat" exe="/usr/bin/cat"`

func TestParseMessagesSingleRecord(t *testing.T) {
	buf := nlMsg(uint16(TypeSyscall), []byte(syscallBody))
	received := time.Unix(1699887654, 0).UTC()

	msgs, rejected, err := parseMessages(buf, received)
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	if rejected != 0 {
		t.Errorf("rejected = %d, want 0", rejected)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Type != TypeSyscall {
		t.Errorf("Type = %d, want %d", msgs[0].Type, TypeSyscall)
	}
	if string(msgs[0].Data) != syscallBody {
		t.Errorf("Data = %q, want %q", msgs[0].Data, syscallBody)
	}
	if !msgs[0].Received.Equal(received) {
		t.Errorf("Received = %v, want %v", msgs[0].Received, received)
	}
}

func TestParseMessagesMultipleWithPadding(t *testing.T) {
	// The bodies have deliberately odd lengths so every message after the
	// first only decodes if alignment padding is handled.
	bodies := []struct {
		typ  RecordType
		body string
	}{
		{TypeSyscall, `audit(1699887654.123:8421): syscall=59 comm="cat"`},
		{TypeExecve, `audit(1699887654.123:8421): argc=2 a0="cat" a1="/etc/shadow"`},
		{TypeCwd, `audit(1699887654.123:8421): cwd="/home/user"`},
		{TypeEoe, `audit(1699887654.123:8421):`},
	}
	var buf []byte
	for _, b := range bodies {
		buf = append(buf, nlMsg(uint16(b.typ), []byte(b.body))...)
	}

	msgs, rejected, err := parseMessages(buf, time.Time{})
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	if rejected != 0 {
		t.Errorf("rejected = %d, want 0", rejected)
	}
	if len(msgs) != len(bodies) {
		t.Fatalf("got %d messages, want %d", len(msgs), len(bodies))
	}
	for i, want := range bodies {
		if msgs[i].Type != want.typ {
			t.Errorf("message %d Type = %d, want %d", i, msgs[i].Type, want.typ)
		}
		if string(msgs[i].Data) != want.body {
			t.Errorf("message %d Data = %q, want %q", i, msgs[i].Data, want.body)
		}
	}
}

func TestParseMessagesCopiesPayload(t *testing.T) {
	// The receive buffer is reused for the next datagram, so a record that
	// aliased it would silently mutate after it was handed out.
	buf := nlMsg(uint16(TypeCwd), []byte(`audit(1699887654.123:8421): cwd="/home/user"`))
	msgs, _, err := parseMessages(buf, time.Time{})
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	before := string(msgs[0].Data)

	for i := range buf {
		buf[i] = 0xff
	}
	if got := string(msgs[0].Data); got != before {
		t.Errorf("Data changed with the receive buffer: %q, want %q", got, before)
	}
}

func TestParseMessagesSkipsNoopAndDone(t *testing.T) {
	var buf []byte
	buf = append(buf, nlMsg(unix.NLMSG_NOOP, nil)...)
	buf = append(buf, nlMsg(uint16(TypeSyscall), []byte(syscallBody))...)
	buf = append(buf, nlMsg(unix.NLMSG_DONE, nil)...)

	msgs, rejected, err := parseMessages(buf, time.Time{})
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	if rejected != 0 {
		t.Errorf("rejected = %d, want 0: NOOP and DONE are framing, not rejections", rejected)
	}
	if len(msgs) != 1 || msgs[0].Type != TypeSyscall {
		t.Fatalf("got %v, want just the SYSCALL record", msgs)
	}
}

func TestParseMessagesRejectsNonAuditTypes(t *testing.T) {
	tests := []struct {
		name string
		typ  uint16
	}{
		{"rtnetlink RTM_NEWLINK", 16},
		{"below the audit range", 999},
		{"above the audit range", 3000},
		{"generic netlink", 0x10},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf []byte
			buf = append(buf, nlMsg(tc.typ, []byte("bogus=1"))...)
			buf = append(buf, nlMsg(uint16(TypeSyscall), []byte(syscallBody))...)

			msgs, rejected, err := parseMessages(buf, time.Time{})
			if err != nil {
				t.Fatalf("parseMessages: %v", err)
			}
			if rejected != 1 {
				t.Errorf("rejected = %d, want 1", rejected)
			}
			// A rejected message must not cost us the good record beside it.
			if len(msgs) != 1 || msgs[0].Type != TypeSyscall {
				t.Fatalf("got %v, want just the SYSCALL record", msgs)
			}
		})
	}
}

func TestParseMessagesNetlinkError(t *testing.T) {
	buf := nlErrorMsg(-int32(unix.EPERM))

	msgs, _, err := parseMessages(buf, time.Time{})
	if err == nil {
		t.Fatalf("parseMessages = %v, want an error", msgs)
	}
	if !errors.Is(err, errBadDatagram) {
		t.Errorf("error %v does not wrap errBadDatagram", err)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Errorf("error %v does not carry the kernel's EPERM", err)
	}
}

func TestParseMessagesNetlinkAck(t *testing.T) {
	// errno 0 is an acknowledgement, not a failure.
	msgs, rejected, err := parseMessages(nlErrorMsg(0), time.Time{})
	if err != nil {
		t.Fatalf("parseMessages: %v", err)
	}
	if len(msgs) != 0 || rejected != 0 {
		t.Errorf("got %d messages and %d rejections, want none", len(msgs), rejected)
	}
}

func TestParseMessagesMalformed(t *testing.T) {
	good := nlMsg(uint16(TypeSyscall), []byte(syscallBody))

	tests := []struct {
		name         string
		buf          []byte
		wantDecoded  int
		wantContains string
	}{
		{
			name:         "length shorter than the header",
			buf:          func() []byte { b := append([]byte(nil), good...); binary.NativeEndian.PutUint32(b[0:4], 4); return b }(),
			wantDecoded:  0,
			wantContains: "out of range",
		},
		{
			name: "length past the end of the datagram",
			buf: func() []byte {
				b := append([]byte(nil), good...)
				binary.NativeEndian.PutUint32(b[0:4], 1<<20)
				return b
			}(),
			wantDecoded:  0,
			wantContains: "out of range",
		},
		{
			name:         "zero length",
			buf:          func() []byte { b := append([]byte(nil), good...); binary.NativeEndian.PutUint32(b[0:4], 0); return b }(),
			wantDecoded:  0,
			wantContains: "out of range",
		},
		{
			name:         "trailing bytes shorter than a header",
			buf:          append(append([]byte(nil), good...), 1, 2, 3, 4),
			wantDecoded:  1,
			wantContains: "trailing bytes",
		},
		{
			name:         "truncated second message",
			buf:          append(append([]byte(nil), good...), nlMsg(uint16(TypeExecve), []byte("audit(1.000:2): argc=0"))[:20]...),
			wantDecoded:  1,
			wantContains: "out of range",
		},
		{
			name:         "NLMSG_ERROR with a short payload",
			buf:          nlMsg(unix.NLMSG_ERROR, []byte{1, 2}),
			wantDecoded:  0,
			wantContains: "NLMSG_ERROR payload",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msgs, _, err := parseMessages(tc.buf, time.Time{})
			if err == nil {
				t.Fatalf("parseMessages = %v, want an error", msgs)
			}
			if !errors.Is(err, errBadDatagram) {
				t.Errorf("error %v does not wrap errBadDatagram", err)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.wantContains)) {
				t.Errorf("error %q does not mention %q", err, tc.wantContains)
			}
			// Records decoded before the framing error are still evidence.
			if len(msgs) != tc.wantDecoded {
				t.Errorf("decoded %d messages, want %d", len(msgs), tc.wantDecoded)
			}
		})
	}
}

func TestParseMessagesEmpty(t *testing.T) {
	msgs, rejected, err := parseMessages(nil, time.Time{})
	if err != nil || len(msgs) != 0 || rejected != 0 {
		t.Fatalf("parseMessages(nil) = %v, %d, %v; want no messages and no error", msgs, rejected, err)
	}
}

func TestFromKernel(t *testing.T) {
	tests := []struct {
		name string
		sa   unix.Sockaddr
		want bool
	}{
		{"kernel", &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0}, true},
		{"local process", &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 4821}, false},
		{"local process with groups", &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 1, Groups: 1}, false},
		{"not netlink at all", &unix.SockaddrInet4{Port: 9000}, false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fromKernel(tc.sa); got != tc.want {
				t.Errorf("fromKernel(%#v) = %v, want %v", tc.sa, got, tc.want)
			}
		})
	}
}

func TestIsPermission(t *testing.T) {
	if !isPermission(unix.EPERM) || !isPermission(unix.EACCES) {
		t.Error("EPERM and EACCES must be recognised so the CAP_AUDIT_READ hint is shown")
	}
	if isPermission(unix.ENOBUFS) || isPermission(nil) {
		t.Error("only permission errors may be treated as a missing capability")
	}
}

func TestNlmsgAlign(t *testing.T) {
	tests := []struct{ in, want int }{
		{0, 0}, {1, 4}, {3, 4}, {4, 4}, {5, 8}, {16, 16}, {17, 20}, {8970, 8972},
	}
	for _, tc := range tests {
		if got := nlmsgAlign(tc.in); got != tc.want {
			t.Errorf("nlmsgAlign(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestSetReceiveDeadline(t *testing.T) {
	// The deadline bookkeeping is pure, so it is checked without a socket.
	c := &NetlinkConn{fd: -1}

	if got := c.deadline(); !got.IsZero() {
		t.Errorf("deadline() = %v on a fresh conn, want the zero time", got)
	}

	want := time.Unix(1699887654, 123456789)
	if err := c.SetReceiveDeadline(want); err != nil {
		t.Fatalf("SetReceiveDeadline: %v", err)
	}
	if got := c.deadline(); !got.Equal(want) {
		t.Errorf("deadline() = %v, want %v", got, want)
	}

	if err := c.SetReceiveDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReceiveDeadline(zero): %v", err)
	}
	if got := c.deadline(); !got.IsZero() {
		t.Errorf("deadline() = %v after clearing, want the zero time", got)
	}

	// The Unix epoch collides with the "no deadline" sentinel and must still
	// read back as a deadline rather than as "none".
	if err := c.SetReceiveDeadline(time.Unix(0, 0)); err != nil {
		t.Fatalf("SetReceiveDeadline(epoch): %v", err)
	}
	if got := c.deadline(); got.IsZero() {
		t.Error("a deadline at the Unix epoch read back as no deadline")
	}

	c.closed = true
	if err := c.SetReceiveDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetReceiveDeadline on a closed conn = %v, want net.ErrClosed", err)
	}
}

// dialForTest opens a real multicast socket or skips.
func dialForTest(t *testing.T) *NetlinkConn {
	t.Helper()
	c, err := Dial(1 << 20)
	if err != nil {
		t.Skipf("cannot open the NETLINK_AUDIT multicast socket (%v); "+
			"this test needs CAP_AUDIT_READ, so run it as root or after "+
			"setcap cap_audit_read+ep on the test binary", err)
	}
	return c
}

func TestDialAndReceiveDeadline(t *testing.T) {
	c := dialForTest(t)
	defer c.Close()

	// With a deadline in the near future and (probably) no audit traffic, the
	// receive must give up rather than block the collector forever.
	if err := c.SetReceiveDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReceiveDeadline: %v", err)
	}
	start := time.Now()
	msgs, err := c.Receive()
	elapsed := time.Since(start)

	switch {
	case err == nil:
		// A busy machine may genuinely deliver records; that is fine.
		if len(msgs) == 0 {
			t.Error("Receive returned no records and no error")
		}
	case errors.Is(err, os.ErrDeadlineExceeded):
		if elapsed > 5*time.Second {
			t.Errorf("Receive honoured the deadline only after %v", elapsed)
		}
	case errors.Is(err, ErrKernelOverrun):
		// Also acceptable: it means the kernel dropped records, which is
		// exactly what the sentinel exists to report.
	default:
		t.Fatalf("Receive: %v", err)
	}

	if c.Rejected() != 0 {
		t.Errorf("Rejected() = %d, want 0 on a quiet socket", c.Rejected())
	}
}

func TestCloseIsIdempotentAndStopsReceive(t *testing.T) {
	c := dialForTest(t)

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if _, err := c.Receive(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Receive after Close = %v, want net.ErrClosed", err)
	}
	if err := c.SetReceiveDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetReceiveDeadline after Close = %v, want net.ErrClosed", err)
	}
}

func TestCloseUnblocksReceive(t *testing.T) {
	c := dialForTest(t)

	done := make(chan error, 1)
	go func() {
		// No deadline: this blocks in recvfrom until Close is observed.
		_, err := c.Receive()
		done <- err
	}()

	// Close must wait for the in-flight recvfrom instead of yanking the
	// descriptor out from under it.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, ErrKernelOverrun) {
			t.Errorf("Receive = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Receive did not return after Close")
	}
}

func TestNewListenerRequiresCapability(t *testing.T) {
	l, err := NewListener(ListenerOptions{ReceiveBuffer: 1 << 20})
	if err != nil {
		// The message has to name the capability: an operator seeing only
		// "operation not permitted" has nothing to act on.
		if isPermission(err) && !bytes.Contains([]byte(err.Error()), []byte("CAP_AUDIT_READ")) {
			t.Errorf("permission error %q does not name CAP_AUDIT_READ", err)
		}
		t.Skipf("cannot open the NETLINK_AUDIT multicast socket (%v); this test needs CAP_AUDIT_READ", err)
	}
	defer l.Close()

	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
