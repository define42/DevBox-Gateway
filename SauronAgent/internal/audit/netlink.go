package audit

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrKernelOverrun reports that the kernel could not fit a multicast audit
// record into this socket's receive queue and therefore discarded it.
//
// It is deliberately a distinct sentinel rather than an ordinary receive
// error. Records lost inside the kernel are invisible everywhere else -- there
// is no sequence number in the multicast stream to notice a gap with -- so an
// ENOBUFS is the only evidence that the guest's audit trail has a hole in it.
// The caller must turn it into a "records lost" event rather than retrying
// quietly, and must not treat it as fatal: the socket stays usable.
var ErrKernelOverrun = errors.New("audit: kernel receive buffer overrun, audit records were lost")

// errBadDatagram marks a datagram that could not be decoded as netlink, or
// that carried an NLMSG_ERROR. It is not fatal: the socket is still healthy,
// only this one datagram is unusable, so the listener counts it and continues
// rather than tearing the collector down over one bad message.
var errBadDatagram = errors.New("audit: malformed netlink datagram")

const (
	// defaultReceiveBuffer is used when the caller asks for no particular
	// size. Audit bursts are large and short: a fork-heavy build or a package
	// upgrade produces tens of thousands of records in a second, and anything
	// that does not fit in the socket buffer is dropped by the kernel, not
	// queued. 4 MiB is therefore a correctness floor, not tuning.
	defaultReceiveBuffer = 4 << 20

	// datagramBufferSize bounds a single netlink datagram. The kernel caps an
	// audit record at MAX_AUDIT_MESSAGE_LENGTH (8970 bytes), so 64 KiB holds
	// any record with room to spare for several messages per datagram.
	datagramBufferSize = 64 << 10

	// receivePollInterval is the longest a blocked recvfrom may sit in the
	// kernel. Close() cannot pull the file descriptor out from under a
	// blocked reader without risking the fd number being reused by another
	// goroutine, so instead every receive is bounded by SO_RCVTIMEO and the
	// reader re-checks the closed flag between attempts.
	receivePollInterval = 250 * time.Millisecond

	// minReceiveTimeout keeps SO_RCVTIMEO strictly positive. A zero timeval
	// means "block forever" to the kernel, which would defeat Close().
	minReceiveTimeout = time.Microsecond

	// auditTypeMin and auditTypeMax bound the netlink message types that can
	// legitimately carry an audit record (AUDIT_GET .. AUDIT_LAST_USER_MSG2).
	// Anything outside the range is not an audit record and is rejected.
	auditTypeMin = RecordType(1000)
	auditTypeMax = RecordType(2999)

	// capHint names the capability an operator has to grant. EPERM on this
	// socket is almost always a missing capability rather than a real
	// configuration error, and guessing wastes an operator's afternoon.
	capHint = "the process needs CAP_AUDIT_READ (for example AmbientCapabilities=CAP_AUDIT_READ in the systemd unit)"
)

// NetlinkConn is a read-only NETLINK_AUDIT multicast socket.
//
// It joins AUDIT_NLGRP_READLOG, which requires only CAP_AUDIT_READ and, unlike
// AUDIT_SET with an audit pid, does not make this process the audit daemon.
// A standard auditd can therefore keep running alongside SauronAgent.
type NetlinkConn struct {
	// fdMu guards the lifetime of fd. Receivers hold it for reading across a
	// single recvfrom; Close takes it for writing, so the descriptor is only
	// closed once no syscall is in flight on it.
	fdMu   sync.RWMutex
	fd     int
	closed bool

	// recvMu serialises receivers, because buf is reused between calls.
	recvMu sync.Mutex
	buf    []byte

	// curTimeout is the SO_RCVTIMEO currently programmed on the socket. It is
	// only read and written from the receive path, under recvMu, and exists so
	// the steady state costs no setsockopt per datagram.
	curTimeout time.Duration

	// deadlineNs is the receive deadline in Unix nanoseconds, 0 for none. It
	// is atomic because SetReceiveDeadline is the one operation a supervising
	// goroutine performs while a receive is blocked.
	deadlineNs atomic.Int64

	// rejected counts messages discarded because they did not come from the
	// kernel or were not audit records. Rejections are counted rather than
	// returned as errors so that a local process cannot stop collection
	// simply by spraying the socket.
	rejected atomic.Uint64
}

// Dial opens the NETLINK_AUDIT multicast socket and subscribes to the
// read-only audit log group.
//
// receiveBuffer requests a socket receive buffer of that many bytes; zero or
// less selects a built-in default.
func Dial(receiveBuffer int) (*NetlinkConn, error) {
	c, err := dial(receiveBuffer, 0)
	if err != nil {
		return nil, err
	}

	err = unix.SetsockoptInt(c.fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, AUDIT_NLGRP_READLOG)
	if err == nil {
		return c, nil
	}
	_ = c.Close()

	if isPermission(err) {
		return nil, fmt.Errorf("audit: joining the NETLINK_AUDIT read-log multicast group: %w (%s)", err, capHint)
	}

	// Kernels that predate NETLINK_ADD_MEMBERSHIP support for audit groups
	// only accept the subscription as part of bind(), as a group bitmask.
	fallback, ferr := dial(receiveBuffer, 1<<(AUDIT_NLGRP_READLOG-1))
	if ferr != nil {
		return nil, fmt.Errorf("audit: joining the audit multicast group: %w; binding to the group directly also failed: %w", err, ferr)
	}
	return fallback, nil
}

// dial creates and binds the socket. groups is the bind-time multicast bitmask,
// normally zero because the group is joined with setsockopt afterwards.
func dial(receiveBuffer int, groups uint32) (*NetlinkConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		if isPermission(err) {
			return nil, fmt.Errorf("audit: opening NETLINK_AUDIT socket: %w (%s)", err, capHint)
		}
		return nil, fmt.Errorf("audit: opening NETLINK_AUDIT socket: %w", err)
	}

	if receiveBuffer <= 0 {
		receiveBuffer = defaultReceiveBuffer
	}
	// Size the buffer before subscribing, so that no burst can arrive while
	// the socket is still using the small default.
	if err := setReceiveBuffer(fd, receiveBuffer); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	// Pid 0 asks the kernel to allocate the port id. Choosing one ourselves
	// would collide with any other netlink user in the same process.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		if isPermission(err) {
			return nil, fmt.Errorf("audit: binding NETLINK_AUDIT socket: %w (%s)", err, capHint)
		}
		return nil, fmt.Errorf("audit: binding NETLINK_AUDIT socket: %w", err)
	}

	c := &NetlinkConn{fd: fd, buf: make([]byte, datagramBufferSize)}
	if err := c.setTimeout(receivePollInterval); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return c, nil
}

// setReceiveBuffer enlarges SO_RCVBUF, preferring SO_RCVBUFFORCE so that a
// deployment with CAP_NET_ADMIN can exceed net.core.rmem_max. Without the
// capability that call fails with EPERM and the ordinary option is used, which
// the kernel silently clamps to rmem_max.
func setReceiveBuffer(fd, n int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, n); err == nil {
		return nil
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, n); err != nil {
		return fmt.Errorf("audit: setting netlink receive buffer to %d bytes: %w", n, err)
	}
	return nil
}

// setTimeout programs SO_RCVTIMEO. The caller must hold at least fdMu for
// reading, and must not pass a non-positive duration.
func (c *NetlinkConn) setTimeout(d time.Duration) error {
	if d < minReceiveTimeout {
		d = minReceiveTimeout
	}
	tv := unix.NsecToTimeval(int64(d))
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("audit: setting netlink receive timeout: %w", err)
	}
	c.curTimeout = d
	return nil
}

// SetReceiveDeadline sets the time after which Receive gives up and returns an
// error wrapping os.ErrDeadlineExceeded. The zero time clears the deadline.
//
// It is safe to call while another goroutine is blocked in Receive, and is the
// intended way to interrupt one: setting a deadline in the past wakes the
// receiver within at most one internal poll interval.
func (c *NetlinkConn) SetReceiveDeadline(t time.Time) error {
	c.fdMu.RLock()
	defer c.fdMu.RUnlock()
	if c.closed {
		return net.ErrClosed
	}
	if t.IsZero() {
		c.deadlineNs.Store(0)
		return nil
	}
	ns := t.UnixNano()
	if ns == 0 {
		// Zero is the "no deadline" sentinel; nudge the epoch instant by 1ns
		// rather than accidentally clearing a deadline the caller set.
		ns = 1
	}
	c.deadlineNs.Store(ns)
	return nil
}

// deadline returns the current receive deadline, or the zero time if none.
func (c *NetlinkConn) deadline() time.Time {
	ns := c.deadlineNs.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Rejected returns the running total of netlink messages discarded because
// they did not originate from the kernel or were not audit record types.
//
// A non-zero value is security-relevant: the only way to reach this socket is
// from inside the guest, so it means some local process attempted to inject
// records into the audit stream.
func (c *NetlinkConn) Rejected() uint64 { return c.rejected.Load() }

// Close shuts the socket down. It is safe to call concurrently with Receive
// and more than once.
//
// Close waits for an in-flight recvfrom to return before closing the
// descriptor -- bounded by the internal poll interval -- because closing a
// descriptor another goroutine is blocked on is a use-after-free in disguise:
// the number can be handed straight back out by the next open() in the
// process and the blocked reader would then read a stranger's file.
func (c *NetlinkConn) Close() error {
	c.fdMu.Lock()
	defer c.fdMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if err := unix.Close(c.fd); err != nil {
		return fmt.Errorf("audit: closing netlink socket: %w", err)
	}
	return nil
}

// Receive returns the audit records carried by one netlink datagram.
//
// Datagrams that carry nothing usable -- only NLMSG_NOOP, or a forged source
// address -- are skipped and the next one is read, so Receive returns either
// at least one record, an error, or nothing once the receive deadline passes.
// Each returned RawMessage owns a copy of its payload; the receive buffer is
// reused on the next call.
//
// A non-nil error may accompany a non-empty slice: when a datagram turns out
// to be malformed part way through, the records decoded before that point are
// still returned so that they are not lost along with the framing error.
//
// Callers must distinguish three errors: ErrKernelOverrun means records were
// dropped inside the kernel, errors wrapping os.ErrDeadlineExceeded mean the
// deadline passed, and net.ErrClosed means the socket was closed.
func (c *NetlinkConn) Receive() ([]RawMessage, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for {
		n, from, err := c.receiveOnce()
		switch {
		case err == nil:
			// fall through to decoding
		case errors.Is(err, unix.EINTR):
			// A signal (profiling, SIGURG from the Go runtime) interrupted the
			// syscall. That is not a failure of the audit stream.
			continue
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK):
			if dl := c.deadline(); !dl.IsZero() && !time.Now().Before(dl) {
				return nil, fmt.Errorf("audit: netlink receive: %w", os.ErrDeadlineExceeded)
			}
			continue
		case errors.Is(err, unix.ENOBUFS):
			return nil, fmt.Errorf("audit: netlink receive: %w", ErrKernelOverrun)
		default:
			return nil, err
		}

		// The audit multicast group is reachable by any process in the guest
		// that can open a netlink socket. Without this check a local attacker
		// could unicast fabricated SYSCALL records at our port id and have
		// them forwarded to the collector as kernel evidence.
		if !fromKernel(from) {
			c.rejected.Add(1)
			continue
		}

		msgs, rejected, perr := parseMessages(c.buf[:n], time.Now())
		if rejected > 0 {
			c.rejected.Add(rejected)
		}
		if perr != nil {
			return msgs, perr
		}
		if len(msgs) == 0 {
			continue
		}
		return msgs, nil
	}
}

// receiveOnce performs a single bounded recvfrom.
func (c *NetlinkConn) receiveOnce() (int, unix.Sockaddr, error) {
	timeout := receivePollInterval
	if dl := c.deadline(); !dl.IsZero() {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return 0, nil, unix.EAGAIN
		}
		if remaining < timeout {
			timeout = remaining
		}
	}

	c.fdMu.RLock()
	defer c.fdMu.RUnlock()
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	if timeout != c.curTimeout {
		if err := c.setTimeout(timeout); err != nil {
			return 0, nil, err
		}
	}
	return unix.Recvfrom(c.fd, c.buf, 0)
}

// fromKernel reports whether a netlink source address is the kernel itself.
// The kernel always uses port id 0; every user-space sender has a non-zero
// port id assigned at bind time, so this is a reliable origin check.
func fromKernel(sa unix.Sockaddr) bool {
	nl, ok := sa.(*unix.SockaddrNetlink)
	return ok && nl.Pid == 0
}

// isPermission reports whether err is the kernel refusing us for lack of
// privilege, which for this socket means a missing CAP_AUDIT_READ.
func isPermission(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

// nlmsgAlign rounds a netlink message length up to the message alignment.
func nlmsgAlign(n int) int {
	return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
}

// parseMessages splits one netlink datagram into audit records.
//
// It returns the records it decoded, how many messages it rejected as
// non-audit types, and an error if the datagram was malformed. Records decoded
// before a framing error are still returned: half a datagram of genuine audit
// evidence is worth more than a clean error.
func parseMessages(b []byte, received time.Time) ([]RawMessage, uint64, error) {
	var (
		msgs     []RawMessage
		rejected uint64
	)

	for len(b) > 0 {
		if len(b) < unix.NLMSG_HDRLEN {
			return msgs, rejected, fmt.Errorf("%w: %d trailing bytes are shorter than a netlink header", errBadDatagram, len(b))
		}
		// Netlink headers are in host byte order, not network order.
		length := int(binary.NativeEndian.Uint32(b[0:4]))
		msgType := binary.NativeEndian.Uint16(b[4:6])

		// Every subsequent slice is derived from length, so it is validated
		// against what actually arrived before anything is indexed with it.
		if length < unix.NLMSG_HDRLEN || length > len(b) {
			return msgs, rejected, fmt.Errorf("%w: nlmsg_len %d is out of range for %d available bytes", errBadDatagram, length, len(b))
		}
		payload := b[unix.NLMSG_HDRLEN:length]

		switch {
		case msgType == unix.NLMSG_NOOP || msgType == unix.NLMSG_DONE:
			// Padding and end-of-dump markers carry no record.
		case msgType == unix.NLMSG_ERROR:
			if len(payload) < 4 {
				return msgs, rejected, fmt.Errorf("%w: NLMSG_ERROR payload is %d bytes, want at least 4", errBadDatagram, len(payload))
			}
			code := int32(binary.NativeEndian.Uint32(payload[0:4]))
			if code != 0 {
				return msgs, rejected, fmt.Errorf("%w: kernel reported %w", errBadDatagram, unix.Errno(-code))
			}
		default:
			t := RecordType(msgType)
			if t < auditTypeMin || t > auditTypeMax {
				rejected++
				break
			}
			// The receive buffer is reused, so the record has to own its bytes.
			data := make([]byte, len(payload))
			copy(data, payload)
			msgs = append(msgs, RawMessage{Type: t, Data: data, Received: received})
		}

		advance := nlmsgAlign(length)
		if advance >= len(b) {
			// Trailing alignment padding, nothing more to decode.
			break
		}
		b = b[advance:]
	}
	return msgs, rejected, nil
}
