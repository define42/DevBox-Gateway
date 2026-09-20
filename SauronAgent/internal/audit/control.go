package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// This control socket is separate from the multicast event socket. Only the
// startup goroutine owns it, and closing it never interrupts event collection.
type controlSocket struct{ fd int }

type auditControlTransport interface {
	send([]byte) error
	receive([]byte) (int, unix.Sockaddr, error)
}

type auditControlClient struct {
	transport auditControlTransport
	sequence  uint32
}

type controlReply struct {
	messageType uint16
	flags       uint16
	sequence    uint32
	payload     []byte
}

func openControlSocket() (*controlSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &controlSocket{fd: fd}, nil
}

func (s *controlSocket) send(payload []byte) error {
	return unix.Sendto(s.fd, payload, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func (s *controlSocket) receive(buffer []byte) (int, unix.Sockaddr, error) {
	n, _, flags, from, err := unix.Recvmsg(s.fd, buffer, nil, 0)
	if err == nil && flags&unix.MSG_TRUNC != 0 {
		return 0, nil, errors.New("audit: truncated control reply")
	}
	return n, from, err
}

func (s *controlSocket) close() { _ = unix.Close(s.fd) }

func (c *auditControlClient) enabled(ctx context.Context) (uint32, error) {
	replies, err := c.exchange(ctx, unix.AUDIT_GET, nil)
	if err != nil {
		return 0, controlError("reading kernel audit status", err)
	}
	if len(replies) != 1 || len(replies[0]) < 40 {
		return 0, errors.New("audit: malformed kernel audit status")
	}
	enabled := binary.NativeEndian.Uint32(replies[0][4:8])
	if enabled > 2 {
		return 0, fmt.Errorf("audit: unexpected kernel audit enabled state %d", enabled)
	}
	return enabled, nil
}

func (c *auditControlClient) rules(ctx context.Context) ([]auditRule, error) {
	replies, err := c.exchange(ctx, unix.AUDIT_LIST_RULES, nil)
	if err != nil {
		return nil, controlError("listing kernel audit rules", err)
	}
	rules := make([]auditRule, 0, len(replies))
	for _, payload := range replies {
		rule, err := parseKernelRule(payload)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (c *auditControlClient) exchange(ctx context.Context, messageType uint16, payload []byte) ([][]byte, error) {
	c.sequence++
	request := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], messageType)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], c.sequence)
	copy(request[unix.NLMSG_HDRLEN:], payload)
	if err := c.send(ctx, request); err != nil {
		return nil, err
	}
	return c.readReplies(ctx, messageType)
}

func (c *auditControlClient) send(ctx context.Context, request []byte) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.transport.send(request)
		if !retryControlIO(err) {
			return err
		}
		if err := waitControlIO(ctx); err != nil {
			return err
		}
	}
}

func (c *auditControlClient) receive(ctx context.Context, buffer []byte) ([]controlReply, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, sender, err := c.transport.receive(buffer)
		if retryControlIO(err) {
			if err := waitControlIO(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		if !fromKernel(sender) {
			continue
		}
		return parseControlReplies(buffer[:n])
	}
}

func (c *auditControlClient) readReplies(ctx context.Context, messageType uint16) ([][]byte, error) {
	buffer := make([]byte, datagramBufferSize)
	var replies [][]byte
	var acknowledged, completed bool
	var responseBytes int
	for !acknowledged || !completed {
		messages, err := c.receive(ctx, buffer)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.sequence != c.sequence {
				continue
			}
			if message.flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, errors.New("audit: kernel interrupted audit-rule dump")
			}
			ack, done, err := acceptControlReply(message, messageType)
			if err != nil {
				return nil, err
			}
			acknowledged = acknowledged || ack
			completed = completed || done
			if message.messageType == messageType {
				responseBytes += len(message.payload)
				if responseBytes > 16<<20 || len(replies) >= 16384 {
					return nil, errors.New("audit: kernel audit-rule dump exceeds startup limit")
				}
				replies = append(replies, message.payload)
			}
		}
	}
	return replies, nil
}

func acceptControlReply(reply controlReply, requestType uint16) (ack, done bool, err error) {
	switch reply.messageType {
	case unix.NLMSG_ERROR:
		if len(reply.payload) < 4+unix.NLMSG_HDRLEN {
			return false, false, errors.New("audit: truncated netlink acknowledgement")
		}
		if binary.NativeEndian.Uint16(reply.payload[8:10]) != requestType || binary.NativeEndian.Uint32(reply.payload[12:16]) != reply.sequence {
			return false, false, errors.New("audit: netlink acknowledgement does not match the request")
		}
		if err := controlReplyError(reply.payload); err != nil {
			return false, false, err
		}
		return true, requestType != unix.AUDIT_GET && requestType != unix.AUDIT_LIST_RULES, nil
	case unix.NLMSG_DONE:
		if requestType != unix.AUDIT_LIST_RULES {
			return false, false, errors.New("audit: unexpected netlink dump completion")
		}
		if len(reply.payload) != 0 {
			if err := controlReplyError(reply.payload); err != nil {
				return false, false, err
			}
		}
		return false, true, nil
	case requestType:
		if requestType != unix.AUDIT_GET && requestType != unix.AUDIT_LIST_RULES {
			return false, false, errors.New("audit: unexpected netlink control payload")
		}
		return false, requestType == unix.AUDIT_GET, nil
	default:
		return false, false, fmt.Errorf("audit: unexpected netlink reply type %d", reply.messageType)
	}
}

func controlReplyError(payload []byte) error {
	if len(payload) < 4 {
		return errors.New("audit: truncated netlink error code")
	}
	code := int32(binary.NativeEndian.Uint32(payload[:4]))
	if code > 0 {
		return errors.New("audit: invalid positive netlink error code")
	}
	if code < 0 {
		return unix.Errno(-int64(code))
	}
	return nil
}

func parseControlReplies(buffer []byte) ([]controlReply, error) {
	var replies []controlReply
	for len(buffer) != 0 {
		if len(buffer) < unix.NLMSG_HDRLEN {
			return nil, errors.New("audit: truncated netlink control header")
		}
		length := uint64(binary.NativeEndian.Uint32(buffer[:4]))
		if length < unix.NLMSG_HDRLEN || length > uint64(len(buffer)) {
			return nil, errors.New("audit: invalid netlink control message length")
		}
		replies = append(replies, controlReply{
			messageType: binary.NativeEndian.Uint16(buffer[4:6]),
			flags:       binary.NativeEndian.Uint16(buffer[6:8]),
			sequence:    binary.NativeEndian.Uint32(buffer[8:12]),
			payload:     append([]byte(nil), buffer[unix.NLMSG_HDRLEN:length]...),
		})
		advance := nlmsgAlign(int(length))
		if advance >= len(buffer) {
			break
		}
		buffer = buffer[advance:]
	}
	return replies, nil
}

func retryControlIO(err error) bool {
	return errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN)
}

func waitControlIO(ctx context.Context) error {
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
