package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestControlExchangeAuthenticatesKernelAndSequence(t *testing.T) {
	t.Parallel()
	transport := &scriptedControlTransport{onSend: func(request []byte) []controlPacket {
		wrongSequence := slices.Clone(request)
		binary.NativeEndian.PutUint32(wrongSequence[8:12], 999)
		return []controlPacket{
			{data: controlACK(request, unix.EPERM), senderPID: 1234},
			{data: controlACK(wrongSequence, unix.EPERM)},
			{data: controlACK(request, 0)},
		}
	}}
	client := &auditControlClient{transport: transport}
	if _, err := client.exchange(t.Context(), unix.AUDIT_ADD_RULE, nil); err != nil {
		t.Fatal(err)
	}
	if len(transport.queue) != 0 {
		t.Fatal("did not read the genuine acknowledgement")
	}
}

func TestControlExchangeHandlesAcknowledgementBeforePayload(t *testing.T) {
	t.Parallel()
	transport := &scriptedControlTransport{onSend: func(request []byte) []controlPacket {
		status := make([]byte, 40)
		binary.NativeEndian.PutUint32(status[4:8], 2)
		return []controlPacket{
			{data: controlACK(request, 0)},
			{data: controlMessage(unix.AUDIT_GET, 1, status)},
		}
	}}
	client := &auditControlClient{transport: transport}
	state, err := client.enabled(t.Context())
	if err != nil || state != 2 {
		t.Fatalf("state=%d error=%v", state, err)
	}
}

func TestControlExchangeRequiresCompleteReply(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		typ   uint16
		reply func([]byte) []byte
	}{
		{name: "missing acknowledgement", typ: unix.AUDIT_GET, reply: func(_ []byte) []byte {
			return controlMessage(unix.AUDIT_GET, 1, make([]byte, 40))
		}},
		{name: "missing status", typ: unix.AUDIT_GET, reply: func(request []byte) []byte { return controlACK(request, 0) }},
		{name: "missing dump terminator", typ: unix.AUDIT_LIST_RULES, reply: func(request []byte) []byte { return controlACK(request, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			transport := &scriptedControlTransport{onSend: func(request []byte) []controlPacket {
				return []controlPacket{{data: tc.reply(request)}}
			}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
			defer cancel()
			client := &auditControlClient{transport: transport}
			if _, err := client.exchange(ctx, tc.typ, nil); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error=%v, want deadline exceeded", err)
			}
		})
	}
}

func TestControlExchangeRejectsMalformedReplies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		reply func([]byte) []byte
		want  string
	}{
		{name: "short header", reply: func(_ []byte) []byte { return []byte{1} }, want: "header"},
		{name: "oversize length", reply: func(request []byte) []byte {
			data := controlACK(request, 0)
			binary.NativeEndian.PutUint32(data[:4], 0xffffffff)
			return data
		}, want: "length"},
		{name: "truncated ACK", reply: func(_ []byte) []byte { return controlMessage(unix.NLMSG_ERROR, 1, make([]byte, 4)) }, want: "acknowledgement"},
		{name: "ACK wrong original type", reply: func(request []byte) []byte {
			data := controlACK(request, 0)
			binary.NativeEndian.PutUint16(data[24:26], unix.AUDIT_SET)
			return data
		}, want: "does not match"},
		{name: "ACK wrong original sequence", reply: func(request []byte) []byte {
			data := controlACK(request, 0)
			binary.NativeEndian.PutUint32(data[28:32], 99)
			return data
		}, want: "does not match"},
		{name: "positive errno", reply: func(request []byte) []byte {
			data := controlACK(request, 0)
			binary.NativeEndian.PutUint32(data[16:20], 1)
			return data
		}, want: "positive"},
		{name: "unexpected response type", reply: func(_ []byte) []byte { return controlMessage(unix.AUDIT_SET, 1, nil) }, want: "unexpected"},
		{name: "interrupted dump", reply: func(_ []byte) []byte {
			data := controlMessage(unix.NLMSG_DONE, 1, nil)
			binary.NativeEndian.PutUint16(data[6:8], unix.NLM_F_DUMP_INTR)
			return data
		}, want: "interrupted"},
		{name: "short DONE status", reply: func(_ []byte) []byte { return controlMessage(unix.NLMSG_DONE, 1, []byte{0}) }, want: "truncated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			transport := &scriptedControlTransport{onSend: func(request []byte) []controlPacket {
				return []controlPacket{{data: tc.reply(request)}}
			}}
			client := &auditControlClient{transport: transport}
			_, err := client.exchange(t.Context(), unix.AUDIT_LIST_RULES, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestControlExchangePropagatesIOAndKernelErrors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		transport scriptedControlTransport
		want      error
	}{
		{name: "send", transport: scriptedControlTransport{sendErr: unix.ENOBUFS}, want: unix.ENOBUFS},
		{name: "receive", transport: scriptedControlTransport{receiveErr: unix.ENOBUFS}, want: unix.ENOBUFS},
		{name: "negative ACK", transport: scriptedControlTransport{onSend: func(request []byte) []controlPacket {
			return []controlPacket{{data: controlACK(request, unix.EPERM)}}
		}}, want: unix.EPERM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &auditControlClient{transport: &tc.transport}
			if _, err := client.exchange(t.Context(), unix.AUDIT_SET, nil); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestControlExchangeCancelsBlockedSend(t *testing.T) {
	t.Parallel()
	transport := &scriptedControlTransport{sendErr: unix.EAGAIN}
	client := &auditControlClient{transport: transport}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	if _, err := client.exchange(ctx, unix.AUDIT_SET, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want deadline exceeded", err)
	}
}

func TestParseControlRepliesMultipartDatagram(t *testing.T) {
	t.Parallel()
	data := controlMessage(unix.AUDIT_LIST_RULES, 12, []byte{1, 2, 3})
	data = append(data, 0) // netlink alignment before the next message
	data = append(data, controlMessage(unix.NLMSG_DONE, 12, nil)...)
	messages, err := parseControlReplies(data)
	if err != nil || len(messages) != 2 {
		t.Fatalf("messages=%v error=%v", messages, err)
	}
	if messages[0].sequence != 12 || messages[1].messageType != unix.NLMSG_DONE || !slices.Equal(messages[0].payload, []byte{1, 2, 3}) {
		t.Fatalf("messages=%v", messages)
	}
	data[unix.NLMSG_HDRLEN] = 99
	if messages[0].payload[0] != 1 {
		t.Fatal("decoded payload aliases the reusable receive buffer")
	}
}

type controlPacket struct {
	data      []byte
	senderPID uint32
}

type scriptedControlTransport struct {
	onSend     func([]byte) []controlPacket
	queue      []controlPacket
	sendErr    error
	receiveErr error
}

func (s *scriptedControlTransport) send(request []byte) error {
	if s.onSend != nil {
		s.queue = append(s.queue, s.onSend(request)...)
	}
	return s.sendErr
}

func (s *scriptedControlTransport) receive(buffer []byte) (int, unix.Sockaddr, error) {
	if s.receiveErr != nil {
		return 0, nil, s.receiveErr
	}
	if len(s.queue) == 0 {
		return 0, nil, unix.EAGAIN
	}
	packet := s.queue[0]
	s.queue = s.queue[1:]
	return copy(buffer, packet.data), &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: packet.senderPID}, nil
}
