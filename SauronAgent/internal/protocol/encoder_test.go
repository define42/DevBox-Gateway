package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/event"
)

// sampleEvent is a normalized "cat /etc/shadow" execution, as the correlator
// would build it from a real SYSCALL/EXECVE/CWD/PATH/PROCTITLE group. The
// tests encode real event shapes rather than toy structs so that a change in
// the event model shows up here as a codec test failure.
func sampleEvent() *event.Event {
	return &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    8421,
		Timestamp:   time.Unix(1789752345, 312000000).UTC(),
		Type:        event.TypeProcessExec,
		Severity:    event.SeverityNotice,
		AuditID:     "1789752345.312:8421",
		BootID:      "2f1c9a7e-3b5d-4a1e-9c6f-8d2b0e4a7c31",
		PID:         event.Int(4821),
		PPID:        event.Int(4702),
		UID:         event.Int(0),
		GID:         event.Int(0),
		AUID:        event.Int(1000),
		Executable:  "/usr/bin/cat",
		Command:     "cat /etc/shadow",
		CWD:         "/home/user",
		Paths:       []string{"/etc/shadow", "/lib64/ld-linux-x86-64.so.2"},
		Result:      event.ResultSuccess,
		RecordTypes: []string{"SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"},
		Fields: map[string]any{
			"arch":    "c000003e",
			"syscall": "59",
			"exit":    "0",
			"tty":     "pts0",
			"ses":     "3",
			"comm":    "cat",
			"subj":    "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
		},
		Raw: []string{
			`type=SYSCALL msg=audit(1789752345.312:8421): arch=c000003e syscall=59 success=yes exit=0 a0=55f0a1c2b3d0 a1=55f0a1c2b400 a2=55f0a1c2b420 a3=8 items=2 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="exec-watch"`,
			`type=EXECVE msg=audit(1789752345.312:8421): argc=2 a0="cat" a1="/etc/shadow"`,
			`type=CWD msg=audit(1789752345.312:8421): cwd="/home/user"`,
			`type=PATH msg=audit(1789752345.312:8421): item=0 name="/etc/shadow" inode=1443 dev=fd:00 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`,
			`type=PROCTITLE msg=audit(1789752345.312:8421): proctitle=636174002F6574632F736861646F77`,
		},
	}
}

// messageCase is one message type's realistic payload plus an empty value of
// the same type to decode it back into.
type messageCase struct {
	name string
	typ  MessageType
	seq  uint64
	msg  any
	into func() any
}

// sampleMessages returns one realistic payload of every message type defined
// in message.go.
func sampleMessages() []messageCase {
	return []messageCase{
		{
			name: "hello",
			typ:  MsgHello,
			seq:  0,
			msg: &Hello{
				ProtocolVersion: Version,
				AgentVersion:    "sauronagent/1.0.0",
				Hostname:        "transfer-vm-03",
				BootID:          "2f1c9a7e-3b5d-4a1e-9c6f-8d2b0e4a7c31",
				MachineID:       "9d4a1f0c8b7e4d2a91f3c6b5a8e07d14",
				Kernel:          "6.12.9-200.fc41.x86_64",
				FirstSequence:   8400,
			},
			into: func() any { return new(Hello) },
		},
		{
			name: "ready",
			typ:  MsgReady,
			seq:  0,
			msg: &Ready{
				ProtocolVersion: Version,
				HostVersion:     "sauronhost/1.0.0",
				SessionID:       "hypervisor-01/cid-102/17897523451",
				ResumeFrom:      8420,
				MaxPayloadSize:  DefaultMaxPayloadSize,
			},
			into: func() any { return new(Ready) },
		},
		{
			name: "event",
			typ:  MsgEvent,
			seq:  8421,
			msg:  &EventMessage{Event: sampleEvent()},
			into: func() any { return new(EventMessage) },
		},
		{
			name: "ack",
			typ:  MsgAck,
			seq:  8421,
			msg:  &Ack{Sequence: 8421},
			into: func() any { return new(Ack) },
		},
		{
			name: "ping",
			typ:  MsgPing,
			seq:  12,
			msg: &Ping{
				UptimeSeconds:  86_400,
				EventsReceived: 1_204_331,
				EventsSent:     1_204_200,
				EventsSpooled:  131,
				EventsDropped:  0,
				AuditEnabled:   true,
				QueueDepth:     17,
				SpoolBytes:     262_144,
			},
			into: func() any { return new(Ping) },
		},
		{
			name: "pong",
			typ:  MsgPong,
			seq:  12,
			msg:  &Pong{EchoUptime: 86_400, UnixNano: 1789752345312000000},
			into: func() any { return new(Pong) },
		},
		{
			name: "error",
			typ:  MsgError,
			seq:  8421,
			msg: &ErrorMessage{
				Code:    ErrCodeBadSequence,
				Message: "sequence 8421 precedes acknowledged 8500",
				Fatal:   true,
			},
			into: func() any { return new(ErrorMessage) },
		},
		{
			name: "shutdown",
			typ:  MsgShutdown,
			seq:  8421,
			msg:  &Shutdown{Reason: "systemd stop", LastSequence: 8421},
			into: func() any { return new(Shutdown) },
		},
	}
}

// buildFrame is the tests' own framer, written independently of the encoder so
// that a bug in the encoder cannot cancel out against a bug in the expectation.
func buildFrame(tb testing.TB, typ uint8, version uint8, flags uint16, seq uint64, declaredLen uint32, payload []byte) []byte {
	tb.Helper()
	buf := make([]byte, HeaderSize, HeaderSize+len(payload))
	copy(buf[0:4], "SAUR")
	buf[4] = version
	buf[5] = typ
	binary.BigEndian.PutUint16(buf[6:8], flags)
	binary.BigEndian.PutUint64(buf[8:16], seq)
	binary.BigEndian.PutUint32(buf[16:20], declaredLen)
	return append(buf, payload...)
}

// countingWriter records how many Write calls a frame costs.
type countingWriter struct {
	buf    bytes.Buffer
	writes int
	err    error
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.err != nil {
		return 0, w.err
	}
	return w.buf.Write(p)
}

func TestWriteFrameExactBytes(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf, 4096)

	payload := []byte(`{"sequence":8421}`)
	if err := enc.WriteFrame(MsgAck, 0x0102030405060708, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	want := []byte{
		'S', 'A', 'U', 'R', // magic
		0x01,       // version
		0x04,       // type = MsgAck
		0x00, 0x00, // flags = FlagsNone
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // sequence, big-endian
		0x00, 0x00, 0x00, 0x11, // payload length 17, big-endian
	}
	want = append(want, payload...)

	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("frame bytes mismatch\n got % x\nwant % x", got, want)
	}
}

func TestWriteMessageExactBytes(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf, 4096)

	if err := enc.WriteMessage(MsgAck, 8421, &Ack{Sequence: 8421}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	payload := []byte(`{"sequence":8421}`)
	want := buildFrame(t, uint8(MsgAck), Version, uint16(FlagsNone), 8421, uint32(len(payload)), payload)
	if got := buf.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("frame bytes mismatch\n got %q\nwant %q", got, want)
	}
	// The JSON value must be the whole payload: json.Encoder's trailing
	// newline would otherwise be shipped as trailing data.
	if bytes.Contains(buf.Bytes()[HeaderSize:], []byte("\n")) {
		t.Errorf("payload contains a newline: %q", buf.Bytes()[HeaderSize:])
	}
}

func TestWriteFrameZeroLengthPayload(t *testing.T) {
	for _, payload := range [][]byte{nil, {}} {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, 4096)
		if err := enc.WriteFrame(MsgPong, 7, payload); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		if got, want := buf.Len(), HeaderSize; got != want {
			t.Fatalf("wrote %d bytes, want %d", got, want)
		}
		h, err := UnmarshalHeader(buf.Bytes(), DefaultMaxPayloadSize)
		if err != nil {
			t.Fatalf("UnmarshalHeader: %v", err)
		}
		if h.PayloadLen != 0 || h.Type != MsgPong || h.Sequence != 7 {
			t.Fatalf("header = %+v", h)
		}
	}
}

func TestWriteFramePayloadLimit(t *testing.T) {
	const max = 4096

	t.Run("exactly at the limit", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, max)
		payload := bytes.Repeat([]byte{'a'}, max)
		if err := enc.WriteFrame(MsgEvent, 1, payload); err != nil {
			t.Fatalf("WriteFrame at the limit: %v", err)
		}
		if got, want := buf.Len(), HeaderSize+max; got != want {
			t.Fatalf("wrote %d bytes, want %d", got, want)
		}
	})

	t.Run("one byte over the limit", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, max)
		payload := bytes.Repeat([]byte{'a'}, max+1)
		err := enc.WriteFrame(MsgEvent, 1, payload)
		if !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
		}
		if buf.Len() != 0 {
			t.Fatalf("wrote %d bytes for a rejected frame, want 0", buf.Len())
		}
		if !IsProtocolError(err) {
			t.Errorf("IsProtocolError(%v) = false, want true", err)
		}
	})

	t.Run("message over the limit", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, 128)
		// A guest with a pathological PROCTITLE can produce an event larger
		// than the negotiated frame size; it must be refused locally rather
		// than sent for the host to reject as a violation.
		msg := &ErrorMessage{Code: ErrCodeInternal, Message: strings.Repeat("x", 4096)}
		err := enc.WriteMessage(MsgError, 1, msg)
		if !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
		}
		if buf.Len() != 0 {
			t.Fatalf("wrote %d bytes for a rejected frame, want 0", buf.Len())
		}
	})
}

func TestWriteFrameSingleWrite(t *testing.T) {
	sizes := []int{0, 1, 17, 4096, encoderScratch, encoderScratch + 1, 512 << 10}
	for _, size := range sizes {
		w := &countingWriter{}
		enc := NewEncoder(w, DefaultMaxPayloadSize)
		if err := enc.WriteFrame(MsgEvent, 1, bytes.Repeat([]byte{'z'}, size)); err != nil {
			t.Fatalf("WriteFrame(%d): %v", size, err)
		}
		if w.writes != 1 {
			t.Errorf("payload of %d bytes took %d writes, want 1", size, w.writes)
		}
		if got, want := w.buf.Len(), HeaderSize+size; got != want {
			t.Errorf("payload of %d bytes wrote %d bytes, want %d", size, got, want)
		}
	}

	w := &countingWriter{}
	enc := NewEncoder(w, DefaultMaxPayloadSize)
	if err := enc.WriteMessage(MsgEvent, 8421, &EventMessage{Event: sampleEvent()}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if w.writes != 1 {
		t.Errorf("WriteMessage took %d writes, want 1", w.writes)
	}
}

func TestWriteFrameRejectsUndefinedType(t *testing.T) {
	for _, typ := range []MessageType{0, 9, 255} {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, 4096)
		if err := enc.WriteFrame(typ, 1, nil); !errors.Is(err, ErrBadType) {
			t.Errorf("WriteFrame(%d) err = %v, want ErrBadType", typ, err)
		}
		if err := enc.WriteMessage(typ, 1, &Ack{}); !errors.Is(err, ErrBadType) {
			t.Errorf("WriteMessage(%d) err = %v, want ErrBadType", typ, err)
		}
		if buf.Len() != 0 {
			t.Errorf("type %d wrote %d bytes, want 0", typ, buf.Len())
		}
	}
}

func TestWriteMessageUnencodableValue(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf, 4096)

	err := enc.WriteMessage(MsgEvent, 1, map[string]any{"ch": make(chan int)})
	if err == nil {
		t.Fatal("WriteMessage(chan) succeeded, want an error")
	}
	if buf.Len() != 0 {
		t.Fatalf("wrote %d bytes for an unencodable value, want 0", buf.Len())
	}
	if IsProtocolError(err) {
		t.Errorf("IsProtocolError(%v) = true; a local encoding bug is not a peer violation", err)
	}

	// The encoder must stay usable: a half-filled assembly buffer would
	// corrupt the next frame.
	if err := enc.WriteMessage(MsgAck, 2, &Ack{Sequence: 2}); err != nil {
		t.Fatalf("WriteMessage after a failed encode: %v", err)
	}
	payload := []byte(`{"sequence":2}`)
	want := buildFrame(t, uint8(MsgAck), Version, 0, 2, uint32(len(payload)), payload)
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("frame after a failed encode = %q, want %q", buf.Bytes(), want)
	}
}

func TestWriteFrameWriterFailure(t *testing.T) {
	sentinel := errors.New("vsock: connection reset by peer")
	w := &countingWriter{err: sentinel}
	enc := NewEncoder(w, 4096)

	err := enc.WriteFrame(MsgPing, 1, []byte(`{}`))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap %v", err, sentinel)
	}
	if IsProtocolError(err) {
		t.Errorf("IsProtocolError(%v) = true; a transport failure is not a peer violation", err)
	}
	var we *writeError
	if !errors.As(err, &we) {
		t.Errorf("err = %v, want it to be a *writeError so Conn can abandon the stream", err)
	}
}

func TestEncoderMaxPayloadNormalization(t *testing.T) {
	tests := []struct {
		name       string
		maxPayload uint32
		payload    int
		wantErr    bool
	}{
		{name: "zero means the default", maxPayload: 0, payload: DefaultMaxPayloadSize, wantErr: false},
		{name: "zero still bounds", maxPayload: 0, payload: DefaultMaxPayloadSize + 1, wantErr: true},
		{name: "explicit limit", maxPayload: 512, payload: 512, wantErr: false},
		{name: "above the ceiling is clamped", maxPayload: 1 << 31, payload: MaxPayloadCeiling + 1, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enc := NewEncoder(io.Discard, tc.maxPayload)
			err := enc.WriteFrame(MsgEvent, 1, make([]byte, tc.payload))
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("WriteFrame(%d bytes) err = %v, wantErr = %v", tc.payload, err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrPayloadTooLarge) {
				t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
			}
		})
	}
}

func TestEncoderReleasesOversizedBuffer(t *testing.T) {
	// One large frame must not pin a large buffer for the life of the
	// connection; a collector holds one encoder per connected guest.
	enc := NewEncoder(io.Discard, DefaultMaxPayloadSize)
	if err := enc.WriteFrame(MsgEvent, 1, make([]byte, DefaultMaxPayloadSize)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if got := enc.buf.Cap(); got > encoderScratch {
		t.Fatalf("encoder retained %d bytes after a large frame, want at most %d", got, encoderScratch)
	}
}

func TestWriteMessageRawPayload(t *testing.T) {
	// The spool stores events already encoded; sending them must not mean
	// decoding and re-encoding them.
	var buf bytes.Buffer
	enc := NewEncoder(&buf, 4096)
	raw := json.RawMessage(`{"sequence":99}`)
	if err := enc.WriteMessage(MsgAck, 99, raw); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if got, want := string(buf.Bytes()[HeaderSize:]), `{"sequence":99}`; got != want {
		t.Fatalf("payload = %s, want %s", got, want)
	}
}
