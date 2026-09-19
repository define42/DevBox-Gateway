package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"testing/iotest"
)

// readPastHeader is an error reported by a reader that was asked for payload
// bytes it should never have been asked for.
var errReadPastHeader = errors.New("decoder read past a rejected header")

// headerOnlyReader serves exactly one header and fails the test if the decoder
// comes back for a body. A rejected header must cost the receiver nothing.
type headerOnlyReader struct {
	t      *testing.T
	header []byte
	off    int
}

func (r *headerOnlyReader) Read(p []byte) (int, error) {
	if r.off >= len(r.header) {
		r.t.Error("decoder read past the header of a frame it must reject before allocating")
		return 0, errReadPastHeader
	}
	n := copy(p, r.header[r.off:])
	r.off += n
	return n, nil
}

func TestReadFrameExactBytes(t *testing.T) {
	payload := []byte(`{"sequence":8421}`)
	wire := []byte{
		'S', 'A', 'U', 'R',
		0x01,       // version
		0x03,       // type = MsgEvent
		0x00, 0x00, // flags
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xE5, // sequence 8421
		0x00, 0x00, 0x00, 0x11, // payload length 17
	}
	wire = append(wire, payload...)

	dec := NewDecoder(bytes.NewReader(wire), DefaultMaxPayloadSize)
	f, err := dec.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Version != Version || f.Type != MsgEvent || f.Flags != FlagsNone {
		t.Errorf("header = %+v", f.Header)
	}
	if f.Sequence != 8421 {
		t.Errorf("Sequence = %d, want 8421", f.Sequence)
	}
	if f.PayloadLen != uint32(len(payload)) {
		t.Errorf("PayloadLen = %d, want %d", f.PayloadLen, len(payload))
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload = %q, want %q", f.Payload, payload)
	}

	if _, err := dec.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("second ReadFrame err = %v, want io.EOF", err)
	}
}

func TestRoundTripEveryMessageType(t *testing.T) {
	for _, tc := range sampleMessages() {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := NewEncoder(&buf, DefaultMaxPayloadSize)
			if err := enc.WriteMessage(tc.typ, tc.seq, tc.msg); err != nil {
				t.Fatalf("WriteMessage: %v", err)
			}

			dec := NewDecoder(&buf, DefaultMaxPayloadSize)
			f, err := dec.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if f.Type != tc.typ || f.Sequence != tc.seq {
				t.Fatalf("header = %+v, want type %s sequence %d", f.Header, tc.typ, tc.seq)
			}

			got := tc.into()
			if err := DecodePayload(f, got); err != nil {
				t.Fatalf("DecodePayload: %v", err)
			}
			// Comparing re-encoded JSON rather than the structs keeps the
			// check on the data that crosses the wire, without depending on
			// time.Time's internal representation.
			wantJSON, err := json.Marshal(tc.msg)
			if err != nil {
				t.Fatalf("marshal want: %v", err)
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("marshal got: %v", err)
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Errorf("round trip mismatch\n got %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestReadFrameSplitAcrossReads(t *testing.T) {
	// A VSOCK stream delivers whatever fits in the receive buffer; the decoder
	// must never assume a frame arrives in one piece.
	var buf bytes.Buffer
	enc := NewEncoder(&buf, DefaultMaxPayloadSize)
	msgs := sampleMessages()
	for _, tc := range msgs {
		if err := enc.WriteMessage(tc.typ, tc.seq, tc.msg); err != nil {
			t.Fatalf("WriteMessage(%s): %v", tc.name, err)
		}
	}

	dec := NewDecoder(iotest.OneByteReader(&buf), DefaultMaxPayloadSize)
	for _, tc := range msgs {
		f, err := dec.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame(%s): %v", tc.name, err)
		}
		if f.Type != tc.typ || f.Sequence != tc.seq {
			t.Fatalf("header = %+v, want type %s sequence %d", f.Header, tc.typ, tc.seq)
		}
		if err := DecodePayload(f, tc.into()); err != nil {
			t.Fatalf("DecodePayload(%s): %v", tc.name, err)
		}
	}
	if _, err := dec.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the last frame err = %v, want io.EOF", err)
	}
}

func TestReadFramePayloadAliasesDecoderBuffer(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf, DefaultMaxPayloadSize)
	if err := enc.WriteFrame(MsgEvent, 1, []byte(`{"n":"first "}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if err := enc.WriteFrame(MsgEvent, 2, []byte(`{"n":"second"}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	dec := NewDecoder(&buf, DefaultMaxPayloadSize)
	first, err := dec.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	kept := first.Payload
	if _, err := dec.ReadFrame(); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	// This asserts the documented hazard, not a desirable property: a caller
	// that keeps a payload across ReadFrame sees the next frame's bytes and
	// must copy instead.
	if string(kept) != `{"n":"second"}` {
		t.Fatalf("payload from the first frame = %q; the aliasing contract in the ReadFrame doc has changed", kept)
	}
}

func TestReadFrameIntoCallerOwnedFrame(t *testing.T) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf, DefaultMaxPayloadSize)
	if err := enc.WriteMessage(MsgAck, 8421, &Ack{Sequence: 8421}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	dec := NewDecoder(&buf, DefaultMaxPayloadSize)
	var f Frame
	if err := dec.ReadFrameInto(&f); err != nil {
		t.Fatalf("ReadFrameInto: %v", err)
	}
	var ack Ack
	if err := DecodePayload(&f, &ack); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if ack.Sequence != 8421 {
		t.Errorf("Ack.Sequence = %d, want 8421", ack.Sequence)
	}

	if err := dec.ReadFrameInto(nil); err == nil {
		t.Error("ReadFrameInto(nil) succeeded, want an error")
	}
}

func TestReadFrameAdversarial(t *testing.T) {
	validPayload := []byte(`{"sequence":1}`)

	tests := []struct {
		name         string
		wire         []byte
		maxPayload   uint32
		wantErr      error
		wantProtocol bool
	}{
		{
			name:         "bad magic",
			wire:         append([]byte("SAUX\x01\x04\x00\x00"), make([]byte, 12)...),
			wantErr:      ErrBadMagic,
			wantProtocol: true,
		},
		{
			name:         "plain text on the socket",
			wire:         []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
			wantErr:      ErrBadMagic,
			wantProtocol: true,
		},
		{
			name:         "unsupported version",
			wire:         buildFrame(t, uint8(MsgEvent), 2, 0, 1, uint32(len(validPayload)), validPayload),
			wantErr:      ErrBadVersion,
			wantProtocol: true,
		},
		{
			name:         "version zero",
			wire:         buildFrame(t, uint8(MsgEvent), 0, 0, 1, uint32(len(validPayload)), validPayload),
			wantErr:      ErrBadVersion,
			wantProtocol: true,
		},
		{
			name:         "undefined message type",
			wire:         buildFrame(t, 9, Version, 0, 1, uint32(len(validPayload)), validPayload),
			wantErr:      ErrBadType,
			wantProtocol: true,
		},
		{
			name:         "message type zero",
			wire:         buildFrame(t, 0, Version, 0, 1, uint32(len(validPayload)), validPayload),
			wantErr:      ErrBadType,
			wantProtocol: true,
		},
		{
			name:         "reserved flag bit",
			wire:         buildFrame(t, uint8(MsgEvent), Version, 0x0001, 1, uint32(len(validPayload)), validPayload),
			wantErr:      ErrReservedFlags,
			wantProtocol: true,
		},
		{
			name:         "high reserved flag bit",
			wire:         buildFrame(t, uint8(MsgEvent), Version, 0x8000, 1, uint32(len(validPayload)), validPayload),
			wantErr:      ErrReservedFlags,
			wantProtocol: true,
		},
		{
			name:         "declared length 0xFFFFFFFF",
			wire:         buildFrame(t, uint8(MsgEvent), Version, 0, 1, 0xFFFFFFFF, nil),
			wantErr:      ErrPayloadTooLarge,
			wantProtocol: true,
		},
		{
			name:         "declared length one over the limit",
			wire:         buildFrame(t, uint8(MsgEvent), Version, 0, 1, 4097, nil),
			maxPayload:   4096,
			wantErr:      ErrPayloadTooLarge,
			wantProtocol: true,
		},
		{
			name:         "truncated header",
			wire:         buildFrame(t, uint8(MsgEvent), Version, 0, 1, 0, nil)[:HeaderSize-1],
			wantErr:      io.ErrUnexpectedEOF,
			wantProtocol: false,
		},
		{
			name:         "single byte",
			wire:         []byte{'S'},
			wantErr:      io.ErrUnexpectedEOF,
			wantProtocol: false,
		},
		{
			name:         "header with a truncated payload",
			wire:         buildFrame(t, uint8(MsgEvent), Version, 0, 1, 64, validPayload),
			wantErr:      io.ErrUnexpectedEOF,
			wantProtocol: false,
		},
		{
			name:         "empty stream",
			wire:         nil,
			wantErr:      io.EOF,
			wantProtocol: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := NewDecoder(bytes.NewReader(tc.wire), tc.maxPayload)
			f, err := dec.ReadFrame()
			if f != nil {
				t.Fatalf("ReadFrame returned a frame %+v for %s", f.Header, tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.wantErr)
			}
			if got := IsProtocolError(err); got != tc.wantProtocol {
				t.Errorf("IsProtocolError(%v) = %v, want %v", err, got, tc.wantProtocol)
			}
		})
	}
}

func TestReadFrameRejectsOversizedLengthWithoutAllocating(t *testing.T) {
	// The whole point of validating the header first: 20 bytes claiming a 4 GiB
	// body must not become 4 GiB of receiver memory, nor even one read of the
	// body.
	for _, declared := range []uint32{0xFFFFFFFF, 0x80000000, DefaultMaxPayloadSize + 1} {
		r := &headerOnlyReader{
			t:      t,
			header: buildFrame(t, uint8(MsgEvent), Version, 0, 1, declared, nil),
		}
		dec := NewDecoder(r, DefaultMaxPayloadSize)
		_, err := dec.ReadFrame()
		if !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("declared %d: err = %v, want ErrPayloadTooLarge", declared, err)
		}
		if errors.Is(err, errReadPastHeader) {
			t.Fatalf("declared %d: decoder read the body of a rejected frame", declared)
		}
		if cap(dec.buf) != 0 {
			t.Fatalf("declared %d: decoder allocated a %d byte buffer for a rejected header", declared, cap(dec.buf))
		}
	}
}

func TestDecoderBufferStaysWithinLimit(t *testing.T) {
	const max = 8192

	var buf bytes.Buffer
	enc := NewEncoder(&buf, max)
	for _, size := range []int{1, 100, 4096, max, 7, max} {
		if err := enc.WriteFrame(MsgEvent, uint64(size), bytes.Repeat([]byte{'e'}, size)); err != nil {
			t.Fatalf("WriteFrame(%d): %v", size, err)
		}
	}

	dec := NewDecoder(&buf, max)
	for {
		f, err := dec.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if int(f.PayloadLen) != len(f.Payload) {
			t.Fatalf("PayloadLen = %d but payload is %d bytes", f.PayloadLen, len(f.Payload))
		}
		if cap(dec.buf) > max {
			t.Fatalf("decoder buffer grew to %d, above the %d limit", cap(dec.buf), max)
		}
	}
}

func TestDecoderPayloadExactlyAtLimit(t *testing.T) {
	const max = 4096

	var buf bytes.Buffer
	enc := NewEncoder(&buf, max)
	payload := bytes.Repeat([]byte{'p'}, max)
	if err := enc.WriteFrame(MsgEvent, 1, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	dec := NewDecoder(&buf, max)
	f, err := dec.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame at the limit: %v", err)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatalf("payload of %d bytes did not survive the limit", len(payload))
	}
}

func TestDecoderMaxPayloadNormalization(t *testing.T) {
	tests := []struct {
		name       string
		maxPayload uint32
		want       uint32
	}{
		{name: "zero means the default", maxPayload: 0, want: DefaultMaxPayloadSize},
		{name: "explicit value is honoured", maxPayload: 4096, want: 4096},
		{name: "ceiling is honoured", maxPayload: MaxPayloadCeiling, want: MaxPayloadCeiling},
		{name: "above the ceiling is clamped", maxPayload: MaxPayloadCeiling + 1, want: MaxPayloadCeiling},
		{name: "0xFFFFFFFF is clamped", maxPayload: 0xFFFFFFFF, want: MaxPayloadCeiling},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := NewDecoder(bytes.NewReader(nil), tc.maxPayload)
			if got := dec.MaxPayload(); got != tc.want {
				t.Fatalf("MaxPayload() = %d, want %d", got, tc.want)
			}

			// A header declaring one byte more than the resolved limit must be
			// rejected, which is what proves the clamp is load-bearing.
			wire := buildFrame(t, uint8(MsgEvent), Version, 0, 1, tc.want+1, nil)
			dec = NewDecoder(bytes.NewReader(wire), tc.maxPayload)
			if _, err := dec.ReadFrame(); !errors.Is(err, ErrPayloadTooLarge) {
				t.Fatalf("err = %v, want ErrPayloadTooLarge", err)
			}
		})
	}
}

func TestDecodePayload(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr error
	}{
		{
			name:    "well formed",
			payload: `{"sequence":8421}`,
		},
		{
			name: "unknown fields are accepted for forward compatibility",
			// A newer agent adding a field must not take the stream down.
			payload: `{"sequence":8421,"delivery_attempt":3,"nested":{"a":[1,2]}}`,
		},
		{
			name:    "trailing whitespace is tolerated",
			payload: "{\"sequence\":8421}\n\t ",
		},
		{
			name:    "a second document is rejected",
			payload: `{"sequence":8421}{"sequence":1}`,
			wantErr: ErrTrailingData,
		},
		{
			name:    "trailing junk is rejected",
			payload: `{"sequence":8421} not json`,
			wantErr: ErrTrailingData,
		},
		{
			name:    "an unbalanced brace is rejected",
			payload: `{"sequence":8421}}`,
			wantErr: ErrTrailingData,
		},
		{
			name:    "not JSON at all",
			payload: "type=SYSCALL msg=audit(1789752345.312:8421): arch=c000003e",
			wantErr: ErrMalformedPayload,
		},
		{
			name:    "truncated JSON",
			payload: `{"sequence":`,
			wantErr: ErrMalformedPayload,
		},
		{
			name:    "empty payload",
			payload: "",
			wantErr: ErrMalformedPayload,
		},
		{
			name:    "wrong JSON type for the field",
			payload: `{"sequence":"8421"}`,
			wantErr: ErrMalformedPayload,
		},
		{
			name:    "a JSON value that is not an object",
			payload: `[1,2,3]`,
			wantErr: ErrMalformedPayload,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &Frame{
				Header:  Header{Version: Version, Type: MsgAck, Sequence: 8421, PayloadLen: uint32(len(tc.payload))},
				Payload: []byte(tc.payload),
			}
			var ack Ack
			err := DecodePayload(f, &ack)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("DecodePayload: %v", err)
				}
				if ack.Sequence != 8421 {
					t.Fatalf("Ack.Sequence = %d, want 8421", ack.Sequence)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want it to wrap %v", err, tc.wantErr)
			}
			if !IsProtocolError(err) {
				t.Errorf("IsProtocolError(%v) = false; a malformed payload is a peer violation", err)
			}
		})
	}

	if err := DecodePayload(nil, &Ack{}); !errors.Is(err, ErrMalformedPayload) {
		t.Errorf("DecodePayload(nil) err = %v, want ErrMalformedPayload", err)
	}
}

func TestDecodePayloadPreservesLargeIntegers(t *testing.T) {
	// A float64 round trip would quietly corrupt values above 2^53, such as
	// nanosecond timestamps carried in an event's free-form fields.
	const nanos = "1789752345312000123"
	f := &Frame{
		Header:  Header{Version: Version, Type: MsgEvent},
		Payload: []byte(`{"event":{"version":1,"sequence":8421,"timestamp":"2026-09-18T00:00:00Z","type":"process.exec","fields":{"boot_nanos":` + nanos + `}}}`),
	}
	var msg EventMessage
	if err := DecodePayload(f, &msg); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	got := fmt.Sprint(msg.Event.Fields["boot_nanos"])
	if got != nanos {
		t.Fatalf("boot_nanos = %s, want %s", got, nanos)
	}
}

func TestDecodePayloadCopiesOutOfTheDecoderBuffer(t *testing.T) {
	// A decoded message must survive the next frame, or the sender would be
	// acknowledging events whose contents have already been overwritten.
	var buf bytes.Buffer
	enc := NewEncoder(&buf, DefaultMaxPayloadSize)
	if err := enc.WriteMessage(MsgEvent, 8421, &EventMessage{Event: sampleEvent()}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if err := enc.WriteMessage(MsgPing, 1, &Ping{UptimeSeconds: 5, AuditEnabled: true}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	dec := NewDecoder(&buf, DefaultMaxPayloadSize)
	f, err := dec.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	var msg EventMessage
	if err := DecodePayload(f, &msg); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if _, err := dec.ReadFrame(); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msg.Event.Command != "cat /etc/shadow" || msg.Event.Raw[0][:12] != "type=SYSCALL" {
		t.Fatalf("decoded event was disturbed by the next frame: %+v", msg.Event)
	}
}

func TestIsProtocolError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "bad magic", err: fmt.Errorf("read: %w", ErrBadMagic), want: true},
		{name: "bad version", err: ErrBadVersion, want: true},
		{name: "bad type", err: ErrBadType, want: true},
		{name: "reserved flags", err: ErrReservedFlags, want: true},
		{name: "payload too large", err: ErrPayloadTooLarge, want: true},
		{name: "short header", err: ErrShortHeader, want: true},
		{name: "malformed payload", err: ErrMalformedPayload, want: true},
		{name: "trailing data", err: ErrTrailingData, want: true},
		{name: "bare json syntax error", err: &json.SyntaxError{}, want: true},
		{name: "bare json type error", err: &json.UnmarshalTypeError{}, want: true},
		{name: "clean EOF", err: io.EOF, want: false},
		{name: "truncated stream", err: io.ErrUnexpectedEOF, want: false},
		{name: "deadline", err: os.ErrDeadlineExceeded, want: false},
		{name: "closed connection", err: net.ErrClosed, want: false},
		{name: "wrapped transport failure", err: fmt.Errorf("protocol: read header: %w", io.ErrUnexpectedEOF), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsProtocolError(tc.err); got != tc.want {
				t.Fatalf("IsProtocolError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestReadFrameSequenceIsBigEndian(t *testing.T) {
	// The sequence is what the host deduplicates on, so byte order is not
	// cosmetic: a mis-read sequence silently discards or duplicates events.
	var buf bytes.Buffer
	enc := NewEncoder(&buf, DefaultMaxPayloadSize)
	seqs := []uint64{0, 1, 255, 256, 0x0102030405060708, 1<<64 - 1}
	for _, seq := range seqs {
		if err := enc.WriteFrame(MsgEvent, seq, nil); err != nil {
			t.Fatalf("WriteFrame(%d): %v", seq, err)
		}
	}
	wire := buf.Bytes()
	for i, seq := range seqs {
		off := i * HeaderSize
		if got := binary.BigEndian.Uint64(wire[off+8 : off+16]); got != seq {
			t.Errorf("sequence on the wire = %d, want %d", got, seq)
		}
	}

	dec := NewDecoder(bytes.NewReader(wire), DefaultMaxPayloadSize)
	for _, seq := range seqs {
		f, err := dec.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if f.Sequence != seq {
			t.Errorf("Sequence = %d, want %d", f.Sequence, seq)
		}
	}
}
