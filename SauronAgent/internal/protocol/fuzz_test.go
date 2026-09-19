package protocol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// fuzzMaxPayload keeps fuzzing cheap while still exercising the limit checks;
// the decoder's behaviour does not depend on the particular value.
const fuzzMaxPayload = 4096

// classify asserts that err belongs to exactly one of the two worlds a caller
// has to act on: a malformed peer, or a broken stream. An error in neither is
// a bug, because the collector would not know whether to reconnect or to
// report a protocol violation.
func classify(t *testing.T, err error) {
	t.Helper()
	if err == nil || IsProtocolError(err) {
		return
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return
	}
	t.Fatalf("unclassifiable error %v (%T): neither a protocol violation nor a transport failure", err, err)
}

// seedFrames returns the byte strings the decoder fuzzer starts from: one
// valid frame per message type, plus every adversarial header the unit tests
// cover, so the fuzzer explores outwards from the interesting cases instead of
// spending its budget rediscovering them.
func seedFrames(tb testing.TB) [][]byte {
	tb.Helper()

	var seeds [][]byte
	var buf bytes.Buffer
	enc := NewEncoder(&buf, fuzzMaxPayload)
	for _, tc := range sampleMessages() {
		buf.Reset()
		if err := enc.WriteMessage(tc.typ, tc.seq, tc.msg); err != nil {
			// The sample event exceeds fuzzMaxPayload; the hand-built EVENT
			// frames below keep that type in the corpus regardless.
			continue
		}
		seeds = append(seeds, append([]byte(nil), buf.Bytes()...))
	}

	payload := []byte(`{"sequence":8421}`)
	seeds = append(seeds,
		nil,
		[]byte("S"),
		buildFrame(tb, uint8(MsgEvent), Version, 0, 8421, uint32(len(payload)), payload),
		buildFrame(tb, uint8(MsgEvent), Version, 0, 8421, 0, nil),
		buildFrame(tb, uint8(MsgEvent), Version, 0, 1, uint32(len(payload)), payload)[:HeaderSize-1],
		buildFrame(tb, uint8(MsgEvent), Version, 0, 1, 64, payload),
		buildFrame(tb, uint8(MsgEvent), Version, 0, 1, 0xFFFFFFFF, nil),
		buildFrame(tb, uint8(MsgEvent), Version, 0, 1, fuzzMaxPayload+1, nil),
		buildFrame(tb, uint8(MsgEvent), 2, 0, 1, uint32(len(payload)), payload),
		buildFrame(tb, 9, Version, 0, 1, uint32(len(payload)), payload),
		buildFrame(tb, 0, Version, 0, 1, uint32(len(payload)), payload),
		buildFrame(tb, uint8(MsgEvent), Version, 0x0001, 1, uint32(len(payload)), payload),
		buildFrame(tb, uint8(MsgEvent), Version, 0x8000, 1, uint32(len(payload)), payload),
		buildFrame(tb, uint8(MsgAck), Version, 0, 1, 31, []byte(`{"sequence":1}{"sequence":2}`)),
		buildFrame(tb, uint8(MsgAck), Version, 0, 1, 26, []byte("type=SYSCALL msg=audit(1):")),
		[]byte("SAUX\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"),
		[]byte("GET / HTTP/1.1\r\nHost: sauron\r\n\r\n"),
	)
	// Two valid frames back to back: the decoder must not lose the frame
	// boundary between them.
	seeds = append(seeds, append(
		buildFrame(tb, uint8(MsgAck), Version, 0, 1, uint32(len(payload)), payload),
		buildFrame(tb, uint8(MsgPing), Version, 0, 2, 2, []byte("{}"))...,
	))
	return seeds
}

// FuzzDecoder drives the decoder with arbitrary bytes, which is what a
// compromised guest gets to do to a collector. The properties asserted here
// are the whole reason the framing is this small: it must never panic, never
// allocate more than the configured limit, and always produce an error a
// caller can act on.
func FuzzDecoder(f *testing.F) {
	for _, seed := range seedFrames(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := NewDecoder(bytes.NewReader(data), fuzzMaxPayload)

		// Bounded: one frame needs at least HeaderSize bytes, so this can
		// never stop the loop early on well-formed input.
		for i := 0; i <= len(data)/HeaderSize; i++ {
			frame, err := dec.ReadFrame()
			classify(t, err)
			if cap(dec.buf) > fuzzMaxPayload {
				t.Fatalf("decoder buffer grew to %d bytes, above the %d limit", cap(dec.buf), fuzzMaxPayload)
			}
			if err != nil {
				if frame != nil {
					t.Fatalf("ReadFrame returned both a frame and the error %v", err)
				}
				return
			}
			if frame.Version != Version || !frame.Type.Valid() || frame.Flags != FlagsNone {
				t.Fatalf("accepted an invalid header: %+v", frame.Header)
			}
			if int(frame.PayloadLen) != len(frame.Payload) {
				t.Fatalf("PayloadLen = %d but payload is %d bytes", frame.PayloadLen, len(frame.Payload))
			}
			if frame.PayloadLen > fuzzMaxPayload {
				t.Fatalf("accepted a payload of %d bytes, above the %d limit", frame.PayloadLen, fuzzMaxPayload)
			}

			// The payload is attacker-controlled too; decoding it must fail
			// cleanly rather than panicking or accepting smuggled data.
			classify(t, DecodePayload(frame, payloadValue(frame.Type)))
		}
	})
}

// payloadValue returns an empty message of the type a frame claims to carry.
func payloadValue(t MessageType) any {
	switch t {
	case MsgHello:
		return new(Hello)
	case MsgReady:
		return new(Ready)
	case MsgEvent:
		return new(EventMessage)
	case MsgAck:
		return new(Ack)
	case MsgPing:
		return new(Ping)
	case MsgPong:
		return new(Pong)
	case MsgError:
		return new(ErrorMessage)
	default:
		return new(Shutdown)
	}
}

// FuzzRoundTrip checks that anything the encoder accepts the decoder reads back
// unchanged. A frame the agent can produce but the host rejects would be a
// silent, permanent loss of the stream.
func FuzzRoundTrip(f *testing.F) {
	f.Add(uint8(MsgEvent), uint64(8421), []byte(`{"sequence":8421}`))
	f.Add(uint8(MsgAck), uint64(0), []byte(""))
	f.Add(uint8(MsgPing), uint64(1<<64-1), []byte("{}"))
	f.Add(uint8(MsgError), uint64(1), []byte(`{"code":"bad_frame","fatal":true}`))
	f.Add(uint8(0), uint64(1), []byte("x"))
	f.Add(uint8(255), uint64(1), []byte("x"))
	f.Add(uint8(MsgEvent), uint64(7), bytes.Repeat([]byte{0}, fuzzMaxPayload+1))
	f.Add(uint8(MsgEvent), uint64(7), []byte("\x00\xff\xfe binary \x80 payload"))

	f.Fuzz(func(t *testing.T, typ uint8, seq uint64, payload []byte) {
		var buf bytes.Buffer
		enc := NewEncoder(&buf, fuzzMaxPayload)

		err := enc.WriteFrame(MessageType(typ), seq, payload)
		if err != nil {
			if !errors.Is(err, ErrBadType) && !errors.Is(err, ErrPayloadTooLarge) {
				t.Fatalf("WriteFrame rejected a frame for an unexpected reason: %v", err)
			}
			if buf.Len() != 0 {
				t.Fatalf("a rejected frame put %d bytes on the wire", buf.Len())
			}
			return
		}

		dec := NewDecoder(&buf, fuzzMaxPayload)
		frame, err := dec.ReadFrame()
		if err != nil {
			t.Fatalf("frame the encoder accepted failed to decode: %v", err)
		}
		if frame.Type != MessageType(typ) || frame.Sequence != seq {
			t.Fatalf("header = %+v, want type %d sequence %d", frame.Header, typ, seq)
		}
		if !bytes.Equal(frame.Payload, payload) {
			t.Fatalf("payload = %q, want %q", frame.Payload, payload)
		}
		if _, err := dec.ReadFrame(); !errors.Is(err, io.EOF) {
			t.Fatalf("trailing bytes after one frame: %v", err)
		}
	})
}
