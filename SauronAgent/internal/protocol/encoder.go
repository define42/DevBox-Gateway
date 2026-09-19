package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// encoderScratch bounds the buffer an Encoder keeps between frames.
//
// A host collector holds one Encoder per connected guest, so retaining a
// maxPayload-sized buffer per connection would let a single oversized frame
// pin megabytes for the life of the process. Anything larger is assembled in a
// temporary buffer that is handed back to the collector immediately.
const encoderScratch = 64 << 10

// headerPlaceholder reserves header space in the assembly buffer. The real
// header is written over it once the payload length is known.
var headerPlaceholder [HeaderSize]byte

// Encoder writes Sauron frames to a stream.
//
// An Encoder is not safe for concurrent use: frames would interleave on the
// wire and the internal assembly buffer would race. Conn serializes access for
// the common case of a heartbeat goroutine sharing a connection with an
// event-sending goroutine.
type Encoder struct {
	w          io.Writer
	maxPayload uint32
	buf        bytes.Buffer
}

// NewEncoder returns an Encoder writing frames to w.
//
// maxPayload bounds the payload of a frame this Encoder will emit; 0 selects
// DefaultMaxPayloadSize. It is clamped to MaxPayloadCeiling so that a
// configuration mistake cannot let the agent build frames the peer is certain
// to reject as hostile.
func NewEncoder(w io.Writer, maxPayload uint32) *Encoder {
	return &Encoder{w: w, maxPayload: normalizeMaxPayload(maxPayload)}
}

// WriteFrame writes one frame carrying payload verbatim.
//
// Header and payload are assembled into one buffer and written with a single
// Write. A frame split into two writes is observable by a slow reader as a
// header with no body, which on the host side is indistinguishable from a
// guest that is deliberately stalling mid-frame; one write keeps that
// ambiguity off the wire whenever the underlying writer is atomic for a single
// Write, which a stream socket is up to its send buffer.
//
// A payload larger than the Encoder's limit returns ErrPayloadTooLarge and
// writes nothing.
func (e *Encoder) WriteFrame(t MessageType, seq uint64, payload []byte) error {
	if !t.Valid() {
		return fmt.Errorf("%w: %d", ErrBadType, uint8(t))
	}
	if uint64(len(payload)) > uint64(e.maxPayload) {
		return fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, len(payload), e.maxPayload)
	}

	e.buf.Reset()
	e.buf.Grow(HeaderSize + len(payload))
	e.buf.Write(headerPlaceholder[:])
	e.buf.Write(payload)
	return e.flush(t, seq)
}

// WriteMessage encodes v as JSON and writes it as the payload of one frame.
//
// v is marshalled into the same buffer the frame is assembled in, so the frame
// still reaches the transport as a single Write. A payload that exceeds the
// Encoder's limit returns ErrPayloadTooLarge and writes nothing, which matters
// because the peer would otherwise close the connection on a protocol
// violation of our own making. Pass a json.RawMessage to send a payload that
// is already encoded.
func (e *Encoder) WriteMessage(t MessageType, seq uint64, v any) error {
	if !t.Valid() {
		return fmt.Errorf("%w: %d", ErrBadType, uint8(t))
	}

	e.buf.Reset()
	e.buf.Write(headerPlaceholder[:])
	if err := json.NewEncoder(&e.buf).Encode(v); err != nil {
		e.recycle()
		return fmt.Errorf("protocol: encode %s payload: %w", t, err)
	}
	// json.Encoder terminates each value with a newline. The payload is the
	// JSON value itself, so the newline is dropped rather than shipped as
	// trailing bytes the peer's own trailing-data check would reject.
	if b := e.buf.Bytes(); len(b) > HeaderSize && b[len(b)-1] == '\n' {
		e.buf.Truncate(len(b) - 1)
	}

	if n := e.buf.Len() - HeaderSize; uint64(n) > uint64(e.maxPayload) {
		e.recycle()
		return fmt.Errorf("%w: %s payload %d > %d", ErrPayloadTooLarge, t, n, e.maxPayload)
	}
	return e.flush(t, seq)
}

// flush stamps the header over the placeholder and writes the assembled frame.
func (e *Encoder) flush(t MessageType, seq uint64) error {
	b := e.buf.Bytes()
	h := Header{
		Version:    Version,
		Type:       t,
		Flags:      FlagsNone,
		Sequence:   seq,
		PayloadLen: uint32(len(b) - HeaderSize),
	}
	if err := MarshalHeader(b, h); err != nil {
		e.recycle()
		return err
	}

	_, err := e.w.Write(b)
	e.recycle()
	if err != nil {
		return &writeError{typ: t, err: err}
	}
	return nil
}

// writeError marks a failure of the underlying writer, as opposed to a caller
// error caught before anything was written.
//
// The distinction is not cosmetic: a failed Write may already have put part of
// a frame on the wire, which leaves the peer's parser inside a payload that
// will never be completed. Conn watches for this type to refuse any further
// use of the connection instead of appending a second frame to a torn one.
type writeError struct {
	typ MessageType
	err error
}

func (e *writeError) Error() string {
	return fmt.Sprintf("protocol: write %s frame: %v", e.typ, e.err)
}

func (e *writeError) Unwrap() error { return e.err }

// recycle releases an assembly buffer that grew past encoderScratch.
func (e *Encoder) recycle() {
	if e.buf.Cap() > encoderScratch {
		e.buf = bytes.Buffer{}
		return
	}
	e.buf.Reset()
}
