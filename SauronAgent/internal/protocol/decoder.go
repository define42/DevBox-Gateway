package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxPayloadCeiling is the largest payload limit a Decoder or Encoder will
// honour, whatever configuration asks for.
//
// The payload limit is the only thing standing between a 20-byte header from a
// compromised guest and an allocation of the receiver's choosing, so a
// mistyped configuration value must not be able to switch the protection off.
const MaxPayloadCeiling = DefaultMaxPayloadSize * 64

// Payload errors. Like the framing errors in frame.go they are wrapped, not
// returned bare, so that errors.Is works and IsProtocolError can classify
// them.
var (
	// ErrMalformedPayload means the frame body was not the JSON value the
	// message type calls for. It is a statement about the peer, not about the
	// transport.
	ErrMalformedPayload = errors.New("protocol: malformed frame payload")
	// ErrTrailingData means bytes followed the JSON value inside one payload.
	// Accepting them would let a peer smuggle a second document past a parser
	// that only ever looks at the first.
	ErrTrailingData = errors.New("protocol: trailing data after payload")
)

// normalizeMaxPayload resolves a configured payload limit: 0 means the
// default, and anything above the ceiling is clamped to it.
func normalizeMaxPayload(maxPayload uint32) uint32 {
	switch {
	case maxPayload == 0:
		return DefaultMaxPayloadSize
	case maxPayload > MaxPayloadCeiling:
		return MaxPayloadCeiling
	default:
		return maxPayload
	}
}

// IsProtocolError reports whether err means the peer sent something this
// protocol does not allow, as opposed to the connection failing underneath it.
//
// The distinction drives two different reactions. A protocol error is a
// statement about the peer: the stream is no longer trustworthy or even
// parseable, so the connection is closed and a sauron.protocol.violation event
// is reported. A transport error -- EOF, a reset, a deadline -- says nothing
// about the peer's behaviour and is answered by reconnecting with backoff.
// Treating the two alike would either hide a hostile guest among ordinary
// disconnects or turn every network blip into a security alert.
//
// An EOF in mid-frame is deliberately classified as transport: a truncated
// stream is how a connection dies, not how a peer lies.
func IsProtocolError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrBadMagic) ||
		errors.Is(err, ErrBadVersion) ||
		errors.Is(err, ErrBadType) ||
		errors.Is(err, ErrReservedFlags) ||
		errors.Is(err, ErrPayloadTooLarge) ||
		errors.Is(err, ErrShortHeader) ||
		errors.Is(err, ErrMalformedPayload) ||
		errors.Is(err, ErrTrailingData) {
		return true
	}
	// Payload JSON is also parsed outside DecodePayload -- the host unmarshals
	// nested event bodies -- so classify the decoder's own error types too.
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
	)
	return errors.As(err, &syntaxErr) || errors.As(err, &typeErr)
}

// Decoder reads Sauron frames from a stream.
//
// A Decoder is not safe for concurrent use. It owns one payload buffer that is
// reused across frames, which is what keeps a hostile peer from turning a
// stream of large headers into a stream of allocations.
type Decoder struct {
	r          io.Reader
	maxPayload uint32
	hdr        [HeaderSize]byte
	buf        []byte
	frame      Frame
}

// NewDecoder returns a Decoder reading frames from r.
//
// maxPayload bounds the payload length the Decoder will accept and therefore
// the largest buffer it will ever allocate; 0 selects DefaultMaxPayloadSize
// and values above MaxPayloadCeiling are clamped to it.
func NewDecoder(r io.Reader, maxPayload uint32) *Decoder {
	return &Decoder{r: r, maxPayload: normalizeMaxPayload(maxPayload)}
}

// MaxPayload reports the payload limit this Decoder enforces, after the zero
// value and the ceiling have been applied. The host announces it to the guest
// in Ready.MaxPayloadSize.
func (d *Decoder) MaxPayload() uint32 { return d.maxPayload }

// ReadFrame reads the next frame.
//
// THE RETURNED FRAME AND ITS PAYLOAD ALIAS THE DECODER'S INTERNAL BUFFER AND
// ARE ONLY VALID UNTIL THE NEXT CALL ON THIS DECODER. A caller that keeps a
// payload -- queues it, spools it, hands it to another goroutine -- must copy
// it first. This is the price of not allocating per frame; DecodePayload is
// safe because it copies everything it keeps into the target value.
//
// A clean close at a frame boundary returns io.EOF unwrapped, so callers can
// compare against it directly. Every other failure is wrapped and can be
// classified with IsProtocolError.
func (d *Decoder) ReadFrame() (*Frame, error) {
	if err := d.ReadFrameInto(&d.frame); err != nil {
		return nil, err
	}
	return &d.frame, nil
}

// ReadFrameInto reads the next frame into f, for callers that want to own the
// Frame value. The same aliasing rule applies: f.Payload points into the
// Decoder's buffer and is only valid until the next call on this Decoder.
func (d *Decoder) ReadFrameInto(f *Frame) error {
	if f == nil {
		return errors.New("protocol: ReadFrameInto: nil frame")
	}

	if _, err := io.ReadFull(d.r, d.hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			// Nothing at all was read: the peer closed between frames, which
			// is an orderly end of stream rather than a truncated one.
			return io.EOF
		}
		return fmt.Errorf("protocol: read header: %w", err)
	}

	// The header is validated in full -- magic, version, type, flags and
	// length -- before a single payload byte is read or a single byte of
	// payload buffer is reserved.
	h, err := UnmarshalHeader(d.hdr[:], d.maxPayload)
	if err != nil {
		return err
	}
	if h.PayloadLen > d.maxPayload {
		// Unreachable via UnmarshalHeader, kept because this is the one place
		// where a peer-supplied number becomes an allocation.
		return fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, h.PayloadLen, d.maxPayload)
	}

	n := int(h.PayloadLen)
	if n > cap(d.buf) {
		grown := cap(d.buf) * 2
		if grown < n {
			grown = n
		}
		if grown > int(d.maxPayload) {
			grown = int(d.maxPayload)
		}
		d.buf = make([]byte, grown)
	}
	payload := d.buf[:n]
	if n > 0 {
		if _, err := io.ReadFull(d.r, payload); err != nil {
			// A frame that stops mid-payload is a broken stream, not a
			// malformed one; io.ReadFull has already turned a clean EOF here
			// into io.ErrUnexpectedEOF.
			return fmt.Errorf("protocol: read %s payload (%d bytes): %w", h.Type, n, err)
		}
	}

	f.Header = h
	f.Payload = payload
	return nil
}

// DecodePayload decodes a frame's JSON payload into v.
//
// Unknown fields are accepted on purpose: an agent and a collector of
// different vintages must interoperate, and a newer peer adding a field must
// not take the stream down. Anything after the JSON value is rejected with
// ErrTrailingData, so one frame carries exactly one document and a second one
// cannot ride along behind a parser that stops at the first.
//
// v is populated by copying, so it stays valid after the next ReadFrame.
func DecodePayload(f *Frame, v any) error {
	if f == nil {
		return fmt.Errorf("%w: nil frame", ErrMalformedPayload)
	}

	dec := json.NewDecoder(bytes.NewReader(f.Payload))
	// Numbers landing in an any -- an event's free-form Fields, for instance --
	// are kept as text rather than float64. Audit data carries values above
	// 2^53, such as nanosecond timestamps and 64-bit identifiers, and a float
	// round trip would corrupt them on the way to the SIEM without anything
	// reporting a loss.
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %s frame: %w", ErrMalformedPayload, f.Type, err)
	}
	// Token reports io.EOF only when the value was the whole payload. Trailing
	// whitespace is tolerated; a second value, or junk, is not.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %s frame", ErrTrailingData, f.Type)
	}
	return nil
}
