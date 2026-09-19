// Package protocol implements the Sauron wire protocol: a small binary framing
// layer carrying JSON payloads over a VSOCK stream.
//
// The framing is deliberately minimal. Both the guest agent and the host
// collector parse attacker-influenced bytes with it -- a compromised guest can
// send anything it likes to the host -- so the format is kept small enough to
// audit by reading it and is covered by fuzz tests.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Magic identifies a Sauron frame. It is the first four bytes on the wire.
var Magic = [4]byte{'S', 'A', 'U', 'R'}

// Version is the protocol version this build speaks.
const Version uint8 = 1

// HeaderSize is the fixed size of a frame header in bytes:
//
//	+------------------+
//	| Magic "SAUR"     | 4 bytes
//	+------------------+
//	| Version          | 1 byte
//	+------------------+
//	| Type             | 1 byte
//	+------------------+
//	| Flags            | 2 bytes
//	+------------------+
//	| Sequence         | 8 bytes
//	+------------------+
//	| Payload length   | 4 bytes
//	+------------------+
//	| Payload          | N bytes
//	+------------------+
//
// All multi-byte integers are big-endian.
const HeaderSize = 20

// DefaultMaxPayloadSize bounds how large a single frame payload may be.
//
// The limit exists to stop a peer from forcing an allocation of arbitrary
// size: the length field is read before the payload, so an unbounded value
// would let a hostile sender exhaust the receiver's memory with one 20-byte
// header. Both ends enforce it.
const DefaultMaxPayloadSize = 1 << 20 // 1 MiB

// MessageType identifies the payload carried by a frame.
type MessageType uint8

// Protocol message types.
const (
	// MsgHello is the agent's opening message, describing itself.
	MsgHello MessageType = 1
	// MsgReady is the host's acceptance, optionally resuming a stream.
	MsgReady MessageType = 2
	// MsgEvent carries one normalized event.
	MsgEvent MessageType = 3
	// MsgAck cumulatively acknowledges every event up to a sequence number.
	MsgAck MessageType = 4
	// MsgPing is the agent's periodic heartbeat with liveness counters.
	MsgPing MessageType = 5
	// MsgPong is the host's heartbeat response.
	MsgPong MessageType = 6
	// MsgError reports a protocol or processing error.
	MsgError MessageType = 7
	// MsgShutdown announces an orderly disconnect.
	MsgShutdown MessageType = 8
)

// String implements fmt.Stringer.
func (t MessageType) String() string {
	switch t {
	case MsgHello:
		return "HELLO"
	case MsgReady:
		return "READY"
	case MsgEvent:
		return "EVENT"
	case MsgAck:
		return "ACK"
	case MsgPing:
		return "PING"
	case MsgPong:
		return "PONG"
	case MsgError:
		return "ERROR"
	case MsgShutdown:
		return "SHUTDOWN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

// Valid reports whether t is a message type this version defines.
func (t MessageType) Valid() bool {
	return t >= MsgHello && t <= MsgShutdown
}

// Flags is a bitfield of per-frame flags.
type Flags uint16

// FlagsNone is the only value a version 1 peer may send. Every other bit is
// reserved; a receiver rejects frames that set one rather than ignoring it, so
// that a future flag with semantic meaning can never be silently discarded by
// an older build.
const FlagsNone Flags = 0

// Header is a decoded frame header.
type Header struct {
	Version    uint8
	Type       MessageType
	Flags      Flags
	Sequence   uint64
	PayloadLen uint32
}

// Frame is a complete decoded frame.
type Frame struct {
	Header
	Payload []byte
}

// Framing errors. They are all wrapped by the decoder so callers can
// distinguish a malformed peer from a transport failure with errors.Is.
var (
	// ErrBadMagic means the stream is not carrying Sauron frames.
	ErrBadMagic = errors.New("protocol: bad frame magic")
	// ErrBadVersion means the peer speaks a protocol version we do not.
	ErrBadVersion = errors.New("protocol: unsupported protocol version")
	// ErrBadType means the frame's message type is not defined.
	ErrBadType = errors.New("protocol: unknown message type")
	// ErrReservedFlags means the frame set a reserved flag bit.
	ErrReservedFlags = errors.New("protocol: reserved flag bits set")
	// ErrPayloadTooLarge means the declared payload exceeds the receiver's limit.
	ErrPayloadTooLarge = errors.New("protocol: payload exceeds maximum size")
	// ErrShortHeader means fewer than HeaderSize bytes were available.
	ErrShortHeader = errors.New("protocol: short frame header")
)

// MarshalHeader writes h into buf, which must be at least HeaderSize bytes.
func MarshalHeader(buf []byte, h Header) error {
	if len(buf) < HeaderSize {
		return ErrShortHeader
	}
	copy(buf[0:4], Magic[:])
	buf[4] = h.Version
	buf[5] = uint8(h.Type)
	binary.BigEndian.PutUint16(buf[6:8], uint16(h.Flags))
	binary.BigEndian.PutUint64(buf[8:16], h.Sequence)
	binary.BigEndian.PutUint32(buf[16:20], h.PayloadLen)
	return nil
}

// UnmarshalHeader decodes a frame header from buf and validates every field
// that can be checked without the payload.
//
// maxPayload bounds the accepted payload length; pass DefaultMaxPayloadSize
// unless configuration says otherwise.
func UnmarshalHeader(buf []byte, maxPayload uint32) (Header, error) {
	var h Header
	if len(buf) < HeaderSize {
		return h, ErrShortHeader
	}
	if string(buf[0:4]) != string(Magic[:]) {
		return h, fmt.Errorf("%w: got %q", ErrBadMagic, buf[0:4])
	}
	h.Version = buf[4]
	if h.Version != Version {
		return h, fmt.Errorf("%w: got %d, want %d", ErrBadVersion, h.Version, Version)
	}
	h.Type = MessageType(buf[5])
	if !h.Type.Valid() {
		return h, fmt.Errorf("%w: %d", ErrBadType, buf[5])
	}
	h.Flags = Flags(binary.BigEndian.Uint16(buf[6:8]))
	if h.Flags != FlagsNone {
		return h, fmt.Errorf("%w: %#04x", ErrReservedFlags, uint16(h.Flags))
	}
	h.Sequence = binary.BigEndian.Uint64(buf[8:16])
	h.PayloadLen = binary.BigEndian.Uint32(buf[16:20])
	if h.PayloadLen > maxPayload {
		return h, fmt.Errorf("%w: %d > %d", ErrPayloadTooLarge, h.PayloadLen, maxPayload)
	}
	return h, nil
}
