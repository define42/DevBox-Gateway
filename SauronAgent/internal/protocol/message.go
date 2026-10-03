package protocol

import "github.com/define42/devbox-gateway/SauronAgent/internal/event"

// Hello is the payload of MsgHello: the agent introducing itself.
//
// Everything here is informational. The host derives a guest's authoritative
// identity from the VSOCK CID of the connection, because a compromised guest
// is free to put any hostname it likes in this message.
type Hello struct {
	ProtocolVersion uint8  `json:"protocol_version"`
	AgentVersion    string `json:"agent_version"`
	Hostname        string `json:"hostname,omitempty"`
	BootID          string `json:"boot_id,omitempty"`
	MachineID       string `json:"machine_id,omitempty"`
	Kernel          string `json:"kernel,omitempty"`

	// FirstSequence is the lowest sequence number the agent still holds and
	// can replay. It lets the host tell whether a gap is a lost event or just
	// data the agent already had acknowledged.
	FirstSequence uint64 `json:"first_sequence,omitempty"`
}

// Ready is the payload of MsgReady: the host accepting the session.
type Ready struct {
	ProtocolVersion uint8  `json:"protocol_version"`
	HostVersion     string `json:"host_version,omitempty"`

	// SessionID identifies this connection in host-side logs.
	SessionID string `json:"session_id,omitempty"`

	// ResumeFrom is the highest contiguous sequence accounted for by accepted
	// events or published gap reports for this (CID, HELLO boot ID) pair.
	// The agent may discard retained events through this position. Zero means
	// no position is remembered, which also occurs after collector restart.
	// Sink acceptance determines durability; this state is held in memory.
	ResumeFrom uint64 `json:"resume_from,omitempty"`

	// MaxPayloadSize is the largest frame payload the host will accept.
	MaxPayloadSize uint32 `json:"max_payload_size,omitempty"`
}

// EventMessage is the payload of MsgEvent.
//
// The frame header and nested event must carry the same nonzero sequence.
// The collector parses the event and rejects a mismatch before deduplication.
type EventMessage struct {
	Event *event.Event `json:"event"`
}

// Ack is the payload of MsgAck. Acknowledging N permits the agent to discard
// retained events through N. The collector advances this position after sink
// acceptance of events or gap reports; durability depends on the sink.
type Ack struct {
	Sequence uint64 `json:"sequence"`
}

// Ping is the payload of MsgPing: the agent's heartbeat.
//
// Counters describe the guest's view of collection and backlog. They are
// untrusted claims; a heartbeat alone does not establish audit coverage.
type Ping struct {
	// UptimeSeconds is how long the agent process has been running.
	UptimeSeconds uint64 `json:"uptime"`

	EventsReceived uint64 `json:"events_received"`
	EventsSent     uint64 `json:"events_sent"`
	EventsSpooled  uint64 `json:"events_spooled"`
	EventsDropped  uint64 `json:"events_dropped"`

	// AuditEnabled is the agent's configured startup value. It does not query
	// the live kernel policy or prove that audit records are still arriving.
	AuditEnabled bool `json:"audit_enabled"`

	// QueueDepth and SpoolBytes expose backpressure to the host.
	QueueDepth uint64 `json:"queue_depth"`
	SpoolBytes uint64 `json:"spool_bytes"`
}

// Pong is the payload of MsgPong.
type Pong struct {
	// EchoUptime repeats the uptime from the Ping it answers, so the agent can
	// match a response to its request.
	EchoUptime uint64 `json:"echo_uptime,omitempty"`

	// UnixNano is the host's clock at the time of the response. A client can
	// compare it with its own clock; the shipped agent does not report drift.
	UnixNano int64 `json:"unix_nano,omitempty"`
}

// ErrorCode classifies a protocol error.
type ErrorCode string

// Protocol error codes.
const (
	ErrCodeBadFrame       ErrorCode = "bad_frame"
	ErrCodeBadPayload     ErrorCode = "bad_payload"
	ErrCodeBadSequence    ErrorCode = "bad_sequence"
	ErrCodeUnexpectedType ErrorCode = "unexpected_type"
	ErrCodeUnauthorized   ErrorCode = "unauthorized"
	ErrCodeInternal       ErrorCode = "internal"
	ErrCodeOverloaded     ErrorCode = "overloaded"
)

// ErrorMessage is the payload of MsgError.
type ErrorMessage struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message,omitempty"`

	// Fatal tells the peer that the sender is about to close the connection.
	Fatal bool `json:"fatal,omitempty"`
}

// Shutdown is the payload of MsgShutdown, sent by either side before an
// orderly close so the peer can tell a planned stop from a crash.
type Shutdown struct {
	Reason string `json:"reason,omitempty"`

	// LastSequence is the highest sequence the agent sent before stopping.
	LastSequence uint64 `json:"last_sequence,omitempty"`
}
