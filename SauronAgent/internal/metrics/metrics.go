// Package metrics holds SauronAgent's counters.
//
// The counters exist to make failure visible. A security agent that quietly
// stops delivering is worse than one that is plainly down, so every way an
// event can be lost -- a parse failure, a full queue, a full spool -- has a
// counter, and those counters are reported to the host in every heartbeat.
package metrics

import "sync/atomic"

// Agent holds the guest-side counters. The zero value is ready to use and all
// methods are safe for concurrent use.
type Agent struct {
	AuditMessagesReceived atomic.Uint64
	AuditMessagesDropped  atomic.Uint64
	KernelRecordsLost     atomic.Uint64
	ParseErrors           atomic.Uint64

	EventsCreated      atomic.Uint64
	EventsSent         atomic.Uint64
	EventsAcknowledged atomic.Uint64
	EventsDropped      atomic.Uint64
	EventsResent       atomic.Uint64

	QueueDepth  atomic.Int64
	SpoolBytes  atomic.Int64
	SpoolEvents atomic.Int64

	VSOCKReconnects atomic.Uint64
	SendErrors      atomic.Uint64
}

// AgentSnapshot is a point-in-time copy of the agent counters.
type AgentSnapshot struct {
	AuditMessagesReceived uint64 `json:"audit_messages_received_total"`
	AuditMessagesDropped  uint64 `json:"audit_messages_dropped_total"`
	KernelRecordsLost     uint64 `json:"kernel_records_lost_total"`
	ParseErrors           uint64 `json:"parse_errors_total"`

	EventsCreated      uint64 `json:"events_created_total"`
	EventsSent         uint64 `json:"events_sent_total"`
	EventsAcknowledged uint64 `json:"events_acknowledged_total"`
	EventsDropped      uint64 `json:"events_dropped_total"`
	EventsResent       uint64 `json:"events_resent_total"`

	QueueDepth  int64 `json:"queue_depth"`
	SpoolBytes  int64 `json:"spool_bytes"`
	SpoolEvents int64 `json:"spool_events"`

	VSOCKReconnects uint64 `json:"vsock_reconnects_total"`
	SendErrors      uint64 `json:"send_errors_total"`
}

// Snapshot copies the current counter values.
func (a *Agent) Snapshot() AgentSnapshot {
	return AgentSnapshot{
		AuditMessagesReceived: a.AuditMessagesReceived.Load(),
		AuditMessagesDropped:  a.AuditMessagesDropped.Load(),
		KernelRecordsLost:     a.KernelRecordsLost.Load(),
		ParseErrors:           a.ParseErrors.Load(),
		EventsCreated:         a.EventsCreated.Load(),
		EventsSent:            a.EventsSent.Load(),
		EventsAcknowledged:    a.EventsAcknowledged.Load(),
		EventsDropped:         a.EventsDropped.Load(),
		EventsResent:          a.EventsResent.Load(),
		QueueDepth:            a.QueueDepth.Load(),
		SpoolBytes:            a.SpoolBytes.Load(),
		SpoolEvents:           a.SpoolEvents.Load(),
		VSOCKReconnects:       a.VSOCKReconnects.Load(),
		SendErrors:            a.SendErrors.Load(),
	}
}

// Host holds the collector-side counters.
type Host struct {
	ConnectionsAccepted atomic.Uint64
	ConnectionsRejected atomic.Uint64
	ConnectionsActive   atomic.Int64

	FramesReceived  atomic.Uint64
	FrameErrors     atomic.Uint64
	EventsReceived  atomic.Uint64
	EventsDuplicate atomic.Uint64
	EventsOutput    atomic.Uint64
	OutputErrors    atomic.Uint64

	StreamsLost atomic.Uint64
}

// HostSnapshot is a point-in-time copy of the collector counters.
type HostSnapshot struct {
	ConnectionsAccepted uint64 `json:"connections_accepted_total"`
	ConnectionsRejected uint64 `json:"connections_rejected_total"`
	ConnectionsActive   int64  `json:"connections_active"`

	FramesReceived  uint64 `json:"frames_received_total"`
	FrameErrors     uint64 `json:"frame_errors_total"`
	EventsReceived  uint64 `json:"events_received_total"`
	EventsDuplicate uint64 `json:"events_duplicate_total"`
	EventsOutput    uint64 `json:"events_output_total"`
	OutputErrors    uint64 `json:"output_errors_total"`

	StreamsLost uint64 `json:"streams_lost_total"`
}

// Snapshot copies the current counter values.
func (h *Host) Snapshot() HostSnapshot {
	return HostSnapshot{
		ConnectionsAccepted: h.ConnectionsAccepted.Load(),
		ConnectionsRejected: h.ConnectionsRejected.Load(),
		ConnectionsActive:   h.ConnectionsActive.Load(),
		FramesReceived:      h.FramesReceived.Load(),
		FrameErrors:         h.FrameErrors.Load(),
		EventsReceived:      h.EventsReceived.Load(),
		EventsDuplicate:     h.EventsDuplicate.Load(),
		EventsOutput:        h.EventsOutput.Load(),
		OutputErrors:        h.OutputErrors.Load(),
		StreamsLost:         h.StreamsLost.Load(),
	}
}
