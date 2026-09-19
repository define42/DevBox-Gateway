package event

import "time"

// Internal agent events.
//
// SauronAgent reports its own failures into the same stream as the audit data
// it forwards (DESIGN sections 19 and 40). A collector that only ever sees
// audit events cannot distinguish a quiet guest from an agent that is dropping
// everything on the floor, so every loss of fidelity is turned into an event
// that is as actionable as the audit events around it.
//
// Sequence numbers are assigned later by the spool/sender, which is also what
// makes the loss accounting below meaningful: first_missing_sequence and
// last_missing_sequence name the exact range a collector should not expect to
// receive.

// Field keys used by the internal events. DESIGN section 19 names the loss
// accounting keys explicitly; they are part of the wire contract with the
// collector, so they are defined once here rather than spelled out at each
// call site.
const (
	fieldEventsDropped  = "events_dropped"
	fieldFirstMissing   = "first_missing_sequence"
	fieldLastMissing    = "last_missing_sequence"
	fieldRecordsLost    = "records_lost"
	fieldReason         = "reason"
	fieldAttempt        = "attempt"
	fieldPeer           = "peer"
	fieldRaw            = "raw"
	fieldRawTruncated   = "raw_truncated"
	fieldRawOriginalLen = "raw_original_bytes"
)

// maxInternalRawBytes bounds how much unparseable record text is copied into a
// parse-failure event. The text comes from a source the guest may control, and
// an event large enough to be rejected by the transport would turn a parse
// failure into a second, silent failure.
const maxInternalRawBytes = 4096

// NewInternal builds an agent self-reporting event of the given type.
//
// An empty severity is filled in from the event type, so that callers cannot
// accidentally emit an unclassified report of the agent's own failure. The
// fields map is copied: the caller may reuse or mutate its map afterwards, and
// an event that changes after it was queued is not evidence.
func NewInternal(typ, severity string, fields map[string]any) *Event {
	if severity == "" {
		severity = internalSeverity(typ)
	}
	e := &Event{
		Version:   SchemaVersion,
		Timestamp: time.Now().UTC(),
		Type:      typ,
		Severity:  severity,
	}
	for k, v := range fields {
		e.SetField(k, v)
	}
	return e
}

// internalSeverity is the default severity for each internal event type.
//
// Anything that means evidence was destroyed is critical: once records are
// gone they cannot be recovered, and a compromised guest producing a flood of
// events is one of the ways an intruder hides. A broken transport is only a
// warning because the spool is still holding the data, and the lifecycle
// events are notices: worth correlating against a gap in the stream, but not
// themselves a problem.
func internalSeverity(typ string) string {
	switch typ {
	case TypeQueueOverflow, TypeSpoolFull, TypeAuditKernelLost, TypeStreamLost:
		return SeverityCritical
	case TypeParseFailure, TypeSpoolError, TypeTransportDisconnect, TypeProtocolViolation:
		return SeverityWarning
	case TypeTransportConnected, TypeAgentStarted, TypeAgentStopping, TypeStreamResumed:
		return SeverityNotice
	}
	return SeverityInfo
}

// NewQueueOverflow reports that the bounded in-memory queue discarded events.
//
// It is critical: the discarded events are gone, and the sequence range tells
// the collector precisely which ones, so that a gap in the received sequence
// is explained rather than treated as a suppressed stream.
func NewQueueOverflow(dropped uint64, firstMissing, lastMissing uint64) *Event {
	return NewInternal(TypeQueueOverflow, SeverityCritical, map[string]any{
		fieldEventsDropped: dropped,
		fieldFirstMissing:  firstMissing,
		fieldLastMissing:   lastMissing,
	})
}

// NewSpoolFull reports that the disk spool hit its size limit and discarded
// events. Like a queue overflow this is unrecoverable evidence loss, and it
// carries the same sequence accounting.
func NewSpoolFull(dropped uint64, firstMissing, lastMissing uint64) *Event {
	return NewInternal(TypeSpoolFull, SeverityCritical, map[string]any{
		fieldEventsDropped: dropped,
		fieldFirstMissing:  firstMissing,
		fieldLastMissing:   lastMissing,
	})
}

// NewKernelRecordsLost reports records the kernel itself dropped before the
// agent could read them, as counted by the audit subsystem's lost counter.
//
// Critical for the same reason as an overflow: the records no longer exist.
// Unlike the queue and spool cases no sequence range can be given, because the
// agent never saw the records and could not number them.
func NewKernelRecordsLost(lost uint64) *Event {
	return NewInternal(TypeAuditKernelLost, SeverityCritical, map[string]any{
		fieldRecordsLost: lost,
	})
}

// NewParseFailure reports a record the parser could not interpret.
//
// The record text is preserved (bounded, see maxInternalRawBytes) so that the
// parser can be fixed against real input and so that an operator can read what
// the agent could not. Truncation is flagged rather than applied quietly.
// Severity is warning, not critical: the record survives in this event, which
// is not true of a queue overflow.
func NewParseFailure(raw string, reason string) *Event {
	fields := map[string]any{
		fieldReason: reason,
	}
	if len(raw) > maxInternalRawBytes {
		fields[fieldRaw] = raw[:maxInternalRawBytes]
		fields[fieldRawTruncated] = true
		fields[fieldRawOriginalLen] = len(raw)
	} else {
		fields[fieldRaw] = raw
	}
	return NewInternal(TypeParseFailure, SeverityWarning, fields)
}

// NewTransportDisconnected reports that the link to the host collector went
// away. Warning rather than critical: events keep accumulating in the queue
// and spool, so nothing is lost yet -- but a disconnect that is never followed
// by a matching connected event is how a blocked VSOCK path looks from the
// guest side. attempt is the reconnection attempt counter.
func NewTransportDisconnected(reason string, attempt int) *Event {
	return NewInternal(TypeTransportDisconnect, SeverityWarning, map[string]any{
		fieldReason:  reason,
		fieldAttempt: attempt,
	})
}

// NewTransportConnected reports a (re)established link to the host collector.
// peer identifies the endpoint that was reached, and attempt reports how many
// tries it took, which is what turns a flapping link into a visible pattern.
func NewTransportConnected(peer string, attempt int) *Event {
	return NewInternal(TypeTransportConnected, SeverityNotice, map[string]any{
		fieldPeer:    peer,
		fieldAttempt: attempt,
	})
}
