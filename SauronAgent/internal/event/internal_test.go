package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestInternalEventShape covers the constructors that report SauronAgent's own
// failures. The field names are a wire contract with the collector (DESIGN
// section 19), so they are asserted literally.
func TestInternalEventShape(t *testing.T) {
	tests := []struct {
		name         string
		event        *Event
		wantType     string
		wantSeverity string
		wantFields   map[string]any
	}{
		{
			name:         "queue overflow",
			event:        NewQueueOverflow(128, 9001, 9128),
			wantType:     TypeQueueOverflow,
			wantSeverity: SeverityCritical,
			wantFields: map[string]any{
				"events_dropped":         uint64(128),
				"first_missing_sequence": uint64(9001),
				"last_missing_sequence":  uint64(9128),
			},
		},
		{
			name:         "spool full",
			event:        NewSpoolFull(4096, 1, 4096),
			wantType:     TypeSpoolFull,
			wantSeverity: SeverityCritical,
			wantFields: map[string]any{
				"events_dropped":         uint64(4096),
				"first_missing_sequence": uint64(1),
				"last_missing_sequence":  uint64(4096),
			},
		},
		{
			name:         "kernel records lost",
			event:        NewKernelRecordsLost(17),
			wantType:     TypeAuditKernelLost,
			wantSeverity: SeverityCritical,
			wantFields:   map[string]any{"records_lost": uint64(17)},
		},
		{
			name:         "parse failure",
			event:        NewParseFailure(`type=SYSCALL msg=audit(bogus: arch=`, "malformed audit() header"),
			wantType:     TypeParseFailure,
			wantSeverity: SeverityWarning,
			wantFields: map[string]any{
				"raw":    `type=SYSCALL msg=audit(bogus: arch=`,
				"reason": "malformed audit() header",
			},
		},
		{
			name:         "transport disconnected",
			event:        NewTransportDisconnected("write: connection reset by peer", 3),
			wantType:     TypeTransportDisconnect,
			wantSeverity: SeverityWarning,
			wantFields: map[string]any{
				"reason":  "write: connection reset by peer",
				"attempt": 3,
			},
		},
		{
			name:         "transport connected",
			event:        NewTransportConnected("vsock:2:9000", 4),
			wantType:     TypeTransportConnected,
			wantSeverity: SeverityNotice,
			wantFields: map[string]any{
				"peer":    "vsock:2:9000",
				"attempt": 4,
			},
		},
	}

	start := time.Now().Add(-time.Second)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := tc.event
			if e == nil {
				t.Fatal("constructor returned nil")
			}
			if got := e.Type; got != tc.wantType {
				t.Errorf("Type = %q, want %q", got, tc.wantType)
			}
			if got := e.Severity; got != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", got, tc.wantSeverity)
			}
			if got, want := e.Version, SchemaVersion; got != want {
				t.Errorf("Version = %d, want %d", got, want)
			}
			if e.Timestamp.Before(start) || e.Timestamp.After(time.Now().Add(time.Second)) {
				t.Errorf("Timestamp = %v, want roughly now", e.Timestamp)
			}
			if e.Sequence != 0 {
				t.Errorf("Sequence = %d, want 0: it is assigned by the spool/sender", e.Sequence)
			}
			if !IsInternal(e.Type) {
				t.Errorf("IsInternal(%q) = false, want true", e.Type)
			}
			for k, want := range tc.wantFields {
				if got, ok := e.Fields[k]; !ok || got != want {
					t.Errorf("Fields[%q] = %#v (present=%t), want %#v", k, got, ok, want)
				}
			}
			if got, want := len(e.Fields), len(tc.wantFields); got != want {
				t.Errorf("Fields = %#v, want exactly %d entries", e.Fields, want)
			}
			if _, err := json.Marshal(e); err != nil {
				t.Errorf("event does not serialize: %v", err)
			}
		})
	}
}

// TestNewInternalDefaultSeverity checks that an unclassified self-report is
// impossible: the type decides when the caller does not.
func TestNewInternalDefaultSeverity(t *testing.T) {
	tests := map[string]string{
		TypeQueueOverflow:       SeverityCritical,
		TypeSpoolFull:           SeverityCritical,
		TypeAuditKernelLost:     SeverityCritical,
		TypeStreamLost:          SeverityCritical,
		TypeParseFailure:        SeverityWarning,
		TypeSpoolError:          SeverityWarning,
		TypeTransportDisconnect: SeverityWarning,
		TypeProtocolViolation:   SeverityWarning,
		TypeTransportConnected:  SeverityNotice,
		TypeAgentStarted:        SeverityNotice,
		TypeAgentStopping:       SeverityNotice,
		TypeStreamResumed:       SeverityNotice,
		"sauron.something.new":  SeverityInfo,
	}
	for typ, want := range tests {
		if got := NewInternal(typ, "", nil).Severity; got != want {
			t.Errorf("NewInternal(%q, \"\").Severity = %q, want %q", typ, got, want)
		}
	}

	// An explicit severity always wins over the default.
	if got, want := NewInternal(TypeAgentStarted, SeverityCritical, nil).Severity, SeverityCritical; got != want {
		t.Errorf("explicit severity = %q, want %q", got, want)
	}
}

// TestNewInternalCopiesFields proves an event cannot change after it has been
// handed on. An event that mutates in the queue is not evidence.
func TestNewInternalCopiesFields(t *testing.T) {
	fields := map[string]any{"uptime_seconds": 42, "events_sent": 7}
	e := NewInternal(TypeAgentStarted, SeverityNotice, fields)

	fields["uptime_seconds"] = 99
	fields["injected"] = true
	delete(fields, "events_sent")

	if got, want := e.Fields["uptime_seconds"], 42; got != want {
		t.Errorf("Fields[uptime_seconds] = %v, want %v", got, want)
	}
	if got, want := e.Fields["events_sent"], 7; got != want {
		t.Errorf("Fields[events_sent] = %v, want %v", got, want)
	}
	if _, ok := e.Fields["injected"]; ok {
		t.Error("mutating the caller's map changed the event")
	}

	if e := NewInternal(TypeAgentStopping, SeverityNotice, nil); e.Fields != nil {
		t.Errorf("Fields = %#v, want nil for a nil field map", e.Fields)
	}
}

// TestNewParseFailureBounded checks that an oversized unparseable record is
// truncated visibly rather than either dropped or copied whole into an event
// too large for the transport.
func TestNewParseFailureBounded(t *testing.T) {
	raw := strings.Repeat("A", maxInternalRawBytes*3)
	e := NewParseFailure(raw, "record exceeds maximum length")

	kept, ok := e.Fields["raw"].(string)
	if !ok {
		t.Fatalf("Fields[raw] = %#v, want string", e.Fields["raw"])
	}
	if len(kept) != maxInternalRawBytes {
		t.Errorf("len(Fields[raw]) = %d, want %d", len(kept), maxInternalRawBytes)
	}
	if e.Fields["raw_truncated"] != true {
		t.Error("truncation was not reported")
	}
	if got, want := e.Fields["raw_original_bytes"], len(raw); got != want {
		t.Errorf("Fields[raw_original_bytes] = %v, want %v", got, want)
	}

	// Short input is kept whole and not flagged.
	short := NewParseFailure("type=UNKNOWN[9999] msg=???", "unknown record")
	if _, ok := short.Fields["raw_truncated"]; ok {
		t.Error("short raw text was flagged as truncated")
	}
	if got, want := short.Fields["raw"], "type=UNKNOWN[9999] msg=???"; got != want {
		t.Errorf("Fields[raw] = %v, want %q", got, want)
	}
}

// TestInternalEventJSON checks the shape a collector actually receives.
func TestInternalEventJSON(t *testing.T) {
	blob, err := json.Marshal(NewQueueOverflow(10, 100, 109))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	text := string(blob)
	for _, want := range []string{
		`"type":"sauron.queue.overflow"`,
		`"severity":"critical"`,
		`"events_dropped":10`,
		`"first_missing_sequence":100`,
		`"last_missing_sequence":109`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("event JSON missing %s: %s", want, text)
		}
	}
	// Internal events carry no guest identity fields at all.
	for _, unwanted := range []string{`"pid"`, `"uid"`, `"auid"`, `"raw"`} {
		if strings.Contains(text, unwanted) {
			t.Errorf("event JSON unexpectedly contains %s: %s", unwanted, text)
		}
	}
}
