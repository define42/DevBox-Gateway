// Package event defines SauronAgent's normalized event model: a stable schema
// that downstream consumers can rely on independently of the exact Linux audit
// record layout it was derived from.
package event

import "time"

// SchemaVersion is the version of the normalized event schema. It is carried
// in every event so that a collector can handle agents of different vintages.
//
// Bump it whenever the meaning of an existing field changes. Purely additive
// changes (new optional fields) do not require a bump.
const SchemaVersion uint32 = 1

// Event is one normalized security event.
//
// Identity fields (PID, UID, ...) are pointers rather than plain ints on
// purpose. A plain int with `omitempty` would erase the single most
// security-relevant value in the model: uid=0. Pointers keep "root" and
// "field not present in the source records" distinguishable, which a value of
// 0 cannot do.
type Event struct {
	// Version is the normalized schema version; see SchemaVersion.
	Version uint32 `json:"version"`

	// Sequence is a per-boot, strictly increasing event number assigned by the
	// agent. Together with BootID it uniquely identifies an event within a
	// guest, which is what lets the host deduplicate after a reconnect.
	Sequence uint64 `json:"sequence"`

	// Timestamp is the kernel-supplied event time where one is available, and
	// otherwise the time the agent observed the event.
	Timestamp time.Time `json:"timestamp"`

	// Type is the normalized category, e.g. "process.exec". See categories.go.
	Type string `json:"type"`

	// Severity conveys how much attention the event warrants. Events that
	// report on the audit subsystem itself are deliberately escalated.
	Severity string `json:"severity,omitempty"`

	// AuditID is the kernel audit event identifier, "<secs>.<msecs>:<serial>",
	// shared by every raw record that was correlated into this event.
	AuditID string `json:"audit_id,omitempty"`

	// BootID scopes Sequence. It changes on every guest reboot.
	BootID string `json:"boot_id,omitempty"`

	PID  *int `json:"pid,omitempty"`
	PPID *int `json:"ppid,omitempty"`

	UID  *int `json:"uid,omitempty"`
	GID  *int `json:"gid,omitempty"`
	AUID *int `json:"auid,omitempty"`

	// Executable is the resolved program path (exe= in the SYSCALL record).
	Executable string `json:"exe,omitempty"`

	// Command is the reconstructed command line, from EXECVE arguments where
	// present and from PROCTITLE otherwise.
	Command string `json:"command,omitempty"`

	// CWD is the working directory the operation took place in.
	CWD string `json:"cwd,omitempty"`

	// Paths are the filesystem objects the operation touched, in the order the
	// kernel reported them.
	Paths []string `json:"paths,omitempty"`

	// Result is "success" or "failure" where the source records say.
	Result string `json:"result,omitempty"`

	// RecordTypes lists the canonical names of the raw records that were
	// correlated into this event, e.g. ["SYSCALL","EXECVE","CWD","PATH"].
	RecordTypes []string `json:"record_types,omitempty"`

	// Fields carries everything the typed fields above do not cover, including
	// per-record-type detail such as SELinux contexts or netfilter tables.
	Fields map[string]any `json:"fields,omitempty"`

	// Raw preserves the original kernel record text, one entry per record.
	// Normalization must never be the only representation of an event: raw
	// records are what forensic review and parser regressions are checked
	// against. It is omitted when preserve_raw is disabled in configuration.
	Raw []string `json:"raw,omitempty"`
}

// Severity levels, ordered from least to most urgent.
const (
	SeverityInfo     = "info"
	SeverityNotice   = "notice"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Results reported in Event.Result.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Int returns a pointer to a copy of v, for populating the identity fields.
func Int(v int) *int { return &v }

// AUIDUnset is the value the kernel uses for "no audit login uid has been set"
// (unsigned -1). Normalization leaves Event.AUID nil in that case rather than
// reporting a nonsensical 4294967295.
const AUIDUnset = 4294967295

// Clone returns a deep copy of e. The sender may retain an event after handing
// it on (for example in the spool), so mutation must not be shared.
func (e *Event) Clone() *Event {
	if e == nil {
		return nil
	}
	c := *e
	c.PID = cloneInt(e.PID)
	c.PPID = cloneInt(e.PPID)
	c.UID = cloneInt(e.UID)
	c.GID = cloneInt(e.GID)
	c.AUID = cloneInt(e.AUID)
	if e.Paths != nil {
		c.Paths = append([]string(nil), e.Paths...)
	}
	if e.RecordTypes != nil {
		c.RecordTypes = append([]string(nil), e.RecordTypes...)
	}
	if e.Raw != nil {
		c.Raw = append([]string(nil), e.Raw...)
	}
	if e.Fields != nil {
		c.Fields = make(map[string]any, len(e.Fields))
		for k, v := range e.Fields {
			c.Fields[k] = v
		}
	}
	return &c
}

func cloneInt(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// SetField stores a value in Fields, allocating the map on first use.
func (e *Event) SetField(key string, value any) {
	if e.Fields == nil {
		e.Fields = make(map[string]any, 8)
	}
	e.Fields[key] = value
}
