package audit

import "time"

// Group is a set of audit records that the kernel emitted for one logical
// operation, identified by a shared AuditID.
//
// A single action such as "cat /etc/shadow" produces a SYSCALL record, an
// EXECVE record, a CWD record, one or more PATH records and a PROCTITLE
// record. Forwarding those as five unrelated security events would make the
// stream almost unusable, so the correlator collects them into one Group and
// the normalizer turns each Group into exactly one Event.
type Group struct {
	// AuditID is the kernel event identifier shared by every record.
	AuditID string

	// Serial is the numeric part of AuditID.
	Serial uint64

	// Timestamp is the event time, taken from the first record seen.
	Timestamp time.Time

	// Records are the records in arrival order, which is the order the kernel
	// emitted them.
	Records []*Record

	// Complete reports whether the group was closed by an explicit end-of-event
	// marker rather than by the correlation timeout. An incomplete group is
	// still emitted -- holding an event back indefinitely would be a worse
	// failure than emitting it with fewer records -- but the distinction is
	// recorded on the event so that a consumer can tell the difference.
	Complete bool
}

// First returns the first record of the given type, or nil.
func (g *Group) First(t RecordType) *Record {
	for _, r := range g.Records {
		if r.Type == t {
			return r
		}
	}
	return nil
}

// All returns every record of the given type, in arrival order.
func (g *Group) All(t RecordType) []*Record {
	var out []*Record
	for _, r := range g.Records {
		if r.Type == t {
			out = append(out, r)
		}
	}
	return out
}

// Has reports whether the group contains a record of the given type.
func (g *Group) Has(t RecordType) bool { return g.First(t) != nil }

// Types returns the canonical names of every record in the group, in order.
func (g *Group) Types() []string {
	out := make([]string, 0, len(g.Records))
	for _, r := range g.Records {
		out = append(out, r.TypeName)
	}
	return out
}

// RawLines returns the original text of every record in the group.
func (g *Group) RawLines() []string {
	out := make([]string, 0, len(g.Records))
	for _, r := range g.Records {
		out = append(out, r.Raw)
	}
	return out
}

// Field looks up a field by key across the group, preferring the record types
// given in order of preference. It returns the first match found.
func (g *Group) Field(key string, prefer ...RecordType) (string, bool) {
	for _, t := range prefer {
		for _, r := range g.Records {
			if r.Type != t {
				continue
			}
			if v, ok := r.Fields[key]; ok {
				return v, true
			}
		}
	}
	for _, r := range g.Records {
		if v, ok := r.Fields[key]; ok {
			return v, true
		}
	}
	return "", false
}
