package audit

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// maxRecordLength bounds a single record. The kernel caps an audit record
	// at MAX_AUDIT_MESSAGE_LENGTH (8970 bytes); the limit here is far higher
	// so that replaying a hand-written or concatenated log still works, while
	// still refusing to size any work off an unbounded input.
	maxRecordLength = 1 << 20

	// maxFields bounds how many key=value pairs one record may contribute.
	// A real record has a few dozen; anything near this limit is malformed
	// input trying to make the parser allocate.
	maxFields = 8192

	// maxExecveIndex bounds the argument and fragment indices accepted in
	// EXECVE keys such as a12[3], so that a crafted index cannot be used to
	// size anything.
	maxExecveIndex = 65535
)

// hexStringFields are the fields whose values are text and are therefore
// hex-encoded by the kernel whenever they contain a space, a quote or an
// unprintable byte. Only these are hex-decoded: fields such as arch, syscall
// or the SYSCALL a0..a3 registers are already hex *numbers*, and decoding
// those would turn a syscall argument into nonsense bytes.
var hexStringFields = map[string]bool{
	"acct":      true,
	"cmd":       true,
	"comm":      true,
	"cwd":       true,
	"data":      true,
	"dir":       true,
	"exe":       true,
	"file":      true,
	"key":       true,
	"msg":       true,
	"name":      true,
	"path":      true,
	"proctitle": true,
}

// ParseRecord parses one record received from the netlink socket.
//
// msg.Type is authoritative for the record type: it is the netlink message
// type the kernel stamped on the datagram, which no amount of text in the body
// can contradict.
func ParseRecord(msg RawMessage) (*Record, error) {
	body := trimRecord(string(msg.Data))
	if body == "" {
		return nil, fmt.Errorf("audit: empty %s record body", RecordTypeName(msg.Type))
	}
	return parse(msg.Type, RecordTypeName(msg.Type), body, msg.Received)
}

// ParseLine parses a record in auditd's on-disk form,
// "type=NAME msg=audit(<secs>.<msecs>:<serial>): <fields>".
//
// The leading "type=NAME msg=" is optional; a bare "audit(...): ..." line
// parses with an unknown record type. Unlike ParseRecord there is no netlink
// header to fall back on, so a record without a usable event id timestamp gets
// the zero time rather than an arrival time.
func ParseLine(line string) (*Record, error) {
	s := trimRecord(line)
	if s == "" {
		return nil, errors.New("audit: empty record")
	}

	typ := RecordType(0)
	name := ""
	if rest, ok := strings.CutPrefix(s, "type="); ok {
		name, s, _ = strings.Cut(rest, " ")
		s = strings.TrimLeft(s, " \t")
		typ = resolveTypeName(name)
		if body, ok := strings.CutPrefix(s, "msg="); ok {
			s = body
		}
	}
	if name == "" {
		if !strings.HasPrefix(s, "audit(") {
			return nil, errors.New("audit: not an audit record: no type= prefix and no audit(...) event id")
		}
		name = RecordTypeName(typ)
	}
	return parse(typ, name, s, time.Time{})
}

// resolveTypeName maps an auditd type name back to its numeric type, including
// the UNKNOWN[nnnn] spelling this package emits for types it has no name for,
// so that a record round-trips through text without losing its type.
func resolveTypeName(name string) RecordType {
	if t, ok := RecordTypeByName(name); ok {
		return t
	}
	if inner, ok := strings.CutPrefix(name, "UNKNOWN["); ok {
		if digits, ok := strings.CutSuffix(inner, "]"); ok {
			if v, err := strconv.ParseUint(digits, 10, 16); err == nil {
				return RecordType(v)
			}
		}
	}
	return 0
}

// trimRecord strips the framing the kernel and auditd add around a record:
// a trailing newline, and the NUL padding netlink messages are padded with.
func trimRecord(s string) string {
	return strings.Trim(s, " \t\r\n\x00")
}

// parse turns a record body -- everything after "type=NAME msg=" -- into a
// Record. received is used as the timestamp only when the record carries no
// event id of its own.
func parse(typ RecordType, name, body string, received time.Time) (*Record, error) {
	if len(body) > maxRecordLength {
		return nil, fmt.Errorf("audit: %s record is %d bytes, over the %d byte limit", name, len(body), maxRecordLength)
	}

	rec := &Record{
		Type:      typ,
		TypeName:  name,
		Fields:    make(map[string]string, 16),
		Timestamp: received,
		// Raw is rebuilt in auditd's own on-disk shape so that preserved
		// evidence can be diffed against /var/log/audit/audit.log directly.
		Raw: "type=" + name + " msg=" + body,
	}

	rest := body
	if after, ok := strings.CutPrefix(body, "audit("); ok {
		end := strings.IndexByte(after, ')')
		if end < 0 {
			return nil, fmt.Errorf("audit: %s record has a truncated event id", name)
		}
		id := after[:end]
		ts, serial, err := parseEventID(id)
		if err != nil {
			return nil, fmt.Errorf("audit: %s record: %w", name, err)
		}
		rec.AuditID = id
		rec.Serial = serial
		rec.Timestamp = ts
		rest = strings.TrimPrefix(after[end+1:], ":")
	}

	rest = strings.TrimLeft(rest, " \t")
	parseSELinuxPrefix(rec, rest)
	if err := parseFields(rec, rest, false); err != nil {
		return nil, fmt.Errorf("audit: %s record: %w", name, err)
	}

	// A user-space record wraps its own key=value pairs in msg='...'. Flatten
	// them so consumers do not have to re-implement this parser, but keep the
	// original string too: it is the only place the exact wording survives.
	if nested, ok := rec.Fields["msg"]; ok && strings.ContainsRune(nested, '=') {
		parseSELinuxPrefix(rec, nested)
		if err := parseFields(rec, nested, true); err != nil {
			return nil, fmt.Errorf("audit: %s record nested msg: %w", name, err)
		}
	}

	return rec, nil
}

// parseEventID decodes "<secs>.<msecs>:<serial>". The string itself is kept
// verbatim as Record.AuditID because it is the correlation key: reformatting
// it would silently split one logical event in two.
func parseEventID(id string) (time.Time, uint64, error) {
	secs, rest, ok := strings.Cut(id, ".")
	if !ok {
		return time.Time{}, 0, fmt.Errorf("event id %q has no fractional second", id)
	}
	msecs, serial, ok := strings.Cut(rest, ":")
	if !ok {
		return time.Time{}, 0, fmt.Errorf("event id %q has no serial", id)
	}
	if !isDigits(secs, 1, 19) || !isDigits(msecs, 1, 3) || !isDigits(serial, 1, 20) {
		return time.Time{}, 0, fmt.Errorf("event id %q is not <secs>.<msecs>:<serial>", id)
	}

	sec, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("event id %q: %w", id, err)
	}
	msec, err := strconv.ParseInt(msecs, 10, 32)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("event id %q: %w", id, err)
	}
	ser, err := strconv.ParseUint(serial, 10, 64)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("event id %q: %w", id, err)
	}
	// UTC rather than local: the timestamp is forwarded off the machine and a
	// guest's local zone is not something the collector should have to guess.
	return time.Unix(sec, msec*int64(time.Millisecond)).UTC(), ser, nil
}

// isDigits reports whether s consists of between min and max ASCII digits.
// Length is checked before any conversion so that a huge run of digits is
// rejected rather than parsed.
func isDigits(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseSELinuxPrefix extracts the fixed prefix an AVC record starts with,
// "avc:  denied  { read write } for  pid=...", into seresult and seperms.
//
// Those two tokens are not key=value pairs, so without this the single most
// important fact about an SELinux record -- whether the access was denied --
// would only survive in Raw, where the normalizer cannot see it. The names
// match auparse's, so a consumer that already knows auditd sees no surprise.
func parseSELinuxPrefix(rec *Record, s string) {
	rest, ok := strings.CutPrefix(s, "avc:")
	if !ok {
		return
	}
	rest = strings.TrimLeft(rest, " \t")
	result, rest, _ := strings.Cut(rest, " ")
	if result == "" {
		return
	}
	if _, exists := rec.Fields["seresult"]; !exists {
		rec.Fields["seresult"] = result
	}

	rest = strings.TrimLeft(rest, " \t")
	inner, ok := strings.CutPrefix(rest, "{")
	if !ok {
		return
	}
	perms, _, ok := strings.Cut(inner, "}")
	if !ok {
		return
	}
	if _, exists := rec.Fields["seperms"]; !exists {
		rec.Fields["seperms"] = strings.Join(strings.Fields(perms), " ")
	}
}

// parseFields scans a run of key=value pairs into rec.Fields.
//
// nested is true for the contents of a user-space msg='...'. Nested pairs
// never overwrite a key already set at the top level: the outer fields come
// from the kernel, the inner ones are composed by a user-space program that an
// attacker may control, and letting the inner ones win would let a process
// rewrite the uid on its own audit record.
func parseFields(rec *Record, s string, nested bool) error {
	// fragments collects split EXECVE arguments: argument index -> fragment
	// index -> text. The kernel splits an argument that does not fit a single
	// record into a0[0], a0[1], ... and only the concatenation is meaningful.
	var fragments map[int]map[int]string
	fragmentCount := 0

	i := 0
	for i < len(s) {
		if c := s[i]; c == ' ' || c == '\t' {
			i++
			continue
		}

		start := i
		for i < len(s) && isKeyByte(s[i]) {
			i++
		}
		if i == start || i >= len(s) || s[i] != '=' {
			// Not a key=value token. Records are not purely key=value: AVC
			// records open with prose. Skipping to the next space keeps one
			// odd token from desynchronising the rest of the scan.
			for i < len(s) && s[i] != ' ' && s[i] != '\t' {
				i++
			}
			continue
		}
		key := s[start:i]
		i++ // consume '='

		value, quoted, next := scanValue(s, i)
		i = next

		if len(rec.Fields) >= maxFields {
			return fmt.Errorf("more than %d fields", maxFields)
		}

		// An EXECVE fragment decodes as if it were the argument it belongs to,
		// because the kernel hex-encodes fragments the same way.
		decodeKey := key
		argIndex, fragIndex, isFragment := parseExecveFragmentKey(key)
		if isFragment && rec.Type == TypeExecve {
			decodeKey = "a" + strconv.Itoa(argIndex)
		}

		value = decodeValue(rec.Type, decodeKey, value, quoted)

		if isFragment && rec.Type == TypeExecve && !nested {
			// Fragments live outside rec.Fields, so they need their own bound
			// or a record full of a0[n] keys would size the map for us.
			if fragmentCount >= maxFields {
				return fmt.Errorf("more than %d EXECVE argument fragments", maxFields)
			}
			fragmentCount++
			if fragments == nil {
				fragments = make(map[int]map[int]string, 2)
			}
			parts := fragments[argIndex]
			if parts == nil {
				parts = make(map[int]string, 4)
				fragments[argIndex] = parts
			}
			parts[fragIndex] = value
			// The fragment keys are dropped from Fields deliberately: only the
			// reassembled argument is meaningful, and Raw still holds the
			// fragments exactly as the kernel wrote them.
			continue
		}

		if nested {
			if _, exists := rec.Fields[key]; exists {
				continue
			}
		}
		rec.Fields[key] = value
	}

	for argIndex, parts := range fragments {
		name := "a" + strconv.Itoa(argIndex)
		if _, exists := rec.Fields[name]; exists {
			// The kernel emitted the whole argument as well; trust that over
			// a reassembly rather than overwriting kernel-supplied text.
			continue
		}
		rec.Fields[name] = joinFragments(parts)
	}
	return nil
}

// joinFragments concatenates split EXECVE argument fragments in index order.
func joinFragments(parts map[int]string) string {
	indices := make([]int, 0, len(parts))
	for i := range parts {
		indices = append(indices, i)
	}
	slices.Sort(indices)

	var b strings.Builder
	for _, i := range indices {
		b.WriteString(parts[i])
	}
	return b.String()
}

// isKeyByte reports whether c can appear in a field key. Brackets are included
// because split EXECVE arguments are keyed a0[0], a0[1], ...
func isKeyByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_' || c == '-' || c == '[' || c == ']':
		return true
	}
	return false
}

// scanValue reads the value starting at i, returning the value, whether it was
// quoted, and the index just past it.
//
// An unterminated quote yields the rest of the record as a best-effort value.
// Discarding the record instead would lose a genuine audit event over one
// missing byte, and Raw still carries the original text for review.
func scanValue(s string, i int) (value string, quoted bool, next int) {
	if i >= len(s) {
		return "", false, i
	}
	switch c := s[i]; c {
	case '"', '\'':
		end := strings.IndexByte(s[i+1:], c)
		if end < 0 {
			return s[i+1:], true, len(s)
		}
		return s[i+1 : i+1+end], true, i + end + 2
	default:
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		return s[i:j], false, j
	}
}

// decodeValue applies the kernel's hex encoding rules to one value.
//
// The kernel writes a text field either quoted or, when it contains a space or
// an unprintable byte, as an unquoted run of hex digits. An unquoted value on
// a text field is therefore hex by construction. The ambiguity with a file
// literally named "cafe" is the kernel's own encoding, not a decision made
// here: it would have been quoted.
func decodeValue(typ RecordType, key, value string, quoted bool) string {
	if quoted || !isHexEncodedField(typ, key) {
		return value
	}
	if b, ok := decodeHex(value); ok {
		return string(b)
	}
	return value
}

// isHexEncodedField reports whether a field's unquoted value should be read as
// hex-encoded text.
func isHexEncodedField(typ RecordType, key string) bool {
	if hexStringFields[key] {
		return true
	}
	// a0..aN collide: on EXECVE they are command-line arguments and are text,
	// on SYSCALL they are the syscall's register arguments and are already
	// hex numbers. Only the record type can tell them apart.
	return typ == TypeExecve && isExecveArgKey(key)
}

// isExecveArgKey reports whether key is an EXECVE argument such as a0 or a12.
// a0_len and a0[0] are deliberately excluded; they are handled separately.
func isExecveArgKey(key string) bool {
	if len(key) < 2 || key[0] != 'a' {
		return false
	}
	return isDigits(key[1:], 1, 5)
}

// parseExecveFragmentKey decodes the a<arg>[<fragment>] spelling the kernel
// uses for an argument too long for one record.
func parseExecveFragmentKey(key string) (argIndex, fragIndex int, ok bool) {
	if len(key) < 5 || key[0] != 'a' || key[len(key)-1] != ']' {
		return 0, 0, false
	}
	arg, frag, found := strings.Cut(key[1:len(key)-1], "[")
	if !found || !isDigits(arg, 1, 5) || !isDigits(frag, 1, 5) {
		return 0, 0, false
	}
	a, err := strconv.Atoi(arg)
	if err != nil || a > maxExecveIndex {
		return 0, 0, false
	}
	f, err := strconv.Atoi(frag)
	if err != nil || f > maxExecveIndex {
		return 0, 0, false
	}
	return a, f, true
}

// decodeHex decodes an even-length run of hex digits. It reports false for
// anything else, including the "?" and "(null)" placeholders the kernel uses
// for values it does not have.
func decodeHex(s string) ([]byte, bool) {
	if len(s) == 0 || len(s)%2 != 0 {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return nil, false
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// isHexDigit reports whether c is an ASCII hex digit. The kernel emits upper
// case; lower case is accepted so that records reformatted by other tools
// still decode.
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
