package event

import (
	"encoding/hex"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/define42/SauronAgent/internal/audit"
)

// Normalization turns one correlated group of raw kernel audit records into a
// single Event. Two rules drive every decision in this file:
//
//   - Nothing is dropped. Every field of every record ends up in a typed Event
//     field or in Event.Fields, and with PreserveRaw the original record text
//     travels along with it. A normalizer that quietly forgets a field is
//     indistinguishable from an attacker suppressing it.
//   - The kernel's own words survive. Where normalization interprets a value
//     (a syscall number, a relative path) the interpretation is stored next to
//     the literal value instead of replacing it, because the literal value is
//     the evidence.
//
// Fields layout: SYSCALL fields sit at the top level of Event.Fields, because
// they describe the event as a whole. Every other record type is namespaced
// under its lowercased record-type name -- Fields["avc"], Fields["user_cmd"],
// Fields["netfilter_cfg"] -- so that two record types carrying the same key
// (both AVC and NETFILTER_CFG have their own meaning for "op") cannot
// overwrite each other. Where a group holds several records of one type, the
// namespaced value becomes a []map[string]any instead of a map[string]any.
// The reserved top-level keys normalization adds itself are "path_details",
// "exit", "proctitle", "argv", "syscall_name", "syscall_extra",
// "execve_argc_mismatch" and "correlation_incomplete".

// Bounds on parsing attacker-influenced record content. A compromised guest
// can emit audit records with arbitrary keys, so every loop below terminates
// on record content that is already in memory and never allocates from a
// length field supplied by the record itself.
const (
	maxExecveArgs    = 4096
	maxArgChunks     = 1024
	maxEmbeddedPairs = 128
	maxEmbeddedValue = 64 * 1024
)

// NormalizeOptions controls how a Group is turned into an Event.
type NormalizeOptions struct {
	// PreserveRaw copies the original record text onto Event.Raw. It is
	// configurable because raw records roughly double event size, but
	// disabling it means the normalized view is the only evidence left.
	PreserveRaw bool

	// BootID scopes the event's sequence number; see Event.BootID.
	BootID string
}

// Normalize converts a correlated audit group into one normalized Event.
//
// It never returns an error: a group that cannot be interpreted still yields
// an event (TypeSystemSecurity) carrying every field that was parsed, because
// an unrecognised security record is exactly the kind of thing an operator
// must still see. A nil group yields a nil event.
func Normalize(g *audit.Group, opts NormalizeOptions) *Event {
	if g == nil {
		return nil
	}

	n := &normalizer{
		g:        g,
		sc:       g.First(audit.TypeSyscall),
		promoted: make(map[string]bool, 8),
		e: &Event{
			Version:     SchemaVersion,
			Timestamp:   g.Timestamp,
			AuditID:     g.AuditID,
			BootID:      opts.BootID,
			RecordTypes: g.Types(),
		},
	}
	if opts.PreserveRaw {
		n.e.Raw = g.RawLines()
	}
	n.parseEmbedded()

	n.call = n.syscallName()
	n.e.Type = n.classify()
	n.extractIdentity()
	n.extractExecutable()
	n.extractCWD()
	n.extractCommand()
	n.extractPaths()
	n.extractResult()
	n.collectFields()
	n.e.Severity = n.severity()

	if !g.Complete {
		// A group closed by the correlation timeout may be missing records
		// the kernel had not emitted yet. Consumers must be able to tell that
		// apart from an event the kernel closed itself.
		n.e.SetField("correlation_incomplete", true)
	}
	return n.e
}

// normalizer holds the per-group state shared by the extraction steps.
type normalizer struct {
	g  *audit.Group
	e  *Event
	sc *audit.Record

	// call is the syscall name, or the numeric string when it could not be
	// translated safely. See syscallName.
	call string

	// resolvedCall reports whether call came from translating a number.
	resolvedCall bool

	// embedded holds the key=value pairs parsed out of each record's msg='...'
	// payload, indexed like g.Records. User-space records (USER_AUTH,
	// USER_CMD, ...) hide their interesting content there.
	embedded []map[string]string

	// promoted records the SYSCALL keys that became typed Event fields and are
	// therefore not repeated at the top level of Fields.
	promoted map[string]bool
}

func (n *normalizer) parseEmbedded() {
	n.embedded = make([]map[string]string, len(n.g.Records))
	for i, r := range n.g.Records {
		if msg, ok := r.Fields["msg"]; ok {
			n.embedded[i] = embeddedPairs(msg)
		}
	}
}

// lookup finds a field anywhere in the group, preferring the SYSCALL record,
// and falls back to the pairs embedded in a msg='...' payload. The fallback
// matters because whether those pairs are expanded by the record parser or
// left as one opaque string is a parser detail this package must not depend
// on.
func (n *normalizer) lookup(key string) (string, bool) {
	if v, ok := n.g.Field(key, audit.TypeSyscall); ok {
		return v, true
	}
	for _, pairs := range n.embedded {
		if v, ok := pairs[key]; ok {
			return v, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// syscall identification
// ---------------------------------------------------------------------------

// syscallName resolves the SYSCALL record's syscall= value to a name.
//
// The kernel reports the syscall as a number, and a syscall number means a
// different call on every architecture: 59 is execve on x86_64 but restart at
// a different table entry elsewhere, and on arm64 the exec syscalls have no
// such number at all. Translating blindly would mislabel every event from a
// non-x86_64 guest, which is worse than not translating: a wrong category is
// trusted, a numeric one is obviously uninterpreted.
//
// Therefore a number is only translated when arch= says x86_64 (c000003e).
// On any other architecture the numeric string is kept as-is, and
// classification falls back to PATH nametype, which is architecture
// independent. Adding another architecture means adding its syscall table
// here; until then such guests are categorised conservatively rather than
// incorrectly.
func (n *normalizer) syscallName() string {
	if n.sc == nil {
		return ""
	}
	v := strings.TrimSpace(n.sc.Fields["syscall"])
	if v == "" {
		return ""
	}
	if !isAllDigits(v) {
		// Already a name: some producers (ausearch-style enrichment)
		// interpret the number before we ever see the record.
		return v
	}
	if !isX8664(n.sc.Fields["arch"]) {
		return v
	}
	num, err := strconv.Atoi(v)
	if err != nil {
		return v
	}
	name, ok := x8664Syscalls[num]
	if !ok {
		return v
	}
	n.resolvedCall = true
	return name
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isX8664 reports whether an audit arch= value denotes x86_64. The kernel
// emits the AUDIT_ARCH_* constant in hex (c000003e); enriched logs may spell
// the name out instead.
func isX8664(arch string) bool {
	a := strings.ToLower(strings.TrimSpace(arch))
	a = strings.TrimPrefix(a, "0x")
	return a == "c000003e" || a == "x86_64"
}

// ---------------------------------------------------------------------------
// category
// ---------------------------------------------------------------------------

// classify picks the normalized category from the group's most specific
// record.
//
// Precedence is deliberate and is not the order of the rule list. Several
// record types routinely accompany a SYSCALL record, so the question is which
// record describes what actually happened:
//
//   - An AVC/SELINUX_ERR record means the operation was denied by policy. The
//     denial is the event; the syscall is only its context.
//   - NETFILTER_CFG, USER_CMD and the audit-configuration records likewise
//     describe an action that the bare syscall would under-report (auditctl
//     writing to a netlink socket is not "file.modify").
//   - Only then does the syscall decide, so that an execve carrying a
//     BPRM_FCAPS or CAPSET record stays process.exec instead of being demoted
//     to privilege.change.
func (n *normalizer) classify() string {
	switch {
	case n.g.Has(audit.TypeAvc), n.g.Has(audit.TypeUserAvc), n.g.Has(audit.TypeSelinuxErr):
		return TypeSELinuxDenial
	case n.g.Has(audit.TypeNetfilterCfg):
		return TypeFirewallConfiguration
	case n.g.Has(audit.TypeUserCmd):
		return TypeUserCommand
	case n.hasAny(auditConfigTypes):
		return TypeAuditConfiguration
	}

	if n.sc != nil {
		switch {
		case isExecSyscall(n.call):
			return TypeProcessExec
		case isExitSyscall(n.call):
			return TypeProcessExit
		}
		if n.g.Has(audit.TypePath) {
			if t, ok := n.fileCategory(); ok {
				return t
			}
		}
	}

	if n.hasAny(authLoginTypes) {
		if n.resultWord() == ResultFailure {
			return TypeAuthFailure
		}
		// An auth record that does not say it failed is reported as a login.
		// Under-reporting a successful login is preferable to inventing a
		// failure that the records do not claim.
		return TypeAuthLogin
	}
	if n.hasAny(authLogoutTypes) {
		return TypeAuthLogout
	}
	if n.hasAny(privilegeTypes) {
		return TypePrivilegeChange
	}

	// The syscall did not settle it -- either there is no SYSCALL record, or
	// the number could not be translated on this architecture. The kernel's
	// own nametype is architecture independent, so it decides instead.
	if t, ok := n.pathNametypeCategory(); ok {
		return t
	}
	return TypeSystemSecurity
}

func (n *normalizer) hasAny(types []audit.RecordType) bool {
	for _, t := range types {
		if n.g.Has(t) {
			return true
		}
	}
	return false
}

var auditConfigTypes = []audit.RecordType{
	audit.TypeConfigChange,
	audit.TypeDaemonStart,
	audit.TypeDaemonEnd,
	audit.TypeDaemonAbort,
	audit.TypeDaemonConfig,
	audit.TypeFeatureChange,
	audit.TypeAddRule,
	audit.TypeDelRule,
	audit.TypeSet,
	audit.TypeReplace,
}

var authLoginTypes = []audit.RecordType{
	audit.TypeUserAuth,
	audit.TypeUserLogin,
	audit.TypeLogin,
	audit.TypeUserStart,
	audit.TypeCredAcq,
}

var authLogoutTypes = []audit.RecordType{
	audit.TypeUserLogout,
	audit.TypeUserEnd,
	audit.TypeCredDisp,
}

var privilegeTypes = []audit.RecordType{
	audit.TypeUserMgmt,
	audit.TypeAddUser,
	audit.TypeDelUser,
	audit.TypeAddGroup,
	audit.TypeDelGroup,
	audit.TypeRoleAssign,
	audit.TypeRoleRemove,
	audit.TypeChuserID,
	audit.TypeChgrpID,
	audit.TypeUserChauthtok,
	audit.TypeCapset,
	audit.TypeSeccomp,
	audit.TypeBprmFcaps,
}

func isExecSyscall(call string) bool {
	return call == "execve" || call == "execveat"
}

func isExitSyscall(call string) bool {
	return call == "exit" || call == "exit_group"
}

// fileSyscallCategory maps a file-touching syscall to its category. The open
// family is handled separately because its category depends on the flags and
// on the kernel's nametype.
var fileSyscallCategory = map[string]string{
	"unlink":   TypeFileDelete,
	"unlinkat": TypeFileDelete,
	"rmdir":    TypeFileDelete,

	"creat":     TypeFileCreate,
	"mkdir":     TypeFileCreate,
	"mkdirat":   TypeFileCreate,
	"link":      TypeFileCreate,
	"linkat":    TypeFileCreate,
	"symlink":   TypeFileCreate,
	"symlinkat": TypeFileCreate,
	"mknod":     TypeFileCreate,
	"mknodat":   TypeFileCreate,

	"write":        TypeFileModify,
	"pwrite64":     TypeFileModify,
	"writev":       TypeFileModify,
	"pwritev":      TypeFileModify,
	"pwritev2":     TypeFileModify,
	"truncate":     TypeFileModify,
	"ftruncate":    TypeFileModify,
	"fallocate":    TypeFileModify,
	"rename":       TypeFileModify,
	"renameat":     TypeFileModify,
	"renameat2":    TypeFileModify,
	"chmod":        TypeFileModify,
	"fchmod":       TypeFileModify,
	"fchmodat":     TypeFileModify,
	"fchmodat2":    TypeFileModify,
	"chown":        TypeFileModify,
	"fchown":       TypeFileModify,
	"lchown":       TypeFileModify,
	"fchownat":     TypeFileModify,
	"setxattr":     TypeFileModify,
	"lsetxattr":    TypeFileModify,
	"fsetxattr":    TypeFileModify,
	"removexattr":  TypeFileModify,
	"lremovexattr": TypeFileModify,
	"fremovexattr": TypeFileModify,
	"utimensat":    TypeFileModify,
	"utime":        TypeFileModify,
	"utimes":       TypeFileModify,
	"futimesat":    TypeFileModify,

	"read":       TypeFileAccess,
	"pread64":    TypeFileAccess,
	"readv":      TypeFileAccess,
	"preadv":     TypeFileAccess,
	"preadv2":    TypeFileAccess,
	"readlink":   TypeFileAccess,
	"readlinkat": TypeFileAccess,
	"stat":       TypeFileAccess,
	"stat64":     TypeFileAccess,
	"lstat":      TypeFileAccess,
	"lstat64":    TypeFileAccess,
	"fstat":      TypeFileAccess,
	"fstatat":    TypeFileAccess,
	"fstatat64":  TypeFileAccess,
	"newfstatat": TypeFileAccess,
	"statx":      TypeFileAccess,
	"access":     TypeFileAccess,
	"faccessat":  TypeFileAccess,
	"faccessat2": TypeFileAccess,
	"getxattr":   TypeFileAccess,
	"lgetxattr":  TypeFileAccess,
	"fgetxattr":  TypeFileAccess,
	"listxattr":  TypeFileAccess,
	"llistxattr": TypeFileAccess,
	"flistxattr": TypeFileAccess,
	"getdents":   TypeFileAccess,
	"getdents64": TypeFileAccess,
}

func (n *normalizer) fileCategory() (string, bool) {
	switch n.call {
	case "open", "openat", "openat2":
		// The kernel already tells us when the path was created; that is more
		// reliable than guessing from O_CREAT, whose numeric value differs
		// between architectures.
		if n.pathHasNametype("CREATE") {
			return TypeFileCreate, true
		}
		if n.openForWriting() {
			return TypeFileModify, true
		}
		return TypeFileAccess, true
	}
	if t, ok := fileSyscallCategory[n.call]; ok {
		return t, true
	}
	return "", false
}

// openForWriting reports whether an open/openat carried a write access mode.
//
// Only the low two bits of the flags argument (O_RDONLY/O_WRONLY/O_RDWR) are
// examined: those three values are identical on every Linux architecture,
// while O_CREAT, O_TRUNC and O_APPEND are not, and this function must not
// become a second place where an architecture assumption can mislabel events.
// openat2 passes a struct pointer rather than flags, so it is never inspected.
func (n *normalizer) openForWriting() bool {
	if n.sc == nil {
		return false
	}
	var key string
	switch n.call {
	case "open":
		key = "a1"
	case "openat":
		key = "a2"
	default:
		return false
	}
	v, ok := n.sc.Fields[key]
	if !ok {
		return false
	}
	flags, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 64)
	if err != nil {
		return false
	}
	return flags&3 != 0
}

func (n *normalizer) pathHasNametype(want string) bool {
	for _, r := range n.g.All(audit.TypePath) {
		if strings.EqualFold(r.Fields["nametype"], want) {
			return true
		}
	}
	return false
}

// pathNametypeCategory is the architecture-independent fallback: the kernel
// labels every PATH record with what it did to that path.
func (n *normalizer) pathNametypeCategory() (string, bool) {
	paths := n.g.All(audit.TypePath)
	if len(paths) == 0 {
		return "", false
	}
	switch {
	case n.pathHasNametype("CREATE"):
		return TypeFileCreate, true
	case n.pathHasNametype("DELETE"):
		return TypeFileDelete, true
	}
	// NORMAL, PARENT, UNKNOWN or absent: a path was touched and we cannot say
	// it was changed, so report the weaker claim.
	return TypeFileAccess, true
}

// ---------------------------------------------------------------------------
// typed field extraction
// ---------------------------------------------------------------------------

// extractIdentity fills the pointer-valued identity fields. A field is only
// removed from Fields when it was successfully promoted, so a value that could
// not be parsed as a number (an enriched "root", an unset auid) stays visible
// as raw evidence instead of disappearing.
func (n *normalizer) extractIdentity() {
	n.e.PID = n.promoteID("pid")
	n.e.PPID = n.promoteID("ppid")
	n.e.UID = n.promoteID("uid")
	n.e.GID = n.promoteID("gid")

	if v, ok := n.lookup("auid"); ok {
		if isAUIDUnset(v) {
			// The kernel writes unsigned -1 when no login uid was ever set.
			// Reporting 4294967295 as a user id would be actively misleading,
			// so the typed field stays nil and the literal value remains in
			// Fields.
			n.e.AUID = nil
		} else if id, ok := parseID(v); ok {
			n.e.AUID = Int(id)
			n.promoted["auid"] = true
		}
	}
}

func (n *normalizer) promoteID(key string) *int {
	v, ok := n.lookup(key)
	if !ok {
		return nil
	}
	id, ok := parseID(v)
	if !ok {
		return nil
	}
	n.promoted[key] = true
	return Int(id)
}

// parseID accepts the unsigned 32-bit ids the kernel reports. Negative and
// non-numeric values (enriched names such as "root", or "unset") are rejected
// so that they are not silently coerced into a wrong numeric identity.
func parseID(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if !isAllDigits(v) {
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, false
	}
	return int(id), true
}

func isAUIDUnset(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case strconv.FormatUint(AUIDUnset, 10), "-1", "unset", "4294967295":
		return true
	}
	return false
}

func (n *normalizer) extractExecutable() {
	if v, ok := n.lookup("exe"); ok && v != "" && v != "?" {
		n.e.Executable = v
		n.promoted["exe"] = true
	}
}

func (n *normalizer) extractCWD() {
	if v, ok := n.g.Field("cwd", audit.TypeCwd); ok && v != "" {
		n.e.CWD = v
		return
	}
	// USER_CMD carries its working directory inside msg='cwd="..." ...'.
	for _, pairs := range n.embedded {
		if v, ok := pairs["cwd"]; ok && v != "" {
			n.e.CWD = v
			return
		}
	}
}

// extractCommand reconstructs the command line, preferring EXECVE (the exact
// argument vector the kernel saw) over PROCTITLE (a snapshot of /proc that the
// process itself can rewrite).
func (n *normalizer) extractCommand() {
	if args, ok := n.execveArgs(); ok {
		n.e.Command = strings.Join(args, " ")
		// Joining with spaces cannot be undone when an argument contains a
		// space, so the exact vector is kept as well. Argument boundaries are
		// what distinguishes `rm "-rf /"` from `rm -rf /`.
		n.e.SetField("argv", args)
		if proc, ok := n.proctitle(); ok {
			n.e.SetField("proctitle", proc)
		}
		return
	}
	if proc, ok := n.proctitle(); ok {
		n.e.Command = proc
		return
	}
	// USER_CMD (sudo and friends) reports the command inside its msg payload.
	for _, pairs := range n.embedded {
		if v, ok := pairs["cmd"]; ok && v != "" {
			n.e.Command = v
			return
		}
	}
}

// execveArgs rebuilds argv from the EXECVE record(s).
//
// argc is treated as a hint, never as an allocation size: the loop walks the
// keys that are actually present and stops at the first gap, so a record
// claiming argc=2000000 costs nothing. The kernel splits long arguments into
// a<i>_len plus a<i>[0], a<i>[1], ... chunks, which are reassembled here.
func (n *normalizer) execveArgs() ([]string, bool) {
	recs := n.g.All(audit.TypeExecve)
	if len(recs) == 0 {
		return nil, false
	}
	merged := make(map[string]string, 16)
	for _, r := range recs {
		for k, v := range r.Fields {
			if _, dup := merged[k]; !dup {
				merged[k] = v
			}
		}
	}

	args := make([]string, 0, 8)
	for i := 0; i < maxExecveArgs; i++ {
		key := "a" + strconv.Itoa(i)
		if v, ok := merged[key]; ok {
			args = append(args, v)
			continue
		}
		if _, ok := merged[key+"_len"]; !ok {
			break
		}
		var sb strings.Builder
		for j := 0; j < maxArgChunks; j++ {
			chunk, ok := merged[key+"["+strconv.Itoa(j)+"]"]
			if !ok {
				break
			}
			sb.WriteString(chunk)
		}
		args = append(args, sb.String())
	}

	if argc, err := strconv.Atoi(merged["argc"]); err == nil && argc != len(args) {
		// Either the record was truncated or it is inconsistent. Report the
		// discrepancy rather than trusting the reconstruction silently.
		n.e.SetField("execve_argc_mismatch", true)
	}
	return args, true
}

// proctitle decodes the PROCTITLE record. Its value is the NUL-separated argv
// of the process; a value without any NUL is a single argument, which is what
// the kernel emits when the title was rewritten by the process itself.
func (n *normalizer) proctitle() (string, bool) {
	r := n.g.First(audit.TypeProctitle)
	if r == nil {
		return "", false
	}
	v, ok := r.Fields["proctitle"]
	if !ok {
		return "", false
	}
	v = strings.TrimRight(v, "\x00")
	if v == "" {
		return "", false
	}
	if !strings.Contains(v, "\x00") {
		return v, true
	}
	return strings.Join(strings.Split(v, "\x00"), " "), true
}

// extractPaths collects the PATH records.
//
// Event.Paths holds the names exactly as the kernel reported them, because the
// literal value is the evidence; the absolute form of a relative name is
// recorded alongside it in the per-path detail under "resolved".
func (n *normalizer) extractPaths() {
	recs := n.g.All(audit.TypePath)
	if len(recs) == 0 {
		return
	}

	// The kernel emits PATH records in item order, but ordering the group by
	// the item number makes the result independent of arrival order after a
	// timeout-truncated correlation.
	order := make([]int, len(recs))
	items := make([]int, len(recs))
	for i, r := range recs {
		order[i] = i
		items[i] = i
		if v, err := strconv.Atoi(strings.TrimSpace(r.Fields["item"])); err == nil && v >= 0 {
			items[i] = v
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return items[order[a]] < items[order[b]] })

	details := make([]map[string]any, 0, len(recs))
	seen := make(map[string]bool, len(recs))
	for _, idx := range order {
		r := recs[idx]
		detail := make(map[string]any, len(r.Fields)+1)
		for k, v := range r.Fields {
			detail[k] = v
		}
		// Type the numeric members so that a consumer can compare them.
		for _, k := range []string{"item", "inode", "ouid", "ogid"} {
			if s, ok := r.Fields[k]; ok {
				if v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
					detail[k] = v
				}
			}
		}

		name := r.Fields["name"]
		if name != "" && name != "?" {
			if !strings.HasPrefix(name, "/") && n.e.CWD != "" {
				detail["resolved"] = path.Join(n.e.CWD, name)
			}
			if !seen[name] {
				seen[name] = true
				n.e.Paths = append(n.e.Paths, name)
			}
		}
		details = append(details, detail)
	}
	n.e.SetField("path_details", details)

	// An exec whose SYSCALL record carried no exe= is still identified by the
	// path the kernel resolved for it.
	if n.e.Executable == "" && n.e.Type == TypeProcessExec && len(n.e.Paths) > 0 {
		n.e.Executable = n.e.Paths[0]
	}
}

func (n *normalizer) extractResult() {
	n.e.Result = n.resultWord()
	if v, ok := n.lookup("exit"); ok {
		if code, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			n.e.SetField("exit", code)
		} else {
			n.e.SetField("exit", v)
		}
		n.promoted["exit"] = true
	}
}

func (n *normalizer) resultWord() string {
	if v, ok := n.lookup("success"); ok {
		if r := resultOf(v); r != "" {
			n.promoted["success"] = true
			return r
		}
	}
	if v, ok := n.lookup("res"); ok {
		if r := resultOf(v); r != "" {
			return r
		}
	}
	return ""
}

func resultOf(v string) string {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(v), "'\"")) {
	case "yes", "success", "1", "ok":
		return ResultSuccess
	case "no", "failed", "fail", "failure", "0":
		return ResultFailure
	}
	return ""
}

// ---------------------------------------------------------------------------
// remaining fields
// ---------------------------------------------------------------------------

// collectFields moves everything that did not become a typed field into
// Event.Fields. SYSCALL fields go to the top level minus the promoted keys;
// every other record is stored verbatim under its namespaced key so that a
// consumer reading Fields["avc"] sees exactly what the kernel wrote.
func (n *normalizer) collectFields() {
	syscallSeen := false
	for i, r := range n.g.Records {
		if r == nil {
			continue
		}
		if r.Type == audit.TypeSyscall && !syscallSeen {
			syscallSeen = true
			n.collectSyscall(r)
			continue
		}
		n.namespaceRecord(i, r)
	}
}

func (n *normalizer) collectSyscall(r *audit.Record) {
	for k, v := range r.Fields {
		if n.promoted[k] {
			continue
		}
		n.e.SetField(k, v)
	}
	if n.resolvedCall {
		// Keep the number as the kernel wrote it and add the translation, so
		// that a wrong table can be spotted instead of silently believed.
		n.e.SetField("syscall_name", n.call)
	}
}

// namespaceRecord stores one non-SYSCALL record under its record-type key.
// Keys already consumed into a typed field are skipped; anything left over is
// preserved so that no record contributes zero information.
func (n *normalizer) namespaceRecord(idx int, r *audit.Record) {
	switch r.Type {
	case audit.TypePath:
		// Fully represented by Fields["path_details"].
		return
	case audit.TypeProctitle:
		if _, ok := n.e.Fields["proctitle"]; !ok && n.e.Command == "" {
			// Neither Command nor Fields["proctitle"] took it (empty or
			// unparseable): keep whatever was there.
			if v, ok := r.Fields["proctitle"]; ok {
				n.e.SetField("proctitle", v)
			}
		}
		n.namespaceLeftovers(idx, r, func(k string) bool { return k == "proctitle" })
		return
	case audit.TypeCwd:
		n.namespaceLeftovers(idx, r, func(k string) bool { return k == "cwd" })
		return
	case audit.TypeExecve:
		n.namespaceLeftovers(idx, r, isExecveArgKey)
		return
	case audit.TypeSyscall:
		// A second SYSCALL record in one group should not happen; it is kept
		// under its own key rather than overwriting the first one's fields.
		n.storeNamespaced("syscall_extra", n.recordMap(idx, r, nil))
		return
	}
	n.storeNamespaced(namespaceKey(r.TypeName), n.recordMap(idx, r, nil))
}

func (n *normalizer) namespaceLeftovers(idx int, r *audit.Record, consumed func(string) bool) {
	m := n.recordMap(idx, r, consumed)
	if len(m) == 0 {
		return
	}
	n.storeNamespaced(namespaceKey(r.TypeName), m)
}

func (n *normalizer) recordMap(idx int, r *audit.Record, consumed func(string) bool) map[string]any {
	m := make(map[string]any, len(r.Fields)+4)
	for k, v := range r.Fields {
		if consumed != nil && consumed(k) {
			continue
		}
		m[k] = v
	}
	// Pairs hidden inside msg='...' are lifted alongside the verbatim msg
	// string. Existing keys win, so the record's own fields are never
	// overwritten by the encapsulated copy.
	if idx >= 0 && idx < len(n.embedded) {
		for k, v := range n.embedded[idx] {
			if _, ok := m[k]; !ok {
				m[k] = v
			}
		}
	}
	return m
}

// storeNamespaced keeps every record of a repeated type: the first becomes a
// map, further ones turn the value into a list of maps.
func (n *normalizer) storeNamespaced(key string, m map[string]any) {
	switch cur := n.e.Fields[key].(type) {
	case nil:
		n.e.SetField(key, m)
	case map[string]any:
		n.e.SetField(key, []map[string]any{cur, m})
	case []map[string]any:
		n.e.SetField(key, append(cur, m))
	default:
		n.e.SetField(key+"_extra", m)
	}
}

// isExecveArgKey matches the EXECVE argument keys (a0, a1, a1_len, a1[0]),
// which are consumed into Command and Fields["argv"].
func isExecveArgKey(k string) bool {
	if k == "argc" {
		return true
	}
	if len(k) < 2 || k[0] != 'a' {
		return false
	}
	i := 1
	for i < len(k) && k[i] >= '0' && k[i] <= '9' {
		i++
	}
	if i == 1 {
		return false
	}
	rest := k[i:]
	return rest == "" || rest == "_len" || (strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]"))
}

// namespaceKey turns a record type name into a Fields key: lowercase, with
// anything that is not a letter or digit collapsed to an underscore, so that
// an unknown record (UNKNOWN[1234]) still gets a stable, safe key.
func namespaceKey(typeName string) string {
	var b strings.Builder
	b.Grow(len(typeName))
	sep := true
	for i := 0; i < len(typeName); i++ {
		c := typeName[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c - 'A' + 'a')
			sep = false
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
			sep = false
		default:
			if !sep {
				b.WriteByte('_')
				sep = true
			}
		}
	}
	s := strings.TrimSuffix(b.String(), "_")
	if s == "" {
		return "record"
	}
	return s
}

// ---------------------------------------------------------------------------
// severity
// ---------------------------------------------------------------------------

// severity scores the event. DESIGN section 30 is explicit that changes to the
// audit subsystem itself are never ordinary informational events, so they
// start at warning and escalate to critical when auditing is being weakened.
func (n *normalizer) severity() string {
	switch n.e.Type {
	case TypeAuditConfiguration:
		if n.auditWeakened() {
			return SeverityCritical
		}
		return SeverityWarning
	case TypeAuthFailure, TypeSELinuxDenial, TypeFirewallConfiguration, TypePrivilegeChange:
		return SeverityWarning
	}
	return SeverityInfo
}

// auditWeakened reports whether the configuration change disables auditing or
// alters the rule set -- the two changes an intruder makes before doing
// anything they do not want recorded.
func (n *normalizer) auditWeakened() bool {
	if n.g.Has(audit.TypeDaemonAbort) || n.g.Has(audit.TypeDaemonEnd) {
		return true
	}
	// A rule add or delete is itself a rule change, whichever way it is
	// reported: as a record type or as an op= on CONFIG_CHANGE.
	if n.g.Has(audit.TypeAddRule) || n.g.Has(audit.TypeDelRule) {
		return true
	}
	for _, key := range []string{"enabled", "audit_enabled"} {
		if v, ok := n.lookup(key); ok && strings.TrimSpace(v) == "0" {
			return true
		}
	}
	if v, ok := n.lookup("op"); ok {
		switch normalizeOp(v) {
		case "add_rule", "remove_rule", "delete_rule":
			return true
		}
	}
	return false
}

// normalizeOp folds the spellings auditd has used over the years
// ("remove rule", "remove_rule", quoted variants) onto one token.
func normalizeOp(v string) string {
	v = strings.ToLower(strings.Trim(strings.TrimSpace(v), "'\""))
	return strings.ReplaceAll(v, " ", "_")
}

// ---------------------------------------------------------------------------
// msg='...' payloads
// ---------------------------------------------------------------------------

// embeddedPairs extracts the key=value pairs that user-space records carry
// inside msg='...'.
//
// Records such as USER_AUTH keep everything that matters (op, acct, res) in
// that payload, and whether the record parser expands it is a detail this
// package must not depend on. The scan is bounded by maxEmbeddedPairs and by
// the length of the string, allocates nothing from a length in the input and
// never recurses, because the payload originates in a process the guest
// controls.
func embeddedPairs(s string) map[string]string {
	if len(s) > maxEmbeddedValue {
		s = s[:maxEmbeddedValue]
	}
	if !strings.Contains(s, "=") {
		return nil
	}
	var out map[string]string
	i := 0
	for i < len(s) && (out == nil || len(out) < maxEmbeddedPairs) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == ',' || s[i] == '\'') {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			for i < len(s) && s[i] != ' ' {
				i++
			}
			continue
		}
		key := s[start:i]
		i++
		var val string
		if i < len(s) && (s[i] == '"' || s[i] == '\'') {
			quote := s[i]
			i++
			vs := i
			for i < len(s) && s[i] != quote {
				i++
			}
			val = s[vs:i]
			if i < len(s) {
				i++
			}
		} else {
			vs := i
			for i < len(s) && s[i] != ' ' {
				i++
			}
			val = strings.TrimRight(s[vs:i], "'")
		}
		if key == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string, 8)
		}
		if _, dup := out[key]; !dup {
			out[key] = decodeEmbedded(key, val)
		}
	}
	return out
}

// decodeEmbedded hex-decodes the two payload values that auditd hex-encodes
// when they contain shell metacharacters. It is limited to those keys on
// purpose: any even-length decimal value would otherwise look like valid hex
// and be mangled. The original text remains available in the verbatim msg
// field, so decoding cannot lose anything.
func decodeEmbedded(key, val string) string {
	switch key {
	case "cmd", "proctitle":
	default:
		return val
	}
	if len(val) < 2 || len(val)%2 != 0 || len(val) > maxEmbeddedValue {
		return val
	}
	raw, err := hex.DecodeString(val)
	if err != nil {
		return val
	}
	decoded := strings.TrimRight(string(raw), "\x00")
	return strings.ReplaceAll(decoded, "\x00", " ")
}

// ---------------------------------------------------------------------------
// x86_64 syscall table
// ---------------------------------------------------------------------------

// x8664Syscalls maps the syscall numbers this package classifies on to their
// names, for the x86_64 ABI only (AUDIT_ARCH_X86_64 = c000003e).
//
// It is deliberately not a complete table: it covers the calls that
// classification depends on plus the immediately neighbouring file calls.
// Numbers that are absent are reported numerically, which is the safe outcome.
//
// LIMITATION: these numbers are valid for x86_64 and nothing else. arm64,
// i386, s390x and the compat ABIs all number their syscalls differently --
// 59 is execve on x86_64, but on arm64 it is close(). syscallName therefore
// refuses to consult this table unless arch= says x86_64, and events from
// other architectures are classified from PATH nametype instead. Anyone
// adding an architecture must add its own table rather than relaxing that
// check.
var x8664Syscalls = map[int]string{
	0:   "read",
	1:   "write",
	2:   "open",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	59:  "execve",
	60:  "exit",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	132: "utime",
	133: "mknod",
	188: "setxattr",
	189: "lsetxattr",
	190: "fsetxattr",
	191: "getxattr",
	192: "lgetxattr",
	193: "fgetxattr",
	194: "listxattr",
	195: "llistxattr",
	196: "flistxattr",
	197: "removexattr",
	198: "lremovexattr",
	199: "fremovexattr",
	217: "getdents64",
	231: "exit_group",
	235: "utimes",
	257: "openat",
	258: "mkdirat",
	259: "mknodat",
	260: "fchownat",
	261: "futimesat",
	262: "newfstatat",
	263: "unlinkat",
	264: "renameat",
	265: "linkat",
	266: "symlinkat",
	267: "readlinkat",
	268: "fchmodat",
	269: "faccessat",
	280: "utimensat",
	285: "fallocate",
	295: "preadv",
	296: "pwritev",
	316: "renameat2",
	322: "execveat",
	327: "preadv2",
	328: "pwritev2",
	332: "statx",
	437: "openat2",
	439: "faccessat2",
	452: "fchmodat2",
}
