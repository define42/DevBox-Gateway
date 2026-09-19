package event

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/audit"
)

// ---------------------------------------------------------------------------
// test helpers
//
// The record text used throughout this file is real auditd output. It is
// turned into audit.Record values by the helper below rather than by
// audit.ParseLine, because the parser is being implemented in parallel with
// this package. The helper follows the documented parser contract (quotes
// removed, hex-encoded values decoded, keys as the kernel emitted them), so
// swapping it for ParseLine must not change a single expectation here.
// ---------------------------------------------------------------------------

func mustRecord(tb testing.TB, line string) *audit.Record {
	tb.Helper()
	raw := strings.TrimSpace(line)

	rest, ok := strings.CutPrefix(raw, "type=")
	if !ok {
		tb.Fatalf("record does not start with type=: %q", raw)
	}
	name, rest, ok := strings.Cut(rest, " ")
	if !ok {
		tb.Fatalf("record has no message body: %q", raw)
	}
	typ, ok := audit.RecordTypeByName(name)
	if !ok {
		tb.Fatalf("unknown record type name %q", name)
	}
	rest, ok = strings.CutPrefix(rest, "msg=audit(")
	if !ok {
		tb.Fatalf("record has no audit() header: %q", raw)
	}
	id, body, ok := strings.Cut(rest, "):")
	if !ok {
		tb.Fatalf("unterminated audit() header: %q", raw)
	}

	stamp, serialText, _ := strings.Cut(id, ":")
	secsText, msecsText, _ := strings.Cut(stamp, ".")
	secs, err := strconv.ParseInt(secsText, 10, 64)
	if err != nil {
		tb.Fatalf("bad timestamp %q: %v", id, err)
	}
	msecs, _ := strconv.ParseInt(msecsText, 10, 64)
	serial, _ := strconv.ParseUint(serialText, 10, 64)

	return &audit.Record{
		Type:      typ,
		TypeName:  name,
		Timestamp: time.Unix(secs, msecs*int64(time.Millisecond)).UTC(),
		Serial:    serial,
		AuditID:   id,
		Fields:    parseTestFields(name, strings.TrimSpace(body)),
		Raw:       raw,
	}
}

func parseTestFields(typeName, body string) map[string]string {
	fields := make(map[string]string, 16)
	i := 0
	for i < len(body) {
		for i < len(body) && body[i] == ' ' {
			i++
		}
		start := i
		for i < len(body) && body[i] != '=' && body[i] != ' ' {
			i++
		}
		if i >= len(body) || body[i] != '=' {
			for i < len(body) && body[i] != ' ' {
				i++
			}
			continue
		}
		key := body[start:i]
		i++
		var val string
		if i < len(body) && (body[i] == '"' || body[i] == '\'') {
			quote := body[i]
			i++
			vs := i
			for i < len(body) && body[i] != quote {
				i++
			}
			val = body[vs:i]
			if i < len(body) {
				i++
			}
		} else {
			vs := i
			for i < len(body) && body[i] != ' ' {
				i++
			}
			val = decodeTestHex(typeName, key, body[vs:i])
		}
		if key != "" {
			fields[key] = val
		}
	}
	return fields
}

// decodeTestHex mirrors the parser rule that unquoted values of text fields
// are hex-encoded when they contain characters that would break the record
// format. The SYSCALL record's a0..a3 are hex *numbers*, not strings, so the
// argument keys are only decoded for EXECVE.
func decodeTestHex(typeName, key, val string) string {
	switch key {
	case "proctitle", "name", "cmd":
	default:
		if typeName != "EXECVE" || len(key) < 2 || key[0] != 'a' {
			return val
		}
	}
	if len(val) < 2 || len(val)%2 != 0 {
		return val
	}
	raw, err := hex.DecodeString(val)
	if err != nil {
		return val
	}
	return string(raw)
}

func mustGroup(tb testing.TB, complete bool, lines ...string) *audit.Group {
	tb.Helper()
	g := &audit.Group{Complete: complete}
	for _, line := range lines {
		r := mustRecord(tb, line)
		if len(g.Records) == 0 {
			g.AuditID = r.AuditID
			g.Serial = r.Serial
			g.Timestamp = r.Timestamp
		}
		g.Records = append(g.Records, r)
	}
	return g
}

// ---------------------------------------------------------------------------
// realistic record text shared by several tests
// ---------------------------------------------------------------------------

const (
	execSyscall   = `type=SYSCALL msg=audit(1789752345.312:8421): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd1a2b3c40 a1=7ffd1a2b3d10 a2=7ffd1a2b3d28 a3=8 items=2 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" subj=unconfined_u:unconfined_r:unconfined_t:s0 key=(null)`
	execExecve    = `type=EXECVE msg=audit(1789752345.312:8421): argc=2 a0="cat" a1="/etc/shadow"`
	execCwd       = `type=CWD msg=audit(1789752345.312:8421): cwd="/home/user"`
	execPath      = `type=PATH msg=audit(1789752345.312:8421): item=0 name="/etc/shadow" inode=1442 dev=fd:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0`
	execProctitle = `type=PROCTITLE msg=audit(1789752345.312:8421): proctitle=636174002F6574632F736861646F77`
)

func execGroup(tb testing.TB) *audit.Group {
	tb.Helper()
	return mustGroup(tb, true, execSyscall, execExecve, execCwd, execPath, execProctitle)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

// TestNormalizeExecveGroup asserts the worked example in DESIGN section 7:
// five kernel records for one `cat /etc/shadow` collapse into exactly one
// process.exec event with those field values.
func TestNormalizeExecveGroup(t *testing.T) {
	e := Normalize(execGroup(t), NormalizeOptions{BootID: "8f1d0c1e-2b4a-4a7e-9f31-0d5c6b2a7e10"})
	if e == nil {
		t.Fatal("Normalize returned nil for a complete group")
	}

	if got, want := e.Type, TypeProcessExec; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
	if got, want := e.AuditID, "1789752345.312:8421"; got != want {
		t.Errorf("AuditID = %q, want %q", got, want)
	}
	if got, want := e.Severity, SeverityInfo; got != want {
		t.Errorf("Severity = %q, want %q", got, want)
	}
	if got, want := e.Version, SchemaVersion; got != want {
		t.Errorf("Version = %d, want %d", got, want)
	}
	if got, want := e.BootID, "8f1d0c1e-2b4a-4a7e-9f31-0d5c6b2a7e10"; got != want {
		t.Errorf("BootID = %q, want %q", got, want)
	}
	if got, want := e.Timestamp.UnixMilli(), int64(1789752345312); got != want {
		t.Errorf("Timestamp = %d ms, want %d ms", got, want)
	}

	assertInt(t, "PID", e.PID, 4821)
	assertInt(t, "PPID", e.PPID, 4702)
	assertInt(t, "UID", e.UID, 0)
	assertInt(t, "GID", e.GID, 0)
	assertInt(t, "AUID", e.AUID, 1000)

	if got, want := e.Executable, "/usr/bin/cat"; got != want {
		t.Errorf("Executable = %q, want %q", got, want)
	}
	if got, want := e.Command, "cat /etc/shadow"; got != want {
		t.Errorf("Command = %q, want %q", got, want)
	}
	if got, want := e.CWD, "/home/user"; got != want {
		t.Errorf("CWD = %q, want %q", got, want)
	}
	assertStrings(t, "Paths", e.Paths, []string{"/etc/shadow"})
	if got, want := e.Result, ResultSuccess; got != want {
		t.Errorf("Result = %q, want %q", got, want)
	}
	assertStrings(t, "RecordTypes", e.RecordTypes,
		[]string{"SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"})

	if e.Raw != nil {
		t.Errorf("Raw = %v, want nil when PreserveRaw is off", e.Raw)
	}

	// SYSCALL fields live at the top level of Fields, minus the ones promoted
	// to typed fields.
	for _, key := range []string{"pid", "ppid", "uid", "gid", "auid", "exe", "success"} {
		if v, ok := e.Fields[key]; ok {
			t.Errorf("Fields[%q] = %v, want it promoted to a typed field", key, v)
		}
	}
	if got, want := e.Fields["comm"], "cat"; got != want {
		t.Errorf("Fields[comm] = %v, want %q", got, want)
	}
	if got, want := e.Fields["ses"], "3"; got != want {
		t.Errorf("Fields[ses] = %v, want %q", got, want)
	}
	if got, want := e.Fields["syscall"], "59"; got != want {
		t.Errorf("Fields[syscall] = %v, want the literal kernel value %q", got, want)
	}
	if got, want := e.Fields["syscall_name"], "execve"; got != want {
		t.Errorf("Fields[syscall_name] = %v, want %q", got, want)
	}
	if got, want := e.Fields["exit"], int64(0); got != want {
		t.Errorf("Fields[exit] = %#v, want %#v", e.Fields["exit"], want)
	}
	argv, ok := e.Fields["argv"].([]string)
	if !ok {
		t.Fatalf("Fields[argv] = %#v, want []string", e.Fields["argv"])
	}
	assertStrings(t, "Fields[argv]", argv, []string{"cat", "/etc/shadow"})
	if got, want := e.Fields["proctitle"], "cat /etc/shadow"; got != want {
		t.Errorf("Fields[proctitle] = %v, want %q (PROCTITLE must not be lost)", got, want)
	}
	if _, ok := e.Fields["correlation_incomplete"]; ok {
		t.Error("Fields[correlation_incomplete] set for a complete group")
	}

	details, ok := e.Fields["path_details"].([]map[string]any)
	if !ok || len(details) != 1 {
		t.Fatalf("Fields[path_details] = %#v, want one entry", e.Fields["path_details"])
	}
	if got, want := details[0]["nametype"], "NORMAL"; got != want {
		t.Errorf("path_details[0][nametype] = %v, want %q", got, want)
	}
	if got, want := details[0]["inode"], int64(1442); got != want {
		t.Errorf("path_details[0][inode] = %#v, want %#v", details[0]["inode"], want)
	}
	if got, want := details[0]["ogid"], int64(42); got != want {
		t.Errorf("path_details[0][ogid] = %#v, want %#v", details[0]["ogid"], want)
	}
	if got, want := details[0]["mode"], "0100640"; got != want {
		t.Errorf("path_details[0][mode] = %v, want %q", got, want)
	}
	if _, ok := details[0]["resolved"]; ok {
		t.Error("path_details[0][resolved] set for an absolute path")
	}
}

// TestEventJSONUIDZero is the regression that matters most in this package: a
// root event must serialize uid=0, and an event with no uid at all must omit
// the key entirely. A plain int with omitempty would make those two cases
// indistinguishable and hide every action taken by root.
func TestEventJSONUIDZero(t *testing.T) {
	e := Normalize(execGroup(t), NormalizeOptions{})
	blob, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"uid":0`) {
		t.Fatalf("uid=0 did not survive serialization: %s", blob)
	}
	if !strings.Contains(string(blob), `"gid":0`) {
		t.Fatalf("gid=0 did not survive serialization: %s", blob)
	}

	var back Event
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assertInt(t, "round-tripped UID", back.UID, 0)
	assertInt(t, "round-tripped AUID", back.AUID, 1000)
	if back.Type != e.Type || back.Command != e.Command || back.Executable != e.Executable {
		t.Errorf("round trip changed the event: %+v", back)
	}
	assertStrings(t, "round-tripped Paths", back.Paths, e.Paths)

	// A record set that carries no uid at all must not gain one.
	noUID := Normalize(mustGroup(t, true,
		`type=NETFILTER_CFG msg=audit(1789753200.500:9300): table=filter family=2 entries=189`,
	), NormalizeOptions{})
	blob, err = json.Marshal(noUID)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(blob), `"uid"`) {
		t.Fatalf("absent uid was serialized anyway: %s", blob)
	}
	if strings.Contains(string(blob), `"auid"`) {
		t.Fatalf("absent auid was serialized anyway: %s", blob)
	}
}

// TestNormalizeAUIDUnset checks that the kernel's "no login uid" sentinel
// never reaches a consumer as a user id.
func TestNormalizeAUIDUnset(t *testing.T) {
	tests := []struct {
		name    string
		auid    string
		want    *int
		inField bool
	}{
		{name: "unsigned -1", auid: "4294967295", want: nil, inField: true},
		{name: "signed -1", auid: "-1", want: nil, inField: true},
		{name: "enriched unset", auid: "unset", want: nil, inField: true},
		{name: "real login uid", auid: "1000", want: Int(1000)},
		{name: "root login uid", auid: "0", want: Int(0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := `type=SYSCALL msg=audit(1789752345.312:8421): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1 pid=900 auid=` + tc.auid +
				` uid=0 gid=0 ses=4294967295 comm="systemd" exe="/usr/lib/systemd/systemd" key=(null)`
			e := Normalize(mustGroup(t, true, line,
				`type=PATH msg=audit(1789752345.312:8421): item=0 name="/etc/machine-id" inode=12 dev=fd:01 mode=0100444 ouid=0 ogid=0 nametype=NORMAL`,
			), NormalizeOptions{})

			switch {
			case tc.want == nil && e.AUID != nil:
				t.Fatalf("AUID = %d, want nil for auid=%q", *e.AUID, tc.auid)
			case tc.want != nil && e.AUID == nil:
				t.Fatalf("AUID = nil, want %d", *tc.want)
			case tc.want != nil && *e.AUID != *tc.want:
				t.Fatalf("AUID = %d, want %d", *e.AUID, *tc.want)
			}
			if tc.inField {
				// The literal value is still evidence and must remain visible.
				if got, ok := e.Fields["auid"]; !ok || got != tc.auid {
					t.Errorf("Fields[auid] = %v (present=%t), want the literal %q", got, ok, tc.auid)
				}
			}
		})
	}
}

// TestNormalizeCategories drives the category mapping from realistic record
// text, one group per rule.
func TestNormalizeCategories(t *testing.T) {
	tests := []struct {
		name         string
		lines        []string
		wantType     string
		wantSeverity string
		wantResult   string
		check        func(t *testing.T, e *Event)
	}{
		{
			name:         "execve is process.exec",
			lines:        []string{execSyscall, execExecve, execCwd, execPath, execProctitle},
			wantType:     TypeProcessExec,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
		},
		{
			name: "exit_group is process.exit",
			lines: []string{
				`type=SYSCALL msg=audit(1789752400.010:8500): arch=c000003e syscall=231 success=yes exit=0 a0=0 items=0 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 ses=3 comm="cat" exe="/usr/bin/cat" key=(null)`,
			},
			wantType:     TypeProcessExit,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
		},
		{
			name: "openat with nametype CREATE is file.create",
			lines: []string{
				`type=SYSCALL msg=audit(1789752500.100:8600): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe4c2a1b30 a2=241 a3=1b6 items=2 ppid=2100 pid=2711 auid=1000 uid=1000 gid=1000 ses=5 comm="touch" exe="/usr/bin/touch" key="perm_mod"`,
				`type=CWD msg=audit(1789752500.100:8600): cwd="/home/user"`,
				`type=PATH msg=audit(1789752500.100:8600): item=0 name="/tmp" inode=2 dev=fd:01 mode=041777 ouid=0 ogid=0 rdev=00:00 nametype=PARENT`,
				`type=PATH msg=audit(1789752500.100:8600): item=1 name="/tmp/payload" inode=99123 dev=fd:01 mode=0100644 ouid=1000 ogid=1000 rdev=00:00 nametype=CREATE`,
			},
			wantType:     TypeFileCreate,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
			check: func(t *testing.T, e *Event) {
				assertStrings(t, "Paths", e.Paths, []string{"/tmp", "/tmp/payload"})
			},
		},
		{
			name: "chmod is file.modify",
			lines: []string{
				`type=SYSCALL msg=audit(1789752600.200:8700): arch=c000003e syscall=268 success=yes exit=0 a0=ffffff9c a1=55d1c2 a2=1ff a3=0 items=1 ppid=2100 pid=2801 auid=1000 uid=0 gid=0 ses=5 comm="chmod" exe="/usr/bin/chmod" key="perm_mod"`,
				`type=CWD msg=audit(1789752600.200:8700): cwd="/etc"`,
				`type=PATH msg=audit(1789752600.200:8700): item=0 name="shadow" inode=1442 dev=fd:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL`,
			},
			wantType:     TypeFileModify,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
			check: func(t *testing.T, e *Event) {
				// The kernel reported a relative name; Paths keeps it and the
				// absolute form is recorded beside it.
				assertStrings(t, "Paths", e.Paths, []string{"shadow"})
				details := e.Fields["path_details"].([]map[string]any)
				if got, want := details[0]["resolved"], "/etc/shadow"; got != want {
					t.Errorf("path_details[0][resolved] = %v, want %q", got, want)
				}
			},
		},
		{
			name: "openat for writing is file.modify",
			lines: []string{
				`type=SYSCALL msg=audit(1789752610.200:8710): arch=c000003e syscall=257 success=yes exit=4 a0=ffffff9c a1=7ffe4c2a1b30 a2=401 a3=0 items=1 ppid=1 pid=3312 auid=4294967295 uid=0 gid=0 ses=4294967295 comm="rsyslogd" exe="/usr/sbin/rsyslogd" key=(null)`,
				`type=PATH msg=audit(1789752610.200:8710): item=0 name="/var/log/secure" inode=4021 dev=fd:01 mode=0100600 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`,
			},
			wantType:     TypeFileModify,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
		},
		{
			name: "unlinkat is file.delete",
			lines: []string{
				`type=SYSCALL msg=audit(1789752700.300:8800): arch=c000003e syscall=263 success=yes exit=0 a0=ffffff9c a1=7ffd88 a2=0 a3=0 items=2 ppid=2100 pid=2901 auid=1000 uid=1000 gid=1000 ses=5 comm="rm" exe="/usr/bin/rm" key="delete"`,
				`type=CWD msg=audit(1789752700.300:8800): cwd="/var/tmp/work"`,
				`type=PATH msg=audit(1789752700.300:8800): item=1 name="secret.txt" inode=99124 dev=fd:00 mode=0100600 ouid=1000 ogid=1000 rdev=00:00 nametype=DELETE`,
				`type=PATH msg=audit(1789752700.300:8800): item=0 name="/var/tmp/work" inode=88 dev=fd:00 mode=040755 ouid=1000 ogid=1000 rdev=00:00 nametype=PARENT`,
			},
			wantType:     TypeFileDelete,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
			check: func(t *testing.T, e *Event) {
				// PATH records arrived out of order; item order decides.
				assertStrings(t, "Paths", e.Paths, []string{"/var/tmp/work", "secret.txt"})
				details := e.Fields["path_details"].([]map[string]any)
				if got, want := details[0]["item"], int64(0); got != want {
					t.Errorf("path_details[0][item] = %#v, want %#v", details[0]["item"], want)
				}
				if got, want := details[1]["resolved"], "/var/tmp/work/secret.txt"; got != want {
					t.Errorf("path_details[1][resolved] = %v, want %q", got, want)
				}
			},
		},
		{
			name: "read-only openat is file.access",
			lines: []string{
				`type=SYSCALL msg=audit(1789752800.400:8900): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe1c a2=0 a3=0 items=1 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 ses=3 comm="cat" exe="/usr/bin/cat" key="watch_shadow"`,
				`type=PATH msg=audit(1789752800.400:8900): item=0 name="/etc/shadow" inode=1442 dev=fd:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL`,
			},
			wantType:     TypeFileAccess,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
		},
		{
			name: "non-x86_64 syscall numbers fall back to nametype",
			lines: []string{
				// arm64: syscall 56 is openat, not the x86_64 meaning of 56.
				`type=SYSCALL msg=audit(1789752850.450:8950): arch=c00000b7 syscall=56 success=yes exit=3 a0=ffffff9c a1=aaaad2 a2=241 a3=1b6 items=2 ppid=1 pid=771 auid=0 uid=0 gid=0 ses=1 comm="tee" exe="/usr/bin/tee" key=(null)`,
				`type=PATH msg=audit(1789752850.450:8950): item=1 name="/etc/cron.d/backdoor" inode=770 dev=fd:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE`,
			},
			wantType:     TypeFileCreate,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
			check: func(t *testing.T, e *Event) {
				if got, want := e.Fields["syscall"], "56"; got != want {
					t.Errorf("Fields[syscall] = %v, want the untranslated %q", got, want)
				}
				if got, ok := e.Fields["syscall_name"]; ok {
					t.Errorf("Fields[syscall_name] = %v, want no translation off x86_64", got)
				}
			},
		},
		{
			name: "failed USER_AUTH is authentication.failure",
			lines: []string{
				`type=USER_AUTH msg=audit(1789752901.145:9012): pid=1832 uid=0 auid=4294967295 ses=4294967295 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=203.0.113.9 addr=203.0.113.9 terminal=ssh res=failed'`,
			},
			wantType:     TypeAuthFailure,
			wantSeverity: SeverityWarning,
			wantResult:   ResultFailure,
			check: func(t *testing.T, e *Event) {
				if e.AUID != nil {
					t.Errorf("AUID = %d, want nil", *e.AUID)
				}
				assertInt(t, "PID", e.PID, 1832)
				assertInt(t, "UID", e.UID, 0)
				if got, want := e.Executable, "/usr/sbin/sshd"; got != want {
					t.Errorf("Executable = %q, want %q", got, want)
				}
				ns := namespaced(t, e, "user_auth")
				if got, want := ns["acct"], "root"; got != want {
					t.Errorf("Fields[user_auth][acct] = %v, want %q", got, want)
				}
				if got, want := ns["res"], "failed"; got != want {
					t.Errorf("Fields[user_auth][res] = %v, want %q", got, want)
				}
				if _, ok := ns["msg"]; !ok {
					t.Error("Fields[user_auth][msg] missing: the verbatim payload must be kept")
				}
			},
		},
		{
			name: "successful USER_LOGIN is authentication.login",
			lines: []string{
				`type=USER_LOGIN msg=audit(1789752910.900:9020): pid=1832 uid=0 auid=1000 ses=5 subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/0 res=success'`,
			},
			wantType:     TypeAuthLogin,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
		},
		{
			name: "LOGIN with res=1 is authentication.login",
			lines: []string{
				`type=LOGIN msg=audit(1789752345.100:8400): pid=1832 uid=0 subj=system_u:system_r:sshd_t:s0 old-auid=4294967295 auid=1000 tty=(none) old-ses=4294967295 ses=5 res=1`,
			},
			wantType:     TypeAuthLogin,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
			check: func(t *testing.T, e *Event) {
				assertInt(t, "AUID", e.AUID, 1000)
			},
		},
		{
			name: "USER_LOGOUT is authentication.logout",
			lines: []string{
				`type=USER_LOGOUT msg=audit(1789753000.000:9050): pid=1832 uid=0 auid=1000 ses=5 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/0 res=success'`,
			},
			wantType:     TypeAuthLogout,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
		},
		{
			name: "USER_CMD is user.command",
			lines: []string{
				`type=USER_CMD msg=audit(1789752999.201:9100): pid=2712 uid=1000 auid=1000 ses=5 subj=unconfined_u:unconfined_r:unconfined_t:s0 msg='cwd="/home/user" cmd=636174202F6574632F736861646F77 terminal=pts/0 res=success'`,
			},
			wantType:     TypeUserCommand,
			wantSeverity: SeverityInfo,
			wantResult:   ResultSuccess,
			check: func(t *testing.T, e *Event) {
				if got, want := e.Command, "cat /etc/shadow"; got != want {
					t.Errorf("Command = %q, want %q", got, want)
				}
				if got, want := e.CWD, "/home/user"; got != want {
					t.Errorf("CWD = %q, want %q", got, want)
				}
				ns := namespaced(t, e, "user_cmd")
				if got, want := ns["terminal"], "pts/0"; got != want {
					t.Errorf("Fields[user_cmd][terminal] = %v, want %q", got, want)
				}
			},
		},
		{
			name: "AVC denial outranks the syscall it happened under",
			lines: []string{
				`type=AVC msg=audit(1789753100.001:9200): avc:  denied  { read } for  pid=2901 comm="httpd" name="shadow" dev="dm-0" ino=1442 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`,
				`type=SYSCALL msg=audit(1789753100.001:9200): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7f3c a2=0 a3=0 items=1 ppid=1 pid=2901 auid=4294967295 uid=48 gid=48 ses=4294967295 comm="httpd" exe="/usr/sbin/httpd" key=(null)`,
				`type=PATH msg=audit(1789753100.001:9200): item=0 name="/etc/shadow" inode=1442 dev=fd:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL`,
			},
			wantType:     TypeSELinuxDenial,
			wantSeverity: SeverityWarning,
			wantResult:   ResultFailure,
			check: func(t *testing.T, e *Event) {
				if got, want := e.Fields["exit"], int64(-13); got != want {
					t.Errorf("Fields[exit] = %#v, want %#v", e.Fields["exit"], want)
				}
				ns := namespaced(t, e, "avc")
				if got, want := ns["scontext"], "system_u:system_r:httpd_t:s0"; got != want {
					t.Errorf("Fields[avc][scontext] = %v, want %q", got, want)
				}
				if got, want := ns["tclass"], "file"; got != want {
					t.Errorf("Fields[avc][tclass] = %v, want %q", got, want)
				}
				// The AVC's own name= must not overwrite the SYSCALL view.
				if got, want := ns["name"], "shadow"; got != want {
					t.Errorf("Fields[avc][name] = %v, want %q", got, want)
				}
				assertStrings(t, "Paths", e.Paths, []string{"/etc/shadow"})
			},
		},
		{
			name: "NETFILTER_CFG is firewall.configuration",
			lines: []string{
				`type=NETFILTER_CFG msg=audit(1789753200.500:9300): table=filter family=2 entries=189 op=nft_register_rule pid=3011 subj=system_u:system_r:iptables_t:s0 comm="nft"`,
			},
			wantType:     TypeFirewallConfiguration,
			wantSeverity: SeverityWarning,
			check: func(t *testing.T, e *Event) {
				ns := namespaced(t, e, "netfilter_cfg")
				if got, want := ns["table"], "filter"; got != want {
					t.Errorf("Fields[netfilter_cfg][table] = %v, want %q", got, want)
				}
				if got, want := ns["entries"], "189"; got != want {
					t.Errorf("Fields[netfilter_cfg][entries] = %v, want %q", got, want)
				}
			},
		},
		{
			name: "CONFIG_CHANGE disabling audit is critical",
			lines: []string{
				`type=CONFIG_CHANGE msg=audit(1789753300.100:9400): op=set audit_enabled=0 old=1 auid=1000 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0 res=1`,
			},
			wantType:     TypeAuditConfiguration,
			wantSeverity: SeverityCritical,
			wantResult:   ResultSuccess,
		},
		{
			name: "CONFIG_CHANGE removing a rule is critical",
			lines: []string{
				`type=CONFIG_CHANGE msg=audit(1789753310.100:9410): auid=0 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0 op=remove_rule key="watch_shadow" list=4 res=1`,
			},
			wantType:     TypeAuditConfiguration,
			wantSeverity: SeverityCritical,
			wantResult:   ResultSuccess,
		},
		{
			name: "other audit configuration changes are warnings",
			lines: []string{
				`type=CONFIG_CHANGE msg=audit(1789753320.100:9420): op=set audit_backlog_limit=8192 old=64 auid=0 ses=1 res=1`,
			},
			wantType:     TypeAuditConfiguration,
			wantSeverity: SeverityWarning,
			wantResult:   ResultSuccess,
		},
		{
			name: "DAEMON_END is critical",
			lines: []string{
				`type=DAEMON_END msg=audit(1789753330.100:9430): op=terminate auid=0 pid=1700 subj=system_u:system_r:auditd_t:s0 res=success`,
			},
			wantType:     TypeAuditConfiguration,
			wantSeverity: SeverityCritical,
			wantResult:   ResultSuccess,
		},
		{
			name: "ADD_USER is privilege.change",
			lines: []string{
				`type=ADD_USER msg=audit(1789753400.700:9500): pid=3200 uid=0 auid=0 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0 msg='op=adding-user id=1001 exe="/usr/sbin/useradd" hostname=guest-01 addr=? terminal=pts/1 res=success'`,
			},
			wantType:     TypePrivilegeChange,
			wantSeverity: SeverityWarning,
			wantResult:   ResultSuccess,
		},
		{
			name: "CAPSET is privilege.change",
			lines: []string{
				`type=SYSCALL msg=audit(1789753410.700:9510): arch=c000003e syscall=126 success=yes exit=0 a0=20080522 a1=0 a2=0 a3=0 items=0 ppid=1 pid=3301 auid=4294967295 uid=0 gid=0 ses=4294967295 comm="sshd" exe="/usr/sbin/sshd" key=(null)`,
				`type=CAPSET msg=audit(1789753410.700:9510): pid=3301 cap_pi=0 cap_pp=0 cap_pe=0 cap_pa=0`,
			},
			wantType:     TypePrivilegeChange,
			wantSeverity: SeverityWarning,
			wantResult:   ResultSuccess,
		},
		{
			name: "unrecognised security record is system.security",
			lines: []string{
				`type=ANOM_PROMISCUOUS msg=audit(1789753500.800:9600): dev=eth0 prom=256 old_prom=0 auid=1000 uid=0 gid=0 ses=3`,
			},
			wantType:     TypeSystemSecurity,
			wantSeverity: SeverityInfo,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := Normalize(mustGroup(t, true, tc.lines...), NormalizeOptions{BootID: "boot"})
			if e == nil {
				t.Fatal("Normalize returned nil")
			}
			if got := e.Type; got != tc.wantType {
				t.Errorf("Type = %q, want %q", got, tc.wantType)
			}
			if got := e.Severity; got != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q", got, tc.wantSeverity)
			}
			if got := e.Result; got != tc.wantResult {
				t.Errorf("Result = %q, want %q", got, tc.wantResult)
			}
			if got, want := len(e.RecordTypes), len(tc.lines); got != want {
				t.Errorf("len(RecordTypes) = %d, want %d", got, want)
			}
			if tc.check != nil {
				tc.check(t, e)
			}
			if _, err := json.Marshal(e); err != nil {
				t.Errorf("event does not serialize: %v", err)
			}
		})
	}
}

// TestNormalizeProctitleFallback covers an exec whose EXECVE record never
// arrived: the command line has to come from PROCTITLE instead.
func TestNormalizeProctitleFallback(t *testing.T) {
	t.Run("NUL separated argv", func(t *testing.T) {
		e := Normalize(mustGroup(t, false, execSyscall, execCwd, execPath, execProctitle), NormalizeOptions{})
		if got, want := e.Command, "cat /etc/shadow"; got != want {
			t.Errorf("Command = %q, want %q", got, want)
		}
		if _, ok := e.Fields["argv"]; ok {
			t.Error("Fields[argv] set without an EXECVE record")
		}
		if got, ok := e.Fields["proctitle"]; ok {
			t.Errorf("Fields[proctitle] = %v, want it promoted to Command only", got)
		}
		if e.Fields["correlation_incomplete"] != true {
			t.Error("Fields[correlation_incomplete] must be set for a timed-out group")
		}
	})

	t.Run("single argument title", func(t *testing.T) {
		// sshd rewrites its own /proc title; there is no NUL to split on.
		e := Normalize(mustGroup(t, true,
			`type=SYSCALL msg=audit(1789753600.900:9700): arch=c000003e syscall=59 success=yes exit=0 items=1 ppid=1832 pid=1901 auid=1000 uid=0 gid=0 ses=5 comm="sshd" exe="/usr/sbin/sshd" key=(null)`,
			`type=PROCTITLE msg=audit(1789753600.900:9700): proctitle="sshd: user [priv]"`,
		), NormalizeOptions{})
		if got, want := e.Command, "sshd: user [priv]"; got != want {
			t.Errorf("Command = %q, want %q", got, want)
		}
		if got, want := e.Type, TypeProcessExec; got != want {
			t.Errorf("Type = %q, want %q", got, want)
		}
	})
}

// TestNormalizeExecveSplitArguments covers the kernel's chunked encoding of a
// long argument (a1_len plus a1[0], a1[1], ...).
func TestNormalizeExecveSplitArguments(t *testing.T) {
	long := strings.Repeat("A", 40)
	e := Normalize(mustGroup(t, true,
		`type=SYSCALL msg=audit(1789753700.000:9800): arch=c000003e syscall=59 success=yes exit=0 items=1 ppid=2100 pid=2900 auid=1000 uid=1000 gid=1000 ses=5 comm="bash" exe="/usr/bin/bash" key=(null)`,
		`type=EXECVE msg=audit(1789753700.000:9800): argc=3 a0="echo" a1_len=40 a1[0]="`+long[:20]+`" a1[1]="`+long[20:]+`" a2="tail"`,
	), NormalizeOptions{})

	if got, want := e.Command, "echo "+long+" tail"; got != want {
		t.Errorf("Command = %q, want %q", got, want)
	}
	argv := e.Fields["argv"].([]string)
	assertStrings(t, "Fields[argv]", argv, []string{"echo", long, "tail"})
	if _, ok := e.Fields["execve_argc_mismatch"]; ok {
		t.Error("Fields[execve_argc_mismatch] set although argc matched")
	}
}

// TestNormalizeExecveArgcMismatch proves a truncated or lying EXECVE record is
// reported rather than silently accepted.
func TestNormalizeExecveArgcMismatch(t *testing.T) {
	e := Normalize(mustGroup(t, true,
		`type=SYSCALL msg=audit(1789753710.000:9810): arch=c000003e syscall=59 success=yes exit=0 items=0 ppid=1 pid=2 auid=0 uid=0 gid=0 ses=1 comm="sh" exe="/usr/bin/sh" key=(null)`,
		`type=EXECVE msg=audit(1789753710.000:9810): argc=9 a0="sh" a1="-c"`,
	), NormalizeOptions{})
	if e.Fields["execve_argc_mismatch"] != true {
		t.Errorf("Fields[execve_argc_mismatch] = %v, want true", e.Fields["execve_argc_mismatch"])
	}
	if got, want := e.Command, "sh -c"; got != want {
		t.Errorf("Command = %q, want %q", got, want)
	}
}

// TestNormalizePathDeduplication keeps repeated names out of Paths without
// losing any of the per-item detail.
func TestNormalizePathDeduplication(t *testing.T) {
	e := Normalize(mustGroup(t, true,
		`type=SYSCALL msg=audit(1789753800.000:9900): arch=c000003e syscall=82 success=yes exit=0 items=4 ppid=2100 pid=3100 auid=1000 uid=0 gid=0 ses=5 comm="mv" exe="/usr/bin/mv" key="rename"`,
		`type=CWD msg=audit(1789753800.000:9900): cwd="/etc"`,
		`type=PATH msg=audit(1789753800.000:9900): item=0 name="/etc" inode=1 dev=fd:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT`,
		`type=PATH msg=audit(1789753800.000:9900): item=1 name="/etc" inode=1 dev=fd:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT`,
		`type=PATH msg=audit(1789753800.000:9900): item=2 name="passwd" inode=1400 dev=fd:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`,
		`type=PATH msg=audit(1789753800.000:9900): item=3 name="?" inode=1401 dev=fd:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=DELETE`,
	), NormalizeOptions{})

	assertStrings(t, "Paths", e.Paths, []string{"/etc", "passwd"})
	details, ok := e.Fields["path_details"].([]map[string]any)
	if !ok {
		t.Fatalf("Fields[path_details] = %#v, want []map[string]any", e.Fields["path_details"])
	}
	if len(details) != 4 {
		t.Fatalf("len(path_details) = %d, want 4: de-duplication must not drop detail", len(details))
	}
	if got, want := details[3]["name"], "?"; got != want {
		t.Errorf("path_details[3][name] = %v, want %q kept as evidence", got, want)
	}
	if _, ok := details[3]["resolved"]; ok {
		t.Error(`path_details[3][resolved] set for an unknown ("?") name`)
	}
	if got, want := e.Type, TypeFileModify; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
}

// TestNormalizePreserveRaw checks that the raw records are carried only when
// asked for, and verbatim when they are.
func TestNormalizePreserveRaw(t *testing.T) {
	g := execGroup(t)

	off := Normalize(g, NormalizeOptions{PreserveRaw: false})
	if off.Raw != nil {
		t.Errorf("Raw = %v, want nil when PreserveRaw is false", off.Raw)
	}

	on := Normalize(g, NormalizeOptions{PreserveRaw: true})
	if got, want := len(on.Raw), 5; got != want {
		t.Fatalf("len(Raw) = %d, want %d", got, want)
	}
	for i, line := range []string{execSyscall, execExecve, execCwd, execPath, execProctitle} {
		if on.Raw[i] != line {
			t.Errorf("Raw[%d] = %q, want the record verbatim %q", i, on.Raw[i], line)
		}
	}
	blob, err := json.Marshal(on)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(blob), `"raw"`) {
		t.Errorf("preserved raw records missing from JSON: %s", blob)
	}
}

// TestNormalizeRepeatedRecordTypes checks that a second record of one type is
// kept instead of overwriting the first.
func TestNormalizeRepeatedRecordTypes(t *testing.T) {
	e := Normalize(mustGroup(t, true,
		`type=AVC msg=audit(1789753900.000:9950): avc:  denied  { read } for  pid=2901 comm="httpd" name="shadow" dev="dm-0" ino=1442 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`,
		`type=AVC msg=audit(1789753900.000:9950): avc:  denied  { open } for  pid=2901 comm="httpd" name="shadow" dev="dm-0" ino=1442 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`,
	), NormalizeOptions{})

	list, ok := e.Fields["avc"].([]map[string]any)
	if !ok {
		t.Fatalf("Fields[avc] = %#v, want []map[string]any for a repeated record type", e.Fields["avc"])
	}
	if len(list) != 2 {
		t.Fatalf("len(Fields[avc]) = %d, want 2", len(list))
	}
	if got, want := e.Type, TypeSELinuxDenial; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
}

func TestNormalizeNilGroup(t *testing.T) {
	if e := Normalize(nil, NormalizeOptions{}); e != nil {
		t.Fatalf("Normalize(nil) = %+v, want nil", e)
	}
}

// TestNormalizeEmptyAndMalformedGroups makes sure normalization of unusable
// input still yields a reportable event rather than panicking or dropping it.
func TestNormalizeEmptyAndMalformedGroups(t *testing.T) {
	empty := Normalize(&audit.Group{AuditID: "1789754000.000:10000"}, NormalizeOptions{})
	if empty == nil {
		t.Fatal("Normalize of an empty group returned nil")
	}
	if got, want := empty.Type, TypeSystemSecurity; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
	if empty.Fields["correlation_incomplete"] != true {
		t.Error("an empty group is by definition incomplete")
	}

	// A SYSCALL record with nothing but noise must not produce a panic or an
	// invented identity.
	weird := Normalize(&audit.Group{
		AuditID:  "1789754001.000:10001",
		Complete: true,
		Records: []*audit.Record{{
			Type:     audit.TypeSyscall,
			TypeName: "SYSCALL",
			Fields: map[string]string{
				"syscall": "999999999999999999999999",
				"arch":    "c000003e",
				"uid":     "root",
				"pid":     "-3",
				"exit":    "not-a-number",
			},
		}},
	}, NormalizeOptions{})
	if weird.UID != nil || weird.PID != nil {
		t.Errorf("non-numeric ids were coerced: uid=%v pid=%v", weird.UID, weird.PID)
	}
	if got, want := weird.Fields["uid"], "root"; got != want {
		t.Errorf("Fields[uid] = %v, want the literal %q to remain", got, want)
	}
	if got, want := weird.Fields["exit"], "not-a-number"; got != want {
		t.Errorf("Fields[exit] = %v, want the literal %q to remain", got, want)
	}
}

// TestEmbeddedPairs covers the msg='...' payload scanner directly, including
// the bounds that keep a hostile record from turning into unbounded work.
func TestEmbeddedPairs(t *testing.T) {
	pairs := embeddedPairs(`op=PAM:authentication acct="root" exe="/usr/sbin/sshd" terminal=ssh res=failed'`)
	for k, want := range map[string]string{
		"op":       "PAM:authentication",
		"acct":     "root",
		"exe":      "/usr/sbin/sshd",
		"terminal": "ssh",
		"res":      "failed",
	} {
		if got := pairs[k]; got != want {
			t.Errorf("embeddedPairs[%q] = %q, want %q", k, got, want)
		}
	}

	if got := embeddedPairs("no pairs here"); got != nil {
		t.Errorf("embeddedPairs(no pairs) = %v, want nil", got)
	}

	flood := strings.Repeat("k=v ", 10000)
	if got := len(embeddedPairs(flood)); got > maxEmbeddedPairs {
		t.Errorf("embeddedPairs kept %d pairs, want at most %d", got, maxEmbeddedPairs)
	}
	// A value that is hex only by coincidence must not be decoded.
	if got, want := embeddedPairs("res=1234")["res"], "1234"; got != want {
		t.Errorf("embeddedPairs[res] = %q, want %q", got, want)
	}
}

func TestNamespaceKey(t *testing.T) {
	tests := map[string]string{
		"AVC":             "avc",
		"USER_CMD":        "user_cmd",
		"NETFILTER_CFG":   "netfilter_cfg",
		"UNKNOWN[1234]":   "unknown_1234",
		"ANOM_ADD_ACCT":   "anom_add_acct",
		"":                "record",
		"[[[///]]]":       "record",
		"MAC_POLICY_LOAD": "mac_policy_load",
	}
	for in, want := range tests {
		if got := namespaceKey(in); got != want {
			t.Errorf("namespaceKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzNormalize feeds arbitrary record bodies through normalization. Audit
// records come from a kernel that a compromised guest can influence, so the
// requirement is that no input produces a panic, an unbounded allocation or a
// non-serializable event.
func FuzzNormalize(f *testing.F) {
	f.Add(
		`arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 auid=1000 uid=0 gid=0 exe="/usr/bin/cat"`,
		`argc=2 a0="cat" a1="/etc/shadow"`,
		`item=0 name="/etc/shadow" nametype=NORMAL inode=1442`,
		`op=PAM:authentication acct="root" res=failed`,
	)
	f.Add(`syscall=4294967296 arch=`, `argc=99999999999999 a0=`, `item=-1 name= nametype=`, `res=`)
	f.Add(``, ``, ``, ``)
	f.Add(`syscall=59 arch=c000003e`, `a0_len=9999 a0[0]=x`, `name=../../etc/shadow nametype=CREATE`, `cmd=6161`)

	f.Fuzz(func(t *testing.T, syscallBody, execveBody, pathBody, msgBody string) {
		mk := func(typ audit.RecordType, name, body string) *audit.Record {
			return &audit.Record{
				Type:     typ,
				TypeName: name,
				Fields:   parseTestFields(name, body),
				Raw:      "type=" + name + " msg=audit(1.000:1): " + body,
			}
		}
		g := &audit.Group{
			AuditID:   "1.000:1",
			Serial:    1,
			Timestamp: time.Unix(1, 0),
			Records: []*audit.Record{
				mk(audit.TypeSyscall, "SYSCALL", syscallBody),
				mk(audit.TypeExecve, "EXECVE", execveBody),
				mk(audit.TypePath, "PATH", pathBody),
				mk(audit.TypeCwd, "CWD", pathBody),
				mk(audit.TypeProctitle, "PROCTITLE", execveBody),
				{Type: audit.TypeUserAuth, TypeName: "USER_AUTH", Fields: map[string]string{"msg": msgBody}},
			},
		}

		e := Normalize(g, NormalizeOptions{PreserveRaw: true, BootID: "boot"})
		if e == nil {
			t.Fatal("Normalize returned nil for a non-nil group")
		}
		if e.Type == "" {
			t.Fatal("event has no category")
		}
		if e.Severity == "" {
			t.Fatal("event has no severity")
		}
		for i, p := range e.Paths {
			if p == "" || p == "?" {
				t.Fatalf("Paths[%d] = %q, want unusable names skipped", i, p)
			}
		}
		if e.AUID != nil && *e.AUID == AUIDUnset {
			t.Fatal("the unset auid sentinel reached a typed field")
		}
		if _, err := json.Marshal(e); err != nil {
			t.Fatalf("event does not serialize: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// assertions
// ---------------------------------------------------------------------------

func assertInt(tb testing.TB, name string, got *int, want int) {
	tb.Helper()
	if got == nil {
		tb.Errorf("%s = nil, want %d", name, want)
		return
	}
	if *got != want {
		tb.Errorf("%s = %d, want %d", name, *got, want)
	}
}

func assertStrings(tb testing.TB, name string, got, want []string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Errorf("%s = %v, want %v", name, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			tb.Errorf("%s = %v, want %v", name, got, want)
			return
		}
	}
}

func namespaced(tb testing.TB, e *Event, key string) map[string]any {
	tb.Helper()
	m, ok := e.Fields[key].(map[string]any)
	if !ok {
		tb.Fatalf("Fields[%q] = %#v, want map[string]any", key, e.Fields[key])
	}
	return m
}
