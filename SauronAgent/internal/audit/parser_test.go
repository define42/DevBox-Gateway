package audit

import (
	"maps"
	"strings"
	"testing"
	"time"
)

// noHeader marks a case that carries no audit(...) event id, so no kernel
// timestamp is expected.
const noHeader = int64(-1)

type parseCase struct {
	name string
	line string

	wantErr bool

	wantType   RecordType
	wantName   string
	wantID     string
	wantSerial uint64
	// wantMillis is the expected timestamp in Unix milliseconds, or noHeader.
	wantMillis int64
	wantFields map[string]string
	// wantRaw is the expected Record.Raw; empty means "identical to line".
	wantRaw string
}

// parseCases are realistic records, one per record type DESIGN.md section 6
// calls out, plus the encodings the kernel mixes into them.
var parseCases = []parseCase{
	{
		name:       "syscall",
		line:       `type=SYSCALL msg=audit(1699887654.123:8421): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd a1=7ffd a2=7ffd a3=8 items=2 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" subj=unconfined key="watch-shadow"`,
		wantType:   TypeSyscall,
		wantName:   "SYSCALL",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{
			// a0..a3 are hex syscall register arguments here, not text, and
			// must survive undecoded even though "7ffd" is valid hex.
			"arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0",
			"a0": "7ffd", "a1": "7ffd", "a2": "7ffd", "a3": "8",
			"items": "2", "ppid": "4702", "pid": "4821", "auid": "1000",
			"uid": "0", "gid": "0", "euid": "0", "suid": "0", "fsuid": "0",
			"egid": "0", "sgid": "0", "fsgid": "0",
			"tty": "pts0", "ses": "3",
			"comm": "cat", "exe": "/usr/bin/cat",
			"subj": "unconfined", "key": "watch-shadow",
		},
	},
	{
		name:       "execve quoted args",
		line:       `type=EXECVE msg=audit(1699887654.123:8421): argc=2 a0="cat" a1="/etc/shadow"`,
		wantType:   TypeExecve,
		wantName:   "EXECVE",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"argc": "2", "a0": "cat", "a1": "/etc/shadow"},
	},
	{
		name:       "execve hex args",
		line:       `type=EXECVE msg=audit(1699887654.123:8421): argc=3 a0=2F62696E2F7368 a1=2D63 a2=6563686F2022686920746865726522`,
		wantType:   TypeExecve,
		wantName:   "EXECVE",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{
			"argc": "3",
			"a0":   "/bin/sh",
			"a1":   "-c",
			"a2":   `echo "hi there"`,
		},
	},
	{
		name:       "execve split quoted argument",
		line:       `type=EXECVE msg=audit(1699887654.123:8421): argc=1 a0_len=11 a0[0]="hello " a0[1]="world"`,
		wantType:   TypeExecve,
		wantName:   "EXECVE",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		// The a0[n] fragment keys are consumed into a0; the fragments stay
		// visible in Raw.
		wantFields: map[string]string{"argc": "1", "a0_len": "11", "a0": "hello world"},
	},
	{
		name:       "execve split hex argument out of order",
		line:       `type=EXECVE msg=audit(1699887654.123:8421): argc=1 a0_len=8 a0[1]=62696E a0[0]=2F7573722F`,
		wantType:   TypeExecve,
		wantName:   "EXECVE",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"argc": "1", "a0_len": "8", "a0": "/usr/bin"},
	},
	{
		name:       "cwd quoted",
		line:       `type=CWD msg=audit(1699887654.123:8421): cwd="/home/user"`,
		wantType:   TypeCwd,
		wantName:   "CWD",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"cwd": "/home/user"},
	},
	{
		name:       "cwd hex encoded because of a space",
		line:       `type=CWD msg=audit(1699887654.123:8421): cwd=2F686F6D652F7573657220646972`,
		wantType:   TypeCwd,
		wantName:   "CWD",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"cwd": "/home/user dir"},
	},
	{
		name:       "path",
		line:       `type=PATH msg=audit(1699887654.123:8421): item=0 name="/etc/shadow" inode=1234 dev=fd:00 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0`,
		wantType:   TypePath,
		wantName:   "PATH",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{
			"item": "0", "name": "/etc/shadow", "inode": "1234", "dev": "fd:00",
			"mode": "0100640", "ouid": "0", "ogid": "42", "rdev": "00:00",
			"nametype": "NORMAL", "cap_fp": "0", "cap_fi": "0", "cap_fe": "0", "cap_fver": "0",
		},
	},
	{
		name:       "proctitle hex with nul separators",
		line:       `type=PROCTITLE msg=audit(1699887654.123:8421): proctitle=636174002F6574632F736861646F77`,
		wantType:   TypeProctitle,
		wantName:   "PROCTITLE",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		// NUL separators are left in place: splitting argv is normalization's
		// job, and the raw decoded bytes are what the kernel actually had.
		wantFields: map[string]string{"proctitle": "cat\x00/etc/shadow"},
	},
	{
		name:       "proctitle quoted single argument",
		line:       `type=PROCTITLE msg=audit(1699887654.123:8422): proctitle="bash"`,
		wantType:   TypeProctitle,
		wantName:   "PROCTITLE",
		wantID:     "1699887654.123:8422",
		wantSerial: 8422,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"proctitle": "bash"},
	},
	{
		name:       "user_auth with nested msg",
		line:       `type=USER_AUTH msg=audit(1699887700.456:8500): pid=1234 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=failed'`,
		wantType:   TypeUserAuth,
		wantName:   "USER_AUTH",
		wantID:     "1699887700.456:8500",
		wantSerial: 8500,
		wantMillis: 1699887700456,
		wantFields: map[string]string{
			"pid": "1234", "uid": "0", "auid": "4294967295", "ses": "4294967295",
			"msg":      `op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=failed`,
			"op":       "PAM:authentication",
			"grantors": "?",
			"acct":     "root",
			"exe":      "/usr/sbin/sshd",
			"hostname": "10.0.0.5",
			"addr":     "10.0.0.5",
			"terminal": "ssh",
			"res":      "failed",
		},
	},
	{
		name:       "user_login",
		line:       `type=USER_LOGIN msg=audit(1699887710.789:8510): pid=1240 uid=0 auid=1000 ses=5 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/1 res=success'`,
		wantType:   TypeUserLogin,
		wantName:   "USER_LOGIN",
		wantID:     "1699887710.789:8510",
		wantSerial: 8510,
		wantMillis: 1699887710789,
		wantFields: map[string]string{
			"pid": "1240", "uid": "0", "auid": "1000", "ses": "5",
			"msg":      `op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/1 res=success`,
			"op":       "login",
			"id":       "1000",
			"exe":      "/usr/sbin/sshd",
			"hostname": "10.0.0.5",
			"addr":     "10.0.0.5",
			"terminal": "/dev/pts/1",
			"res":      "success",
		},
	},
	{
		name:       "user_logout",
		line:       `type=USER_LOGOUT msg=audit(1699887900.001:8600): pid=1240 uid=0 auid=1000 ses=5 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/1 res=success'`,
		wantType:   TypeUserLogout,
		wantName:   "USER_LOGOUT",
		wantID:     "1699887900.001:8600",
		wantSerial: 8600,
		wantMillis: 1699887900001,
		wantFields: map[string]string{
			"pid": "1240", "uid": "0", "auid": "1000", "ses": "5",
			"msg":      `op=login id=1000 exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=/dev/pts/1 res=success`,
			"op":       "login",
			"id":       "1000",
			"exe":      "/usr/sbin/sshd",
			"hostname": "10.0.0.5",
			"addr":     "10.0.0.5",
			"terminal": "/dev/pts/1",
			"res":      "success",
		},
	},
	{
		name:       "login with dashed keys",
		line:       `type=LOGIN msg=audit(1699887710.700:8509): pid=1240 uid=0 subj=unconfined old-auid=4294967295 auid=1000 tty=(none) old-ses=4294967295 ses=5 res=1`,
		wantType:   TypeLogin,
		wantName:   "LOGIN",
		wantID:     "1699887710.700:8509",
		wantSerial: 8509,
		wantMillis: 1699887710700,
		wantFields: map[string]string{
			"pid": "1240", "uid": "0", "subj": "unconfined",
			"old-auid": "4294967295", "auid": "1000", "tty": "(none)",
			"old-ses": "4294967295", "ses": "5", "res": "1",
		},
	},
	{
		name:       "user_cmd with hex cmd in nested msg",
		line:       `type=USER_CMD msg=audit(1699887720.111:8520): pid=5001 uid=1000 auid=1000 ses=3 msg='cwd="/home/user" cmd=636174202F6574632F736861646F77 terminal=pts/0 res=failed'`,
		wantType:   TypeUserCmd,
		wantName:   "USER_CMD",
		wantID:     "1699887720.111:8520",
		wantSerial: 8520,
		wantMillis: 1699887720111,
		wantFields: map[string]string{
			"pid": "5001", "uid": "1000", "auid": "1000", "ses": "3",
			"msg":      `cwd="/home/user" cmd=636174202F6574632F736861646F77 terminal=pts/0 res=failed`,
			"cwd":      "/home/user",
			"cmd":      "cat /etc/shadow",
			"terminal": "pts/0",
			"res":      "failed",
		},
	},
	{
		name:       "avc denial",
		line:       `type=AVC msg=audit(1699887730.222:8530): avc:  denied  { read open } for  pid=4821 comm="cat" name="shadow" dev="dm-0" ino=1234 scontext=unconfined_u:unconfined_r:unconfined_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`,
		wantType:   TypeAvc,
		wantName:   "AVC",
		wantID:     "1699887730.222:8530",
		wantSerial: 8530,
		wantMillis: 1699887730222,
		wantFields: map[string]string{
			// The prose prefix is not key=value, so it is lifted out under
			// auparse's names rather than being left only in Raw.
			"seresult": "denied", "seperms": "read open",
			"pid": "4821", "comm": "cat", "name": "shadow", "dev": "dm-0", "ino": "1234",
			"scontext": "unconfined_u:unconfined_r:unconfined_t:s0",
			"tcontext": "system_u:object_r:shadow_t:s0",
			"tclass":   "file", "permissive": "0",
		},
	},
	{
		name:       "netfilter_cfg",
		line:       `type=NETFILTER_CFG msg=audit(1699887740.333:8540): table=filter family=2 entries=190 op=nft_register_rule pid=6001 subj=unconfined comm="nft"`,
		wantType:   TypeNetfilterCfg,
		wantName:   "NETFILTER_CFG",
		wantID:     "1699887740.333:8540",
		wantSerial: 8540,
		wantMillis: 1699887740333,
		wantFields: map[string]string{
			"table": "filter", "family": "2", "entries": "190",
			"op": "nft_register_rule", "pid": "6001", "subj": "unconfined", "comm": "nft",
		},
	},
	{
		name:       "config_change rule added",
		line:       `type=CONFIG_CHANGE msg=audit(1699887750.444:8550): auid=1000 ses=3 subj=unconfined op=add_rule key="watch-shadow" list=4 res=1`,
		wantType:   TypeConfigChange,
		wantName:   "CONFIG_CHANGE",
		wantID:     "1699887750.444:8550",
		wantSerial: 8550,
		wantMillis: 1699887750444,
		wantFields: map[string]string{
			"auid": "1000", "ses": "3", "subj": "unconfined",
			"op": "add_rule", "key": "watch-shadow", "list": "4", "res": "1",
		},
	},
	{
		name:       "config_change audit disabled",
		line:       `type=CONFIG_CHANGE msg=audit(1699887751.000:8551): op=set audit_enabled=0 old=1 auid=1000 ses=3 res=1`,
		wantType:   TypeConfigChange,
		wantName:   "CONFIG_CHANGE",
		wantID:     "1699887751.000:8551",
		wantSerial: 8551,
		wantMillis: 1699887751000,
		wantFields: map[string]string{
			"op": "set", "audit_enabled": "0", "old": "1",
			"auid": "1000", "ses": "3", "res": "1",
		},
	},
	{
		name:       "eoe has no fields",
		line:       `type=EOE msg=audit(1699887654.123:8421):`,
		wantType:   TypeEoe,
		wantName:   "EOE",
		wantID:     "1699887654.123:8421",
		wantSerial: 8421,
		wantMillis: 1699887654123,
		wantFields: map[string]string{},
	},
	{
		name:       "key null placeholder and unknown exe",
		line:       `type=SYSCALL msg=audit(1699887654.999:8423): syscall=2 key=(null) exe=? comm=(none)`,
		wantType:   TypeSyscall,
		wantName:   "SYSCALL",
		wantID:     "1699887654.999:8423",
		wantSerial: 8423,
		wantMillis: 1699887654999,
		wantFields: map[string]string{"syscall": "2", "key": "(null)", "exe": "?", "comm": "(none)"},
	},
	{
		name:       "control record without an event id",
		line:       `type=GET msg=enabled=1 flag=1 pid=900 rate_limit=0 backlog_limit=8192 lost=0 backlog=0`,
		wantType:   TypeGet,
		wantName:   "GET",
		wantID:     "",
		wantSerial: 0,
		wantMillis: noHeader,
		wantFields: map[string]string{
			"enabled": "1", "flag": "1", "pid": "900", "rate_limit": "0",
			"backlog_limit": "8192", "lost": "0", "backlog": "0",
		},
	},
	{
		name:       "unknown record type round trips",
		line:       `type=UNKNOWN[9999] msg=audit(1699887654.123:8424): foo=bar`,
		wantType:   RecordType(9999),
		wantName:   "UNKNOWN[9999]",
		wantID:     "1699887654.123:8424",
		wantSerial: 8424,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"foo": "bar"},
	},
	{
		name:       "unterminated quote is best effort",
		line:       `type=CWD msg=audit(1699887654.123:8425): cwd="/home/user`,
		wantType:   TypeCwd,
		wantName:   "CWD",
		wantID:     "1699887654.123:8425",
		wantSerial: 8425,
		wantMillis: 1699887654123,
		wantFields: map[string]string{"cwd": "/home/user"},
	},
	{
		name:       "nested msg never overwrites a kernel field",
		line:       `type=USER_ACCT msg=audit(1699887760.555:8560): pid=7001 uid=1000 msg='uid=0 acct="root" res=success'`,
		wantType:   TypeUserAcct,
		wantName:   "USER_ACCT",
		wantID:     "1699887760.555:8560",
		wantSerial: 8560,
		wantMillis: 1699887760555,
		wantFields: map[string]string{
			// uid stays the kernel's 1000 even though the user-space message
			// claims 0: a process must not be able to rewrite its own uid.
			"pid": "7001", "uid": "1000",
			"msg":  `uid=0 acct="root" res=success`,
			"acct": "root", "res": "success",
		},
	},
	{
		name:    "truncated event id",
		line:    `type=SYSCALL msg=audit(1699887654.123:8421`,
		wantErr: true,
	},
	{
		name:    "non numeric event id",
		line:    `type=SYSCALL msg=audit(notatime:xyz): a=b`,
		wantErr: true,
	},
	{
		name:    "event id with no serial",
		line:    `type=SYSCALL msg=audit(1699887654.123): a=b`,
		wantErr: true,
	},
	{
		name:    "event id with an oversized fraction",
		line:    `type=SYSCALL msg=audit(1699887654.1234567:8421): a=b`,
		wantErr: true,
	},
	{
		name:    "empty line",
		line:    "",
		wantErr: true,
	},
	{
		name:    "not an audit record",
		line:    "hello world",
		wantErr: true,
	},
}

func TestParseLine(t *testing.T) {
	for _, tc := range parseCases {
		t.Run(tc.name, func(t *testing.T) {
			rec, err := ParseLine(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseLine(%q) = %+v, want an error", tc.line, rec)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseLine(%q): %v", tc.line, err)
			}

			if rec.Type != tc.wantType {
				t.Errorf("Type = %d, want %d", rec.Type, tc.wantType)
			}
			if rec.TypeName != tc.wantName {
				t.Errorf("TypeName = %q, want %q", rec.TypeName, tc.wantName)
			}
			if rec.AuditID != tc.wantID {
				t.Errorf("AuditID = %q, want %q", rec.AuditID, tc.wantID)
			}
			if rec.Serial != tc.wantSerial {
				t.Errorf("Serial = %d, want %d", rec.Serial, tc.wantSerial)
			}
			if tc.wantMillis == noHeader {
				if !rec.Timestamp.IsZero() {
					t.Errorf("Timestamp = %v, want the zero time for a record with no event id", rec.Timestamp)
				}
			} else if got := rec.Timestamp.UnixMilli(); got != tc.wantMillis {
				t.Errorf("Timestamp = %d ms (%v), want %d ms", got, rec.Timestamp, tc.wantMillis)
			}

			assertFields(t, rec.Fields, tc.wantFields)

			wantRaw := tc.wantRaw
			if wantRaw == "" {
				wantRaw = strings.TrimRight(tc.line, " ")
			}
			if rec.Raw != wantRaw {
				t.Errorf("Raw =\n  %q\nwant\n  %q", rec.Raw, wantRaw)
			}
		})
	}
}

// TestParseRecord drives the same records through the netlink entry point,
// where the type comes from the netlink header instead of the text.
func TestParseRecord(t *testing.T) {
	for _, tc := range parseCases {
		if tc.wantErr || tc.wantName != RecordTypeName(tc.wantType) {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			body, ok := strings.CutPrefix(tc.line, "type="+tc.wantName+" msg=")
			if !ok {
				t.Skipf("case is not in on-disk form")
			}
			received := time.Unix(1700000000, 0).UTC()
			rec, err := ParseRecord(RawMessage{Type: tc.wantType, Data: []byte(body), Received: received})
			if err != nil {
				t.Fatalf("ParseRecord: %v", err)
			}
			if rec.Type != tc.wantType {
				t.Errorf("Type = %d, want %d", rec.Type, tc.wantType)
			}
			if rec.AuditID != tc.wantID {
				t.Errorf("AuditID = %q, want %q", rec.AuditID, tc.wantID)
			}
			assertFields(t, rec.Fields, tc.wantFields)

			// Without an event id the arrival time is the only timestamp there
			// is, so it must be used rather than left zero.
			if tc.wantMillis == noHeader && !rec.Timestamp.Equal(received) {
				t.Errorf("Timestamp = %v, want the netlink arrival time %v", rec.Timestamp, received)
			}
		})
	}
}

func TestParseRecordTrimsKernelPadding(t *testing.T) {
	// Netlink pads a message body out to the alignment with NUL bytes, and
	// auditd appends a newline; neither is part of the record.
	data := []byte("audit(1699887654.123:8421): cwd=\"/home/user\"\n\x00\x00\x00")
	rec, err := ParseRecord(RawMessage{Type: TypeCwd, Data: data})
	if err != nil {
		t.Fatalf("ParseRecord: %v", err)
	}
	if got := rec.Fields["cwd"]; got != "/home/user" {
		t.Errorf("cwd = %q, want %q", got, "/home/user")
	}
	want := `type=CWD msg=audit(1699887654.123:8421): cwd="/home/user"`
	if rec.Raw != want {
		t.Errorf("Raw = %q, want %q", rec.Raw, want)
	}
}

func TestParseRecordEmptyBody(t *testing.T) {
	if rec, err := ParseRecord(RawMessage{Type: TypeSyscall, Data: nil}); err == nil {
		t.Fatalf("ParseRecord(empty) = %+v, want an error", rec)
	}
	if rec, err := ParseRecord(RawMessage{Type: TypeSyscall, Data: []byte("\x00\x00")}); err == nil {
		t.Fatalf("ParseRecord(padding only) = %+v, want an error", rec)
	}
}

func TestParseRejectsOversizedRecord(t *testing.T) {
	// An enormous field must be refused outright rather than parsed into a
	// map sized by the attacker.
	line := "type=CWD msg=audit(1699887654.123:8421): cwd=" + strings.Repeat("a", maxRecordLength+1)
	if rec, err := ParseLine(line); err == nil {
		t.Fatalf("ParseLine(oversized) = %+v, want an error", rec)
	}
}

func TestParseRejectsTooManyFields(t *testing.T) {
	var b strings.Builder
	b.WriteString("type=SYSCALL msg=audit(1699887654.123:8421):")
	for i := 0; i <= maxFields; i++ {
		b.WriteString(" k")
		b.WriteString(strings.Repeat("x", 1))
		b.WriteString(itoa(i))
		b.WriteString("=1")
	}
	if rec, err := ParseLine(b.String()); err == nil {
		t.Fatalf("ParseLine(too many fields) = %d fields, want an error", len(rec.Fields))
	}
}

func TestParseEmbeddedNULAndInvalidUTF8(t *testing.T) {
	// The kernel hex-encodes exactly so that bytes like these survive; the
	// parser must hand them back verbatim rather than sanitising them away.
	rec, err := ParseLine(`type=PATH msg=audit(1699887654.123:8421): item=0 name=612F00FF62`)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if got, want := rec.Fields["name"], "a/\x00\xffb"; got != want {
		t.Errorf("name = %q, want %q", got, want)
	}
}

func TestParseHexIsTypeAware(t *testing.T) {
	// The same key means different things on different records; getting this
	// wrong turns a syscall argument into garbage text or vice versa.
	syscall, err := ParseLine(`type=SYSCALL msg=audit(1699887654.123:8421): a0=63617400 a1=4141`)
	if err != nil {
		t.Fatalf("ParseLine(SYSCALL): %v", err)
	}
	if got := syscall.Fields["a0"]; got != "63617400" {
		t.Errorf("SYSCALL a0 = %q, want the raw hex number", got)
	}
	if got := syscall.Fields["a1"]; got != "4141" {
		t.Errorf("SYSCALL a1 = %q, want the raw hex number", got)
	}

	execve, err := ParseLine(`type=EXECVE msg=audit(1699887654.123:8421): argc=2 a0=63617400 a1=4141`)
	if err != nil {
		t.Fatalf("ParseLine(EXECVE): %v", err)
	}
	if got, want := execve.Fields["a0"], "cat\x00"; got != want {
		t.Errorf("EXECVE a0 = %q, want %q", got, want)
	}
	if got := execve.Fields["a1"]; got != "AA" {
		t.Errorf("EXECVE a1 = %q, want %q", got, "AA")
	}
}

func TestParseKeepsWholeArgumentOverFragments(t *testing.T) {
	rec, err := ParseLine(`type=EXECVE msg=audit(1699887654.123:8421): argc=1 a0="whole" a0[0]="frag"`)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if got := rec.Fields["a0"]; got != "whole" {
		t.Errorf("a0 = %q, want the kernel's whole argument %q", got, "whole")
	}
}

// assertFields compares a record's fields against the expected map exactly, so
// that a stray or missing key is a failure rather than a surprise later.
func assertFields(t *testing.T, got, want map[string]string) {
	t.Helper()
	if maps.Equal(got, want) {
		return
	}
	for k, wv := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("missing field %q (want %q)", k, wv)
			continue
		}
		if gv != wv {
			t.Errorf("field %q = %q, want %q", k, gv, wv)
		}
	}
	for k, gv := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected field %q = %q", k, gv)
		}
	}
}

// itoa avoids pulling strconv into the test table for one use.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

func TestParseRejectsTooManyExecveFragments(t *testing.T) {
	// Fragments are held outside Fields while being reassembled, so they need
	// a bound of their own.
	var b strings.Builder
	b.WriteString("type=EXECVE msg=audit(1699887654.123:8421): argc=1")
	for i := 0; i <= maxFields; i++ {
		b.WriteString(" a0[")
		b.WriteString(itoa(i % 100000))
		b.WriteString("]=41")
	}
	if rec, err := ParseLine(b.String()); err == nil {
		t.Fatalf("ParseLine(too many fragments) = %+v, want an error", rec)
	}
}
