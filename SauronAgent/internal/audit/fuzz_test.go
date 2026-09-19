package audit

import (
	"maps"
	"strings"
	"testing"
)

// fuzzBodies are record bodies -- everything the kernel puts after
// "type=NAME msg=" -- covering each encoding the parser has to survive.
var fuzzBodies = []struct {
	typ  RecordType
	body string
}{
	{TypeSyscall, `audit(1699887654.123:8421): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd a1=7ffd a2=7ffd a3=8 items=2 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="cat" exe="/usr/bin/cat" subj=unconfined key="watch-shadow"`},
	{TypeExecve, `audit(1699887654.123:8421): argc=2 a0="cat" a1="/etc/shadow"`},
	{TypeExecve, `audit(1699887654.123:8421): argc=3 a0=2F62696E2F7368 a1=2D63 a2=6563686F2022686920746865726522`},
	{TypeExecve, `audit(1699887654.123:8421): argc=1 a0_len=100 a0[0]="first" a0[1]="second"`},
	{TypeCwd, `audit(1699887654.123:8421): cwd="/home/user"`},
	{TypePath, `audit(1699887654.123:8421): item=0 name="/etc/shadow" inode=1234 dev=fd:00 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0`},
	{TypeProctitle, `audit(1699887654.123:8421): proctitle=636174002F6574632F736861646F77`},
	{TypeEoe, `audit(1699887654.123:8421):`},
	{TypeUserAuth, `audit(1699887700.456:8500): pid=1234 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="root" exe="/usr/sbin/sshd" hostname=10.0.0.5 addr=10.0.0.5 terminal=ssh res=failed'`},
	{TypeUserCmd, `audit(1699887720.111:8520): pid=5001 uid=1000 auid=1000 ses=3 msg='cwd="/home/user" cmd=636174202F6574632F736861646F77 terminal=pts/0 res=failed'`},
	{TypeAvc, `audit(1699887730.222:8530): avc:  denied  { read } for  pid=4821 comm="cat" name="shadow" dev="dm-0" ino=1234 scontext=unconfined_u:unconfined_r:unconfined_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0`},
	{TypeNetfilterCfg, `audit(1699887740.333:8540): table=filter family=2 entries=190 op=nft_register_rule pid=6001 subj=unconfined comm="nft"`},
	{TypeConfigChange, `audit(1699887750.444:8550): auid=1000 ses=3 op=set audit_enabled=0 old=1 res=1`},
	{TypeGet, `enabled=1 flag=1 pid=900 rate_limit=0 backlog_limit=8192 lost=0 backlog=0`},

	// Shapes that have to fail or degrade gracefully rather than crash.
	{TypeSyscall, `audit(1699887654.123:8421`},
	{TypeSyscall, `audit(notatime:xyz): a=b`},
	{TypeCwd, `audit(1699887654.123:8421): cwd="/home/user`},
	{TypePath, `audit(1699887654.123:8421): name=612F00FF62`},
	{TypeSyscall, `audit(0.000:0):`},
	{TypeSyscall, ``},
	{TypeSyscall, "audit(1699887654.123:8421): comm=\x00\xff a=\"\x00\""},
	{RecordType(9999), `audit(1699887654.123:8424): foo=bar`},
}

func FuzzParseRecord(f *testing.F) {
	for _, s := range fuzzBodies {
		f.Add(uint16(s.typ), []byte(s.body))
	}
	f.Add(uint16(0), []byte(nil))
	f.Add(uint16(1300), []byte("audit("))
	f.Add(uint16(1300), []byte("audit()"))
	f.Add(uint16(1309), []byte("audit(1.1:1): a0[0]=41 a0[99999999999]=42"))

	f.Fuzz(func(t *testing.T, typ uint16, data []byte) {
		msg := RawMessage{Type: RecordType(typ), Data: data}
		rec, err := ParseRecord(msg)
		if err != nil {
			if rec != nil {
				t.Fatalf("ParseRecord returned both a record and an error %v", err)
			}
			return
		}
		if rec.Type != RecordType(typ) {
			t.Fatalf("Type = %d, want the netlink header's %d", rec.Type, typ)
		}
		if rec.TypeName != RecordTypeName(RecordType(typ)) {
			t.Fatalf("TypeName = %q, want %q", rec.TypeName, RecordTypeName(RecordType(typ)))
		}
		if rec.AuditID == "" && !rec.Timestamp.Equal(msg.Received) {
			t.Fatalf("Timestamp = %v with no event id, want the arrival time %v", rec.Timestamp, msg.Received)
		}
		checkRecord(t, rec)
	})
}

func FuzzParseLine(f *testing.F) {
	for _, s := range fuzzBodies {
		f.Add("type=" + RecordTypeName(s.typ) + " msg=" + s.body)
	}
	f.Add("")
	f.Add("hello world")
	f.Add("type=")
	f.Add("type=SYSCALL")
	f.Add("type=SYSCALL msg=")
	f.Add("audit(1699887654.123:8421): a=b")
	f.Add("type=UNKNOWN[9999] msg=audit(1699887654.123:8424): foo=bar")
	f.Add("type=EXECVE msg=audit(1.1:1): argc=1 a0_len=4 a0[1]=6262 a0[0]=6161")
	f.Add("type=SYSCALL msg=audit(99999999999999999999.123:8421): a=b")
	f.Add("type=USER_AUTH msg=audit(1.1:1): msg='msg='nested''")

	f.Fuzz(func(t *testing.T, line string) {
		rec, err := ParseLine(line)
		if err != nil {
			if rec != nil {
				t.Fatalf("ParseLine returned both a record and an error %v", err)
			}
			return
		}
		if rec.AuditID == "" && !rec.Timestamp.IsZero() {
			t.Fatalf("Timestamp = %v with no event id, want the zero time", rec.Timestamp)
		}
		checkRecord(t, rec)
	})
}

// checkRecord asserts the invariants every successfully parsed record must
// hold, whichever entry point produced it.
func checkRecord(t *testing.T, rec *Record) {
	t.Helper()

	if rec.Fields == nil {
		t.Fatal("Fields is nil")
	}
	if rec.TypeName == "" {
		t.Fatal("TypeName is empty")
	}
	if len(rec.Fields) > maxFields {
		t.Fatalf("Fields has %d entries, over the %d limit", len(rec.Fields), maxFields)
	}
	for k := range rec.Fields {
		if k == "" {
			t.Fatal("Fields has an empty key")
		}
		for i := 0; i < len(k); i++ {
			if !isKeyByte(k[i]) {
				t.Fatalf("field key %q contains byte %q, which the scanner cannot produce", k, k[i])
			}
		}
	}

	// The event id is the correlation key, so the string, the serial and the
	// timestamp must agree: a record whose AuditID says one thing and whose
	// Serial says another would split or merge events wrongly.
	if rec.AuditID != "" {
		ts, serial, err := parseEventID(rec.AuditID)
		if err != nil {
			t.Fatalf("AuditID %q does not re-parse: %v", rec.AuditID, err)
		}
		if serial != rec.Serial {
			t.Fatalf("AuditID %q carries serial %d, but Serial is %d", rec.AuditID, serial, rec.Serial)
		}
		if !ts.Equal(rec.Timestamp) {
			t.Fatalf("AuditID %q carries time %v, but Timestamp is %v", rec.AuditID, ts, rec.Timestamp)
		}
		if !strings.Contains(rec.Raw, rec.AuditID) {
			t.Fatalf("Raw %q does not contain the event id %q", rec.Raw, rec.AuditID)
		}
	}

	// Raw is the preserved evidence, so it has to be in auditd's shape and it
	// has to parse back to the same record.
	prefix := "type=" + rec.TypeName + " msg="
	if !strings.HasPrefix(rec.Raw, prefix) {
		t.Fatalf("Raw %q does not start with %q", rec.Raw, prefix)
	}

	again, err := ParseLine(rec.Raw)
	if err != nil {
		t.Fatalf("Raw %q does not re-parse: %v", rec.Raw, err)
	}
	if again.Type != rec.Type || again.TypeName != rec.TypeName {
		t.Fatalf("Raw re-parsed as type %d/%q, want %d/%q", again.Type, again.TypeName, rec.Type, rec.TypeName)
	}
	if again.AuditID != rec.AuditID || again.Serial != rec.Serial {
		t.Fatalf("Raw re-parsed as %q/%d, want %q/%d", again.AuditID, again.Serial, rec.AuditID, rec.Serial)
	}
	if !maps.Equal(again.Fields, rec.Fields) {
		t.Fatalf("Raw re-parsed to different fields:\n got %v\nwant %v", again.Fields, rec.Fields)
	}
}
