package output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
)

const (
	testBootID    = "6f2b4a1c-9d3e-4c7a-8b15-2f0d9a7c4e11"
	testMachineID = "9c3a51f0b7e24d1b8a6f2c4d0e7b1a53"
)

// testReceivedAt is the host's clock, deliberately later than the guest's
// event timestamp so that a test confusing the two is visible.
var testReceivedAt = time.Date(2026, 5, 20, 9, 4, 5, 123000000, time.UTC)

// execEnvelope is one enriched process.exec event of the shape the collector
// emits: trusted hypervisor-side identity in Source, and the guest's own
// claims -- which disagree with it -- under Source.Reported.
func execEnvelope(seq uint64) *Envelope {
	return &Envelope{
		ReceivedAt: testReceivedAt,
		Source: Source{
			CID:            102,
			VM:             "transfer-vm-03",
			Host:           "hypervisor-01",
			UUID:           "0b9f1d84-3c27-4f56-9c1e-7a0d5b26e8f1",
			Environment:    "production",
			SecurityDomain: "restricted",
			VLAN:           "vlan-204",
			Labels:         map[string]string{"owner": "platform", "tier": "gold"},
			Known:          true,
			Reported: &Reported{
				// The guest calls itself something else entirely. Keeping both
				// is the point of the envelope: the disagreement is evidence.
				Hostname:     "build-runner-11",
				MachineID:    testMachineID,
				BootID:       testBootID,
				Kernel:       "6.8.0-45-generic",
				AgentVersion: "sauronagent/1.0.0",
			},
		},
		Event: &event.Event{
			Version:     event.SchemaVersion,
			Sequence:    seq,
			Timestamp:   time.Date(2026, 5, 20, 9, 4, 5, 112000000, time.UTC),
			Type:        event.TypeProcessExec,
			Severity:    event.SeverityNotice,
			AuditID:     fmt.Sprintf("1779008645.112:%d", 8400+seq),
			BootID:      testBootID,
			PID:         event.Int(2941),
			PPID:        event.Int(2870),
			UID:         event.Int(0),
			GID:         event.Int(0),
			AUID:        event.Int(1000),
			Executable:  "/usr/bin/cat",
			Command:     "cat /etc/shadow",
			CWD:         "/home/alice",
			Paths:       []string{"/usr/bin/cat", "/etc/shadow"},
			Result:      event.ResultSuccess,
			RecordTypes: []string{"SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"},
			Fields: map[string]any{
				"arch":    "x86_64",
				"ses":     "12",
				"syscall": "execve",
				"tty":     "pts0",
			},
			Raw: []string{
				"type=SYSCALL msg=audit(1779008645.112:8421): arch=c000003e syscall=59 success=yes exit=0 ppid=2870 pid=2941 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 tty=pts0 ses=12 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"exec\"",
				"type=PATH msg=audit(1779008645.112:8421): item=0 name=\"/etc/shadow\" inode=262151 dev=fd:01 mode=0100640 ouid=0 ogid=42 nametype=NORMAL",
			},
		},
	}
}

// denialEnvelope is a critical SELinux denial from a guest with no
// configuration entry, i.e. Known=false and nothing the host can trust.
func denialEnvelope(seq uint64) *Envelope {
	return &Envelope{
		ReceivedAt: testReceivedAt.Add(2 * time.Second),
		Source: Source{
			CID:   9911,
			VM:    "unknown-cid-9911",
			Host:  "hypervisor-01",
			Known: false,
			Reported: &Reported{
				Hostname:     "db-primary",
				BootID:       testBootID,
				AgentVersion: "sauronagent/1.0.0",
			},
		},
		Event: &event.Event{
			Version:     event.SchemaVersion,
			Sequence:    seq,
			Timestamp:   time.Date(2026, 5, 20, 9, 4, 7, 5000000, time.UTC),
			Type:        event.TypeSELinuxDenial,
			Severity:    event.SeverityCritical,
			AuditID:     fmt.Sprintf("1779008647.005:%d", 8400+seq),
			BootID:      testBootID,
			PID:         event.Int(1188),
			UID:         event.Int(27),
			Executable:  "/usr/libexec/mysqld",
			Result:      event.ResultFailure,
			RecordTypes: []string{"AVC"},
			Fields: map[string]any{
				"scontext": "system_u:system_r:mysqld_t:s0",
				"tcontext": "system_u:object_r:shadow_t:s0",
				"tclass":   "file",
				"denied":   "read",
			},
		},
	}
}

func TestStdoutWriteLine(t *testing.T) {
	const want = `{"received_at":"2026-05-20T09:04:05.123Z","source":{"cid":102,"vm":"transfer-vm-03","host":"hypervisor-01","uuid":"0b9f1d84-3c27-4f56-9c1e-7a0d5b26e8f1","environment":"production","security_domain":"restricted","vlan":"vlan-204","labels":{"owner":"platform","tier":"gold"},"known":true,"reported":{"hostname":"build-runner-11","machine_id":"9c3a51f0b7e24d1b8a6f2c4d0e7b1a53","boot_id":"6f2b4a1c-9d3e-4c7a-8b15-2f0d9a7c4e11","kernel":"6.8.0-45-generic","agent_version":"sauronagent/1.0.0"}},"event":{"version":1,"sequence":41,"timestamp":"2026-05-20T09:04:05.112Z","type":"process.exec","severity":"notice","audit_id":"1779008645.112:8441","boot_id":"6f2b4a1c-9d3e-4c7a-8b15-2f0d9a7c4e11","pid":2941,"ppid":2870,"uid":0,"gid":0,"auid":1000,"exe":"/usr/bin/cat","command":"cat /etc/shadow","cwd":"/home/alice","paths":["/usr/bin/cat","/etc/shadow"],"result":"success","record_types":["SYSCALL","EXECVE","CWD","PATH","PROCTITLE"],"fields":{"arch":"x86_64","ses":"12","syscall":"execve","tty":"pts0"},"raw":["type=SYSCALL msg=audit(1779008645.112:8421): arch=c000003e syscall=59 success=yes exit=0 ppid=2870 pid=2941 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 tty=pts0 ses=12 comm=\"cat\" exe=\"/usr/bin/cat\" key=\"exec\"","type=PATH msg=audit(1779008645.112:8421): item=0 name=\"/etc/shadow\" inode=262151 dev=fd:01 mode=0100640 ouid=0 ogid=42 nametype=NORMAL"]}}` + "\n"

	var buf bytes.Buffer
	s := newStdout(&buf, false)
	if err := s.Write(context.Background(), execEnvelope(41)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := buf.String(); got != want {
		t.Errorf("line mismatch\n got: %s\nwant: %s", got, want)
	}
}

// The whole point of the envelope is that the hypervisor's view of a guest and
// the guest's claims about itself are kept apart. A sink that flattened them
// would let a compromised VM rename itself in the evidence.
func TestStdoutKeepsTrustedAndReportedDistinct(t *testing.T) {
	var buf bytes.Buffer
	s := newStdout(&buf, false)
	if err := s.Write(context.Background(), execEnvelope(7)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var doc struct {
		Source struct {
			CID      uint32 `json:"cid"`
			VM       string `json:"vm"`
			Known    bool   `json:"known"`
			Reported *struct {
				Hostname     string `json:"hostname"`
				MachineID    string `json:"machine_id"`
				AgentVersion string `json:"agent_version"`
			} `json:"reported"`
		} `json:"source"`
		Event *event.Event `json:"event"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("emitted line is not valid JSON: %v", err)
	}
	if doc.Source.CID != 102 || doc.Source.VM != "transfer-vm-03" || !doc.Source.Known {
		t.Errorf("trusted source block wrong: %+v", doc.Source)
	}
	if doc.Source.Reported == nil {
		t.Fatal("reported block missing: the guest's claims must be preserved, not dropped")
	}
	if doc.Source.Reported.Hostname != "build-runner-11" {
		t.Errorf("reported hostname = %q, want the guest's own claim", doc.Source.Reported.Hostname)
	}
	if doc.Source.Reported.Hostname == doc.Source.VM {
		t.Error("trusted vm name and reported hostname collapsed into one value")
	}
	if doc.Event == nil || doc.Event.Type != event.TypeProcessExec || doc.Event.UID == nil || *doc.Event.UID != 0 {
		t.Errorf("event block wrong: %+v", doc.Event)
	}
	if doc.Event.Sequence != 7 {
		t.Errorf("sequence = %d, want 7", doc.Event.Sequence)
	}
	if len(doc.Event.Raw) != 2 {
		t.Errorf("raw records = %d, want the originals preserved", len(doc.Event.Raw))
	}
}

func TestStdoutPretty(t *testing.T) {
	var buf bytes.Buffer
	s := newStdout(&buf, true)
	if err := s.Write(context.Background(), denialEnvelope(3)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "\n  \"source\": {") {
		t.Errorf("pretty output is not indented:\n%s", out)
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Errorf("pretty output must still be newline terminated:\n%s", out)
	}
	var env Envelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("pretty output is not valid JSON: %v", err)
	}
	if env.Event.Severity != event.SeverityCritical {
		t.Errorf("severity = %q, want %q", env.Event.Severity, event.SeverityCritical)
	}
}

// Audit data is full of characters encoding/json escapes for HTML by default.
// Escaping them would make the evidence differ from the raw records it is
// supposed to be checkable against.
func TestStdoutDoesNotHTMLEscape(t *testing.T) {
	env := execEnvelope(1)
	env.Event.Command = "sh -c 'cat /etc/shadow > /tmp/x && echo done'"

	var buf bytes.Buffer
	s := newStdout(&buf, false)
	if err := s.Write(context.Background(), env); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), "/etc/shadow > /tmp/x && echo done") {
		t.Errorf("command was escaped:\n%s", buf.String())
	}
}

// The collector serves many guests at once. Two envelopes must never end up
// spliced into one line; run under -race this also proves the lock exists.
func TestStdoutConcurrentWrites(t *testing.T) {
	const (
		writers   = 32
		perWriter = 25
		total     = writers * perWriter
	)
	var buf bytes.Buffer
	s := newStdout(&buf, false)

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				seq := uint64(w*perWriter + i + 1)
				var env *Envelope
				if seq%2 == 0 {
					env = denialEnvelope(seq)
				} else {
					env = execEnvelope(seq)
				}
				if err := s.Write(context.Background(), env); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != total {
		t.Fatalf("got %d lines, want %d", len(lines), total)
	}
	seen := make(map[uint64]bool, total)
	for i, line := range lines {
		var env Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("line %d is not a complete JSON object (%v): %s", i, err, line)
		}
		if env.Event == nil {
			t.Fatalf("line %d has no event: %s", i, line)
		}
		if seen[env.Event.Sequence] {
			t.Errorf("sequence %d written twice", env.Event.Sequence)
		}
		seen[env.Event.Sequence] = true
	}
	for seq := uint64(1); seq <= total; seq++ {
		if !seen[seq] {
			t.Errorf("sequence %d never reached the sink", seq)
		}
	}
}

// failingWriter reports the kind of failure a full disk or a closed pipe
// produces.
type failingWriter struct {
	err error
	n   int
}

func (f *failingWriter) Write(p []byte) (int, error) { return f.n, f.err }

func TestStdoutWriteErrorsAreReported(t *testing.T) {
	sentinel := errors.New("broken pipe")
	s := newStdout(&failingWriter{err: sentinel}, false)
	err := s.Write(context.Background(), execEnvelope(1))
	if err == nil {
		t.Fatal("Write returned nil after the writer failed; the event would be acknowledged and lost")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error %v does not wrap the underlying failure", err)
	}
}

func TestStdoutRejectsNilEnvelope(t *testing.T) {
	var buf bytes.Buffer
	s := newStdout(&buf, false)
	err := s.Write(context.Background(), nil)
	if !errors.Is(err, errNilEnvelope) {
		t.Fatalf("err = %v, want errNilEnvelope", err)
	}
	if buf.Len() != 0 {
		t.Errorf("nothing should have been written, got %q", buf.String())
	}
}

func TestStdoutHonoursContext(t *testing.T) {
	var buf bytes.Buffer
	s := newStdout(&buf, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Write(ctx, execEnvelope(1)); !errors.Is(err, context.Canceled) {
		t.Errorf("Write err = %v, want context.Canceled", err)
	}
	if err := s.Flush(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Flush err = %v, want context.Canceled", err)
	}
}

func TestNewStdout(t *testing.T) {
	s, err := NewStdout(config.StdoutOutput{Enabled: true, Pretty: true})
	if err != nil {
		t.Fatalf("NewStdout: %v", err)
	}
	if s.Name() != "stdout" {
		t.Errorf("Name = %q, want %q", s.Name(), "stdout")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
	// Close must not close the process's standard output.
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if _, err := fmt.Fprint(os.Stdout, ""); err != nil {
		t.Errorf("standard output was closed by the sink: %v", err)
	}
}
