package output

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
)

func TestParseFacility(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    syslog.Priority
		wantErr bool
	}{
		{name: "empty defaults to authpriv", in: "", want: syslog.LOG_AUTHPRIV},
		{name: "whitespace defaults to authpriv", in: "  ", want: syslog.LOG_AUTHPRIV},
		{name: "authpriv", in: "authpriv", want: syslog.LOG_AUTHPRIV},
		{name: "auth", in: "auth", want: syslog.LOG_AUTH},
		{name: "daemon", in: "daemon", want: syslog.LOG_DAEMON},
		{name: "kern", in: "kern", want: syslog.LOG_KERN},
		{name: "user", in: "user", want: syslog.LOG_USER},
		{name: "cron", in: "cron", want: syslog.LOG_CRON},
		{name: "local0", in: "local0", want: syslog.LOG_LOCAL0},
		{name: "local7", in: "local7", want: syslog.LOG_LOCAL7},
		{name: "mixed case", in: "LOCAL3", want: syslog.LOG_LOCAL3},
		{name: "padded", in: " authpriv\t", want: syslog.LOG_AUTHPRIV},
		{name: "unknown", in: "securiy", wantErr: true},
		{name: "local8 does not exist", in: "local8", wantErr: true},
		{name: "numeric is not accepted", in: "10", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFacility(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFacility(%q) = %d, want an error: a mistyped facility must not silently reroute evidence", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFacility(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseFacility(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestSyslogSeverity(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want syslog.Priority
	}{
		{name: "critical", in: event.SeverityCritical, want: syslog.LOG_CRIT},
		{name: "warning", in: event.SeverityWarning, want: syslog.LOG_WARNING},
		{name: "notice", in: event.SeverityNotice, want: syslog.LOG_NOTICE},
		{name: "info", in: event.SeverityInfo, want: syslog.LOG_INFO},
		{name: "unset", in: "", want: syslog.LOG_INFO},
		{name: "unknown is raised, not buried", in: "emergency", want: syslog.LOG_NOTICE},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := syslogSeverity(tt.in); got != tt.want {
				t.Errorf("syslogSeverity(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// syslogListener is a stand-in for rsyslog: a unix datagram socket that
// records the framed messages it receives.
type syslogListener struct {
	path string
	conn net.PacketConn
	msgs chan string
	once sync.Once
}

// socketPath returns a socket path inside the test's temporary directory,
// skipping if it would exceed the sockaddr_un limit.
func socketPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log")
	if len(path) > 100 {
		t.Skipf("temporary directory path %q is too long for a unix socket", path)
	}
	return path
}

func listenSyslog(t *testing.T, path string) *syslogListener {
	t.Helper()
	conn, err := net.ListenPacket("unixgram", path)
	if err != nil {
		t.Skipf("unix datagram sockets are unavailable here: %v", err)
	}
	l := &syslogListener{path: path, conn: conn, msgs: make(chan string, 64)}
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, err := l.conn.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case l.msgs <- string(buf[:n]):
			default:
			}
		}
	}()
	t.Cleanup(l.close)
	return l
}

func (l *syslogListener) close() {
	l.once.Do(func() { _ = l.conn.Close() })
}

// receive waits for one message. A timeout is a failure rather than a skip:
// an event that never reaches the daemon is the bug this sink must not have.
func (l *syslogListener) receive(t *testing.T) string {
	t.Helper()
	select {
	case msg := <-l.msgs:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog message arrived")
		return ""
	}
}

// splitPriority splits "<PRI>rest" as RFC 3164 frames it.
func splitPriority(t *testing.T, msg string) (syslog.Priority, string) {
	t.Helper()
	if !strings.HasPrefix(msg, "<") {
		t.Fatalf("message has no priority prefix: %q", msg)
	}
	end := strings.Index(msg, ">")
	if end < 0 {
		t.Fatalf("message has no priority terminator: %q", msg)
	}
	p, err := strconv.Atoi(msg[1:end])
	if err != nil {
		t.Fatalf("unparsable priority in %q: %v", msg, err)
	}
	return syslog.Priority(p), msg[end+1:]
}

func TestSyslogWritePriority(t *testing.T) {
	tests := []struct {
		name     string
		facility string
		severity string
		want     syslog.Priority
	}{
		{
			name: "critical on authpriv", facility: "authpriv", severity: event.SeverityCritical,
			want: syslog.LOG_AUTHPRIV | syslog.LOG_CRIT,
		},
		{
			name: "warning on authpriv", facility: "authpriv", severity: event.SeverityWarning,
			want: syslog.LOG_AUTHPRIV | syslog.LOG_WARNING,
		},
		{
			name: "notice on default facility", facility: "", severity: event.SeverityNotice,
			want: syslog.LOG_AUTHPRIV | syslog.LOG_NOTICE,
		},
		{
			name: "info on local3", facility: "local3", severity: event.SeverityInfo,
			want: syslog.LOG_LOCAL3 | syslog.LOG_INFO,
		},
		{
			name: "unset severity on daemon", facility: "daemon", severity: "",
			want: syslog.LOG_DAEMON | syslog.LOG_INFO,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := socketPath(t)
			l := listenSyslog(t, path)

			s, err := NewSyslog(config.SyslogOutput{
				Enabled:  true,
				Network:  "unixgram",
				Address:  path,
				Tag:      "sauronhost-test",
				Facility: tt.facility,
			})
			if err != nil {
				t.Fatalf("NewSyslog: %v", err)
			}
			defer func() { _ = s.Close() }()

			env := execEnvelope(17)
			env.Event.Severity = tt.severity
			if err := s.Write(context.Background(), env); err != nil {
				t.Fatalf("Write: %v", err)
			}

			got, rest := splitPriority(t, l.receive(t))
			if got != tt.want {
				t.Errorf("priority = %d, want %d (facility %d, severity %d)",
					got, tt.want, tt.want/8, tt.want%8)
			}
			if !strings.Contains(rest, "sauronhost-test[") {
				t.Errorf("message is not tagged with the collector: %q", rest)
			}

			body := rest[strings.Index(rest, ": ")+2:]
			var decoded Envelope
			if err := json.Unmarshal([]byte(strings.TrimSuffix(body, "\n")), &decoded); err != nil {
				t.Fatalf("message body is not a complete envelope (%v): %q", err, body)
			}
			if decoded.Source.VM != "transfer-vm-03" || decoded.Source.Reported == nil ||
				decoded.Source.Reported.Hostname != "build-runner-11" {
				t.Errorf("trusted and reported identity did not survive the syslog hop: %+v", decoded.Source)
			}
			if decoded.Event == nil || decoded.Event.Sequence != 17 {
				t.Errorf("event did not survive the syslog hop: %+v", decoded.Event)
			}
		})
	}
}

// A message must be one line, or a daemon splitting on newlines turns one
// event into several partial ones.
func TestSyslogMessageIsASingleLine(t *testing.T) {
	path := socketPath(t)
	l := listenSyslog(t, path)
	s, err := NewSyslog(config.SyslogOutput{Enabled: true, Network: "unixgram", Address: path, Tag: "sauronhost-test"})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	defer func() { _ = s.Close() }()

	env := execEnvelope(5)
	// A guest is free to put newlines in a command line; the encoding must
	// escape them rather than pass them through to the daemon.
	env.Event.Command = "sh -c 'echo one\necho two'"
	if err := s.Write(context.Background(), env); err != nil {
		t.Fatalf("Write: %v", err)
	}
	msg := l.receive(t)
	if strings.Count(strings.TrimSuffix(msg, "\n"), "\n") != 0 {
		t.Errorf("message spans several lines: %q", msg)
	}
}

// The collector acknowledges to the guest only on the strength of a sink
// accepting an event, so a daemon that is down has to produce an error. Once
// it comes back the sink must recover by itself.
func TestSyslogReportsOutageAndReconnects(t *testing.T) {
	path := socketPath(t)
	l := listenSyslog(t, path)

	s, err := NewSyslog(config.SyslogOutput{Enabled: true, Network: "unixgram", Address: path, Tag: "sauronhost-test"})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	if err := s.Write(ctx, execEnvelope(1)); err != nil {
		t.Fatalf("Write while the daemon is up: %v", err)
	}
	l.receive(t)

	l.close()
	_ = os.Remove(path)

	// A datagram socket may accept the first send before the kernel reports
	// the peer as gone, so allow a couple of attempts -- but not silence.
	var outage error
	for i := 0; i < 5 && outage == nil; i++ {
		outage = s.Write(ctx, execEnvelope(uint64(100+i)))
	}
	if outage == nil {
		t.Fatal("Write kept returning nil with no daemon listening: events would be acknowledged and lost")
	}

	restarted := listenSyslog(t, path)
	if err := s.Write(ctx, execEnvelope(2)); err != nil {
		t.Fatalf("Write after the daemon came back: %v", err)
	}
	got, _ := splitPriority(t, restarted.receive(t))
	if got != syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE {
		t.Errorf("priority after reconnect = %d, want %d", got, syslog.LOG_AUTHPRIV|syslog.LOG_NOTICE)
	}
}

func TestNewSyslogRejectsBadConfiguration(t *testing.T) {
	t.Run("unknown facility", func(t *testing.T) {
		if s, err := NewSyslog(config.SyslogOutput{Enabled: true, Facility: "audit"}); err == nil {
			_ = s.Close()
			t.Fatal("NewSyslog accepted an unknown facility")
		}
	})
	t.Run("unreachable daemon", func(t *testing.T) {
		// Failing here rather than at the first event means a collector whose
		// syslog destination is wrong says so at startup.
		missing := filepath.Join(t.TempDir(), "absent.sock")
		s, err := NewSyslog(config.SyslogOutput{Enabled: true, Network: "unixgram", Address: missing})
		if err == nil {
			_ = s.Close()
			t.Fatal("NewSyslog succeeded with no daemon at the configured address")
		}
		if !strings.Contains(err.Error(), missing) {
			t.Errorf("error %q does not name the destination", err)
		}
	})
}

func TestSyslogWriteAfterCloseIsRefused(t *testing.T) {
	path := socketPath(t)
	listenSyslog(t, path)
	s, err := NewSyslog(config.SyslogOutput{Enabled: true, Network: "unixgram", Address: path, Tag: "sauronhost-test"})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := s.Write(context.Background(), execEnvelope(1)); !errors.Is(err, errSinkClosed) {
		t.Errorf("Write after Close = %v, want errSinkClosed", err)
	}
	if s.Name() != "syslog" {
		t.Errorf("Name = %q, want %q", s.Name(), "syslog")
	}
}

func TestSyslogRejectsNilEnvelope(t *testing.T) {
	path := socketPath(t)
	l := listenSyslog(t, path)
	s, err := NewSyslog(config.SyslogOutput{Enabled: true, Network: "unixgram", Address: path, Tag: "sauronhost-test"})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Write(context.Background(), nil); !errors.Is(err, errNilEnvelope) {
		t.Fatalf("err = %v, want errNilEnvelope", err)
	}
	select {
	case msg := <-l.msgs:
		t.Errorf("a nil envelope produced a message: %q", msg)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSyslogDefaultsTag(t *testing.T) {
	path := socketPath(t)
	l := listenSyslog(t, path)
	s, err := NewSyslog(config.SyslogOutput{Enabled: true, Network: "unixgram", Address: path})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	defer func() { _ = s.Close() }()

	if err := s.Write(context.Background(), denialEnvelope(4)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	msg := l.receive(t)
	if !strings.Contains(msg, fmt.Sprintf("%s[%d]:", defaultSyslogTag, os.Getpid())) {
		t.Errorf("message %q is not tagged %q", msg, defaultSyslogTag)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Errorf("Flush: %v", err)
	}
}
