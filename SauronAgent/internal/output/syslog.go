package output

// This sink uses log/syslog, which the standard library provides on Unix only.
// There is deliberately no build tag here: SauronAgent reads NETLINK_AUDIT and
// is a Linux program end to end, and a tag that compiled the sink away
// elsewhere would turn "syslog is configured" into "events go nowhere" without
// anyone being told.

import (
	"bytes"
	"context"
	"fmt"
	"log/syslog"
	"strings"
	"sync"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
)

// defaultSyslogTag is used when configuration names none, so that events can
// always be traced back to the collector that emitted them.
const defaultSyslogTag = "sauronhost"

// syslogFacilities maps the configuration's facility names onto the syslog
// facility codes.
var syslogFacilities = map[string]syslog.Priority{
	"kern":     syslog.LOG_KERN,
	"user":     syslog.LOG_USER,
	"mail":     syslog.LOG_MAIL,
	"daemon":   syslog.LOG_DAEMON,
	"auth":     syslog.LOG_AUTH,
	"syslog":   syslog.LOG_SYSLOG,
	"lpr":      syslog.LOG_LPR,
	"news":     syslog.LOG_NEWS,
	"uucp":     syslog.LOG_UUCP,
	"cron":     syslog.LOG_CRON,
	"authpriv": syslog.LOG_AUTHPRIV,
	"ftp":      syslog.LOG_FTP,
	"local0":   syslog.LOG_LOCAL0,
	"local1":   syslog.LOG_LOCAL1,
	"local2":   syslog.LOG_LOCAL2,
	"local3":   syslog.LOG_LOCAL3,
	"local4":   syslog.LOG_LOCAL4,
	"local5":   syslog.LOG_LOCAL5,
	"local6":   syslog.LOG_LOCAL6,
	"local7":   syslog.LOG_LOCAL7,
}

// parseFacility resolves a configured facility name.
//
// An unknown name is an error rather than a fallback: silently sending audit
// evidence to a facility the operator did not choose can route it to a
// world-readable file, or to no file at all.
func parseFacility(name string) (syslog.Priority, error) {
	trimmed := strings.ToLower(strings.TrimSpace(name))
	if trimmed == "" {
		// authpriv is the configured default: on a stock system its files are
		// already restricted, which is where authentication evidence belongs.
		return syslog.LOG_AUTHPRIV, nil
	}
	p, ok := syslogFacilities[trimmed]
	if !ok {
		return 0, fmt.Errorf("output/syslog: unknown facility %q", name)
	}
	return p, nil
}

// syslogSeverity maps an event severity onto a syslog severity.
func syslogSeverity(severity string) syslog.Priority {
	switch severity {
	case event.SeverityCritical:
		return syslog.LOG_CRIT
	case event.SeverityWarning:
		return syslog.LOG_WARNING
	case event.SeverityNotice:
		return syslog.LOG_NOTICE
	case event.SeverityInfo, "":
		return syslog.LOG_INFO
	default:
		// An unrecognized severity is not evidence that the event is routine.
		// Raise it to notice so a newer agent's vocabulary cannot bury an
		// event below the level an operator filters on.
		return syslog.LOG_NOTICE
	}
}

// syslogSink forwards envelopes to a syslog daemon as JSON messages.
type syslogSink struct {
	mu sync.Mutex

	network  string
	address  string
	tag      string
	facility syslog.Priority

	// w is nil whenever there is no usable connection, which is the state a
	// Write recovers from by dialling again.
	w      *syslog.Writer
	closed bool
}

// NewSyslog returns a sink forwarding events to a syslog daemon.
//
// An empty cfg.Network means the local syslog socket; otherwise Network and
// Address are dialled. The connection is established here so that a collector
// configured for a syslog daemon it cannot reach fails visibly at startup
// instead of discovering it on the first event.
func NewSyslog(cfg config.SyslogOutput) (Sink, error) {
	facility, err := parseFacility(cfg.Facility)
	if err != nil {
		return nil, err
	}
	tag := strings.TrimSpace(cfg.Tag)
	if tag == "" {
		tag = defaultSyslogTag
	}
	s := &syslogSink{
		network:  cfg.Network,
		address:  cfg.Address,
		tag:      tag,
		facility: facility,
	}
	if err := s.connectLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

// connectLocked dials the daemon if there is no live connection. The caller
// must hold mu, except in NewSyslog where the sink is not yet shared.
func (s *syslogSink) connectLocked() error {
	if s.w != nil {
		return nil
	}
	// The severity in this priority is only the writer's default; every
	// message below picks its own from the event.
	priority := s.facility | syslog.LOG_INFO
	var (
		w   *syslog.Writer
		err error
	)
	if s.network == "" {
		w, err = syslog.New(priority, s.tag)
	} else {
		w, err = syslog.Dial(s.network, s.address, priority, s.tag)
	}
	if err != nil {
		return fmt.Errorf("output/syslog: connecting to %s: %w", s.destination(), err)
	}
	s.w = w
	return nil
}

func (s *syslogSink) destination() string {
	if s.network == "" {
		return "local syslog socket"
	}
	return s.network + ":" + s.address
}

// Write forwards one envelope as a single JSON syslog message.
//
// A daemon that is down produces an error, never a silent drop: the collector
// acknowledges an event to the guest only once every sink has accepted it, and
// the guest's spool is what replays the events a restarting rsyslog missed.
func (s *syslogSink) Write(ctx context.Context, env *Envelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	line, err := marshalLine(env, false)
	if err != nil {
		return fmt.Errorf("output/syslog: encoding envelope: %w", err)
	}
	// One syslog message is one line. The JSON encoding already escapes any
	// newline inside the event, so only the terminator has to come off.
	//
	// An oversized message is reported as a write error rather than truncated
	// here: a shortened record is corrupted evidence, and a receiver that
	// rejects it should be fixed by configuration, not hidden.
	msg := string(bytes.TrimRight(line, "\n"))
	severity := syslogSeverity(envelopeSeverity(env))

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	if err := s.connectLocked(); err != nil {
		return err
	}
	if err := s.emitLocked(severity, msg); err != nil {
		// Drop the connection so the next Write dials again. A restarted
		// daemon then costs only the events it was actually down for, rather
		// than everything until the collector is restarted.
		s.closeWriterLocked()
		return fmt.Errorf("output/syslog: writing to %s: %w", s.destination(), err)
	}
	return nil
}

// emitLocked sends msg at the given severity. syslog.Writer only exposes a
// method per severity, so the mapping is spelled out here.
func (s *syslogSink) emitLocked(severity syslog.Priority, msg string) error {
	switch severity {
	case syslog.LOG_CRIT:
		return s.w.Crit(msg)
	case syslog.LOG_WARNING:
		return s.w.Warning(msg)
	case syslog.LOG_NOTICE:
		return s.w.Notice(msg)
	default:
		return s.w.Info(msg)
	}
}

func (s *syslogSink) closeWriterLocked() {
	if s.w == nil {
		return
	}
	_ = s.w.Close()
	s.w = nil
}

// envelopeSeverity reads the event's severity, tolerating an envelope that
// carries no event so that a malformed one is reported by Write rather than
// crashing the collector here.
func envelopeSeverity(env *Envelope) string {
	if env == nil || env.Event == nil {
		return ""
	}
	return env.Event.Severity
}

// Flush is a no-op: syslog.Writer holds no buffer of its own, so an envelope
// has been handed to the daemon by the time Write returns. Durability from
// there is the daemon's.
func (s *syslogSink) Flush(ctx context.Context) error { return ctx.Err() }

// Close releases the connection to the daemon.
func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.w == nil {
		return nil
	}
	w := s.w
	s.w = nil
	if err := w.Close(); err != nil {
		return fmt.Errorf("output/syslog: closing %s: %w", s.destination(), err)
	}
	return nil
}

// Name identifies the sink in logs and metrics.
func (s *syslogSink) Name() string { return "syslog" }
