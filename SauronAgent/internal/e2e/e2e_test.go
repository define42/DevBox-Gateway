package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/config"
	"github.com/define42/SauronAgent/internal/event"
	"github.com/define42/SauronAgent/internal/protocol"
)

// Two event types the collector generates. They are unexported in
// internal/host and repeated here because they are what the tests below assert
// on: a hole in a guest's sequence numbers, and an event no sink would accept.
const (
	typeStreamGap    = "sauron.stream.gap"
	typeOutputFailed = "sauron.output.failed"
)

// ---------------------------------------------------------------------------
// 1. the whole session, end to end
// ---------------------------------------------------------------------------

// expectedEvent is one normalized event as the collector should have written
// it. A nil identity pointer means the field must be absent: "no uid in the
// source records" and "uid 0" are different facts and the model keeps them
// apart.
type expectedEvent struct {
	auditID     string
	typ         string
	severity    string
	result      string
	pid         *int
	ppid        *int
	uid         *int
	auid        *int
	exe         string
	command     string
	cwd         string
	paths       []string
	recordTypes []string
}

// sessionExpectations describes every event testdata/audit_session.txt should
// produce, in the order the kernel emitted the records.
//
// Between them they are the scenarios DESIGN.md asks an integration test to
// produce: a failed authentication, a login, a sudo command, a process
// execution, a file access, an nft change, an SELinux denial and two audit
// configuration changes.
func sessionExpectations() []expectedEvent {
	return []expectedEvent{
		{
			auditID: "1789752301.123:8412", typ: event.TypeAuthFailure,
			severity: event.SeverityWarning, result: event.ResultFailure,
			pid: event.Int(1421), uid: event.Int(0), exe: "/usr/sbin/sshd",
			recordTypes: []string{"USER_AUTH"},
		},
		{
			auditID: "1789752305.451:8414", typ: event.TypeAuthLogin,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(1421), uid: event.Int(0), exe: "/usr/sbin/sshd",
			recordTypes: []string{"USER_AUTH"},
		},
		{
			auditID: "1789752305.455:8415", typ: event.TypeAuthLogin,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(1421), uid: event.Int(0), exe: "/usr/sbin/sshd",
			recordTypes: []string{"CRED_ACQ"},
		},
		{
			// The record that sets the audit login uid: from here on every
			// event of this session carries auid=1000, however often the user
			// changes identity.
			auditID: "1789752305.459:8416", typ: event.TypeAuthLogin,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(1421), uid: event.Int(0), auid: event.Int(1000),
			recordTypes: []string{"LOGIN"},
		},
		{
			auditID: "1789752305.462:8417", typ: event.TypeAuthLogin,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(1421), uid: event.Int(0), auid: event.Int(1000),
			exe: "/usr/sbin/sshd", recordTypes: []string{"USER_START"},
		},
		{
			auditID: "1789752305.466:8418", typ: event.TypeAuthLogin,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(1421), uid: event.Int(0), auid: event.Int(1000),
			exe: "/usr/sbin/sshd", recordTypes: []string{"USER_LOGIN"},
		},
		{
			// sudo. The command is hex encoded in the record because it
			// contains a space, and has to arrive decoded.
			auditID: "1789752340.201:8420", typ: event.TypeUserCommand,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(4820), uid: event.Int(1000), auid: event.Int(1000),
			command: "/usr/bin/cat /etc/shadow", cwd: "/home/analyst",
			recordTypes: []string{"USER_CMD"},
		},
		{
			// The execution itself: root by then, but still auid=1000.
			auditID: "1789752340.225:8421", typ: event.TypeProcessExec,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(4821), ppid: event.Int(4820),
			uid: event.Int(0), auid: event.Int(1000),
			exe: "/usr/bin/cat", command: "/usr/bin/cat /etc/shadow", cwd: "/home/analyst",
			paths:       []string{"/usr/bin/cat", "/lib64/ld-linux-x86-64.so.2"},
			recordTypes: []string{"SYSCALL", "EXECVE", "CWD", "PATH", "PATH", "PROCTITLE", "EOE"},
		},
		{
			auditID: "1789752340.240:8424", typ: event.TypeFileAccess,
			severity: event.SeverityInfo, result: event.ResultSuccess,
			pid: event.Int(4821), ppid: event.Int(4820),
			uid: event.Int(0), auid: event.Int(1000),
			exe: "/usr/bin/cat", command: "/usr/bin/cat /etc/shadow", cwd: "/home/analyst",
			paths:       []string{"/etc/shadow"},
			recordTypes: []string{"SYSCALL", "CWD", "PATH", "PROCTITLE", "EOE"},
		},
		{
			// NETFILTER_CFG decides the category: the bare sendmsg(2) it
			// travelled in would have been reported as nothing at all.
			auditID: "1789752352.118:8429", typ: event.TypeFirewallConfiguration,
			severity: event.SeverityWarning, result: event.ResultSuccess,
			pid: event.Int(4841), ppid: event.Int(4840),
			uid: event.Int(0), auid: event.Int(1000),
			exe: "/usr/sbin/nft", command: "nft -f /etc/nftables.conf",
			recordTypes: []string{"NETFILTER_CFG", "SYSCALL", "PROCTITLE", "EOE"},
		},
		{
			// The denial is the event; the syscall is its context. auid is
			// absent because the kernel reported it unset, which is not the
			// same as 0.
			auditID: "1789752361.744:8433", typ: event.TypeSELinuxDenial,
			severity: event.SeverityWarning, result: event.ResultFailure,
			pid: event.Int(4850), ppid: event.Int(1), uid: event.Int(33),
			exe: "/usr/sbin/nginx", command: "nginx: worker process", cwd: "/",
			paths:       []string{"/etc/shadow"},
			recordTypes: []string{"AVC", "SYSCALL", "CWD", "PATH", "PROCTITLE", "EOE"},
		},
		{
			// A rule change is never an ordinary event.
			auditID: "1789752372.909:8436", typ: event.TypeAuditConfiguration,
			severity: event.SeverityCritical, result: event.ResultSuccess,
			auid: event.Int(1000), recordTypes: []string{"CONFIG_CHANGE"},
		},
		{
			// Auditing switched off: the last thing this guest would ever
			// report if nobody were watching for it.
			auditID: "1789752380.517:8438", typ: event.TypeAuditConfiguration,
			severity: event.SeverityCritical, result: event.ResultSuccess,
			auid: event.Int(1000), recordTypes: []string{"CONFIG_CHANGE"},
		},
	}
}

// TestSessionArrivesNormalizedAndIntact replays a whole audit session through
// a real agent into a real collector and checks what came out the far end:
// the right events, in the right order, categorised correctly, carrying the
// host's trusted enrichment, and with the kernel's original record text
// preserved byte for byte.
func TestSessionArrivesNormalizedAndIntact(t *testing.T) {
	blocks := loadSession(t)
	want := sessionExpectations()
	if len(blocks) != len(want) {
		t.Fatalf("%s holds %d events, the expectations describe %d", sessionPath, len(blocks), len(want))
	}

	h := newHarness(t, nil)
	cfg := agentConfig(h.addr(guestCID), t.TempDir())
	// Heartbeats on. They are asserted indirectly: a PING the collector never
	// answered would tear the session down and leave a
	// sauron.transport.disconnected event behind, and there must be none.
	cfg.Heartbeat.Interval = config.Duration(50 * time.Millisecond)
	cfg.Heartbeat.Timeout = config.Duration(5 * time.Second)

	started := time.Now()
	g := h.startGuest(cfg, guestIdentity())

	// One event at a time, so that the order of arrival is the order the
	// kernel emitted them and not a race between two correlation timeouts.
	for i, b := range blocks {
		g.feed(b)
		h.waitAudited(i + 1)
	}

	got := h.rec.audited()
	if len(got) != len(want) {
		t.Fatalf("the collector wrote %d audit events, want %d", len(got), len(want))
	}

	var lastSeq uint64
	for i, w := range want {
		checkEvent(t, i, w, got[i], blocks[i])

		e := got[i].env.Event
		if e.Sequence <= lastSeq {
			t.Errorf("event %d (%s) has sequence %d, which does not follow %d",
				i, e.AuditID, e.Sequence, lastSeq)
		}
		lastSeq = e.Sequence

		// Trusted enrichment, on every event and not just the first: the CID
		// came from the connection, the VM name and the asset metadata from
		// the collector's configuration, the hypervisor name from the host.
		src := got[i].env.Source
		if src.CID != guestCID || src.VM != guestVM || !src.Known {
			t.Errorf("event %d source is cid=%d vm=%q known=%t, want cid=%d vm=%q known",
				i, src.CID, src.VM, src.Known, guestCID, guestVM)
		}
		if src.Host != hypervisorName {
			t.Errorf("event %d source.host = %q, want %q", i, src.Host, hypervisorName)
		}
		if src.Environment != "production" || src.SecurityDomain != "restricted" || src.VLAN != "310" {
			t.Errorf("event %d lost the configured asset metadata: %+v", i, src)
		}
		if src.Labels["owner"] != "data-team" {
			t.Errorf("event %d source.labels = %v, want owner=data-team", i, src.Labels)
		}
		if src.Reported == nil || src.Reported.Hostname != guestVM ||
			src.Reported.BootID != guestIdentity().BootID {
			t.Errorf("event %d did not record what the guest claimed: %+v", i, src.Reported)
		}
		if got[i].env.ReceivedAt.Before(started) {
			t.Errorf("event %d was stamped %s, before the test started at %s",
				i, got[i].env.ReceivedAt, started)
		}
	}

	// The agent reports on itself in the same stream. Exactly one start and
	// one connection, and no disconnection at all, is what a session that
	// never broke looks like.
	if n := len(h.rec.internalOfType(event.TypeAgentStarted)); n != 1 {
		t.Errorf("%d sauron.agent.started events, want 1", n)
	}
	if n := len(h.rec.internalOfType(event.TypeTransportConnected)); n != 1 {
		t.Errorf("%d sauron.transport.connected events, want 1", n)
	}
	for _, typ := range []string{
		event.TypeTransportDisconnect,
		event.TypeParseFailure,
		event.TypeQueueOverflow,
		event.TypeSpoolFull,
		event.TypeProtocolViolation,
		typeStreamGap,
	} {
		if n := len(h.rec.internalOfType(typ)); n != 0 {
			t.Errorf("%d %s events on a healthy run, want none", n, typ)
		}
	}
	assertNoGaps(t, h.rec)
}

// checkEvent compares one delivered event with what the records said, and
// checks that the records themselves travelled with it.
func checkEvent(t *testing.T, i int, want expectedEvent, got delivered, src block) {
	t.Helper()

	e := got.env.Event
	if e.AuditID != want.auditID {
		t.Fatalf("event %d has audit id %s, want %s (events out of order?)", i, e.AuditID, want.auditID)
	}
	label := fmt.Sprintf("event %d (%s)", i, want.auditID)

	if e.Type != want.typ {
		t.Errorf("%s type = %q, want %q", label, e.Type, want.typ)
	}
	if e.Severity != want.severity {
		t.Errorf("%s severity = %q, want %q", label, e.Severity, want.severity)
	}
	if e.Result != want.result {
		t.Errorf("%s result = %q, want %q", label, e.Result, want.result)
	}
	if e.Version != event.SchemaVersion {
		t.Errorf("%s schema version = %d, want %d", label, e.Version, event.SchemaVersion)
	}
	if e.BootID != guestIdentity().BootID {
		t.Errorf("%s boot id = %q, want %q", label, e.BootID, guestIdentity().BootID)
	}
	checkID(t, label+" pid", e.PID, want.pid)
	checkID(t, label+" ppid", e.PPID, want.ppid)
	checkID(t, label+" uid", e.UID, want.uid)
	checkID(t, label+" auid", e.AUID, want.auid)
	if e.Executable != want.exe {
		t.Errorf("%s exe = %q, want %q", label, e.Executable, want.exe)
	}
	if e.Command != want.command {
		t.Errorf("%s command = %q, want %q", label, e.Command, want.command)
	}
	if e.CWD != want.cwd {
		t.Errorf("%s cwd = %q, want %q", label, e.CWD, want.cwd)
	}
	if !reflect.DeepEqual(e.Paths, want.paths) {
		t.Errorf("%s paths = %v, want %v", label, e.Paths, want.paths)
	}
	if !reflect.DeepEqual(e.RecordTypes, want.recordTypes) {
		t.Errorf("%s record types = %v, want %v", label, e.RecordTypes, want.recordTypes)
	}

	// DESIGN.md section 10: normalization must not be the only representation
	// of an event. The kernel's own words have to survive the parser, the
	// correlator, the normalizer, the spool, the JSON codec and the collector
	// without a byte changing.
	if !reflect.DeepEqual(e.Raw, src.lines) {
		t.Errorf("%s raw records were not preserved.\n got: %q\nwant: %q", label, e.Raw, src.lines)
	}
}

// checkID compares an identity field, treating absence as a value of its own.
func checkID(t *testing.T, label string, got, want *int) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("%s is absent, want %d", label, *want)
	case want == nil:
		t.Errorf("%s = %d, want it absent", label, *got)
	case *got != *want:
		t.Errorf("%s = %d, want %d", label, *got, *want)
	}
}

// ---------------------------------------------------------------------------
// 2. root events survive
// ---------------------------------------------------------------------------

// TestRootIdentitySurvivesTheWholePath checks the regression the pointer
// identity fields exist for: uid=0 is the single most security-relevant value
// in the model, and a plain int with omitempty would erase it somewhere
// between the guest's normalizer and the collector's output.
//
// The SELinux denial is checked alongside it for the opposite reason: its auid
// really is absent, and an absent field must stay absent rather than be
// rendered as 0.
func TestRootIdentitySurvivesTheWholePath(t *testing.T) {
	blocks := loadSession(t)
	rootExec := blockByID(t, blocks, "1789752340.225:8421")
	denial := blockByID(t, blocks, "1789752361.744:8433")

	h := newHarness(t, nil)
	g := h.startGuest(agentConfig(h.addr(guestCID), t.TempDir()), guestIdentity())
	g.feed(rootExec)
	g.feed(denial)
	h.waitAuditIDs([]string{rootExec.auditID, denial.auditID})

	got := h.rec.audited()
	if len(got) != 2 {
		t.Fatalf("the collector wrote %d audit events, want 2", len(got))
	}

	exec := got[0]
	if exec.env.Event.UID == nil || *exec.env.Event.UID != 0 {
		t.Fatalf("the root execution arrived with uid %v, want 0", exec.env.Event.UID)
	}
	doc := eventJSON(t, exec)
	uid, ok := doc["uid"]
	if !ok {
		t.Errorf("uid is missing from the written JSON; root would be invisible in the evidence:\n%s", exec.line)
	} else if n, isNum := uid.(json.Number); !isNum || n.String() != "0" {
		t.Errorf("written uid = %#v, want the number 0", uid)
	}

	avc := got[1]
	if avc.env.Event.AUID != nil {
		t.Errorf("the denial arrived with auid %d, want it absent: the kernel reported it unset",
			*avc.env.Event.AUID)
	}
	avcDoc := eventJSON(t, avc)
	if _, present := avcDoc["auid"]; present {
		t.Errorf("an unset auid was written as a value:\n%s", avc.line)
	}
	// The literal the kernel wrote is still there as evidence, one level down,
	// so nothing was discarded -- only kept out of the typed field where it
	// would have read as a real user id.
	fields, _ := avcDoc["fields"].(map[string]any)
	if fields == nil || fields["auid"] != "4294967295" {
		t.Errorf("the unset auid was dropped instead of preserved: %v", fields["auid"])
	}
}

// ---------------------------------------------------------------------------
// 3. the guest cannot choose who it is
// ---------------------------------------------------------------------------

// TestIdentityCannotBeForged has the agent claim to be another VM in the
// collector's own map. DESIGN.md section 13: the VM is identified by the CID
// its connection arrived on, and everything it says about itself is recorded
// as a claim.
func TestIdentityCannotBeForged(t *testing.T) {
	blocks := loadSession(t)
	h := newHarness(t, nil)

	liar := guestIdentity()
	liar.Hostname = claimedVM
	liar.MachineID = "0000000000000000000000000000dead"
	liar.BootID = "00000000-0000-4000-8000-00000000beef"

	g := h.startGuest(agentConfig(h.addr(guestCID), t.TempDir()), liar)
	g.feed(blocks[0])
	h.waitAudited(1)

	src := h.rec.audited()[0].env.Source
	if src.VM != guestVM {
		t.Errorf("source.vm = %q, want %q: the VM name comes from the collector's "+
			"CID map, never from the guest", src.VM, guestVM)
	}
	if src.VM == claimedVM {
		t.Error("the guest talked the collector into another VM's identity")
	}
	if src.CID != guestCID || !src.Known {
		t.Errorf("source cid=%d known=%t, want cid=%d known", src.CID, src.Known, guestCID)
	}
	if src.Host != hypervisorName {
		t.Errorf("source.host = %q, want %q", src.Host, hypervisorName)
	}
	if src.SecurityDomain != "restricted" {
		t.Errorf("source.security_domain = %q, want the domain configured for CID %d",
			src.SecurityDomain, guestCID)
	}

	// The claim is not thrown away: a guest reporting a hostname that
	// disagrees with its CID mapping is a signal, and it is only a signal if
	// it was recorded.
	if src.Reported == nil {
		t.Fatal("the guest's claims were not recorded at all")
	}
	if src.Reported.Hostname != claimedVM {
		t.Errorf("source.reported.hostname = %q, want the guest's claim %q", src.Reported.Hostname, claimedVM)
	}
	if src.Reported.MachineID != liar.MachineID || src.Reported.BootID != liar.BootID {
		t.Errorf("source.reported = %+v, want the machine and boot ids the guest sent", src.Reported)
	}
	if src.Reported.AgentVersion != liar.Version {
		t.Errorf("source.reported.agent_version = %q, want %q", src.Reported.AgentVersion, liar.Version)
	}
}

// ---------------------------------------------------------------------------
// 4. a host outage loses nothing
// ---------------------------------------------------------------------------

// TestHostOutageAndRecovery stops the collector in the middle of a session,
// keeps feeding the guest and starts the collector again. Every event must
// arrive. Duplicates are allowed -- delivery is at-least-once and a reconnect
// replays -- but a hole is not.
func TestHostOutageAndRecovery(t *testing.T) {
	blocks := loadSession(t)
	h := newHarness(t, nil)
	g := h.startGuest(agentConfig(h.addr(guestCID), t.TempDir()), guestIdentity())

	before, during, after := blocks[:3], blocks[3:8], blocks[8:]

	g.feedAll(before)
	h.waitAuditIDs(auditIDs(before))

	// The collector dies rather than stops: the guest gets no SHUTDOWN and no
	// last acknowledgement, so anything it had in flight is still owed and
	// will be sent again.
	h.crashCollector()

	// The guest keeps collecting through the outage: nothing upstream of the
	// spool is allowed to wait for the host.
	g.feedAll(during)
	waitFor(t, "the agent to number everything it was fed during the outage", func() bool {
		return g.created() >= uint64(len(before)+len(during)+1)
	})
	if n := h.rec.closed(); n < 1 {
		t.Errorf("the collector's sink was closed %d times, want at least 1", n)
	}

	h.startCollector()
	g.feedAll(after)

	h.waitAuditIDs(auditIDs(blocks))
	assertNoGaps(t, h.rec)

	delivered := h.rec.auditIDs()
	if len(delivered) != len(blocks) {
		t.Errorf("%d distinct audit events arrived, want %d", len(delivered), len(blocks))
	}
	// The reconnected collector holds no history of the stream, so it asks for
	// everything the guest still has and deduplication takes the rest. That
	// makes duplicates likely here, and losing one an outright failure.
	for _, b := range blocks {
		if delivered[b.auditID] == 0 {
			t.Errorf("audit event %s was never delivered", b.auditID)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. an agent restart resumes the spool
// ---------------------------------------------------------------------------

// TestAgentRestartRedeliversAndContinuesNumbering stops an agent with events
// it never managed to deliver and starts another one on the same spool. The
// unacknowledged events must be sent again, and the new agent must carry on
// numbering above them rather than starting over: within one boot a sequence
// number is issued exactly once, which is what makes the host's deduplication
// key mean anything.
func TestAgentRestartRedeliversAndContinuesNumbering(t *testing.T) {
	blocks := loadSession(t)
	h := newHarness(t, nil)
	spoolDir := t.TempDir()

	// The collector is down for the whole of the first agent's life, so
	// everything it collects stays in the spool, unacknowledged.
	h.stopCollector()

	cfg := agentConfig(h.addr(guestCID), spoolDir)
	// Slower retries: a failed dial is reported as an event, and at five
	// milliseconds apart those reports would outnumber the audit data.
	cfg.Reconnect.InitialDelay = config.Duration(100 * time.Millisecond)
	cfg.Reconnect.MaxDelay = config.Duration(200 * time.Millisecond)

	first, second := blocks[:4], blocks[4:6]

	g1 := h.startGuest(cfg, guestIdentity())
	g1.feedAll(first)
	waitFor(t, "the first agent to number everything it collected", func() bool {
		return g1.created() >= uint64(len(first)+1)
	})
	g1.stop()
	highestBeforeRestart := g1.created()
	if highestBeforeRestart == 0 {
		t.Fatal("the first agent numbered nothing")
	}

	h.startCollector()
	g2 := h.startGuest(cfg, guestIdentity())
	g2.feedAll(second)

	h.waitAuditIDs(auditIDs(blocks[:6]))
	assertNoGaps(t, h.rec)

	// What the first agent collected reached the collector only because the
	// second one found it on disk.
	for _, b := range first {
		if h.rec.auditIDs()[b.auditID] == 0 {
			t.Errorf("audit event %s, collected before the restart, was never delivered", b.auditID)
		}
	}

	// And the second agent's own events are numbered above everything the
	// first one issued.
	newIDs := make(map[string]bool, len(second))
	for _, b := range second {
		newIDs[b.auditID] = true
	}
	for _, d := range h.rec.audited() {
		e := d.env.Event
		if newIDs[e.AuditID] && e.Sequence <= highestBeforeRestart {
			t.Errorf("event %s collected after the restart reused sequence %d; the first agent "+
				"had already issued up to %d", e.AuditID, e.Sequence, highestBeforeRestart)
		}
	}
}

// ---------------------------------------------------------------------------
// 6. duplicate suppression
// ---------------------------------------------------------------------------

// TestDuplicateSuppression checks the deduplication key from protocol.md
// section 6: (peer CID, boot id, sequence). A replay of the same triple is
// suppressed, and a change in either of the other two members is a different
// stream whose sequence 1 is a new event and not a duplicate.
func TestDuplicateSuppression(t *testing.T) {
	h := newHarness(t, nil)

	send := func(c *rawClient, boot string, seqs ...uint64) {
		for _, seq := range seqs {
			c.sendEvent(seq, rawEvent(seq, boot))
		}
	}
	waitReceived := func(n uint64) {
		waitFor(t, fmt.Sprintf("%d event frames at the collector", n), func() bool {
			return h.counters.EventsReceived.Load() >= n
		})
	}

	first := h.dialRaw(guestCID)
	first.hello("boot-a", 1)
	send(first, "boot-a", 1, 2, 3)
	waitReceived(3)
	h.waitAudited(3)

	// The same three sequences again, on the same stream. The collector holds
	// them already, so it must write nothing and still acknowledge: an event
	// it refuses to acknowledge is one the guest can never release.
	send(first, "boot-a", 1, 2, 3)
	waitReceived(6)
	waitFor(t, "the collector to count the duplicates", func() bool {
		return h.counters.EventsDuplicate.Load() >= 3
	})
	if n := h.rec.auditedCount(); n != 3 {
		t.Errorf("%d events written after a full replay, want 3", n)
	}
	first.waitAck(3)

	// A reboot restarts the guest's numbering, so the same sequences are
	// different events and suppressing them would destroy evidence.
	rebooted := h.dialRaw(guestCID)
	rebooted.hello("boot-b", 1)
	send(rebooted, "boot-b", 1, 2, 3)
	waitReceived(9)
	h.waitAudited(6)

	// And a different VM's stream is not this one's, however it numbers its
	// events: the CID half of the key is not something a guest can choose.
	neighbour := h.dialRaw(otherCID)
	neighbour.hello("boot-a", 1)
	send(neighbour, "boot-a", 1, 2, 3)
	waitReceived(12)
	h.waitAudited(9)

	if got := h.counters.EventsDuplicate.Load(); got != 3 {
		t.Errorf("the collector suppressed %d events, want exactly the 3 that were replayed", got)
	}
	if n := h.rec.auditedCount(); n != 9 {
		t.Errorf("%d events written in total, want 9", n)
	}
	for _, d := range h.rec.audited() {
		if d.env.Source.CID != guestCID && d.env.Source.CID != otherCID {
			t.Errorf("event %s arrived attributed to CID %d", d.env.Event.AuditID, d.env.Source.CID)
		}
	}
}

// rawEvent builds one plausible event for a hand-written guest.
func rawEvent(seq uint64, boot string) *event.Event {
	return &event.Event{
		Version:     event.SchemaVersion,
		Sequence:    seq,
		Timestamp:   time.Unix(1789752400+int64(seq), 0).UTC(),
		Type:        event.TypeProcessExec,
		Severity:    event.SeverityInfo,
		AuditID:     fmt.Sprintf("178975240%d.000:%d", seq, 9000+seq),
		BootID:      boot,
		PID:         event.Int(int(4900 + seq)),
		UID:         event.Int(0),
		Executable:  "/usr/bin/id",
		Command:     "id",
		Result:      event.ResultSuccess,
		RecordTypes: []string{"SYSCALL", "EXECVE"},
	}
}

// ---------------------------------------------------------------------------
// 7. backpressure
// ---------------------------------------------------------------------------

// TestBackpressureHoldsAcknowledgement makes the collector's output fail.
//
// An acknowledgement tells the guest it may delete its only copy, so nothing
// may be acknowledged while the sinks are refusing. When the output recovers,
// everything must be delivered and acknowledged without a nudge from the test.
func TestBackpressureHoldsAcknowledgement(t *testing.T) {
	blocks := loadSession(t)
	h := newHarness(t, nil)

	cfg := agentConfig(h.addr(guestCID), t.TempDir())
	// A host that takes the bytes and never acknowledges is what a failing
	// sink looks like from the guest. The acknowledgement timeout is what
	// eventually makes the agent reconnect and try again, so turn it down to
	// something a test can wait for.
	cfg.Transport.AckTimeout = config.Duration(500 * time.Millisecond)

	h.rec.setFailing(true)
	g := h.startGuest(cfg, guestIdentity())

	fed := blocks[:3]
	g.feedAll(fed)
	waitFor(t, "the collector to have tried, and failed, to write every event", func() bool {
		refused := h.rec.refusedAuditIDs()
		for _, b := range fed {
			if refused[b.auditID] == 0 {
				return false
			}
		}
		return true
	})

	if n := h.rec.auditedCount(); n != 0 {
		t.Fatalf("%d events were recorded while every write was failing", n)
	}
	if n := g.acknowledged(); n != 0 {
		t.Errorf("the guest was told %d events were safe while the collector could not write one", n)
	}
	if n := h.counters.OutputErrors.Load(); n == 0 {
		t.Error("the collector did not count a single output error")
	}
	// The failure is not only counted. It cannot be written to the sink that
	// is failing, so the collector hands it to the supervising process
	// instead, which is the only way a deployment learns its outputs are down.
	var reportedFailures int
	for _, env := range h.reported() {
		if env.Event != nil && env.Event.Type == typeOutputFailed {
			reportedFailures++
		}
	}
	if reportedFailures == 0 {
		t.Errorf("the collector never reported a %s event", typeOutputFailed)
	}

	h.rec.setFailing(false)

	h.waitAuditIDs(auditIDs(fed))
	waitFor(t, "the guest to be told its events are safe", func() bool {
		return g.acknowledged() >= uint64(len(fed))
	})
	assertNoGaps(t, h.rec)
}

// ---------------------------------------------------------------------------
// 8. a hostile guest
// ---------------------------------------------------------------------------

// hostileCase is one thing a compromised guest can put on the wire.
type hostileCase struct {
	name string
	// handshake completes HELLO/READY first, for the violations that are only
	// reachable in the steady state.
	handshake bool
	attack    func(t *testing.T, c *rawClient)
	// wantCode is the ERROR the collector must answer with, or "" when the
	// failure is a torn stream rather than a statement about the peer.
	wantCode protocol.ErrorCode
	// wantViolation is whether the collector must report the peer.
	wantViolation bool
}

// TestHostileGuestCannotDisturbTheCollector throws at the collector everything
// a compromised guest can send, one connection at a time, while a well-behaved
// guest is delivering on another CID.
//
// Each attack must end with that connection closed and the collector still
// serving. The other guest's stream must come through untouched: a collector
// that one VM can silence for the rest of the fleet would be worse than no
// collector at all.
func TestHostileGuestCannotDisturbTheCollector(t *testing.T) {
	blocks := loadSession(t)
	h := newHarness(t, nil)
	g := h.startGuest(agentConfig(h.addr(guestCID), t.TempDir()), guestIdentity())

	g.feedAll(blocks[:2])
	h.waitAuditIDs(auditIDs(blocks[:2]))

	cases := []hostileCase{
		{
			name: "garbage",
			attack: func(t *testing.T, c *rawClient) {
				c.sendRaw([]byte("GET /events HTTP/1.1\r\nHost: sauronhost\r\nAccept: */*\r\n\r\n"))
			},
			wantCode: protocol.ErrCodeBadFrame, wantViolation: true,
		},
		{
			name: "wrong magic",
			attack: func(t *testing.T, c *rawClient) {
				buf := header(t, protocol.Header{Version: protocol.Version, Type: protocol.MsgHello})
				buf[0] = 'X'
				c.sendRaw(buf)
			},
			wantCode: protocol.ErrCodeBadFrame, wantViolation: true,
		},
		{
			name: "oversized declared payload",
			attack: func(t *testing.T, c *rawClient) {
				// Eight megabytes announced by twenty bytes. The length has to
				// be refused before it becomes an allocation.
				c.sendRaw(header(t, protocol.Header{
					Version: protocol.Version, Type: protocol.MsgEvent, PayloadLen: 8 << 20,
				}))
			},
			wantCode: protocol.ErrCodeBadFrame, wantViolation: true,
		},
		{
			name: "reserved flag bit",
			attack: func(t *testing.T, c *rawClient) {
				payload := []byte(`{"protocol_version":1,"agent_version":"hostile"}`)
				c.sendRaw(header(t, protocol.Header{
					Version: protocol.Version, Type: protocol.MsgHello,
					Flags: protocol.Flags(1), PayloadLen: uint32(len(payload)),
				}))
				c.sendRaw(payload)
			},
			wantCode: protocol.ErrCodeBadFrame, wantViolation: true,
		},
		{
			name: "valid header, truncated body",
			attack: func(t *testing.T, c *rawClient) {
				payload := []byte(`{"protocol_version":1,"agent_version":"hostile"}`)
				c.sendRaw(header(t, protocol.Header{
					Version: protocol.Version, Type: protocol.MsgHello, PayloadLen: uint32(len(payload)),
				}))
				c.sendRaw(payload[:len(payload)/2])
				// Half-closed, so the collector sees a stream that stopped
				// rather than a peer still writing. protocol.md section 8: an
				// EOF in mid-frame is a transport failure, not a lie.
				c.closeWrite()
			},
			wantCode: "", wantViolation: false,
		},
		{
			name: "event header and payload sequences disagree", handshake: true,
			attack: func(t *testing.T, c *rawClient) {
				c.sendEvent(7, rawEvent(8, "boot-hostile"))
			},
			wantCode: protocol.ErrCodeBadSequence, wantViolation: true,
		},
		{
			name: "ACK sent by a guest", handshake: true,
			attack: func(t *testing.T, c *rawClient) {
				c.send(protocol.MsgAck, 0, protocol.Ack{Sequence: 1})
			},
			wantCode: protocol.ErrCodeUnexpectedType, wantViolation: true,
		},
	}

	for i, tc := range cases {
		violationsBefore := len(h.rec.internalOfType(event.TypeProtocolViolation))
		errorsBefore := h.counters.FrameErrors.Load()

		c := h.dialRaw(otherCID)
		if tc.handshake {
			c.hello(fmt.Sprintf("boot-hostile-%d", i), 1)
		}
		tc.attack(t, c)
		c.waitClosed()

		var gotCode protocol.ErrorCode
		for _, f := range c.drain() {
			if f.typ == protocol.MsgError {
				gotCode = f.fail.Code
			}
		}
		if gotCode != tc.wantCode {
			t.Errorf("%s: the collector answered with ERROR %q, want %q", tc.name, gotCode, tc.wantCode)
		}
		c.close()

		if !tc.wantViolation {
			// The session ends after the collector has published whatever it
			// had to say about the peer, so by the time the connection is
			// closed the absence of a report is a fact and not a race. A
			// truncated stream must not be reported as a hostile guest, or
			// every network blip would read like an attack.
			if n := len(h.rec.internalOfType(event.TypeProtocolViolation)); n != violationsBefore {
				t.Errorf("%s: the collector reported a protocol violation for a torn stream", tc.name)
			}
			continue
		}

		waitFor(t, "the collector to report the violation by "+tc.name, func() bool {
			return len(h.rec.internalOfType(event.TypeProtocolViolation)) > violationsBefore
		})
		if got := h.counters.FrameErrors.Load(); got <= errorsBefore {
			t.Errorf("%s: frame_errors stayed at %d", tc.name, got)
		}
		// The report names the CID the connection arrived on, which is how an
		// analyst knows which VM to go and look at.
		reported := h.rec.internalOfType(event.TypeProtocolViolation)
		last := reported[len(reported)-1]
		if last.env.Source.CID != otherCID || last.env.Source.VM != otherVM {
			t.Errorf("%s: the violation was attributed to cid=%d vm=%q, want cid=%d vm=%q",
				tc.name, last.env.Source.CID, last.env.Source.VM, otherCID, otherVM)
		}
	}

	// The violations were also handed to the supervising process, which is how
	// a deployment reacts to them without parsing the event stream.
	var notified int
	for _, env := range h.reported() {
		if env.Event != nil && env.Event.Type == event.TypeProtocolViolation {
			notified++
		}
	}
	if notified == 0 {
		t.Error("no protocol violation reached Options.OnInternalEvent")
	}

	// And the guest that was behaving correctly never noticed any of it.
	g.feedAll(blocks[2:4])
	h.waitAuditIDs(auditIDs(blocks[:4]))
	assertNoGaps(t, h.rec)
	for _, d := range h.rec.audited() {
		if d.env.Source.CID != guestCID {
			t.Errorf("audit event %s came from CID %d, want %d",
				d.env.Event.AuditID, d.env.Source.CID, guestCID)
		}
	}
}

// header marshals a frame header, including the ones no correct sender would
// produce.
func header(t *testing.T, h protocol.Header) []byte {
	t.Helper()
	buf := make([]byte, protocol.HeaderSize)
	if err := protocol.MarshalHeader(buf, h); err != nil {
		t.Fatalf("MarshalHeader: %v", err)
	}
	return buf
}

// ---------------------------------------------------------------------------
// 9. the shipped binaries and their configurations
// ---------------------------------------------------------------------------

// TestShippedCommandsAndConfigurations builds both commands and runs them the
// two ways an operator does before a deployment: -version, and -check-config.
// The agent checks its built-in configuration; the host checks the example
// configuration file this repository ships.
func TestShippedCommandsAndConfigurations(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	goTool := goCommand(t)
	binDir := t.TempDir()

	for _, cmd := range []string{"sauronagent", "sauronhost"} {
		binary := filepath.Join(binDir, cmd)
		build := command(t, goTool, "build", "-o", binary, "./cmd/"+cmd)
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", cmd, err, out)
		}

		version := run(t, binary, "-version")
		if !strings.Contains(version, cmd) {
			t.Errorf("%s -version does not name the program:\n%s", cmd, version)
		}
		if !strings.Contains(version, runtime.Version()) {
			t.Errorf("%s -version does not report the Go version:\n%s", cmd, version)
		}

		var check string
		if cmd == "sauronagent" {
			check = run(t, binary, "-check-config")
			if !strings.Contains(check, "built-in") {
				t.Errorf("sauronagent -check-config did not identify its built-in configuration:\n%s", check)
			}
		} else {
			example := filepath.Join(root, "examples", "sauronhost.yaml")
			if _, err := os.Stat(example); err != nil {
				t.Fatalf("the shipped example configuration is missing: %v", err)
			}
			check = run(t, binary, "-check-config", "-config", example)
			if !strings.Contains(check, example) {
				t.Errorf("sauronhost -check-config did not name the file it read:\n%s", check)
			}
		}
		if !strings.Contains(check, "is valid") {
			t.Errorf("%s -check-config did not accept its configuration:\n%s", cmd, check)
		}
		// The summary is the part an operator reads back before trusting the
		// effective settings, so an empty "valid" is not enough.
		if !strings.Contains(check, "logging:") {
			t.Errorf("%s -check-config printed no summary:\n%s", cmd, check)
		}
	}
}

// goCommand finds the toolchain that is running these tests.
func goCommand(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	p := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	t.Fatal("no go toolchain found, and this test builds the shipped commands")
	return ""
}

// command prepares a subprocess bounded by the test's own timeout, so a
// wedged build or binary fails the test instead of hanging it.
func command(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	t.Cleanup(cancel)
	return exec.CommandContext(ctx, name, args...)
}

// run executes a command that must succeed and returns everything it printed.
func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := command(t, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(name), strings.Join(args, " "), err, out)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// auditIDs lists the kernel event ids of a run of blocks.
func auditIDs(blocks []block) []string {
	out := make([]string, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, b.auditID)
	}
	return out
}

// blockByID finds one event's records in the session.
func blockByID(t *testing.T, blocks []block, id string) block {
	t.Helper()
	for _, b := range blocks {
		if b.auditID == id {
			return b
		}
	}
	t.Fatalf("%s holds no event %s", sessionPath, id)
	return block{}
}
