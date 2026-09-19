package audit

import (
	"context"
	"testing"
	"time"
)

// Realistic records for one "cat /etc/shadow" execution, plus a second,
// interleaved event, so ordering and grouping are exercised with the same
// shape of data the kernel actually emits.
const (
	recSyscallA   = `type=SYSCALL msg=audit(1699887654.123:8421): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd a1=7ffd a2=7ffd a3=8 items=2 ppid=4702 pid=4821 auid=1000 uid=0 gid=0 comm="cat" exe="/usr/bin/cat" key="watch-shadow"`
	recExecveA    = `type=EXECVE msg=audit(1699887654.123:8421): argc=2 a0="cat" a1="/etc/shadow"`
	recCwdA       = `type=CWD msg=audit(1699887654.123:8421): cwd="/home/user"`
	recPathA      = `type=PATH msg=audit(1699887654.123:8421): item=0 name="/etc/shadow" inode=1234 dev=fd:00 mode=0100640 ouid=0 ogid=42 nametype=NORMAL`
	recProctitleA = `type=PROCTITLE msg=audit(1699887654.123:8421): proctitle=636174002F6574632F736861646F77`
	recEoeA       = `type=EOE msg=audit(1699887654.123:8421):`

	recSyscallB = `type=SYSCALL msg=audit(1699887654.456:8422): arch=c000003e syscall=257 success=yes exit=3 items=1 ppid=1 pid=900 auid=4294967295 uid=0 gid=0 comm="sshd" exe="/usr/sbin/sshd"`
	recPathB    = `type=PATH msg=audit(1699887654.456:8422): item=0 name="/etc/passwd" inode=99 dev=fd:00 mode=0100644 ouid=0 ogid=0 nametype=NORMAL`
	recEoeB     = `type=EOE msg=audit(1699887654.456:8422):`

	// A control-range reply carries no audit event id at all.
	recNoEventID = `type=GET msg=enabled=1 flag=1 pid=900 rate_limit=0 backlog_limit=8192 lost=0 backlog=0`
)

func mustParse(t *testing.T, line string) *Record {
	t.Helper()
	r, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine(%q): %v", line, err)
	}
	return r
}

// fakeClock is an injected, entirely manual clock: correlation timing is
// tested by moving it, never by sleeping.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestCorrelator(timeout time.Duration, maxPending int) (*Correlator, *fakeClock) {
	clk := &fakeClock{now: time.Unix(1699887654, 0).UTC()}
	c := NewCorrelator(CorrelatorOptions{
		Timeout:          timeout,
		MaxPendingEvents: maxPending,
		Now:              clk.Now,
	})
	return c, clk
}

func groupTypes(g *Group) []string { return g.Types() }

func assertTypes(t *testing.T, g *Group, want ...string) {
	t.Helper()
	got := groupTypes(g)
	if len(got) != len(want) {
		t.Fatalf("group %s has records %v, want %v", g.AuditID, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("group %s has records %v, want %v", g.AuditID, got, want)
		}
	}
}

func TestCorrelatorClosesOnEOE(t *testing.T) {
	c, _ := newTestCorrelator(2*time.Second, 16)

	for _, line := range []string{recSyscallA, recExecveA, recCwdA, recPathA, recProctitleA} {
		if closed := c.Add(mustParse(t, line)); len(closed) != 0 {
			t.Fatalf("Add(%q) closed %d groups early", line, len(closed))
		}
	}
	if got := c.Pending(); got != 1 {
		t.Fatalf("Pending() = %d, want 1", got)
	}

	closed := c.Add(mustParse(t, recEoeA))
	if len(closed) != 1 {
		t.Fatalf("EOE closed %d groups, want 1", len(closed))
	}
	g := closed[0]
	if !g.Complete {
		t.Error("Complete = false, want true for a group closed by EOE")
	}
	if g.AuditID != "1699887654.123:8421" {
		t.Errorf("AuditID = %q", g.AuditID)
	}
	if g.Serial != 8421 {
		t.Errorf("Serial = %d, want 8421", g.Serial)
	}
	if want := time.UnixMilli(1699887654123).UTC(); !g.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v (the first record's)", g.Timestamp, want)
	}
	// The EOE record is kept so that the preserved raw evidence still matches
	// exactly what the kernel emitted.
	assertTypes(t, g, "SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE", "EOE")
	if got := c.Pending(); got != 0 {
		t.Errorf("Pending() = %d after close, want 0", got)
	}
}

func TestCorrelatorOutOfOrderRecords(t *testing.T) {
	c, _ := newTestCorrelator(2*time.Second, 16)

	// The kernel's emission order is not guaranteed once records queue up; the
	// audit id is what decides membership, not position.
	c.Add(mustParse(t, recProctitleA))
	c.Add(mustParse(t, recPathA))
	c.Add(mustParse(t, recSyscallA))
	closed := c.Add(mustParse(t, recEoeA))

	if len(closed) != 1 {
		t.Fatalf("closed %d groups, want 1", len(closed))
	}
	assertTypes(t, closed[0], "PROCTITLE", "PATH", "SYSCALL", "EOE")
	if closed[0].First(TypeSyscall) == nil {
		t.Error("First(TypeSyscall) = nil")
	}
	if !closed[0].Has(TypePath) {
		t.Error("Has(TypePath) = false")
	}
}

func TestCorrelatorInterleavedEvents(t *testing.T) {
	c, _ := newTestCorrelator(2*time.Second, 16)

	c.Add(mustParse(t, recSyscallA))
	c.Add(mustParse(t, recSyscallB))
	c.Add(mustParse(t, recExecveA))
	c.Add(mustParse(t, recPathB))
	if got := c.Pending(); got != 2 {
		t.Fatalf("Pending() = %d, want 2", got)
	}

	closedB := c.Add(mustParse(t, recEoeB))
	if len(closedB) != 1 || closedB[0].AuditID != "1699887654.456:8422" {
		t.Fatalf("EOE for B closed %v, want just B", closedB)
	}
	assertTypes(t, closedB[0], "SYSCALL", "PATH", "EOE")

	closedA := c.Add(mustParse(t, recEoeA))
	if len(closedA) != 1 || closedA[0].AuditID != "1699887654.123:8421" {
		t.Fatalf("EOE for A closed %v, want just A", closedA)
	}
	assertTypes(t, closedA[0], "SYSCALL", "EXECVE", "EOE")
}

func TestCorrelatorExpiresOnTimeout(t *testing.T) {
	c, clk := newTestCorrelator(2*time.Second, 16)

	c.Add(mustParse(t, recSyscallA))
	clk.advance(time.Second)
	c.Add(mustParse(t, recSyscallB))

	// Nothing is due yet: the first group is only one second old.
	if expired := c.Expire(clk.Now()); len(expired) != 0 {
		t.Fatalf("Expire too early returned %d groups", len(expired))
	}

	// A later record must not extend the first group's deadline.
	clk.advance(time.Second)
	c.Add(mustParse(t, recExecveA))
	expired := c.Expire(clk.Now())
	if len(expired) != 1 {
		t.Fatalf("Expire returned %d groups, want 1", len(expired))
	}
	if expired[0].AuditID != "1699887654.123:8421" {
		t.Errorf("expired %q, want the oldest group", expired[0].AuditID)
	}
	if expired[0].Complete {
		t.Error("Complete = true for a group closed by timeout, want false")
	}
	assertTypes(t, expired[0], "SYSCALL", "EXECVE")

	clk.advance(time.Second)
	expired = c.Expire(clk.Now())
	if len(expired) != 1 || expired[0].AuditID != "1699887654.456:8422" {
		t.Fatalf("second Expire returned %v, want group B", expired)
	}
	if got := c.Pending(); got != 0 {
		t.Errorf("Pending() = %d, want 0", got)
	}
}

func TestCorrelatorExpiresOldestFirst(t *testing.T) {
	c, clk := newTestCorrelator(time.Second, 16)

	c.Add(mustParse(t, recSyscallA))
	clk.advance(10 * time.Millisecond)
	c.Add(mustParse(t, recSyscallB))
	clk.advance(2 * time.Second)

	expired := c.Expire(clk.Now())
	if len(expired) != 2 {
		t.Fatalf("Expire returned %d groups, want 2", len(expired))
	}
	if expired[0].AuditID != "1699887654.123:8421" || expired[1].AuditID != "1699887654.456:8422" {
		t.Errorf("Expire order = %q, %q, want oldest first", expired[0].AuditID, expired[1].AuditID)
	}
}

func TestCorrelatorMaxPendingForcesOldestOut(t *testing.T) {
	c, clk := newTestCorrelator(time.Hour, 2)

	c.Add(mustParse(t, recSyscallA))
	clk.advance(time.Millisecond)
	c.Add(mustParse(t, recSyscallB))
	clk.advance(time.Millisecond)

	third := mustParse(t, `type=SYSCALL msg=audit(1699887655.000:8500): syscall=2 pid=1 comm="init"`)
	closed := c.Add(third)
	if len(closed) != 1 {
		t.Fatalf("exceeding MaxPendingEvents closed %d groups, want 1", len(closed))
	}
	if closed[0].AuditID != "1699887654.123:8421" {
		t.Errorf("forced out %q, want the oldest group", closed[0].AuditID)
	}
	if closed[0].Complete {
		t.Error("Complete = true for a group forced out early, want false")
	}
	// It is forced out, never dropped: the records are all still there.
	assertTypes(t, closed[0], "SYSCALL")
	if got := c.Pending(); got != 2 {
		t.Errorf("Pending() = %d, want 2 (the bound)", got)
	}

	// The newest group survives; the bound must not evict what just arrived.
	remaining := c.Flush()
	if len(remaining) != 2 {
		t.Fatalf("Flush returned %d groups, want 2", len(remaining))
	}
	if remaining[1].AuditID != "1699887655.000:8500" {
		t.Errorf("newest group = %q, want it still pending", remaining[1].AuditID)
	}
}

func TestCorrelatorRecordWithoutEventID(t *testing.T) {
	c, _ := newTestCorrelator(time.Hour, 16)

	closed := c.Add(mustParse(t, recNoEventID))
	if len(closed) != 1 {
		t.Fatalf("Add returned %d groups, want 1 emitted immediately", len(closed))
	}
	if closed[0].AuditID != "" {
		t.Errorf("AuditID = %q, want empty", closed[0].AuditID)
	}
	if closed[0].Complete {
		t.Error("Complete = true, want false: nothing closed it with an EOE")
	}
	assertTypes(t, closed[0], "GET")
	if got := c.Pending(); got != 0 {
		t.Errorf("Pending() = %d, want 0: an uncorrelatable record is never held", got)
	}

	// Two of them must not merge into one group under the empty audit id.
	second := c.Add(mustParse(t, recNoEventID))
	if len(second) != 1 || len(second[0].Records) != 1 {
		t.Fatalf("second uncorrelatable record produced %v", second)
	}
}

func TestCorrelatorAddNil(t *testing.T) {
	c, _ := newTestCorrelator(time.Hour, 16)
	if closed := c.Add(nil); closed != nil {
		t.Fatalf("Add(nil) = %v, want nil", closed)
	}
}

func TestCorrelatorFlushEmptiesEverything(t *testing.T) {
	c, _ := newTestCorrelator(time.Hour, 16)
	c.Add(mustParse(t, recSyscallA))
	c.Add(mustParse(t, recSyscallB))

	flushed := c.Flush()
	if len(flushed) != 2 {
		t.Fatalf("Flush returned %d groups, want 2", len(flushed))
	}
	for _, g := range flushed {
		if g.Complete {
			t.Errorf("group %s Complete = true, want false", g.AuditID)
		}
	}
	if got := c.Pending(); got != 0 {
		t.Errorf("Pending() = %d after Flush, want 0", got)
	}
	if again := c.Flush(); len(again) != 0 {
		t.Errorf("second Flush returned %d groups, want 0", len(again))
	}
}

func TestCorrelatorRunEmitsOnEOE(t *testing.T) {
	c, _ := newTestCorrelator(time.Minute, 16)
	in := make(chan *Record)
	out := make(chan *Group, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, in, out) }()

	for _, line := range []string{recSyscallA, recExecveA, recCwdA, recPathA, recProctitleA, recEoeA} {
		in <- mustParse(t, line)
	}

	g := <-out
	assertTypes(t, g, "SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE", "EOE")
	if !g.Complete {
		t.Error("Complete = false, want true")
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil for an orderly shutdown", err)
	}
}

func TestCorrelatorRunFlushesOnInputClose(t *testing.T) {
	c, _ := newTestCorrelator(time.Minute, 16)
	in := make(chan *Record)
	out := make(chan *Group, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, in, out) }()

	in <- mustParse(t, recSyscallA)
	in <- mustParse(t, recExecveA)
	close(in)

	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil", err)
	}
	// A partially assembled event must still reach the collector: holding it
	// back would lose the evidence entirely.
	select {
	case g := <-out:
		assertTypes(t, g, "SYSCALL", "EXECVE")
		if g.Complete {
			t.Error("Complete = true, want false for a flushed group")
		}
	default:
		t.Fatal("Run exited without flushing the pending group")
	}
}

func TestCorrelatorRunFlushesOnCancel(t *testing.T) {
	c, _ := newTestCorrelator(time.Minute, 16)
	in := make(chan *Record)
	out := make(chan *Group, 4)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, in, out) }()

	in <- mustParse(t, recSyscallA)
	cancel()

	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil", err)
	}
	select {
	case g := <-out:
		assertTypes(t, g, "SYSCALL")
	default:
		t.Fatal("Run exited on cancellation without flushing the pending group")
	}
}

func TestCorrelatorRunCancellationBeatsBackpressure(t *testing.T) {
	c, _ := newTestCorrelator(time.Minute, 16)
	in := make(chan *Record)
	// Unbuffered and never read while Run is sending, so the send blocks.
	out := make(chan *Group)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, in, out) }()

	// Closing a group with no reader on out parks Run in a blocking send.
	in <- mustParse(t, recSyscallA)
	in <- mustParse(t, recEoeA)

	cancel()
	// The shutdown drain still offers the group, so read it rather than
	// waiting out the grace period.
	go func() {
		for range out {
		}
	}()
	if err := <-done; err != nil {
		t.Errorf("Run returned %v, want nil", err)
	}
}
