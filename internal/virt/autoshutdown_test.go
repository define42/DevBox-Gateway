package virt

import (
	"testing"
	"time"

	"libvirt.org/go/libvirt"
)

func TestIdleAutoShutdownDue(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC)
	const timestamp = "2026-08-15T10:00:00Z"

	tests := []struct {
		name        string
		lastUsed    string
		hasLastUsed bool
		after       time.Duration
		want        bool
		wantErr     bool
	}{
		{name: "disabled", after: 0, want: false},
		{name: "missing timestamp", after: time.Hour, want: true},
		{name: "blank timestamp", lastUsed: " ", hasLastUsed: true, after: time.Hour, want: true},
		{name: "before deadline", lastUsed: timestamp, hasLastUsed: true, after: 3 * time.Hour, want: false},
		{name: "at deadline", lastUsed: timestamp, hasLastUsed: true, after: 2 * time.Hour, want: true},
		{name: "after deadline", lastUsed: timestamp, hasLastUsed: true, after: time.Hour, want: true},
		{name: "future timestamp", lastUsed: "2026-08-15T13:00:00Z", hasLastUsed: true, after: time.Hour, want: false},
		{name: "malformed timestamp", lastUsed: "not-a-time", hasLastUsed: true, after: time.Hour, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := idleAutoShutdownDue(tc.lastUsed, tc.hasLastUsed, tc.after, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("idleAutoShutdownDue() error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("idleAutoShutdownDue() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDomainStateEligibleForIdleAutoShutdown(t *testing.T) {
	for _, state := range []libvirt.DomainState{
		libvirt.DOMAIN_RUNNING,
		libvirt.DOMAIN_BLOCKED,
		libvirt.DOMAIN_PAUSED,
		libvirt.DOMAIN_PMSUSPENDED,
	} {
		if !domainStateEligibleForIdleAutoShutdown(state) {
			t.Fatalf("expected state %d to be eligible", state)
		}
	}
	for _, state := range []libvirt.DomainState{
		libvirt.DOMAIN_NOSTATE,
		libvirt.DOMAIN_SHUTDOWN,
		libvirt.DOMAIN_SHUTOFF,
		libvirt.DOMAIN_CRASHED,
	} {
		if domainStateEligibleForIdleAutoShutdown(state) {
			t.Fatalf("did not expect state %d to be eligible", state)
		}
	}
}

func TestSingletonWorkerAutoShutdownConfiguration(t *testing.T) {
	worker := &SingletonWorker{}
	worker.SetAutoShutdownHours(6)
	if got := worker.autoShutdownDuration(); got != 6*time.Hour {
		t.Fatalf("expected six-hour policy, got %s", got)
	}
	worker.SetAutoShutdownHours(0)
	if got := worker.autoShutdownDuration(); got != 0 {
		t.Fatalf("expected disabled policy, got %s", got)
	}
	worker.SetAutoShutdownHours(-1)
	if got := worker.autoShutdownDuration(); got != 0 {
		t.Fatalf("expected negative policy to be disabled, got %s", got)
	}
}

func TestEnforceIdleAutoShutdownDisabledAndConnectionError(t *testing.T) {
	now := time.Now().UTC()
	invalidConn := &libvirt.Connect{}
	if err := enforceIdleAutoShutdown(invalidConn, 0, now); err != nil {
		t.Fatalf("disabled auto-shutdown should not touch libvirt: %v", err)
	}
	if err := enforceIdleAutoShutdown(invalidConn, time.Hour, now); err == nil {
		t.Fatal("expected active-domain listing error from invalid connection")
	}
}

func TestViocovAutoShutdownDomainIfIdle(t *testing.T) {
	conn := newTestLibvirtConn(t)
	now := time.Now().UTC().Truncate(time.Second)

	tests := []autoShutdownDomainTestCase{
		{name: "disabled with missing timestamp", managed: true, after: 0, wantActive: true},
		{name: "managed missing timestamp", managed: true, after: 2 * time.Hour, wantActive: false},
		{name: "managed expired timestamp", managed: true, lastUsed: now.Add(-3 * time.Hour).Format(time.RFC3339), after: 2 * time.Hour, wantActive: false},
		{name: "managed recent timestamp", managed: true, lastUsed: now.Add(-time.Hour).Format(time.RFC3339), after: 2 * time.Hour, wantActive: true},
		{name: "unmanaged missing timestamp", after: 2 * time.Hour, wantActive: true},
		{name: "malformed timestamp", managed: true, lastUsed: "not-a-time", after: 2 * time.Hour, wantActive: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertAutoShutdownDomainCase(t, conn, now, tc)
		})
	}
}

type autoShutdownDomainTestCase struct {
	name       string
	managed    bool
	lastUsed   string
	after      time.Duration
	wantActive bool
}

func assertAutoShutdownDomainCase(t *testing.T, conn *libvirt.Connect, now time.Time, tc autoShutdownDomainTestCase) {
	t.Helper()

	name := viocovUniqueName("idle")
	dom := viocovStartDomain(t, conn, name, "")
	if tc.managed {
		if err := setDomainOwnerMetadata(dom, "cvio-idle-owner"); err != nil {
			t.Fatalf("set owner metadata: %v", err)
		}
	}
	if tc.lastUsed != "" {
		if err := setDomainLastUsedMetadata(dom, tc.lastUsed); err != nil {
			t.Fatalf("set last-used metadata: %v", err)
		}
	}

	autoShutdownDomainIfIdle(dom, tc.after, now)
	active, err := dom.IsActive()
	if err != nil {
		t.Fatalf("check domain active state: %v", err)
	}
	if active != tc.wantActive {
		t.Fatalf("active = %v, want %v", active, tc.wantActive)
	}
}
