package virt

import (
	"testing"

	"libvirt.org/go/libvirt"
)

func TestDomainCanReportIPs(t *testing.T) {
	tests := []struct {
		state libvirt.DomainState
		want  bool
	}{
		{libvirt.DOMAIN_RUNNING, true},
		{libvirt.DOMAIN_PAUSED, true},
		{libvirt.DOMAIN_PMSUSPENDED, true},
		{libvirt.DOMAIN_NOSTATE, false},
		{libvirt.DOMAIN_BLOCKED, false},
		{libvirt.DOMAIN_SHUTDOWN, false},
		{libvirt.DOMAIN_CRASHED, false},
		{libvirt.DOMAIN_SHUTOFF, false},
		{libvirt.DomainState(999), false}, // default branch
	}
	for _, tc := range tests {
		if got := domainCanReportIPs(tc.state); got != tc.want {
			t.Fatalf("domainCanReportIPs(%v) = %v, want %v", tc.state, got, tc.want)
		}
	}
}

func TestFormatStateForAllCases(t *testing.T) {
	// formatState should produce some non-empty representation for every known state.
	states := []libvirt.DomainState{
		libvirt.DOMAIN_RUNNING,
		libvirt.DOMAIN_PAUSED,
		libvirt.DOMAIN_SHUTOFF,
		libvirt.DOMAIN_CRASHED,
		libvirt.DOMAIN_SHUTDOWN,
		libvirt.DOMAIN_NOSTATE,
		libvirt.DOMAIN_BLOCKED,
		libvirt.DOMAIN_PMSUSPENDED,
		libvirt.DomainState(999),
	}
	for _, s := range states {
		if got := formatState(s); got == "" {
			t.Fatalf("formatState(%v) returned empty string", s)
		}
	}
}
