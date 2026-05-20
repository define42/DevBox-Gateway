package virt

import (
	"testing"

	"libvirt.org/go/libvirt"
)

func TestAppendUniqueDomainIPSkipsEmpty(t *testing.T) {
	seen := map[string]struct{}{}
	got := appendUniqueDomainIP(nil, seen, "")
	if got != nil {
		t.Fatalf("expected nil result for empty addr, got %v", got)
	}
	if len(seen) != 0 {
		t.Fatalf("expected seen map to remain empty, got %v", seen)
	}
}

func TestAppendUniqueDomainIPDeduplicates(t *testing.T) {
	seen := map[string]struct{}{}
	got := appendUniqueDomainIP(nil, seen, "10.0.0.1")
	got = appendUniqueDomainIP(got, seen, "10.0.0.1")
	got = appendUniqueDomainIP(got, seen, "10.0.0.2")
	got = appendUniqueDomainIP(got, seen, "10.0.0.2")
	got = appendUniqueDomainIP(got, seen, "10.0.0.3")
	if len(got) != 3 {
		t.Fatalf("expected 3 unique addresses, got %v", got)
	}
	expected := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for i, want := range expected {
		if got[i] != want {
			t.Fatalf("unexpected address at index %d: got %q, want %q", i, got[i], want)
		}
	}
}

func TestAppendDomainInterfaceIPsFlattensAddresses(t *testing.T) {
	iface := libvirt.DomainInterface{
		Name: "eth0",
		Addrs: []libvirt.DomainIPAddress{
			{Addr: "10.0.0.1"},
			{Addr: "10.0.0.2"},
			{Addr: ""},         // skipped
			{Addr: "10.0.0.1"}, // duplicate, skipped
		},
	}
	seen := map[string]struct{}{}
	got := appendDomainInterfaceIPs(nil, seen, iface)

	if len(got) != 2 {
		t.Fatalf("expected 2 unique addresses, got %v", got)
	}
	if got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("unexpected addresses: %v", got)
	}
}

func TestAppendDomainInterfaceIPsHandlesNoAddresses(t *testing.T) {
	iface := libvirt.DomainInterface{Name: "eth0"}
	seen := map[string]struct{}{}
	got := appendDomainInterfaceIPs([]string{"existing"}, seen, iface)
	if len(got) != 1 || got[0] != "existing" {
		t.Fatalf("expected existing slice to be returned unchanged, got %v", got)
	}
}
