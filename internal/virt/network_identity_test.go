package virt

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateNetworkIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity NetworkIdentity
		valid    bool
	}{
		{"first allocation", identityForAddress(2), true},
		{"last allocation", identityForAddress(253), true},
		{"gateway", identityForAddress(1), false},
		{"reserved", identityForAddress(254), false},
		{"broadcast", identityForAddress(255), false},
		{"empty", NetworkIdentity{}, false},
		{"another VM MAC", NetworkIdentity{MAC: identityForAddress(3).MAC, IP: identityForAddress(2).IP}, false},
		{"other network", NetworkIdentity{MAC: identityForAddress(2).MAC, IP: "192.168.122.2"}, false},
		{"IPv6", NetworkIdentity{MAC: identityForAddress(2).MAC, IP: "::1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateNetworkIdentity(tc.identity); (err == nil) != tc.valid {
				t.Fatalf("validateNetworkIdentity(%+v) = %v, want valid=%t", tc.identity, err, tc.valid)
			}
		})
	}
}

func TestNetworkReservationName(t *testing.T) {
	names := []string{"alice.vm", "ALICE.vm", "alice@example.com.vm", "alice+team.vm", strings.Repeat("x", 192)}
	seen := make(map[string]bool)
	for _, name := range names {
		reservation := networkReservationName(name)
		if len(reservation) > 63 || seen[reservation] {
			t.Fatalf("invalid or duplicate reservation key: %q", reservation)
		}
		for _, char := range reservation {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				t.Fatalf("reservation key %q is not a DNS label", reservation)
			}
		}
		seen[reservation] = true
	}
}

func TestChooseNetworkIdentityPreservesReservations(t *testing.T) {
	var hosts []networkDHCPHost
	for i := range 252 {
		name := fmt.Sprintf("owner.vm%d", i)
		identity, exists, err := chooseNetworkIdentity(hosts, name)
		if err != nil || exists {
			t.Fatalf("new reservation %d: identity=%+v existing=%t err=%v", i, identity, exists, err)
		}
		hosts = append(hosts, networkDHCPHost{Name: networkReservationName(name), MAC: identity.MAC, IP: identity.IP})
	}
	if _, _, err := chooseNetworkIdentity(hosts, "owner.overflow"); err == nil {
		t.Fatal("full pool must reject new allocation")
	}
	identity, exists, err := chooseNetworkIdentity(hosts, "owner.vm7")
	if err != nil || !exists || identity != identityForAddress(9) {
		t.Fatalf("existing identity changed in full pool: %+v %t %v", identity, exists, err)
	}
	hosts = append(hosts[:7], hosts[8:]...)
	reused, exists, err := chooseNetworkIdentity(hosts, "owner.replacement")
	if err != nil || exists || reused != identity {
		t.Fatalf("released address was not reused: %+v %t %v", reused, exists, err)
	}
}

func TestChooseNetworkIdentityRejectsAmbiguousReservations(t *testing.T) {
	first := networkDHCPHost{Name: networkReservationName("alice.vm"), MAC: identityForAddress(2).MAC, IP: identityForAddress(2).IP}
	for _, tc := range []struct {
		name   string
		mutate func(*networkDHCPHost)
	}{
		{"duplicate address", func(host *networkDHCPHost) { host.Name = networkReservationName("bob.vm") }},
		{"duplicate name", func(host *networkDHCPHost) { host.MAC = identityForAddress(3).MAC; host.IP = identityForAddress(3).IP }},
		{"client ID", func(host *networkDHCPHost) { host.ID = "untrusted-client-id" }},
		{"wrong MAC", func(host *networkDHCPHost) { host.MAC = identityForAddress(3).MAC }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := first
			tc.mutate(&other)
			if _, _, err := chooseNetworkIdentity([]networkDHCPHost{first, other}, "alice.vm"); err == nil {
				t.Fatal("ambiguous reservation must fail even when the requested VM already exists")
			}
		})
	}
}
