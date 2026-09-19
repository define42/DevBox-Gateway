package virt

import (
	"strings"
	"testing"
)

func TestParseDomainNetworkIdentity(t *testing.T) {
	identity := identityForAddress(2)
	doc := DomainXML("alice.vm", "seed.iso", "pool", 2, 2048, false, identity)
	parsed, err := parseDomainNetworkIdentity(doc)
	if err != nil || parsed != identity {
		t.Fatalf("protected domain identity = %+v, %v", parsed, err)
	}
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"shared network", "network='devbox'", "network='default'"},
		{"bridge bypass", "type='network'", "type='bridge'"},
		{"no port isolation", "isolated='yes'", "isolated='no'"},
		{"no filter", "filter='devbox-isolated-ipv4'", "filter='clean-traffic'"},
		{"guest IP learning", "value='none'", "value='any'"},
		{"DHCP IP learning", "value='none'", "value='dhcp'"},
		{"different source MAC", identity.MAC, identityForAddress(3).MAC},
		{"different source IP", identity.IP, identityForAddress(3).IP},
		{"duplicate IP parameter", "name='CTRL_IP_LEARNING' value='none'", "name='IP' value='192.168.123.2'"},
		{"MAC override", "name='CTRL_IP_LEARNING' value='none'", "name='MAC' value='52:54:00:db:7b:03'"},
		{"second interface", "</devices>", "<interface type='network'><source network='default'/></interface></devices>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsafe := strings.Replace(doc, tc.old, tc.replacement, 1)
			if unsafe == doc {
				t.Fatal("test mutation did not modify the domain")
			}
			if _, err := parseDomainNetworkIdentity(unsafe); err == nil {
				t.Fatal("unsafe domain network was accepted")
			}
		})
	}
}

func TestValidateIdentityReservation(t *testing.T) {
	identity := identityForAddress(2)
	hosts := []networkDHCPHost{{Name: networkReservationName("alice.vm"), MAC: identity.MAC, IP: identity.IP}}
	if err := validateIdentityReservation(hosts, "alice.vm", identity); err != nil {
		t.Fatal(err)
	}
	if err := validateIdentityReservation(hosts, "bob.vm", identity); err == nil {
		t.Fatal("another VM's reservation was accepted")
	}
	if err := validateIdentityReservation(hosts, "alice.vm", identityForAddress(3)); err == nil {
		t.Fatal("unreserved identity was accepted")
	}
}
