package virt

import (
	"strings"
	"testing"
)

func TestParseGatewayNetwork(t *testing.T) {
	doc := defaultNetworkXML()
	if _, err := parseGatewayNetwork(doc); err != nil {
		t.Fatalf("gateway network rejected: %v", err)
	}
	for _, tc := range []struct {
		name, old, replacement string
	}{
		{"shared default network", "<name>devbox</name>", "<name>default</name>"},
		{"foreign ownership", "urn:devbox:network", "urn:foreign:network"},
		{"shared bridge", "virbr-devbox", "virbr0"},
		{"routed network", "mode='nat'", "mode='route'"},
		{"wrong subnet", "192.168.123.1", "192.168.122.1"},
		{"wrong DHCP range", "192.168.123.253", "192.168.123.254"},
		{"untrusted client IDs", "<dnsmasq:option value='dhcp-ignore-clid'/>", ""},
		{"unreserved clients", "<dnsmasq:option value='dhcp-ignore=tag:!known'/>", ""},
		{"IPv6", "<name>devbox", "<ip family='ipv6' address='fd00::1' prefix='64'/><name>devbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsafe := strings.Replace(doc, tc.old, tc.replacement, 1)
			if _, err := parseGatewayNetwork(unsafe); err == nil {
				t.Fatal("unsafe gateway network was accepted")
			}
		})
	}
}
