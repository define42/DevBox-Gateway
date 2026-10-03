package rdp

import (
	"net"
	"strings"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/session"
)

func TestResolveFrontRoute(t *testing.T) {
	t.Setenv(config.FRONT_DOMAIN, " Example.Test ")
	settings := config.NewSettings(false)
	manager := session.New()
	token := issueUserSession(t, manager, "alice", "127.0.0.1:5000", "vm1")["vm1"]
	otherToken := strings.Repeat("0", 32)
	tests := []struct {
		name, token, sni string
		wantOK           bool
	}{
		{name: "shared hostname", token: token, sni: "example.test", wantOK: true},
		{name: "no SNI", token: token, wantOK: true},
		{name: "VM subdomain rejected even with matching token", token: token, sni: token + ".example.test"},
		{name: "legacy SNI cannot replace token", sni: token + ".example.test"},
		{name: "conflicting SNI", token: token, sni: otherToken + ".example.test"},
		{name: "foreign SNI", token: token, sni: token + ".other.test"},
		{name: "suffix attack", token: token, sni: "notexample.test"},
		{name: "unknown token", token: otherToken, sni: "example.test"},
		{name: "unknown token with legacy SNI", token: otherToken, sni: token + ".example.test"},
		{name: "invalid token with shared hostname", token: "invalid", sni: "example.test"},
		{name: "invalid token with legacy SNI", token: "invalid", sni: token + ".example.test"},
		{name: "invalid hex", token: strings.Repeat("z", 32), sni: "example.test"},
		{name: "shared hostname needs token", sni: "example.test"},
		{name: "no route"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vmName, ok := resolveFrontRoute(tt.token, tt.sni, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, settings, manager)
			if ok != tt.wantOK || (ok && vmName != "vm1") || (!ok && vmName != "") {
				t.Fatalf("route = %q, %v; want allowed=%v", vmName, ok, tt.wantOK)
			}
		})
	}
	if !manager.ConsumeRDPConnectGrant(token, "alice", "127.0.0.1", "vm1") {
		t.Fatal("routing lookup consumed the token before authorization")
	}
}
