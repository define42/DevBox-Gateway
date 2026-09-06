package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/define42/devbox-gateway/internal/config"
)

func TestLDAPTransportAddress(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		network string
		address string
		wantErr bool
	}{
		{name: "LDAP default port", url: "ldap://directory.example", network: "tcp", address: "directory.example:389"},
		{name: "LDAPS default port", url: "ldaps://directory.example", network: "tcp", address: "directory.example:636"},
		{name: "LDAP custom port", url: "ldap://directory.example:1389", network: "tcp", address: "directory.example:1389"},
		{name: "LDAPS custom port", url: "ldaps://directory.example:1636", network: "tcp", address: "directory.example:1636"},
		{name: "IPv6 default port", url: "ldap://[::1]", network: "tcp", address: "[::1]:389"},
		{name: "IPv6 custom port", url: "ldaps://[2001:db8::1]:1636", network: "tcp", address: "[2001:db8::1]:1636"},
		{name: "LDAP DN path", url: "ldap://directory.example/dc=example,dc=com", network: "tcp", address: "directory.example:389"},
		{name: "CLDAP default port", url: "cldap://directory.example", network: "udp", address: "directory.example:389"},
		{name: "CLDAP custom port", url: "cldap://directory.example:1389", network: "udp", address: "directory.example:1389"},
		{name: "Unix encoded host", url: "ldapi://%2Ftmp%2Fldap.sock", network: "unix", address: "/tmp/ldap.sock"},
		{name: "Unix encoded host with DN", url: "ldapi://%2Ftmp%2Fldap.sock/dc=example,dc=com", network: "unix", address: "/tmp/ldap.sock"},
		{name: "Unix legacy path", url: "ldapi:///tmp/ldap.sock", network: "unix", address: "/tmp/ldap.sock"},
		{name: "Unix default path", url: "ldapi://", network: "unix", address: "/var/run/slapd/ldapi"},
		{name: "Unix root default path", url: "ldapi:///", network: "unix", address: "/var/run/slapd/ldapi"},
		{name: "invalid Unix escape", url: "ldapi://%zz", wantErr: true},
		{name: "unsupported scheme", url: "https://directory.example", wantErr: true},
		{name: "missing scheme", url: "directory.example:389", wantErr: true},
		{name: "invalid port", url: "ldap://directory.example:invalid", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkLDAPTransportAddress(t, tt.url, tt.network, tt.address, tt.wantErr)
		})
	}
}

func checkLDAPTransportAddress(t *testing.T, rawURL, wantNetwork, wantAddress string, wantErr bool) {
	t.Helper()
	u, err := parseLDAPURL(rawURL)
	var network, address string
	if err == nil {
		network, address, err = ldapAddress(u)
	}
	if wantErr {
		if err == nil {
			t.Fatal("invalid LDAP URL was accepted")
		}
		return
	}
	if err != nil {
		t.Fatalf("LDAP transport address: %v", err)
	}
	if network != wantNetwork || address != wantAddress {
		t.Fatalf("transport = (%q, %q), want (%q, %q)", network, address, wantNetwork, wantAddress)
	}
}

func TestDialLDAPCanceledContext(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "LDAP", url: "ldap://127.0.0.1:389"},
		{name: "LDAPS", url: "ldaps://127.0.0.1:636"},
		{name: "CLDAP", url: "cldap://127.0.0.1:389"},
		{name: "Unix socket", url: "ldapi:///tmp/devbox-canceled-ldap.sock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings := config.NewSettings(false)
			if err := settings.OverwriteForTestString(config.LDAP_URL, tt.url); err != nil {
				t.Fatalf("set LDAP URL: %v", err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			conn, err := dialLDAP(ctx, settings)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("canceled dial returned an LDAP connection")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("dial error = %v, want context.Canceled", err)
			}
		})
	}
}
