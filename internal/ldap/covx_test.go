package ldap

import (
	"devboxgateway/internal/config"
	"net"
	"testing"
)

// startClosingLDAPListener starts a loopback TCP listener that immediately
// closes every accepted connection, so LDAP dials succeed at the TCP layer but
// every subsequent LDAP operation fails deterministically.
func startClosingLDAPListener(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	return ln.Addr().String()
}

func TestDialLDAPStartTLSFailure(t *testing.T) {
	addr := startClosingLDAPListener(t)
	t.Setenv(config.LDAP_URL, "ldap://"+addr)
	t.Setenv(config.LDAP_STARTTLS, "true")
	t.Setenv(config.LDAP_SKIP_TLS_VERIFY, "true")
	settings := config.NewSettingType(false)

	conn, err := dialLDAP(settings)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected StartTLS against a non-LDAP server to fail")
	}
}

func TestAuthenticateAccessDialFailure(t *testing.T) {
	// Reserve a loopback port, then close it so the dial is refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	t.Setenv(config.LDAP_URL, "ldap://"+addr)
	t.Setenv(config.LDAP_STARTTLS, "false")
	settings := config.NewSettingType(false)

	user, err := AuthenticateAccess("covxuser", "covxpassword", settings)
	if user != nil {
		t.Fatalf("expected no user on dial failure, got %#v", user)
	}
	if err == nil {
		t.Fatal("expected dial error for unreachable LDAP server")
	}
}
