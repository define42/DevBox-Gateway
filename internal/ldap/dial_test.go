package ldap

import (
	"rdptlsgateway/internal/config"
	"strings"
	"testing"
)

func TestDialLDAPInvalidURLFormat(t *testing.T) {
	t.Setenv(config.LDAP_URL, "not-a-real-url")
	settings := config.NewSettingType(false)

	if _, err := dialLDAP(settings); err == nil {
		t.Fatal("expected error for invalid LDAP URL")
	}
}

func TestDialLDAPConnectionRefused(t *testing.T) {
	t.Setenv(config.LDAP_URL, "ldap://127.0.0.1:1")
	settings := config.NewSettingType(false)

	_, err := dialLDAP(settings)
	if err == nil {
		t.Fatal("expected error connecting to closed port")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refused") &&
		!strings.Contains(strings.ToLower(err.Error()), "network") {
		t.Fatalf("expected network/refused error, got %v", err)
	}
}

func TestDialLDAPStartTLSFailureClosesConn(t *testing.T) {
	t.Setenv(config.LDAP_URL, "ldap://127.0.0.1:1")
	t.Setenv(config.LDAP_STARTTLS, "true")
	settings := config.NewSettingType(false)

	if _, err := dialLDAP(settings); err == nil {
		t.Fatal("expected error when StartTLS path cannot complete")
	}
}
