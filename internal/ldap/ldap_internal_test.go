package ldap

import (
	"errors"
	"rdptlsgateway/internal/config"
	"testing"

	ldaplib "github.com/go-ldap/ldap/v3"
)

func TestIsLDAPCredentialErrorNonLDAP(t *testing.T) {
	if isLDAPCredentialError(errors.New("not an ldap error")) {
		t.Fatal("expected isLDAPCredentialError=false for generic error")
	}
	if isLDAPCredentialError(nil) {
		t.Fatal("expected isLDAPCredentialError=false for nil error")
	}
}

func TestIsLDAPCredentialErrorRecognisedCodes(t *testing.T) {
	codes := []uint16{
		ldaplib.LDAPResultInvalidCredentials,
		ldaplib.LDAPResultInappropriateAuthentication,
		ldaplib.LDAPResultInsufficientAccessRights,
		ldaplib.LDAPResultAuthorizationDenied,
		ldaplib.ErrorEmptyPassword,
	}
	for _, code := range codes {
		err := &ldaplib.Error{ResultCode: code, Err: errors.New("boom")}
		if !isLDAPCredentialError(err) {
			t.Fatalf("expected credential error for LDAP result %d", code)
		}
	}
}

func TestIsLDAPCredentialErrorUnknownCode(t *testing.T) {
	err := &ldaplib.Error{ResultCode: ldaplib.LDAPResultBusy, Err: errors.New("transient")}
	if isLDAPCredentialError(err) {
		t.Fatal("expected non-credential LDAP errors to be reported as non-credential")
	}
}

func TestLoginIdentifierAppendsDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice@example.test" {
		t.Fatalf("expected alice@example.test, got %q", got)
	}
}

func TestLoginIdentifierAppendsDomainWithAtPrefix(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "@example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice@example.test" {
		t.Fatalf("expected alice@example.test, got %q", got)
	}
}

func TestLoginIdentifierKeepsExistingDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "example.test")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice@other.test", settings); got != "alice@other.test" {
		t.Fatalf("expected unmodified address, got %q", got)
	}
}

func TestLoginIdentifierWithoutDomain(t *testing.T) {
	t.Setenv(config.LDAP_USER_DOMAIN, "")
	settings := config.NewSettingType(false)

	if got := loginIdentifier("alice", settings); got != "alice" {
		t.Fatalf("expected unmodified username, got %q", got)
	}
}
