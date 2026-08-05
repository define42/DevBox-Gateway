package config

import (
	"strings"
	"testing"
)

func TestValidateFrontDomainAcceptsDefault(t *testing.T) {
	// The default FRONT_DOMAIN is non-empty, so a freshly built settings object
	// passes without any override.
	if err := ValidateFrontDomain(NewSettingType(false)); err != nil {
		t.Fatalf("expected default FRONT_DOMAIN to be valid, got %v", err)
	}
}

func TestValidateFrontDomainAcceptsExplicit(t *testing.T) {
	t.Setenv(FRONT_DOMAIN, "vdi.example.test")
	if err := ValidateFrontDomain(NewSettingType(false)); err != nil {
		t.Fatalf("expected explicit FRONT_DOMAIN to be valid, got %v", err)
	}
}

func TestValidateFrontDomainRejectsEmpty(t *testing.T) {
	for _, value := range []string{"", "   "} {
		t.Setenv(FRONT_DOMAIN, value)
		err := ValidateFrontDomain(NewSettingType(false))
		if err == nil {
			t.Fatalf("expected empty FRONT_DOMAIN (%q) to be rejected", value)
		}
		if !strings.Contains(err.Error(), FRONT_DOMAIN) {
			t.Fatalf("expected error to name FRONT_DOMAIN, got %v", err)
		}
	}
}

func TestValidateFrontDomainNilSettings(t *testing.T) {
	if err := ValidateFrontDomain(nil); err == nil {
		t.Fatal("expected nil settings to be rejected")
	}
}

func TestValidateRemovedSSHTunnelModeAcceptsUnsetAndDisabled(t *testing.T) {
	// Unset is the common case; disabled and unparsable values match how the
	// setting resolved when it existed (SetBool ignored unparsable values), and
	// all of them meant the old binary bound LISTEN_ADDR locally too.
	if err := ValidateRemovedSSHTunnelMode(); err != nil {
		t.Fatalf("expected unset %s to be accepted, got %v", removedSSHTunnelEnableKey, err)
	}
	for _, value := range []string{"false", "0", " no ", "", "not-a-bool"} {
		t.Setenv(removedSSHTunnelEnableKey, value)
		if err := ValidateRemovedSSHTunnelMode(); err != nil {
			t.Fatalf("expected %s=%q to be accepted, got %v", removedSSHTunnelEnableKey, value, err)
		}
	}
}

func TestValidateRemovedSSHTunnelModeRejectsEnabled(t *testing.T) {
	for _, value := range []string{"true", "1", " TRUE "} {
		t.Setenv(removedSSHTunnelEnableKey, value)
		err := ValidateRemovedSSHTunnelMode()
		if err == nil {
			t.Fatalf("expected %s=%q to be rejected", removedSSHTunnelEnableKey, value)
		}
		if !strings.Contains(err.Error(), removedSSHTunnelEnableKey) {
			t.Fatalf("expected error to name %s, got %v", removedSSHTunnelEnableKey, err)
		}
	}
}
