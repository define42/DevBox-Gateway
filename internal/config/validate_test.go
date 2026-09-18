package config

import (
	"strings"
	"testing"
)

func TestValidateLDAPURLAcceptsDefault(t *testing.T) {
	if err := ValidateLDAPURL(NewSettings(false)); err != nil {
		t.Fatalf("expected default LDAP_URL to be valid, got %v", err)
	}
}

func TestValidateLDAPURLRejectsEmpty(t *testing.T) {
	for _, value := range []string{"", "   "} {
		t.Setenv(LDAP_URL, value)
		err := ValidateLDAPURL(NewSettings(false))
		if err == nil {
			t.Fatalf("expected empty LDAP_URL (%q) to be rejected", value)
		}
		if !strings.Contains(err.Error(), LDAP_URL) {
			t.Fatalf("expected error to name LDAP_URL, got %v", err)
		}
	}
}

func TestValidateLDAPURLRejectsNilSettings(t *testing.T) {
	if err := ValidateLDAPURL(nil); err == nil {
		t.Fatal("expected nil settings to be rejected")
	}
}

func TestValidateFrontDomainAcceptsDefault(t *testing.T) {
	// The default FRONT_DOMAIN is non-empty, so a freshly built settings object
	// passes without any override.
	if err := ValidateFrontDomain(NewSettings(false)); err != nil {
		t.Fatalf("expected default FRONT_DOMAIN to be valid, got %v", err)
	}
}

func TestValidateFrontDomainAcceptsExplicit(t *testing.T) {
	t.Setenv(FRONT_DOMAIN, "vdi.example.test")
	if err := ValidateFrontDomain(NewSettings(false)); err != nil {
		t.Fatalf("expected explicit FRONT_DOMAIN to be valid, got %v", err)
	}
}

func TestValidateFrontDomainRejectsEmpty(t *testing.T) {
	for _, value := range []string{"", "   "} {
		t.Setenv(FRONT_DOMAIN, value)
		err := ValidateFrontDomain(NewSettings(false))
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

func TestValidateSplunkHEC(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		token    string
		index    string
		wantErr  string
	}{
		{name: "disabled"},
		{name: "endpoint and token", endpoint: "https://splunk.example.test:8088", token: "token"},
		{name: "endpoint token and index", endpoint: "https://splunk.example.test:8088", token: "token", index: "devbox"},
		{name: "endpoint without token", endpoint: "https://splunk.example.test:8088", token: "  ", wantErr: SPLUNK_HEC_TOKEN},
		{name: "token without endpoint", token: "token", wantErr: SPLUNK_HEC_ENDPOINT},
		{name: "index without endpoint", index: "devbox", wantErr: SPLUNK_HEC_ENDPOINT},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(SPLUNK_HEC_ENDPOINT, test.endpoint)
			t.Setenv(SPLUNK_HEC_TOKEN, test.token)
			t.Setenv(SPLUNK_HEC_INDEX, test.index)

			err := ValidateSplunkHEC(NewSettings(false))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateSplunkHEC() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateSplunkHEC() error = %v, want it to name %s", err, test.wantErr)
			}
		})
	}
}

func TestValidateSplunkHECRejectsNilSettings(t *testing.T) {
	if err := ValidateSplunkHEC(nil); err == nil {
		t.Fatal("expected nil settings to be rejected")
	}
}
