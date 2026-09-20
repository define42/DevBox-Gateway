package config

import (
	"math"
	"strconv"
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

func TestValidateLDAPUserDomainAcceptsDefault(t *testing.T) {
	if err := ValidateLDAPUserDomain(NewSettings(false)); err != nil {
		t.Fatalf("expected default LDAP_USER_DOMAIN to be valid, got %v", err)
	}
}

func TestValidateLDAPUserDomainRejectsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "whitespace", value: "   "},
		{name: "separator only", value: "@"},
		{name: "multiple separators", value: "@@example.test"},
		{name: "embedded separator", value: "example@test"},
		{name: "embedded whitespace", value: "example test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(LDAP_USER_DOMAIN, test.value)
			err := ValidateLDAPUserDomain(NewSettings(false))
			if err == nil {
				t.Fatalf("expected invalid LDAP_USER_DOMAIN (%q) to be rejected", test.value)
			}
			if !strings.Contains(err.Error(), LDAP_USER_DOMAIN) {
				t.Fatalf("expected error to name LDAP_USER_DOMAIN, got %v", err)
			}
		})
	}
}

func TestValidateLDAPUserDomainRejectsNilSettings(t *testing.T) {
	if err := ValidateLDAPUserDomain(nil); err == nil {
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

func TestValidateRDPPort(t *testing.T) {
	if err := ValidateRDPPort(nil); err == nil {
		t.Fatal("nil settings accepted")
	}
	cases := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "automatic", valid: true},
		{name: "minimum", value: "1", valid: true},
		{name: "maximum", value: "65535", valid: true},
		{name: "trimmed", value: " 8443 ", valid: true},
		{name: "zero", value: "0"},
		{name: "negative", value: "-1"},
		{name: "out of range", value: "65536"},
		{name: "not numeric", value: "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(RDP_PORT, tc.value)
			err := ValidateRDPPort(NewSettings(false))
			if tc.valid && err != nil {
				t.Fatalf("ValidateRDPPort: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), RDP_PORT)) {
				t.Fatalf("error = %v, want error naming RDP_PORT", err)
			}
		})
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
		name       string
		endpoint   string
		token      string
		index      string
		ackEnabled bool
		wantErr    string
	}{
		{name: "disabled"},
		{name: "endpoint and token", endpoint: "https://splunk.example.test:8088", token: "token"},
		{name: "endpoint token and index", endpoint: "https://splunk.example.test:8088", token: "token", index: "devbox"},
		{name: "endpoint token and acknowledgement", endpoint: "https://splunk.example.test:8088", token: "token", ackEnabled: true},
		{name: "acknowledgement without endpoint", ackEnabled: true, wantErr: SPLUNK_HEC_ENDPOINT},
		{name: "acknowledgement with blank endpoint", endpoint: "  ", ackEnabled: true, wantErr: SPLUNK_HEC_ACK_ENABLED},
		{name: "endpoint without token", endpoint: "https://splunk.example.test:8088", token: "  ", wantErr: SPLUNK_HEC_TOKEN},
		{name: "token without endpoint", token: "token", wantErr: SPLUNK_HEC_ENDPOINT},
		{name: "index without endpoint", index: "devbox", wantErr: SPLUNK_HEC_ENDPOINT},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(SPLUNK_HEC_ENDPOINT, test.endpoint)
			t.Setenv(SPLUNK_HEC_TOKEN, test.token)
			t.Setenv(SPLUNK_HEC_INDEX, test.index)
			t.Setenv(SPLUNK_HEC_ACK_ENABLED, strconv.FormatBool(test.ackEnabled))

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

func TestValidateSplunkHECRejectsSpoolByteOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("an int cannot hold a MiB value large enough to overflow int64 bytes")
	}
	t.Setenv(SPLUNK_HEC_ENDPOINT, "https://splunk.example.test:8088")
	t.Setenv(SPLUNK_HEC_TOKEN, "token")
	t.Setenv(DEVBOX_GATEWAY_SPOOL_MAX_MIB, strconv.FormatInt((math.MaxInt64>>20)+1, 10))

	err := ValidateSplunkHEC(NewSettings(false))
	if err == nil || !strings.Contains(err.Error(), DEVBOX_GATEWAY_SPOOL_MAX_MIB) {
		t.Fatalf("ValidateSplunkHEC() error = %v, want it to name %s", err, DEVBOX_GATEWAY_SPOOL_MAX_MIB)
	}
}

func TestValidateSauron(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{name: "mandatory collection with default event log"},
		{name: "file output with acknowledgement disabled", env: map[string]string{SAURON_SPLUNK_HEC_ACK_ENABLED: "false"}},
		{name: "hec with acknowledgement enabled", env: map[string]string{
			SAURON_SPLUNK_HEC_ENDPOINT: "https://splunk.example.test:8088", SAURON_SPLUNK_HEC_TOKEN: "token", SAURON_SPLUNK_HEC_ACK_ENABLED: "true",
		}},
		{name: "acknowledgement without endpoint", env: map[string]string{SAURON_SPLUNK_HEC_ACK_ENABLED: "true"}, wantErr: SAURON_SPLUNK_HEC_ENDPOINT},
		{name: "acknowledgement with blank endpoint", env: map[string]string{
			SAURON_SPLUNK_HEC_ENDPOINT: "  ", SAURON_SPLUNK_HEC_ACK_ENABLED: "true",
		}, wantErr: SAURON_SPLUNK_HEC_ACK_ENABLED},
		{name: "hec only", env: map[string]string{
			SAURON_EVENT_LOG_FILE:      "",
			SAURON_SPLUNK_HEC_ENDPOINT: "https://splunk.example.test:8088", SAURON_SPLUNK_HEC_TOKEN: "token", SAURON_SPLUNK_HEC_INDEX: "sauron",
		}},
		{name: "no output at all", env: map[string]string{SAURON_EVENT_LOG_FILE: " "}, wantErr: SAURON_EVENT_LOG_FILE},
		{name: "endpoint without token", env: map[string]string{
			SAURON_SPLUNK_HEC_ENDPOINT: "https://splunk.example.test:8088",
		}, wantErr: SAURON_SPLUNK_HEC_TOKEN},
		{name: "index without endpoint", env: map[string]string{SAURON_SPLUNK_HEC_INDEX: "sauron"}, wantErr: SAURON_SPLUNK_HEC_ENDPOINT},
		{name: "legacy disable cannot bypass output requirement", env: map[string]string{
			"SAURON_ENABLE": "false", SAURON_EVENT_LOG_FILE: "",
		}, wantErr: SAURON_EVENT_LOG_FILE},
		{name: "legacy port cannot change collection", env: map[string]string{"SAURON_VSOCK_PORT": "0"}},
		{name: "hec and default event log", env: map[string]string{
			SAURON_SPLUNK_HEC_ENDPOINT: "https://splunk.example.test:8088", SAURON_SPLUNK_HEC_TOKEN: "token",
		}},
		{name: "token without endpoint", env: map[string]string{SAURON_SPLUNK_HEC_TOKEN: "token"}, wantErr: SAURON_SPLUNK_HEC_ENDPOINT},
		{name: "audit hec is independent of sauron", env: map[string]string{
			SPLUNK_HEC_ENDPOINT: "https://splunk.example.test:8088", SPLUNK_HEC_TOKEN: "token", SPLUNK_HEC_ACK_ENABLED: "true",
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for key, value := range test.env {
				t.Setenv(key, value)
			}

			err := ValidateSauron(NewSettings(false))
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateSauron() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateSauron() error = %v, want it to name %s", err, test.wantErr)
			}
		})
	}
}

func TestValidateSauronRejectsNilSettings(t *testing.T) {
	if err := ValidateSauron(nil); err == nil {
		t.Fatal("expected nil settings to be rejected")
	}
}
